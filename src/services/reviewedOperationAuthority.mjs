import { types } from 'node:util';
import { getCheckById } from '../contracts/checks.mjs';
import { buildReviewedOperationBinding, validateCurrentReviewedOperationBinding } from '../contracts/reviewedOperationBinding.mjs';
import { effectiveTargetVerifications } from '../lib/effectiveTargetVerification.mjs';

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const failure = (error, status = 409) => ({ ok: false, error, status, grants_execution: false, execution_available: false });
function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value))
    && Reflect.ownKeys(value).every((key) => typeof key === 'string'
      && Object.getOwnPropertyDescriptor(value, key)?.enumerable
      && Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'));
}
const exact = (value, keys) => record(value) && Reflect.ownKeys(value).length === keys.length
  && keys.every((key) => Object.hasOwn(value, key));
function json(value, seen = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (!value || typeof value !== 'object' || seen.has(value)) return false;
  seen.add(value);
  if (Array.isArray(value)) return Reflect.ownKeys(value).length === value.length + 1
    && Array.from({ length: value.length }, (_, i) => Object.getOwnPropertyDescriptor(value, String(i)))
      .every((descriptor) => descriptor?.enumerable && Object.hasOwn(descriptor, 'value') && json(descriptor.value, seen));
  return record(value) && Object.values(value).every((item) => json(item, seen));
}
function utc(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value;
}
function requestCopy(request) {
  try {
    if (!record(request) || !['build', 'compare'].includes(request.mode)) return null;
    const keys = request.mode === 'build' ? ['mode', 'reviewId', 'targetId', 'checkId', 'originalAuthority']
      : ['mode', 'targetId', 'checkId', 'binding'];
    if (!exact(request, keys) || !ID.test(typeof request.targetId === 'string' ? request.targetId : '')
      || !ID.test(typeof request.checkId === 'string' ? request.checkId : '')) return null;
    if (request.mode === 'build') {
      if (typeof request.reviewId !== 'string' || !ID.test(request.reviewId)
        || !exact(request.originalAuthority, ['issued_at', 'not_after'])
        || !utc(request.originalAuthority.issued_at) || !utc(request.originalAuthority.not_after)) return null;
    } else {
      if (!json(request.binding) || !record(request.binding) || typeof request.binding.review_id !== 'string'
        || !ID.test(request.binding.review_id) || !exact(request.binding.authority, ['issued_at', 'original_not_after', 'not_after'])
        || !Object.values(request.binding.authority).every(utc)) return null;
    }
    return structuredClone(request);
  } catch { return null; }
}
function frozenCopy(value) {
  function freeze(item) {
    // Freezing a Date does not prevent setTime(). Driver presentation clocks become
    // finite ISO strings; exact authority clocks were read as strings and stay exact.
    if (item instanceof Date) {
      if (!Number.isFinite(item.getTime())) throw new Error('invalid snapshot timestamp');
      return item.toISOString();
    }
    if (Array.isArray(item)) return Object.freeze(item.map(freeze));
    // Object.fromEntries preserves literal __proto__ JSON material as an own key.
    if (item && typeof item === 'object') return Object.freeze(Object.fromEntries(
      Object.entries(item).map(([key, field]) => [key, freeze(field)]),
    ));
    return item;
  }
  return freeze(structuredClone(value));
}
// Selection MUST precede this lossless display conversion. Never truncate real microseconds.
const canonicalMillis = (value) => typeof value === 'string' ? value.replace(/(\.\d{3})000Z$/, '$1Z') : value;

/**
 * Internal current-row prerequisite only, never an HMAC/grant verifier or execution grant.
 * PG holds its tenant transaction through validation AND callback. Dev only supplies a
 * synchronous actual-row snapshot; its review queue does not lock catalog/ownership writers.
 * A snapshot is not signing/admission authority: revalidate after any signing wait.
 */
export function createReviewedOperationAuthority({ backend } = {}) {
  if (typeof backend?.withAuthorityRows !== 'function') throw new Error('reviewed operation authority backend required');
  return {
    withCurrentAuthority(ctx, request, callback, options = {}) {
      const selected = requestCopy(request);
      if (!selected || typeof ctx?.tenantId !== 'string' || !ID.test(ctx.tenantId) || typeof callback !== 'function') {
        return failure('invalid_reviewed_operation_authority_request', 400);
      }
      if (!record(options) || Object.keys(options).some((key) => key !== 'client')
        || Object.hasOwn(options, 'client') && (!options.client || typeof options.client.query !== 'function')
        || backend.synchronousAuthority === true && (Object.hasOwn(options, 'client') || types.isAsyncFunction(callback))) {
        return failure('invalid_reviewed_operation_authority_options', 400);
      }
      const tenantId = ctx.tenantId;
      const reviewId = selected.mode === 'build' ? selected.reviewId : selected.binding.review_id;
      return backend.withAuthorityRows({ ...ctx, tenantId }, selected.targetId, reviewId, (rows) => {
        const { review, targetGroup, target, ownershipHistory, checkedAt } = rows;
        if (!target || target.id !== selected.targetId || target.tenant_id !== tenantId || target.deleted_at != null
          || !targetGroup || targetGroup.tenant_id !== tenantId || targetGroup.id !== target.target_group_id
          || targetGroup.deleted_at != null || targetGroup.archived_at != null) return failure('operation_target_changed');
        if (selected.mode === 'compare' && (selected.binding.plan?.target_id !== selected.targetId
          || selected.binding.plan?.check_id !== selected.checkId)) return failure('reviewed_operation_binding_changed');
        // Empty targets means no parent inheritance, provider promotion or demo fallback.
        // ALL direct history participates, including malformed and ambiguous rows.
        const current = effectiveTargetVerifications({ targets: [], targetVerifications: ownershipHistory }, tenantId,
          [selected.targetId]).get(selected.targetId) ?? null;
        const ownership = current ? { ...current, transitioned_at: canonicalMillis(current.transitioned_at) } : null;
        const check = getCheckById(selected.checkId);
        const context = { tenantId, reviewId, review, target, check, ownership, now: checkedAt };
        const validated = selected.mode === 'build'
          ? buildReviewedOperationBinding({ ...context, originalAuthority: selected.originalAuthority })
          : validateCurrentReviewedOperationBinding(selected.binding, context);
        if (!validated.ok || validated.legacy) return validated.ok ? failure('reviewed_operation_binding_invalid') : validated;
        let snapshot;
        try {
          snapshot = frozenCopy({ ok: true, tenantId, reviewId, review, targetGroup, target, check, ownership,
            ownershipHistory, checkedAt, binding: validated.binding, delivery: validated.delivery,
            grants_execution: false, execution_available: false });
        } catch { return failure('reviewed_operation_authority_snapshot_invalid'); }
        return callback(snapshot);
      }, options);
    },
  };
}
