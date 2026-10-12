import { createHash } from 'node:crypto';
import { canonicalJsonStringify, CONTENT_CANONICALIZATION } from '../lib/custody.mjs';
import { validateReviewedOperationReservation } from './reviewedOperationBinding.mjs';

export const REVIEWED_EXECUTION_GRANT_VERSION = 'reviewed-execution-grant.v1';
export const REVIEWED_EXECUTION_GRANT_ENVELOPE_VERSION = 'reviewed-execution-grant-envelope.v1';
export const REVIEWED_EXECUTION_GRANT_PURPOSE = 'astranull.reviewed-operation.execution-grant';
export const REVIEWED_EXECUTION_GRANT_SIGNATURE_VERSION = 'reviewed-execution-grant-signature.v1';
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const HEX = /^[a-f0-9]{64}$/;
export const ORIGINAL_JOB_SIGNED_KEYS = Object.freeze(['check_id', 'constraints', 'id', 'nonce_hash', 'probe_profile', 'target', 'tenant_id', 'test_run_id']);
const REQUIRED_CONSTRAINTS = ['authority_version', 'issued_at', 'not_after', 'execution_attempts', 'timeout_ms',
  'max_probe_requests', 'min_destination_resolver_attempts', 'max_destination_resolver_attempts',
  'max_total_operations', 'max_requests', 'ownership_binding', 'reviewed_operation_binding'];
const OPTIONAL_CONSTRAINTS = ['max_events', 'max_duration_seconds', 'max_concurrent_runs_per_target_group'];
const INPUT_KEYS = ['originalJob', 'reservation', 'check', 'tenantId', 'workerId', 'leasedAt', 'now'];
const ENVELOPE_KEYS = ['version', 'purpose', 'content_canonicalization', 'algorithm', 'key_reference',
  'public_key_fingerprint_sha256', 'tenant_id', 'job', 'original_job_payload', 'original_job_signature_sha256',
  'worker', 'reservation', 'budgets', 'authority'];
const KEY_REFERENCE = /^key:\/\/[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/;
const fail = (error, status = 409) => ({ ok: false, error, status });
const hash = (value) => createHash('sha256').update(value, 'utf8').digest('hex');

export function reviewedGrantRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value))
    && Reflect.ownKeys(value).every((key) => typeof key === 'string' && key !== '__proto__'
      && Object.getOwnPropertyDescriptor(value, key)?.enumerable
      && Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'));
}
export function reviewedGrantExact(value, keys) {
  return reviewedGrantRecord(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

/** No coercion, accessors, sparse arrays, hidden fields, cycles or non-JSON authority. */
export function reviewedGrantJson(value) {
  const seen = new Set();
  let nodes = 0;
  function visit(item, depth) {
    if (++nodes > 20000 || depth > 64) return false;
    if (item === null || typeof item === 'string' || typeof item === 'boolean') return true;
    if (typeof item === 'number') return Number.isFinite(item) && !Object.is(item, -0);
    if (typeof item !== 'object' || seen.has(item)) return false;
    seen.add(item);
    let valid;
    if (Array.isArray(item)) {
      valid = Object.getPrototypeOf(item) === Array.prototype && Reflect.ownKeys(item).length === item.length + 1;
      for (let i = 0; valid && i < item.length; i += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(item, String(i));
        valid = !!descriptor?.enumerable && Object.hasOwn(descriptor, 'value') && visit(descriptor.value, depth + 1);
      }
    } else {
      valid = reviewedGrantRecord(item) && Object.values(item).every((child) => visit(child, depth + 1));
    }
    seen.delete(item);
    return valid;
  }
  try { return visit(value, 0); } catch { return false; }
}

/** Authority labels use exactly canonical UTC milliseconds, never rounded microseconds. */
export function reviewedGrantUtc(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return NaN;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value ? time : NaN;
}
export function reviewedGrantClock(value) {
  const time = value instanceof Date ? value.getTime() : typeof value === 'number' ? value : reviewedGrantUtc(value);
  return Number.isSafeInteger(time) && Number.isFinite(time) && time >= 0 && time <= 253402300799999 ? time : NaN;
}
export function freezeReviewedGrant(value) {
  const copy = structuredClone(value);
  function freeze(item) {
    if (item && typeof item === 'object') { Object.values(item).forEach(freeze); Object.freeze(item); }
    return item;
  }
  return freeze(copy);
}

function originalPayload(job) {
  if (!reviewedGrantRecord(job)) return null;
  const payload = Object.fromEntries(ORIGINAL_JOB_SIGNED_KEYS.map((key) => [key, job[key]]));
  if (!reviewedGrantJson(payload) || !reviewedGrantRecord(payload.constraints)
    || REQUIRED_CONSTRAINTS.some((key) => !Object.hasOwn(payload.constraints, key))
    || Object.keys(payload.constraints).some((key) => ![...REQUIRED_CONSTRAINTS, ...OPTIONAL_CONSTRAINTS].includes(key))
    || OPTIONAL_CONSTRAINTS.some((key) => Object.hasOwn(payload.constraints, key)
      && (!Number.isSafeInteger(payload.constraints[key]) || payload.constraints[key] < 1))
    || !['id', 'tenant_id', 'test_run_id', 'check_id'].every((key) => typeof payload[key] === 'string' && ID.test(payload[key]))
    || typeof payload.nonce_hash !== 'string' || !HEX.test(payload.nonce_hash)
    || typeof job.job_signature !== 'string' || !HEX.test(job.job_signature)
    || !reviewedGrantRecord(payload.target) || !ID.test(payload.target.id)
    || job.target_id !== payload.target.id) return null;
  // probeJobs stableStringify and custody canonical JSON are byte-identical on this strictly
  // JSON subset. Never sign a whole leased DB record or re-sign a later reservation into it.
  const canonical = canonicalJsonStringify(payload);
  return canonical.length <= 131072 ? { payload, canonical } : null;
}

function build(input, signer) {
  if (!reviewedGrantExact(input, INPUT_KEYS) || !reviewedGrantJson(input.reservation) || !reviewedGrantJson(input.check)
    || !reviewedGrantExact(signer, ['algorithm', 'key_reference', 'public_key_fingerprint_sha256'])
    || signer.algorithm !== 'ed25519' || typeof signer.key_reference !== 'string' || !KEY_REFERENCE.test(signer.key_reference)
    || typeof signer.public_key_fingerprint_sha256 !== 'string' || !HEX.test(signer.public_key_fingerprint_sha256)) return fail('reviewed_grant_input_invalid', 400);
  const original = originalPayload(input.originalJob);
  if (!original) return fail('reviewed_grant_original_job_invalid');
  const job = input.originalJob, c = original.payload.constraints, binding = c.reviewed_operation_binding;
  if (typeof input.tenantId !== 'string' || !ID.test(input.tenantId) || input.tenantId !== job.tenant_id) return fail('reviewed_grant_tenant_mismatch');
  const at = reviewedGrantClock(input.now), leased = reviewedGrantUtc(input.leasedAt);
  const issued = reviewedGrantUtc(c.issued_at), until = reviewedGrantUtc(c.not_after);
  if (![at, leased, issued, until].every(Number.isFinite)) return fail('reviewed_grant_clock_invalid');
  if (!reviewedGrantJson(binding) || !reviewedGrantRecord(binding.authority)
    || ![binding.authority.issued_at, binding.authority.original_not_after, binding.authority.not_after,
      binding.approval?.approved_at, binding.ownership?.transitioned_at, binding.plan?.expires_at, input.reservation.reserved_at]
      .every((value) => Number.isFinite(reviewedGrantUtc(value)))) return fail('reviewed_grant_clock_invalid');
  if (at < issued || at >= until) return fail('reviewed_grant_expired');
  const checked = validateReviewedOperationReservation(job, input.reservation,
    { check: input.check, now: at, workerId: input.workerId, leasedAt: input.leasedAt });
  if (!checked.ok) return fail(checked.error);
  if (checked.legacy) return fail('reviewed_grant_review_required');
  const envelope = {
    version: REVIEWED_EXECUTION_GRANT_ENVELOPE_VERSION, purpose: REVIEWED_EXECUTION_GRANT_PURPOSE,
    content_canonicalization: CONTENT_CANONICALIZATION, ...signer, tenant_id: input.tenantId,
    job: { id: job.id, test_run_id: job.test_run_id, check_id: job.check_id, target_id: job.target_id, nonce_hash: job.nonce_hash },
    original_job_payload: original.canonical, original_job_signature_sha256: hash(job.job_signature),
    worker: { id: input.workerId, leased_at: input.leasedAt }, reservation: input.reservation,
    budgets: { max_probe_requests: c.max_probe_requests, max_destination_resolver_attempts: c.max_destination_resolver_attempts,
      max_total_operations: c.max_total_operations, execution_attempts: c.execution_attempts, timeout_ms: c.timeout_ms },
    authority: { issued_at: c.issued_at, original_not_after: binding.authority.original_not_after,
      not_after: c.not_after, grant_issued_at: new Date(at).toISOString() },
  };
  return { ok: true, envelope: freezeReviewedGrant(envelope) };
}

/** Pure capability contract. Caller must independently authenticate original HMAC and current DB reads. */
export function buildReviewedExecutionGrantEnvelope(input, signer) {
  try { return build(input, signer); } catch { return fail('reviewed_grant_input_invalid', 400); }
}

/** Historical comparison reconstructs at original grant issuance, never renews its deadline. */
export function validateReviewedExecutionGrantEnvelope(envelope, context, mode = 'current') {
  try {
    if (!['current', 'historical'].includes(mode) || !reviewedGrantExact(envelope, ENVELOPE_KEYS) || !reviewedGrantJson(envelope)
      || envelope.version !== REVIEWED_EXECUTION_GRANT_ENVELOPE_VERSION || envelope.purpose !== REVIEWED_EXECUTION_GRANT_PURPOSE
      || envelope.content_canonicalization !== CONTENT_CANONICALIZATION || envelope.algorithm !== 'ed25519'
      || !reviewedGrantExact(envelope.authority, ['issued_at', 'original_not_after', 'not_after', 'grant_issued_at'])
      || !reviewedGrantExact(context, INPUT_KEYS)) return fail('reviewed_grant_envelope_invalid');
    const grantedAt = reviewedGrantUtc(envelope.authority.grant_issued_at), now = reviewedGrantClock(context.now);
    if (![grantedAt, now].every(Number.isFinite) || grantedAt > now) return fail('reviewed_grant_clock_invalid');
    const rebuilt = build({ ...context, now: grantedAt }, { algorithm: envelope.algorithm, key_reference: envelope.key_reference,
      public_key_fingerprint_sha256: envelope.public_key_fingerprint_sha256 });
    if (!rebuilt.ok) return rebuilt;
    if (canonicalJsonStringify(envelope) !== canonicalJsonStringify(rebuilt.envelope)) return fail('reviewed_grant_binding_mismatch');
    if (mode === 'current' && now >= reviewedGrantUtc(envelope.authority.not_after)) return fail('reviewed_grant_expired');
    return { ok: true };
  } catch { return fail('reviewed_grant_envelope_invalid'); }
}
