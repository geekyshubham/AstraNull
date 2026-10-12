import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { canonicalJsonStringify } from '../lib/custody.mjs';
import { buildProbeProfile } from './checks.mjs';
import { deriveCheckDefinitionVersion, approvedScenarioVersion } from '../lib/checkDefinitionVersion.mjs';
import { SUPPORTED_EVASION_TRANSFORMS } from '../lib/probeEvidenceTiers.mjs';
import { dnsOwnershipProofMatchesTarget } from '../lib/dnsOwnershipTarget.mjs';
import { reviewedOperationGap, REVIEWED_OPERATION_VERSION, REVIEWED_OPERATION_MAX_LIFETIME_MS } from './reviewedOperations.mjs';

export const REVIEWED_OPERATION_BINDING_VERSION = 'reviewed-operation-binding.v1';
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const PLAN_KEYS = ['version', 'tenant_id', 'target_id', 'target_definition_digest', 'check_id', 'check_version',
  'check_definition_digest', 'scenario_version', 'endpoint', 'method', 'template', 'semantics', 'side_effects',
  'request_schema', 'expires_at', 'maximum_body_bytes', 'maximum_probe_operations'];
const BINDING_KEYS = ['version', 'review_id', 'plan_digest', 'plan', 'approval', 'ownership', 'probe_profile_digest', 'authority'];
const PROFILE_KEYS = ['kind', 'max_requests', 'timeout_ms', 'marker', 'evasion_transform', 'marker_class',
  'scenario_family', 'marker_type', 'expected_action', 'nonce_hash_only', 'collect',
  'observation_only', 'scenario_version', 'delivery_supported', 'requires_complete_comparison'];
const fail = (error, status = 409) => ({ ok: false, error, status, grants_execution: false, execution_available: false });
const success = (extra = {}) => ({ ok: true, grants_execution: false, execution_available: false, ...extra });
const hash = (value) => createHash('sha256').update(canonicalJsonStringify(value)).digest('hex');
const same = (a, b) => canonicalJsonStringify(a) === canonicalJsonStringify(b);
const id = (value) => typeof value === 'string' && ID.test(value);
const digest = (value) => typeof value === 'string' && DIGEST.test(value);

// Reject accessor, symbol and non-JSON authority rather than normalizing it away.
function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value))
    && Reflect.ownKeys(value).every((key) => typeof key === 'string'
      && Object.getOwnPropertyDescriptor(value, key)?.enumerable
      && Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'));
}
function exact(value, keys) {
  return record(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
function utc(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) return NaN;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === (value.includes('.') ? value : value.replace('Z', '.000Z')) ? time : NaN;
}
function clock(now) {
  if (now instanceof Date) return now.getTime();
  if (typeof now === 'number' && Number.isSafeInteger(now)) return now;
  return utc(now);
}
function frozenCopy(value) {
  const copy = structuredClone(value);
  function freeze(item) {
    if (item && typeof item === 'object') { Object.values(item).forEach(freeze); Object.freeze(item); }
    return item;
  }
  return freeze(copy);
}
function endpoint(value) {
  if (typeof value !== 'string' || value.length > 4096) return null;
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) && url.hostname && !url.username && !url.password
      && !url.search && !url.hash && url.href === value ? url : null;
  } catch { return null; }
}

/** Only a selection is client input. All authority comes from server reads, never this body. */
function selection(body) {
  if (!record(body)) return fail('invalid_reviewed_operation_selection', 400);
  const forbidden = /^(?:reviewed_operation(?:_.*)?|reviewed_plan(?:_.*)?|plan(?:_.*)?|operation_plan(?:_.*)?|approval(?:_.*)?|approved(?:_.*)?|actor(?:_.*)?|reviewer(?:_.*)?|approver(?:_.*)?|user_id|role|grants_execution|execution_available|original_authority|authority|ownership_binding)$/;
  const seen = new Set();
  function containsAuthority(value) {
    if (!value || typeof value !== 'object') return false;
    if (seen.has(value)) return true;
    seen.add(value);
    if (!Array.isArray(value) && !record(value)) return true;
    return Object.keys(value).some((key) => key !== 'reviewed_operation_id'
      && (forbidden.test(key.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`).replace(/[-\s]/g, '_')) || containsAuthority(value[key])));
  }
  if (containsAuthority(body)) return fail('reviewed_operation_authority_not_allowed', 400);
  if (!Object.hasOwn(body, 'reviewed_operation_id')) return success({ review_id: null, legacy: true });
  if (!id(body.reviewed_operation_id)) return fail('invalid_reviewed_operation_selection', 400);
  return success({ review_id: body.reviewed_operation_id, legacy: false });
}

/** Capability enumeration only; no serializer, request, DNS or transport is implemented here. */
function deliveryCapability(plan, check, profile = check?.probe_profile) {
  const p = check?.probe_profile;
  if (plan?.template !== 'marker-query-v1' || plan?.method !== 'GET' || plan?.request_schema !== 'fixed-asn-probe-query.v1'
    || plan?.maximum_body_bytes !== 0 || check?.safety_class !== 'safe' || !check?.supported_targets?.includes('url')
    || !record(p) || Object.keys(p).some((key) => !PROFILE_KEYS.includes(key))
    || p.kind !== 'waf_evasion_marker_probe' || !SUPPORTED_EVASION_TRANSFORMS.includes(p.evasion_transform)
    || p.evasion_transform === 'parameter_location' || !['sqli', 'xss', 'path_traversal'].includes(p.marker_class)
    || p.scenario_family !== 'marker' || p.marker_type !== 'query' || p.expected_action !== 'block'
    || p.nonce_hash_only !== true || p.observation_only !== false || p.scenario_version !== 'marker-comparison-v4'
    || p.delivery_supported !== true || p.requires_complete_comparison !== true
    || !Number.isSafeInteger(p.max_requests) || p.max_requests < 1 || p.max_requests > 4
    || !Number.isSafeInteger(p.timeout_ms) || p.timeout_ms < 1 || p.timeout_ms > 5000
    || typeof p.marker !== 'string' || p.marker.length < 1 || p.marker.length > 128
    || !Array.isArray(p.collect) || !p.collect.every((field) => typeof field === 'string')
    || !record(profile) || !same(profile, buildProbeProfile(p))) {
    return { available: false, error: 'reviewed_operation_delivery_unavailable' };
  }
  return Object.freeze({ available: true, serializer: 'marker-query-v1', method: 'GET', where: 'query', body_bytes: 0 });
}

function shapeGap(binding, now) {
  if (!exact(binding, BINDING_KEYS) || binding.version !== REVIEWED_OPERATION_BINDING_VERSION || !id(binding.review_id)
    || !digest(binding.plan_digest) || !digest(binding.probe_profile_digest) || !exact(binding.plan, PLAN_KEYS)
    || !exact(binding.approval, ['kind', 'id', 'role', 'approved_at'])
    || binding.approval.kind !== 'human' || !id(binding.approval.id) || !['owner', 'admin'].includes(binding.approval.role)
    || !exact(binding.ownership, ['kind', 'state', 'target_id', 'transitioned_at'])
    || binding.ownership.kind !== 'dns_txt' || binding.ownership.state !== 'dns_verified'
    || !exact(binding.authority, ['issued_at', 'original_not_after', 'not_after'])) return 'reviewed_operation_binding_invalid';
  const p = binding.plan, a = binding.authority;
  if (p.version !== REVIEWED_OPERATION_VERSION || !id(p.tenant_id) || !id(p.target_id) || !id(p.check_id)
    || !digest(p.target_definition_digest) || !digest(p.check_definition_digest)
    || typeof p.check_version !== 'string' || p.check_version.length < 1 || p.check_version.length > 128
    || (p.scenario_version !== null && (typeof p.scenario_version !== 'string' || p.scenario_version.length > 128))
    || !endpoint(p.endpoint) || !['marker-query-v1', 'inert-json-v1'].includes(p.template)
    || p.method !== (p.template === 'marker-query-v1' ? 'GET' : 'POST')
    || p.request_schema !== (p.template === 'marker-query-v1' ? 'fixed-asn-probe-query.v1' : 'fixed-asn-marker-json.v1')
    || p.maximum_body_bytes !== (p.template === 'marker-query-v1' ? 0 : 1024)
    || p.semantics !== 'inert_diagnostic' || p.side_effects !== 'none' || p.maximum_probe_operations !== 4
    || binding.ownership.target_id !== p.target_id || binding.plan_digest !== hash(p)) return 'reviewed_operation_binding_invalid';
  const at = clock(now), approved = utc(binding.approval.approved_at), expiry = utc(p.expires_at), owned = utc(binding.ownership.transitioned_at);
  const issued = utc(a.issued_at), original = utc(a.original_not_after), until = utc(a.not_after);
  if (![at, approved, expiry, owned, issued, original, until].every(Number.isFinite)
    || approved > at || owned > at || approved > issued || owned > issued || issued > at
    || expiry <= approved || expiry - approved > REVIEWED_OPERATION_MAX_LIFETIME_MS
    || original <= issued || original - issued > 120_000 || until !== Math.min(original, expiry) || until <= issued) return 'reviewed_operation_clock_invalid';
  if (expiry <= at) return 'operation_expired';
  if (until <= at) return 'probe_authority_expired';
  return null;
}

/** Inputs must be actual current server rows; this function is not a DB-read substitute. */
function buildBinding({ reviewId, review, tenantId, target, check, ownership, originalAuthority, now } = {}) {
  if (!Number.isFinite(clock(now))) return fail('reviewed_operation_clock_invalid');
  if (!id(reviewId) || !record(review) || review.id !== reviewId || !id(tenantId)) return fail('operation_not_found', 404);
  if (!id(review.approved_by) || !['owner', 'admin'].includes(review.approved_role)
    || review.service_account_id != null || review.approved_actor_kind != null && review.approved_actor_kind !== 'human'
    || !Number.isFinite(utc(review.approved_at))) return fail('operation_review_invalid');
  if (!exact(review.plan, PLAN_KEYS)) return fail('operation_review_invalid');
  if (review.revoked_at != null || review.revoked_by != null) return fail('operation_revoked');
  if (target?.deleted_at != null) return fail('operation_target_changed');
  const gap = reviewedOperationGap(review, { tenantId, target, check, now });
  if (gap) return fail(gap);
  if (!record(ownership) || ownership.tenant_id !== tenantId || ownership.target_id !== target.id
    || ownership.state !== 'dns_verified' || ownership.source_kind !== 'dns_txt'
    || ownership.provider_provenance != null || ownership.inherited_from_target_id != null
    || ownership.revoked_at != null || ownership.deleted_at != null || !Number.isFinite(utc(ownership.transitioned_at))
    || !dnsOwnershipProofMatchesTarget(target, ownership)) return fail('ownership_not_verified');
  if (!exact(originalAuthority, ['issued_at', 'not_after'])) return fail('probe_authority_invalid');
  const expiry = utc(review.plan.expires_at), original = utc(originalAuthority.not_after);
  if (!Number.isFinite(original) || !Number.isFinite(expiry)) return fail('reviewed_operation_clock_invalid');
  const binding = {
    version: REVIEWED_OPERATION_BINDING_VERSION, review_id: review.id, plan_digest: review.plan_digest,
    plan: review.plan, approval: { kind: 'human', id: review.approved_by, role: review.approved_role, approved_at: review.approved_at },
    ownership: { kind: ownership.source_kind, state: ownership.state, target_id: ownership.target_id, transitioned_at: ownership.transitioned_at },
    probe_profile_digest: hash(buildProbeProfile(check.probe_profile)),
    authority: { issued_at: originalAuthority.issued_at, original_not_after: originalAuthority.not_after,
      not_after: new Date(Math.min(original, expiry)).toISOString() },
  };
  const malformed = shapeGap(binding, now);
  if (malformed) return fail(malformed);
  const delivery = reviewedOperationDelivery(binding.plan, check, buildProbeProfile(check.probe_profile));
  if (!delivery.available) return fail(delivery.error);
  return success({ binding: frozenCopy(binding), delivery });
}

/** Admission/recovery/reservation re-read and compare immutable identity, actor, plan and proof. */
function validateCurrent(binding, context = {}) {
  if (binding === undefined) return success({ legacy: true });
  const malformed = shapeGap(binding, context.now);
  if (malformed) return fail(malformed);
  const current = buildReviewedOperationBinding({ ...context, reviewId: binding.review_id,
    originalAuthority: { issued_at: binding.authority.issued_at, not_after: binding.authority.original_not_after } });
  if (!current.ok) return current;
  if (!same(binding, current.binding)) return fail('reviewed_operation_binding_changed');
  return success({ binding: current.binding, delivery: current.delivery, legacy: false });
}

function signedGap(job, binding, check, now) {
  if (!record(job) || !record(job.constraints)) return 'reviewed_operation_binding_invalid';
  const malformed = shapeGap(binding, now);
  if (malformed) return malformed;
  const p = binding.plan, c = job.constraints, t = job.target, url = endpoint(p.endpoint);
  // Full DB target digests are checked ONLY by validateCurrent...; a worker descriptor omits material columns.
  if (job.tenant_id !== p.tenant_id || job.target_id !== p.target_id || job.check_id !== p.check_id || !record(t) || t.id !== p.target_id || t.kind !== 'url'
    || Object.keys(t).some((key) => !['id', 'kind', 'value', 'expected_behavior', 'port', 'protocol', 'metadata'].includes(key))
    || typeof t.value !== 'string') return 'reviewed_operation_destination_mismatch';
  let actual;
  try { actual = new URL(t.value); } catch { return 'reviewed_operation_destination_mismatch'; }
  if (actual.href !== p.endpoint || actual.username || actual.password || actual.search || actual.hash
    || t.port != null && t.port !== Number(url.port || (url.protocol === 'https:' ? 443 : 80))
    || t.protocol != null && ![url.protocol, url.protocol.slice(0, -1)].includes(t.protocol)) return 'reviewed_operation_destination_mismatch';
  const version = deriveCheckDefinitionVersion(check);
  if (check?.check_id !== p.check_id || version.check_version !== p.check_version || version.digest !== p.check_definition_digest
    || approvedScenarioVersion(check) !== p.scenario_version) return 'operation_check_changed';
  const delivery = reviewedOperationDelivery(p, check, job.probe_profile);
  if (!delivery.available) return delivery.error;
  if (binding.probe_profile_digest !== hash(job.probe_profile)) return 'reviewed_operation_profile_mismatch';
  if (c.authority_version !== 'probe-authority-v2' || c.issued_at !== binding.authority.issued_at
    || c.not_after !== binding.authority.not_after) return 'probe_authority_invalid';
  const resolver = isIP(url.hostname.replace(/^\[|\]$/g, '')) ? 0 : 2;
  if (!Number.isSafeInteger(c.max_probe_requests) || c.max_probe_requests < 1 || c.max_probe_requests > 4
    || c.max_probe_requests > job.probe_profile.max_requests
    || c.min_destination_resolver_attempts !== resolver || c.max_destination_resolver_attempts !== resolver
    || c.max_total_operations !== c.max_probe_requests + resolver || c.max_requests !== c.max_total_operations
    || c.execution_attempts !== 1 || !Number.isSafeInteger(c.timeout_ms) || c.timeout_ms < 1
    || c.timeout_ms > job.probe_profile.timeout_ms
    || ['retry_attempts', 'retries', 'refunds', 'budget_refunds'].some((key) => Object.hasOwn(c, key))) return 'probe_operation_budget_invalid';
  if (!same(c.ownership_binding, binding.ownership)) return 'reviewed_operation_ownership_mismatch';
  return null;
}

function reservationGap(job, reservation, { now, workerId, leasedAt }) {
  const c = job.constraints, b = c.reviewed_operation_binding;
  if (!exact(reservation, ['version', 'id', 'worker_id', 'leased_at', 'reserved_at', 'not_after', 'max_probe_requests',
    'max_destination_resolver_attempts', 'max_total_operations', 'state', 'reviewed_operation'])
    || reservation.version !== 'execution-reservation.v1' || reservation.state !== 'reserved_unknown'
    || !id(reservation.id) || !id(reservation.worker_id) || !id(workerId) || !Number.isFinite(utc(leasedAt))
    || job.leased_by !== workerId || job.leased_at !== leasedAt
    || reservation.worker_id !== workerId || reservation.leased_at !== leasedAt
    || !exact(reservation.reviewed_operation, ['binding_version', 'review_id', 'plan_version', 'plan_digest'])
    || !same(reservation.reviewed_operation, { binding_version: b.version, review_id: b.review_id, plan_version: b.plan.version, plan_digest: b.plan_digest })
    || ['not_after', 'max_probe_requests', 'max_destination_resolver_attempts', 'max_total_operations'].some((key) => reservation[key] !== c[key])) return 'reviewed_operation_reservation_mismatch';
  const reserved = utc(reservation.reserved_at), leased = utc(reservation.leased_at), at = clock(now);
  if (![reserved, leased, at].every(Number.isFinite) || leased < utc(c.issued_at) || reserved < leased
    || reserved >= utc(c.not_after) || reserved > at) return 'reviewed_operation_reservation_mismatch';
  return null;
}

/** Invoke AFTER ORIGINAL job signature verification and BEFORE DNS; not an execution grant. */
function validateSigned(job, options = {}) {
  if (!record(options) || Object.keys(options).some((key) => !['check', 'now'].includes(key))) return fail('reviewed_operation_validation_options_invalid');
  if (!Object.hasOwn(job?.constraints ?? {}, 'reviewed_operation_binding')) return success({ legacy: true });
  // Jobs are signed while pending. A reservation must NEVER be inserted into that signed payload,
  // even by re-signing it: a later independent grant carries reservation authority separately.
  if (Object.hasOwn(job.constraints, 'execution_reservation')) return fail('reviewed_operation_original_job_mutated');
  const binding = job.constraints.reviewed_operation_binding;
  const gap = signedGap(job, binding, options.check, options.now);
  if (gap) return fail(gap);
  return success({ legacy: false, binding: frozenCopy(binding), delivery: reviewedOperationDelivery(binding.plan, options.check, job.probe_profile) });
}

/**
 * Pure structural comparison only. Caller MUST first verify the original job signature AND
 * the actual independent execution-grant envelope signature and its binding to this original
 * job identity. Those cryptographic/runtime integrations are not implemented here. There is
 * no authorization boolean substitute. workerId/leasedAt must come from authenticated lease
 * context, not the reservation or worker_metadata. Neither the job nor reservation is mutated.
 */
function validateReservation(job, reservation, options = {}) {
  if (!record(options) || Object.keys(options).some((key) => !['check', 'now', 'workerId', 'leasedAt'].includes(key))) return fail('reviewed_operation_validation_options_invalid');
  const checked = validateSignedReviewedOperationBinding(job, { check: options.check, now: options.now });
  if (!checked.ok || checked.legacy) return checked;
  const gap = reservationGap(job, reservation, options);
  if (gap) return fail(gap);
  return checked;
}

// Malformed JSON-like input never escapes as a coercion/canonicalization exception.
function guarded(work, error = 'reviewed_operation_binding_invalid', status = 409) {
  try { return work(); } catch { return fail(error, status); }
}
export function validateReviewedOperationSelection(body) {
  return guarded(() => selection(body), 'invalid_reviewed_operation_selection', 400);
}
export function reviewedOperationDelivery(plan, check, profile) {
  try { return deliveryCapability(plan, check, profile); }
  catch { return { available: false, error: 'reviewed_operation_delivery_unavailable' }; }
}
export function buildReviewedOperationBinding(context) {
  return guarded(() => buildBinding(context));
}
export function validateCurrentReviewedOperationBinding(binding, context) {
  return guarded(() => validateCurrent(binding, context));
}
export function validateSignedReviewedOperationBinding(job, options) {
  return guarded(() => validateSigned(job, options));
}
export function validateReviewedOperationReservation(job, reservation, options) {
  return guarded(() => validateReservation(job, reservation, options));
}
