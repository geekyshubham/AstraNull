import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { buildReviewedOperationPlan } from '../../src/contracts/reviewedOperations.mjs';
import { getCheckById, buildProbeProfile } from '../../src/contracts/checks.mjs';
import { canonicalJsonStringify } from '../../src/lib/custody.mjs';
import { dnsOwnershipTargetBinding } from '../../src/lib/dnsOwnershipTarget.mjs';
import { SUPPORTED_EVASION_TRANSFORMS } from '../../src/lib/probeEvidenceTiers.mjs';
import { applyEvasionTransform, buildEvasionRequest } from '../../src/lib/vectorProbes/evasionProbes.mjs';
import { targetDescriptor, signProbeJob, verifyProbeJobSignature } from '../../src/lib/probeJobs.mjs';
import {
  REVIEWED_OPERATION_BINDING_VERSION, validateReviewedOperationSelection, reviewedOperationDelivery,
  buildReviewedOperationBinding, validateCurrentReviewedOperationBinding, validateSignedReviewedOperationBinding,
  validateReviewedOperationReservation,
} from '../../src/contracts/reviewedOperationBinding.mjs';

const AT = '2026-10-10T00:00:00.000Z';
const UNTIL = '2026-10-10T00:02:00.000Z';
const hash = (value) => createHash('sha256').update(canonicalJsonStringify(value)).digest('hex');
function fixture(checkId = 'waf.evasion_base64_wrap.safe', template = 'marker-query-v1') {
  const check = structuredClone(getCheckById(checkId));
  const target = { id: 'tgt_review', tenant_id: 'ten_test', kind: 'url', value: 'https://owned.example.test/diagnostic',
    target_group_id: 'tg_test', declaration_json: { operation: 'inert' }, expected_behavior: 'must_block_before_origin' };
  const proposal = buildReviewedOperationPlan({ target_id: target.id, check_id: check.check_id, template,
    semantics: 'inert_diagnostic', side_effects: 'none', expires_at: '2026-10-10T01:00:00.000Z' },
  { tenantId: target.tenant_id, target, check, now: AT });
  return { tenantId: target.tenant_id, reviewId: 'rop_test', target, check, now: AT,
    originalAuthority: { issued_at: AT, not_after: UNTIL },
    ownership: { id: 'verification_test', tenant_id: target.tenant_id, target_id: target.id, state: 'dns_verified',
      source_kind: 'dns_txt', source_ref: { dns_target_binding: dnsOwnershipTargetBinding(target) },
      transitioned_at: '2026-10-09T00:00:00.000Z' },
    review: { id: 'rop_test', tenant_id: target.tenant_id, target_id: target.id, plan: proposal.plan,
      plan_digest: proposal.plan_digest, approved_by: 'usr_reviewer', approved_role: 'admin', approved_at: AT,
      revoked_at: null, revoked_by: null } };
}
function bound(context = fixture()) {
  const result = buildReviewedOperationBinding(context);
  assert.equal(result.ok, true, JSON.stringify(result));
  return structuredClone(result.binding);
}
function job(context = fixture()) {
  const binding = bound(context);
  return { id: 'job_test', test_run_id: 'run_test', tenant_id: context.tenantId, target_id: context.target.id,
    check_id: context.check.check_id, target: targetDescriptor(context.target), probe_profile: buildProbeProfile(context.check.probe_profile),
    nonce_hash: 'a'.repeat(64), constraints: { authority_version: 'probe-authority-v2', issued_at: binding.authority.issued_at,
      not_after: binding.authority.not_after, execution_attempts: 1, timeout_ms: 5000,
      max_probe_requests: 4, min_destination_resolver_attempts: 2, max_destination_resolver_attempts: 2,
      max_total_operations: 6, max_requests: 6, ownership_binding: structuredClone(binding.ownership), reviewed_operation_binding: binding } };
}
function reservation(j) {
  const b = j.constraints.reviewed_operation_binding;
  return { version: 'execution-reservation.v1', id: 'res_test', worker_id: 'worker_test', leased_at: AT, reserved_at: AT,
    not_after: j.constraints.not_after, max_probe_requests: j.constraints.max_probe_requests,
    max_destination_resolver_attempts: j.constraints.max_destination_resolver_attempts,
    max_total_operations: j.constraints.max_total_operations, state: 'reserved_unknown',
    reviewed_operation: { binding_version: b.version, review_id: b.review_id, plan_version: b.plan.version, plan_digest: b.plan_digest } };
}
function offline(j, options = {}) { return validateSignedReviewedOperationBinding(j, { check: fixture().check, now: AT, ...options }); }
function leasedJob() { return { ...job(), leased_by: 'worker_test', leased_at: AT }; }
// Structural fixtures only: no independent execution-grant signature or runtime is implemented.
function checkReservation(j, r, options = {}) {
  return validateReviewedOperationReservation(j, r, { check: fixture().check, now: AT, workerId: 'worker_test', leasedAt: AT, ...options });
}
function denied(result, error) {
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.equal(result.grants_execution, false);
  assert.equal(result.execution_available, false);
  if (error) assert.equal(result.error, error);
  assert.ok(Number.isInteger(result.status));
}

for (const body of [{}, { target_id: 'tgt_old', check_id: 'l7.http.safe', probe_profile: { timeout_ms: 1000 } }]) {
  test('selection omission retains ordinary legacy run body', () => assert.deepEqual(validateReviewedOperationSelection(body),
    { ok: true, grants_execution: false, execution_available: false, review_id: null, legacy: true }));
}
test('selection accepts only bounded typed explicit review identity', () => {
  assert.equal(validateReviewedOperationSelection({ reviewed_operation_id: 'rop_test' }).review_id, 'rop_test');
  assert.equal(validateReviewedOperationSelection({ reviewed_operation_id: 'a'.repeat(128) }).ok, true);
});
for (const value of [null, undefined, true, false, 0, 1, [], {}, ['rop_test'], '', ' rop_test', 'rop_test ', 'a'.repeat(129), 'x/other', '\nuser']) {
  test(`selection rejects ${JSON.stringify(value)}`, () => denied(validateReviewedOperationSelection({ reviewed_operation_id: value }), 'invalid_reviewed_operation_selection'));
}
for (const body of [null, undefined, [], 'rop_test', new Date(), Object.create({ reviewed_operation_id: 'rop_test' })]) {
  test('selection rejects non-plain bodies and inherited identity', () => denied(validateReviewedOperationSelection(body)));
}
for (const key of ['reviewed_operation_binding', 'reviewed_operation_plan', 'reviewed_operation_digest', 'reviewed_operation_approval',
  'reviewed_operation_actor', 'reviewed_operation_snapshot', 'reviewed_plan', 'reviewed_plan_digest', 'plan', 'plan_digest',
  'approval', 'approved_by', 'approved_role', 'approved_at', 'actor', 'actor_id', 'reviewer', 'reviewer_id',
  'grants_execution', 'execution_available', 'original_authority', 'reviewedOperationBinding', 'approvedBy']) {
  for (const nested of [false, true]) test(`selection rejects ${nested ? 'nested ' : ''}caller ${key}`, () => {
    const injected = { [key]: null };
    denied(validateReviewedOperationSelection(nested ? { metadata: [injected] } : injected), 'reviewed_operation_authority_not_allowed');
  });
}
test('selection rejects accessors, symbol fields and cyclic authority', () => {
  let invoked = false;
  const getter = Object.defineProperty({}, 'reviewed_operation_id', { enumerable: true, get() { invoked = true; return 'rop_test'; } });
  denied(validateReviewedOperationSelection(getter)); assert.equal(invoked, false);
  denied(validateReviewedOperationSelection({ [Symbol('authority')]: true }));
  const cyclic = {}; cyclic.metadata = cyclic;
  denied(validateReviewedOperationSelection(cyclic));
});

test('builder pins full reviewed plan, typed human, proof, profile and original authority without granting execution', () => {
  const c = fixture(), result = buildReviewedOperationBinding(c), b = result.binding;
  assert.equal(result.ok, true);
  assert.equal(result.grants_execution, false); assert.equal(result.execution_available, false);
  assert.equal(b.version, REVIEWED_OPERATION_BINDING_VERSION);
  assert.equal(b.review_id, c.review.id); assert.equal(b.plan_digest, c.review.plan_digest);
  assert.deepEqual(b.plan, c.review.plan);
  assert.deepEqual(b.approval, { kind: 'human', id: c.review.approved_by, role: 'admin', approved_at: AT });
  assert.equal(b.authority.original_not_after, UNTIL); assert.equal(b.authority.not_after, UNTIL);
  assert.deepEqual(result.delivery, { available: true, serializer: 'marker-query-v1', method: 'GET', where: 'query', body_bytes: 0 });
  c.review.plan.endpoint = 'https://foreign.example.test/'; c.review.approved_by = 'usr_changed'; c.ownership.state = 'unverified';
  c.originalAuthority.not_after = '2026-10-11T00:00:00.000Z';
  assert.equal(b.plan.endpoint, c.target.value); assert.equal(b.approval.id, 'usr_reviewer'); assert.equal(b.ownership.state, 'dns_verified');
  assert.equal(b.authority.not_after, UNTIL);
  for (const value of [b, b.plan, b.approval, b.ownership, b.authority]) assert.ok(Object.isFrozen(value));
  assert.throws(() => { b.plan.method = 'DELETE'; }, TypeError);
});
test('owner role is accepted; approved time and immutable actor are current-row authority', () => {
  const c = fixture(); c.review.approved_role = 'owner';
  assert.equal(buildReviewedOperationBinding(c).ok, true);
});
for (const [label, mutate, error] of [
  ['missing URL proof material binding', (c) => { delete c.ownership.source_ref; }, 'ownership_not_verified'],
  ['wrong URL proof material digest', (c) => { c.ownership.source_ref.dns_target_binding.definition_digest = '0'.repeat(64); }, 'ownership_not_verified'],
  ['foreign URL proof material target', (c) => { c.ownership.source_ref.dns_target_binding.target_id = 'tgt_other'; }, 'ownership_not_verified'],
  ['missing review', (c) => { c.review = null; }, 'operation_not_found'],
  ['wrong selected review', (c) => { c.reviewId = 'rop_other'; }, 'operation_not_found'],
  ['foreign review tenant', (c) => { c.review.tenant_id = 'ten_other'; }, 'operation_not_found'],
  ['foreign plan tenant', (c) => { c.review.plan.tenant_id = 'ten_other'; }, 'operation_review_invalid'],
  ['foreign target', (c) => { c.target.tenant_id = 'ten_other'; }, 'operation_target_changed'],
  ['revoked', (c) => { c.review.revoked_at = AT; }, 'operation_revoked'],
  ['review actor object', (c) => { c.review.approved_by = {}; }, 'operation_review_invalid'],
  ['review actor array', (c) => { c.review.approved_by = ['usr_test']; }, 'operation_review_invalid'],
  ['review actor absent', (c) => { delete c.review.approved_by; }, 'operation_review_invalid'],
  ['review actor oversized', (c) => { c.review.approved_by = 'u'.repeat(129); }, 'operation_review_invalid'],
  ['service account', (c) => { c.review.service_account_id = 'svc_test'; }, 'operation_review_invalid'],
  ['actor kind service', (c) => { c.review.approved_actor_kind = 'service'; }, 'operation_review_invalid'],
  ['role engineer', (c) => { c.review.approved_role = 'engineer'; }, 'operation_review_invalid'],
  ['role SOC', (c) => { c.review.approved_role = 'soc'; }, 'operation_review_invalid'],
  ['role array', (c) => { c.review.approved_role = ['admin']; }, 'operation_review_invalid'],
  ['approval malformed', (c) => { c.review.approved_at = '2026-10-10'; }, 'operation_review_invalid'],
  ['approval calendar rollover', (c) => { c.review.approved_at = '2026-02-30T00:00:00Z'; }, 'operation_review_invalid'],
  ['approval future', (c) => { c.review.approved_at = UNTIL; }, 'operation_review_invalid'],
  ['deleted target', (c) => { c.target.deleted_at = AT; }, 'operation_target_changed'],
  ['changed endpoint', (c) => { c.target.value += '/other'; }, 'operation_target_changed'],
  ['changed declaration', (c) => { c.target.declaration_json.operation = 'business'; }, 'operation_target_changed'],
  ['changed port', (c) => { c.target.port = 8443; }, 'operation_target_changed'],
  ['changed protocol', (c) => { c.target.protocol = 'http'; }, 'operation_target_changed'],
  ['changed target kind', (c) => { c.target.kind = 'fqdn'; }, 'operation_target_changed'],
  ['changed group material', (c) => { c.target.target_group_id = 'tg_other'; }, 'operation_target_changed'],
  ['changed expected behavior', (c) => { c.target.expected_behavior = 'must_allow'; }, 'operation_target_changed'],
  ['missing check', (c) => { c.check = null; }, 'operation_check_changed'],
  ['changed check description', (c) => { c.check.description += 'change'; }, 'operation_check_changed'],
  ['changed check profile', (c) => { c.check.probe_profile.timeout_ms = 99; }, 'operation_check_changed'],
  ['changed check version', (c) => { c.check.version = '2.0.0'; }, 'operation_check_changed'],
  ['changed scenario', (c) => { c.check.probe_profile.scenario_family = 'business'; }, 'operation_check_changed'],
  ['expired review', (c) => { c.now = c.review.plan.expires_at; }, 'operation_expired'],
]) test(`builder rejects ${label}`, () => { const c = fixture(); mutate(c); denied(buildReviewedOperationBinding(c), error); });

for (const [label, mutate] of [
  ['absent', (c) => { c.ownership = undefined; }], ['boolean', (c) => { c.ownership = true; }],
  ['foreign tenant', (c) => { c.ownership.tenant_id = 'ten_other'; }], ['foreign target', (c) => { c.ownership.target_id = 'tgt_other'; }],
  ['unverified', (c) => { c.ownership.state = 'unverified'; }], ['legacy agent', (c) => { c.ownership.state = 'agent_verified'; }],
  ['provider', (c) => { c.ownership.state = 'provider_verified'; c.ownership.source_kind = 'provider_account'; }],
  ['provider provenance', (c) => { c.ownership.provider_provenance = {}; }],
  ['inherited', (c) => { c.ownership.inherited_from_target_id = 'tgt_parent'; }],
  ['attestation', (c) => { c.ownership.state = 'user_confirmed'; c.ownership.source_kind = 'user_attestation'; }],
  ['manual', (c) => { c.ownership.source_kind = 'manual_override'; }],
  ['unsupported http proof', (c) => { c.ownership.source_kind = 'http_file'; }],
  ['revoked', (c) => { c.ownership.revoked_at = AT; }], ['deleted', (c) => { c.ownership.deleted_at = AT; }],
  ['clock array', (c) => { c.ownership.transitioned_at = [AT]; }], ['clock malformed', (c) => { c.ownership.transitioned_at = '2026-10-09'; }],
]) test(`builder rejects ${label} ownership`, () => { const c = fixture(); mutate(c); denied(buildReviewedOperationBinding(c), 'ownership_not_verified'); });

for (const [field, value] of [['method', 'DELETE'], ['request_schema', 'arbitrary'], ['maximum_body_bytes', 100],
  ['maximum_probe_operations', 5], ['side_effects', 'send_email'], ['semantics', 'business'], ['version', 'future.v2'],
  ['endpoint', 'https://other.example.test/'], ['extra_authority', true]]) {
  test(`builder rejects re-digested fabricated ${field}`, () => {
    const c = fixture(); c.review.plan[field] = value; c.review.plan_digest = hash(c.review.plan);
    denied(buildReviewedOperationBinding(c));
  });
}
for (const invalid of [null, undefined, {}, { issued_at: AT }, { issued_at: AT, not_after: UNTIL, retry: true },
  { issued_at: '2026-10-10', not_after: UNTIL }, { issued_at: AT, not_after: AT },
  { issued_at: AT, not_after: '2026-10-10T00:02:00.001Z' }, { issued_at: [AT], not_after: UNTIL },
  { issued_at: AT, not_after: '2026-02-30T00:00:00Z' }]) {
  test('builder requires bounded original two-minute authority', () => { const c = fixture(); c.originalAuthority = invalid; denied(buildReviewedOperationBinding(c)); });
}
for (const now of [undefined, null, 'invalid', '2026-10-10', '2026-02-30T00:00:00Z', Infinity, NaN, {}, [], new Date(NaN)]) {
  test('builder rejects malformed clock', () => { const c = fixture(); c.now = now; denied(buildReviewedOperationBinding(c), 'reviewed_operation_clock_invalid'); });
}
test('deadline is capped by review expiry, not renewed at recovery', () => {
  const c = fixture(); c.review.plan.expires_at = '2026-10-10T00:01:00.000Z'; c.review.plan_digest = hash(c.review.plan);
  const b = bound(c); assert.equal(b.authority.not_after, c.review.plan.expires_at);
  c.now = '2026-10-10T00:00:30.000Z';
  const checked = validateCurrentReviewedOperationBinding(b, c);
  assert.equal(checked.ok, true); assert.equal(checked.binding.authority.not_after, '2026-10-10T00:01:00.000Z');
  c.now = '2026-10-10T00:01:00.000Z'; denied(validateCurrentReviewedOperationBinding(b, c), 'operation_expired');
});
test('authority elapsed is terminal even when review remains valid; future-issued authority is rejected', () => {
  const c = fixture(), b = bound(c); c.now = UNTIL;
  denied(validateCurrentReviewedOperationBinding(b, c), 'probe_authority_expired');
  c.now = AT; c.originalAuthority = { issued_at: UNTIL, not_after: '2026-10-10T00:03:00.000Z' };
  denied(buildReviewedOperationBinding(c), 'reviewed_operation_clock_invalid');
});
test('proof after original issuance cannot recover authority', () => {
  const c = fixture(); c.now = '2026-10-10T00:00:20.000Z'; c.ownership.transitioned_at = '2026-10-10T00:00:10.000Z';
  denied(buildReviewedOperationBinding(c), 'reviewed_operation_clock_invalid');
});

for (const transform of SUPPORTED_EVASION_TRANSFORMS.filter((t) => t !== 'parameter_location')) {
  test(`existing exact query serializer capability is enumerated for ${transform}`, () => {
    const checkId = `waf.evasion_${transform}.safe`;
    const c = fixture();
    // Some supported transforms use older catalog identities; retaining the actual definition is mandatory.
    const current = getCheckById(checkId);
    if (current) assert.equal(buildReviewedOperationBinding(fixture(checkId)).ok, true);
    else {
      c.check.probe_profile.evasion_transform = transform;
      assert.equal(reviewedOperationDelivery(c.review.plan, c.check, buildProbeProfile(c.check.probe_profile)).available, true);
    }
  });
}
for (const checkId of ['waf.evasion_parameter_location.safe', 'waf.evasion_path_matrix.safe', 'waf.evasion_path_suffix.safe',
  'waf.evasion_body_gzip.safe', 'waf.evasion_body_nested_encoding.safe', 'waf.evasion_parser_header_dup.safe',
  'waf.evasion_parser_json_dup.safe', 'waf.evasion_json_unicode_escape.safe', 'waf.evasion_alt_charset.safe',
  'waf.evasion_method_override.safe', 'waf.evasion_framing_cl_te.safe', 'waf.evasion_protocol_upgrade.safe', 'waf.inspection_limit.safe']) {
  test(`delivery fails closed for existing unsupported/cookie/path/body/header/HEAD ${checkId}`, () => {
    denied(buildReviewedOperationBinding(fixture(checkId)), 'reviewed_operation_delivery_unavailable');
  });
}
test('inert-json approval has no shipped serializer and fails closed', () => {
  const c = fixture('waf.evasion_base64_wrap.safe', 'inert-json-v1');
  denied(buildReviewedOperationBinding(c), 'reviewed_operation_delivery_unavailable');
  assert.equal(reviewedOperationDelivery(c.review.plan, c.check).available, false);
});
for (const [key, value] of [['entry_path_scenario', 'declared_login_path'], ['permitted_baseline', true], ['http_method', 'HEAD'],
  ['probe_path', '/other'], ['headers', {}], ['raw_body', '{}'], ['declared_block_signature', { status: 403 }],
  ['cookie', 'inert'], ['method', 'POST'], ['evasion_transform', 'not_a_serializer'], ['max_requests', 5], ['timeout_ms', 5001]]) {
  test(`no definition/profile override can enable delivery via ${key}`, () => {
    const c = fixture(); c.check.probe_profile[key] = value;
    assert.equal(reviewedOperationDelivery(c.review.plan, c.check, c.check.probe_profile).available, false);
  });
}

test('current validation accepts only reconstructed current review; presentation edits are immaterial', () => {
  const c = fixture(), b = bound(c); c.target.tags = ['new']; c.target.name = 'Renamed'; c.target.updated_at = UNTIL;
  assert.equal(validateCurrentReviewedOperationBinding(b, c).ok, true);
});
for (const [label, mutate] of [
  ['actual review changed ID', (c) => { c.review.id = 'rop_other'; }],
  ['actual review changed actor', (c) => { c.review.approved_by = 'usr_other'; }],
  ['actual review changed role', (c) => { c.review.approved_role = 'owner'; }],
  ['actual review changed approval time', (c) => { c.review.approved_at = '2026-10-09T23:59:59.000Z'; }],
  ['actual review revoked', (c) => { c.review.revoked_at = AT; }],
  ['actual review removed', (c) => { c.review = undefined; }],
  ['actual target removed', (c) => { c.target = undefined; }],
  ['actual ownership replaced', (c) => { c.ownership.transitioned_at = '2026-10-09T12:00:00.000Z'; }],
  ['actual expiry edited', (c) => { c.review.plan.expires_at = '2026-10-10T02:00:00.000Z'; c.review.plan_digest = hash(c.review.plan); }],
]) test(`current admission/recovery/reservation rejects ${label}`, () => {
  const c = fixture(), b = bound(c); mutate(c); denied(validateCurrentReviewedOperationBinding(b, c));
});

for (const mutate of [
  (b) => { b.extra = true; }, (b) => { delete b.plan; }, (b) => { b.version = 'v2'; }, (b) => { b.review_id = []; },
  (b) => { b.plan.extra = true; b.plan_digest = hash(b.plan); }, (b) => { b.plan_digest = 'A'.repeat(64); },
  (b) => { b.plan.maximum_probe_operations = 5; b.plan_digest = hash(b.plan); },
  (b) => { b.plan.maximum_body_bytes = 1; b.plan_digest = hash(b.plan); },
  (b) => { b.plan.method = 'HEAD'; b.plan_digest = hash(b.plan); },
  (b) => { b.plan.request_schema = 'custom'; b.plan_digest = hash(b.plan); },
  (b) => { b.plan.endpoint += '?probe=inert'; b.plan_digest = hash(b.plan); },
  (b) => { b.plan.endpoint += '#fragment'; b.plan_digest = hash(b.plan); },
  (b) => { b.plan.endpoint = 'https://user:pass@owned.example.test/diagnostic'; b.plan_digest = hash(b.plan); },
  (b) => { b.approval.extra = true; }, (b) => { b.approval.kind = 'service'; }, (b) => { b.approval.id = {}; },
  (b) => { b.approval.role = 'viewer'; }, (b) => { b.approval.approved_at = ['2026-10-10T00:00:00Z']; },
  (b) => { b.ownership.provider_provenance = {}; }, (b) => { b.ownership.target_id = 'tgt_other'; },
  (b) => { b.ownership.state = 'user_confirmed'; }, (b) => { b.ownership.kind = 'provider_account'; },
  (b) => { b.ownership.transitioned_at = 'bad'; }, (b) => { b.authority.extra = true; },
  (b) => { b.authority.issued_at = '2026-10-10'; }, (b) => { b.authority.not_after = '2026-10-10T00:02:00.001Z'; },
  (b) => { b.authority.original_not_after = '2026-10-10T00:02:00.001Z'; b.authority.not_after = b.authority.original_not_after; },
  (b) => { b.probe_profile_digest = 'bad'; },
]) test('strict stored/signed binding reconstruction rejects tamper', () => {
  const c = fixture(), b = bound(c); mutate(b);
  denied(validateCurrentReviewedOperationBinding(b, c));
  const j = job(c); j.constraints.reviewed_operation_binding = b; denied(offline(j));
});

test('offline checks descriptor destination separately from unavailable full DB target digest', () => {
  const c = fixture(), j = job(c);
  assert.equal(j.target.tenant_id, undefined); assert.equal(j.target.declaration_json, undefined);
  assert.equal(offline(j).ok, true);
  assert.notEqual(j.constraints.reviewed_operation_binding.plan.target_definition_digest,
    buildReviewedOperationPlan({ target_id: c.target.id, check_id: c.check.check_id, template: 'marker-query-v1',
      semantics: 'inert_diagnostic', side_effects: 'none', expires_at: c.review.plan.expires_at },
    { tenantId: c.tenantId, target: { ...j.target, tenant_id: c.tenantId }, check: c.check, now: AT }).plan.target_definition_digest);
});
for (const [label, mutate, error] of [
  ['foreign tenant', (j) => { j.tenant_id = 'ten_other'; }, 'reviewed_operation_destination_mismatch'],
  ['conflicting signed target identity', (j) => { j.target_id = 'tgt_other'; }, 'reviewed_operation_destination_mismatch'],
  ['missing signed target identity', (j) => { delete j.target_id; }, 'reviewed_operation_destination_mismatch'],
  ['coerced signed target identity', (j) => { j.target_id = [j.target_id]; }, 'reviewed_operation_destination_mismatch'],
  ['wrong check', (j) => { j.check_id = 'other.safe'; }, 'reviewed_operation_destination_mismatch'],
  ['missing destination', (j) => { j.target = undefined; }, 'reviewed_operation_destination_mismatch'],
  ['destination DB fields supplied', (j) => { j.target.declaration_json = {}; }, 'reviewed_operation_destination_mismatch'],
  ['changed target ID', (j) => { j.target.id = 'tgt_other'; }, 'reviewed_operation_destination_mismatch'],
  ['changed kind', (j) => { j.target.kind = 'fqdn'; }, 'reviewed_operation_destination_mismatch'],
  ['changed URL path', (j) => { j.target.value += '/other'; }, 'reviewed_operation_destination_mismatch'],
  ['changed URL query', (j) => { j.target.value += '?old=1'; }, 'reviewed_operation_destination_mismatch'],
  ['changed URL fragment', (j) => { j.target.value += '#old'; }, 'reviewed_operation_destination_mismatch'],
  ['changed URL host', (j) => { j.target.value = 'https://foreign.example.test/diagnostic'; }, 'reviewed_operation_destination_mismatch'],
  ['credentials', (j) => { j.target.value = 'https://usr:pwd@owned.example.test/diagnostic'; }, 'reviewed_operation_destination_mismatch'],
  ['destination coercion', (j) => { j.target.value = [j.target.value]; }, 'reviewed_operation_destination_mismatch'],
  ['conflicting port', (j) => { j.target.port = 80; }, 'reviewed_operation_destination_mismatch'],
  ['coerced port', (j) => { j.target.port = '443'; }, 'reviewed_operation_destination_mismatch'],
  ['conflicting protocol', (j) => { j.target.protocol = 'http'; }, 'reviewed_operation_destination_mismatch'],
  ['renewed deadline', (j) => { j.constraints.not_after = '2026-10-10T00:03:00.000Z'; }, 'probe_authority_invalid'],
  ['renewed issue', (j) => { j.constraints.issued_at = '2026-10-10T00:01:00.000Z'; }, 'probe_authority_invalid'],
  ['missing authority version', (j) => { delete j.constraints.authority_version; }, 'probe_authority_invalid'],
  ['changed ownership', (j) => { j.constraints.ownership_binding.transitioned_at = AT; }, 'reviewed_operation_ownership_mismatch'],
  ['missing ownership', (j) => { delete j.constraints.ownership_binding; }, 'reviewed_operation_ownership_mismatch'],
]) test(`offline worker before-DNS guard rejects ${label}`, () => { const j = job(); mutate(j); denied(offline(j), error); });
for (const field of ['max_requests', 'timeout_ms', 'marker', 'evasion_transform', 'entry_path_scenario', 'http_method', 'probe_path', 'raw_body', 'headers']) {
  test(`offline worker rejects signed profile override ${field}`, () => {
    const j = job(); j.probe_profile[field] = field === 'timeout_ms' ? 1000 : 'override'; denied(offline(j), 'reviewed_operation_delivery_unavailable');
  });
}
test('offline worker checks current actual check definition/version even when explicit version is unchanged', () => {
  const c = fixture(), j = job(c); c.check.description += ' drift';
  denied(offline(j, { check: c.check }), 'operation_check_changed');
  denied(offline(j, { check: undefined }), 'operation_check_changed');
});
test('offline worker independently rejects re-digested unsupported JSON and cookie plans before DNS', () => {
  const j = job(); const b = j.constraints.reviewed_operation_binding;
  b.plan.template = 'inert-json-v1'; b.plan.method = 'POST'; b.plan.request_schema = 'fixed-asn-marker-json.v1';
  b.plan.maximum_body_bytes = 1024; b.plan_digest = hash(b.plan);
  denied(offline(j), 'reviewed_operation_delivery_unavailable');
});
for (const [field, value] of [['max_probe_requests', 5], ['max_probe_requests', 0], ['max_probe_requests', -1], ['max_probe_requests', '4'],
  ['max_probe_requests', 1.5], ['max_probe_requests', NaN], ['max_destination_resolver_attempts', 3],
  ['min_destination_resolver_attempts', 1], ['max_total_operations', 99], ['max_requests', 99],
  ['execution_attempts', 2], ['execution_attempts', 0], ['timeout_ms', 5001], ['timeout_ms', 0], ['timeout_ms', '1000'],
  ['retries', 0], ['retry_attempts', 1], ['refunds', 0], ['budget_refunds', true]]) {
  test(`offline separate nonrenewable budget rejects ${field}=${value}`, () => {
    const j = job(); j.constraints[field] = value; denied(offline(j), 'probe_operation_budget_invalid');
  });
}
test('smaller probe allowance preserves resolver separation without adding retries/refunds', () => {
  const j = job(); j.constraints.max_probe_requests = 1; j.constraints.max_total_operations = 3; j.constraints.max_requests = 3;
  assert.equal(offline(j).ok, true);
});
test('a literal URL cannot acquire direct DNS authority from a fabricated proof', () => {
  const c = fixture(); c.target.value = 'https://[2001:db8::1]/diagnostic';
  const proposal = buildReviewedOperationPlan({ target_id: c.target.id, check_id: c.check.check_id, template: 'marker-query-v1',
    semantics: 'inert_diagnostic', side_effects: 'none', expires_at: c.review.plan.expires_at }, { ...c, now: AT });
  c.review.plan = proposal.plan; c.review.plan_digest = proposal.plan_digest;
  c.ownership.source_ref.dns_target_binding = dnsOwnershipTargetBinding(c.target);
  denied(buildReviewedOperationBinding(c), 'ownership_not_verified');
});
for (const now of [UNTIL, '2026-10-10T00:03:00.000Z', 'bad', null, NaN]) {
  test('offline guard rejects authority expiry and malformed clocks', () => denied(offline(job(), { now })));
}
test('signed constraints protect every reviewed binding element and do not read worker metadata authority', () => {
  const j = job(), secret = 'unit-only-no-traffic'; j.job_signature = signProbeJob(j, secret);
  assert.equal(verifyProbeJobSignature(j, secret), true);
  j.worker_metadata = { reviewed_operation_binding: { approved: true }, execution_reservation: { approved: true } };
  assert.equal(verifyProbeJobSignature(j, secret), true); assert.equal(offline(j).ok, true);
  for (const mutate of [
    (v) => { v.constraints.reviewed_operation_binding.review_id = 'rop_other'; },
    (v) => { v.constraints.reviewed_operation_binding.approval.id = 'usr_other'; },
    (v) => { v.constraints.reviewed_operation_binding.plan_digest = '0'.repeat(64); },
    (v) => { v.constraints.reviewed_operation_binding.authority.not_after = '2026-10-10T00:01:00.000Z'; },
    (v) => { v.constraints.reviewed_operation_binding.plan.endpoint = 'https://foreign.example.test/'; },
  ]) { const tampered = structuredClone(j); mutate(tampered); assert.equal(verifyProbeJobSignature(tampered, secret), false); }
});

test('original pending job validates without reservation; metadata cannot satisfy separate reservation guard', () => {
  const j = job(); assert.equal(offline(j).ok, true);
  j.worker_metadata = { execution_reservation: reservation(j) };
  assert.equal(offline(j).ok, true);
  denied(checkReservation(j, undefined), 'reviewed_operation_reservation_mismatch');
});
for (const requireReservation of [true, false, null, undefined, 'true']) {
  test('removed requireReservation option is explicitly rejected, never ignored', () => {
    denied(offline(job(), { requireReservation }), 'reviewed_operation_validation_options_invalid');
  });
}
test('separate grant reservation agrees with immutable original job/review/deadline/budgets and authenticated worker lease', () => {
  const j = job(), secret = 'unit-only'; j.job_signature = signProbeJob(j, secret);
  const signedOriginal = structuredClone(j);
  j.leased_by = 'worker_test'; j.leased_at = AT;
  const r = reservation(j), before = structuredClone(j), originalReservation = structuredClone(r);
  assert.equal(verifyProbeJobSignature(j, secret), true);
  assert.equal(offline(j).ok, true);
  assert.equal(checkReservation(j, r).ok, true);
  assert.deepEqual(j, before); assert.deepEqual(r, originalReservation);
  assert.deepEqual(j.constraints, signedOriginal.constraints);
  assert.equal(Object.hasOwn(j.constraints, 'execution_reservation'), false);
  assert.equal(checkReservation(j, r).grants_execution, false);
  r.reviewed_operation.review_id = 'rop_other';
  denied(checkReservation(j, r), 'reviewed_operation_reservation_mismatch');
  assert.equal(verifyProbeJobSignature(j, secret), true);
});
for (const value of [null, undefined, {}, true, 'reservation']) {
  test('bound original signed constraints cannot be renewed to contain execution_reservation', () => {
    const j = job(), secret = 'unit-only'; j.job_signature = signProbeJob(j, secret);
    j.constraints.execution_reservation = value;
    // Existing signing canonicalization omits undefined keys; structural rejection still applies.
    assert.equal(verifyProbeJobSignature(j, secret), value === undefined);
    denied(offline(j), 'reviewed_operation_original_job_mutated');
    j.job_signature = signProbeJob(j, secret);
    assert.equal(verifyProbeJobSignature(j, secret), true);
    denied(offline(j), 'reviewed_operation_original_job_mutated');
  });
}
test('even a valid reservation inserted and re-signed into original constraints is rejected', () => {
  const j = leasedJob(); j.constraints.execution_reservation = reservation(j); j.job_signature = signProbeJob(j, 'unit-only');
  assert.equal(verifyProbeJobSignature(j, 'unit-only'), true);
  denied(offline(j), 'reviewed_operation_original_job_mutated');
  denied(checkReservation(j, j.constraints.execution_reservation), 'reviewed_operation_original_job_mutated');
});
for (const [field, value] of [['version', 'future.v2'], ['state', 'refunded'], ['id', ''], ['worker_id', {}],
  ['leased_at', 'bad'], ['reserved_at', 'bad'], ['reserved_at', UNTIL], ['reserved_at', '2026-10-09T23:59:59.000Z'],
  ['leased_at', '2026-10-09T23:59:59.000Z'], ['not_after', '2026-10-10T00:03:00.000Z'],
  ['max_probe_requests', 5], ['max_destination_resolver_attempts', 3], ['max_total_operations', 7], ['extra', true]]) {
  test(`separate grant reservation agreement rejects ${field}`, () => {
    const j = leasedJob(); const r = reservation(j); r[field] = value;
    denied(checkReservation(j, r), 'reviewed_operation_reservation_mismatch');
    assert.equal(offline(j).ok, true);
  });
}
for (const [field, value] of [['binding_version', 'future.v2'], ['review_id', 'rop_other'], ['plan_version', 'future.v2'],
  ['plan_digest', '0'.repeat(64)], ['extra', true]]) {
  test(`separate grant reservation agreement rejects immutable review ${field}`, () => {
    const j = leasedJob(); const r = reservation(j); r.reviewed_operation[field] = value;
    denied(checkReservation(j, r), 'reviewed_operation_reservation_mismatch');
    assert.equal(offline(j).ok, true);
  });
}
test('reservation cannot substitute another worker for exact authenticated lease context', () => {
  const j = leasedJob(), changed = reservation(j); changed.worker_id = 'worker_other';
  denied(checkReservation(j, changed), 'reviewed_operation_reservation_mismatch');
});
for (const [field, value] of [['workerId', undefined], ['workerId', null], ['workerId', ''], ['workerId', []],
  ['workerId', 'worker_other'], ['workerId', 'x'.repeat(129)], ['leasedAt', undefined], ['leasedAt', null],
  ['leasedAt', []], ['leasedAt', '2026-10-10'], ['leasedAt', '2026-02-30T00:00:00Z'],
  ['leasedAt', '2026-10-10T00:00:01.000Z']]) {
  test(`reservation requires exact authenticated ${field}=${JSON.stringify(value)}`, () => {
    const j = leasedJob(); denied(checkReservation(j, reservation(j), { [field]: value }), 'reviewed_operation_reservation_mismatch');
  });
}
for (const field of ['leased_by', 'leased_at']) {
  for (const value of [undefined, null, [], 'other']) test(`reservation rejects absent/changed job ${field}`, () => {
    const j = leasedJob(), r = reservation(j); j[field] = value;
    denied(checkReservation(j, r), 'reviewed_operation_reservation_mismatch');
  });
}
test('unleased original job and missing authenticated options cannot authorize reservation', () => {
  const j = job(), r = reservation(j); denied(checkReservation(j, r), 'reviewed_operation_reservation_mismatch');
  const leased = leasedJob();
  denied(validateReviewedOperationReservation(leased, reservation(leased), { check: fixture().check, now: AT }), 'reviewed_operation_reservation_mismatch');
});
for (const key of ['approved', 'authorized', 'grantSignatureVerified', 'signature_verified', 'requireReservation']) {
  test(`structural guards reject boolean authorization shortcut ${key}`, () => {
    const j = leasedJob();
    denied(checkReservation(j, reservation(j), { [key]: true }), 'reviewed_operation_validation_options_invalid');
    denied(offline(j, { [key]: true }), 'reviewed_operation_validation_options_invalid');
  });
}

test('legacy unbound current and signed jobs remain untouched, without inventing reviewed execution authority', () => {
  assert.equal(validateCurrentReviewedOperationBinding(undefined).legacy, true);
  for (const j of [undefined, {}, { constraints: { max_requests: 8 }, worker_metadata: { reviewed_operation_binding: {} } }]) {
    assert.deepEqual(validateSignedReviewedOperationBinding(j), { ok: true, grants_execution: false, execution_available: false, legacy: true });
    assert.equal(validateReviewedOperationReservation(j, undefined).legacy, true);
  }
  denied(validateCurrentReviewedOperationBinding(null));
  const j = job(); j.constraints.reviewed_operation_binding = null; denied(offline(j));
});

for (const key of ['reviewed_operation', 'reviewed_operation_version', 'reviewed_operation_authority', 'reviewedOperationId',
  'plan_snapshot', 'operation_plan', 'approved_actor_kind', 'approved', 'approver', 'user_id', 'role', 'authority', 'ownership_binding']) {
  test(`selection never accepts alternate caller authority ${key}`, () => denied(validateReviewedOperationSelection({ [key]: 'claimed' })));
}
for (const section of [null, 'plan', 'approval', 'ownership', 'authority']) {
  const original = bound();
  for (const key of Object.keys(section === null ? original : original[section])) {
    test(`every required binding ${section ?? 'root'}.${key} is checked`, () => {
      const b = bound(); delete (section === null ? b : b[section])[key];
      denied(validateCurrentReviewedOperationBinding(b, fixture()));
      const j = job(); j.constraints.reviewed_operation_binding = b; denied(offline(j));
    });
  }
}
for (const [key, value] of [['observation_only', true], ['scenario_version', 'v5'], ['delivery_supported', false],
  ['requires_complete_comparison', false], ['marker_class', 'arbitrary'], ['marker_type', 'cookie'], ['scenario_family', 'entry_path'],
  ['expected_action', 'allow'], ['nonce_hash_only', false], ['marker', ''], ['marker', 'x'.repeat(129)], ['collect', [null]],
  ['max_requests', 0], ['max_requests', '4'], ['timeout_ms', 0], ['timeout_ms', '5000']]) {
  test(`serializer capability fails closed for malformed catalog ${key}`, () => {
    const c = fixture(); c.check.probe_profile[key] = value;
    assert.equal(reviewedOperationDelivery(c.review.plan, c.check, c.check.probe_profile).available, false);
  });
}
test('enumerated query capabilities match existing actual pure serializer across every inert marker class', () => {
  for (const transform of SUPPORTED_EVASION_TRANSFORMS.filter((t) => t !== 'parameter_location')) {
    for (const markerClass of ['sqli', 'xss', 'path_traversal']) {
      const request = buildEvasionRequest(fixture().target.value, applyEvasionTransform(transform, markerClass));
      assert.equal(request.method, 'GET'); assert.equal(request.delivery.where, 'query');
      assert.equal(request.delivery.body_bytes, 0); assert.equal(request.delivery.path_unchanged, true);
      assert.deepEqual(request.headers, {});
      assert.equal(new URL(request.url).pathname, '/diagnostic');
    }
  }
  const cookie = buildEvasionRequest(fixture().target.value, applyEvasionTransform('parameter_location', 'sqli'));
  assert.equal(cookie.delivery.where, 'cookie'); assert.ok(cookie.headers.cookie);
  denied(buildReviewedOperationBinding(fixture('waf.evasion_parameter_location.safe')), 'reviewed_operation_delivery_unavailable');
});
test('malformed canonical data returns structured errors rather than throws', () => {
  const c = fixture(); c.check.circular = c.check;
  denied(buildReviewedOperationBinding(c));
  const b = bound(); b.plan.check_version = Symbol('authority');
  denied(validateCurrentReviewedOperationBinding(b, fixture()));
  const j = job(); j.probe_profile.collect = [Infinity]; denied(offline(j));
  const leased = leasedJob(), cyclicReservation = reservation(leased);
  cyclicReservation.reviewed_operation.plan_digest = cyclicReservation;
  denied(checkReservation(leased, cyclicReservation));
  for (const options of [null, 1, 'bad']) denied(validateSignedReviewedOperationBinding(job(), options));
  assert.equal(reviewedOperationDelivery({}, null).available, false);
});
test('partial/malformed revocation or deletion cannot revive proof', () => {
  for (const key of ['revoked_at', 'revoked_by']) {
    const c = fixture(); c.review[key] = ''; denied(buildReviewedOperationBinding(c), 'operation_revoked');
  }
  const c = fixture(); c.target.deleted_at = ''; denied(buildReviewedOperationBinding(c), 'operation_target_changed');
});
test('UTC clocks accept finite Date/epoch but no rollover/timezone/loose-date authority', () => {
  for (const now of [new Date(AT), Date.parse(AT)]) assert.equal(buildReviewedOperationBinding({ ...fixture(), now }).ok, true);
  for (const invalid of ['2026-10-10T00:00:00+00:00', '2026-10-10T00:00:00.0000Z', '2026-10-10T24:00:00Z', 0, Infinity]) {
    const c = fixture(); c.originalAuthority.issued_at = invalid; denied(buildReviewedOperationBinding(c));
  }
  const c = fixture(); c.review.approved_at = '2026-10-09T00:00:00.000Z';
  c.review.plan.expires_at = '2026-10-10T00:00:00.001Z'; c.review.plan_digest = hash(c.review.plan);
  denied(buildReviewedOperationBinding(c), 'operation_review_invalid');
});
test('offline success returns an immutable detached snapshot, with no job or reservation mutation', () => {
  const j = job(), before = structuredClone(j), result = offline(j);
  assert.equal(result.ok, true); assert.deepEqual(j, before);
  assert.ok(Object.isFrozen(result.binding)); assert.ok(Object.isFrozen(result.binding.plan));
  j.constraints.reviewed_operation_binding.plan.endpoint = 'https://other.example.test/';
  assert.equal(result.binding.plan.endpoint, before.constraints.reviewed_operation_binding.plan.endpoint);
});
