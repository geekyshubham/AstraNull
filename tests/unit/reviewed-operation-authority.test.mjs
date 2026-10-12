import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { buildReviewedOperationPlan } from '../../src/contracts/reviewedOperations.mjs';
import { dnsOwnershipTargetBinding } from '../../src/lib/dnsOwnershipTarget.mjs';
import { canonicalJsonStringify } from '../../src/lib/custody.mjs';
import { createReviewedOperationAuthority } from '../../src/services/reviewedOperationAuthority.mjs';
import { createDevReviewedOperationBackend } from '../../src/services/devReviewedOperations.mjs';
import { getStore, resetStoreForTests } from '../../src/store.mjs';

const AT = '2026-10-10T00:00:00.000Z';
const UNTIL = '2026-10-10T00:02:00.000Z';
const ctx = { tenantId: 'ten_authority', userId: 'usr_owner', role: 'owner' };
const CHECK = 'waf.evasion_base64_wrap.safe';
const hash = (value) => createHash('sha256').update(canonicalJsonStringify(value)).digest('hex');
function fixture() {
  const target = { id: 'tgt_authority', tenant_id: ctx.tenantId, target_group_id: 'tg_authority', kind: 'url',
    value: 'https://authority.example.test/diagnostic', protocol: 'https', port: 443,
    expected_behavior: 'must_block_before_origin', declaration_json: { operation: 'inert' }, metadata_json: {} };
  const targetGroup = { id: target.target_group_id, tenant_id: ctx.tenantId, deleted_at: null, archived_at: null };
  const proposal = buildReviewedOperationPlan({ target_id: target.id, check_id: CHECK, template: 'marker-query-v1',
    semantics: 'inert_diagnostic', side_effects: 'none', expires_at: '2026-10-10T01:00:00.000Z' },
  { tenantId: ctx.tenantId, target, check: getCheckById(CHECK), now: AT });
  const review = { id: 'rop_authority', tenant_id: ctx.tenantId, target_id: target.id, plan: proposal.plan,
    plan_digest: proposal.plan_digest, approved_by: ctx.userId, approved_role: ctx.role, approved_at: AT,
    revoked_at: null, revoked_by: null };
  const ownership = { id: 'proof_authority', tenant_id: ctx.tenantId, target_id: target.id, state: 'dns_verified',
    source_kind: 'dns_txt', source_ref: { dns_target_binding: dnsOwnershipTargetBinding(target) },
    transitioned_at: '2026-10-09T00:00:00.000Z' };
  resetStoreForTests();
  Object.assign(getStore(), { targets: [target], targetGroups: [targetGroup], reviewedOperations: [review], targetVerifications: [ownership] });
  let clock = AT;
  const backend = createDevReviewedOperationBackend({ now: () => new Date(clock) });
  const authority = createReviewedOperationAuthority({ backend });
  const request = { mode: 'build', reviewId: review.id, targetId: target.id, checkId: CHECK,
    originalAuthority: { issued_at: AT, not_after: UNTIL } };
  return { target, targetGroup, review, ownership, backend, authority, request, clock: (value) => { clock = value; } };
}
function load(f, request = f.request, callback = (snapshot) => snapshot, options) {
  return f.authority.withCurrentAuthority(ctx, request, callback, options);
}
function denied(f, error, request = f.request, options) {
  let invoked = false;
  const result = load(f, request, () => { invoked = true; }, options);
  assert.equal(invoked, false);
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.equal(result.grants_execution, false);
  assert.equal(result.execution_available, false);
  if (error) assert.equal(result.error, error);
  return result;
}
const comparison = (f, binding) => ({ mode: 'compare', targetId: f.target.id, checkId: CHECK, binding });

test('dev builds a detached deeply frozen actual-row snapshot and compare preserves original authority', () => {
  const f = fixture(), snapshot = load(f);
  assert.equal(snapshot.ok, true);
  assert.deepEqual(Object.keys(snapshot).sort(), ['ok', 'tenantId', 'reviewId', 'review', 'targetGroup', 'target', 'check',
    'ownership', 'ownershipHistory', 'checkedAt', 'binding', 'delivery', 'grants_execution', 'execution_available'].sort());
  assert.equal(snapshot.grants_execution, false); assert.equal(snapshot.execution_available, false);
  assert.equal(snapshot.checkedAt, AT);
  for (const value of [snapshot, snapshot.target, snapshot.target.declaration_json, snapshot.review, snapshot.review.plan,
    snapshot.ownership, snapshot.ownershipHistory, snapshot.binding, snapshot.check.probe_profile, snapshot.delivery]) {
    assert.equal(Object.isFrozen(value), true);
  }
  f.clock('2026-10-10T00:01:00.000Z');
  const compared = load(f, comparison(f, structuredClone(snapshot.binding)));
  assert.equal(compared.ok, true);
  assert.equal(compared.binding.authority.issued_at, AT);
  assert.equal(compared.binding.authority.not_after, UNTIL);
  f.target.declaration_json.operation = 'changed'; f.review.revoked_at = AT; f.ownership.state = 'unverified';
  assert.equal(snapshot.target.declaration_json.operation, 'inert');
  assert.equal(snapshot.review.revoked_at, null); assert.equal(snapshot.ownership.state, 'dns_verified');
  assert.throws(() => { snapshot.binding.plan.method = 'DELETE'; }, TypeError);
});

for (const extra of ['review', 'target', 'check', 'ownership', 'ownershipHistory', 'authority', 'selector', 'targetGroupId',
  'reviewed_operation_id', 'grants_execution', 'now']) {
  test(`strict request rejects additional ${extra} without loading or invoking callback`, () => {
    const f = fixture(); let loaded = false;
    const authority = createReviewedOperationAuthority({ backend: { withAuthorityRows() { loaded = true; } } });
    const result = authority.withCurrentAuthority(ctx, { ...f.request, [extra]: null }, () => assert.fail());
    assert.equal(result.error, 'invalid_reviewed_operation_authority_request'); assert.equal(loaded, false);
    const binding = load(f).binding;
    denied(f, 'invalid_reviewed_operation_authority_request', { ...comparison(f, binding), [extra]: null });
  });
}
for (const mutate of [
  (r) => { r.reviewId = []; }, (r) => { delete r.reviewId; }, (r) => { r.targetId = 'x/other'; },
  (r) => { r.checkId = 'c'.repeat(129); }, (r) => { r.originalAuthority.extra = true; },
  (r) => { r.originalAuthority.issued_at = '2026-02-30T00:00:00.000Z'; },
  (r) => { r.originalAuthority.not_after = '2026-10-10T00:02:00.000000Z'; },
  (r) => { r.originalAuthority.issued_at = '2026-10-10T00:00:00Z'; },
  (r) => { r.originalAuthority.not_after = '2026-10-10T00:02:00Z'; },
]) test('strict build identity and original clock shape fail closed', () => {
  const f = fixture(); mutate(f.request); denied(f, 'invalid_reviewed_operation_authority_request');
});
test('request accessors, symbols, cyclic/non-JSON bindings and legacy compare cannot enter the reader', () => {
  const f = fixture(); let invoked = false;
  const getter = Object.defineProperty({ ...f.request }, 'mode', { enumerable: true, get() { invoked = true; return 'build'; } });
  denied(f, 'invalid_reviewed_operation_authority_request', getter); assert.equal(invoked, false);
  denied(f, 'invalid_reviewed_operation_authority_request', { ...f.request, [Symbol('authority')]: true });
  const binding = structuredClone(load(f).binding); binding.plan.extra = binding;
  for (const value of [undefined, null, {}, binding, { ...load(f).binding, extra: new Date() }]) {
    denied(f, 'invalid_reviewed_operation_authority_request', comparison(f, value));
  }
});
test('compare requires unchanged canonical millisecond authority clocks, without upgrading old labels', () => {
  const f = fixture(), original = load(f).binding;
  for (const field of ['issued_at', 'original_not_after', 'not_after']) {
    const binding = structuredClone(original);
    binding.authority[field] = binding.authority[field].replace('.000Z', 'Z');
    denied(f, 'invalid_reviewed_operation_authority_request', comparison(f, binding));
    assert.equal(binding.authority[field].includes('.'), false, 'old label is not rewritten');
  }
});
test('compare rejects separately supplied review identity/deadlines and selected target/check mismatches', () => {
  const f = fixture(), binding = load(f).binding;
  for (const extra of [{ reviewId: f.review.id }, { originalAuthority: f.request.originalAuthority }, { original_authority: {} }]) {
    denied(f, 'invalid_reviewed_operation_authority_request', { ...comparison(f, binding), ...extra });
  }
  denied(f, 'reviewed_operation_binding_changed', { ...comparison(f, binding), checkId: 'l7.http.safe' });
  const tampered = structuredClone(binding); tampered.plan.target_id = 'tgt_other';
  denied(f, 'reviewed_operation_binding_changed', comparison(f, tampered));
});

for (const [label, mutate, error] of [
  ['revoked review', (f) => { f.review.revoked_at = AT; }, 'operation_revoked'],
  ['missing review', () => { getStore().reviewedOperations = []; }, 'operation_not_found'],
  ['foreign review', (f) => { f.review.tenant_id = 'ten_other'; }, 'operation_not_found'],
  ['foreign target', (f) => { f.target.tenant_id = 'ten_other'; }, 'operation_target_changed'],
  ['missing target', () => { getStore().targets = []; }, 'operation_target_changed'],
  ['deleted target', (f) => { f.target.deleted_at = AT; }, 'operation_target_changed'],
  ['archived group', (f) => { f.targetGroup.archived_at = AT; }, 'operation_target_changed'],
  ['deleted group', (f) => { f.targetGroup.deleted_at = AT; }, 'operation_target_changed'],
  ['foreign group', (f) => { f.targetGroup.tenant_id = 'ten_other'; }, 'operation_target_changed'],
  ['URL path changed', (f) => { f.target.value += '/other'; }, 'operation_target_changed'],
  ['lossless nested material drift', (f) => { f.target.declaration_json.scope = { endpoint: 'x'.repeat(1000) }; }, 'operation_target_changed'],
  ['port changed', (f) => { f.target.port = 8443; }, 'operation_target_changed'],
  ['expected behavior changed', (f) => { f.target.expected_behavior = 'intentionally_public'; }, 'operation_target_changed'],
  ['latest unverified row', (f) => { getStore().targetVerifications.push({ ...f.ownership, id: 'proof_lost', state: 'unverified', transitioned_at: AT }); }, 'ownership_not_verified'],
  ['missing direct ownership', () => { getStore().targetVerifications = []; }, 'ownership_not_verified'],
  ['foreign ownership', (f) => { f.ownership.tenant_id = 'ten_other'; }, 'ownership_not_verified'],
  ['retained unbound proof', (f) => { f.ownership.source_ref = {}; }, 'ownership_not_verified'],
  ['old DNS scope', (f) => { f.ownership.source_ref.dns_target_binding.version = 'dns-ownership-target.v1'; }, 'ownership_not_verified'],
  ['inherited proof', (f) => { f.ownership.source_kind = 'inherited_parent'; }, 'ownership_not_verified'],
  ['provider proof', (f) => { f.ownership.source_kind = 'provider_account'; f.ownership.state = 'provider_verified'; }, 'ownership_not_verified'],
  ['malformed older chronology', (f) => { getStore().targetVerifications.unshift({ ...f.ownership, id: 'proof_bad', transitioned_at: 'not-a-clock' }); }, 'ownership_not_verified'],
  ['ambiguous latest tie', (f) => { getStore().targetVerifications.push({ ...f.ownership, id: 'proof_tie', state: 'unverified' }); }, 'ownership_not_verified'],
  ['expired original authority', (f) => { f.clock(UNTIL); }, 'probe_authority_expired'],
  ['expired review', (f) => { f.clock(f.review.plan.expires_at); }, 'operation_expired'],
  ['approval microseconds', (f) => { f.review.approved_at = '2026-10-10T00:00:00.000001Z'; }, 'operation_review_invalid'],
  ['unsupported delivery', (f) => { f.review.plan.template = 'inert-json-v1'; f.review.plan.method = 'POST';
    f.review.plan.request_schema = 'fixed-asn-marker-json.v1'; f.review.plan.maximum_body_bytes = 1024;
    f.review.plan_digest = hash(f.review.plan); }, 'reviewed_operation_delivery_unavailable'],
]) test(`current server rows reject ${label} in build and compare without invoking success`, () => {
  const f = fixture(), binding = structuredClone(load(f).binding); mutate(f);
  denied(f, error);
  // An already expired binding can fail its shape clocks before reading changed material.
  denied(f, undefined, comparison(f, binding));
});

test('actual current catalog digest is validated, not a caller-provided check', () => {
  const f = fixture(), check = getCheckById(CHECK), before = check.description;
  try { check.description += ' changed'; denied(f, 'operation_check_changed'); }
  finally { check.description = before; }
});
test('losslessly collapse exact zero microseconds only AFTER full raw chronology selection', () => {
  const f = fixture(); f.ownership.transitioned_at = '2026-10-09T00:00:00.000000Z';
  const snapshot = load(f);
  assert.equal(snapshot.ok, true);
  assert.equal(snapshot.ownership.transitioned_at, '2026-10-09T00:00:00.000Z');
  assert.equal(snapshot.ownershipHistory[0].transitioned_at, '2026-10-09T00:00:00.000000Z');
  getStore().targetVerifications.push({ ...f.ownership, id: 'proof_real_microsecond', transitioned_at: '2026-10-09T00:00:00.000001Z' });
  denied(f, 'ownership_not_verified');
  getStore().targetVerifications[1].state = 'unverified';
  denied(f, 'ownership_not_verified');
  // Removing malformed history from consideration or falling back to the older exact
  // proof would incorrectly succeed in either of these cases.
});
test('Date presentation timestamps become immutable finite ISO strings without losing literal JSON keys', () => {
  const f = fixture();
  f.target.created_at = new Date(AT); f.targetGroup.created_at = new Date(AT);
  f.target.metadata_json = JSON.parse('{"__proto__":{"literal":"retained"}}');
  const snapshot = load(f);
  assert.equal(snapshot.ok, true);
  assert.equal(snapshot.target.created_at, AT); assert.equal(snapshot.targetGroup.created_at, AT);
  assert.equal(snapshot.target.created_at.setTime, undefined);
  assert.equal(Object.hasOwn(snapshot.target.metadata_json, '__proto__'), true);
  assert.equal(snapshot.target.metadata_json.__proto__.literal, 'retained');
  assert.ok(Object.isFrozen(snapshot.target.metadata_json.__proto__));
  f.target.created_at.setTime(0); assert.equal(snapshot.target.created_at, AT);
  f.target.created_at = new Date(NaN);
  denied(f, 'reviewed_operation_authority_snapshot_invalid');
});
test('presentation changes do not invalidate full target material', () => {
  const f = fixture(); f.target.name = 'Renamed'; f.target.tags = ['updated']; f.target.metadata_json = { label: 'changed' };
  assert.equal(load(f).ok, true);
});
test('dev is synchronous and rejects async callbacks/options; callback errors propagate', () => {
  const f = fixture(); let invoked = false;
  assert.equal(f.authority.withCurrentAuthority(ctx, f.request, async () => { invoked = true; }).ok, false);
  assert.equal(invoked, false);
  denied(f, 'invalid_reviewed_operation_authority_options', f.request, { now: AT });
  denied(f, 'invalid_reviewed_operation_authority_options', f.request, { client: { query() {} } });
  assert.throws(() => load(f, f.request, () => Promise.resolve('not-safe')), /async_callback_unavailable/);
  const error = new Error('consumer failed');
  assert.throws(() => load(f, f.request, () => { throw error; }), (caught) => caught === error);
});
test('request is detached before an asynchronous backend wait, with no renewal from later caller mutation', async () => {
  const f = fixture(); let release;
  const waiting = new Promise((resolve) => { release = resolve; });
  const authority = createReviewedOperationAuthority({ backend: { async withAuthorityRows(actor, targetId, reviewId, fn) {
    await waiting;
    return f.backend.withAuthorityRows(actor, targetId, reviewId, fn);
  } } });
  const result = authority.withCurrentAuthority(ctx, f.request, (snapshot) => snapshot);
  f.request.reviewId = 'rop_forged'; f.request.originalAuthority.not_after = '2026-10-11T00:00:00.000Z';
  release(); assert.equal((await result).binding.authority.not_after, UNTIL);
});
