import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, generateKeyPairSync, sign, createHmac } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { getCheckById, buildProbeProfile } from '../../src/contracts/checks.mjs';
import { buildReviewedOperationPlan } from '../../src/contracts/reviewedOperations.mjs';
import { buildReviewedOperationBinding } from '../../src/contracts/reviewedOperationBinding.mjs';
import { dnsOwnershipTargetBinding } from '../../src/lib/dnsOwnershipTarget.mjs';
import { canonicalJsonStringify } from '../../src/lib/custody.mjs';
import { signProbeJob, verifyProbeJobSignature, targetDescriptor } from '../../src/lib/probeJobs.mjs';
import { buildCustodySigningEnvelope } from '../../src/lib/evidenceSigning.mjs';
import {
  REVIEWED_EXECUTION_GRANT_VERSION, REVIEWED_EXECUTION_GRANT_PURPOSE, REVIEWED_EXECUTION_GRANT_SIGNATURE_VERSION,
  buildReviewedExecutionGrantEnvelope, validateReviewedExecutionGrantEnvelope,
} from '../../src/contracts/reviewedExecutionGrant.mjs';
import {
  REVIEWED_EXECUTION_GRANT_TRUST_VERSION, resolveReviewedExecutionGrantTrust, loadReviewedExecutionGrantTrust,
  signReviewedExecutionGrant, verifyReviewedExecutionGrant,
} from '../../src/lib/reviewedExecutionGrant.mjs';
import { createEnvReviewedExecutionGrantAdapter, createExternalReviewedExecutionGrantAdapter } from '../../src/lib/reviewedExecutionGrantAdapter.mjs';

const AT = '2026-10-10T00:00:00.000Z', UNTIL = '2026-10-10T00:02:00.000Z';
const KEY = 'key://astranull/reviewed-execution/test';
const SECRET = 'original-worker-secret-not-a-grant-key';
const pair = generateKeyPairSync('ed25519');
const PUBLIC = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const PRIVATE = pair.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
const fingerprint = createHash('sha256').update(Buffer.from(PUBLIC, 'base64')).digest('hex');
const signer = { algorithm: 'ed25519', key_reference: KEY, public_key_fingerprint_sha256: fingerprint };
const now = () => Date.parse(AT);
function trust() {
  return { version: REVIEWED_EXECUTION_GRANT_TRUST_VERSION, purpose: REVIEWED_EXECUTION_GRANT_PURPOSE,
    tenants: { ten_test: { [KEY]: { algorithm: 'ed25519', public_key_spki_der_base64: PUBLIC,
      public_key_fingerprint_sha256: fingerprint, signing_enabled: true } } } };
}
function env() {
  return { ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_KEYS_JSON: JSON.stringify({ ten_test: { [KEY]: {
    algorithm: 'ed25519', public_key_spki_der_base64: PUBLIC, private_key_pkcs8_der_base64: PRIVATE, signing_enabled: true } } }) };
}
function context() {
  const check = structuredClone(getCheckById('waf.evasion_base64_wrap.safe'));
  const target = { id: 'tgt_test', tenant_id: 'ten_test', target_group_id: 'tg_test', kind: 'url',
    value: 'https://owned.example.test/diagnostic', expected_behavior: 'must_block_before_origin' };
  const proposal = buildReviewedOperationPlan({ target_id: target.id, check_id: check.check_id, template: 'marker-query-v1',
    semantics: 'inert_diagnostic', side_effects: 'none', expires_at: '2026-10-10T01:00:00.000Z' },
  { tenantId: target.tenant_id, target, check, now: AT });
  assert.equal(proposal.error, undefined, JSON.stringify(proposal));
  assert.ok(proposal.plan);
  const built = buildReviewedOperationBinding({ tenantId: target.tenant_id, reviewId: 'rop_test', target, check, now: AT,
    originalAuthority: { issued_at: AT, not_after: UNTIL },
    review: { id: 'rop_test', tenant_id: 'ten_test', target_id: target.id, plan: proposal.plan, plan_digest: proposal.plan_digest,
      approved_by: 'usr_test', approved_role: 'owner', approved_at: AT },
    ownership: { tenant_id: 'ten_test', target_id: target.id, state: 'dns_verified', source_kind: 'dns_txt',
      transitioned_at: '2026-10-09T00:00:00.000Z', source_ref: { dns_target_binding: dnsOwnershipTargetBinding(target) } } });
  assert.equal(built.ok, true, JSON.stringify(built));
  const binding = structuredClone(built.binding);
  const originalJob = { id: 'job_test', tenant_id: 'ten_test', test_run_id: 'run_test', target_id: target.id, check_id: check.check_id,
    nonce_hash: 'a'.repeat(64), target: targetDescriptor(target), probe_profile: buildProbeProfile(check.probe_profile),
    constraints: { authority_version: 'probe-authority-v2', issued_at: AT, not_after: UNTIL, execution_attempts: 1, timeout_ms: 5000,
      max_probe_requests: 4, min_destination_resolver_attempts: 2, max_destination_resolver_attempts: 2, max_total_operations: 6,
      max_requests: 6, ownership_binding: binding.ownership, reviewed_operation_binding: binding },
    leased_at: AT, leased_by: 'worker_test', status: 'leased', worker_metadata: { check_title: 'passive fixture' } };
  originalJob.job_signature = signProbeJob(originalJob, SECRET);
  const reservation = { version: 'execution-reservation.v1', id: 'res_test', worker_id: 'worker_test', leased_at: AT, reserved_at: AT,
    not_after: UNTIL, max_probe_requests: 4, max_destination_resolver_attempts: 2, max_total_operations: 6, state: 'reserved_unknown',
    reviewed_operation: { binding_version: binding.version, review_id: binding.review_id, plan_version: binding.plan.version, plan_digest: binding.plan_digest } };
  return { originalJob, reservation, check, tenantId: 'ten_test', workerId: 'worker_test', leasedAt: AT, now: AT };
}
function envelope(c = context()) {
  const built = buildReviewedExecutionGrantEnvelope(c, signer);
  assert.equal(built.ok, true, JSON.stringify(built));
  return built.envelope;
}
function signed(c = context()) {
  const e = envelope(c);
  return { version: REVIEWED_EXECUTION_GRANT_VERSION, envelope: e,
    signature: sign(null, Buffer.from(canonicalJsonStringify(e)), pair.privateKey).toString('base64') };
}
function verify(grant, c = context(), options = {}) { return verifyReviewedExecutionGrant({ grant, context: c, trust: trust(), ...options }); }
function signInput(c = context(), options = {}) {
  return { context: c, trust: trust(), keyReference: KEY, signingAdapter: createEnvReviewedExecutionGrantAdapter(env(), { now }), now, ...options };
}
function denied(result, error) { assert.equal(result.ok, false, JSON.stringify(result)); if (error) assert.equal(result.error, error); }

 test('generated Ed25519 independent grant verifies exact original payload without job mutation or execution flags', async () => {
  const c = context(), before = structuredClone(c), result = await signReviewedExecutionGrant(signInput(c));
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.deepEqual(c, before);
  assert.equal(verifyProbeJobSignature(c.originalJob, SECRET), true);
  const expected = Object.fromEntries(['check_id', 'constraints', 'id', 'nonce_hash', 'probe_profile', 'target', 'tenant_id', 'test_run_id']
    .map((key) => [key, c.originalJob[key]]));
  assert.equal(result.grant.envelope.original_job_payload, canonicalJsonStringify(expected));
  assert.equal(createHmac('sha256', SECRET).update(result.grant.envelope.original_job_payload).digest('hex'), c.originalJob.job_signature);
  assert.equal(result.grant.envelope.original_job_signature_sha256, createHash('sha256').update(c.originalJob.job_signature).digest('hex'));
  assert.deepEqual(verify(result.grant, c), { ok: true, verification: 'current' });
  assert.equal(Object.hasOwn(result, 'grants_execution'), false);
  assert.equal(Object.hasOwn(result, 'execution_available'), false);
  for (const value of [result.grant, result.grant.envelope, result.grant.envelope.reservation, result.grant.envelope.authority]) assert.equal(Object.isFrozen(value), true);
});

test('historical expired/retired grant verifies but explicitly cannot be current execution authority', () => {
  const c = context(), grant = signed(c), pinned = trust();
  pinned.tenants.ten_test[KEY].signing_enabled = false;
  denied(verify(grant, c, { trust: pinned }), 'reviewed_grant_key_retired');
  c.now = UNTIL;
  denied(verify(grant, c), 'reviewed_grant_expired');
  assert.deepEqual(verify(grant, c, { trust: pinned, mode: 'historical' }), { ok: true, verification: 'historical', execution_valid: false });
  denied(verify(grant, c, { mode: 'historical-or-current' }));
});

test('retired public and private keys cannot issue a new grant', async () => {
  const pinned = trust(); pinned.tenants.ten_test[KEY].signing_enabled = false;
  let called = false;
  denied(await signReviewedExecutionGrant(signInput(context(), { trust: pinned, signingAdapter: { signEnvelope() { called = true; } } })), 'reviewed_grant_key_retired');
  assert.equal(called, false);
  const local = env(), map = JSON.parse(local.ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_KEYS_JSON);
  map.ten_test[KEY].signing_enabled = false; local.ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_KEYS_JSON = JSON.stringify(map);
  denied(await signReviewedExecutionGrant(signInput(context(), { signingAdapter: createEnvReviewedExecutionGrantAdapter(local, { now }) })));
});

for (const [label, mutate] of [
  ['original signature', (c) => { c.originalJob.job_signature = 'b'.repeat(64); }],
  ['nonce', (c) => { c.originalJob.nonce_hash = 'b'.repeat(64); }],
  ['profile', (c) => { c.originalJob.probe_profile.marker = 'different'; }],
  ['job id', (c) => { c.originalJob.id = 'job_other'; }],
  ['run', (c) => { c.originalJob.test_run_id = 'run_other'; }],
  ['tenant', (c) => { c.originalJob.tenant_id = 'ten_other'; }],
  ['foreign authenticated tenant', (c) => { c.tenantId = 'ten_other'; }],
  ['target id', (c) => { c.originalJob.target_id = 'tgt_other'; }],
  ['signed target', (c) => { c.originalJob.target.value += '/other'; }],
  ['check', (c) => { c.originalJob.check_id = 'check_other'; }],
  ['deadline', (c) => { c.originalJob.constraints.not_after = '2026-10-10T00:02:01.000Z'; }],
  ['original deadline', (c) => { c.originalJob.constraints.reviewed_operation_binding.authority.original_not_after = '2026-10-10T00:02:01.000Z'; }],
  ['worker', (c) => { c.workerId = 'worker_other'; }],
  ['lease', (c) => { c.leasedAt = '2026-10-10T00:00:01.000Z'; }],
  ['job worker', (c) => { c.originalJob.leased_by = 'worker_other'; }],
  ['reservation id', (c) => { c.reservation.id = 'res_other'; }],
  ['reservation worker', (c) => { c.reservation.worker_id = 'worker_other'; }],
  ['reservation lease', (c) => { c.reservation.leased_at = '2026-10-10T00:00:01.000Z'; }],
  ['reservation budget', (c) => { c.reservation.max_probe_requests = 5; }],
  ['resolver budget', (c) => { c.reservation.max_destination_resolver_attempts = 3; }],
  ['total budget', (c) => { c.reservation.max_total_operations = 7; }],
  ['reservation review', (c) => { c.reservation.reviewed_operation.review_id = 'rop_other'; }],
  ['reservation plan', (c) => { c.reservation.reviewed_operation.plan_digest = 'b'.repeat(64); }],
  ['reservation completed', (c) => { c.reservation.state = 'completed'; }],
  ['reservation deadline', (c) => { c.reservation.not_after = '2026-10-10T00:02:01.000Z'; }],
]) test(`verification rejects ${label} tamper`, () => { const c = context(), grant = signed(c); mutate(c); denied(verify(grant, c)); });

for (const [label, mutate] of [
  ['purpose', (e) => { e.purpose = 'astranull.custody.v1'; }],
  ['version', (e) => { e.version = 'reviewed-execution-grant-envelope.v2'; }],
  ['algorithm', (e) => { e.algorithm = 'hmac-sha256'; }],
  ['key reference', (e) => { e.key_reference += ' '; }],
  ['fingerprint', (e) => { e.public_key_fingerprint_sha256 = 'b'.repeat(64); }],
  ['grant worker', (e) => { e.worker.id = 'worker_other'; }],
  ['grant budget', (e) => { e.budgets.max_total_operations = 7; }],
  ['grant payload', (e) => { e.original_job_payload += ' '; }],
  ['grant signature digest', (e) => { e.original_job_signature_sha256 = 'b'.repeat(64); }],
  ['grant issuance renewed', (e) => { e.authority.grant_issued_at = '2026-10-10T00:02:00.000Z'; }],
  ['extra authority', (e) => { e.grants_execution = true; }],
]) test(`even re-signed ${label} alteration fails exact context`, () => {
  const c = context(), grant = structuredClone(signed(c)); mutate(grant.envelope);
  grant.signature = sign(null, Buffer.from(canonicalJsonStringify(grant.envelope)), pair.privateKey).toString('base64');
  denied(verify(grant, c));
});

test('custody signature cross-replay and signed custody envelope cannot become grant', () => {
  const c = context(), grant = structuredClone(signed(c));
  const custody = buildCustodySigningEnvelope({ tenantId: c.tenantId, custodyManifestDigest: 'a'.repeat(64) });
  grant.signature = sign(null, Buffer.from(canonicalJsonStringify(custody)), pair.privateKey).toString('base64');
  denied(verify(grant, c), 'reviewed_grant_signature_invalid');
  grant.envelope = custody; denied(verify(grant, c));
});
for (const signature of [undefined, null, '', 'a'.repeat(88), 'AA==', ' ' + sign(null, Buffer.from('x'), pair.privateKey).toString('base64')]) {
  test('missing/invalid independent signature never falls back to HMAC or metadata', () => {
    const c = context(), grant = { ...signed(c), signature };
    c.originalJob.worker_metadata.signature_verified = true;
    assert.equal(verifyProbeJobSignature(c.originalJob, SECRET), true);
    denied(verify(grant, c));
  });
}

test('HMAC independent signature is forbidden even in development', () => {
  const grant = structuredClone(signed()), c = context();
  grant.envelope.algorithm = 'hmac-sha256';
  grant.signature = createHmac('sha256', SECRET).update(canonicalJsonStringify(grant.envelope)).digest('base64');
  denied(verify(grant, c));
});

for (const time of ['2026-10-10T00:00:00Z', '2026-10-10T00:00:00.000000Z', '2026-10-10T00:00:00+00:00',
  '2026-02-30T00:00:00.000Z', '2026-10-10', ['2026-10-10T00:00:00.000Z'], Infinity, NaN, new Date(NaN)]) {
  test(`noncanonical finite authority is rejected ${String(time)}`, () => {
    const c = context(); c.originalJob.constraints.issued_at = time;
    denied(buildReviewedExecutionGrantEnvelope(c, signer));
    const grant = signed(); c.originalJob = context().originalJob; c.now = time;
    denied(verify(grant, c));
  });
}

for (const [label, alter] of [
  ['extra reservation field', (c) => { c.reservation.refund = true; }],
  ['unsigned execution reservation in job', (c) => { c.originalJob.constraints.execution_reservation = c.reservation; }],
  ['extra job constraint', (c) => { c.originalJob.constraints.dispatch_approved = true; }],
  ['undefined profile field', (c) => { c.originalJob.probe_profile.marker = undefined; }],
  ['NaN profile', (c) => { c.originalJob.probe_profile.timeout_ms = NaN; }],
  ['bigint profile', (c) => { c.originalJob.probe_profile.timeout_ms = 1n; }],
  ['symbol authority', (c) => { c.reservation[Symbol('authority')] = true; }],
  ['hidden authority', (c) => { Object.defineProperty(c.reservation, 'hidden', { value: true }); }],
  ['class authority', (c) => { c.reservation.reviewed_operation = new Date(); }],
  ['cyclic authority', (c) => { c.reservation.extra = c.reservation; }],
  ['sparse profile array', (c) => { c.originalJob.probe_profile.collect = Array(2); }],
  ['negative zero', (c) => { c.originalJob.constraints.max_events = -0; }],
]) test(`builder rejects ${label}`, () => { const c = context(); alter(c); denied(buildReviewedExecutionGrantEnvelope(c, signer)); });

test('accessors rejected without invocation at job/reservation/envelope/trust boundaries', () => {
  let invoked = 0;
  const c = context(); Object.defineProperty(c.originalJob, 'nonce_hash', { enumerable: true, get() { invoked++; return 'a'.repeat(64); } });
  denied(buildReviewedExecutionGrantEnvelope(c, signer));
  const c2 = context(); Object.defineProperty(c2.reservation, 'worker_id', { enumerable: true, get() { invoked++; return 'worker_test'; } });
  denied(buildReviewedExecutionGrantEnvelope(c2, signer));
  const grant = structuredClone(signed()); Object.defineProperty(grant.envelope, 'algorithm', { enumerable: true, get() { invoked++; return 'ed25519'; } });
  denied(verify(grant));
  const pinned = trust(); Object.defineProperty(pinned.tenants.ten_test[KEY], 'algorithm', { enumerable: true, get() { invoked++; return 'ed25519'; } });
  denied(resolveReviewedExecutionGrantTrust({ trust: pinned, tenantId: 'ten_test', keyReference: KEY }));
  assert.equal(invoked, 0);
});

for (const [field, value] of [['secret', SECRET], ['private_key_pkcs8_der_base64', PRIVATE], ['privateKey', PRIVATE],
  ['algorithm', 'hmac-sha256'], ['public_key_fingerprint_sha256', 'b'.repeat(64)], ['public_key_spki_der_base64', 'invalid']]) {
  test(`public-only pinned trust rejects ${field}`, () => {
    const pinned = trust(); pinned.tenants.ten_test[KEY][field] = value;
    denied(verify(signed(), context(), { trust: pinned }));
  });
}

test('purpose trust does not use custody environment keys or worker secrets', async () => {
  denied(loadReviewedExecutionGrantTrust({ ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON: env().ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_KEYS_JSON }));
  const loaded = loadReviewedExecutionGrantTrust({ ASTRANULL_REVIEWED_EXECUTION_GRANT_TRUST_JSON: JSON.stringify(trust()) });
  assert.equal(loaded.ok, true); assert.equal(Object.isFrozen(loaded.trust), true);
  denied(await signReviewedExecutionGrant(signInput(context(), { signingAdapter: createEnvReviewedExecutionGrantAdapter({
    ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON: env().ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_KEYS_JSON,
  }, { now }) })));
});

for (const [label, raw] of [
  ['identity small-order', Buffer.concat([Buffer.from([1]), Buffer.alloc(31)])],
  ['zero small-order', Buffer.alloc(32)],
  ['torsion', Buffer.from(ed25519.Point.BASE.add(ed25519.Point.fromBytes(Buffer.alloc(32), false)).toBytes())],
]) test(`shared evidenceSigning point validation rejects ${label}`, () => {
  const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]);
  const pinned = trust(); pinned.tenants.ten_test[KEY].public_key_spki_der_base64 = der.toString('base64');
  pinned.tenants.ten_test[KEY].public_key_fingerprint_sha256 = createHash('sha256').update(der).digest('hex');
  denied(resolveReviewedExecutionGrantTrust({ trust: pinned, tenantId: 'ten_test', keyReference: KEY }), 'reviewed_grant_trust_invalid');
});

test('foreign tenant key and wrong purpose trust rejected', () => {
  const pinned = trust(); pinned.tenants = { ten_other: pinned.tenants.ten_test };
  denied(verify(signed(), context(), { trust: pinned }), 'reviewed_grant_key_untrusted');
  pinned.purpose = 'astranull.custody'; denied(verify(signed(), context(), { trust: pinned }));
});

function externalEnv(overrides = {}) {
  return { ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_ENDPOINT: 'https://signer.example.test',
    ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_ALLOWED_ORIGINS: 'https://signer.example.test',
    ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_BEARER_TOKEN: 'test-independent-signer-token', ...overrides };
}
function responseReceipt(envelope) {
  return { version: REVIEWED_EXECUTION_GRANT_SIGNATURE_VERSION, ...signer,
    signature: sign(null, Buffer.from(canonicalJsonStringify(envelope)), pair.privateKey).toString('base64') };
}
function external(fetchFn, options = {}) { return createExternalReviewedExecutionGrantAdapter({ env: externalEnv(), trust: trust(), fetchFn, now, ...options }); }

test('external mock fetch sends complete envelope over bounded dedicated HTTPS path and locally verifies actual signature', async () => {
  let calls = 0;
  const adapter = external(async (url, options) => {
    calls++; assert.equal(url, 'https://signer.example.test/v1/reviewed-execution-grants/sign');
    assert.equal(options.redirect, 'manual'); assert.equal(options.headers.authorization, 'Bearer test-independent-signer-token');
    const body = JSON.parse(options.body); assert.deepEqual(Object.keys(body), ['envelope']);
    assert.equal(body.envelope.original_job_payload, envelope().original_job_payload);
    assert.equal(body.envelope.purpose, REVIEWED_EXECUTION_GRANT_PURPOSE);
    return new Response(JSON.stringify(responseReceipt(body.envelope)), { headers: { 'content-type': 'application/json' } });
  });
  const result = await signReviewedExecutionGrant(signInput(context(), { signingAdapter: adapter }));
  assert.equal(result.ok, true, JSON.stringify(result)); assert.equal(calls, 1);
});
for (const [label, result] of [
  ['unsigned metadata', { execution_available: true, signature_verified: true }],
  ['missing signature', { version: REVIEWED_EXECUTION_GRANT_SIGNATURE_VERSION, ...signer }],
  ['bad actual signature', { version: REVIEWED_EXECUTION_GRANT_SIGNATURE_VERSION, ...signer, signature: Buffer.alloc(64).toString('base64') }],
  ['wrong fingerprint', { version: REVIEWED_EXECUTION_GRANT_SIGNATURE_VERSION, ...signer, public_key_fingerprint_sha256: 'b'.repeat(64), signature: Buffer.alloc(64).toString('base64') }],
  ['custody receipt', { schema_version: 'astranull.evidence_signing.v1', ...signer, signature: Buffer.alloc(64).toString('base64') }],
]) test(`malformed external signer ${label} fails closed`, async () => {
  const adapter = external(async () => new Response(JSON.stringify(result)));
  denied(await signReviewedExecutionGrant(signInput(context(), { signingAdapter: adapter })));
});

for (const [label, fetchFn] of [
  ['unavailable', async () => { throw new Error('secret-provider-error'); }],
  ['invalid JSON', async () => new Response('{')],
  ['non JSON content', async () => new Response('{}', { headers: { 'content-type': 'text/plain' } })],
  ['oversized response', async () => new Response('x'.repeat(20000))],
  ['redirect', async () => new Response('', { status: 302, headers: { location: 'https://other.example.test' } })],
]) test(`bounded external signer rejects ${label} without provider details`, async () => {
  const result = await signReviewedExecutionGrant(signInput(context(), { signingAdapter: external(fetchFn) }));
  denied(result); assert.equal(JSON.stringify(result).includes('secret-provider-error'), false);
});

for (const overrides of [
  { ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_ENDPOINT: 'http://localhost:1234' },
  { ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_ALLOWED_ORIGINS: '' },
  { ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_BEARER_TOKEN: '' },
  { ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_ENDPOINT: 'https://user:pass@signer.example.test' },
  { ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_ENDPOINT: 'https://signer.example.test?secret=true' },
]) test('external grant transport requires dedicated HTTPS/auth/origin even in dev', async () => {
  let called = false;
  const adapter = external(async () => { called = true; }, { env: externalEnv(overrides) });
  denied(await signReviewedExecutionGrant(signInput(context(), { signingAdapter: adapter }))); assert.equal(called, false);
});

test('deadline/signature wait cannot renew original authority; fresh clock rejects returned late grant', async () => {
  let current = Date.parse(AT);
  const adapter = { async signEnvelope({ envelope: e }) { current = Date.parse(UNTIL); return responseReceipt(e); } };
  denied(await signReviewedExecutionGrant(signInput(context(), { signingAdapter: adapter, now: () => current })), 'reviewed_grant_expired');
});
test('invalid and backwards fresh clock after signer withholds grant', async () => {
  for (const after of [NaN, Infinity, Date.parse(AT) - 1]) {
    let calls = 0;
    denied(await signReviewedExecutionGrant(signInput(context(), { now: () => calls++ ? after : now() })), 'reviewed_grant_clock_invalid');
  }
});
test('hung arbitrary signer times out and cancels; late receipt never creates authority', async () => {
  let release, captured;
  const pending = new Promise((resolve) => { release = resolve; });
  const adapter = { signEnvelope({ signal, envelope: e }) { captured = { signal, e }; return pending; } };
  denied(await signReviewedExecutionGrant(signInput(context(), { signingAdapter: adapter, timeoutMs: 10 })), 'reviewed_grant_signing_timeout');
  assert.equal(captured.signal.aborted, true); release(responseReceipt(captured.e));
  await Promise.resolve();
});
test('caller cancellation rejects late authority and aborts mock transport', async () => {
  const cancellation = new AbortController(); let captured, start;
  const started = new Promise((resolve) => { start = resolve; });
  const adapter = external(async (_, options) => { captured = options.signal; start(); return new Promise(() => {}); });
  const signing = signReviewedExecutionGrant(signInput(context(), { signingAdapter: adapter, signal: cancellation.signal }));
  await started; cancellation.abort();
  denied(await signing, 'reviewed_grant_signing_cancelled'); assert.equal(captured.aborted, true);
});
test('late mock fetch response body is cancelled after absolute transport deadline', async () => {
  let release, cancelled = 0;
  const fetchFn = () => new Promise((resolve) => { release = resolve; });
  const adapter = external(fetchFn, { env: externalEnv({ ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_FETCH_TIMEOUT_MS: '5' }) });
  denied(await signReviewedExecutionGrant(signInput(context(), { signingAdapter: adapter })));
  release(new Response(new ReadableStream({ cancel() { cancelled++; } })));
  await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(cancelled, 1);
});
test('stalled signer body cancels reader within bounded transport time', async () => {
  let cancelled = 0;
  const adapter = external(async () => new Response(new ReadableStream({ pull() {}, cancel() { cancelled++; } })),
    { env: externalEnv({ ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_FETCH_TIMEOUT_MS: '5' }) });
  denied(await signReviewedExecutionGrant(signInput(context(), { signingAdapter: adapter })));
  assert.equal(cancelled, 1);
});
test('context copied before await; later mutable caller job cannot replace signed original authority', async () => {
  const c = context(); let release, start;
  const started = new Promise((resolve) => { start = resolve; });
  const pending = new Promise((resolve) => { release = resolve; });
  const adapter = { signEnvelope({ envelope: e }) { start(); return pending.then(() => responseReceipt(e)); } };
  const signing = signReviewedExecutionGrant(signInput(c, { signingAdapter: adapter })); await started;
  c.originalJob.nonce_hash = 'b'.repeat(64); release();
  const result = await signing; assert.equal(result.ok, true); denied(verify(result.grant, c));
});

for (const field of ['job_signature', 'nonce_hash']) {
  for (const value of [undefined, null, 'A'.repeat(64), ' a'.repeat(32), 1, {}, 'a'.repeat(63)]) {
    test(`original ${field} exact typed lowercase hex format ${String(value)}`, () => {
      const c = context(); c.originalJob[field] = value; denied(buildReviewedExecutionGrantEnvelope(c, signer));
    });
  }
}
for (const path of ['leasedAt', 'reservation.leased_at', 'reservation.reserved_at', 'reservation.not_after',
  'originalJob.constraints.not_after', 'originalJob.constraints.reviewed_operation_binding.approval.approved_at',
  'originalJob.constraints.reviewed_operation_binding.ownership.transitioned_at',
  'originalJob.constraints.reviewed_operation_binding.plan.expires_at']) {
  test(`canonical millisecond labels are required at ${path}`, () => {
    const c = context(), parts = path.split('.'), field = parts.pop();
    const parent = parts.reduce((item, key) => item[key], c);
    parent[field] = parent[field].replace('.000Z', 'Z');
    denied(buildReviewedExecutionGrantEnvelope(c, signer));
  });
}
test('prototype setter JSON rejected to preserve exact original HMAC canonical payload', () => {
  const c = context();
  c.originalJob.target.metadata = JSON.parse('{"__proto__":{"authority":true}}');
  denied(buildReviewedExecutionGrantEnvelope(c, signer));
});
test('API boundary accessors and extra authority never invoke getters or grant', async () => {
  let invoked = 0;
  const getter = Object.defineProperty({}, 'grant', { enumerable: true, get() { invoked++; return signed(); } });
  denied(verifyReviewedExecutionGrant(getter));
  const signerGetter = Object.defineProperty({}, 'context', { enumerable: true, get() { invoked++; return context(); } });
  denied(await signReviewedExecutionGrant(signerGetter));
  const trustGetter = Object.defineProperty({}, 'trust', { enumerable: true, get() { invoked++; return trust(); } });
  denied(resolveReviewedExecutionGrantTrust(trustGetter));
  denied(verifyReviewedExecutionGrant({ grant: signed(), context: context(), trust: trust(), execution_available: true }));
  denied(await signReviewedExecutionGrant({ ...signInput(), signature_verified: true }));
  assert.equal(invoked, 0);
});
test('key retirement during independent signer wait withholds new current capability', async () => {
  const pinned = trust();
  const adapter = { async signEnvelope({ envelope: e }) { pinned.tenants.ten_test[KEY].signing_enabled = false; return responseReceipt(e); } };
  denied(await signReviewedExecutionGrant(signInput(context(), { trust: pinned, signingAdapter: adapter })), 'reviewed_grant_key_retired');
});
test('direct external adapter verifies actual returned signature before returning a receipt', async () => {
  const e = envelope();
  const adapter = external(async () => new Response(JSON.stringify({ ...responseReceipt(e), signature: Buffer.alloc(64).toString('base64') })));
  assert.equal((await adapter.signEnvelope({ envelope: e, signal: new AbortController().signal })).error, 'reviewed_grant_signer_unavailable');
});
test('local and external adapters cannot sign custody-shaped purpose confusion', async () => {
  const custody = buildCustodySigningEnvelope({ tenantId: 'ten_test', custodyManifestDigest: 'a'.repeat(64) });
  let called = false;
  const remote = external(async () => { called = true; });
  assert.ok((await createEnvReviewedExecutionGrantAdapter(env(), { now }).signEnvelope({ envelope: custody })).error);
  assert.ok((await remote.signEnvelope({ envelope: custody })).error); assert.equal(called, false);
});
test('wrong algorithm public key rejected through shared strict importer', () => {
  const wrong = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const der = wrong.publicKey.export({ type: 'spki', format: 'der' }), pinned = trust();
  pinned.tenants.ten_test[KEY].public_key_spki_der_base64 = der.toString('base64');
  pinned.tenants.ten_test[KEY].public_key_fingerprint_sha256 = createHash('sha256').update(der).digest('hex');
  denied(resolveReviewedExecutionGrantTrust({ trust: pinned, tenantId: 'ten_test', keyReference: KEY }));
});
test('independent signature from another actual key cannot qualify trusted grant', () => {
  const foreign = generateKeyPairSync('ed25519'), grant = structuredClone(signed());
  grant.signature = sign(null, Buffer.from(canonicalJsonStringify(grant.envelope)), foreign.privateKey).toString('base64');
  denied(verify(grant), 'reviewed_grant_signature_invalid');
});
test('cancellation during stalled body cancels actual underlying reader without waiting for timeout', async () => {
  let cancelled = 0, begin;
  const started = new Promise((resolve) => { begin = resolve; });
  const adapter = external(async () => new Response(new ReadableStream({ pull() { begin(); }, cancel() { cancelled++; } })));
  const controller = new AbortController();
  const signing = signReviewedExecutionGrant(signInput(context(), { signingAdapter: adapter, signal: controller.signal }));
  await started; controller.abort(); denied(await signing, 'reviewed_grant_signing_cancelled');
  await Promise.resolve(); assert.equal(cancelled, 1);
});
for (const raw of ['{}', 'null', '[]', '{', JSON.stringify({ ...trust(), purpose: 'astranull.custody' }),
  JSON.stringify({ ...trust(), tenants: {} }), JSON.stringify({ ...trust(), tenants: { ten_test: {} } })]) {
  test('environment trust loader rejects malformed or empty purpose trust before use', () => {
    denied(loadReviewedExecutionGrantTrust({ ASTRANULL_REVIEWED_EXECUTION_GRANT_TRUST_JSON: raw }));
  });
}
test('environment public trust loader rejects configured private material and invalid points', () => {
  const pinned = trust(); pinned.tenants.ten_test[KEY].private_key_pkcs8_der_base64 = PRIVATE;
  denied(loadReviewedExecutionGrantTrust({ ASTRANULL_REVIEWED_EXECUTION_GRANT_TRUST_JSON: JSON.stringify(pinned) }));
  delete pinned.tenants.ten_test[KEY].private_key_pkcs8_der_base64;
  pinned.tenants.ten_test[KEY].public_key_spki_der_base64 = 'invalid';
  denied(loadReviewedExecutionGrantTrust({ ASTRANULL_REVIEWED_EXECUTION_GRANT_TRUST_JSON: JSON.stringify(pinned) }));
});
