import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import { createHash } from 'node:crypto';
import { buildReviewedOperationPlan, reviewedOperationGap } from '../../src/contracts/reviewedOperations.mjs';
import { canonicalJsonStringify } from '../../src/lib/custody.mjs';
import { dnsOwnershipTargetBinding } from '../../src/lib/dnsOwnershipTarget.mjs';
import { createReviewedOperationService } from '../../src/services/reviewedOperations.mjs';
import { createDevReviewedOperationBackend } from '../../src/services/devReviewedOperations.mjs';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const at = '2026-10-10T00:00:00.000Z';
const tenantId = 'ten_demo';
const ctx = { tenantId, userId: 'reviewer_test', role: 'admin' };
const check = getCheckById('waf.evasion_alt_charset.safe');
const target = { id: 'tgt_inert_review', tenant_id: tenantId, kind: 'url', value: 'https://owned.example.test/diagnostics',
  target_group_id: 'tg_1', declaration_json: {}, created_at: '2026-10-09T00:00:00.000Z' };
const body = () => ({ target_id: target.id, check_id: check.check_id, template: 'inert-json-v1',
  semantics: 'inert_diagnostic', side_effects: 'none', expires_at: '2026-10-10T01:00:00.000Z' });
let clock, service;
beforeEach(() => {
  freshStore();
  const store = getStore();
  store.targetVerifications = [];
  store.reviewedOperations = [];
  store.targets.push(structuredClone(target));
  store.targetVerifications.push({ id: 'verification_inert_review', tenant_id: tenantId, target_id: target.id,
    state: 'dns_verified', source_kind: 'dns_txt', source_ref: { dns_target_binding: dnsOwnershipTargetBinding(target) },
    transitioned_at: target.created_at, transitioned_by: 'fixture' });
  clock = at;
  service = createReviewedOperationService({ backend: createDevReviewedOperationBackend(), now: () => new Date(clock) });
});
async function approve() {
  const proposal = await service.preview(ctx, body());
  assert.equal(proposal.error, undefined, JSON.stringify(proposal));
  const row = await service.approve(ctx, { ...body(), reviewed_plan_digest: proposal.plan_digest });
  assert.equal(row.error, undefined, JSON.stringify(row));
  return row;
}

describe('durable reviewed inert endpoint preflight', () => {
  it('pins exact URL, fixed schema, source definition, reviewer and expiry without granting execution', async () => {
    const before = getStore().auditLog.length;
    const proposal = await service.preview(ctx, body());
    assert.equal(proposal.plan.endpoint, target.value);
    assert.equal(proposal.plan.method, 'POST');
    assert.equal(proposal.plan.request_schema, 'fixed-asn-marker-json.v1');
    assert.equal(proposal.plan.maximum_body_bytes, 1024);
    assert.equal(getStore().auditLog.length, before);
    const row = await approve();
    assert.equal(row.approved_by, ctx.userId);
    assert.equal(row.approved_role, 'admin');
    assert.equal(row.current_review_gap, null);
    assert.equal(row.grants_execution, false);
    assert.equal(row.execution_available, false);
    assert.equal(getStore().probeJobs.length, 0);
    assert.equal(getStore().testRuns.length, 0);
    assert.equal(getStore().auditLog.filter((entry) => entry.action === 'reviewed_operation.approved').length, 1);
    const replay = await service.approve(ctx, { ...body(), reviewed_plan_digest: row.plan_digest });
    assert.equal(replay.id, row.id);
    assert.equal(replay.replayed, true);
    assert.equal(getStore().reviewedOperations.length, 1);
  });

  for (const actor of [{ ...ctx, role: 'viewer' }, { ...ctx, role: 'engineer' }, { ...ctx, role: 'soc' },
    { ...ctx, serviceAccountId: 'svc_fixture' }, { ...ctx, scopes: ['test_run:read'] }, { ...ctx, userId: undefined }]) {
    it('rejects non-human, insufficient-role or insufficient-scope approval', async () => {
      assert.equal((await service.approve(actor, body())).error, 'forbidden');
      assert.equal(getStore().reviewedOperations.length, 0);
    });
  }
  for (const [key, value] of [['approved_by', 'forged'], ['soc_approved', true], ['raw_body', 'anything'], ['headers', {}],
    ['endpoint', 'https://other.example.test'], ['callback', 'https://other.example.test'], ['credentials', {}]]) {
    it(`rejects arbitrary or server-owned ${key}`, async () => {
      assert.equal((await service.preview(ctx, { ...body(), [key]: value })).error, 'operation_field_not_allowed');
    });
  }
  it('requires the exact reviewed digest, with no review boolean substitute', async () => {
    assert.equal((await service.approve(ctx, body())).error, 'reviewed_plan_digest_mismatch');
    assert.equal((await service.approve(ctx, { ...body(), reviewed_plan_digest: '0'.repeat(64) })).error, 'reviewed_plan_digest_mismatch');
    assert.equal(getStore().reviewedOperations.length, 0);
  });
  it('never calls injected execution availability or projects an unfinished lifecycle as executable', async () => {
    let calls = 0;
    service = createReviewedOperationService({ backend: createDevReviewedOperationBackend(), now: () => new Date(clock),
      executionAvailability: () => { calls++; return { available: true }; } });
    const row = await approve();
    for (const result of [row, await service.get(ctx, row.id),
      await service.approve(ctx, { ...body(), reviewed_plan_digest: row.plan_digest })]) {
      assert.equal(result.grants_execution, false);
      assert.equal(result.execution_available, false);
      assert.equal(result.reviewed_execution.available, false);
      assert.equal(result.reviewed_execution.reason, 'reviewed_operation_execution_unavailable');
    }
    assert.equal(calls, 0);
    assert.equal(getStore().probeJobs.length, 0);
    assert.equal(getStore().testRuns.length, 0);
  });

  it('revocation is audited and terminal; history stays readable without execution', async () => {
    const row = await approve();
    const revoked = await service.revoke(ctx, row.id);
    assert.equal(revoked.current_review_gap, 'operation_revoked');
    assert.equal((await service.revoke(ctx, row.id)).error, 'operation_revoked');
    assert.equal((await service.approve(ctx, { ...body(), reviewed_plan_digest: row.plan_digest })).error, 'operation_revoked');
    assert.equal(getStore().auditLog.filter((entry) => entry.action === 'reviewed_operation.revoked').length, 1);
    assert.equal((await service.get(ctx, row.id)).plan_digest, row.plan_digest);
  });
  it('withholds current review after target change, ownership revocation or expiry without mutating the plan', async () => {
    const row = await approve();
    const mutable = getStore().targets.find((item) => item.id === target.id);
    mutable.value = 'https://owned.example.test/other';
    assert.equal((await service.get(ctx, row.id)).current_review_gap, 'operation_target_changed');
    mutable.value = target.value;
    getStore().targetVerifications.find((item) => item.target_id === target.id).state = 'unverified';
    assert.equal((await service.get(ctx, row.id)).current_review_gap, 'ownership_not_verified');
    clock = '2026-10-10T01:00:00.000Z';
    assert.equal((await service.get(ctx, row.id)).current_review_gap, 'operation_expired');
    assert.equal(getStore().reviewedOperations[0].plan_digest, row.plan_digest);
  });
  it('does not disclose foreign target or review identity', async () => {
    const row = await approve();
    const foreign = { ...ctx, tenantId: 'ten_other' };
    assert.equal((await service.get(foreign, row.id)).error, 'operation_not_found');
    assert.equal((await service.revoke(foreign, row.id)).error, 'operation_not_found');
    assert.equal((await service.preview(foreign, body())).error, 'target_not_found');
  });
  it('binds the canonical check definition, not just its unchanged explicit version', async () => {
    const row = await approve();
    const changed = { ...check, probe_profile: { ...check.probe_profile, timeout_ms: 123 } };
    assert.equal(reviewedOperationGap(row, { tenantId, target, check: changed, now: at }), 'operation_check_changed');
  });
  it('reconstructs fixed schemas rather than accepting arbitrary re-digested stored methods', async () => {
    const row = await approve();
    row.plan.method = 'DELETE';
    row.plan_digest = createHash('sha256').update(canonicalJsonStringify(row.plan)).digest('hex');
    assert.equal(reviewedOperationGap(row, { tenantId, target, check, now: at }), 'operation_review_invalid');
  });
  for (const mutation of [
    (b) => { b.expires_at = at; }, (b) => { b.expires_at = '2026-10-12T00:00:00Z'; },
    (b) => { b.expires_at = 'invalid'; }, (b) => { b.semantics = 'business_transaction'; },
    (b) => { b.side_effects = 'send_email'; }, (b) => { b.template = 'free_form'; },
  ]) it('rejects unsafe semantics, templates and unbounded expiry', () => {
    const value = body(); mutation(value);
    assert.throws(() => buildReviewedOperationPlan(value, { tenantId, target, check, now: at }));
  });
  it('rejects coerced identities, coerced expiry and calendar rollover', () => {
    for (const changes of [{ target_id: [target.id] }, { check_id: [check.check_id] },
      { expires_at: ['2026-10-10T01:00:00Z'] }, { expires_at: '2026-10-09T25:00:00Z' }]) {
      assert.throws(() => buildReviewedOperationPlan({ ...body(), ...changes }, { tenantId, target, check, now: at }));
    }
    assert.throws(() => buildReviewedOperationPlan({ ...body(), expires_at: '2026-02-30T01:00:00Z' },
      { tenantId, target, check, now: '2026-03-01T01:00:00Z' }), /operation_expiry_invalid/);
  });
  it('requires URL applicability, a safe class, matching port and supported template', () => {
    for (const invalid of [{ ...check, supported_targets: ['fqdn'] }, { ...check, safety_class: 'soc_only' },
      { ...check, probe_profile: { ...check.probe_profile, kind: 'tcp_connect' } }]) {
      assert.throws(() => buildReviewedOperationPlan(body(), { tenantId, target, check: invalid, now: at }), /operation_check_not_supported/);
    }
    assert.throws(() => buildReviewedOperationPlan(body(), { tenantId, target: { ...target, port: 8443 }, check, now: at }), /operation_endpoint_port_mismatch/);
    assert.throws(() => buildReviewedOperationPlan(body(), { tenantId, target: { ...target, kind: 'fqdn' }, check, now: at }), /exact_url_target_required/);
    assert.throws(() => buildReviewedOperationPlan(body(), { tenantId, target: { ...target, deleted_at: at }, check, now: at }), /target_not_active/);
  });
  it('rolls back in-memory approval and revocation when audit construction fails', async () => {
    const backend = createDevReviewedOperationBackend();
    const proposal = buildReviewedOperationPlan(body(), { tenantId, target, check, now: at });
    const row = { id: 'rop_audit_failure', tenant_id: tenantId, target_id: target.id,
      plan: proposal.plan, plan_digest: proposal.plan_digest, approved_by: ctx.userId, approved_role: ctx.role,
      approved_at: at, revoked_at: null, revoked_by: null };
    const brokenAudit = Object.defineProperty({}, 'action', { enumerable: true, get() { throw new Error('audit construction failed'); } });
    await assert.rejects(backend.withTarget(ctx, target.id, (tx) => tx.insert(row, brokenAudit)), /audit construction failed/);
    assert.deepEqual(getStore().reviewedOperations, []);
    assert.equal(getStore().auditLog.length, 0);
    const approved = await approve();
    const priorAuditCount = getStore().auditLog.length;
    await assert.rejects(backend.withTarget(ctx, target.id, (tx) => tx.revoke({ ...approved, revoked_at: at, revoked_by: ctx.userId }, brokenAudit)), /audit construction failed/);
    assert.equal(getStore().reviewedOperations[0].revoked_at, null);
    assert.equal(getStore().auditLog.length, priorAuditCount);
    assert.equal((await service.get(ctx, approved.id)).current_review_gap, null);
  });
  it('reads the locked current revocation instead of an earlier optimistic lookup', async () => {
    const row = await approve();
    const revoked = { ...row, revoked_at: at, revoked_by: ctx.userId };
    const reader = createReviewedOperationService({ now: () => new Date(at), backend: {
      get: async () => row,
      withTarget: async (_ctx, _id, fn) => fn({ get: async () => revoked, context: async () => ({ target, ownershipVerified: true }) }),
    } });
    assert.equal((await reader.get(ctx, row.id)).current_review_gap, 'operation_revoked');
  });
  it('serializes concurrent approvals to one immutable record and one audit', async () => {
    const proposal = await service.preview(ctx, body());
    const rows = await Promise.all(Array.from({ length: 8 }, () => service.approve(ctx, { ...body(), reviewed_plan_digest: proposal.plan_digest })));
    assert.equal(new Set(rows.map((row) => row.id)).size, 1);
    assert.equal(rows.filter((row) => row.replayed === false).length, 1);
    assert.equal(getStore().auditLog.filter((entry) => entry.action === 'reviewed_operation.approved').length, 1);
  });
  for (const value of ['https://user:pass@owned.example.test/diagnostics', 'https://owned.example.test/diagnostics?existing=1',
    'https://owned.example.test/diagnostics#fragment', 'ftp://owned.example.test/diagnostics']) {
    it('rejects credentials, query or fragment ambiguity and non-HTTP endpoints', () => {
      assert.throws(() => buildReviewedOperationPlan(body(), { tenantId, target: { ...target, value }, check, now: at }), /invalid_operation_endpoint/);
    });
  }
});
