import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { createReviewedOperationService } from '../../src/services/reviewedOperations.mjs';
import { createDevReviewedOperationBackend } from '../../src/services/devReviewedOperations.mjs';
import { getStore } from '../../src/store.mjs';
import { dnsOwnershipTargetBinding } from '../../src/lib/dnsOwnershipTarget.mjs';
import { freshStore } from '../helpers/reset.mjs';

const AT = '2026-10-10T00:00:00.000Z';
const ctx = { tenantId: 'ten_url_review', userId: 'usr_owner', role: 'owner' };
const target = { id: 'tgt_url_review', tenant_id: ctx.tenantId, target_group_id: 'tg_url_review', kind: 'url',
  value: 'https://owned.example.test/diagnostics', protocol: 'https', port: 443, expected_behavior: 'intentionally_public', declaration_json: {} };
const body = () => ({ target_id: target.id, check_id: getCheckById('waf.evasion_base64_wrap.safe').check_id,
  template: 'marker-query-v1', semantics: 'inert_diagnostic', side_effects: 'none', expires_at: '2026-10-10T01:00:00.000Z' });
let service;
beforeEach(() => {
  freshStore();
  const store = getStore();
  store.targets.push(structuredClone(target));
  store.targetVerifications = [{ id: 'tv_url_review', tenant_id: ctx.tenantId, target_id: target.id,
    state: 'dns_verified', source_kind: 'dns_txt', source_ref: {}, transitioned_at: '2026-10-09T00:00:00.000Z' }];
  store.reviewedOperations = [];
  service = createReviewedOperationService({ backend: createDevReviewedOperationBackend(), now: () => new Date(AT) });
});

test('an exact current direct URL proof permits passive review only', async () => {
  getStore().targetVerifications[0].source_ref = { dns_target_binding: dnsOwnershipTargetBinding(target) };
  const proposal = await service.preview(ctx, body());
  assert.equal(proposal.error, undefined);
  const row = await service.approve(ctx, { ...body(), reviewed_plan_digest: proposal.plan_digest });
  assert.equal(row.current_review_gap, null);
  assert.equal(row.grants_execution, false);
  assert.equal(row.execution_available, false);
  assert.equal(getStore().testRuns.length, 0);
  assert.equal(getStore().probeJobs.length, 0);
});

for (const change of [{ value: 'https://owned.example.test/other' }, { port: 8443 },
  { protocol: 'http' }, { expected_behavior: 'must_block_before_origin' }, { declaration_json: { operation: 'changed' } }]) {
  test('a changed URL cannot use old DNS proof to approve a new material plan', async () => {
    getStore().targetVerifications[0].source_ref = { dns_target_binding: dnsOwnershipTargetBinding(target) };
    Object.assign(getStore().targets.find((row) => row.id === target.id), change);
    assert.deepEqual(await service.preview(ctx, body()), { error: 'ownership_not_verified', status: 409 });
    assert.equal(getStore().reviewedOperations.length, 0);
  });
}

for (const source_kind of ['inherited_parent', 'manual_override', 'provider_account']) {
  test(`non-direct URL proof ${source_kind} cannot approve a reviewed plan`, async () => {
    Object.assign(getStore().targetVerifications[0], { source_kind,
      source_ref: { dns_target_binding: dnsOwnershipTargetBinding(target) } });
    assert.deepEqual(await service.preview(ctx, body()), { error: 'ownership_not_verified', status: 409 });
  });
}

for (const source_ref of [{}, { dns_challenge_id: 'dns_legacy' }, { dns_target_binding: {} }]) {
  test('an unbound legacy URL proof cannot authorize a new exact reviewed plan', async () => {
    getStore().targetVerifications[0].source_ref = source_ref;
    const before = getStore().auditLog.length;
    assert.deepEqual(await service.preview(ctx, body()), { error: 'ownership_not_verified', status: 409 });
    assert.deepEqual(await service.approve(ctx, { ...body(), reviewed_plan_digest: 'a'.repeat(64) }),
      { error: 'ownership_not_verified', status: 409 });
    assert.equal(getStore().reviewedOperations.length, 0);
    assert.equal(getStore().testRuns.length, 0);
    assert.equal(getStore().probeJobs.length, 0);
    assert.equal(getStore().auditLog.length, before);
  });
}
