import assert from 'node:assert/strict';
import { test } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { buildReviewedOperationPlan, reviewedOperationGap } from '../../src/contracts/reviewedOperations.mjs';

const NOW = '2026-02-28T00:00:00.000Z';
const target = { id: 'tgt_clock', tenant_id: 'ten_clock', kind: 'url', value: 'https://clock.example.test/diagnostics',
  protocol: 'https', port: 443, expected_behavior: 'intentionally_public' };
const check = getCheckById('waf.evasion_base64_wrap.safe');
const context = { tenantId: target.tenant_id, target, check, now: NOW };
const proposal = buildReviewedOperationPlan({ target_id: target.id, check_id: check.check_id,
  template: 'marker-query-v1', semantics: 'inert_diagnostic', side_effects: 'none',
  expires_at: '2026-02-28T01:00:00.000Z' }, context);
const review = { id: 'rop_clock', tenant_id: target.tenant_id, target_id: target.id, ...proposal,
  approved_by: 'usr_owner', approved_role: 'owner', approved_at: NOW, revoked_at: null, revoked_by: null };

test('passive review accepts the unchanged canonical approval clock without granting execution', () => {
  assert.equal(reviewedOperationGap(review, context), null);
  assert.equal(proposal.grants_execution, false);
  assert.equal(proposal.execution_available, false);
});

for (const approved_at of [
  '2026-02-28T00:00:00.000999Z',
  '2026-02-27T23:59:59.999999Z',
  '2026-02-28T00:00:00.000000Z',
  '2026-02-28T01:00:00.000+01:00',
  '2026-02-28T00:00:00',
  '2026-02-28',
  null,
  Infinity,
]) {
  test(`passive review rejects noncanonical authority clock ${String(approved_at)}`, () => {
    assert.equal(reviewedOperationGap({ ...review, approved_at }, context), 'operation_review_invalid');
  });
}
