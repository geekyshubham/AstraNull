import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  REVIEWED_SAFE_CHECK_ID, acceptedReviewedSafeExecution, reviewedSafePlanPresentation,
  reviewedSafeReviewPresentation, reviewedSafeStartBody,
} from '../../apps/web/react/src/lib/reviewed-safe-check.mjs';

const now = Date.parse('2026-10-10T12:00:00.000Z');
const target = { id: 'url_target', tenant_id: 'tenant_a', target_group_id: 'group_a', kind: 'url', value: 'https://declared.example/diagnostic' };
const options = { target, tenantId: 'tenant_a', now };
const review = () => ({
  id: 'review_1', tenant_id: 'tenant_a', target_id: 'url_target', plan_digest: 'a'.repeat(64),
  plan: { version: 'reviewed-inert-operation.v1', tenant_id: 'tenant_a', target_id: 'url_target',
    check_id: REVIEWED_SAFE_CHECK_ID, check_version: 'check-definition.v1', scenario_version: 'marker-comparison-v4',
    target_definition_digest: 'b'.repeat(64), check_definition_digest: 'c'.repeat(64),
    endpoint: target.value, method: 'GET', template: 'marker-query-v1',
    semantics: 'inert_diagnostic', side_effects: 'none', request_schema: 'fixed-asn-probe-query.v1',
    maximum_body_bytes: 0, maximum_probe_operations: 4, expires_at: '2026-10-10T12:15:00.000Z' },
  approved_by: 'human_owner', approved_role: 'owner', approved_at: '2026-10-10T11:59:00.000Z',
  revoked_at: null, revoked_by: null, current_review_gap: null,
  grants_execution: false, execution_available: false,
  reviewed_execution: { available: true, check_id: REVIEWED_SAFE_CHECK_ID, reason: null },
});

function rejected(value, context = options) {
  assert.equal(reviewedSafeReviewPresentation(value, context).available, false);
  assert.equal(reviewedSafeStartBody(value, context), null, 'no omitted-selector ordinary-run fallback');
}

describe('reviewed safe GET UI presentation', () => {
  it('keeps a passive preview distinct from approval and executable runtime availability', () => {
    const value = review();
    const preview = { plan: value.plan, plan_digest: value.plan_digest, grants_execution: false, execution_available: false };
    assert.equal(reviewedSafePlanPresentation(preview, options).valid, true);
    rejected(preview);
  });

  it('builds only the exact selected reviewed start body without profile or authority overrides', () => {
    assert.equal(reviewedSafeReviewPresentation(review(), options).available, true);
    assert.deepEqual(reviewedSafeStartBody(review(), options), {
      target_group_id: 'group_a', target_id: 'url_target', check_id: REVIEWED_SAFE_CHECK_ID, reviewed_operation_id: 'review_1',
    });
  });

  it('fails closed for absent, false, mistyped, contradictory or other-check availability', () => {
    for (const projection of [undefined, null, true, {}, { available: false },
      { available: 'true', check_id: REVIEWED_SAFE_CHECK_ID, reason: null },
      { available: true, check_id: 'other', reason: null },
      { available: true, check_id: REVIEWED_SAFE_CHECK_ID },
      { available: true, check_id: REVIEWED_SAFE_CHECK_ID, reason: 'unavailable' }]) {
      rejected({ ...review(), reviewed_execution: projection });
    }
  });

  it('requires explicit current authority rather than missing or truthy review gaps', () => {
    for (const gap of [undefined, false, '', 'ownership_not_verified', 'operation_target_changed', 'operation_expired']) {
      rejected({ ...review(), current_review_gap: gap });
    }
  });

  it('rejects revoked, expired, future-approved and malformed human approval records', () => {
    for (const change of [{ revoked_at: '2026-10-10T11:59:30.000Z' }, { revoked_by: 'owner' },
      { approved_at: '2026-10-10T12:00:00.001Z' }, { approved_at: 'not-a-date' },
      { approved_at: '2026-10-10T11:59:00Z' }, { approved_role: 'analyst' },
      { approved_by: '' }, { approved_by: true }, { id: '../review' }]) rejected({ ...review(), ...change });
    const expired = review(); expired.plan.expires_at = '2026-10-10T12:00:00.000Z'; rejected(expired);
    const long = review(); long.plan.expires_at = '2026-10-11T12:15:00.000Z'; rejected(long);
  });

  it('pins tenant, target, group, endpoint and URL-only material without coercion', () => {
    rejected(review(), { ...options, tenantId: 'tenant_b' });
    for (const change of [{ id: 'other' }, { tenant_id: 'tenant_b' }, { kind: 'fqdn' },
      { value: 'https://declared.example/other' }, { value: 'https://user:password@declared.example/diagnostic' },
      { value: `${target.value}?nonce=old` }, { value: `${target.value}#fragment` }, { deleted_at: '2026-10-10T11:00:00.000Z' }]) {
      rejected(review(), { ...options, target: { ...target, ...change } });
    }
    for (const group of [undefined, null, 1, '', '../group']) {
      assert.equal(reviewedSafeStartBody(review(), { ...options, target: { ...target, target_group_id: group } }), null);
    }
    const other = review(); other.plan.target_id = 'other'; rejected(other);
    rejected({ ...review(), target_id: 'other' });
    rejected({ ...review(), tenant_id: 'tenant_b' });
    for (const id of [undefined, null, 1, '', '../target']) {
      const malformed = review(); malformed.target_id = id; malformed.plan.target_id = id;
      rejected(malformed, { ...options, target: { ...target, id } });
    }
    for (const tenantId of [undefined, null, 1, '', '../tenant']) {
      const malformed = review(); malformed.tenant_id = tenantId; malformed.plan.tenant_id = tenantId;
      rejected(malformed, { ...options, tenantId, target: { ...target, tenant_id: tenantId } });
    }
  });

  it('requires the fixed GET serializer and exact passive bounds, not catalog support flags', () => {
    for (const change of [{ check_id: 'other' }, { method: 'POST' }, { template: 'inert-json-v1' },
      { request_schema: 'arbitrary' }, { maximum_body_bytes: 1 }, { maximum_probe_operations: 3 },
      { maximum_probe_operations: '4' }, { semantics: 'stateful' }, { side_effects: 'unknown' },
      { version: 'reviewed-inert-operation.v0' }, { check_version: undefined }, { scenario_version: 1 },
      { target_definition_digest: 'invalid' }, { check_definition_digest: undefined }]) {
      const value = review(); Object.assign(value.plan, change); rejected(value);
    }
    rejected({ ...review(), grants_execution: true });
    rejected({ ...review(), execution_available: true });
    rejected({ ...review(), plan_digest: 'invalid' });
  });

  it('never uses a malformed or nonfinite presentation clock as current availability', () => {
    for (const value of [NaN, Infinity, -Infinity]) rejected(review(), { ...options, now: value });
    for (const value of ['2026-02-30T12:15:00.000Z', '2026-10-10T12:15:00Z', '2026-10-10T12:15:00.000000Z']) {
      const changed = review(); changed.plan.expires_at = value; rejected(changed);
    }
  });

  it('retains only the exact newly accepted run instead of a historical or mismatched run', () => {
    const run = { id: 'run_1', target_id: target.id, check_id: REVIEWED_SAFE_CHECK_ID };
    assert.deepEqual(acceptedReviewedSafeExecution({ run }, target.id), {
      runId: run.id, targetId: target.id, checkId: REVIEWED_SAFE_CHECK_ID, record: run,
    });
    assert.equal(acceptedReviewedSafeExecution(run, target.id).runId, run.id);
    for (const value of [null, {}, { runs: [run] }, { ...run, id: '' }, { ...run, target_id: 'other' },
      { ...run, check_id: 'other' }, { id: run.id }, { ...run, target_id: undefined }]) {
      assert.equal(acceptedReviewedSafeExecution(value, target.id), null);
    }
  });
});
