import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  claimPolicyDispatchStart,
  completePolicyDispatch,
  createTestPolicy,
  dispatchDueTestPolicies,
  leaseDueTestPolicies,
  listDueTestPolicies,
  patchTestPolicy,
} from '../../src/services/testPolicies.mjs';
import { startTestRun } from '../../src/services/testRuns.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_engineer', role: 'engineer' };
const CHECK_ID = 'dns.authoritative_response.safe';

describe('developer test-policy scheduling', () => {
  it('enforces one active per-group check rule and persists all controls', () => {
    freshStore();
    const created = createTestPolicy(CTX, {
      target_group_id: 'tg_1',
      check_id: CHECK_ID,
      cadence: 'daily',
      timezone: 'UTC',
      enabled: true,
      max_concurrent_runs: 1,
      safe_windows: [],
    }, { now: '2026-06-01T00:00:00.000Z' });

    assert.equal(created.enabled, true);
    assert.equal(created.max_concurrent_runs, 1);
    assert.equal(created.timezone, 'UTC');
    assert.equal(created.next_run_at, '2026-06-01T00:01:00.000Z');

    const duplicate = createTestPolicy(CTX, {
      target_group_id: 'tg_1',
      check_id: CHECK_ID,
      cadence: 'weekly',
    });
    assert.equal(duplicate.error, 'test_policy_exists');
    assert.equal(duplicate.status, 409);
  });

  it('leases only due rows in the tenant and completes each occurrence exactly once', () => {
    freshStore();
    const policy = createTestPolicy(CTX, {
      target_group_id: 'tg_1',
      check_id: CHECK_ID,
      cadence: 'daily',
    }, { now: '2026-06-01T00:00:00.000Z' });
    const raw = getStore().testPolicies.find((row) => row.id === policy.id);
    raw.next_run_at = '2026-06-02T00:00:00.000Z';

    const due = listDueTestPolicies(CTX, { now: '2026-06-02T00:00:01.000Z' });
    assert.deepEqual(due.map((row) => row.id), [policy.id]);
    assert.deepEqual(listDueTestPolicies({ ...CTX, tenantId: 'ten_other' }, { now: '2026-06-03T00:00:00.000Z' }), []);

    const leases = leaseDueTestPolicies(CTX, {
      workerId: 'scheduler-1',
      now: '2026-06-02T00:00:01.000Z',
      leaseMs: 60_000,
    });
    assert.equal(leases.length, 1);
    assert.equal(leases[0].scheduled_for, '2026-06-02T00:00:00.000Z');
    assert.match(leases[0].idempotency_key, /^[a-f0-9]{64}$/);

    const concurrentLease = leaseDueTestPolicies(CTX, {
      workerId: 'scheduler-2',
      now: '2026-06-02T00:00:02.000Z',
    });
    assert.deepEqual(concurrentLease, []);

    const claimed = claimPolicyDispatchStart(CTX, policy.id, {
      dispatch_id: leases[0].dispatch_id,
      lease_token: leases[0].lease_token,
      idempotency_key: leases[0].idempotency_key,
    }, { now: '2026-06-02T00:00:02.500Z' });
    assert.equal(claimed.id, leases[0].dispatch_id);

    getStore().testRuns.push({
      id: 'run_scheduled_1', tenant_id: CTX.tenantId, target_group_id: 'tg_1',
      check_id: CHECK_ID, policy_id: policy.id, policy_dispatch_id: leases[0].dispatch_id,
    });
    const completed = completePolicyDispatch(CTX, policy.id, {
      dispatch_id: leases[0].dispatch_id,
      lease_token: leases[0].lease_token,
      idempotency_key: leases[0].idempotency_key,
      run_id: 'run_scheduled_1',
      state: 'dispatched',
    }, { now: '2026-06-02T00:00:03.000Z' });
    assert.equal(completed.state, 'dispatched');
    assert.equal(completed.run_id, 'run_scheduled_1');
    assert.equal(raw.next_run_at, '2026-06-03T00:00:00.000Z');

    const retry = completePolicyDispatch(CTX, policy.id, {
      dispatch_id: leases[0].dispatch_id,
      lease_token: leases[0].lease_token,
      idempotency_key: leases[0].idempotency_key,
      run_id: 'run_scheduled_1',
      state: 'dispatched',
    }, { now: '2026-06-02T00:00:04.000Z' });
    assert.equal(retry.run_id, 'run_scheduled_1');
    assert.equal(getStore().testPolicyDispatches.length, 1);
  });

  it('re-leases an expired occurrence after a start claim for idempotent recovery', () => {
    freshStore();
    const policy = createTestPolicy(CTX, {
      target_group_id: 'tg_1', check_id: CHECK_ID, cadence: 'daily',
    }, { now: '2026-06-01T00:00:00.000Z' });
    const raw = getStore().testPolicies.find((row) => row.id === policy.id);
    raw.next_run_at = '2026-06-02T00:00:00.000Z';

    const first = leaseDueTestPolicies(CTX, {
      workerId: 'scheduler-1', now: '2026-06-02T00:00:01.000Z', leaseMs: 1_000,
    })[0];
    const second = leaseDueTestPolicies(CTX, {
      workerId: 'scheduler-2', now: '2026-06-02T00:00:03.000Z', leaseMs: 1_000,
    })[0];
    assert.equal(second.dispatch_id, first.dispatch_id);
    assert.notEqual(second.lease_token, first.lease_token);

    const claimed = claimPolicyDispatchStart(CTX, policy.id, {
      dispatch_id: second.dispatch_id,
      lease_token: second.lease_token,
      idempotency_key: second.idempotency_key,
    }, { now: '2026-06-02T00:00:03.500Z' });
    assert.equal(claimed.start_claimed_at, '2026-06-02T00:00:03.500Z');

    const recovered = leaseDueTestPolicies(CTX, {
      workerId: 'scheduler-3', now: '2026-06-02T00:00:05.000Z', leaseMs: 1_000,
    });
    assert.equal(recovered.length, 1);
    assert.equal(recovered[0].dispatch_id, first.dispatch_id);

    const invalidRunBinding = completePolicyDispatch(CTX, policy.id, {
      dispatch_id: second.dispatch_id,
      lease_token: second.lease_token,
      idempotency_key: second.idempotency_key,
      run_id: 'run_must_not_bind',
      state: 'failed',
    }, { now: '2026-06-02T00:00:05.500Z' });
    assert.equal(invalidRunBinding.error, 'invalid_policy_run_binding');

    getStore().testRuns.push({
      id: 'run_after_expiry', tenant_id: CTX.tenantId, target_group_id: 'tg_1',
      check_id: CHECK_ID, policy_id: policy.id, policy_dispatch_id: second.dispatch_id,
    });
    const completed = completePolicyDispatch(CTX, policy.id, {
      dispatch_id: recovered[0].dispatch_id,
      lease_token: recovered[0].lease_token,
      idempotency_key: recovered[0].idempotency_key,
      run_id: 'run_after_expiry',
      state: 'dispatched',
    }, { now: '2026-06-02T00:00:06.000Z' });
    assert.equal(completed.state, 'dispatched');

    const conflict = completePolicyDispatch(CTX, policy.id, {
      dispatch_id: second.dispatch_id,
      lease_token: second.lease_token,
      idempotency_key: second.idempotency_key,
      run_id: 'run_conflict',
      state: 'dispatched',
    }, { now: '2026-06-02T00:00:07.000Z' });
    assert.equal(conflict.error, 'policy_run_binding_mismatch');
  });

  it('claims before start and passes the exact durable dispatch binding', async () => {
    freshStore();
    const policy = createTestPolicy(CTX, {
      target_group_id: 'tg_1', check_id: CHECK_ID, cadence: 'daily',
    }, { now: '2026-06-01T00:00:00.000Z' });
    getStore().testPolicies.find((row) => row.id === policy.id).next_run_at = '2026-06-02T00:00:00.000Z';
    const calls = [];

    const results = await dispatchDueTestPolicies(CTX, {
      workerId: 'scheduler-1', now: '2026-06-02T00:00:01.000Z', leaseMs: 60_000,
      async startTestRun(callCtx, body, runtimeConfig, trusted) {
        calls.push({ callCtx, body, runtimeConfig, trusted });
        const dispatch = getStore().testPolicyDispatches.find((row) => row.id === body.policy_dispatch_id);
        assert.ok(dispatch.start_claimed_at, 'start side effect must follow durable claim');
        const run = { id: 'run_scheduled_exact', tenant_id: CTX.tenantId,
          target_group_id: body.target_group_id, check_id: body.check_id,
          policy_id: body.policy_id, policy_dispatch_id: body.policy_dispatch_id };
        getStore().testRuns.push(run);
        return { run };
      },
    });

    assert.equal(calls.length, 1);
    assert.equal(calls[0].body.policy_dispatch_id, results[0].dispatch.id);
    assert.equal(calls[0].trusted.policyDispatch.dispatch_id, results[0].dispatch.id);
    assert.equal(typeof calls[0].trusted.policyDispatch.lease_token, 'string');
    assert.ok(calls[0].trusted.policyDispatch.lease_token.length > 0);
    assert.equal(calls[0].trusted.policyDispatch.idempotency_key, results[0].dispatch.idempotency_key);
    assert.equal(calls[0].trusted.policyDispatch.scheduled_for, results[0].dispatch.scheduled_for);
    assert.equal(results[0].dispatch.state, 'dispatched');
    assert.equal(results[0].dispatch.run_id, 'run_scheduled_exact');
  });

  it('fails closed for event-driven create and update without a durable consumer', () => {
    freshStore();
    const rejected = createTestPolicy(CTX, {
      target_group_id: 'tg_1', check_id: CHECK_ID, cadence: 'event_driven',
      event_trigger: { type: 'finding.created' },
    });
    assert.equal(rejected.error, 'unsupported_policy_cadence');

    const policy = createTestPolicy(CTX, {
      target_group_id: 'tg_1', check_id: CHECK_ID, cadence: 'manual',
    });
    const patched = patchTestPolicy(CTX, policy.id, {
      cadence: 'event_driven', event_trigger: { type: 'finding.created' },
    });
    assert.equal(patched.error, 'unsupported_policy_cadence');
    assert.equal(getStore().testPolicies.find((row) => row.id === policy.id).cadence, 'manual');
  });

  it('binds a validated manual policy to a run and rejects a disabled rule', () => {
    freshStore();
    const policy = createTestPolicy(CTX, {
      target_group_id: 'tg_1',
      check_id: CHECK_ID,
      cadence: 'manual',
    });

    const disabled = patchTestPolicy(CTX, policy.id, { enabled: false });
    assert.equal(disabled.enabled, false);
    const denied = startTestRun(CTX, {
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: CHECK_ID,
      policy_id: policy.id,
    });
    assert.equal(denied.error, 'test_policy_disabled');

    patchTestPolicy(CTX, policy.id, { enabled: true });
    const started = startTestRun(CTX, {
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: CHECK_ID,
      policy_id: policy.id,
    });
    assert.equal(started.run.policy_id, policy.id);
    assert.equal(getStore().testRuns[0].policy_id, policy.id);
  });
});
