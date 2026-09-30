import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { createTargetGroup } from '../../src/services/targetGroups.mjs';
import { cancelTestRun, startTestRun } from '../../src/services/testRuns.mjs';
import { getStore } from '../../src/store.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

// ADR-0008: agents and agent-observation ingestion are removed. Guardrails now protect the
// inline external-only validation loop (safe windows, rate limits, cancellation).

const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'engineer' };

function completeRunsForGroup() {
  for (const run of getStore().testRuns.filter((r) => r.target_group_id === 'tg_1')) {
    run.status = 'verdicted';
    run.completed_at = new Date().toISOString();
  }
}

describe('safe-test guardrails', () => {
  it('rejects runs outside configured safe_test_windows', () => {
    freshStore();
    const group = getStore().targetGroups.find((g) => g.id === 'tg_1');
    group.safe_test_windows = [
      {
        start_at: new Date(Date.now() + 3_600_000).toISOString(),
        end_at: new Date(Date.now() + 7_200_000).toISOString(),
        reason: 'maintenance',
      },
    ];
    const result = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.equal(result.error, 'safe_window_closed');
    assert.equal(result.status, 429);
    assert.ok(getStore().auditLog.some((a) => a.action === 'test_run.safe_window_denied'));
  });

  it('permits runs inside a current safe_test_window', () => {
    freshStore();
    const group = getStore().targetGroups.find((g) => g.id === 'tg_1');
    group.safe_test_windows = [
      {
        start_at: new Date(Date.now() - 60_000).toISOString(),
        end_at: new Date(Date.now() + 60_000).toISOString(),
      },
    ];
    const result = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.ok(result.run);
    assert.ok(result.run.safety_constraints);
    assert.equal(result.run.safety_constraints.max_runs_per_hour, 60);
  });

  it('enforces max_runs_per_hour for the tenant', () => {
    freshStore();
    const group = getStore().targetGroups.find((g) => g.id === 'tg_1');
    group.safety_policy = { max_runs_per_hour: 1, min_seconds_between_runs: 0 };
    const first = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.ok(first.run);
    completeRunsForGroup();
    const second = startTestRun(ctx, {
      check_id: 'dns.authoritative_response.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.equal(second.error, 'safe_rate_cap_exceeded');
    assert.equal(second.status, 429);
    assert.ok(getStore().auditLog.some((a) => a.action === 'test_run.safe_rate_denied'));
  });

  it('enforces min_seconds_between_runs on the target group', () => {
    freshStore();
    const group = getStore().targetGroups.find((g) => g.id === 'tg_1');
    group.safety_policy = { max_runs_per_hour: 60, min_seconds_between_runs: 300 };
    const first = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.ok(first.run);
    const cancelled = cancelTestRun(ctx, first.run.id);
    assert.ok(cancelled.run);
    const retry = startTestRun(ctx, {
      check_id: 'dns.authoritative_response.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.equal(retry.error, 'safe_min_interval_active');
    assert.equal(retry.status, 429);
    assert.ok(getStore().auditLog.some((a) => a.action === 'test_run.safe_interval_denied'));
  });

  it('stores safety policy fields on createTargetGroup', () => {
    freshStore();
    const adminCtx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const group = createTargetGroup(adminCtx, {
      name: 'Guarded',
      timezone: 'America/New_York',
      safe_test_windows: [{ start_at: '2026-01-01T00:00:00.000Z', end_at: '2026-12-31T00:00:00.000Z' }],
      safety_policy: { max_runs_per_hour: 12, min_seconds_between_runs: 30 },
    });
    assert.equal(group.timezone, 'America/New_York');
    assert.equal(group.safe_test_windows.length, 1);
    assert.equal(group.safety_policy.max_runs_per_hour, 12);
    assert.equal(group.safety_policy.min_seconds_between_runs, 30);
  });

  it('returns not_cancellable for verdicted runs via service and HTTP', async () => {
    freshStore();
    const started = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    getStore().testRuns.find((r) => r.id === started.run.id).status = 'verdicted';
    const denied = cancelTestRun(ctx, started.run.id);
    assert.equal(denied.error, 'not_cancellable');
    assert.equal(denied.status, 409);

    const server = createServer();
    await new Promise((resolve) => server.listen(0, resolve));
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    try {
      const res = await request(baseUrl, 'POST', `/v1/test-runs/${started.run.id}/cancel`, {
        headers: demoHeaders('engineer'),
      });
      assert.equal(res.status, 409);
      assert.equal(res.json.error, 'not_cancellable');
    } finally {
      server.close();
    }
  });
});
