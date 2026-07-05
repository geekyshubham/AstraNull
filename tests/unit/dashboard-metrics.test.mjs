import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  countActiveTargetGroups,
  countAgentsOnline,
  countHighScaleRequests,
  countOpenFindings,
  resolveDashboardMetrics,
  resolveRecentRuns
} from '../../apps/web/react/src/lib/dashboard-metrics.ts';

describe('dashboard-metrics', () => {
  it('derives list-backed counts with the same semantics as GET /v1/state', () => {
    const targetGroups = [
      { id: 'tg_active', archived_at: null },
      { id: 'tg_archived', archived_at: '2026-01-01T00:00:00.000Z' }
    ];
    const agents = [
      { id: 'a1', status: 'online' },
      { id: 'a2', status: 'offline' }
    ];
    const findings = [
      { id: 'f1', status: 'open' },
      { id: 'f2', status: 'closed' }
    ];
    const highScale = [{ id: 'hs1' }, { id: 'hs2' }];

    assert.equal(countActiveTargetGroups(targetGroups), 1);
    assert.equal(countAgentsOnline(agents), 1);
    assert.equal(countOpenFindings(findings), 1);
    assert.equal(countHighScaleRequests(highScale), 2);

    const metrics = resolveDashboardMetrics({
      state: null,
      targetGroups,
      agents,
      findings,
      highScale,
      runs: []
    });

    assert.deepEqual(metrics, {
      targetGroups: 1,
      agentsOnline: 1,
      openFindings: 1,
      highScaleRequests: 2
    });
  });

  it('prefers /v1/state metrics when present', () => {
    const metrics = resolveDashboardMetrics({
      state: {
        target_groups: 4,
        agents_online: 3,
        open_findings: 2,
        high_scale_requests: 1
      },
      targetGroups: [{ id: 'tg1' }],
      agents: [{ id: 'a1', status: 'online' }],
      findings: [{ id: 'f1', status: 'open' }],
      highScale: [],
      runs: []
    });

    assert.deepEqual(metrics, {
      targetGroups: 4,
      agentsOnline: 3,
      openFindings: 2,
      highScaleRequests: 1
    });
  });

  it('prefers state recent_runs over the full runs list', () => {
    const recentRuns = resolveRecentRuns({
      state: {
        recent_runs: [
          { id: 'run_a' },
          { id: 'run_b' },
          { id: 'run_c' }
        ]
      },
      runs: [
        { id: 'run_old' },
        { id: 'run_a' },
        { id: 'run_b' },
        { id: 'run_c' }
      ]
    }, 2);

    assert.deepEqual(recentRuns.map((run) => run.id), ['run_c', 'run_b']);
  });
});