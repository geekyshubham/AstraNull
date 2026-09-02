import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import {
  countActiveTargetGroups,
  countAgentsOnline,
  countHighScaleRequests,
  countOpenFindings,
  resolveDashboardMetrics,
  resolveRecentRuns
} from '../../apps/web/react/src/lib/dashboard-metrics.ts';
import { formatNumber } from '../../apps/web/react/src/lib/utils.ts';

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
      { id: 'f1', state: ' Open ' },
      { id: 'f2', state: ' closed ' }
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

  it('keeps 10k groups, 5k targets, and 33,334 findings distinct at scale', () => {
    const metrics = resolveDashboardMetrics({
      state: {
        target_groups: 10_000,
        agents_online: 0,
        open_findings: 33_334,
        high_scale_requests: 0
      },
      targetGroups: [],
      targets: Array.from({ length: 5_000 }, (_, index) => ({ id: `tgt_${index}` })),
      agents: [],
      findings: [],
      highScale: [],
      runs: []
    });

    assert.equal(metrics.targetGroups, 10_000);
    assert.equal(metrics.openFindings, 33_334);
    assert.equal(formatNumber(metrics.targetGroups), '10,000');
    assert.equal(formatNumber(5_000), '5,000');
    assert.equal(formatNumber(metrics.openFindings), '33,334');
    assert.equal(Object.hasOwn(metrics, 'targets'), false, 'state has no target count to expose');
    assert.equal(Object.hasOwn(metrics, 'targetCount'), false, 'dashboard must not invent a target count');
  });

  it('pins source labels and shared formatting on every scale-count surface', () => {
    const dashboard = readFileSync('apps/web/react/src/pages/page-components.tsx', 'utf8');
    const targets = readFileSync('apps/web/react/src/pages/targets-page.tsx', 'utf8');
    const governance = readFileSync('apps/web/react/src/pages/governance-pages.tsx', 'utf8');

    assert.match(
      dashboard,
      /delta=\{data\.loadErrors\.targetGroups \? 'Target group data unavailable' : `\${formatNumber\(metrics\.targetGroups\)} \${pluralize\(metrics\.targetGroups, 'target group'\)}`\}/,
    );
    assert.doesNotMatch(dashboard, /pluralize\(metrics\.targetGroups, 'target'\)/);
    assert.doesNotMatch(dashboard, /data\.state\?\.(?:targets|target_count)/);
    assert.match(
      dashboard,
      /label="Open findings"[\s\S]*?value=\{data\.loadErrors\.findings \? '—' : formatNumber\(metrics\.openFindings\)\}/,
    );
    assert.match(
      targets,
      /Declared targets<\/span><strong>{formatNumber\(targets\.length\)}/,
    );
    assert.match(
      governance,
      /{formatNumber\(openFindingsCount\)}<\/span> open findings/,
    );
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