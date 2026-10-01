import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import {
  buildDefensePath,
  buildTargetPostureRows,
  classifyVerdict,
  countActiveTargetGroups,
  countHighScaleRequests,
  countOpenFindings,
  findingSeverityBuckets,
  isTargetVerified,
  overallDefenseStatus,
  resolveDashboardMetrics,
  resolveRecentRuns,
  targetTags
} from '../../apps/web/react/src/lib/dashboard-metrics.ts';
import { formatNumber } from '../../apps/web/react/src/lib/utils.ts';

function portalData(overrides = {}) {
  return {
    state: null,
    tenant: null,
    targetGroups: [],
    targets: [],
    checks: [],
    testPolicies: [],
    runs: [],
    findings: [],
    evidence: [],
    highScale: [],
    wafCoverageSummary: null,
    loadErrors: {},
    ...overrides
  };
}

describe('dashboard-metrics', () => {
  it('derives list-backed counts with the same semantics as GET /v1/state', () => {
    const targetGroups = [
      { id: 'tg_active', archived_at: null },
      { id: 'tg_archived', archived_at: '2026-01-01T00:00:00.000Z' }
    ];
    const findings = [
      { id: 'f1', state: ' Open ' },
      { id: 'f2', state: ' closed ' }
    ];
    const highScale = [{ id: 'hs1' }, { id: 'hs2' }];

    assert.equal(countActiveTargetGroups(targetGroups), 1);
    assert.equal(countOpenFindings(findings), 1);
    assert.equal(countHighScaleRequests(highScale), 2);

    const metrics = resolveDashboardMetrics(portalData({ targetGroups, findings, highScale }));
    assert.deepEqual(metrics, { targetGroups: 1, openFindings: 1, highScaleRequests: 2 });
    assert.equal(Object.hasOwn(metrics, 'agentsOnline'), false, 'agents are removed outside-in');
  });

  it('prefers /v1/state metrics when present', () => {
    const metrics = resolveDashboardMetrics(portalData({
      state: { target_groups: 4, open_findings: 2, high_scale_requests: 1 },
      targetGroups: [{ id: 'tg1' }],
      findings: [{ id: 'f1', status: 'open' }]
    }));
    assert.deepEqual(metrics, { targetGroups: 4, openFindings: 2, highScaleRequests: 1 });
  });

  it('keeps 10k groups and 33,334 findings distinct at scale', () => {
    const metrics = resolveDashboardMetrics(portalData({
      state: { target_groups: 10_000, open_findings: 33_334, high_scale_requests: 0 }
    }));
    assert.equal(metrics.targetGroups, 10_000);
    assert.equal(metrics.openFindings, 33_334);
    assert.equal(formatNumber(metrics.targetGroups), '10,000');
    assert.equal(formatNumber(metrics.openFindings), '33,334');
    assert.equal(Object.hasOwn(metrics, 'targets'), false, 'state has no target count to expose');
  });

  it('prefers state recent_runs over the full runs list', () => {
    const recentRuns = resolveRecentRuns({
      state: { recent_runs: [{ id: 'run_a' }, { id: 'run_b' }, { id: 'run_c' }] },
      runs: [{ id: 'run_old' }, { id: 'run_a' }, { id: 'run_b' }, { id: 'run_c' }]
    }, 2);
    assert.deepEqual(recentRuns.map((run) => run.id), ['run_c', 'run_b']);
  });

  it('classifies verdicts into pass/review/gap/none', () => {
    assert.equal(classifyVerdict('pass'), 'pass');
    assert.equal(classifyVerdict('penetrated'), 'gap');
    assert.equal(classifyVerdict('edge_protected'), 'review');
    assert.equal(classifyVerdict(''), 'none');
    assert.equal(classifyVerdict('pending'), 'none');
  });

  it('reads top-level tags and verification (ADR-0008 targets-first)', () => {
    assert.deepEqual(targetTags({ tags: ['Env:Prod', 'edge', 'edge', ' '] }), ['env:prod', 'edge']);
    assert.equal(isTargetVerified({ verification: { state: 'dns_verified' } }), true);
    assert.equal(isTargetVerified({ verification_state: 'unverified' }), false);
    assert.equal(isTargetVerified({ verification: { state: 'user_confirmed' } }), true);
  });

  it('buckets open findings by severity', () => {
    const buckets = findingSeverityBuckets([
      { id: 'a', state: 'open', severity: 'critical' },
      { id: 'b', state: 'open', severity: 's2' },
      { id: 'c', state: 'open', severity: 'medium' },
      { id: 'd', state: 'closed', severity: 'critical' }
    ]);
    assert.deepEqual(buckets, { critical: 1, high: 1, other: 1, total: 3 });
  });

  it('builds target posture rows worst-first with latest evidence-backed verdict', () => {
    const rows = buildTargetPostureRows(portalData({
      targets: [
        { id: 't_pass', value: 'good.example.com', target_group_id: 'g1', verification: { state: 'dns_verified' }, tags: ['prod'] },
        { id: 't_gap', value: 'bad.example.com', target_group_id: 'g1', verification: { state: 'unverified' } }
      ],
      runs: [
        { id: 'r1', target_id: 't_pass', status: 'completed', verdict: 'pass', completed_at: '2026-02-01T00:00:00Z' },
        { id: 'r2', target_id: 't_gap', status: 'verdicted', verdict: 'penetrated', completed_at: '2026-02-02T00:00:00Z' }
      ]
    }));
    assert.equal(rows.length, 2);
    assert.equal(rows[0].id, 't_gap', 'gap sorts before pass');
    assert.equal(rows[0].verdictStatus, 'gap');
    assert.equal(rows[1].verdictStatus, 'pass');
    assert.equal(rows[1].verified, true);
    assert.deepEqual(rows[1].tags, ['prod']);
  });

  it('builds the four outside-in defense stages from loaded data only', () => {
    const stages = buildDefensePath(portalData({
      targets: [
        { id: 't1', verification: { state: 'dns_verified' } },
        { id: 't2', verification: { state: 'unverified' } }
      ],
      wafCoverageSummary: { protected: 3, underprotected: 1, coverage_pct: 75, by_vendor: { cloudflare: 2, generic: 1 } },
      runs: [{ id: 'ro', check_id: 'origin_leak', status: 'completed', verdict: 'pass', evidence_count: 1 }],
      checks: [{ check_id: 'origin_leak', vector_family: 'origin' }]
    }));
    const byKey = Object.fromEntries(stages.map((stage) => [stage.key, stage]));
    assert.equal(stages.length, 4);
    assert.equal(byKey.internet.status, 'review', '1 of 2 verified');
    assert.equal(byKey.edge.headline.includes('1 provider'), true, 'generic vendor excluded');
    assert.equal(byKey.waf.status, 'review', 'protected but some underprotected');
    assert.equal(byKey.origin.status, 'pass');
  });

  it('does not let a passing run settle a target or origin that still has an open finding', () => {
    const data = portalData({
      targets: [{ id: 't1', value: 'checkout.example.com', verification: { state: 'dns_verified' } }],
      runs: [{ id: 'ro', target_id: 't1', check_id: 'origin.leak_scan.safe', status: 'completed', verdict: 'pass', evidence_count: 1 }],
      findings: [{ id: 'f1', target_id: 't1', check_id: 'origin.leak_scan.safe', state: 'open', severity: 's2' }]
    });
    const [row] = buildTargetPostureRows(data);
    assert.equal(row.verdictStatus, 'review');
    assert.equal(row.openFindings, 1);
    const stages = buildDefensePath(data);
    const origin = stages.find((stage) => stage.key === 'origin');
    assert.equal(origin.status, 'gap');
    assert.match(origin.headline, /1 open origin finding/);
    assert.equal(overallDefenseStatus(stages), 'gap');
  });

  it('never reports an all-pass path while any stage is unmeasured', () => {
    const stage = (key, status) => ({ key, label: key, status, headline: '', detail: '', unavailable: false });
    assert.equal(overallDefenseStatus([stage('internet', 'pass'), stage('edge', 'none'), stage('waf', 'pass'), stage('origin', 'pass')]), 'review');
    assert.equal(overallDefenseStatus([stage('internet', 'pass'), stage('edge', 'pass'), stage('waf', 'pass'), stage('origin', 'pass')]), 'pass');
    assert.equal(overallDefenseStatus([stage('internet', 'none'), stage('edge', 'none'), stage('waf', 'none'), stage('origin', 'none')]), 'none');
  });

  it('marks a defense stage unavailable when its dataset failed to load', () => {
    const stages = buildDefensePath(portalData({ loadErrors: { targets: 'boom', runs: 'boom' } }));
    const byKey = Object.fromEntries(stages.map((stage) => [stage.key, stage]));
    assert.equal(byKey.internet.unavailable, true);
    assert.equal(byKey.origin.unavailable, true);
    assert.equal(byKey.internet.status, 'none');
  });

  it('never lets a target inherit a sibling or group run (DASH-01)', () => {
    // Two targets share a group; only the verified one has runs. The unverified sibling
    // (never probed, ownership gate forbids live traffic) must read "No result", not a
    // group-inherited verdict.
    const rows = buildTargetPostureRows(portalData({
      targets: [
        { id: 't_verified', value: 'astranull.site', target_group_id: 'tg_demo_origin', verification: { state: 'dns_verified' } },
        { id: 't_unverified', value: 'checkred.com', target_group_id: 'tg_demo_origin', verification: { state: 'unverified' } }
      ],
      runs: [
        // Both an own run and a bare group run exist for the group; neither may leak to the sibling.
        { id: 'r_own', target_id: 't_verified', target_group_id: 'tg_demo_origin', status: 'completed', verdict: 'pass', completed_at: '2026-03-01T00:00:00Z' },
        { id: 'r_group', target_group_id: 'tg_demo_origin', status: 'verdicted', verdict: 'pass', completed_at: '2026-03-02T00:00:00Z' }
      ]
    }));
    const byId = Object.fromEntries(rows.map((row) => [row.id, row]));
    assert.equal(byId.t_verified.verdictStatus, 'pass', 'target with its own run keeps its verdict');
    assert.equal(byId.t_unverified.verdictStatus, 'none', 'never-probed sibling shows No result');
    assert.equal(byId.t_unverified.verdict, '', 'no inherited verdict string');
  });

  it('counts only target-bound evidence verdicts for coverage over 6 targets (DASH-02)', () => {
    // 6 declared targets, all in one group; only 2 have their own evidence-backed runs.
    const data = portalData({
      targets: Array.from({ length: 6 }, (_unused, index) => ({
        id: `t${index}`,
        value: `t${index}.example.com`,
        target_group_id: 'g',
        verification: { state: index < 2 ? 'dns_verified' : 'unverified' }
      })),
      runs: [
        { id: 'ra', target_id: 't0', target_group_id: 'g', status: 'completed', verdict: 'pass', completed_at: '2026-03-01T00:00:00Z' },
        { id: 'rb', target_id: 't1', target_group_id: 'g', status: 'verdicted', verdict: 'penetrated', completed_at: '2026-03-02T00:00:00Z' }
      ]
    });
    const withEvidence = new Set(
      buildTargetPostureRows(data).filter((row) => row.verdictStatus !== 'none').map((row) => row.id)
    );
    // Numerator counts only the 2 target-bound verdicts, not group-inherited siblings → 2/6.
    assert.deepEqual([...withEvidence].sort(), ['t0', 't1']);
    assert.equal(withEvidence.size, 6 > 0 ? 2 : 0);
    assert.equal(Math.round((withEvidence.size / data.targets.length) * 100), 33);
  });

  it('pins source labels and shared formatting on every scale-count surface', () => {
    const dashboard = readFileSync('apps/web/react/src/pages/dashboard-page.tsx', 'utf8');
    const targets = readFileSync('apps/web/react/src/pages/targets-page.tsx', 'utf8');
    const governance = readFileSync('apps/web/react/src/pages/governance-pages.tsx', 'utf8');

    assert.doesNotMatch(dashboard, /data\.agents\b/, 'dashboard must not read data.agents');
    assert.doesNotMatch(dashboard, /data\.environments\b/, 'dashboard must not read data.environments');
    assert.match(dashboard, /formatNumber\(declaredTargets\)/);
    assert.match(
      targets,
      /Declared targets<\/span><strong>{formatNumber\(targets\.length\)}/,
    );
    assert.match(
      governance,
      /{formatNumber\(openFindingsCount\)}<\/span> open findings/,
    );
  });
});
