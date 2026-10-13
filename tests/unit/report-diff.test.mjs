import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  defaultBaseline,
  diffReports,
  eligibleBaselines,
  reportScopeKey
} from '../../apps/web/react/src/lib/report-diff.ts';

function report(id, asOf, { kind = 'executive', scope = { mode: 'tenant', target_ids: [] }, items = [], frozen = true, complete = true, score = null, factors = [] } = {}) {
  return {
    id,
    kind,
    title: `Report ${id}`,
    created_at: asOf,
    summary: {
      as_of: asOf,
      snapshot_frozen: frozen,
      scope,
      readiness_score: score,
      readiness_score_status: score === null ? 'unknown' : 'published',
      readiness_factors: factors,
      findings_snapshot: { complete, items }
    }
  };
}

const finding = (id, status = 'open', severity = 'high') => ({ id, title: `Finding ${id}`, status, severity });

describe('report diff: baseline selection', () => {
  const current = report('rpt_c', '2026-03-01T00:00:00.000Z');
  const reports = [
    current,
    report('rpt_older', '2026-01-01T00:00:00.000Z'),
    report('rpt_newer_baseline', '2026-02-01T00:00:00.000Z'),
    report('rpt_future', '2026-04-01T00:00:00.000Z'),
    report('rpt_other_kind', '2026-02-15T00:00:00.000Z', { kind: 'technical' }),
    report('rpt_other_scope', '2026-02-20T00:00:00.000Z', { scope: { mode: 'targets', target_ids: ['tgt_1'] } })
  ];

  it('picks the newest earlier report with the same kind and scope', () => {
    assert.deepEqual(eligibleBaselines(current, reports).map((item) => item.id), ['rpt_newer_baseline', 'rpt_older']);
    assert.equal(defaultBaseline(current, reports).id, 'rpt_newer_baseline');
  });

  it('treats target order as irrelevant to scope identity', () => {
    const left = report('a', '2026-01-01T00:00:00.000Z', { scope: { mode: 'targets', target_ids: ['tgt_2', 'tgt_1'] } });
    const right = report('b', '2026-01-02T00:00:00.000Z', { scope: { mode: 'targets', target_ids: ['tgt_1', 'tgt_2'] } });
    assert.equal(reportScopeKey(left), reportScopeKey(right));
  });

  it('keeps reports scoped to different target groups apart', () => {
    const groupA = report('rpt_ga', '2026-01-01T00:00:00.000Z', { scope: { mode: 'target_groups', target_ids: [], target_group_ids: ['tg_a'] } });
    const groupB = report('rpt_gb', '2026-01-02T00:00:00.000Z', { scope: { mode: 'target_groups', target_ids: [], target_group_ids: ['tg_b'] } });
    const groupAFlipped = report('rpt_ga2', '2026-01-03T00:00:00.000Z', { scope: { mode: 'target_groups', target_ids: [], target_group_ids: ['tg_a'] } });
    assert.notEqual(reportScopeKey(groupA), reportScopeKey(groupB));
    assert.deepEqual(eligibleBaselines(groupB, [groupA, groupB, groupAFlipped]).map((row) => row.id), []);
    assert.deepEqual(eligibleBaselines(groupAFlipped, [groupA, groupB, groupAFlipped]).map((row) => row.id), ['rpt_ga']);
  });

  it('offers no baseline when scope or generation time is not recorded', () => {
    const unscoped = { id: 'rpt_x', kind: 'executive', summary: { as_of: '2026-03-01T00:00:00.000Z' } };
    assert.deepEqual(eligibleBaselines(unscoped, reports), []);
    assert.equal(defaultBaseline(unscoped, reports), null);
  });
});

describe('report diff: findings and readiness', () => {
  it('matches findings by ID into new, no longer present, status and severity changes', () => {
    const baseline = report('rpt_b', '2026-01-01T00:00:00.000Z', {
      items: [finding('f1'), finding('f2'), finding('f3', 'open', 'medium'), finding('f4')]
    });
    const current = report('rpt_c', '2026-02-01T00:00:00.000Z', {
      items: [finding('f1'), finding('f3', 'accepted_risk', 'high'), finding('f4', 'resolved'), finding('f5')]
    });
    const diff = diffReports(current, baseline);
    assert.equal(diff.status, 'compared');
    assert.deepEqual(diff.added.map((item) => item.id), ['f5']);
    assert.deepEqual(diff.removed.map((item) => item.id), ['f2']);
    assert.deepEqual(diff.statusChanged.map((item) => [item.id, item.from, item.to, item.acceptedRisk]), [
      ['f3', 'open', 'accepted_risk', true],
      ['f4', 'open', 'resolved', false]
    ]);
    assert.deepEqual(diff.severityChanged.map((item) => [item.id, item.from, item.to]), [['f3', 'medium', 'high']]);
    assert.equal(diff.unchanged, 1);
  });

  it('compares readiness only when both reports published a score', () => {
    const factors = (score) => [{ key: 'coverage', label: 'coverage', score }, { key: 'freshness', label: 'freshness', score: 50 }];
    const baseline = report('rpt_b', '2026-01-01T00:00:00.000Z', { score: 60, factors: factors(40) });
    const current = report('rpt_c', '2026-02-01T00:00:00.000Z', { score: 72, factors: factors(70) });
    const diff = diffReports(current, baseline);
    assert.equal(diff.readiness.compared, true);
    assert.equal(diff.readiness.delta, 12);
    assert.deepEqual(diff.readiness.factors, [{ key: 'coverage', label: 'coverage', from: 40, to: 70 }]);

    const unpublished = diffReports(report('rpt_c2', '2026-02-01T00:00:00.000Z'), baseline);
    assert.equal(unpublished.readiness.compared, false);
    assert.match(unpublished.readiness.reason, /both reports published/);
  });

  it('refuses to compare without an eligible baseline', () => {
    const diff = diffReports(report('rpt_c', '2026-02-01T00:00:00.000Z'), null);
    assert.equal(diff.status, 'not_compared');
    assert.match(diff.reason, /No earlier report/);
  });

  it('refuses to compare when either snapshot was not frozen', () => {
    const diff = diffReports(report('rpt_c', '2026-02-01T00:00:00.000Z'), report('rpt_b', '2026-01-01T00:00:00.000Z', { frozen: false }));
    assert.equal(diff.status, 'not_compared');
    assert.match(diff.reason, /legacy report/);
  });

  it('refuses to compare when either findings snapshot is incomplete', () => {
    const diff = diffReports(
      report('rpt_c', '2026-02-01T00:00:00.000Z', { complete: false, items: [finding('f1')] }),
      report('rpt_b', '2026-01-01T00:00:00.000Z', { items: [finding('f1')] })
    );
    assert.equal(diff.status, 'not_compared');
    assert.match(diff.reason, /only part of its findings/);
  });
});
