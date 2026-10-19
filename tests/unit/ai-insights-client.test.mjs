import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  currentInsightScope,
  formatKpi,
  insightCacheKey,
  insightRequestBody,
  insightScopeForRoute,
  kpiUnitSuffix,
  sanitizeBoard,
  sanitizeNarrativeState,
  sanitizeScope,
} from '../../apps/web/react/src/lib/assistant-insights.mjs';

describe('insight scope for the open page', () => {
  it('maps list pages, record pages and other pages', () => {
    assert.deepEqual(insightScopeForRoute('findings'), { route: 'findings', kind: 'findings', label: 'Findings' });
    assert.deepEqual(currentInsightScope('#target-detail?id=tgt_1&tab=controls'), { route: 'target-detail', kind: 'target', label: 'Target', entity: { id: 'tgt_1' } });
    assert.equal(currentInsightScope('#reports').kind, 'workspace');
    assert.equal(currentInsightScope('').kind, 'dashboard');
    assert.equal(currentInsightScope('#finding-detail'), null, 'a record page without an id has no scope');
    assert.equal(currentInsightScope('#finding-detail?id=bad%20id'), null);
  });

  it('uses a finding group scope only when its page published one', () => {
    assert.equal(currentInsightScope('#finding-group-detail?key=k'), null);
    const published = { route: 'finding-group-detail', kind: 'finding_group', label: 'Finding group', entity: { id: 'k' }, finding_ids: ['fnd_1', 'fnd_1', 'bad id'] };
    assert.deepEqual(currentInsightScope('#finding-group-detail?key=k', published).finding_ids, ['fnd_1']);
    assert.equal(currentInsightScope('#findings', published).kind, 'findings', 'a scope published for another route is ignored');
  });

  it('builds the request and a per-user cache key', () => {
    const scope = sanitizeScope({ route: 'finding-detail', kind: 'finding', label: 'Finding', entity: { id: 'fnd_1' } });
    assert.deepEqual(insightRequestBody(scope, { refresh: true }), { kind: 'finding', entity: { id: 'fnd_1' }, narrative: true, refresh: true });
    assert.notEqual(insightCacheKey('ten_a|alice', scope), insightCacheKey('ten_a|bob', scope));
  });
});

describe('insight board validation', () => {
  const board = {
    kind: 'findings',
    generated_at: '2026-10-19T12:00:00.000Z',
    verdict: { tone: 'evil', score: 140, headline: 'Two open findings.' },
    kpis: [{ id: 'open', label: 'Open findings', value: 2, unit: 'count', tone: 'caution' }, { label: '' }, { id: 'pct', label: 'Rate', value: 'x', unit: 'percent' }],
    sections: [{ id: 'Q1', title: 'By severity', columns: [{ key: 'label', label: 'Severity', type: 'string' }, { key: 'count', label: 'Count', type: 'number' }], rows: [['High', 2], ['Medium', 1]], suggested_visual: 'bar', hint: 'Mix.' }, { id: 'bad', columns: [], rows: [] }],
    actions: [
      { severity: 'high', title: 'Fix TCP 22', route: 'finding-detail?id=fnd_1' },
      { severity: 'high', title: 'Bad link', route: 'javascript:alert(1)' },
      { severity: 'nope', title: 'External', route: 'https://evil.test/' },
    ],
    narrative: { summary: 'Two open findings.', takeaways: ['One.'], ai: true },
    scope: { truncated: true },
  };

  it('keeps valid parts and drops or neutralises the rest', () => {
    const clean = sanitizeBoard(board);
    assert.equal(clean.verdict.tone, 'neutral');
    assert.equal(clean.verdict.score, 100);
    assert.equal(clean.kpis.length, 2);
    assert.equal(clean.kpis[1].value, null);
    assert.equal(clean.sections.length, 1);
    assert.equal(clean.sections[0].hint, 'Mix.');
    assert.equal(clean.actions[0].route, 'finding-detail?id=fnd_1');
    assert.equal(clean.actions[1].route, undefined);
    assert.equal(clean.actions[2].route, undefined);
    assert.equal(clean.actions[2].severity, 'info');
    assert.equal(clean.truncated, true);
    assert.equal(sanitizeBoard({ verdict: {} }), null);
  });

  it('formats KPI values and units', () => {
    assert.equal(formatKpi({ value: null, unit: 'count' }), '—');
    assert.equal(formatKpi({ value: 1234, unit: 'count' }), '1,234');
    assert.equal(kpiUnitSuffix({ value: 42, unit: 'score' }), '/100');
    assert.equal(kpiUnitSuffix({ value: 1, unit: 'days' }), ' day');
    assert.equal(kpiUnitSuffix({ value: 50, unit: 'percent' }), '%');
  });

  it('only trusts a queued narrative that names its job', () => {
    assert.deepEqual(sanitizeNarrativeState({ status: 'queued', job_id: 'asj_1' }), { status: 'queued', jobId: 'asj_1', reason: '' });
    assert.equal(sanitizeNarrativeState({ status: 'queued' }).status, 'unavailable');
    assert.equal(sanitizeNarrativeState({ status: 'weird' }).status, 'unavailable');
  });
});
