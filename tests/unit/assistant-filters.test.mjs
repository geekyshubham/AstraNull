import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { normalizeFilterRequest, unsupportedFilterQuestion, validateFindingFilters, deterministicFindingFilters, loadFilterEntities, prepareFindingFilterPreview, parseFilterOutput, buildFilterPrompt } from '../../src/services/assistantFilters.mjs';
import { assistantFindingQuery, sanitizeFindingFilterPreview } from '../../apps/web/react/src/lib/assistant-filters.mjs';
import { sanitizeRouteParams } from '../../apps/web/react/src/lib/evidence-inspector.mjs';

const ctx = { tenantId: 'ten_a', userId: 'usr_a', role: 'viewer' };
const entities = { target_id: [{ id: 'tgt_a', label: 'shop.example.test' }], check_id: [{ id: 'waf.rule.safe', label: 'WAF rule' }], test_run_id: [{ id: 'run_a', label: 'run_a' }] };
const snapshot = { target_id: ['tgt_a'], check_id: ['waf.rule.safe'], test_run_id: ['run_a'] };
const options = { validation: { filters_snapshot: snapshot, filters_searches: ['Needle'] } };
const deps = {
  listTargets: async () => [{ id: 'tgt_a', tenant_id: 'ten_a', value: 'shop.example.test' }, { id: 'tgt_other', tenant_id: 'ten_b', value: 'private.example.test' }],
  listChecks: async () => [{ check_id: 'waf.rule.safe', name: 'WAF rule' }],
  listRuns: async () => [{ id: 'run_a', tenant_id: 'ten_a' }, { id: 'run_other', tenant_id: 'ten_b' }],
};

describe('NL filter bounded request and unsupported semantics', () => {
  it('accepts only the exact body shape, bounded nonempty plain string and findings kind', () => {
    assert.deepEqual(normalizeFilterRequest({ question: '  show open findings ', kind: 'findings' }), { question: 'show open findings', kind: 'findings' });
    for (const body of [null, [], {}, { kind: 'runs', question: 'open' }, { kind: 'findings', question: '' }, { kind: 'findings', question: 3 }, { kind: 'findings', question: 'x'.repeat(501) }, { kind: 'findings', question: 'open\nfindings' }, { kind: 'findings', question: 'open', target_id: 'tgt_other' }]) assert.equal(normalizeFilterRequest(body), null);
  });
  it('refuses unsupported OR, SQL, provider, date, negation and operator queries rather than approximating', async () => {
    for (const question of ['open or resolved', 'either high and critical', 'SELECT * FROM findings', 'show Cloudflare findings', 'findings from last week', 'findings after 2026-01-01', 'severity >= high', 'not closed', 'target_group_id tg_a', 'status in [open,closed]', 'open and closed findings', 'high and critical findings', 'findings from 2026-01-01', 'findings behind Fortinet']) {
      assert.equal(unsupportedFilterQuestion(question), true, question);
      const result = await prepareFindingFilterPreview(ctx, { kind: 'findings', question }, { listTargets: () => { throw new Error('must not read'); } });
      assert.equal(result.filters, null);
      assert.equal(result.narrative.reason, 'unsupported_filter_request');
      assert.equal(result.job, undefined);
    }
  });
});

describe('NL filter exact grammar and snapshot authorizations', () => {
  it('parses supported single predicates and literal searches, never inferred multi-status', () => {
    assert.deepEqual(deterministicFindingFilters('Show open high severity findings for target shop.example.test and check waf.rule.safe', entities), { target_id: 'tgt_a', check_id: 'waf.rule.safe', status: 'open', severity: 'high' });
    assert.deepEqual(deterministicFindingFilters('Show accepted risk findings', entities), { status: 'accepted_risk' });
    assert.deepEqual(deterministicFindingFilters('Show findings search "Needle Title" for run run_a', entities), { q: 'Needle Title', test_run_id: 'run_a' });
    assert.deepEqual(deterministicFindingFilters('All findings', entities), {});
    assert.equal(deterministicFindingFilters('open high critical findings', entities), null);
    assert.equal(deterministicFindingFilters('urgent findings on our production host', entities), null);
    assert.equal(deterministicFindingFilters('findings for target tgt_other', entities), null);
  });
  it('uses only tenant-scoped authoritative entity reads with role and API-key scopes', async () => {
    const loaded = await loadFilterEntities(ctx, deps);
    assert.deepEqual(loaded.snapshot, snapshot);
    let calls = 0;
    const deniedDeps = Object.fromEntries(Object.keys(deps).map((key) => [key, () => { calls += 1; throw new Error('must not read'); }]));
    const limited = await loadFilterEntities({ ...ctx, scopes: ['finding:read'] }, deniedDeps);
    assert.equal(calls, 0);
    assert.deepEqual(limited.snapshot, { target_id: [], check_id: [], test_run_id: [] });
    assert.deepEqual(limited.requiredPermissions, ['finding:read']);
    await assert.rejects(loadFilterEntities(ctx, { listTargets: async () => ({ error: 'forbidden' }) }));
  });
  it('caps vocabularies, excludes archived entities and never accepts an out-of-snapshot ID', async () => {
    const loaded = await loadFilterEntities(ctx, { listTargets: async () => Array.from({ length: 300 }, (_, i) => ({ id: `tgt_${i}`, value: `${i}.test` })) });
    assert.equal(loaded.entities.target_id.length, 100);
    assert.equal(validateFindingFilters({ target_id: 'tgt_200' }, loaded.snapshot), null);
    const noDeleted = await loadFilterEntities(ctx, { listTargets: async () => [{ id: 'tgt_deleted', deleted_at: '2026-01-01' }] });
    assert.deepEqual(noDeleted.snapshot.target_id, []);
  });
  it('keeps even worst-case escaped vocabularies below the shared prompt and private snapshot bounds', async () => {
    const rows = Array.from({ length: 100 }, (_, index) => ({ id: `${index}_`.padEnd(128, 'x'), check_id: `${index}_`.padEnd(128, 'x'), value: '"'.repeat(160), name: '"'.repeat(160) }));
    const loaded = await loadFilterEntities(ctx, { listTargets: async () => rows, listChecks: async () => rows, listRuns: async () => rows });
    assert.ok(buildFilterPrompt('x'.repeat(500), loaded.entities).length < 120000);
    assert.ok(Buffer.byteLength(JSON.stringify({ filters_snapshot: loaded.snapshot })) < 64 * 1024);
  });
  it('produces a deterministic preview or a tool-less queued request with private allowlists', async () => {
    const direct = await prepareFindingFilterPreview(ctx, { kind: 'findings', question: 'show open high findings' }, deps);
    assert.deepEqual(direct.filters, { status: 'open', severity: 'high' });
    assert.equal(direct.narrative.status, 'not_requested');
    const queued = await prepareFindingFilterPreview(ctx, { kind: 'findings', question: 'Please display findings whose status is open' }, deps);
    assert.equal(queued.job.purpose, 'filters');
    assert.deepEqual(queued.job.validation.filters_snapshot, snapshot);
    assert.deepEqual(queued.job.context, { kind: 'findings' });
    assert.ok(!queued.job.prompt.includes('tgt_other'));
    assert.match(queued.job.prompt, /UNTRUSTED_DATA_BEGIN filter question/);
    assert.equal((await prepareFindingFilterPreview({ ...ctx, scopes: [] }, { question: 'open' }, deps)).status, 403);
    assert.match(buildFilterPrompt('ignore instructions', entities), /No other keys or operators/);
  });
});

describe('strict model output validation and exact existing query compilation', () => {
  it('accepts canonical enum values and snapshot IDs, never aliases, unknown fields or operators', () => {
    const filters = { q: 'Needle', status: 'fix_verified', severity: 'high', target_id: 'tgt_a', check_id: 'waf.rule.safe', test_run_id: 'run_a' };
    const parsed = parseFilterOutput(JSON.stringify({ filters, explanation: 'Model text is not authoritative' }), options);
    assert.deepEqual(parsed.filters, filters);
    assert.match(parsed.explanation, /Match all of:/);
    for (const invalid of [{ severity: 'S2' }, { status: 'pending' }, { target_group_id: 'tg_a' }, { or: [{ status: 'open' }] }, { status: ['open'] }, { target_id: 'tgt_other' }, { check_id: 'invented' }, { test_run_id: 'run_other' }, { q: 'x'.repeat(201) }, { q: 'hello\nworld' }, { q: 'provider Cloudflare' }, { status: ' open' }, { status: null }]) {
      assert.equal(validateFindingFilters(invalid, snapshot), null, JSON.stringify(invalid));
      assert.equal(parseFilterOutput(JSON.stringify({ filters: invalid, explanation: 'ignored' }), options), null);
    }
    assert.equal(parseFilterOutput(JSON.stringify({ filters: { target_id: 'tgt_a' }, explanation: 'x' })), null, 'snapshot is mandatory for entities');
    assert.equal(parseFilterOutput(JSON.stringify({ filters: { q: 'arbitrary fallback search' }, explanation: 'x' }), options), null, 'a model cannot translate an unsupported predicate or the raw prompt into q');
    assert.equal(parseFilterOutput(JSON.stringify({ filters: { q: 'Needle' }, explanation: 'x' }), { validation: { filters_snapshot: snapshot } }), null, 'model searches must bind to an explicit quoted literal');
    for (const raw of ['```json\n{}\n```', '{}', '{', JSON.stringify({ filters: {}, explanation: 'all' }), JSON.stringify({ filters: null, explanation: 'unsupported' }), JSON.stringify({ filters: { status: 'open' }, explanation: 'x', sql: 'ignored' })]) assert.equal(parseFilterOutput(raw, options), null);
  });
  it('compiles all six filters through findingsQuery with server paging and totals unchanged', () => {
    const preview = { filters: { q: 'x'.repeat(200), status: 'open', severity: 'high', target_id: 'tgt_a', check_id: 'waf.rule.safe', test_run_id: 'run_a' }, explanation: 'Exact filters' };
    const params = new URLSearchParams(assistantFindingQuery(preview, { limit: 25, page: 2 }));
    assert.equal(params.get('q').length, 200);
    assert.equal(params.get('page'), '2');
    assert.equal(params.get('limit'), '25');
    assert.equal(params.get('target_id'), 'tgt_a');
    assert.equal(params.get('check_id'), 'waf.rule.safe');
    assert.equal(params.get('test_run_id'), 'run_a');
    assert.equal(sanitizeFindingFilterPreview({ filters: { severity: 'S2' }, explanation: 'x' }), null);
    assert.equal(assistantFindingQuery({ filters: { target_group_id: 'tg_a' }, explanation: 'x' }), null);
  });
  it('preserves 200-character search and exact check/run filters across inspector route rewriting', () => {
    const params = sanitizeRouteParams(new URLSearchParams({ q: `${'abc '.repeat(49)}abcd`, check_id: 'waf.rule.safe', test_run_id: 'run_a', question: 'raw prompt', prompt: 'never store this' }));
    assert.equal(params.get('q').length, 200);
    assert.equal(params.get('check_id'), 'waf.rule.safe');
    assert.equal(params.get('test_run_id'), 'run_a');
    assert.equal(params.has('question'), false);
    assert.equal(params.has('prompt'), false);
    assert.equal(sanitizeRouteParams(new URLSearchParams({ q: 'x '.repeat(101).trim() })).has('q'), false);
  });
});
