import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';
import { stripTypeScriptTypes } from 'node:module';

const source = await readFile(new URL('../../apps/web/react/src/lib/assistant-risk-plan-api.ts', import.meta.url), 'utf8');
// Execute the real client with only its two transport dependencies replaced.
const compiled = stripTypeScriptTypes(source).replace(/^import .*$/gm, '').replace(/^export /gm, '') + '\nObject.assign(exports, { sanitizeRiskPlanComputed, sanitizeRiskPlanAnnotation, generateRiskPlan });';
function client(requestJson = async () => { throw new Error('unexpected request'); }) {
  const exports = {};
  runInNewContext(compiled, { exports, requestJson, sanitizeQueuedJob: (value) => ({ status: value?.status ?? 'unavailable', jobId: value?.job_id ?? '', reason: value?.reason ?? '' }) });
  return exports;
}
const base = () => ({
  target_id: 'tgt_1', snapshot_id: 'snapshot_1', as_of: '2026-10-19T12:00:00.000Z', incomplete: true,
  scope: { target_ids: ['tgt_1'], includes_subdomains: false, confidence: 'external_only' },
  source_finding_ids: ['fnd_1'], limitations: ['Only the explicit declared target.'],
  observed_facts: [{ finding_id: 'fnd_1', check_id: 'a.safe', status: 'open', severity: 'high', observed_at: null, data_labels: ['unknown_age', 'evidence_unknown'], evidence_ids: [] }],
});
const plan = () => ({ ...base(), candidates: [{ check_id: 'a.safe', name: 'Check A', max_requests: 2, source_finding_ids: ['fnd_1'] }, { check_id: 'b.safe', name: 'Check B', max_requests: 1, source_finding_ids: [] }], excluded: [{ check_id: 'c.safe', reason: 'declared_probe_path_required' }], check_ids: ['a.safe'], selection_basis: 'Loaded findings first.', admission: 'Current server admission decides.' });
const story = () => ({ ...base(), stories: [{ source_finding_ids: ['fnd_1'], hypothesis: 'If still present, it may warrant attention.' }] });

test('client accepts bounded computed proposals but rejects cross-target or malformed evidence scope', () => {
  const api = client();
  assert.ok(api.sanitizeRiskPlanComputed(plan(), 'tgt_1', 'validation_plan'));
  assert.ok(api.sanitizeRiskPlanComputed(story(), 'tgt_1', 'risk_story'));
  for (const change of [{ target_id: 'other' }, { scope: { target_ids: ['tgt_1', 'tgt_2'], includes_subdomains: false } }, { scope: { target_ids: ['tgt_1'], includes_subdomains: true, confidence: 'external_only' } }, { observed_facts: [{ finding_id: 'fnd_foreign' }] }, { source_finding_ids: ['fnd_1', 'fnd_1'] }, { as_of: 'unknown' }]) assert.equal(api.sanitizeRiskPlanComputed({ ...plan(), ...change }, 'tgt_1', 'validation_plan'), null);
});

test('client refuses unknown or duplicate recommendations and source citations', () => {
  const api = client();
  for (const change of [{ check_ids: ['invented'] }, { check_ids: ['a.safe', 'a.safe'] }, { candidates: [...plan().candidates, plan().candidates[0]] }, { candidates: [{ ...plan().candidates[0], source_finding_ids: ['foreign'] }] }, { check_ids: Array.from({ length: 13 }, (_, n) => `id${n}`) }]) assert.equal(api.sanitizeRiskPlanComputed({ ...plan(), ...change }, 'tgt_1', 'validation_plan'), null);
  assert.equal(api.sanitizeRiskPlanComputed({ ...story(), stories: [{ source_finding_ids: ['foreign'], hypothesis: 'x' }] }, 'tgt_1', 'risk_story'), null);
});

test('AI answers are bound to the currently displayed snapshot and eligible candidate whitelist', () => {
  const api = client();
  const annotation = { target_id: 'tgt_1', snapshot_id: 'snapshot_1', ai: true, check_ids: ['b.safe', 'a.safe'], rationale: 'Review B then A.' };
  assert.ok(api.sanitizeRiskPlanAnnotation(annotation, plan(), 'validation_plan'));
  for (const change of [{ target_id: 'other' }, { snapshot_id: 'old_snapshot' }, { ai: false }, { check_ids: ['not_eligible'] }, { check_ids: ['a.safe', 'a.safe'] }]) assert.equal(api.sanitizeRiskPlanAnnotation({ ...annotation, ...change }, plan(), 'validation_plan'), null);
  assert.equal(api.sanitizeRiskPlanAnnotation({ target_id: 'tgt_1', snapshot_id: 'snapshot_1', ai: true, stories: [{ source_finding_ids: ['foreign'], hypothesis: 'x' }] }, story(), 'risk_story'), null);
});

test('generation sends only target IDs to feature endpoints, no run or schedule mutation', async () => {
  const requests = [];
  const api = client(async (...args) => { requests.push(args); return { computed: requests.length === 1 ? plan() : story(), narrative: { status: 'unavailable', reason: 'assistant_runner_offline' } }; });
  const signal = new AbortController().signal;
  for (const purpose of ['validation_plan', 'risk_story']) {
    const result = await api.generateRiskPlan({}, {}, 'tgt_1', purpose, signal);
    assert.equal(result.computed.target_id, 'tgt_1');
    assert.equal(result.queued.status, 'unavailable');
  }
  assert.deepEqual(requests.map((args) => args[2]), ['/v1/assistant/validation-plan', '/v1/assistant/risk-stories']);
  for (const args of requests) {
    assert.equal(args[3].method, 'POST');
    assert.equal(args[3].signal, undefined, 'creation response must remain available for late-job cancellation');
    assert.deepEqual(JSON.parse(JSON.stringify(args[3].body)), { target_id: 'tgt_1' });
  }
});

test('malformed or stale generation answers fail instead of being rendered under another target', async () => {
  const api = client(async () => ({ computed: { ...plan(), target_id: 'other' } }));
  await assert.rejects(api.generateRiskPlan({}, {}, 'tgt_1', 'validation_plan', new AbortController().signal), /did not match this target/);
});

test('late creation after request disposal is cancelled and never published under the next scope', async () => {
  const requests = [];
  let release;
  const api = client(async (...args) => {
    requests.push(args);
    if (args[3].method === 'DELETE') return {};
    return new Promise((resolve) => { release = resolve; });
  });
  const controller = new AbortController();
  const pending = api.generateRiskPlan({}, {}, 'tgt_1', 'validation_plan', controller.signal);
  controller.abort();
  release({ computed: plan(), narrative: { status: 'queued', job_id: 'asj_late' } });
  await assert.rejects(pending, /cancelled/);
  assert.equal(requests.length, 2);
  assert.equal(requests[1][2], '/v1/assistant/jobs/asj_late');
  assert.equal(requests[1][3].method, 'DELETE');
});

test('target integration uses shared jobs, status and evidence inspector; prefill does not submit', async () => {
  const panel = await readFile(new URL('../../apps/web/react/src/components/assistant/risk-plan-panel.tsx', import.meta.url), 'utf8');
  const launcher = await readFile(new URL('../../apps/web/react/src/components/runs/validation-scan-launcher.tsx', import.meta.url), 'utf8');
  const targetPage = await readFile(new URL('../../apps/web/react/src/pages/target-detail-view.tsx', import.meta.url), 'utf8');
  assert.match(panel, /useStructuredJob/);
  assert.match(panel, /AiStatusBadge/);
  assert.match(panel, /useOpenInspector/);
  assert.match(panel, /result\?\.session === session/);
  assert.match(panel, /request\.current\?\.abort\(\)/);
  assert.match(panel, /key=\{visible\.computed\.snapshot_id\}/);
  assert.match(panel, /I reviewed this target and these exact checks/);
  assert.match(targetPage, /RiskPlanPanel key=\{executionScope\}/);
  assert.match(launcher, /initialSelection/);
  assert.match(launcher, /selectedChecks\.length !== form\.checkIds\.length/);
  assert.match(launcher, /form\.targetIds\.some\(\(id\) => !Array\.isArray\(catalogByTarget\[id\]\)\)/);
  assert.ok(!panel.includes("'/v1/validation-scans'"));
  assert.ok(!panel.includes('/v1/waf/validation-plans'));
});
