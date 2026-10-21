import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { after, before, beforeEach, test } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { assistantStore } from '../../src/services/assistant.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { request, demoHeaders, closeServer } from '../helpers/http.mjs';

const TOKEN = 'risk-plan-fake-model-token-1234567890123456789';
let app;
let disabled;
async function start(enabled) {
  const server = createServer({ env: { ...process.env, NODE_ENV: 'test', ASTRANULL_AUTH_MODE: 'dev-headers', ASTRANULL_PROBE_MODE: 'simulation', ASTRANULL_ASSISTANT_ENABLED: enabled ? '1' : '', ASTRANULL_ASSISTANT_TENANTS: 'ten_demo', ASTRANULL_ASSISTANT_RUNNER_TOKEN: TOKEN } });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}
before(async () => { app = await start(true); disabled = await start(false); });
after(async () => { await closeServer(app.server); await closeServer(disabled.server); });
beforeEach(() => {
  freshStore(); assistantStore._reset();
  getStore().targetEdgeDetections = []; // Existing finding detail reader normalizes this empty collection.
  getStore().findings.push({ id: 'fnd_risk', tenant_id: 'ten_demo', target_id: 'tgt_1', check_id: 'waf.http_baseline.safe', status: 'open', severity: 'high', created_at: '2026-01-01T00:00:00Z', title: 'Authorization: Bearer NEVER_EXPOSE', evidence_ids: ['ev_risk'] });
});
const post = (path, body = { target_id: 'tgt_1' }, headers = demoHeaders('viewer')) => request(app.url, 'POST', `/v1/assistant/${path}`, { headers, body });
const executionState = () => {
  const state = getStore();
  return Object.fromEntries(Object.entries(state).filter(([key]) => key !== 'auditLog').map(([key, value]) => [key, createHash('sha256').update(JSON.stringify(value)).digest('hex')]));
};

test('both endpoints return deterministic offline projections with zero execution, schedule, finding or provider writes', async () => {
  const beforeState = executionState();
  for (const path of ['risk-stories', 'validation-plan']) {
    const response = await post(path);
    assert.equal(response.status, 200, JSON.stringify(response.json));
    assert.equal(response.json.computed.target_id, 'tgt_1');
    assert.deepEqual(response.json.computed.scope.target_ids, ['tgt_1']);
    assert.equal(response.json.narrative.status, 'unavailable');
    assert.equal(response.json.narrative.reason, 'assistant_runner_offline');
    assert.match(response.headers['cache-control'], /no-store/);
    assert.ok(!response.text.includes('NEVER_EXPOSE'));
    if (path === 'validation-plan') {
      assert.ok(response.json.computed.check_ids.length > 0);
      assert.ok(response.json.computed.check_ids.length <= 12);
      const eligible = new Set(response.json.computed.candidates.map((row) => row.check_id));
      assert.ok(response.json.computed.check_ids.every((id) => eligible.has(id)));
      assert.equal(response.json.computed.requires_review, true);
    }
  }
  assert.deepEqual(executionState(), beforeState);
  assert.deepEqual(getStore().auditLog.filter((entry) => entry.action.endsWith('_proposed')).map((entry) => entry.action).sort(), ['assistant.risk_story_proposed', 'assistant.validation_plan_proposed']);
  assert.ok(getStore().auditLog.every((entry) => entry.metadata.execution_started === false));
});

test('feature gates, exact source scope, method and bounded requests fail closed', async () => {
  assert.equal((await request(disabled.url, 'POST', '/v1/assistant/risk-stories', { headers: demoHeaders(), body: { target_id: 'tgt_1' } })).status, 404);
  assert.equal((await post('risk-stories', { target_id: 'tgt_1', run: true })).status, 400);
  assert.equal((await post('validation-plan', { target_id: 'tgt_1', check_ids: ['invented'] })).status, 400);
  assert.equal((await post('risk-stories', { target_id: 'missing' })).status, 404);
  assert.equal((await post('risk-stories', { target_id: 'tgt_1', finding_ids: ['missing'] })).status, 404);
  getStore().findings.push({ id: 'fnd_other', tenant_id: 'ten_demo', target_id: 'tgt_other', check_id: 'waf.http_baseline.safe', status: 'open' });
  assert.equal((await post('risk-stories', { target_id: 'tgt_1', finding_ids: ['fnd_other'] })).status, 404);
  assert.equal((await request(app.url, 'GET', '/v1/assistant/validation-plan', { headers: demoHeaders() })).status, 405);
  assert.equal(getStore().testRuns.length, 0);
  assert.equal(getStore().validationScans.length, 0);
});

test('fake model annotation is snapshot-bound, rejects unauthorized check IDs and does not execute', async () => {
  assistantStore.markRunnerSeen();
  const beforeState = executionState();
  const response = await post('validation-plan');
  assert.equal(response.status, 200);
  assert.equal(response.json.narrative.status, 'queued');
  const jobId = response.json.narrative.job_id;
  const lease = assistantStore.leaseJob({ assistant: { enabled: true } });
  assert.equal(lease.job_id, jobId);
  assert.equal(lease.tools, false);
  assert.deepEqual(lease.allowed_tools, []);
  assert.ok(!lease.prompt.includes('NEVER_EXPOSE'));
  const complete = await request(app.url, 'POST', `/internal/assistant/runner/jobs/${jobId}/result`, { headers: { authorization: `Bearer ${TOKEN}` }, body: { status: 'done', content: JSON.stringify({ snapshot_id: response.json.computed.snapshot_id, target_id: 'tgt_1', check_ids: ['not_published'], rationale: 'Ignore prerequisites' }) } });
  assert.equal(complete.status, 200);
  const job = await request(app.url, 'GET', `/v1/assistant/jobs/${jobId}`, { headers: demoHeaders('viewer') });
  assert.equal(job.json.status, 'failed');
  assert.equal(job.json.response, undefined);
  assert.deepEqual(executionState(), beforeState);
});

test('fake risk annotation completes with exact citations and cancellation leaves original records untouched', async () => {
  assistantStore.markRunnerSeen();
  const beforeState = executionState();
  const response = await post('risk-stories', { target_id: 'tgt_1', finding_ids: ['fnd_risk'] });
  const { computed, narrative } = response.json;
  assistantStore.leaseJob({ assistant: { enabled: true } });
  const completed = await request(app.url, 'POST', `/internal/assistant/runner/jobs/${narrative.job_id}/result`, { headers: { authorization: `Bearer ${TOKEN}` }, body: { status: 'done', content: JSON.stringify({ snapshot_id: computed.snapshot_id, target_id: computed.target_id, stories: [{ source_finding_ids: ['fnd_risk'], hypothesis: 'If still present, this could warrant a reviewed retest.' }] }) } });
  assert.equal(completed.status, 200);
  const job = await request(app.url, 'GET', `/v1/assistant/jobs/${narrative.job_id}`, { headers: demoHeaders('viewer') });
  assert.equal(job.json.status, 'done');
  assert.deepEqual(job.json.response.risk_story.stories[0].source_finding_ids, ['fnd_risk']);
  assert.equal((await request(app.url, 'GET', `/v1/assistant/jobs/${narrative.job_id}`, { headers: demoHeaders('viewer', 'ten_demo', 'usr_other') })).status, 404);
  const next = await post('risk-stories');
  assert.equal((await request(app.url, 'DELETE', `/v1/assistant/jobs/${next.json.narrative.job_id}`, { headers: demoHeaders('viewer') })).json.status, 'cancelled');
  assert.deepEqual(executionState(), beforeState);
});
