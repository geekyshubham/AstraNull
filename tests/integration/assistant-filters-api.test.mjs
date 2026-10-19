import assert from 'node:assert/strict';
import { after, before, beforeEach, test } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { assistantStore } from '../../src/services/assistant.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { request, demoHeaders, closeServer } from '../helpers/http.mjs';

const TOKEN = 'filters-local-fake-runner-token-0123456789';
const runnerHeaders = { authorization: `Bearer ${TOKEN}` };
const headers = demoHeaders('viewer');
const question = 'Please display findings whose status is open';
let on;
let off;
async function start(enabled) {
  const server = createServer({ env: { ...process.env, NODE_ENV: 'test', ASTRANULL_AUTH_MODE: 'dev-headers', ASTRANULL_ASSISTANT_ENABLED: enabled ? '1' : '', ASTRANULL_ASSISTANT_TENANTS: 'ten_demo', ASTRANULL_ASSISTANT_RUNNER_TOKEN: TOKEN } });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, baseUrl: `http://127.0.0.1:${server.address().port}` };
}
before(async () => { on = await start(true); off = await start(false); });
after(async () => { await closeServer(on.server); await closeServer(off.server); });
beforeEach(() => {
  freshStore();
  assistantStore._reset();
  const store = getStore();
  store.targets.push({ id: 'tgt_filters', tenant_id: 'ten_demo', target_group_id: store.targetGroups[0]?.id, kind: 'fqdn', value: 'filters.example.test' });
  store.targets.push({ id: 'tgt_private', tenant_id: 'ten_other', kind: 'fqdn', value: 'private.example.test' });
  store.testRuns.push({ id: 'run_filters', tenant_id: 'ten_demo', target_id: 'tgt_filters', status: 'completed', check_id: 'filters.check', created_at: new Date().toISOString() });
  for (let index = 0; index < 60; index += 1) store.findings.push({ id: `fnd_filters_${index}`, tenant_id: 'ten_demo', target_id: 'tgt_filters', test_run_id: 'run_filters', check_id: 'filters.check', severity: 'high', status: 'open', title: 'Batch finding', created_at: new Date().toISOString() });
  store.findings.push({ id: 'fnd_private', tenant_id: 'ten_other', target_id: 'tgt_private', severity: 'high', status: 'open', title: 'Private finding' });
});
const post = (body, target = on, who = headers) => request(target.baseUrl, 'POST', '/v1/assistant/filters', { headers: who, body });
const lease = () => request(on.baseUrl, 'POST', '/internal/assistant/runner/lease', { headers: runnerHeaders });

async function fakeResult(jobId, filters) {
  await lease();
  await request(on.baseUrl, 'POST', `/internal/assistant/runner/jobs/${jobId}/result`, { headers: runnerHeaders, body: { status: 'done', content: JSON.stringify({ filters, explanation: 'Use these exact filters.' }) } });
  return request(on.baseUrl, 'GET', `/v1/assistant/jobs/${jobId}`, { headers });
}

test('filters endpoint respects switches, tenant enablement, exact body validation and unsupported requests', async () => {
  assert.equal((await post({ kind: 'findings', question: 'show open findings' }, off)).status, 404);
  assert.equal((await post({ kind: 'findings', question: 'show open findings' }, on, demoHeaders('viewer', 'ten_other'))).status, 403);
  for (const body of [{ kind: 'runs', question: 'open' }, { kind: 'findings', question: '' }, { kind: 'findings', question: 'x'.repeat(501) }, { kind: 'findings', question: 'open', sql: 'SELECT' }]) assert.equal((await post(body)).status, 400);
  for (const unsupported of ['open OR closed findings', 'findings last week', 'findings behind Cloudflare', 'SELECT * FROM findings']) {
    const response = await post({ kind: 'findings', question: unsupported });
    assert.equal(response.status, 200);
    assert.equal(response.json.filters, null);
    assert.equal(response.json.narrative.reason, 'unsupported_filter_request');
  }
  assert.equal(assistantStore._jobs.size, 0);
});

test('an exact deterministic preview works offline and preserves findings totals and pagination', async () => {
  const preview = await post({ kind: 'findings', question: 'show open high severity findings for target filters.example.test' });
  assert.equal(preview.status, 200);
  assert.deepEqual(preview.json.filters, { target_id: 'tgt_filters', status: 'open', severity: 'high' });
  assert.equal(preview.json.narrative.status, 'not_requested');
  const query = new URLSearchParams({ ...preview.json.filters, page: '2', limit: '25' });
  const list = await request(on.baseUrl, 'GET', `/v1/findings?${query}`, { headers });
  assert.equal(list.status, 200);
  assert.equal(list.json.total, 60);
  assert.equal(list.json.items.length, 25);
  assert.equal(list.json.page, 2);
  assert.equal(list.json.has_more, true);
  assert.equal(assistantStore._jobs.size, 0);
});

test('queued previews use only a local fake model, private snapshot, no tools and owner-scoped readback', async () => {
  const offline = await post({ kind: 'findings', question });
  assert.equal(offline.json.narrative.reason, 'assistant_runner_offline');
  await lease();
  const created = await post({ kind: 'findings', question });
  assert.equal(created.status, 200);
  assert.equal(created.json.filters, null);
  const id = created.json.narrative.job_id;
  const job = assistantStore._jobs.get(id);
  assert.equal(job.purpose, 'filters');
  assert.ok(job.validation.filters_snapshot.target_id.includes('tgt_filters'));
  assert.ok(!job.validation.filters_snapshot.target_id.includes('tgt_private'));
  assert.deepEqual(job.context, { kind: 'findings' });
  const leased = await lease();
  assert.equal(leased.json.tools, false);
  assert.deepEqual(leased.json.allowed_tools, []);
  assert.ok(!leased.json.prompt.includes('private.example.test'));
  const tool = await request(on.baseUrl, 'POST', `/internal/assistant/runner/jobs/${id}/tool`, { headers: runnerHeaders, body: { name: 'list_findings' } });
  assert.equal(tool.status, 400);
  const stranger = await request(on.baseUrl, 'GET', `/v1/assistant/jobs/${id}`, { headers: demoHeaders('viewer', 'ten_demo', 'usr_stranger') });
  assert.equal(stranger.status, 404);
  const pending = await request(on.baseUrl, 'GET', `/v1/assistant/jobs/${id}`, { headers });
  assert.ok(!JSON.stringify(pending.json).includes('filters_snapshot'));
  await request(on.baseUrl, 'POST', `/internal/assistant/runner/jobs/${id}/result`, { headers: runnerHeaders, body: { status: 'done', content: JSON.stringify({ filters: { status: 'open', target_id: 'tgt_filters', test_run_id: 'run_filters' }, explanation: 'Model narrative' }) } });
  const done = await request(on.baseUrl, 'GET', `/v1/assistant/jobs/${id}`, { headers });
  assert.equal(done.json.status, 'done');
  assert.deepEqual(done.json.response.filters.filters, { status: 'open', target_id: 'tgt_filters', test_run_id: 'run_filters' });
  assert.match(done.json.response.filters.explanation, /Match all of/);
  const audit = getStore().auditLog.find((entry) => entry.resource_id === id && entry.action === 'assistant.job_created');
  assert.ok(audit);
  assert.ok(!JSON.stringify(audit).includes(question));
  assert.ok(!JSON.stringify(audit).includes('filters_snapshot'));
});

test('fake model cannot introduce cross-tenant IDs, unsupported keys/operators, unknown enums or an all-findings fallback', async () => {
  await lease();
  for (const filters of [{ target_id: 'tgt_private' }, { target_group_id: 'tg_1' }, { or: ['open', 'closed'] }, { severity: 'urgent' }, {}, { test_run_id: 'run_invented' }]) {
    const created = await post({ kind: 'findings', question });
    const done = await fakeResult(created.json.narrative.job_id, filters);
    assert.equal(done.json.status, 'failed', JSON.stringify(filters));
    assert.equal(done.json.response, undefined);
  }
});

test('model search strings must match a server-bound explicit literal, never an approximation or the raw prompt', async () => {
  await lease();
  const literal = await post({ kind: 'findings', question: `${question} search "Batch"` });
  const valid = await fakeResult(literal.json.narrative.job_id, { status: 'open', q: 'Batch' });
  assert.equal(valid.json.status, 'done');
  assert.equal(valid.json.response.filters.filters.q, 'Batch');
  const unbound = await post({ kind: 'findings', question });
  assert.equal((await fakeResult(unbound.json.narrative.job_id, { q: question })).json.status, 'failed');
});
