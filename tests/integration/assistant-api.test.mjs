import assert from 'node:assert/strict';
import { after, before, beforeEach, test } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { assistantStore } from '../../src/services/assistant.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { request, demoHeaders, closeServer } from '../helpers/http.mjs';

const TOKEN = 'assistant-runner-token-for-tests-0123456789';
const runner = (token = TOKEN) => ({ authorization: `Bearer ${token}` });

async function start(enabled) {
  const env = {
    ...process.env,
    NODE_ENV: 'test',
    ASTRANULL_AUTH_MODE: 'dev-headers',
    ASTRANULL_ASSISTANT_ENABLED: enabled ? '1' : '',
    ASTRANULL_ASSISTANT_TENANTS: 'ten_demo',
    ASTRANULL_ASSISTANT_RUNNER_TOKEN: TOKEN,
  };
  const server = createServer({ env });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, baseUrl: `http://127.0.0.1:${server.address().port}` };
}

let on;
let off;
before(async () => { on = await start(true); off = await start(false); });
after(async () => { await closeServer(on.server); await closeServer(off.server); });
beforeEach(() => {
  freshStore();
  assistantStore._reset();
  getStore().findings.push({
    id: 'fnd_1', tenant_id: 'ten_demo', target_id: 'tgt_1', title: 'Rate limiting missing on origin.test', severity: 'high',
    status: 'open', check_id: 'l7.low_rate_rate_limit.safe', created_at: new Date().toISOString(),
  });
});

const ask = { messages: [{ role: 'user', content: 'How do I fix this?' }], context: { finding_id: 'fnd_1' } };

test('disabled deployments hide every assistant route', async () => {
  const status = await request(off.baseUrl, 'GET', '/v1/assistant/status', { headers: demoHeaders('viewer') });
  assert.equal(status.status, 200);
  assert.equal(status.json.reason, 'disabled');
  const create = await request(off.baseUrl, 'POST', '/v1/assistant/jobs', { headers: demoHeaders(), body: ask });
  assert.equal(create.status, 404);
  assert.equal(create.json.error, 'assistant_disabled');
  const lease = await request(off.baseUrl, 'POST', '/internal/assistant/runner/lease', { headers: runner() });
  assert.equal(lease.status, 404);
  const features = await request(off.baseUrl, 'GET', '/v1/tenant/deployment-features', { headers: demoHeaders() });
  assert.equal(features.json.assistant, false);
});

test('a job is queued, leased by the runner, answered and read back by its owner only', async () => {
  const features = await request(on.baseUrl, 'GET', '/v1/tenant/deployment-features', { headers: demoHeaders() });
  assert.equal(features.json.assistant, true);
  const offline = await request(on.baseUrl, 'POST', '/v1/assistant/jobs', { headers: demoHeaders(), body: ask });
  assert.equal(offline.status, 503);
  assert.equal(offline.json.error, 'assistant_runner_offline');

  const idle = await request(on.baseUrl, 'POST', '/internal/assistant/runner/lease', { headers: runner() });
  assert.equal(idle.status, 204);
  const status = await request(on.baseUrl, 'GET', '/v1/assistant/status', { headers: demoHeaders('viewer') });
  assert.deepEqual(status.json, { enabled: true, tenant_enabled: true, runner_online: true, model: 'gemini-3.8-flash-high', reason: null, capabilities: { data_tools: true, visuals: true, page_context: true, web_search: true, insights: true } });
  assert.ok(!status.text.includes(TOKEN));

  const created = await request(on.baseUrl, 'POST', '/v1/assistant/jobs', { headers: demoHeaders('viewer'), body: ask });
  assert.equal(created.status, 202);
  assert.match(created.json.job_id, /^asj_[0-9a-f]{24}$/);
  const id = created.json.job_id;

  const stranger = await request(on.baseUrl, 'GET', `/v1/assistant/jobs/${id}`, { headers: demoHeaders('viewer', 'ten_demo', 'usr_other') });
  assert.equal(stranger.status, 404);

  const lease = await request(on.baseUrl, 'POST', '/internal/assistant/runner/lease', { headers: runner() });
  assert.equal(lease.status, 200);
  assert.equal(lease.json.job_id, id);
  assert.match(lease.json.prompt, /Rate limiting missing on origin\.test/);
  assert.deepEqual(lease.json.allowed_tools, ['search_web', 'read_url_content']);

  const posted = await request(on.baseUrl, 'POST', `/internal/assistant/runner/jobs/${id}/result`, {
    headers: runner(),
    body: { status: 'done', content: '## Summary\nAdd a rate limiting rule.', searches: ['cloudflare rate limiting'], sources: [{ url: 'https://developers.cloudflare.com/waf/rate-limiting-rules/' }] },
  });
  assert.equal(posted.status, 200);
  const again = await request(on.baseUrl, 'POST', `/internal/assistant/runner/jobs/${id}/result`, { headers: runner(), body: { status: 'done', content: 'x' } });
  assert.equal(again.status, 409);

  const done = await request(on.baseUrl, 'GET', `/v1/assistant/jobs/${id}`, { headers: demoHeaders('viewer') });
  assert.equal(done.status, 200);
  assert.equal(done.json.status, 'done');
  assert.match(done.json.response.content, /rate limiting rule/);
  assert.deepEqual(done.json.response.sources, [{ url: 'https://developers.cloudflare.com/waf/rate-limiting-rules/' }]);
  assert.ok(!('prompt' in done.json));

  const audit = getStore().auditLog.find((entry) => entry.action === 'assistant.job_created');
  assert.equal(audit.resource_id, id);
  assert.ok(!JSON.stringify(audit).includes('How do I fix this?'));
});

test('the runner channel rejects bad tokens and human sessions', async () => {
  const bad = await request(on.baseUrl, 'POST', '/internal/assistant/runner/lease', { headers: runner('x'.repeat(48)) });
  assert.equal(bad.status, 401);
  const human = await request(on.baseUrl, 'POST', '/internal/assistant/runner/lease', { headers: demoHeaders('owner') });
  assert.equal(human.status, 401);
  const denial = getStore().auditLog.find((entry) => entry.action === 'assistant_runner.auth_denied');
  assert.ok(denial);
  assert.ok(!JSON.stringify(denial).includes('x'.repeat(48)));
});

test('jobs can be cancelled and unknown findings are refused', async () => {
  await request(on.baseUrl, 'POST', '/internal/assistant/runner/lease', { headers: runner() });
  const missing = await request(on.baseUrl, 'POST', '/v1/assistant/jobs', { headers: demoHeaders(), body: { ...ask, context: { finding_id: 'fnd_none' } } });
  assert.equal(missing.status, 404);
  assert.equal(missing.json.error, 'finding_not_found');
  const invalid = await request(on.baseUrl, 'POST', '/v1/assistant/jobs', { headers: demoHeaders(), body: { messages: [] } });
  assert.equal(invalid.status, 400);
  const created = await request(on.baseUrl, 'POST', '/v1/assistant/jobs', { headers: demoHeaders(), body: ask });
  const cancelled = await request(on.baseUrl, 'DELETE', `/v1/assistant/jobs/${created.json.job_id}`, { headers: demoHeaders() });
  assert.equal(cancelled.json.status, 'cancelled');
  const lease = await request(on.baseUrl, 'POST', '/internal/assistant/runner/lease', { headers: runner() });
  assert.equal(lease.status, 204);
});

test('the runner calls data tools for the asker and the answer carries referenced charts', async () => {
  getStore().findings.push({ id: 'fnd_2', tenant_id: 'ten_demo', target_id: 'tgt_1', title: 'Origin exposed', severity: 'medium', status: 'open', check_id: 'edge.origin', created_at: new Date().toISOString() });
  getStore().findings.push({ id: 'fnd_x', tenant_id: 'ten_other', target_id: 'tgt_x', title: 'Other tenant', severity: 'critical', status: 'open', check_id: 'edge.origin', created_at: new Date().toISOString() });
  await request(on.baseUrl, 'POST', '/internal/assistant/runner/lease', { headers: runner() });
  const page = { route: '/findings', title: 'Findings', kind: 'finding-list', filters: { status: 'open' }, facts: { open_count: '2' } };
  const created = await request(on.baseUrl, 'POST', '/v1/assistant/jobs', { headers: demoHeaders('viewer'), body: { messages: [{ role: 'user', content: 'Open findings by severity?' }], context: { page } } });
  assert.equal(created.status, 202);
  const id = created.json.job_id;
  const lease = await request(on.baseUrl, 'POST', '/internal/assistant/runner/lease', { headers: runner() });
  assert.equal(lease.json.tools, true);
  assert.equal(lease.json.max_tool_calls, 8);
  assert.match(lease.json.prompt, /<<<UNTRUSTED_DATA_BEGIN page context>>>/);

  const human = await request(on.baseUrl, 'POST', `/internal/assistant/runner/jobs/${id}/tool`, { headers: demoHeaders('owner'), body: { name: 'list_findings' } });
  assert.equal(human.status, 401);
  const unknown = await request(on.baseUrl, 'POST', `/internal/assistant/runner/jobs/${id}/tool`, { headers: runner(), body: { name: 'run_sql' } });
  assert.equal(unknown.status, 400);
  const tool = await request(on.baseUrl, 'POST', `/internal/assistant/runner/jobs/${id}/tool`, { headers: runner(), body: { name: 'query_data', args: { dataset: 'findings', group_by: 'severity', filters: { status: 'open' } } } });
  assert.equal(tool.status, 200);
  assert.equal(tool.json.data_result_id, 'Q1');
  assert.match(tool.json.result_text, /UNTRUSTED_DATA_BEGIN tool result query_data/);
  assert.ok(!tool.json.result_text.includes('critical'));
  const audit = await request(on.baseUrl, 'POST', `/internal/assistant/runner/jobs/${id}/tool`, { headers: runner(), body: { name: 'list_audit_events' } });
  assert.equal(audit.json.ok, false);
  assert.match(audit.json.result_text, /permission_denied/);

  await request(on.baseUrl, 'POST', `/internal/assistant/runner/jobs/${id}/result`, {
    headers: runner(),
    body: { status: 'done', content: 'You have two open findings.\n\n[[data:Q1|bar]]\n\n[[data:Q5]]', tool_calls: [{ name: 'query_data', summary: 'query_data (dataset=findings, group_by=severity)' }] },
  });
  const done = await request(on.baseUrl, 'GET', `/v1/assistant/jobs/${id}`, { headers: demoHeaders('viewer') });
  assert.equal(done.json.status, 'done');
  assert.match(done.json.response.content, /\[\[data:Q1\|bar\]\]/);
  assert.ok(!done.json.response.content.includes('Q5'));
  assert.deepEqual(done.json.response.tool_calls, [{ name: 'query_data', summary: 'query_data (dataset=findings, group_by=severity)' }]);
  assert.equal(done.json.response.data_results.length, 1);
  const [chart] = done.json.response.data_results;
  assert.equal(chart.id, 'Q1');
  assert.deepEqual(chart.columns.map((column) => column.key), ['severity', 'count']);
  assert.deepEqual(chart.rows.map((row) => row[0]).sort(), ['high', 'medium']);
  const toolAudits = getStore().auditLog.filter((entry) => entry.action === 'assistant.tool_called' && entry.resource_id === id);
  assert.deepEqual(toolAudits.map((entry) => entry.metadata.tool), ['query_data', 'list_audit_events']);
});

test('AI insights return a computed board and queue a tool-less narrative', async () => {
  const hidden = await request(off.baseUrl, 'POST', '/v1/assistant/insights', { headers: demoHeaders(), body: { kind: 'findings' } });
  assert.equal(hidden.status, 404);
  const invalid = await request(on.baseUrl, 'POST', '/v1/assistant/insights', { headers: demoHeaders(), body: { kind: 'finding' } });
  assert.equal(invalid.status, 400);

  const offline = await request(on.baseUrl, 'POST', '/v1/assistant/insights', { headers: demoHeaders('viewer'), body: { kind: 'finding', entity: { id: 'fnd_1' } } });
  assert.equal(offline.status, 200);
  assert.equal(offline.json.board.kind, 'finding');
  assert.equal(offline.json.board.subject, 'Rate limiting missing on origin.test');
  assert.deepEqual(offline.json.narrative, { status: 'unavailable', reason: 'assistant_runner_offline' });

  const missing = await request(on.baseUrl, 'POST', '/v1/assistant/insights', { headers: demoHeaders(), body: { kind: 'finding', entity: { id: 'fnd_nope' } } });
  assert.equal(missing.status, 404);
  const audit = await request(on.baseUrl, 'POST', '/v1/assistant/insights', { headers: demoHeaders('viewer'), body: { kind: 'audit' } });
  assert.equal(audit.json.board.scope.no_access, true);
  assert.equal(audit.json.narrative.status, 'not_requested');

  await request(on.baseUrl, 'POST', '/internal/assistant/runner/lease', { headers: runner() });
  const queued = await request(on.baseUrl, 'POST', '/v1/assistant/insights', { headers: demoHeaders(), body: { kind: 'findings' } });
  assert.equal(queued.json.narrative.status, 'queued');
  const lease = await request(on.baseUrl, 'POST', '/internal/assistant/runner/lease', { headers: runner() });
  assert.deepEqual(lease.json.allowed_tools, []);
  assert.equal(lease.json.tools, false);
  assert.match(lease.json.prompt, /UNTRUSTED_DATA_BEGIN insight board/);
  const done = await request(on.baseUrl, 'POST', `/internal/assistant/runner/jobs/${lease.json.job_id}/result`, { headers: runner(), body: { status: 'done', content: '{"summary":"One high finding is open.","takeaways":["Add a rate limit rule."]}' } });
  assert.equal(done.status, 200);
  const job = await request(on.baseUrl, 'GET', `/v1/assistant/jobs/${lease.json.job_id}`, { headers: demoHeaders() });
  assert.deepEqual(job.json.response.insight, { summary: 'One high finding is open.', takeaways: ['Add a rate limit rule.'], ai: true });
});
