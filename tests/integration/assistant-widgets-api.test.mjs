import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { after, before, beforeEach, test } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { assistantStore } from '../../src/services/assistant.mjs';
import { tryHandleAssistantRoutes } from '../../src/routes/assistantRoutes.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { request, demoHeaders, closeServer } from '../helpers/http.mjs';

const TOKEN = 'widgets-fake-local-runner-token-for-tests-only';
const runner = { authorization: `Bearer ${TOKEN}` };
const config = { name: 'My observed findings', question: 'Which findings need review?', template: 'finding_list' };
let server, baseUrl;
const env = { ...process.env, NODE_ENV: 'test', ASTRANULL_AUTH_MODE: 'dev-headers', ASTRANULL_ASSISTANT_ENABLED: '1', ASTRANULL_ASSISTANT_TENANTS: 'ten_demo', ASTRANULL_ASSISTANT_RUNNER_TOKEN: TOKEN };
before(async () => {
  server = createServer({ env });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { await closeServer(server); });
beforeEach(() => {
  freshStore(); assistantStore._reset(); getStore().assistantWidgets = [];
  getStore().findings.push({ id: 'fnd_widget', tenant_id: 'ten_demo', target_id: 'tgt_widget', check_id: 'check_widget', severity: 'high', status: 'open', title: 'Observed gap', evidence: 'RAW_PRIVATE_EVIDENCE', raw_http: 'RAW_HTTP_NEVER_SENT' });
  getStore().targets.push({ id: 'tgt_widget', tenant_id: 'ten_demo', target_group_id: 'tg_1', kind: 'fqdn', value: 'widget.example.test', tags: [] });
  getStore().findings.push({ id: 'fnd_widget_foreign', tenant_id: 'ten_other', severity: 'high', title: 'PRIVATE_FOREIGN' });
});
const call = (method, path = '', body, headers = demoHeaders('viewer')) => request(baseUrl, method, `/v1/assistant/widgets${path}`, { headers, ...(body === undefined ? {} : { body }) });
const online = async () => {
  const result = await request(baseUrl, 'POST', '/internal/assistant/runner/lease', { headers: runner });
  assert.ok([200, 204].includes(result.status), JSON.stringify(result));
  return result;
};

test('preview compute/save/list/refresh/edit/delete are read-only definitions and audit with optimistic versions', async () => {
  const snapshot = JSON.stringify({ runs: getStore().testRuns, scans: getStore().validationScans, findings: getStore().findings, targets: getStore().targets, schedules: getStore().testPolicies, jobs: getStore().probeJobs });
  const preview = await call('POST', '/preview', { config });
  assert.equal(preview.status, 200); assert.equal(preview.json.data.count, 1);
  assert.deepEqual(preview.json.narrative, { status: 'not_requested' }); assert.equal(assistantStore._jobs.size, 0);
  assert.equal(getStore().assistantWidgets.length, 0); assert.equal(preview.text.includes('RAW_HTTP'), false); assert.equal(preview.text.includes('PRIVATE_FOREIGN'), false);
  const saved = await call('POST', '', { config });
  assert.equal(saved.status, 201); const widget = saved.json.widget; assert.equal(widget.version, 1);
  assert.deepEqual((await call('GET')).json.widgets, [widget]);
  assert.deepEqual((await call('POST', `/${widget.id}/refresh`, { narrative: false })).json.narrative, { status: 'not_requested' });
  const edited = await call('PATCH', `/${widget.id}`, { config: { ...config, name: 'Edited' }, expected_version: 1 });
  assert.equal(edited.status, 200); assert.equal(edited.json.widget.version, 2);
  const stale = await call('DELETE', `/${widget.id}`, { expected_version: 1 });
  assert.equal(stale.status, 409); assert.deepEqual(stale.json, { error: 'widget_version_conflict', current_version: 2 });
  assert.deepEqual((await call('DELETE', `/${widget.id}`, { expected_version: 2 })).json, { deleted: true });
  assert.deepEqual((await call('GET')).json, { widgets: [] });
  assert.equal(JSON.stringify({ runs: getStore().testRuns, scans: getStore().validationScans, findings: getStore().findings, targets: getStore().targets, schedules: getStore().testPolicies, jobs: getStore().probeJobs }), snapshot);
  assert.deepEqual(getStore().auditLog.filter((event) => event.resource_type === 'assistant_widget').map((event) => event.action), ['assistant.widget_created', 'assistant.widget_updated', 'assistant.widget_deleted']);
});

test('strict fields/version/narrative, missing records and per-user isolation fail closed', async () => {
  for (const body of [{ config, html: '<script>bad</script>' }, { config: { ...config, sql: 'select *' } }, { config: { ...config, template: 'renderer' } }, { config: { ...config, severity: 'S2' } }, { config: { ...config, target_id: 'tgt_foreign' } }]) {
    const result = await call('POST', '', body); assert.ok([400, 404].includes(result.status), JSON.stringify(result.json));
  }
  for (const narrative of ['true', 1, null]) assert.equal((await call('POST', '/preview', { config, narrative })).status, 400);
  const saved = (await call('POST', '', { config })).json.widget;
  const foreign = demoHeaders('viewer', 'ten_demo', 'usr_foreign');
  assert.deepEqual((await call('GET', '', undefined, foreign)).json, { widgets: [] });
  for (const [method, suffix, body] of [['PATCH', '', { config, expected_version: 1 }], ['DELETE', '', { expected_version: 1 }], ['POST', '/refresh', {}]]) {
    assert.equal((await call(method, `/${saved.id}${suffix}`, body, foreign)).status, 404);
  }
  for (const expected_version of [undefined, '1', 0]) assert.equal((await call('PATCH', `/${saved.id}`, { config, expected_version })).status, 400);
  assert.equal((await call('POST', '', { config }, demoHeaders('viewer', 'ten_other'))).status, 403);
});

test('lost target access hides configurations but preserves private owned removal and quota recovery', async () => {
  const scoped = { ...config, target_id: 'tgt_widget', severity: 'high' };
  const saved = [];
  for (let index = 0; index < 12; index += 1) {
    const result = await call('POST', '', { config: scoped }); assert.equal(result.status, 201);
    saved.push(result.json.widget);
  }
  getStore().targets = getStore().targets.filter((target) => target.id !== 'tgt_widget');
  assert.equal((await call('POST', '', { config: scoped })).status, 404);
  const hidden = await call('GET');
  assert.deepEqual(hidden.json.widgets, saved.map(({ id, version }) => ({ id, version, unavailable: true })));
  for (const privateValue of [config.name, config.question, 'tgt_widget']) assert.equal(hidden.text.includes(privateValue), false);
  const { id, version } = saved[0];
  assert.equal((await call('POST', `/${id}/refresh`, {})).status, 404);
  assert.equal((await call('PATCH', `/${id}`, { config, expected_version: version })).status, 404);
  assert.equal((await call('POST', '', { config })).json.error, 'widget_limit_reached');
  const foreign = demoHeaders('viewer', 'ten_demo', 'usr_foreign');
  assert.deepEqual((await call('GET', '', undefined, foreign)).json, { widgets: [] });
  assert.equal((await call('DELETE', `/${id}`, { expected_version: version }, foreign)).status, 404);
  assert.equal((await call('DELETE', `/${id}`, { expected_version: version + 1 })).status, 409);
  assert.deepEqual((await call('DELETE', `/${id}`, { expected_version: version })).json, { deleted: true });
  assert.equal(getStore().auditLog.at(-1).action, 'assistant.widget_deleted');
  assert.equal((await call('POST', '', { config })).status, 201);
  assert.equal(getStore().assistantWidgets.length, 12);
});

test('explicit narrative alone queues tool-free commentary, validates snapshot citations and does not persist results', async () => {
  await online();
  const preview = await call('POST', '/preview', { config, narrative: true });
  assert.equal(preview.status, 200); assert.equal(preview.json.narrative.status, 'queued', JSON.stringify(preview.json));
  const id = preview.json.narrative.job_id, lease = await online();
  assert.equal(lease.json.job_id, id); assert.deepEqual(lease.json.allowed_tools, []); assert.equal(lease.json.tools, false);
  assert.equal(lease.text.includes('RAW_PRIVATE_EVIDENCE'), false); assert.equal(lease.text.includes('RAW_HTTP'), false);
  const commentary = { text: 'Review the observed gap.', citations: ['fnd_widget'] };
  await request(baseUrl, 'POST', `/internal/assistant/runner/jobs/${id}/result`, { headers: runner, body: { status: 'done', content: JSON.stringify(commentary) } });
  const done = await request(baseUrl, 'GET', `/v1/assistant/jobs/${id}`, { headers: demoHeaders('viewer') });
  assert.equal(done.json.status, 'done'); assert.deepEqual(done.json.response.widget_commentary, commentary);
  assert.equal(done.text.includes('validation'), false); assert.equal(getStore().assistantWidgets.length, 0);
  const generated = await call('POST', '/preview', { config, narrative: true }); await online();
  await request(baseUrl, 'POST', `/internal/assistant/runner/jobs/${generated.json.narrative.job_id}/result`, { headers: runner,
    body: { status: 'done', content: JSON.stringify({ ...commentary, citations: ['fnd_widget_foreign'] }) } });
  const bad = await request(baseUrl, 'GET', `/v1/assistant/jobs/${generated.json.narrative.job_id}`, { headers: demoHeaders('viewer') });
  assert.equal(bad.json.status, 'failed'); assert.equal(bad.json.error, 'widget_commentary_unparseable');
});

test('offline explicit AI refresh leaves deterministic data usable; cancellation rejects late output', async () => {
  const preview = await call('POST', '/preview', { config, narrative: true });
  assert.equal(preview.json.data.count, 1); assert.deepEqual(preview.json.narrative, { status: 'unavailable', reason: 'assistant_runner_offline' });
  await online(); const queued = await call('POST', '/preview', { config, narrative: true }); await online();
  const id = queued.json.narrative.job_id;
  assert.equal((await request(baseUrl, 'DELETE', `/v1/assistant/jobs/${id}`, { headers: demoHeaders('viewer') })).json.status, 'cancelled');
  assert.equal((await request(baseUrl, 'POST', `/internal/assistant/runner/jobs/${id}/result`, { headers: runner, body: { status: 'done', content: '{"text":"late","citations":["fnd_widget"]}' } })).status, 409);
});

test('commentary retrieval rechecks every count-basis finding, including undisplayed rows, and current explicit target access', async () => {
  getStore().findings.push(...Array.from({ length: 8 }, (_, i) => ({ id: `fnd_basis_${i}`, tenant_id: 'ten_demo', target_id: 'tgt_widget', severity: 'high', title: 'Another observed gap', status: 'open' })));
  await online();
  const preview = await call('POST', '/preview', { config, narrative: true });
  assert.equal(preview.json.narrative.status, 'queued');
  assert.equal(preview.json.data.rows.length, 6); assert.equal(preview.json.data.count, 9);
  const id = preview.json.narrative.job_id;
  const hidden = getStore().findings.find((finding) => finding.tenant_id === 'ten_demo' && !preview.json.data.citations.includes(finding.id));
  assert.ok(hidden);
  await online();
  await request(baseUrl, 'POST', `/internal/assistant/runner/jobs/${id}/result`, { headers: runner,
    body: { status: 'done', content: JSON.stringify({ text: 'Review these observed gaps.', citations: [preview.json.data.citations[0]] }) } });
  getStore().findings = getStore().findings.filter((finding) => finding.id !== hidden.id);
  assert.equal((await request(baseUrl, 'GET', `/v1/assistant/jobs/${id}`, { headers: demoHeaders('viewer') })).status, 404);
  const scoped = await call('POST', '/preview', { config: { ...config, target_id: 'tgt_widget' }, narrative: true });
  assert.equal(scoped.json.narrative.status, 'queued');
  await online();
  await request(baseUrl, 'POST', `/internal/assistant/runner/jobs/${scoped.json.narrative.job_id}/result`, { headers: runner,
    body: { status: 'done', content: JSON.stringify({ text: 'Review this target snapshot.', citations: [scoped.json.data.citations[0]] }) } });
  getStore().targets = getStore().targets.filter((target) => target.id !== 'tgt_widget');
  assert.equal((await request(baseUrl, 'GET', `/v1/assistant/jobs/${scoped.json.narrative.job_id}`, { headers: demoHeaders('viewer') })).status, 404);
});

test('malformed/oversized JSON is rejected and unsupported role is forbidden', async () => {
  const invalid = await request(baseUrl, 'POST', '/v1/assistant/widgets/preview', { headers: demoHeaders('viewer'), rawBody: '{invalid' });
  assert.equal(invalid.status, 400); assert.equal(invalid.json.error, 'invalid_json');
  const oversized = await call('POST', '/preview', { config: { ...config, question: 'x'.repeat(5000) } });
  assert.equal(oversized.status, 413); assert.equal(oversized.json.error, 'payload_too_large');
  // Dev headers intentionally normalize unknown roles to viewer. Exercise the router's
  // real role/scope gate directly rather than claiming that fixture is an invalid actor.
  for (const actor of [{ role: 'unsupported-role' }, { role: 'viewer', scopes: ['target_group:read'] }]) {
    const response = { setHeader() {}, writeHead(status) { this.status = status; }, end(body) { this.body = JSON.parse(body); } };
    await tryHandleAssistantRoutes({ method: 'GET' }, response, new URL('/v1/assistant/widgets', baseUrl),
      { tenantId: 'ten_demo', userId: 'usr_admin', ...actor }, { assistant: { enabled: true } });
    assert.equal(response.status, 403); assert.equal(response.body.error, 'forbidden');
  }
});

test('every widget handler is disabled behind the assistant switch', async () => {
  const disabled = createServer({ env: { ...env, ASTRANULL_ASSISTANT_ENABLED: '0' } });
  await new Promise((resolve) => disabled.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${disabled.address().port}`;
  try {
    for (const [method, path] of [['GET', ''], ['POST', ''], ['POST', '/preview'], ['PATCH', '/aw_000000000000000000000000'], ['DELETE', '/aw_000000000000000000000000'], ['POST', '/aw_000000000000000000000000/refresh']]) {
      const result = await request(url, method, `/v1/assistant/widgets${path}`, { headers: demoHeaders('viewer'), ...(method === 'GET' ? {} : { body: { config } }) });
      assert.equal(result.status, 404); assert.equal(result.json.error, 'assistant_disabled');
    }
  } finally { await closeServer(disabled); }
});
