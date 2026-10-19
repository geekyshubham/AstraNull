import assert from 'node:assert/strict';
import { after, before, beforeEach, test } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { assistantStore } from '../../src/services/assistant.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { request, demoHeaders, closeServer } from '../helpers/http.mjs';

const TOKEN = 'fix-pack-fake-runner-token-for-tests-only';
const runner = { authorization: `Bearer ${TOKEN}` };
let server;
let baseUrl;
before(async () => {
  server = createServer({ env: { ...process.env, NODE_ENV: 'test', ASTRANULL_AUTH_MODE: 'dev-headers', ASTRANULL_ASSISTANT_ENABLED: '1', ASTRANULL_ASSISTANT_TENANTS: 'ten_demo', ASTRANULL_ASSISTANT_RUNNER_TOKEN: TOKEN } });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { await closeServer(server); });
beforeEach(() => {
  freshStore(); assistantStore._reset();
  getStore().findings.push({ id: 'fnd_fix', tenant_id: 'ten_demo', target_id: 'tgt_fix', check_id: 'l7.low_rate_rate_limit.safe', severity: 'high', status: 'open', title: 'Rate limit', raw_http: 'RAW_HTTP_NEVER_SENT' });
  getStore().findings.push({ id: 'fnd_foreign', tenant_id: 'ten_other', target_id: 'tgt_other', check_id: 'l7.low_rate_rate_limit.safe', severity: 'high', status: 'open', title: 'PRIVATE_FOREIGN_FINDING' });
});
const generate = (body = { finding_id: 'fnd_fix', provider: 'cloudflare' }, headers = demoHeaders('viewer')) => request(baseUrl, 'POST', '/v1/assistant/fix-packs', { headers, body });
const markOnline = () => request(baseUrl, 'POST', '/internal/assistant/runner/lease', { headers: runner });

test('offline runner returns safe published guidance with no finding, target or run mutation', async () => {
  const store = getStore();
  const before = JSON.stringify({ findings: store.findings, targets: store.targets, runs: store.testRuns });
  const result = await generate();
  assert.equal(result.status, 200);
  assert.equal(result.json.pack.provider, 'cloudflare');
  assert.deepEqual(result.json.narrative, { status: 'unavailable', reason: 'assistant_runner_offline' });
  assert.ok(result.json.pack.rollback.length);
  assert.equal(JSON.stringify({ findings: store.findings, targets: store.targets, runs: store.testRuns }), before);
  assert.ok(store.auditLog.some((event) => event.action === 'assistant.fix_pack_requested'));
});

test('unknown and unauthorized IDs are indistinguishable; unsupported providers/extra prompts fail closed', async () => {
  const missing = await generate({ finding_id: 'fnd_missing' });
  const foreign = await generate({ finding_id: 'fnd_foreign' });
  assert.equal(missing.status, 404); assert.equal(foreign.status, 404);
  assert.deepEqual(missing.json, { error: 'not_found' }); assert.deepEqual(foreign.json, missing.json);
  for (const body of [{ finding_id: 'fnd_fix', provider: 'f5' }, { finding_id: 'fnd_fix', provider: 'https://evil.test' }, { finding_id: 'fnd_fix', prompt: 'Apply this' }, { finding_id: '../secret' }]) assert.equal((await generate(body)).status, 400);
  assert.equal(getStore().auditLog.filter((event) => event.action === 'assistant.fix_pack_requested').length, 0);
});

test('fake runner gets only bounded published guidance and returns the typed fix_pack, not chat content', async () => {
  await markOnline();
  const result = await generate();
  assert.equal(result.status, 200); assert.equal(result.json.narrative.status, 'queued');
  const id = result.json.narrative.job_id;
  const lease = await markOnline();
  assert.equal(lease.json.job_id, id); assert.equal(lease.json.tools, false); assert.deepEqual(lease.json.allowed_tools, []);
  assert.ok(!lease.text.includes('RAW_HTTP_NEVER_SENT')); assert.ok(!lease.text.includes('PRIVATE_FOREIGN_FINDING'));
  const returned = { ...result.json.pack, title: 'Review the published rate limit policy' };
  const completed = await request(baseUrl, 'POST', `/internal/assistant/runner/jobs/${id}/result`, { headers: runner, body: { status: 'done', content: JSON.stringify(returned) } });
  assert.equal(completed.status, 200);
  const done = await request(baseUrl, 'GET', `/v1/assistant/jobs/${id}`, { headers: demoHeaders('viewer') });
  assert.equal(done.json.status, 'done'); assert.deepEqual(done.json.response.fix_pack, returned);
  assert.ok(!Object.hasOwn(done.json.response, 'content')); assert.ok(!done.text.includes('validation'));
  assert.equal((await request(baseUrl, 'GET', `/v1/assistant/jobs/${id}`, { headers: demoHeaders('viewer', 'ten_demo', 'usr_other') })).status, 404);
  assert.equal(getStore().findings.find((finding) => finding.id === 'fnd_fix').status, 'open');
});

test('fake model hallucinated citations or source URLs fail parsing and leave static advice intact', async () => {
  for (const change of [{ citations: ['fnd_foreign'] }, { sources: [{ id: 'invented', title: 'Bad link', url: 'https://evil.test/' }] }, { finding_id: 'fnd_foreign' }]) {
    await markOnline();
    const result = await generate(); const id = result.json.narrative.job_id;
    await markOnline();
    await request(baseUrl, 'POST', `/internal/assistant/runner/jobs/${id}/result`, { headers: runner, body: { status: 'done', content: JSON.stringify({ ...result.json.pack, ...change }) } });
    const done = await request(baseUrl, 'GET', `/v1/assistant/jobs/${id}`, { headers: demoHeaders('viewer') });
    assert.equal(done.json.status, 'failed'); assert.equal(done.json.error, 'fix_pack_unparseable');
    assert.equal(done.json.response, undefined); assert.equal(result.json.pack.finding_id, 'fnd_fix');
  }
});

test('completed fix packs are withheld after access to the finding is revoked', async () => {
  await markOnline();
  const result = await generate(); const id = result.json.narrative.job_id;
  await markOnline();
  await request(baseUrl, 'POST', `/internal/assistant/runner/jobs/${id}/result`, { headers: runner, body: { status: 'done', content: JSON.stringify(result.json.pack) } });
  const allowed = await request(baseUrl, 'GET', `/v1/assistant/jobs/${id}`, { headers: demoHeaders('viewer') });
  assert.equal(allowed.json.status, 'done');
  getStore().findings = getStore().findings.filter((finding) => finding.id !== 'fnd_fix');
  const denied = await request(baseUrl, 'GET', `/v1/assistant/jobs/${id}`, { headers: demoHeaders('viewer') });
  assert.equal(denied.status, 404);
  assert.deepEqual(denied.json, { error: 'not_found' });
  assert.ok(!denied.text.includes(result.json.pack.title));
});

test('cancelled tailoring cannot replace static advice', async () => {
  await markOnline();
  const result = await generate(); const id = result.json.narrative.job_id;
  await markOnline();
  const cancelled = await request(baseUrl, 'DELETE', `/v1/assistant/jobs/${id}`, { headers: demoHeaders('viewer') });
  assert.equal(cancelled.json.status, 'cancelled');
  const late = await request(baseUrl, 'POST', `/internal/assistant/runner/jobs/${id}/result`, { headers: runner, body: { status: 'done', content: JSON.stringify(result.json.pack) } });
  assert.equal(late.status, 409);
});
