import assert from 'node:assert/strict';
import { after, before, beforeEach, test } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { request, demoHeaders, closeServer } from '../helpers/http.mjs';

let server; let baseUrl;
const sourceCalls = [];
let uiResult;
before(async () => {
  server = createServer({
    env: { NODE_ENV: 'test', ASTRANULL_AUTH_MODE: 'dev-headers', ASTRANULL_WAF_POSTURE_ENABLED: '1',
      ASTRANULL_SUBDOMAIN_PROXY_URL: 'http://user:private-credential@proxy:10000' },
    services: { subdomainUiRun: async (input, options) => { sourceCalls.push(input); return uiResult(input.domain, options); } },
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

test('stream starts before source completion and reports declaration progress and final result', async () => {
  let release;
  let started;
  const sourceStarted = new Promise(resolve => { started = resolve; });
  uiResult = (domain, options) => {
    options.onProgress({ phase: 'fetching', pages: 1, records: 40 });
    started();
    return new Promise(resolve => { release = () => resolve({ hostnames: [`stream.${domain}`], pages: 1,
      reported_total: 1, truncated: false, stop_reason: null }); });
  };
  const response = await fetch(`${baseUrl}/v1/targets/tgt_1/subdomains/enumerate`, {
    method: 'POST', headers: { ...demoHeaders('admin'), accept: 'text/event-stream', 'content-type': 'application/json' }, body: '{}',
  });
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type'), /text\/event-stream/);
  const reader = response.body.getReader();
  const first = await reader.read();
  let content = new TextDecoder().decode(first.value);
  assert.match(content, /preparing/);
  await sourceStarted;
  release();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    content += new TextDecoder().decode(value);
  }
  reader.releaseLock();
  const events = content.trim().split('\n\n').map(frame => JSON.parse(frame.slice(6)));
  assert.ok(events.some(event => event.progress?.records === 40));
  assert.ok(events.some(event => event.progress?.phase === 'declaring'));
  const result = events.find(event => event.type === 'result');
  assert.equal(result.payload.created.length, 1);
});

test('disconnecting a discovery stream cancels the source and creates no child targets', { timeout: 3000 }, async () => {
  let started; let aborted;
  const sourceStarted = new Promise(resolve => { started = resolve; });
  const sourceAborted = new Promise(resolve => { aborted = resolve; });
  uiResult = (_domain, options) => new Promise(resolve => {
    options.signal.addEventListener('abort', () => {
      aborted(); resolve({ error: 'subdomain_discovery_cancelled' });
    }, { once: true });
    started();
  });
  const before = getStore().targets.length;
  const controller = new AbortController();
  const response = await fetch(`${baseUrl}/v1/targets/tgt_1/subdomains/enumerate`, {
    method: 'POST', headers: { ...demoHeaders('admin'), accept: 'text/event-stream', 'content-type': 'application/json' },
    body: '{}', signal: controller.signal,
  });
  await sourceStarted;
  controller.abort();
  await sourceAborted;
  await response.body.cancel().catch(() => {});
  assert.equal(getStore().targets.length, before);
});

test('a rejected stream ends with an error event instead of a success or an endless connection', async () => {
  uiResult = () => ({ error: 'subdomain_source_auth_failed' });
  const response = await fetch(`${baseUrl}/v1/targets/tgt_1/subdomains/enumerate`, {
    method: 'POST', headers: { ...demoHeaders('admin'), accept: 'text/event-stream', 'content-type': 'application/json' }, body: '{}',
  });
  const content = await response.text();
  assert.match(content, /"type":"error"/);
  assert.match(content, /subdomain_source_auth_failed/);
  assert.doesNotMatch(content, /"type":"result"/);
});
after(async () => closeServer(server));
beforeEach(() => {
  freshStore(); sourceCalls.length = 0;
  uiResult = (domain) => ({ hostnames: [`api.${domain}`, `api.${domain}`, 'unrelated.net', `www.${domain}`],
    pages: 2, reported_total: 80, truncated: true, stop_reason: 'rate_limited' });
});

test('default keyless UI source imports bounded descendants and audits partial results without credentials', async () => {
  const list = await request(baseUrl, 'GET', '/v1/targets/tgt_1/subdomains', { headers: demoHeaders('viewer') });
  assert.equal(list.status, 200);
  assert.equal(list.json.source.name, 'virustotal_ui');
  assert.equal(list.json.source.configured, true);
  assert.equal(sourceCalls.length, 0);
  assert.ok(!JSON.stringify(list.json).includes('private-credential'));
  const imported = await request(baseUrl, 'POST', '/v1/targets/tgt_1/subdomains/enumerate', { headers: demoHeaders('admin'), body: {} });
  assert.equal(imported.status, 202, JSON.stringify(imported.json));
  assert.equal(imported.json.source, 'virustotal_ui');
  assert.equal(imported.json.created.length, 2);
  assert.equal(imported.json.truncated, true);
  assert.equal(imported.json.stop_reason, 'rate_limited');
  assert.equal(sourceCalls[0].proxyUrl, 'http://user:private-credential@proxy:10000');
  assert.equal(sourceCalls[0].maxResults, 0);
  const audit = getStore().auditLog.find((row) => row.action === 'target.subdomains_enumerated');
  assert.equal(audit.metadata.source, 'virustotal_ui');
  assert.equal(audit.metadata.stop_reason, 'rate_limited');
  assert.ok(!JSON.stringify({ response: imported.json, audit }).includes('private-credential'));
  const repeated = await request(baseUrl, 'POST', '/v1/targets/tgt_1/subdomains/enumerate', { headers: demoHeaders('admin'), body: {} });
  assert.equal(repeated.json.already_declared, 2);
  assert.equal(repeated.json.created.length, 0);
});

test('UI source honors write permission and imports nothing on first-page errors', async () => {
  const blocked = await request(baseUrl, 'POST', '/v1/targets/tgt_1/subdomains/enumerate', { headers: demoHeaders('viewer'), body: {} });
  assert.equal(blocked.status, 403);
  assert.equal(sourceCalls.length, 0);
  const before = getStore().targets.length;
  for (const error of ['subdomain_source_auth_failed', 'subdomain_source_not_configured', 'subdomain_source_rate_limited']) {
    uiResult = () => ({ error });
    const failed = await request(baseUrl, 'POST', '/v1/targets/tgt_1/subdomains/enumerate', { headers: demoHeaders('admin'), body: {} });
    assert.equal(failed.json.error, error);
    assert.equal(failed.json.source, 'virustotal_ui');
    assert.equal(getStore().targets.length, before);
  }
});

test('imports and lists every host beyond both the old 1000 import cap and 2000 inventory cap', async () => {
  uiResult = (domain) => ({ hostnames: Array.from({ length: 2401 }, (_, i) => `full-${i}.${domain}`),
    pages: 61, reported_total: 2401, truncated: false, stop_reason: null });
  const imported = await request(baseUrl, 'POST', '/v1/targets/tgt_1/subdomains/enumerate', {
    headers: demoHeaders('admin'), body: {},
  });
  assert.equal(imported.status, 202);
  assert.equal(imported.json.found, 2401);
  assert.equal(imported.json.created.length, 2401);
  assert.equal(imported.json.truncated, false);
  const listed = await request(baseUrl, 'GET', '/v1/targets/tgt_1/subdomains', { headers: demoHeaders('viewer') });
  assert.equal(listed.status, 200);
  for (const row of imported.json.created) assert.ok(listed.json.items.some((item) => item.target_id === row.target_id));
  assert.equal(listed.json.meta.truncated, false);
});
