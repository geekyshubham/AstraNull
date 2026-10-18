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
    services: { subdomainUiRun: async (input) => { sourceCalls.push(input); return uiResult(input.domain); } },
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
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
  assert.equal(sourceCalls[0].maxResults, 200);
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
