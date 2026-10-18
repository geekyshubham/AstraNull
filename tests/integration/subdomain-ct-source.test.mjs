import assert from 'node:assert/strict';
import { after, before, beforeEach, test } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { request, demoHeaders, closeServer } from '../helpers/http.mjs';

const sourceCalls = [];
let ctResponse = () => ({ status: 200, json: async () => [] });

async function startServer(extraEnv) {
  const server = createServer({
    env: { ...process.env, NODE_ENV: 'test', ASTRANULL_AUTH_MODE: 'dev-headers', ASTRANULL_WAF_POSTURE_ENABLED: '1',
      ASTRANULL_VIRUSTOTAL_API_KEY: '', ASTRANULL_SUBDOMAIN_SOURCE: 'crtsh', ...extraEnv },
    services: { subdomainFetch: async (url) => { sourceCalls.push(new URL(url)); return ctResponse(new URL(url)); } },
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, baseUrl: `http://127.0.0.1:${server.address().port}` };
}

let keyless; let disabled;
before(async () => {
  keyless = await startServer({});
  disabled = await startServer({ ASTRANULL_SUBDOMAIN_SOURCE: 'disabled' });
});
after(async () => { await closeServer(keyless.server); await closeServer(disabled.server); });
beforeEach(() => { freshStore(); sourceCalls.length = 0; ctResponse = () => ({ status: 200, json: async () => [] }); });

function parentHost() {
  const parent = getStore().targets.find((row) => row.id === 'tgt_1');
  return String(parent.normalized_value ?? parent.value).toLowerCase();
}

test('explicit Certificate Transparency discovery imports hosts without a VirusTotal key', async () => {
  const host = parentHost();
  ctResponse = () => ({ status: 200, json: async () => [
    { common_name: `www.${host}`, name_value: `www.${host}\napi.${host}\n*.${host}` },
    { common_name: 'unrelated.example.net', name_value: `unrelated.example.net\nops@${host}` },
  ] });
  const list = await request(keyless.baseUrl, 'GET', '/v1/targets/tgt_1/subdomains', { headers: demoHeaders('viewer') });
  assert.equal(list.status, 200);
  assert.equal(list.json.source.configured, true);
  assert.equal(list.json.source.name, 'crtsh');
  assert.match(list.json.source.label, /Certificate Transparency/);
  assert.equal(sourceCalls.length, 0, 'reading the inventory never queries the source');

  const imported = await request(keyless.baseUrl, 'POST', '/v1/targets/tgt_1/subdomains/enumerate', { headers: demoHeaders('admin'), body: {} });
  assert.equal(imported.status, 202, JSON.stringify(imported.json));
  assert.equal(imported.json.source, 'crtsh');
  assert.deepEqual(imported.json.created.map((row) => row.hostname).sort(), [`api.${host}`, `www.${host}`]);
  assert.equal(sourceCalls.length, 1);
  assert.equal(sourceCalls[0].origin, 'https://crt.sh');
  assert.equal(sourceCalls[0].searchParams.get('q'), `%.${host}`);
  assert.equal(sourceCalls[0].searchParams.get('output'), 'json');

  const reloaded = await request(keyless.baseUrl, 'GET', '/v1/targets/tgt_1/subdomains', { headers: demoHeaders('viewer') });
  assert.deepEqual(reloaded.json.items.map((row) => row.hostname), [`api.${host}`, `www.${host}`]);
  assert.ok(reloaded.json.items.every((row) => row.origin === 'discovered'));
  const audit = getStore().auditLog.find((entry) => entry.action === 'target.subdomains_enumerated');
  assert.equal(audit.metadata.source, 'crtsh');
});

test('an unavailable Certificate Transparency source fails visibly without importing anything', async () => {
  const before = getStore().targets.length;
  ctResponse = () => ({ status: 502, json: async () => ({}) });
  const failed = await request(keyless.baseUrl, 'POST', '/v1/targets/tgt_1/subdomains/enumerate', { headers: demoHeaders('admin'), body: {} });
  assert.equal(failed.status, 502);
  assert.equal(failed.json.error, 'subdomain_source_failed');
  assert.equal(failed.json.source, 'crtsh');
  ctResponse = () => { throw new TypeError('fetch failed'); };
  const unreachable = await request(keyless.baseUrl, 'POST', '/v1/targets/tgt_1/subdomains/enumerate', { headers: demoHeaders('admin'), body: {} });
  assert.equal(unreachable.status, 502);
  assert.equal(unreachable.json.error, 'subdomain_source_unreachable');
  assert.equal(getStore().targets.length, before);
});

test('an explicitly disabled source reports why and never calls out', async () => {
  const list = await request(disabled.baseUrl, 'GET', '/v1/targets/tgt_1/subdomains', { headers: demoHeaders('viewer') });
  assert.equal(list.json.source.configured, false);
  assert.equal(list.json.source.reason, 'disabled');
  const blocked = await request(disabled.baseUrl, 'POST', '/v1/targets/tgt_1/subdomains/enumerate', { headers: demoHeaders('admin'), body: {} });
  assert.equal(blocked.status, 503);
  assert.equal(blocked.json.error, 'subdomain_source_not_configured');
  assert.equal(sourceCalls.length, 0);
});
