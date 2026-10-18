import assert from 'node:assert/strict';
import { after, before, beforeEach, test } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { request, demoHeaders, closeServer } from '../helpers/http.mjs';
import { recordDnsVerification } from '../helpers/subdomain-fixtures.mjs';

let server; let baseUrl; let sourceCalls = 0;
const ctx = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
before(async () => {
  server = createServer({ env: { ...process.env, NODE_ENV: 'test', ASTRANULL_AUTH_MODE: 'dev-headers',
    ASTRANULL_VIRUSTOTAL_API_KEY: 'fixture-key', ASTRANULL_SUBDOMAIN_SOURCE: 'virustotal', ASTRANULL_WAF_POSTURE_ENABLED: '1' },
    services: { subdomainFetch: async (url) => {
      sourceCalls += 1;
      const domain = decodeURIComponent(new URL(url).pathname.split('/').at(-2));
      return { status: 200, json: async () => ({ data: [{ id: `api.${domain}` }, { id: 'foreign.example.net' }] }) };
    } },
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});
after(async () => closeServer(server));
beforeEach(() => { freshStore(); sourceCalls = 0; });

test('subdomain import is explicit, idempotent and never starts probes before review', async () => {
  const parent = getStore().targets.find((row) => row.id === 'tgt_1');
  recordDnsVerification(ctx, parent);
  const before = getStore().testRuns.length;
  const imported = await request(baseUrl, 'POST', '/v1/targets/tgt_1/subdomains/enumerate', { headers: demoHeaders('admin'), body: {} });
  assert.equal(imported.status, 202);
  assert.equal(imported.json.created.length, 1);
  assert.deepEqual(imported.json.detection.queued, []);
  assert.equal(getStore().testRuns.length, before);
  const initial = await request(baseUrl, 'GET', `/v1/targets/${imported.json.created[0].target_id}/initial-detection`, { headers: demoHeaders('viewer') });
  assert.equal(initial.status, 200);
  assert.equal(initial.json.initial_detection.status, 'queued');
  assert.equal(getStore().testRuns.length, before, 'queue read cannot start a probe');
  const list = await request(baseUrl, 'GET', '/v1/targets/tgt_1/subdomains', { headers: demoHeaders('viewer') });
  assert.equal(list.status, 200);
  const child = list.json.items.find((row) => row.target_id === imported.json.created[0].target_id);
  assert.equal(child.verification_inherited, true);
  assert.equal(child.ownership_verified, true);
  assert.equal(child.exposure, 'not_checked');
  const again = await request(baseUrl, 'POST', '/v1/targets/tgt_1/subdomains/enumerate', { headers: demoHeaders('admin'), body: {} });
  assert.equal(again.json.created.length, 0);
  assert.equal(again.json.already_declared, 1);
  assert.ok(getStore().auditLog.some((entry) => entry.action === 'target.subdomains_enumerated'));
});

test('enumeration and detection keep permissions, parent boundaries and tenant isolation', async () => {
  assert.equal((await request(baseUrl, 'POST', '/v1/targets/tgt_1/subdomains/enumerate', { headers: demoHeaders('viewer'), body: {} })).status, 403);
  assert.equal(sourceCalls, 0);
  assert.equal((await request(baseUrl, 'GET', '/v1/targets/foreign/subdomains', { headers: demoHeaders('admin') })).status, 404);
  const imported = await request(baseUrl, 'POST', '/v1/targets/tgt_1/subdomains/enumerate', { headers: demoHeaders('admin'), body: {} });
  const childId = imported.json.created[0].target_id;
  assert.equal((await request(baseUrl, 'POST', `/v1/targets/${childId}/subdomains/enumerate`, { headers: demoHeaders('admin'), body: {} })).status, 409);
  const before = getStore().testRuns.length;
  const detection = await request(baseUrl, 'POST', '/v1/targets/tgt_1/subdomains/detect', { headers: demoHeaders('admin'), body: { scope: 'unchecked' } });
  assert.equal(detection.status, 202);
  assert.equal(detection.json.queued.length, 0);
  assert.equal(detection.json.skipped[0].reason, 'target_ownership_not_verified');
  assert.equal(getStore().testRuns.length, before);
});
