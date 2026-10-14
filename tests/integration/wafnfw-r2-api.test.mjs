import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, before, beforeEach, describe, test } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { probeWorkerAuthHeaders } from '../../src/services/probeCoordinator.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const headers = demoHeaders('owner');
const PATH = '/v1/targets/tgt_1/control-declarations';
const DENY_22 = { version: 1, network_policy: [{ protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' }] };

async function listen(server) {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${server.address().port}`;
}

describe('dev control-declarations concurrency and target-scoped checks', () => {
  let server;
  let baseUrl;
  before(async () => { server = createServer(); baseUrl = await listen(server); });
  after(async () => { await closeServer(server); });
  beforeEach(() => { freshStore(); });

  test('GET returns an ETag and revision; PUT needs If-Match and the second writer gets 412', async () => {
    const first = await request(baseUrl, 'GET', PATH, { headers });
    assert.equal(first.status, 200);
    assert.equal(first.json.revision, 0);
    assert.equal(first.headers.etag, '"decl-r0"');

    const missing = await request(baseUrl, 'PUT', PATH, { headers, body: DENY_22 });
    assert.equal(missing.status, 428);
    assert.equal(missing.json.error, 'precondition_required');

    const writerA = await request(baseUrl, 'PUT', PATH, { headers: { ...headers, 'if-match': first.headers.etag }, body: DENY_22 });
    assert.equal(writerA.status, 200);
    assert.equal(writerA.json.revision, 1);
    assert.equal(writerA.headers.etag, '"decl-r1"');

    const writerB = await request(baseUrl, 'PUT', PATH, {
      headers: { ...headers, 'if-match': first.headers.etag },
      body: { version: 1, waf: { expected_action: 'block' } },
    });
    assert.equal(writerB.status, 412);
    assert.equal(writerB.json.error, 'declarations_conflict');
    assert.equal(writerB.json.revision, 1);
    assert.equal(writerB.headers.etag, '"decl-r1"');

    const star = await request(baseUrl, 'PUT', PATH, { headers: { ...headers, 'if-match': '*' }, body: DENY_22 });
    assert.equal(star.status, 412);

    const kept = await request(baseUrl, 'GET', PATH, { headers });
    assert.deepEqual(kept.json.network_policy, DENY_22.network_policy);
    assert.equal(kept.json.waf, undefined);
    assert.equal(getStore().auditLog.filter((row) => row.action === 'target.control_declarations_updated').length, 1);
  });

  test('GET /v1/checks?target_id= lists a port check once the target declares tcp/22', async () => {
    const before = await request(baseUrl, 'GET', '/v1/checks?target_id=tgt_1', { headers });
    assert.equal(before.status, 200);
    assert.equal(before.json.target_id, 'tgt_1');
    assert.equal(before.json.items.some((check) => check.check_id === 'l3.tcp_flag_anomaly.readiness'), false);
    const etag = (await request(baseUrl, 'GET', PATH, { headers })).headers.etag;
    assert.equal((await request(baseUrl, 'PUT', PATH, { headers: { ...headers, 'if-match': etag }, body: DENY_22 })).status, 200);
    const afterDeclare = await request(baseUrl, 'GET', '/v1/checks?target_id=tgt_1', { headers });
    assert.equal(afterDeclare.json.items.some((check) => check.check_id === 'l3.tcp_flag_anomaly.readiness'), true);
    assert.equal(afterDeclare.json.items.some((check) => check.check_id === 'l3.basic_deny_rule.safe'), true);
    assert.equal(before.json.items.some((check) => check.check_id === 'l3.basic_deny_rule.safe'), false);
    const all = await request(baseUrl, 'GET', '/v1/checks?scope=all&target_id=tgt_1', { headers });
    assert.equal(all.json.items.find((check) => check.check_id === 'l3.tcp_flag_anomaly.readiness').requires_additional_input, false);
    const plain = await request(baseUrl, 'GET', '/v1/checks?scope=all', { headers });
    assert.equal(plain.json.items.find((check) => check.check_id === 'l3.tcp_flag_anomaly.readiness').requires_additional_input, true);
    assert.equal((await request(baseUrl, 'GET', '/v1/checks?target_id=missing', { headers })).status, 404);
  });

  test('a single-target scan refuses a port check without a port and plans it with a declared rule', async () => {
    const body = { target_group_id: 'tg_1', target_id: 'tgt_1', check_ids: ['l3.tcp_flag_anomaly.readiness'] };
    const refused = await request(baseUrl, 'POST', '/v1/validation-scans', { headers, body });
    assert.equal(refused.status, 400);
    assert.equal(refused.json.error, 'check_requires_additional_input');
    assert.equal(refused.json.reason, 'port_required');
    const etag = (await request(baseUrl, 'GET', PATH, { headers })).headers.etag;
    assert.equal((await request(baseUrl, 'PUT', PATH, { headers: { ...headers, 'if-match': etag }, body: DENY_22 })).status, 200);
    const planned = await request(baseUrl, 'POST', '/v1/validation-scans', { headers, body });
    assert.equal(planned.status, 201, planned.text);
  });
});

describe('dev per-perspective worker secret', () => {
  const SHARED = randomBytes(32).toString('hex');
  const EU_SECRET = randomBytes(32).toString('hex');
  let server;
  let baseUrl;
  before(async () => {
    const env = {
      ...process.env,
      ASTRANULL_PROBE_MODE: 'signed-worker',
      ASTRANULL_PROBE_WORKER_SECRET: SHARED,
      ASTRANULL_RATE_LIMIT_DISABLED: '1',
      ASTRANULL_PROBE_PERSPECTIVES: JSON.stringify([
        { id: 'eu-1', label: 'EU', egress_ips: [], worker_secret: EU_SECRET },
        { id: 'us-1', label: 'US', egress_ips: [] },
      ]),
    };
    server = createServer({ runtimeConfig: loadRuntimeConfig(env), env });
    baseUrl = await listen(server);
  });
  after(async () => { await closeServer(server); });
  beforeEach(() => { freshStore(); });

  test('a lease claiming a secured perspective with the shared secret is 403 and audited without secrets', async () => {
    const path = '/internal/probe/jobs';
    const forged = probeWorkerAuthHeaders('w_forged', { method: 'GET', path, tenantId: 'ten_demo', perspectiveId: 'eu-1' }, SHARED);
    const denied = await request(baseUrl, 'GET', path, { headers: forged });
    assert.equal(denied.status, 403);
    assert.equal(denied.json.error, 'probe_perspective_unauthenticated');
    const entry = getStore().auditLog.find((row) => row.action === 'probe_worker.perspective_auth_denied');
    assert.ok(entry);
    assert.equal(entry.resource_id, 'eu-1');
    assert.equal(JSON.stringify(entry).includes(EU_SECRET) || JSON.stringify(entry).includes(SHARED), false);

    const signed = probeWorkerAuthHeaders('w_eu', { method: 'GET', path, tenantId: 'ten_demo', perspectiveId: 'eu-1' }, EU_SECRET);
    assert.equal((await request(baseUrl, 'GET', path, { headers: signed })).status, 200);
    const open = probeWorkerAuthHeaders('w_us', { method: 'GET', path, tenantId: 'ten_demo', perspectiveId: 'us-1' }, SHARED);
    assert.equal((await request(baseUrl, 'GET', path, { headers: open })).status, 200);
  });
});
