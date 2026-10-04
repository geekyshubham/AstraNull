import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { probeWorkerAuthHeaders } from '../../src/services/probeCoordinator.mjs';
import { getStore } from '../../src/store.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const SECRET = '938d3c93a4befa41b096eae03ad0902bc90b4e006b8c8ba0454cc517711b9948';

test('signed activity is lease-bound, immutable, tenant-scoped, read-only, and revoked by Stop', async () => {
  freshStore();
  const at = new Date().toISOString();
  const store = getStore();
  store.testRuns.push({ id: 'run_activity', tenant_id: 'ten_demo', target_id: 'tgt_1', target_group_id: 'tg_1', check_id: 'waf.fingerprint.safe',
    status: 'collecting', created_at: at, collection_deadline_at: new Date(Date.now() - 1000).toISOString(), safety_constraints: { max_events: 1 } });
  store.probeJobs = [{ id: 'job_activity', tenant_id: 'ten_demo', test_run_id: 'run_activity', target_id: 'tgt_1', check_id: 'waf.fingerprint.safe',
    status: 'leased', leased_by: 'worker_activity', leased_at: at, nonce_hash: 'hash_activity' }];
  const env = { ...process.env, NODE_ENV: 'test', ASTRANULL_AUTH_MODE: 'dev-headers', ASTRANULL_PROBE_MODE: 'signed-worker', ASTRANULL_PROBE_WORKER_SECRET: SECRET };
  const server = createServer({ env, runtimeConfig: loadRuntimeConfig(env) });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const path = '/internal/probe/jobs/job_activity/activity';
  const body = { leased_at: at, items: [{ sequence: 1, at, stage: 'request_started', method: 'GET', url: 'https://owned.test/path?key=private', request_content_type: 'application/json', request_payload_preview: '{"marker":"inert","password":"private-password"}' }] };
  const post = (payload = body, workerId = 'worker_activity', tenantId = 'ten_demo') => request(base, 'POST', path, { body: payload,
    headers: probeWorkerAuthHeaders(workerId, { method: 'POST', path, bodyText: JSON.stringify(payload), tenantId }, SECRET) });
  try {
    assert.equal((await request(base, 'POST', path, { headers: demoHeaders(), body })).status, 401);
    assert.equal((await post()).status, 201);
    assert.equal((await post()).json.accepted, 0);
    assert.equal((await post({ ...body, items: [{ ...body.items[0], method: 'POST' }] })).status, 409);
    assert.equal((await post(body, 'another_worker')).status, 403);
    assert.equal((await post(body, 'worker_activity', 'ten_other')).status, 404);
    const before = { events: store.events.length, runs: store.testRuns.length, audits: store.auditLog.length };
    const read = await request(base, 'GET', '/v1/test-runs/run_activity/activity', { headers: demoHeaders('viewer') });
    assert.equal(read.status, 200);
    assert.ok(read.json.items.some((item) => item.method === 'GET'));
    assert.ok(read.json.items.some((item) => item.request_payload_preview?.includes('inert')));
    assert.equal(JSON.stringify(read.json).includes('private'), false);
    assert.equal(store.testRuns[0].status, 'collecting');
    assert.deepEqual({ events: store.events.length, runs: store.testRuns.length, audits: store.auditLog.length }, before);
    assert.equal((await request(base, 'GET', '/v1/test-runs/run_activity/activity', { headers: demoHeaders('admin', 'ten_other') })).status, 404);
    const spoof = await request(base, 'POST', '/v1/events', { headers: demoHeaders(), body: { event_id: 'spoof', signal_type: 'probe_activity' } });
    assert.equal(spoof.status, 400);
    assert.equal(spoof.json.error, 'reserved_signal_type');
    assert.equal((await request(base, 'POST', '/v1/test-runs/run_activity/cancel', { headers: demoHeaders(), body: { reason: 'User stopped this check' } })).status, 200);
    assert.equal((await post({ leased_at: at, items: [] })).status, 409);
    assert.equal(store.events.length, before.events);
  } finally { await closeServer(server); }
});
