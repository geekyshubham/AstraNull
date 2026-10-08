import assert from 'node:assert/strict';
import { after, before, beforeEach, test } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

let server;
let baseUrl;
const headers = demoHeaders('owner');
before(async () => {
  server = createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { await closeServer(server); });
beforeEach(() => {
  freshStore();
  getStore().targets.push({ ...getStore().targets[0], id: 'tgt_peer', value: 'peer.test', normalized_value: 'peer.test' });
});

test('direct target ownership exposes only that target and cannot verify a peer challenge', async () => {
  const issue = await request(baseUrl, 'POST', '/v1/targets/tgt_1/dns-ownership/issue', { headers, body: {} });
  assert.equal(issue.status, 201);
  assert.equal(issue.json.challenge.target_id, 'tgt_1');
  assert.equal(JSON.stringify(issue.json).includes('target_group'), false);
  const peer = await request(baseUrl, 'POST', '/v1/targets/tgt_peer/dns-ownership/issue', { headers, body: {} });
  assert.equal(peer.status, 201);
  const own = await request(baseUrl, 'GET', '/v1/targets/tgt_1/dns-ownership', { headers });
  assert.equal(own.status, 200);
  assert.ok(own.json.items.every((item) => item.target_id === 'tgt_1'));
  const wrong = await request(baseUrl, 'POST', '/v1/targets/tgt_1/dns-ownership/verify', { headers, body: { challenge_id: peer.json.challenge.id } });
  assert.equal(wrong.status, 404);
  assert.equal(wrong.json.error, 'target_challenge_not_found');
  assert.equal((await request(baseUrl, 'GET', '/v1/targets/foreign/dns-ownership', { headers })).status, 404);
  assert.equal((await request(baseUrl, 'POST', '/v1/targets/tgt_1/dns-ownership/issue', { headers: demoHeaders('viewer'), body: {} })).status, 403);
});

test('direct run requests use target_id and preserve the inherited execution policy', async () => {
  const result = await request(baseUrl, 'POST', '/v1/test-runs', { headers, body: { target_id: 'tgt_1', check_id: 'waf.fingerprint.safe' } });
  assert.equal(result.status, 201);
  const recorded = getStore().testRuns.find((run) => run.id === result.json.run.id);
  assert.equal(recorded.target_id, 'tgt_1');
  assert.equal(recorded.target_group_id, 'tg_1');
  assert.equal((await request(baseUrl, 'POST', '/v1/test-runs', { headers, body: { target_id: 'foreign', check_id: 'waf.fingerprint.safe' } })).status, 404);
});

test('direct target removal remains permission-gated and refuses an active run', async () => {
  getStore().testRuns.push({ id: 'run_active', tenant_id: 'ten_demo', target_group_id: 'tg_1', target_id: 'tgt_1', status: 'collecting' });
  assert.equal((await request(baseUrl, 'DELETE', '/v1/targets/tgt_1', { headers })).status, 409);
  assert.equal((await request(baseUrl, 'DELETE', '/v1/targets/tgt_peer', { headers: demoHeaders('viewer') })).status, 403);
  assert.equal((await request(baseUrl, 'DELETE', '/v1/targets/tgt_peer', { headers })).status, 200);
  assert.ok(getStore().targets.find((target) => target.id === 'tgt_peer').deleted_at);
});

test('direct CSV intake validates the entire file before creating any declared target', async () => {
  const before = getStore().targets.length;
  const invalid = await request(baseUrl, 'POST', '/v1/targets:csv', { headers, body: { csv: 'kind,value\nfqdn,new.example\nip,invalid-ip' } });
  assert.equal(invalid.status, 422);
  assert.equal(getStore().targets.length, before);
  const valid = await request(baseUrl, 'POST', '/v1/targets:csv', { headers, body: { csv: 'kind,value\nfqdn,first.example\nfqdn,second.example' } });
  assert.equal(valid.status, 201);
  assert.equal(valid.json.created.length, 2);
  assert.ok(valid.json.created.every((target) => target.id && !Object.hasOwn(target, 'target_group_id')));
  assert.equal(getStore().targets.length, before + 2);
});

test('direct portal representations omit grouping fields while durable execution binding stays intact', async () => {
  const directHeaders = { ...headers, 'x-astranull-target-model': 'direct' };
  const result = await request(baseUrl, 'POST', '/v1/test-runs', { headers: directHeaders, body: { target_id: 'tgt_1', check_id: 'waf.fingerprint.safe' } });
  assert.equal(result.status, 201);
  assert.equal(Object.hasOwn(result.json.run, 'target_group_id'), false);
  assert.equal(getStore().testRuns.find((run) => run.id === result.json.run.id).target_group_id, 'tg_1');
  const inventory = await request(baseUrl, 'GET', '/v1/targets', { headers: directHeaders });
  assert.equal(inventory.status, 200);
  assert.ok(inventory.json.items.every((target) => !Object.hasOwn(target, 'target_group_id') && !Object.hasOwn(target, 'target_group_name')));
});

test('target authorization excludes peer scope and requires an explicit valid signer and attestation', async () => {
  const missing = await request(baseUrl, 'POST', '/v1/targets/tgt_1/authorization', { headers, body: { attested: true } });
  assert.equal(missing.status, 400);
  const wrongScope = await request(baseUrl, 'POST', '/v1/targets/tgt_1/authorization', { headers, body: { signer_name: 'Owner', signer_email: 'owner@example.test', attested: true, scope_ack: ['tgt_peer'] } });
  assert.equal(wrongScope.status, 400);
  assert.equal(wrongScope.json.error, 'target_selection_conflict');
  const noAttestation = await request(baseUrl, 'POST', '/v1/targets/tgt_1/authorization', { headers, body: { signer_name: 'Owner', signer_email: 'owner@example.test', attested: false } });
  assert.equal(noAttestation.status, 403);
  getStore().loaSignatures = [];
  getStore().loaSignatures.push({ id: 'loa_peer', tenant_id: 'ten_demo', target_group_id: 'tg_1', state: 'signed', scope_snapshot: { targets: ['tgt_peer'] } });
  const mine = await request(baseUrl, 'GET', '/v1/targets/tgt_1/authorization', { headers });
  assert.equal(mine.status, 200);
  assert.equal(mine.json.authorization, null);
  const peer = await request(baseUrl, 'GET', '/v1/targets/tgt_peer/authorization', { headers });
  assert.equal(peer.json.authorization.id, 'loa_peer');
  assert.equal((await request(baseUrl, 'GET', '/v1/targets/foreign/authorization', { headers })).status, 404);
  assert.equal(getStore().highScaleRequests.length, 0);
  assert.equal(getStore().testRuns.length, 0);
});

test('distinct domain authorizations coexist without overriding or covering their peers', async () => {
  getStore().loaSignatures = [];
  getStore().targetVerifications = ['tgt_1', 'tgt_peer'].map((target_id) => ({ id: `tv_${target_id}`, tenant_id: 'ten_demo', target_id, state: 'dns_verified', source_kind: 'dns_txt', transitioned_at: new Date().toISOString() }));
  const body = { signer_name: 'Owner', signer_email: 'owner@example.test', attested: true };
  const first = await request(baseUrl, 'POST', '/v1/targets/tgt_1/authorization', { headers, body });
  const second = await request(baseUrl, 'POST', '/v1/targets/tgt_peer/authorization', { headers, body });
  assert.equal(first.status, 201);
  assert.equal(second.status, 201);
  assert.deepEqual(first.json.loa.scope_snapshot.targets, ['tgt_1']);
  assert.deepEqual(second.json.loa.scope_snapshot.targets, ['tgt_peer']);
  assert.equal((await request(baseUrl, 'GET', '/v1/targets/tgt_1/authorization', { headers })).json.authorization.id, first.json.loa.id);
  assert.equal((await request(baseUrl, 'GET', '/v1/targets/tgt_peer/authorization', { headers })).json.authorization.id, second.json.loa.id);
  assert.equal((await request(baseUrl, 'POST', '/v1/targets/tgt_1/authorization', { headers, body })).status, 409);
  assert.equal(getStore().loaSignatures.length, 2);
  assert.equal(getStore().auditLog.filter((entry) => entry.action === 'loa.signed').length, 2);
  assert.equal(getStore().testRuns.length, 0);
});
