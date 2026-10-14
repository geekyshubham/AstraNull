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
beforeEach(() => { freshStore(); });

test('GET control-declarations returns version 1 when none are stored', async () => {
  const result = await request(baseUrl, 'GET', '/v1/targets/tgt_1/control-declarations', { headers });
  assert.equal(result.status, 200);
  assert.equal(result.json.version, 1);
  assert.equal(result.json.waf, undefined);
});

test('PUT then GET round-trips validated declarations', async () => {
  const body = {
    version: 1,
    network_policy: [{ protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' }],
    waf: {
      block_signature: { header_name: 'X-WAF-Block', header_value: 'edge-deny', status_codes: [403] },
      expected_action: 'block',
      rate_limit_canary: { path: '/rl', method: 'HEAD', threshold: 2, window_seconds: 5 },
      marker_paths: ['/marker'],
    },
    origin: { lockdown_expected: false },
    perspectives: { allowlisted_perspective_ids: ['default'] },
    canary_sink: { url: 'https://origin.test/sink' },
    connection_limits: [{ protocol: 'tcp', port: 443, max_connections_per_source: 3 }],
  };
  const put = await request(baseUrl, 'PUT', '/v1/targets/tgt_1/control-declarations', { headers: { ...headers, 'if-match': '"decl-r0"' }, body });
  assert.equal(put.status, 200);
  assert.equal(put.json.version, 1);
  assert.equal(put.json.waf.block_signature.header_name, 'x-waf-block');
  assert.equal(typeof put.json.updated_at, 'string');
  assert.equal(put.json.updated_by, 'usr_admin');
  const got = await request(baseUrl, 'GET', '/v1/targets/tgt_1/control-declarations', { headers });
  assert.equal(got.status, 200);
  assert.equal(got.json.waf.expected_action, 'block');
  assert.equal(got.json.canary_sink.url, 'https://origin.test/sink');
  assert.deepEqual(got.json.perspectives.allowlisted_perspective_ids, ['default']);
});

test('PUT returns 400 with field-level errors on validation failure', async () => {
  const result = await request(baseUrl, 'PUT', '/v1/targets/tgt_1/control-declarations', {
    headers: { ...headers, 'if-match': '"decl-r0"' },
    body: { version: 1, extra: true, waf: { expected_action: 'allow' } },
  });
  assert.equal(result.status, 400);
  assert.equal(result.json.error, 'invalid_control_declarations');
  assert.ok(result.json.field);
  assert.equal(Array.isArray(result.json.errors), true);
  assert.ok(result.json.errors.length >= 1);
});

test('control-declarations are 404 across tenants and 403 for viewers on write', async () => {
  const foreign = await request(baseUrl, 'GET', '/v1/targets/tgt_1/control-declarations', {
    headers: demoHeaders('owner', 'ten_other', 'usr_other'),
  });
  assert.equal(foreign.status, 404);
  assert.equal(foreign.json.error, 'not_found');
  const missing = await request(baseUrl, 'PUT', '/v1/targets/missing/control-declarations', {
    headers: { ...headers, 'if-match': '"decl-r0"' },
    body: { version: 1 },
  });
  assert.equal(missing.status, 404);
  const viewerGet = await request(baseUrl, 'GET', '/v1/targets/tgt_1/control-declarations', {
    headers: demoHeaders('viewer'),
  });
  assert.equal(viewerGet.status, 200);
  const viewerPut = await request(baseUrl, 'PUT', '/v1/targets/tgt_1/control-declarations', {
    headers: { ...demoHeaders('viewer'), 'if-match': '"decl-r0"' },
    body: { version: 1 },
  });
  assert.equal(viewerPut.status, 403);
});

test('PUT writes an audit event with a before/after summary and no header value', async () => {
  const put = await request(baseUrl, 'PUT', '/v1/targets/tgt_1/control-declarations', {
    headers: { ...headers, 'if-match': '"decl-r0"' },
    body: {
      version: 1,
      waf: {
        block_signature: { header_name: 'x-waf-block', header_value: 'edge-deny', status_codes: [403] },
        expected_action: 'block',
      },
    },
  });
  assert.equal(put.status, 200);
  const entry = getStore().auditLog.find((row) => row.action === 'target.control_declarations_updated');
  assert.ok(entry);
  assert.equal(entry.resource_type, 'target');
  assert.equal(entry.resource_id, 'tgt_1');
  assert.equal(entry.metadata.after.block_header_name, 'x-waf-block');
  assert.equal(entry.metadata.after.block_header_value_length, 9);
  assert.equal(JSON.stringify(entry).includes('edge-deny'), false);
});

test('GET /v1/probe-perspectives lists the default registry', async () => {
  const result = await request(baseUrl, 'GET', '/v1/probe-perspectives', { headers });
  assert.equal(result.status, 200);
  assert.equal(result.json.count, 1);
  assert.equal(result.json.items[0].id, 'default');
  assert.equal(result.json.items[0].label, 'Primary');
  assert.deepEqual(result.json.items[0].egress_ips, []);
  assert.equal((await request(baseUrl, 'GET', '/v1/probe-perspectives', { headers: demoHeaders('viewer') })).status, 200);
});
