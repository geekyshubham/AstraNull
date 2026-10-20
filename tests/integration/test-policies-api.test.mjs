import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

let server;
let baseUrl;

const previousNoPersist = process.env.ASTRANULL_NO_PERSIST;

before(async () => {
  freshStore();
  server = createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  assert.equal(address.address, '127.0.0.1');
  assert.equal(address.family, 'IPv4');
  assert.ok(address.port > 0);
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  try {
    await closeServer(server);
  } finally {
    if (previousNoPersist === undefined) delete process.env.ASTRANULL_NO_PERSIST;
    else process.env.ASTRANULL_NO_PERSIST = previousNoPersist;
  }
});

beforeEach(() => {
  freshStore();
});

describe('test policies API', () => {
  it('creates, lists, updates, and archives safe validation policies', async () => {
    const engineer = demoHeaders('engineer');

    const created = await request(baseUrl, 'POST', '/v1/test-policies', {
      headers: engineer,
      body: {
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
        check_id: 'dns.authoritative_response.safe',
        cadence: 'weekly',
        expected_verdict: 'pass',
        safe_windows: [{ day: 'Mon', start: '09:00', end: '11:00', timezone: 'UTC' }],
      },
    });

    assert.equal(created.status, 201);
    assert.equal(created.json.target_group_id, 'tg_1');
    assert.equal(created.json.target_id, 'tgt_1');
    assert.equal(created.json.target.id, 'tgt_1');
    assert.equal(created.json.target.kind, 'fqdn');
    assert.equal(created.json.target.value, 'origin.test');
    assert.equal(created.json.check_id, 'dns.authoritative_response.safe');
    assert.equal(created.json.cadence, 'weekly');
    assert.equal(created.json.check.safety_class, 'safe');
    assert.equal(created.json.target_group.name, 'TG');

    const listed = await request(baseUrl, 'GET', '/v1/test-policies', { headers: engineer });
    assert.equal(listed.status, 200);
    assert.equal(listed.json.items.length, 1);
    assert.equal(listed.json.items[0].id, created.json.id);
    assert.equal(listed.json.items[0].target_count, 1);

    const patched = await request(baseUrl, 'PATCH', `/v1/test-policies/${created.json.id}`, {
      headers: engineer,
      body: {
        cadence: 'monthly',
        expected_verdict: 'warn',
        target_group_id: 'tg_other',
        target_id: 'tgt_other',
        check_id: 'path.protected_canary.safe',
      },
    });
    assert.equal(patched.status, 200);
    assert.equal(patched.json.cadence, 'monthly');
    assert.equal(patched.json.expected_verdict, 'warn');
    assert.equal(patched.json.target_group_id, 'tg_1');
    assert.equal(patched.json.target_id, 'tgt_1');
    assert.equal(patched.json.check_id, 'dns.authoritative_response.safe');

    const archived = await request(baseUrl, 'DELETE', `/v1/test-policies/${created.json.id}`, {
      headers: engineer,
    });
    assert.equal(archived.status, 200);
    assert.equal(archived.json.archived, true);

    const listedAfterArchive = await request(baseUrl, 'GET', '/v1/test-policies', { headers: engineer });
    assert.equal(listedAfterArchive.status, 200);
    assert.equal(listedAfterArchive.json.items.length, 0);
  });

  it('rejects SOC-gated checks as customer-runnable policy bindings', async () => {
    // Exercise a normal customer; usr_admin is the explicit demo-account exception.
    const engineer = demoHeaders('engineer', 'ten_demo', 'usr_engineer');
    const created = await request(baseUrl, 'POST', '/v1/test-policies', {
      headers: engineer,
      body: {
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
        check_id: 'high_scale.volumetric.request_only',
        cadence: 'manual',
      },
    });

    assert.equal(created.status, 403);
    assert.equal(created.json.error, 'soc_gated_check');
  });

  it('retains a successful policy and its audit across later failed and duplicate pair writes', async () => {
    const headers = demoHeaders('engineer', 'ten_demo', 'usr_engineer');
    const body = { target_group_id: 'tg_1', target_id: 'tgt_1', check_id: 'dns.authoritative_response.safe', cadence: 'weekly', timezone: 'UTC' };
    const created = await request(baseUrl, 'POST', '/v1/test-policies', { headers, body });
    assert.equal(created.status, 201);
    const incompatible = await request(baseUrl, 'POST', '/v1/test-policies', { headers, body: { ...body, check_id: 'path.protected_canary.safe' } });
    assert.equal(incompatible.status, 400);
    const duplicate = await request(baseUrl, 'POST', '/v1/test-policies', { headers, body });
    assert.equal(duplicate.status, 409);
    assert.equal(duplicate.json.error, 'test_policy_exists');
    assert.deepEqual(getStore().testPolicies.map((policy) => policy.id), [created.json.id]);
    const audits = getStore().auditLog.filter((entry) => entry.action === 'test_policy.created');
    assert.equal(audits.length, 1);
    assert.equal(audits[0].resource_id, created.json.id);
    assert.equal(audits[0].metadata.target_id, body.target_id);
    assert.equal(audits[0].metadata.check_id, body.check_id);
    assert.equal(getStore().testRuns.length, 0);
    assert.equal(getStore().probeJobs.length, 0);
  });

  for (const scenario of ['read-only role', 'foreign tenant', 'foreign target', 'archived target']) {
    it(`rejects ${scenario} without creating policies or execution jobs`, async () => {
      const body = { target_group_id: 'tg_1', target_id: 'tgt_1', check_id: 'dns.authoritative_response.safe' };
      let headers = demoHeaders('engineer', 'ten_demo', 'usr_engineer');
      if (scenario === 'read-only role') headers = demoHeaders('auditor', 'ten_demo', 'usr_auditor');
      if (scenario === 'foreign tenant') headers = demoHeaders('engineer', 'ten_other', 'usr_other');
      if (scenario === 'foreign target') getStore().targets[0].tenant_id = 'ten_other';
      if (scenario === 'archived target') getStore().targets[0].deleted_at = new Date().toISOString();
      const response = await request(baseUrl, 'POST', '/v1/test-policies', { headers, body });
      assert.equal(response.status, scenario === 'read-only role' ? 403 : 404);
      assert.equal(getStore().testPolicies.length, 0);
      assert.equal(getStore().auditLog.filter((entry) => entry.action === 'test_policy.created').length, 0);
      assert.equal(getStore().testRuns.length, 0);
      assert.equal(getStore().probeJobs.length, 0);
    });
  }

  it('rejects check and effective target-kind incompatibility before persistence', async () => {
    const engineer = demoHeaders('engineer');
    const created = await request(baseUrl, 'POST', '/v1/test-policies', {
      headers: engineer,
      body: {
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
        check_id: 'path.protected_canary.safe',
        cadence: 'manual',
      },
    });

    assert.equal(created.status, 400);
    assert.deepEqual(created.json, {
      error: 'target_kind_not_supported',
      status: 400,
      check_id: 'path.protected_canary.safe',
      target_kind: 'fqdn',
      supported_targets: ['url'],
    });
    const listed = await request(baseUrl, 'GET', '/v1/test-policies', { headers: engineer });
    assert.equal(listed.json.items.length, 0);
  });
});
