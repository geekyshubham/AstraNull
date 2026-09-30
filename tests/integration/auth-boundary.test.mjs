import assert from 'node:assert/strict';
import { after, afterEach, before, describe, it } from 'node:test';
import { mintSignedSessionToken } from '../../src/context.mjs';
import { createServer } from '../../src/server.mjs';
import { createAddressedSecret } from '../../src/lib/addressedSecrets.mjs';

import {
  demoHeaders,
  request,
  signedSessionHeaders,
} from '../helpers/http.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const TEST_SECRET = 'integration-session-secret-32chars-min';
const envSnapshot = { ...process.env };

let baseUrl;
let server;

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function startSignedSessionServer() {
  freshStore();
  process.env.ASTRANULL_AUTH_MODE = 'signed-session';
  process.env.ASTRANULL_SESSION_SECRET = TEST_SECRET;
  delete process.env.NODE_ENV;
  server = createServer();
  server.listen(0);
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
}

before(() => {
  startSignedSessionServer();
});

after(() => {
  server?.close();
  restoreEnv();
});

afterEach(() => {
  restoreEnv();
  process.env.ASTRANULL_AUTH_MODE = 'signed-session';
  process.env.ASTRANULL_SESSION_SECRET = TEST_SECRET;
});

describe('signed-session API boundary', () => {
  it('returns 401 for /v1/state without session token', async () => {
    const res = await request(baseUrl, 'GET', '/v1/state');
    assert.equal(res.status, 401);
    assert.equal(res.json.error, 'unauthorized');
  });

  it('allows tenant read with a valid signed session', async () => {
    const headers = signedSessionHeaders('engineer', 'ten_demo', 'usr_eng', TEST_SECRET, mintSignedSessionToken);
    const res = await request(baseUrl, 'GET', '/v1/tenants/current', { headers });
    assert.equal(res.status, 200);
    assert.equal(res.json.id, 'ten_demo');
  });

  it('ignores spoofed x-role when session role is viewer', async () => {
    const headers = {
      ...signedSessionHeaders('viewer', 'ten_demo', 'usr_view', TEST_SECRET, mintSignedSessionToken),
      'x-role': 'admin',
      'x-tenant-id': 'ten_demo',
    };
    const res = await request(baseUrl, 'POST', '/v1/targets', {
      headers,
      body: { kind: 'fqdn', value: 'should-fail.example.com' },
    });
    assert.equal(res.status, 403);
    assert.equal(res.json.error, 'forbidden');
  });

  it('invalid addressed service-account bearer audits without secret material', async () => {
    const tampered = createAddressedSecret('svc_', 'ten_demo', 'sacc_nonexistent');
    const bogus = `${tampered}x`;
    const before = getStore().auditLog.length;
    const res = await request(baseUrl, 'GET', '/v1/target-groups', {
      headers: { Authorization: `Bearer ${bogus}` },
    });
    assert.equal(res.status, 401);
    const failure = getStore().auditLog
      .slice(before)
      .find((a) => a.action === 'service_account.auth_failed');
    assert.ok(failure);
    assert.equal(failure.tenant_id, 'ten_demo');
    assert.equal(failure.resource_id, 'sacc_nonexistent');
    assert.deepEqual(failure.metadata, { reason: 'invalid_token' });
    assert.ok(!JSON.stringify(failure).includes(bogus));
  });

  it('opaque bogus service-account bearer does not write auth_failed audit', async () => {
    const bogus = 'svc_bogus_integration_token_not_real';
    const before = getStore().auditLog.length;
    const res = await request(baseUrl, 'GET', '/v1/target-groups', {
      headers: { Authorization: `Bearer ${bogus}` },
    });
    assert.equal(res.status, 401);
    const failures = getStore().auditLog
      .slice(before)
      .filter((a) => a.action === 'service_account.auth_failed');
    assert.equal(failures.length, 0);
  });

  it('admin service account with wildcard cannot use SOC-only routes', async () => {
    const adminHeaders = signedSessionHeaders('admin', 'ten_demo', 'usr_admin', TEST_SECRET, mintSignedSessionToken);
    const created = await request(baseUrl, 'POST', '/v1/service-accounts', {
      headers: adminHeaders,
      body: { name: 'wildcard-admin', role: 'admin', scopes: ['*'] },
    });
    assert.equal(created.status, 201);
    const svcHeaders = { Authorization: `Bearer ${created.json.secret}` };

    const killSwitch = await request(baseUrl, 'POST', '/internal/soc/kill-switch', {
      headers: svcHeaders,
      body: { active: true, reason: 'integration-test' },
    });
    assert.equal(killSwitch.status, 403);
    assert.equal(killSwitch.json.permission, 'soc:kill_switch');
  });

  it('service account bearer authenticates scoped API access', async () => {
    const adminHeaders = signedSessionHeaders('admin', 'ten_demo', 'usr_admin', TEST_SECRET, mintSignedSessionToken);
    const created = await request(baseUrl, 'POST', '/v1/service-accounts', {
      headers: adminHeaders,
      body: { name: 'integration-bot', role: 'engineer', scopes: ['target_group:read'] },
    });
    assert.equal(created.status, 201);
    assert.ok(created.json.secret?.startsWith('svc_'));
    const svcHeaders = { Authorization: `Bearer ${created.json.secret}` };

    const list = await request(baseUrl, 'GET', '/v1/target-groups', { headers: svcHeaders });
    assert.equal(list.status, 200);

    const denied = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: svcHeaders,
      body: { check_id: 'dns_authority_exposure', target_group_id: 'tg_1' },
    });
    assert.equal(denied.status, 403);
  });

});
