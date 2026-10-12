import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, before, beforeEach, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { closeServer, demoHeaders, request, staffHeaders } from '../helpers/http.mjs';
import { PERMISSIONS } from '../../src/contracts/roles.mjs';
import { STAFF_PERMISSIONS } from '../../src/contracts/staffRoles.mjs';
import { CUSTOMER_ACTION_ROLES, STAFF_ACTION_ROLES, MUTATING_ACTION_FAMILIES, STAFF_MUTATING_ACTION_FAMILIES } from '../fixtures/portal-action-coverage.mjs';

const inheritedEnv = { ...process.env };
let server;
let baseUrl;
function businessSnapshot() {
  // Compare every current business collection, including optional lazily-created state.
  // Only denial auditing and explicitly documented authentication-use metadata are exempt.
  return JSON.stringify(Object.fromEntries(Object.entries(getStore()).filter(([name]) => !['auditLog', 'internalAuditLog'].includes(name)).sort(([a], [b]) => a.localeCompare(b)).map(([name, value]) => [name, !Array.isArray(value) ? value : value.map((item) => {
    // Bearer authentication records use metadata; it is not the forbidden business mutation.
    if (name !== 'serviceAccounts') return item;
    const { last_used_at, last_used_ip, ...business } = item;
    return business;
  })])));
}
function assertDenialAudit(permission, role, from, { staff = false, scope = false } = {}) {
  const log = staff ? getStore().internalAuditLog : getStore().auditLog;
  const audit = log.slice(from).find((entry) => entry.action === (staff ? 'staff.rbac.denied' : 'rbac.denied') && entry.metadata.permission === permission);
  assert.ok(audit, `Missing persisted denial audit ${role} ${permission}`);
  assert.equal(staff ? audit.staff_role : audit.actor_role, role);
  if (scope) assert.equal(audit.metadata.reason, 'scope');
  assert.equal(JSON.stringify(audit).includes('synthetic-never-a-provider-credential'), false);
}

before(async () => {
  // This suite is deliberately dev-json. Never inherit a production/local PostgreSQL URL.
  delete process.env.ASTRANULL_DATABASE_URL;
  delete process.env.ASTRANULL_ADMIN_DATABASE_URL;
  Object.assign(process.env, { NODE_ENV: 'test', ASTRANULL_AUTH_MODE: 'dev-headers', ASTRANULL_NO_PERSIST: '1', ASTRANULL_RATE_LIMIT_DISABLED: '1', ASTRANULL_WAF_POSTURE_ENABLED: '1', ASTRANULL_CONNECTORS_ENABLED: '1', ASTRANULL_SECRET_ENCRYPTION_KEY: randomBytes(32).toString('base64') });
  freshStore();
  server = createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
  await closeServer(server);
  for (const key of Object.keys(process.env)) if (!(key in inheritedEnv)) delete process.env[key];
  Object.assign(process.env, inheritedEnv);
});
beforeEach(() => freshStore());

describe('shipped UI mutators: real API role denial, no business write, persisted denial audit', () => {
  for (const family of MUTATING_ACTION_FAMILIES) {
    assert.ok(PERMISSIONS[family.permission], family.permission);
    for (const role of CUSTOMER_ACTION_ROLES.filter((role) => !PERMISSIONS[family.permission].includes(role))) {
      it(`${family.id}: ${role} denied before service execution`, async () => {
        const before = businessSnapshot();
        const auditFrom = getStore().auditLog.length;
        const result = await request(baseUrl, family.method, family.path, { headers: demoHeaders(role, 'ten_demo', `usr_${role}`), body: family.body });
        assert.equal(result.status, 403, `${family.method} ${family.path}: ${result.text}`);
        assert.equal(result.json.permission, family.permission);
        assert.equal(businessSnapshot(), before, 'forbidden caller must not mutate business state');
        assertDenialAudit(family.permission, role, auditFrom);
      });
    }
  }
});

describe('shipped UI mutators: automation token cannot inherit its admin role beyond explicit scope', () => {
  for (const family of MUTATING_ACTION_FAMILIES) it(`${family.id}: admin bearer without mutation scope denied and audited`, async () => {
    const created = await request(baseUrl, 'POST', '/v1/service-accounts', { headers: demoHeaders('admin'), body: { name: 'action-readonly-scope', role: 'admin', scopes: ['check:read'] } });
    assert.equal(created.status, 201);
    const token = created.json.secret;
    assert.ok(token);
    const before = businessSnapshot();
    const auditFrom = getStore().auditLog.length;
    const result = await request(baseUrl, family.method, family.path, { headers: { Authorization: `Bearer ${token}` }, body: family.body });
    assert.equal(result.status, 403, result.text);
    assert.equal(result.json.permission, family.permission);
    assert.equal(businessSnapshot(), before);
    assertDenialAudit(family.permission, 'admin', auditFrom, { scope: true });
    assert.equal(JSON.stringify(getStore().auditLog.slice(auditFrom)).includes(token), false);
  });
});

describe('staff action authorization is a separate six-role matrix', () => {
  for (const family of STAFF_MUTATING_ACTION_FAMILIES) {
    assert.ok(STAFF_PERMISSIONS[family.permission]);
    for (const role of STAFF_ACTION_ROLES.filter((role) => !STAFF_PERMISSIONS[family.permission].includes(role))) it(`${family.id}: ${role} denied and internal-audited`, async () => {
      const before = businessSnapshot();
      const auditFrom = getStore().internalAuditLog?.length ?? 0;
      const result = await request(baseUrl, family.method, family.path, { headers: staffHeaders(role, `staff_${role}`), body: family.body });
      assert.equal(result.status, 403, result.text);
      assert.equal(result.json.permission, family.permission);
      assert.equal(businessSnapshot(), before);
      assertDenialAudit(family.permission, role, auditFrom, { staff: true });
    });
  }
});

it('vault and service-account resource IDs cannot cross tenants or alter the owning records', async () => {
  const secret = await request(baseUrl, 'POST', '/v1/secrets', { headers: demoHeaders('admin'), body: { purpose: 'connector', name: 'tenant-bound', plaintext: 'synthetic-cross-tenant-secret' } });
  const account = await request(baseUrl, 'POST', '/v1/service-accounts', { headers: demoHeaders('admin'), body: { name: 'tenant-bound', role: 'viewer', scopes: ['report:read'] } });
  assert.equal(secret.status, 201);
  assert.equal(account.status, 201);
  for (const path of [`/v1/secrets/${secret.json.secret.id}/rotate`, `/v1/service-accounts/${account.json.id}/rotate`, `/v1/service-accounts/${account.json.id}/revoke`]) {
    const before = businessSnapshot();
    const result = await request(baseUrl, 'POST', path, { headers: demoHeaders('admin', 'ten_other'), body: { plaintext: 'synthetic-denied-rotation' } });
    assert.equal(result.status, 404, result.text);
    assert.equal(result.json.error, 'not_found');
    assert.equal(businessSnapshot(), before);
    assert.equal(result.text.includes(secret.json.secret.id), false);
    assert.equal(result.text.includes('synthetic-cross-tenant-secret'), false);
  }
});

for (const operation of ['vault.rotate', 'service-account.rotate', 'service-account.revoke']) it(`${operation}: tenant-masked denial still requires a persisted caller-tenant audit`, async () => {
  const secret = await request(baseUrl, 'POST', '/v1/secrets', { headers: demoHeaders('admin'), body: { purpose: 'connector', name: 'tenant-audit-bound', plaintext: 'synthetic-cross-tenant-audit-secret' } });
  const account = await request(baseUrl, 'POST', '/v1/service-accounts', { headers: demoHeaders('admin'), body: { name: 'tenant-audit-bound', role: 'viewer', scopes: ['report:read'] } });
  assert.equal(secret.status, 201); assert.equal(account.status, 201);
  const id = operation === 'vault.rotate' ? secret.json.secret.id : account.json.id;
  const path = operation === 'vault.rotate' ? `/v1/secrets/${id}/rotate` : `/v1/service-accounts/${id}/${operation.endsWith('revoke') ? 'revoke' : 'rotate'}`;
  const before = businessSnapshot();
  const auditFrom = getStore().auditLog.length;
  const result = await request(baseUrl, 'POST', path, { headers: demoHeaders('admin', 'ten_other', 'usr_cross_tenant'), body: { plaintext: 'synthetic-denied-rotation' } });
  assert.equal(result.status, 404); assert.equal(businessSnapshot(), before);
  const denial = getStore().auditLog.slice(auditFrom).find((entry) => /(?:denied|not_found)$/.test(entry.action) && entry.tenant_id === 'ten_other' && entry.actor_user_id === 'usr_cross_tenant' && entry.resource_id === id);
  assert.ok(denial, `Missing tenant denial audit for POST ${path}; HTTP 404 alone is not authorization evidence`);
  assert.equal(JSON.stringify(denial).includes('synthetic-cross-tenant-audit-secret'), false);
  assert.equal(JSON.stringify(denial).includes('synthetic-denied-rotation'), false);
  assert.equal(JSON.stringify(denial).includes(account.json.secret), false);

  // Absent and foreign resource IDs must be indistinguishable to the caller and both audited.
  const missingId = operation === 'vault.rotate' ? 'sec_absent_action_audit' : 'sacc_absent_action_audit';
  const missingPath = path.replace(id, missingId);
  const missingAuditFrom = getStore().auditLog.length;
  const missing = await request(baseUrl, 'POST', missingPath, { headers: demoHeaders('admin', 'ten_other', 'usr_cross_tenant'), body: { plaintext: 'synthetic-denied-rotation' } });
  assert.equal(missing.status, result.status);
  assert.deepEqual(missing.json, result.json, 'foreign and absent resource failures must be identical');
  assert.equal(businessSnapshot(), before);
  const missingAudit = getStore().auditLog.slice(missingAuditFrom).find((entry) => /(?:denied|not_found)$/.test(entry.action) && entry.tenant_id === 'ten_other' && entry.actor_user_id === 'usr_cross_tenant' && entry.resource_id === missingId);
  assert.ok(missingAudit, `Missing absent-resource audit for POST ${missingPath}`);
  assert.equal(JSON.stringify(missingAudit).includes('synthetic-denied-rotation'), false);
});
