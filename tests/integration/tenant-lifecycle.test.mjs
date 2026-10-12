import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { resetSignupRateLimitsForTests } from '../../src/services/signupIntake.mjs';
import { closeServer, demoHeaders, request, staffHeaders } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

let server;
let baseUrl;

async function bootIsolatedServer() {
  freshStore();
  resetSignupRateLimitsForTests();
  // This in-memory fixture uses real dev-header staff/customer authorization, not
  // inherited deployment settings. Probe execution stays simulated; high-scale is disabled.
  const env = {
    NODE_ENV: 'test',
    ASTRANULL_NO_PERSIST: '1',
    ASTRANULL_AUTH_MODE: 'dev-headers',
    ASTRANULL_PERSISTENCE_MODE: 'dev-json',
    ASTRANULL_PROBE_MODE: 'simulation',
    ASTRANULL_HIGH_SCALE_ADAPTER_MODE: 'disabled',
    ASTRANULL_PUBLIC_SIGNUP_ENABLED: '1',
    ASTRANULL_RATE_LIMIT_DISABLED: '0',
    ASTRANULL_RATE_LIMIT_WINDOW_MS: '60000',
    ASTRANULL_RATE_LIMIT_MAX_REQUESTS: '600',
  };
  server = createServer({ env });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
}

before(bootIsolatedServer);

after(async () => closeServer(server));

describe('tenant lifecycle (FT-CRUD-TEN-01)', () => {
  it('signup request → approve → provisioned → suspend → reactivate', { timeout: 60_000 }, async () => {
    const submitted = await request(baseUrl, 'POST', '/v1/signup-requests', {
      body: {
        organization_name: 'Lifecycle Tenant Co',
        contact_email: 'owner@lifecycle-tenant.example',
        contact_name: 'Owner',
        requested_plan: 'starter',
        intended_use: 'evaluation',
        region: 'us',
      },
    });
    assert.equal(submitted.status, 201, submitted.text);
    assert.equal(submitted.json.request.state, 'submitted');
    const requestId = submitted.json.request.id;

    const publicStatus = await request(baseUrl, 'GET', `/v1/signup-requests/${requestId}`);
    assert.equal(publicStatus.status, 200, publicStatus.text);
    assert.equal(publicStatus.json.request.id, requestId);
    assert.equal(publicStatus.json.request.state, 'submitted');

    for (const headers of [{}, demoHeaders('admin')]) {
      const denied = await request(baseUrl, 'POST', `/internal/admin/signup-requests/${requestId}/approve`, {
        headers,
        body: { reason: 'Unauthorized approval', provision: true },
      });
      assert.equal(denied.status, 403, denied.text);
      assert.equal(denied.json.error, 'staff_forbidden');
    }
    assert.equal(getStore().signupRequests.find((entry) => entry.id === requestId).state, 'submitted');

    const approved = await request(baseUrl, 'POST', `/internal/admin/signup-requests/${requestId}/approve`, {
      headers: staffHeaders('internal_admin'),
      body: { reason: 'Verified organization', provision: true },
    });
    assert.equal(approved.status, 200);
    assert.equal(approved.json.request.state, 'customer_invited');
    const tenantId = approved.json.provisioning.tenant_id;
    const environmentId = approved.json.provisioning.environment_id;
    assert.ok(tenantId);

    const store = getStore();
    assert.ok(store.tenants.some((tenant) => tenant.id === tenantId));
    assert.ok(store.internalAuditLog.some((entry) => entry.action === 'signup.request_approved'));

    const targetGroup = await request(baseUrl, 'POST', '/v1/target-groups', {
      headers: demoHeaders('admin', tenantId),
      body: { name: 'Provisioned scope', environment_id: environmentId },
    });
    assert.equal(targetGroup.status, 201);
    const groupId = targetGroup.json.id;

    const target = await request(baseUrl, 'POST', `/v1/target-groups/${groupId}/targets`, {
      headers: demoHeaders('admin', tenantId),
      body: { kind: 'fqdn', value: 'provisioned.lifecycle.example' },
    });
    assert.equal(target.status, 201);

    const suspended = await request(baseUrl, 'PATCH', `/internal/admin/tenants/${tenantId}`, {
      headers: staffHeaders('internal_admin'),
      body: { lifecycle_state: 'suspended', reason: 'policy hold' },
    });
    assert.equal(suspended.status, 200);
    assert.equal(suspended.json.account.lifecycle_state, 'suspended');

    const blockedRun = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: demoHeaders('admin', tenantId),
      body: {
        target_group_id: groupId,
        target_id: target.json.id,
        check_id: 'dns.authoritative_response.safe',
      },
    });
    assert.equal(blockedRun.status, 403);
    assert.equal(blockedRun.json.error, 'tenant_suspended');

    const reactivated = await request(baseUrl, 'PATCH', `/internal/admin/tenants/${tenantId}`, {
      headers: staffHeaders('internal_admin'),
      body: { lifecycle_state: 'active', reason: 'hold cleared' },
    });
    assert.equal(reactivated.status, 200);
    assert.equal(reactivated.json.account.lifecycle_state, 'active');
  });
});