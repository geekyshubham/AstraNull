import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { demoHeaders, request, staffHeaders } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';
import { resetSignupRateLimitsForTests } from '../../src/services/signupIntake.mjs';

let baseUrl;
let server;

const signupPayload = () => ({
  organization_name: 'Northwind Defense',
  contact_email: 'security@northwind.example',
  contact_name: 'Alex Morgan',
  requested_plan: 'professional',
  intended_use: 'Defensive DDoS readiness validation for declared production origins.',
  region: 'us',
  high_scale_interest: true,
});

before(() => {
  process.env.ASTRANULL_NO_PERSIST = '1';
  freshStore();
  resetSignupRateLimitsForTests();
  server = createServer();
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

describe('public landing and internal management APIs', () => {
  it('serves public site config and landing without auth', async () => {
    const landing = await request(baseUrl, 'GET', '/');
    assert.equal(landing.status, 200);
    assert.match(landing.text, /No-access-first/);
    assert.match(landing.text, /Sign up/);
    assert.match(landing.text, /id="root"/);
    assert.match(landing.text, /react-app\.js/);
    assert.doesNotMatch(landing.text, /internal\/admin|staff-login|Internal management sign-in/);

    const appShell = await request(baseUrl, 'GET', '/app');
    assert.equal(appShell.status, 200);
    assert.match(appShell.text, /id="root"/);
    assert.match(appShell.text, /react-app\.js/);

    const config = await request(baseUrl, 'GET', '/v1/public/site-config');
    assert.equal(config.status, 200);
    assert.equal(config.json.product_name, 'AstraNull');
    assert.equal(config.json.customer_portal_path, '/app');
    assert.equal(config.json.staff_login_path, undefined);
    assert.equal(config.json.internal_admin_path, undefined);
    assert.equal(config.json.safety_framing.no_default_cloud_access, true);
    assert.equal(typeof config.json.feature_flags, 'object');
    assert.equal(typeof config.json.feature_flags.waf_posture, 'boolean');
    assert.equal(typeof config.json.feature_flags.external_discovery, 'boolean');

    const loginPage = await request(baseUrl, 'GET', '/login');
    assert.equal(loginPage.status, 200);
    assert.match(loginPage.text, /id="root"/);
    assert.match(loginPage.text, /react-app\.js/);
    assert.doesNotMatch(loginPage.text, /internal\/admin|Internal management sign-in|AstraNull staff/);

    const loginModuleRes = await fetch(`${baseUrl}/react-app.js`);
    assert.equal(loginModuleRes.status, 200);
    assert.match(loginModuleRes.headers.get('content-type') ?? '', /javascript/);

    const portalAuthRes = await fetch(`${baseUrl}/react-app.css`);
    assert.equal(portalAuthRes.status, 200);
    assert.match(portalAuthRes.headers.get('content-type') ?? '', /css/);
  });

  it('accepts public signup requests and exposes public status', async () => {
    const created = await request(baseUrl, 'POST', '/v1/signup-requests', {
      body: signupPayload(),
    });
    assert.equal(created.status, 201);
    assert.equal(created.json.request.state, 'submitted');
    const requestId = created.json.request.id;

    const status = await request(baseUrl, 'GET', `/v1/signup-requests/${requestId}`);
    assert.equal(status.status, 200);
    assert.equal(status.json.request.id, requestId);

    const dup = await request(baseUrl, 'POST', '/v1/signup-requests', {
      body: signupPayload(),
    });
    assert.equal(dup.status, 409);
    assert.equal(dup.json.error, 'duplicate_request');
  });

  it('denies customer principals on internal admin routes', async () => {
    const routes = [
      ['GET', '/internal/admin/overview'],
      ['GET', '/internal/admin/signup-requests'],
      ['GET', '/internal/admin/tenants'],
      ['GET', '/internal/admin/approval-requests'],
      ['GET', '/internal/admin/audit-log'],
      ['POST', '/internal/admin/tenants/ten_demo/entitlements'],
    ];
    for (const [method, route] of routes) {
      const denied = await request(baseUrl, method, route, {
        headers: demoHeaders('admin'),
        body: method === 'POST' ? { feature: 'safe_validation', enabled: true } : undefined,
      });
      assert.equal(denied.status, 403, `${method} ${route}`);
      assert.equal(denied.json.error, 'staff_forbidden', `${method} ${route}`);
    }
  });

  it('allows staff review, provisioning, subscription enforcement, and audit', async () => {
    const created = await request(baseUrl, 'POST', '/v1/signup-requests', {
      body: {
        ...signupPayload(),
        organization_name: 'Contoso Security',
        contact_email: 'ops@contoso.example',
      },
    });
    assert.equal(created.status, 201);
    const requestId = created.json.request.id;

    const queue = await request(baseUrl, 'GET', '/internal/admin/signup-requests', {
      headers: staffHeaders('internal_admin'),
    });
    assert.equal(queue.status, 200);
    assert.ok(queue.json.items.some((item) => item.id === requestId));

    const approved = await request(baseUrl, 'POST', `/internal/admin/signup-requests/${requestId}/approve`, {
      headers: staffHeaders('internal_admin'),
      body: { reason: 'Verified organization' },
    });
    assert.equal(approved.status, 200);
    assert.equal(approved.json.request.state, 'customer_invited');
    const tenantId = approved.json.provisioning.tenant_id;
    assert.ok(tenantId);

    const store = getStore();
    assert.ok(store.tenantSubscriptions.some((s) => s.tenant_id === tenantId));
    assert.ok(store.internalAuditLog.some((a) => a.action === 'signup.request_approved'));

    const currentSubscription = await request(baseUrl, 'GET', '/v1/subscription/current', {
      headers: demoHeaders('admin', tenantId),
    });
    assert.equal(currentSubscription.status, 200);
    assert.equal(currentSubscription.json.tenant_id, tenantId);
    assert.equal(currentSubscription.json.subscription.plan_id, 'professional');
    assert.equal(currentSubscription.json.plan.id, 'professional');
    assert.equal(currentSubscription.json.support.owner, 'staff_admin');
    assert.equal(currentSubscription.json.usage.target_groups, 0);

    const auditLog = await request(baseUrl, 'GET', '/internal/admin/audit-log?limit=50', {
      headers: staffHeaders('internal_admin'),
    });
    assert.equal(auditLog.status, 200);
    assert.ok(
      auditLog.json.items.some(
        (a) => a.action === 'signup.request_approved' && a.resource_id === requestId,
      ),
    );

    const customerAuditDenied = await request(baseUrl, 'GET', '/internal/admin/audit-log', {
      headers: demoHeaders('admin'),
    });
    assert.equal(customerAuditDenied.status, 403);
    assert.equal(customerAuditDenied.json.error, 'staff_forbidden');

    const suspended = await request(baseUrl, 'PATCH', `/internal/admin/tenants/${tenantId}`, {
      headers: staffHeaders('internal_admin'),
      body: { lifecycle_state: 'suspended', reason: 'policy hold' },
    });
    assert.equal(suspended.status, 200);
    assert.equal(suspended.json.account.lifecycle_state, 'suspended');

    const storeAfterSuspend = getStore();
    const supportEntitlementDenied = await request(
      baseUrl,
      'POST',
      `/internal/admin/tenants/${tenantId}/entitlements`,
      {
        headers: staffHeaders('support_engineer', 'staff_support'),
        body: { feature: 'safe_validation', enabled: true, reason: 'support cannot grant' },
      },
    );
    assert.equal(supportEntitlementDenied.status, 403);
    assert.equal(supportEntitlementDenied.json.error, 'forbidden');
    assert.equal(supportEntitlementDenied.json.permission, 'staff:entitlement:write');

    const entitlementGrant = await request(
      baseUrl,
      'POST',
      `/internal/admin/tenants/${tenantId}/entitlements`,
      {
        headers: staffHeaders('internal_admin'),
        body: { feature: 'safe_validation', enabled: true, reason: 'verified plan exception' },
      },
    );
    assert.equal(entitlementGrant.status, 200);
    assert.equal(entitlementGrant.json.tenant_id, tenantId);
    assert.equal(entitlementGrant.json.feature, 'safe_validation');
    assert.ok(
      getStore().internalAuditLog.some(
        (a) => a.action === 'staff.entitlement.granted' && a.tenant_id === tenantId,
      ),
    );

    const approvalId = 'iar_public_boundary_demo';
    storeAfterSuspend.internalApprovalRequests.push({
      id: approvalId,
      tenant_id: tenantId,
      kind: 'subscription_exception',
      state: 'submitted',
      created_at: '2026-07-04T00:00:00.000Z',
      updated_at: '2026-07-04T00:00:00.000Z',
      summary: 'Metadata-only approval request for integration coverage.',
    });
    const approvalQueue = await request(baseUrl, 'GET', '/internal/admin/approval-requests', {
      headers: staffHeaders('internal_admin'),
    });
    assert.equal(approvalQueue.status, 200);
    assert.ok(approvalQueue.json.items.some((item) => item.id === approvalId));

    const supportApprovalDenied = await request(
      baseUrl,
      'POST',
      `/internal/admin/approval-requests/${approvalId}/decision`,
      {
        headers: staffHeaders('support_engineer', 'staff_support'),
        body: { decision: 'approve', reason: 'support cannot approve' },
      },
    );
    assert.equal(supportApprovalDenied.status, 403);
    assert.equal(supportApprovalDenied.json.error, 'forbidden');
    assert.equal(supportApprovalDenied.json.permission, 'staff:approval:decide');

    const approvalDecision = await request(
      baseUrl,
      'POST',
      `/internal/admin/approval-requests/${approvalId}/decision`,
      {
        headers: staffHeaders('internal_admin'),
        body: { decision: 'approve', reason: 'verified approval workflow' },
      },
    );
    assert.equal(approvalDecision.status, 200);
    assert.equal(approvalDecision.json.request.state, 'approved');
    assert.ok(
      getStore().internalAuditLog.some(
        (a) => a.action === 'staff.approval.approved' && a.resource_id === approvalId,
      ),
    );

    const tgId = 'tg_contoso_demo';
    storeAfterSuspend.targetGroups.push({
      id: tgId,
      tenant_id: tenantId,
      environment_id: approved.json.provisioning.environment_id,
      name: 'Origin Group',
      expected_behavior_default: 'must_block_before_origin',
    });
    storeAfterSuspend.targets.push({
      id: 'tgt_contoso_1',
      tenant_id: tenantId,
      target_group_id: tgId,
      kind: 'fqdn',
      value: 'origin.contoso.example',
      expected_behavior: 'must_block_before_origin',
    });

    const blockedRun = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: { ...demoHeaders('engineer'), 'x-tenant-id': tenantId, 'x-user-id': 'usr_owner' },
      body: {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: tgId,
        target_id: 'tgt_contoso_1',
      },
    });
    assert.equal(blockedRun.status, 403);
    assert.equal(blockedRun.json.error, 'tenant_suspended');
  });

  it('enforces subscription safe-run plan caps before starting validation runs', async () => {
    const created = await request(baseUrl, 'POST', '/v1/signup-requests', {
      body: {
        ...signupPayload(),
        organization_name: 'Plan Cap Test Co',
        contact_email: 'limits@plancap.example',
      },
    });
    assert.equal(created.status, 201);
    const requestId = created.json.request.id;

    const approved = await request(baseUrl, 'POST', `/internal/admin/signup-requests/${requestId}/approve`, {
      headers: staffHeaders('internal_admin'),
      body: { reason: 'Verified plan-cap test organization' },
    });
    assert.equal(approved.status, 200);
    const tenantId = approved.json.provisioning.tenant_id;
    const store = getStore();
    const subscription = store.tenantSubscriptions.find((s) => s.tenant_id === tenantId);
    assert.ok(subscription);
    subscription.limits.safe_runs_per_hour = 0;

    const tgId = 'tg_plan_cap_demo';
    store.targetGroups.push({
      id: tgId,
      tenant_id: tenantId,
      environment_id: approved.json.provisioning.environment_id,
      name: 'Plan Cap Origin Group',
      expected_behavior_default: 'must_block_before_origin',
    });
    store.targets.push({
      id: 'tgt_plan_cap_1',
      tenant_id: tenantId,
      target_group_id: tgId,
      kind: 'fqdn',
      value: 'origin.plancap.example',
      expected_behavior: 'must_block_before_origin',
    });

    const blockedRun = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: { ...demoHeaders('engineer'), 'x-tenant-id': tenantId, 'x-user-id': 'usr_owner' },
      body: {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: tgId,
        target_id: 'tgt_plan_cap_1',
      },
    });
    assert.equal(blockedRun.status, 403);
    assert.equal(blockedRun.json.error, 'entitlement_limit_exceeded');
    assert.equal(blockedRun.json.metric, 'safe_runs_per_hour');
    assert.equal(blockedRun.json.limit, 0);
    assert.equal(blockedRun.json.current, 0);
  });

  it('records staff rejection with customer-safe notice', async () => {
    const created = await request(baseUrl, 'POST', '/v1/signup-requests', {
      body: {
        ...signupPayload(),
        organization_name: 'Rejected Co',
        contact_email: 'deny@rejected.example',
      },
    });
    assert.equal(created.status, 201);
    const requestId = created.json.request.id;

    const rejected = await request(baseUrl, 'POST', `/internal/admin/signup-requests/${requestId}/reject`, {
      headers: staffHeaders('internal_admin'),
      body: { reason: 'Could not verify business domain.' },
    });
    assert.equal(rejected.status, 200);
    assert.equal(rejected.json.request.state, 'rejected');
    assert.ok(rejected.json.request.customer_notice);
    assert.ok(getStore().internalAuditLog.some((a) => a.action === 'signup.request_rejected'));
  });

  it('serves internal management shell without customer nav leakage', async () => {
    const page = await request(baseUrl, 'GET', '/internal/admin');
    assert.equal(page.status, 200);
    assert.match(page.text, /id="root"/);
    assert.match(page.text, /react-app\.js/);
    assert.doesNotMatch(page.text, /internal-admin\.js/);
  });
});
