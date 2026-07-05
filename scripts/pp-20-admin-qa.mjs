#!/usr/bin/env node
/**
 * PP-20 /admin + #tenant-detail page QA — L1 data fidelity, L2 staff provisioning flow, L3 browser matrix.
 *
 * Prereq: server on PORT=4320 (e.g. ASTRANULL_NO_PERSIST=1 npm start)
 */
const BASE_URL = process.env.ASTRANULL_BASE_URL ?? 'http://127.0.0.1:4320';

const STAFF_HEADERS = {
  'x-principal-type': 'staff',
  'x-staff-id': 'staff_admin',
  'x-staff-role': 'internal_admin',
  'Content-Type': 'application/json'
};

const CUSTOMER_HEADERS = {
  'x-tenant-id': 'ten_demo',
  'x-user-id': 'usr_admin',
  'x-role': 'admin',
  'Content-Type': 'application/json'
};

const VIEWPORTS = [
  { name: 'desktop', width: 1440, height: 1000 },
  { name: 'tablet', width: 820, height: 1180 },
  { name: 'mobile', width: 390, height: 844 }
];

const results = {
  l1: { pass: true, notes: [] },
  l2: { pass: true, notes: [] },
  l3: { pass: true, notes: [] },
  failures: []
};

function fail(layer, detail) {
  results[layer].pass = false;
  results.failures.push({ layer, detail });
}

function note(layer, detail) {
  results[layer].notes.push(detail);
}

function bodyIncludesSnippet(bodyText, snippet) {
  return bodyText.toLowerCase().includes(snippet.toLowerCase());
}

function getString(item, keys, fallback = '') {
  if (!item || typeof item !== 'object') return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

async function api(method, route, body, headers = STAFF_HEADERS) {
  const res = await fetch(`${BASE_URL}${route}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }
  return { status: res.status, json, text };
}

async function fetchStaffFixture() {
  const [overview, signups, tenants, approvals, audit] = await Promise.all([
    api('GET', '/internal/admin/overview'),
    api('GET', '/internal/admin/signup-requests'),
    api('GET', '/internal/admin/tenants'),
    api('GET', '/internal/admin/approval-requests'),
    api('GET', '/internal/admin/audit-log?limit=20')
  ]);
  return { overview, signups, tenants, approvals, audit };
}

async function runL1() {
  const fixture = await fetchStaffFixture();
  const { overview, signups, tenants, approvals, audit } = fixture;

  if (overview.status !== 200) fail('l1', `GET /internal/admin/overview failed (${overview.status})`);
  if (signups.status !== 200) fail('l1', `GET /internal/admin/signup-requests failed (${signups.status})`);
  if (tenants.status !== 200) fail('l1', `GET /internal/admin/tenants failed (${tenants.status})`);
  if (approvals.status !== 200) fail('l1', `GET /internal/admin/approval-requests failed (${approvals.status})`);
  if (audit.status !== 200) fail('l1', `GET /internal/admin/audit-log failed (${audit.status})`);

  const signupItems = signups.json?.items ?? [];
  const tenantItems = tenants.json?.items ?? [];
  const approvalItems = approvals.json?.items ?? [];
  const auditItems = audit.json?.items ?? [];

  const queueDepth = Number(overview.json?.pending_signups ?? 0) + Number(overview.json?.pending_approval_requests ?? 0);
  const tenantCount = Number(overview.json?.tenant_count ?? tenantItems.length);
  const highScaleReviews = Number(overview.json?.high_scale_reviews ?? 0);

  note('l1', `queue_depth=${queueDepth}`);
  note('l1', `tenant_count=${tenantCount}`);
  note('l1', `high_scale_reviews=${highScaleReviews}`);
  note('l1', `signup_items=${signupItems.length}`);
  note('l1', `tenant_items=${tenantItems.length}`);

  for (const signup of signupItems) {
    if (!signup.id) fail('l1', 'signup request missing id');
    if (!signup.organization_name) fail('l1', `signup ${signup.id} missing organization_name`);
    if (!signup.state) fail('l1', `signup ${signup.id} missing state`);
  }

  for (const tenant of tenantItems) {
    const tenantId = getString(tenant, ['tenant_id', 'id']);
    if (!tenantId) fail('l1', 'tenant missing tenant_id');
    if (!tenant.lifecycle_state) fail('l1', `tenant ${tenantId} missing lifecycle_state`);
  }

  const customerDenied = await api('GET', '/internal/admin/overview', undefined, CUSTOMER_HEADERS);
  if (customerDenied.status !== 403 || customerDenied.json?.error !== 'staff_forbidden') {
    fail('l1', `customer principal should be denied on staff overview (got ${customerDenied.status})`);
  } else {
    note('l1', 'customer denied on staff overview');
  }

  return {
    fixture,
    queueDepth,
    tenantCount,
    highScaleReviews,
    signupItems,
    tenantItems,
    approvalItems,
    auditItems
  };
}

async function createSignupRequest(suffix = Date.now()) {
  const signup = await api('POST', '/v1/signup-requests', {
    organization_name: `PP-20 Staff Provision Org ${suffix}`,
    contact_email: `pp20-staff-${suffix}@e2e-${suffix}.astranull.local`,
    contact_name: 'PP-20 Staff Provision Contact',
    requested_plan: 'starter',
    intended_use: 'PP-20 staff provisioning QA validation.',
    region: 'us',
    high_scale_interest: false
  }, { 'Content-Type': 'application/json' });
  if (signup.status !== 201 || !signup.json?.request?.id) {
    fail('l2', `POST /v1/signup-requests failed (${signup.status})`);
    return null;
  }
  return {
    suffix,
    signupRequestId: signup.json.request.id,
    organizationName: `PP-20 Staff Provision Org ${suffix}`
  };
}

async function resolveProvisionedTenantId(organizationName, signupRequestId = '') {
  if (signupRequestId) {
    const signupStatus = await api('GET', '/internal/admin/signup-requests');
    if (signupStatus.status === 200 && Array.isArray(signupStatus.json?.items)) {
      const request = signupStatus.json.items.find((item) => item.id === signupRequestId);
      const tenantFromRequest = request?.provisioned_tenant_id ?? '';
      if (tenantFromRequest) return tenantFromRequest;
    }
  }

  const tenants = await api('GET', `/internal/admin/tenants?q=${encodeURIComponent(organizationName)}`);
  if (tenants.status !== 200 || !Array.isArray(tenants.json?.items)) {
    fail('l2', `tenant directory lookup failed (${tenants.status})`);
    return '';
  }
  const match = tenants.json.items.find((item) => {
    const name = String(item.name ?? item.legal_name ?? '').toLowerCase();
    return name.includes(organizationName.toLowerCase());
  });
  return getString(match, ['tenant_id', 'id'], '');
}

async function validateProvisionedTenant(tenantId, feature = 'waf_posture') {
  const headers = {
    'x-tenant-id': tenantId,
    'x-user-id': `usr_pp20_${tenantId}`,
    'x-role': 'admin',
    'Content-Type': 'application/json'
  };
  const subscription = await api('GET', '/v1/subscription/current', undefined, headers);
  if (subscription.status !== 200) {
    fail('l2', `provisioned tenant subscription lookup failed (${subscription.status})`);
    return null;
  }
  if (!subscription.json?.subscription) {
    fail('l2', 'provisioned tenant expected subscription record after staff approval');
    return null;
  }
  const enabled = subscription.json?.effective_entitlements?.[feature]
    ?? subscription.json?.subscription?.effective_entitlements?.[feature];
  return { subscription: subscription.json, enabled };
}

async function runL2() {
  const signup = await createSignupRequest();
  if (!signup) return null;

  const queueBefore = await api('GET', '/internal/admin/signup-requests');
  const pendingBefore = (queueBefore.json?.items ?? []).filter((item) =>
    ['submitted', 'under_review'].includes(getString(item, ['state']))
  ).length;
  note('l2', `pending_signups_before=${pendingBefore}`);

  const approved = await api(
    'POST',
    `/internal/admin/signup-requests/${encodeURIComponent(signup.signupRequestId)}/approve`,
    { reason: 'PP-20 staff provisioning QA approval.' }
  );
  if (approved.status !== 200 || !approved.json?.provisioning?.tenant_id) {
    fail('l2', `signup approve failed (${approved.status})`);
    return null;
  }
  const tenantId = approved.json.provisioning.tenant_id;
  note('l2', `approved tenant ${tenantId}`);

  const detail = await api('GET', `/internal/admin/tenants/${encodeURIComponent(tenantId)}`);
  if (detail.status !== 200) {
    fail('l2', `GET /internal/admin/tenants/:id failed (${detail.status})`);
  } else {
    const lifecycle = getString(detail.json?.account, ['lifecycle_state'], getString(detail.json, ['lifecycle_state']));
    if (lifecycle !== 'active') fail('l2', `expected active lifecycle got ${lifecycle}`);
    else note('l2', 'tenant detail lifecycle active');
  }

  const subscription = await api('GET', `/internal/admin/tenants/${encodeURIComponent(tenantId)}/subscription`);
  if (subscription.status !== 200) {
    fail('l2', `GET tenant subscription failed (${subscription.status})`);
  } else {
    note('l2', `plan=${subscription.json?.plan_id ?? subscription.json?.subscription?.plan_id ?? 'unknown'}`);
  }

  const suspended = await api('PATCH', `/internal/admin/tenants/${encodeURIComponent(tenantId)}`, {
    lifecycle_state: 'suspended',
    reason: 'PP-20 suspend validation'
  });
  if (suspended.status !== 200 || getString(suspended.json?.account, ['lifecycle_state']) !== 'suspended') {
    fail('l2', `tenant suspend failed (${suspended.status})`);
  } else {
    note('l2', 'tenant suspended');
  }

  const reactivated = await api('PATCH', `/internal/admin/tenants/${encodeURIComponent(tenantId)}`, {
    lifecycle_state: 'active',
    reason: 'PP-20 reactivate validation'
  });
  if (reactivated.status !== 200 || getString(reactivated.json?.account, ['lifecycle_state']) !== 'active') {
    fail('l2', `tenant reactivate failed (${reactivated.status})`);
  } else {
    note('l2', 'tenant reactivated');
  }

  const supportPatch = await api('PATCH', `/internal/admin/tenants/${encodeURIComponent(tenantId)}`, {
    support_owner: 'pp20-support@astranull.local',
    reason: 'PP-20 support owner assignment'
  });
  if (supportPatch.status !== 200) {
    fail('l2', `support owner patch failed (${supportPatch.status})`);
  } else {
    note('l2', 'support owner assigned');
  }

  const entitlement = await api('POST', `/internal/admin/tenants/${encodeURIComponent(tenantId)}/entitlements`, {
    feature: 'waf_posture',
    enabled: true,
    reason: 'PP-20 entitlement grant validation'
  });
  if (entitlement.status !== 200) {
    fail('l2', `entitlement grant failed (${entitlement.status})`);
  } else {
    note('l2', 'waf_posture entitlement granted');
  }

  const customerSub = await validateProvisionedTenant(tenantId, 'waf_posture');
  if (customerSub && customerSub.enabled !== true) {
    fail('l2', 'customer subscription missing waf_posture entitlement after staff grant');
  } else if (customerSub) {
    note('l2', 'customer subscription reflects entitlement');
  }

  const audit = await api('GET', '/internal/admin/audit-log?limit=50');
  const auditActions = (audit.json?.items ?? []).map((item) => item.action);
  for (const expected of ['signup.request_approved', 'staff.entitlement.granted']) {
    if (!auditActions.includes(expected)) {
      fail('l2', `internal audit missing action ${expected}`);
    }
  }
  if (auditActions.includes('signup.request_approved') && auditActions.includes('staff.entitlement.granted')) {
    note('l2', 'audit records provisioning actions');
  }

  const supportDenied = await api(
    'POST',
    `/internal/admin/tenants/${encodeURIComponent(tenantId)}/entitlements`,
    { feature: 'waf_posture', enabled: true, reason: 'support cannot grant' },
    {
      'x-principal-type': 'staff',
      'x-staff-id': 'staff_support',
      'x-staff-role': 'support_engineer',
      'Content-Type': 'application/json'
    }
  );
  if (supportDenied.status !== 403) {
    fail('l2', `support_engineer entitlement grant should be denied (got ${supportDenied.status})`);
  } else {
    note('l2', 'support_engineer RBAC denied on entitlements');
  }

  return {
    signup,
    tenantId,
    organizationName: signup.organizationName
  };
}

async function ensurePlaywright() {
  return import('playwright-core');
}

async function injectStaffSession(page) {
  await page.evaluate(() => {
    sessionStorage.setItem('astranull.portal.session.v1', JSON.stringify({
      mode: 'dev-headers',
      principal: 'staff',
      staff_id: 'staff_admin',
      staff_role: 'internal_admin',
      role: 'internal_admin'
    }));
  });
}

async function runL3(l1Fixture, l2Fixture) {
  const { chromium } = await ensurePlaywright();
  let browser;
  try {
    browser = await chromium.launch({ headless: true, channel: 'chrome' });
  } catch {
    browser = await chromium.launch({ headless: true });
  }

  const { queueDepth, tenantCount, highScaleReviews } = l1Fixture;
  const provisionedTenantId = l2Fixture?.tenantId ?? '';
  const organizationName = l2Fixture?.organizationName ?? '';

  for (const viewport of VIEWPORTS) {
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    const consoleErrors = [];
    const pageErrors = [];
    page.on('console', (msg) => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });
    page.on('pageerror', (err) => pageErrors.push(String(err)));

    try {
      await page.goto(`${BASE_URL}/internal/admin`, { waitUntil: 'domcontentloaded', timeout: 45000 });
      await injectStaffSession(page);
      await page.reload({ waitUntil: 'networkidle', timeout: 45000 });
      await page.goto(`${BASE_URL}/internal/admin#admin`, { waitUntil: 'networkidle', timeout: 45000 });
      await page.waitForTimeout(1000);

      let bodyText = await page.locator('body').innerText();
      const requiredAdmin = [
        'Entitlement grants',
        'Tenant directory',
        'Signup queue',
        'Approval requests',
        'Internal audit',
        'Support owner assignment'
      ];
      for (const snippet of requiredAdmin) {
        if (!bodyIncludesSnippet(bodyText, snippet)) {
          fail('l3', `${viewport.name} /admin: missing "${snippet}"`);
        }
      }

      if (!bodyText.includes(String(queueDepth))) {
        fail('l1', `${viewport.name}: review queue metric mismatch (expected ${queueDepth})`);
      }
      if (!bodyText.includes(String(tenantCount))) {
        fail('l1', `${viewport.name}: managed tenants metric mismatch (expected ${tenantCount})`);
      }
      if (!bodyText.includes(String(highScaleReviews))) {
        fail('l1', `${viewport.name}: SOC reviews metric mismatch (expected ${highScaleReviews})`);
      }

      const adminOverflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
      if (adminOverflow) fail('l3', `${viewport.name} /admin: horizontal overflow`);

      if (viewport.name === 'desktop' && organizationName) {
        await page.getByRole('button', { name: 'Refresh' }).click({ timeout: 10000 });
        await page.waitForTimeout(1200);
        bodyText = await page.locator('body').innerText();
        if (!bodyText.includes(organizationName)) {
          fail('l2', `desktop /admin: approved org ${organizationName} not visible in signup queue`);
        } else {
          note('l2', 'desktop signup visible after approve');
        }
      }

      if (provisionedTenantId) {
        await page.goto(`${BASE_URL}/internal/admin#tenant-detail?id=${encodeURIComponent(provisionedTenantId)}`, {
          waitUntil: 'networkidle',
          timeout: 45000
        });
        await page.waitForTimeout(1200);
        bodyText = await page.locator('body').innerText();

        const requiredDetail = [
          'Tenant administration',
          'Subscription',
          'Support owner',
          'Staff tenant operations'
        ];
        for (const snippet of requiredDetail) {
          if (!bodyIncludesSnippet(bodyText, snippet)) {
            fail('l3', `${viewport.name} /tenant-detail: missing "${snippet}"`);
          }
        }

        if (!bodyText.includes(provisionedTenantId)) {
          fail('l1', `${viewport.name}: tenant-detail missing id ${provisionedTenantId}`);
        }

        const detailOverflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
        if (detailOverflow) fail('l3', `${viewport.name} /tenant-detail: horizontal overflow`);

        if (viewport.name === 'desktop') {
          await page.getByRole('button', { name: 'Suspend' }).click({ timeout: 10000 });
          await page.waitForTimeout(1200);
          bodyText = await page.locator('body').innerText();
          if (!bodyText.toLowerCase().includes('suspended')) {
            fail('l2', 'desktop tenant-detail suspend did not update lifecycle');
          } else {
            note('l2', 'desktop tenant-detail suspend ok');
          }

          await page.getByRole('button', { name: 'Activate' }).click({ timeout: 10000 });
          await page.waitForTimeout(1200);
          bodyText = await page.locator('body').innerText();
          if (!bodyText.toLowerCase().includes('active')) {
            fail('l2', 'desktop tenant-detail activate did not update lifecycle');
          } else {
            note('l2', 'desktop tenant-detail activate ok');
          }
        }
      }

      const benign = (detail) => /favicon/i.test(detail)
        || (/429/.test(detail) && /signup-requests/i.test(detail));
      const badConsole = consoleErrors.filter((detail) => !benign(detail));
      if (badConsole.length) fail('l3', `${viewport.name}: console errors ${badConsole.join('; ')}`);
      if (pageErrors.length) fail('l3', `${viewport.name}: page errors ${pageErrors.join('; ')}`);

      note('l3', `${viewport.name}: admin + tenant-detail ok`);
    } catch (error) {
      fail('l3', `${viewport.name}: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      await context.close();
    }
  }

  await browser.close();
}

async function main() {
  console.log(`PP-20 QA starting at ${BASE_URL}`);
  const l1Fixture = await runL1();
  const l2Fixture = await runL2();
  await runL3(l1Fixture, l2Fixture);

  const verdict = results.l1.pass && results.l2.pass && results.l3.pass ? 'PASS' : 'FAIL';
  console.log('\nPAGE QA PP-20');
  console.log(`VERDICT: ${verdict}`);
  console.log(`L1: ${results.l1.pass ? 'PASS' : 'FAIL'} — ${results.l1.notes.join('; ')}`);
  console.log(`L2: ${results.l2.pass ? 'PASS' : 'FAIL'} — ${results.l2.notes.join('; ')}`);
  console.log(`L3: ${results.l3.pass ? 'PASS' : 'FAIL'} — ${results.l3.notes.join('; ')}`);
  if (results.failures.length) {
    console.log('FAILURES:');
    for (const failure of results.failures) console.log(`- [${failure.layer}] ${failure.detail}`);
  }
  process.exit(verdict === 'PASS' ? 0 : 1);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});