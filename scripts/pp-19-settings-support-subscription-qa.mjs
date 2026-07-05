#!/usr/bin/env node
/**
 * PP-19 /settings, /support, /subscription page QA — L1 data fidelity, L2 backend actions, L3 browser matrix.
 *
 * APIs: GET/PATCH /v1/tenants/current, GET/POST /v1/secrets, POST /v1/secrets/:id/rotate,
 *       GET /v1/subscription/current, bootstrap/service-account mutations on settings API keys tab.
 *
 * Run with:
 *   PORT=4320 ASTRANULL_NO_PERSIST=1 ASTRANULL_SECRET_ENCRYPTION_KEY=<32-byte-hex> npm start
 */
const BASE_URL = process.env.ASTRANULL_BASE_URL ?? 'http://127.0.0.1:4320';

const HEADERS = {
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

const SETTINGS_TABS = [
  'Organization',
  'Users & roles',
  'API keys',
  'SSO',
  'Data retention',
  'Secret vault',
  'Audit log'
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

async function api(method, route, body, headers = HEADERS) {
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

async function injectSession(page, tenantId = 'ten_demo', userId = 'usr_admin') {
  await page.goto(`${BASE_URL}/app`, { waitUntil: 'domcontentloaded', timeout: 45000 });
  await page.evaluate(({ tenantId: nextTenantId, userId: nextUserId }) => {
    sessionStorage.setItem('astranull.portal.session.v1', JSON.stringify({
      mode: 'dev-headers',
      principal: 'customer',
      tenant_id: nextTenantId,
      user_id: nextUserId,
      role: 'admin'
    }));
  }, { tenantId, userId });
}

async function bootstrapTenantWithoutSubscription() {
  const suffix = Date.now();
  const tenantId = `ten_pp19_nosub_${suffix}`;
  const userId = `usr_pp19_nosub_${suffix}`;
  const headers = {
    'x-tenant-id': tenantId,
    'x-user-id': userId,
    'x-role': 'admin',
    'Content-Type': 'application/json'
  };
  const current = await api('GET', '/v1/subscription/current', undefined, headers);
  if (current.status !== 200) throw new Error(`subscription lookup failed (${current.status})`);
  if (current.json?.subscription) throw new Error('fresh tenant expected null subscription');
  return { tenantId, userId, headers };
}

async function snapshotFixture() {
  const [tenant, subscription, secrets, state] = await Promise.all([
    api('GET', '/v1/tenants/current'),
    api('GET', '/v1/subscription/current'),
    api('GET', '/v1/secrets'),
    api('GET', '/v1/state')
  ]);
  return {
    tenant,
    subscription,
    secrets,
    state,
    tenantName: tenant.json?.name ?? '',
    metadataRetention: tenant.json?.privacy_settings?.metadata_retention_days ?? 90,
    secretCount: secrets.json?.items?.length ?? 0,
    planName: subscription.json?.plan?.name ?? '',
    supportOwner: subscription.json?.support?.owner ?? subscription.json?.account?.support_owner ?? '',
    safeRunsLimit: subscription.json?.subscription?.limits?.safe_runs_per_hour ?? -1,
    openFindings: subscription.json?.usage?.open_findings ?? 0,
    pendingHighScale: subscription.json?.usage?.pending_high_scale_requests ?? 0,
    highScaleEnabled: subscription.json?.subscription?.effective_entitlements?.high_scale_program === true,
    killSwitchActive: Boolean(state.json?.kill_switch?.active ?? state.json?.kill_switch?.enabled)
  };
}

async function runL1() {
  const fixture = await snapshotFixture();

  if (fixture.tenant.status !== 200) fail('l1', `GET /v1/tenants/current failed (${fixture.tenant.status})`);
  if (fixture.subscription.status !== 200) fail('l1', `GET /v1/subscription/current failed (${fixture.subscription.status})`);
  if (fixture.secrets.status !== 200) fail('l1', `GET /v1/secrets failed (${fixture.secrets.status})`);

  if (!fixture.tenantName) fail('l1', 'tenant name missing');
  else note('l1', `tenant.name=${fixture.tenantName}`);

  note('l1', `metadata_retention_days=${fixture.metadataRetention}`);
  note('l1', `secrets.count=${fixture.secretCount}`);

  if (!fixture.subscription.json?.subscription) fail('l1', 'ten_demo missing seeded subscription');
  if (fixture.planName !== 'Professional') fail('l1', `plan.name expected Professional got ${fixture.planName}`);
  else note('l1', `plan.name=${fixture.planName}`);

  const subStatus = fixture.subscription.json?.subscription?.status ?? '';
  if (subStatus !== 'active') fail('l1', `subscription.status expected active got ${subStatus}`);
  else note('l1', `subscription.status=${subStatus}`);

  if (!fixture.supportOwner) fail('l1', 'support owner missing');
  else note('l1', `support.owner=${fixture.supportOwner}`);

  if (typeof fixture.safeRunsLimit !== 'number') fail('l1', 'safe_runs_per_hour missing');
  else note('l1', `limits.safe_runs_per_hour=${fixture.safeRunsLimit}`);

  note('l1', `usage.open_findings=${fixture.openFindings}`);
  note('l1', `usage.pending_high_scale_requests=${fixture.pendingHighScale}`);
  note('l1', `high_scale_program=${fixture.highScaleEnabled ? 'enabled' : 'disabled'}`);
  note('l1', `kill_switch=${fixture.killSwitchActive ? 'active' : 'inactive'}`);

  return fixture;
}

async function runL2() {
  const tenant = await api('GET', '/v1/tenants/current');
  const originalName = tenant.json?.name ?? 'Demo';
  const suffix = Date.now();
  const testOrgName = `PP19 Org ${suffix}`;
  const secretPlaintext = `pp19-secret-${suffix}`;
  const secretName = `pp19-vault-${suffix}`;

  const patchOrg = await api('PATCH', '/v1/tenants/current', { name: testOrgName });
  if (patchOrg.status !== 200 || patchOrg.json?.name !== testOrgName) {
    fail('l2', `PATCH /v1/tenants/current organization failed (${patchOrg.status})`);
  } else {
    note('l2', 'organization patch ok');
  }

  const patchRetention = await api('PATCH', '/v1/tenants/current', {
    privacy_settings: {
      metadata_retention_days: 120,
      evidence_retention: {
        report_days: 400,
        audit_log_days: 2555,
        high_scale_artifact_days: 2555,
        legal_hold: false
      }
    }
  });
  if (patchRetention.status !== 200) {
    fail('l2', `PATCH retention failed (${patchRetention.status})`);
  } else {
    note('l2', 'retention patch ok');
  }

  const createSecret = await api('POST', '/v1/secrets', {
    purpose: 'integration_credential',
    name: secretName,
    plaintext: secretPlaintext,
    metadata: { source: 'pp19_qa' }
  });
  if (createSecret.status === 503 && createSecret.json?.error === 'encryption_not_configured') {
    fail('l2', 'POST /v1/secrets blocked: ASTRANULL_SECRET_ENCRYPTION_KEY not configured on server');
  } else if (createSecret.status !== 201 || !createSecret.json?.secret?.id) {
    fail('l2', `POST /v1/secrets failed (${createSecret.status})`);
  } else {
    note('l2', `secret created ${createSecret.json.secret.id}`);
    const secretId = createSecret.json.secret.id;
    const listed = await api('GET', '/v1/secrets');
    const found = (listed.json?.items ?? []).find((item) => item.id === secretId);
    if (!found) fail('l2', 'created secret missing from GET /v1/secrets');
    else if (JSON.stringify(found).includes(secretPlaintext)) fail('l2', 'secret list leaked plaintext');
    else note('l2', 'secret list redacted');

    const rotated = await api('POST', `/v1/secrets/${secretId}/rotate`, { plaintext: `pp19-rotated-${suffix}` });
    if (rotated.status !== 200) fail('l2', `POST /v1/secrets/:id/rotate failed (${rotated.status})`);
    else note('l2', 'secret rotate ok');
  }

  const bootstrap = await api('POST', '/v1/bootstrap-tokens', {
    name: `pp19-bootstrap-${suffix}`,
    environment_id: 'env_demo',
    max_registrations: 1
  });
  if (bootstrap.status !== 201 || !bootstrap.json?.id) {
    fail('l2', `POST /v1/bootstrap-tokens failed (${bootstrap.status})`);
  } else {
    note('l2', `bootstrap token created ${bootstrap.json.id}`);
    const revoke = await api('POST', `/v1/bootstrap-tokens/${bootstrap.json.id}/revoke`, {});
    if (revoke.status !== 200) fail('l2', `bootstrap revoke failed (${revoke.status})`);
    else note('l2', 'bootstrap revoke ok');
  }

  const serviceAccount = await api('POST', '/v1/service-accounts', {
    name: `pp19-svc-${suffix}`,
    role: 'viewer',
    scopes: ['tenant:read']
  });
  if (serviceAccount.status !== 201 || !serviceAccount.json?.id) {
    fail('l2', `POST /v1/service-accounts failed (${serviceAccount.status})`);
  } else {
    note('l2', `service account created ${serviceAccount.json.id}`);
    const rotateSvc = await api('POST', `/v1/service-accounts/${serviceAccount.json.id}/rotate`, {});
    if (rotateSvc.status !== 200) fail('l2', `service account rotate failed (${rotateSvc.status})`);
    else note('l2', 'service account rotate ok');
    const revokeSvc = await api('POST', `/v1/service-accounts/${serviceAccount.json.id}/revoke`, {});
    if (revokeSvc.status !== 200) fail('l2', `service account revoke failed (${revokeSvc.status})`);
    else note('l2', 'service account revoke ok');
  }

  await api('PATCH', '/v1/tenants/current', {
    name: originalName,
    privacy_settings: {
      metadata_retention_days: 90,
      evidence_retention: {
        report_days: 365,
        audit_log_days: 2555,
        high_scale_artifact_days: 2555,
        legal_hold: false
      }
    }
  });
}

async function openRoute(page, route) {
  await page.goto(`${BASE_URL}/app#${route}`, { waitUntil: 'domcontentloaded', timeout: 45000 });
  await page.waitForTimeout(1200);
}

async function runL3(noSubTenant) {
  const fixture = await snapshotFixture();
  const { chromium } = await import('playwright-core');
  let browser;
  try {
    browser = await chromium.launch({ headless: true, channel: 'chrome' });
  } catch {
    browser = await chromium.launch({ headless: true });
  }

  for (const viewport of VIEWPORTS) {
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    const consoleErrors = [];
    const pageErrors = [];
    page.on('console', (msg) => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });
    page.on('pageerror', (err) => pageErrors.push(String(err)));

    try {
      await injectSession(page);
      await openRoute(page, 'settings');
      let bodyText = await page.locator('body').innerText();

      for (const tab of SETTINGS_TABS) {
        if (!(await page.getByRole('tab', { name: tab }).count())) {
          fail('l3', `${viewport.name}:settings missing tab ${tab}`);
        }
      }

      if (!bodyIncludesSnippet(bodyText, fixture.tenantName)) {
        fail('l1', `${viewport.name}:settings organization metric missing tenant name`);
      }
      if (!bodyIncludesSnippet(bodyText, `${fixture.metadataRetention}d`)) {
        fail('l1', `${viewport.name}:settings metadata retention metric mismatch (expected ${fixture.metadataRetention}d)`);
      }
      if (!bodyIncludesSnippet(bodyText, 'Organization profile')) {
        fail('l3', `${viewport.name}:settings missing Organization profile`);
      }

      if (viewport.name === 'desktop') {
        await page.getByRole('tab', { name: 'Secret vault' }).click();
        await page.waitForTimeout(400);
        bodyText = await page.locator('body').innerText();
        if (!bodyIncludesSnippet(bodyText, String(fixture.secretCount))) {
          fail('l1', `${viewport.name}:settings secret vault count mismatch (expected ${fixture.secretCount})`);
        }
      }

      await openRoute(page, 'support');
      bodyText = await page.locator('body').innerText();
      if (!bodyIncludesSnippet(bodyText, fixture.supportOwner)) {
        fail('l1', `${viewport.name}:support owner mismatch (expected ${fixture.supportOwner})`);
      }
      if (!bodyIncludesSnippet(bodyText, String(fixture.openFindings))) {
        fail('l1', `${viewport.name}:support open findings mismatch (expected ${fixture.openFindings})`);
      }
      if (!bodyIncludesSnippet(bodyText, 'Support readiness')) {
        fail('l3', `${viewport.name}:support missing Support readiness panel`);
      }

      await openRoute(page, 'subscription');
      bodyText = await page.locator('body').innerText();
      if (!bodyIncludesSnippet(bodyText, fixture.planName)) {
        fail('l1', `${viewport.name}:subscription plan mismatch (expected ${fixture.planName})`);
      }
      if (!bodyIncludesSnippet(bodyText, String(fixture.safeRunsLimit))) {
        fail('l1', `${viewport.name}:subscription safe-run cap mismatch (expected ${fixture.safeRunsLimit})`);
      }
      if (!bodyIncludesSnippet(bodyText, fixture.highScaleEnabled ? 'Enabled' : 'Disabled')) {
        fail('l1', `${viewport.name}:subscription high-scale entitlement mismatch`);
      }
      if (!bodyIncludesSnippet(bodyText, 'Entitlement breakdown')) {
        fail('l3', `${viewport.name}:subscription missing Entitlement breakdown`);
      }

      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
      if (overflow) fail('l3', `${viewport.name}: horizontal overflow`);
      if (consoleErrors.length) fail('l3', `${viewport.name}: console errors ${consoleErrors.join('; ')}`);
      if (pageErrors.length) fail('l3', `${viewport.name}: page errors ${pageErrors.join('; ')}`);
      note('l3', `${viewport.name}: settings/support/subscription render ok`);
    } catch (error) {
      fail('l3', `${viewport.name}: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      await context.close();
    }
  }

  for (const viewport of [VIEWPORTS[0], VIEWPORTS[2]]) {
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    try {
      await injectSession(page, noSubTenant.tenantId, noSubTenant.userId);
      await page.reload({ waitUntil: 'domcontentloaded', timeout: 45000 });
      await openRoute(page, 'subscription');
      const bodyText = await page.locator('body').innerText();
      if (!bodyIncludesSnippet(bodyText, 'No subscription configured')) {
        fail('l3', `${viewport.name}:subscription-empty missing empty state`);
      }
      if (bodyIncludesSnippet(bodyText, 'Professional')) {
        fail('l3', `${viewport.name}:subscription-empty leaked seeded plan name`);
      }
      note('l3', `${viewport.name}:subscription empty state ok`);
    } catch (error) {
      fail('l3', `${viewport.name}:subscription-empty ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      await context.close();
    }
  }

  await browser.close();
}

async function main() {
  await runL1();
  const noSubTenant = await bootstrapTenantWithoutSubscription();
  await runL2();
  await runL3(noSubTenant);

  const verdict = results.l1.pass && results.l2.pass && results.l3.pass ? 'PASS' : 'FAIL';
  console.log('PAGE QA PP-19');
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