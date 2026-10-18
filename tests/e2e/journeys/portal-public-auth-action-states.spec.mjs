import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { assertPublicPortalAction, buildPublicPortalActionCoverage, PUBLIC_OBSERVATIONS as O } from '../../helpers/portal-public-action-coverage.mjs';
import {
  createPortalSourceServer,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import { collectPortalBrowserFailures } from '../../helpers/portal-browser-failures.mjs';
import { installPortalBrowserResources } from '../../helpers/portal-browser-resources.mjs';

const SYNTHETIC_EMAIL = 'analyst@example.test';
const SYNTHETIC_PASSWORD = 'Harbor-lantern-42';
const SESSION_KEY = 'astranull.portal.session.v1';

let baseUrl = '';
let sourceServer;
let sourceCache;
let coverage;

test.describe.configure({ retries: 0 });

test.beforeAll(async () => {
  const api = await startPortalPlaywrightServer();
  sourceCache = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-public-source-'));
  // Exercise current source, with the production no-identity-bootstrap guard. Default
  // Vite development auto-session creation would destroy the visitor precondition.
  sourceServer = await createPortalSourceServer({
    cacheDir: sourceCache,
    define: { 'import.meta.env.DEV': 'false' },
    server: { host: '127.0.0.1', port: 0, strictPort: false, hmr: false, proxy: { '/v1': api.baseUrl, '/ready': api.baseUrl, '/internal': api.baseUrl } },
  });
  await sourceServer.listen();
  baseUrl = `http://127.0.0.1:${sourceServer.httpServer.address().port}`;
  coverage = buildPublicPortalActionCoverage();
});

test.beforeEach(async ({ page }) => {
  await installPortalBrowserResources(page);
  // These are UI/session-boundary tests, not backend authorization proofs. Login
  // responses below are synthetic; explicitly fixture their read-only destination
  // instead of sending a fake JWT to the real dev-header API and asserting only a
  // transient /app URL before its inevitable reauthentication bounce.
  const emptyLists = new Set(['/v1/targets', '/v1/checks', '/v1/test-policies', '/v1/test-runs', '/v1/validation-scans', '/v1/findings', '/v1/evidence', '/v1/high-scale-requests', '/v1/reports', '/v1/audit-log']);
  await page.route('**/v1/**', (route) => {
    if (route.request().method() !== 'GET') return route.fallback();
    const pathname = new URL(route.request().url()).pathname;
    const json = pathname === '/v1/tenants/current' ? { id: 'ten_demo', name: 'Synthetic public-auth fixture' }
      : pathname === '/v1/state' ? { tenant_id: 'ten_demo' }
        : pathname === '/v1/tenant/deployment-features' ? { connectors: false, waf_posture: false, external_discovery: false }
          : pathname === '/v1/analytics/declared-hosts' ? { total: 0, items: [] }
            : pathname === '/v1/subscription/current' ? {}
              : pathname === '/v1/notifications' ? { rules: [], events: [] }
                : emptyLists.has(pathname) ? { items: [] } : null;
    return json ? route.fulfill({ status: 200, json }) : route.fallback();
  });
});

test.afterAll(async () => {
  await sourceServer?.close();
  if (sourceCache) fs.rmSync(sourceCache, { recursive: true, force: true });
  await stopPortalPlaywrightServer();
});

async function proof(testInfo, query, route, state, observations, assertBehavior) {
  return assertPublicPortalAction(testInfo, coverage, query, route, state, async () => {
    await assertBehavior();
    return observations;
  });
}
const customer = (query = {}) => ({ owner: 'CredentialLoginPage', lane: 'password', ...query });
const staff = (query = {}) => ({ owner: 'StaffLoginPage', lane: 'staging', ...query });
const session = (page) => page.evaluate((key) => JSON.parse(sessionStorage.getItem(key) ?? 'null'), SESSION_KEY);
const noSession = async (page) => expect(await session(page)).toBeNull();

const PASSWORD_LANE = {
  product_name: 'AstraNull',
  login_url: '/login',
  signup_enabled: true,
  signup_path: '/signup',
  customer_portal_path: '/app',
  auth_mode: 'oidc-jwt',
  bundled_staging_login_enabled: false,
  password_login_enabled: true,
};

async function discovery(page, { ready, site }) {
  await page.route('**/ready', (route) => route.fulfill(ready));
  await page.route('**/v1/public/site-config', (route) => route.fulfill(site));
}

function recordPosts(page, path) {
  const posts = [];
  page.on('request', (request) => {
    if (request.method() === 'POST' && new URL(request.url()).pathname === path) posts.push(request.postDataJSON());
  });
  return posts;
}

async function storageText(page) {
  return page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }));
}

test.describe('password login challenges', () => {
  test('an empty or partial authenticator code is rejected locally and never burns a verification attempt', async ({ page }, testInfo) => {
    const browser = await collectPortalBrowserFailures(page, baseUrl, {
      allowResponse: (response) => new URL(response.url()).pathname === '/v1/auth/login' && response.status() === 401,
    });
    await discovery(page, { ready: { status: 200, json: { status: 'ready', auth_mode: 'oidc-jwt' } }, site: { status: 200, json: PASSWORD_LANE } });
    const posts = recordPosts(page, '/v1/auth/login');
    await page.route('**/v1/auth/login', (route) => {
      const body = route.request().postDataJSON();
      if (body.totp === '123456') return route.fulfill({ status: 401, json: { error: 'mfa_invalid' } });
      return route.fulfill({ status: 401, json: { error: 'mfa_required' } });
    });

    await page.goto(`${baseUrl}/login`);
    await page.getByLabel('Work email').fill(SYNTHETIC_EMAIL);
    await proof(testInfo, customer({ name: 'login-user-id' }), '/login', 'success', [O.local], async () => {
      await expect(page.getByLabel('Work email')).toHaveValue(SYNTHETIC_EMAIL);
      expect(posts).toHaveLength(0);
      await noSession(page);
    });
    await page.locator('#login-password').fill(SYNTHETIC_PASSWORD);
    await proof(testInfo, customer({ name: 'login-password' }), '/login', 'success', [O.local, O.secrets], async () => {
      await expect(page.locator('#login-password')).toHaveValue(SYNTHETIC_PASSWORD);
      await expect(page.locator('#login-password')).toHaveAttribute('type', 'password');
      expect(posts).toHaveLength(0);
      expect(await storageText(page)).not.toContain(SYNTHETIC_PASSWORD);
    });
    await page.getByRole('button', { name: 'Continue to portal' }).click();
    const code = page.getByLabel('Authenticator code');
    await expect(code).toBeVisible();
    await expect(page.getByRole('status').filter({ hasText: 'Enter the 6-digit code' })).toContainText('Password accepted.');
    await expect(page.getByRole('alert')).toHaveCount(0);
    await expect(code).toBeFocused();
    expect(posts).toHaveLength(1);
    expect(posts[0]).toEqual({ email: SYNTHETIC_EMAIL, password: SYNTHETIC_PASSWORD });

    await page.getByRole('button', { name: 'Verify and continue' }).click();
    await proof(testInfo, customer({ kind: 'form-keyboard' }), '/login', 'invalid', [O.invalid], async () => {
      await expect(code).toHaveAttribute('aria-invalid', 'true');
      await expect(code).toBeFocused();
      expect(posts).toHaveLength(1);
    });
    await proof(testInfo, customer({ name: 'login-totp' }), '/login', 'empty', [O.invalid], async () => {
      await expect(code).toHaveValue('');
      await expect(code).toHaveAttribute('aria-invalid', 'true');
      expect(posts).toHaveLength(1);
    });

    await code.fill('123');
    await code.press('Enter');
    await proof(testInfo, customer({ name: 'login-totp' }), '/login', 'invalid', [O.invalid], async () => {
      await expect(code).toHaveValue('123');
      await expect(code).toHaveAttribute('aria-invalid', 'true');
      expect(posts).toHaveLength(1);
    });

    await code.fill('123456');
    await code.press('Enter');
    await expect(page.getByRole('alert')).toContainText('That authenticator code could not be verified.');
    expect(posts).toHaveLength(2);
    expect(posts[1]).toEqual({ email: SYNTHETIC_EMAIL, password: SYNTHETIC_PASSWORD, totp: '123456' });
    expect(await storageText(page)).not.toContain(SYNTHETIC_PASSWORD);
    expect(await storageText(page)).not.toContain('123456');
    expect(page.url()).not.toContain('123456');
    browser.assertClean();
  });

  test('a required workspace ID is validated locally before resubmitting credentials', async ({ page }, testInfo) => {
    const browser = await collectPortalBrowserFailures(page, baseUrl, {
      allowResponse: (response) => new URL(response.url()).pathname === '/v1/auth/login' && response.status() === 400,
    });
    await discovery(page, { ready: { status: 200, json: { status: 'ready', auth_mode: 'oidc-jwt' } }, site: { status: 200, json: PASSWORD_LANE } });
    const posts = recordPosts(page, '/v1/auth/login');
    await page.route('**/v1/auth/login', (route) => {
      const body = route.request().postDataJSON();
      if (body.tenant_id === 'ten_synthetic') {
        return route.fulfill({ status: 200, json: { access_token: 'synthetic.jwt.value', principal: 'customer', tenant_id: 'ten_synthetic', user_id: 'usr_synthetic', role: 'viewer', expires_in: 600 } });
      }
      return route.fulfill({ status: 400, json: { error: 'tenant_required' } });
    });

    await page.goto(`${baseUrl}/login`);
    await page.getByLabel('Work email').fill(SYNTHETIC_EMAIL);
    await page.locator('#login-password').fill(SYNTHETIC_PASSWORD);
    await page.getByRole('button', { name: 'Continue to portal' }).click();
    const workspace = page.getByLabel('Workspace ID');
    await expect(workspace).toBeVisible();
    await expect(page.getByRole('status').filter({ hasText: 'Choose which workspace to open.' })).toBeVisible();
    await expect(page.getByRole('alert')).toHaveCount(0);
    await expect(workspace).toBeFocused();
    expect(posts).toHaveLength(1);

    await page.getByRole('button', { name: 'Continue to portal' }).click();
    await proof(testInfo, customer({ name: 'login-tenant-scope' }), '/login', 'invalid', [O.invalid], async () => {
      await expect(workspace).toHaveAttribute('aria-invalid', 'true');
      await expect(workspace).toBeFocused();
      expect(posts).toHaveLength(1);
    });

    browser.assertClean();
    await workspace.fill('ten_synthetic');
    await workspace.press('Enter');
    await page.waitForURL((url) => url.pathname.startsWith('/app'));
    expect(posts).toHaveLength(2);
    expect(posts[1]).toEqual({ email: SYNTHETIC_EMAIL, password: SYNTHETIC_PASSWORD, tenant_id: 'ten_synthetic' });
    await proof(testInfo, customer({ kind: 'form-keyboard' }), '/login', 'success', [O.success, O.serverIdentity, O.secrets], async () => {
      await expect(page.locator('#portal-main h1')).toBeVisible();
      await expect(page.locator('#boot')).toHaveCount(0);
      expect(await session(page)).toMatchObject({ principal: 'customer', tenant_id: 'ten_synthetic', role: 'viewer', user_id: 'usr_synthetic' });
      expect(posts).toHaveLength(2);
      expect(posts[1]).toEqual({ email: SYNTHETIC_EMAIL, password: SYNTHETIC_PASSWORD, tenant_id: 'ten_synthetic' });
      expect(await storageText(page)).not.toContain(SYNTHETIC_PASSWORD);
      expect(page.url()).not.toContain(SYNTHETIC_PASSWORD);
      browser.assertClean();
    });
  });

  test('a password that opens several workspaces offers only those workspaces by name', async ({ page }, testInfo) => {
    const browser = await collectPortalBrowserFailures(page, baseUrl, {
      allowResponse: (response) => new URL(response.url()).pathname === '/v1/auth/login' && response.status() === 400,
    });
    await discovery(page, { ready: { status: 200, json: { status: 'ready', auth_mode: 'oidc-jwt' } }, site: { status: 200, json: PASSWORD_LANE } });
    const posts = recordPosts(page, '/v1/auth/login');
    await page.route('**/v1/auth/login', (route) => {
      const body = route.request().postDataJSON();
      if (body.tenant_id === 'ten_beta') {
        return route.fulfill({ status: 200, json: { access_token: 'synthetic.jwt.value', principal: 'customer', tenant_id: 'ten_beta', user_id: 'usr_synthetic', role: 'viewer', expires_in: 600 } });
      }
      return route.fulfill({
        status: 400,
        json: {
          error: 'tenant_required',
          workspaces: [
            { tenant_id: 'ten_alpha', name: 'Synthetic Alpha' },
            { tenant_id: 'ten_beta', name: 'Synthetic Beta' },
          ],
        },
      });
    });

    await page.goto(`${baseUrl}/login`);
    await page.getByLabel('Work email').fill(SYNTHETIC_EMAIL);
    await page.locator('#login-password').fill(SYNTHETIC_PASSWORD);
    await page.getByRole('button', { name: 'Continue to portal' }).click();
    const group = page.getByRole('group', { name: 'Choose a workspace' });
    await expect(group).toBeVisible();
    await expect(group.getByRole('radio')).toHaveCount(2);
    await expect(group).toContainText('ten_alpha');
    await expect(page.getByLabel('Workspace ID')).toHaveCount(0);
    await expect(page.getByRole('alert')).toHaveCount(0);
    await expect(group.getByRole('radio').first()).toBeFocused();

    await page.getByRole('button', { name: 'Continue to portal' }).click();
    await expect(group.getByText('Choose the workspace you want to open.')).toBeVisible();
    expect(posts).toHaveLength(1);

    await group.getByRole('radio', { name: /Synthetic Beta/ }).check();
    await page.getByRole('button', { name: 'Continue to portal' }).click();
    await page.waitForURL((url) => url.pathname.startsWith('/app'));
    expect(posts).toHaveLength(2);
    expect(posts[1]).toEqual({ email: SYNTHETIC_EMAIL, password: SYNTHETIC_PASSWORD, tenant_id: 'ten_beta' });
    browser.assertClean();
  });
});

test.describe('staff sign-in', () => {
  test('unknown authentication mode fails closed: nothing can be submitted', async ({ page }, testInfo) => {
    const browser = await collectPortalBrowserFailures(page, baseUrl, {
      allowResponse: (response) => ['/ready', '/v1/public/site-config'].includes(new URL(response.url()).pathname) && response.status() === 503,
    });
    await discovery(page, { ready: { status: 503, json: { status: 'not_ready' } }, site: { status: 503, json: {} } });
    const posts = recordPosts(page, '/v1/auth/bundled-staging-login');
    await page.goto(`${baseUrl}/internal/admin/login`);
    await expect(page.getByRole('alert')).toContainText('We could not confirm how this deployment signs staff in.');
    await expect(page.getByRole('heading', { level: 1, name: 'Staff sign-in' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible();
    await expect(page.getByLabel('Staff ID')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Continue to internal admin' })).toHaveCount(0);
    expect(posts).toHaveLength(0);
    expect(await page.evaluate((key) => sessionStorage.getItem(key), SESSION_KEY)).toBeNull();
    browser.assertClean();
    await page.unroute('**/ready');
    await page.unroute('**/v1/public/site-config');
    await discovery(page, readyLane({ ...PASSWORD_LANE, password_login_enabled: false, bundled_staging_login_enabled: true }));
    await page.getByRole('button', { name: 'Try again' }).click();
    await proof(testInfo, { owner: 'StaffLoginPage', lane: 'unknown', handler: 'window.location.reload' }, '/internal/admin/login', 'error-retry', [O.discovery], async () => {
      await expect(page.getByLabel('Staff ID')).toBeVisible();
      await expect(page.getByRole('button', { name: 'Continue to internal admin' })).toBeVisible();
      expect(posts).toHaveLength(0);
      await noSession(page);
      browser.assertClean();
    });
  });

  test('a pending bundled staging sign-in cannot be submitted twice from the keyboard and retries explicitly', async ({ page }, testInfo) => {
    const browser = await collectPortalBrowserFailures(page, baseUrl, {
      allowResponse: (response) => new URL(response.url()).pathname === '/v1/auth/bundled-staging-login' && response.status() === 403,
    });
    await discovery(page, {
      ready: { status: 200, json: { status: 'ready', auth_mode: 'oidc-jwt' } },
      site: { status: 200, json: { ...PASSWORD_LANE, password_login_enabled: false, bundled_staging_login_enabled: true } },
    });
    const posts = recordPosts(page, '/v1/auth/bundled-staging-login');
    let release;
    const held = new Promise((resolve) => { release = resolve; });
    await page.route('**/v1/auth/bundled-staging-login', async (route) => {
      await held;
      await route.fulfill({ status: 403, json: { error: 'forbidden' } });
    });
    await page.goto(`${baseUrl}/internal/admin/login`);
    const staffId = page.getByLabel('Staff ID');
    const submit = page.getByRole('button', { name: /Continue to internal admin/ });
    await staffId.fill('stf_synthetic');
    await staffId.press('Enter');
    await expect(submit).toBeDisabled();
    await expect.poll(() => posts.length).toBe(1);
    await staffId.press('Enter');
    await submit.click({ force: true });
    await proof(testInfo, staff({ kind: 'form-keyboard' }), '/internal/admin/login', 'busy', [O.busy], async () => {
      await expect(submit).toBeDisabled();
      await expect(page.locator('form')).toHaveAttribute('aria-busy', 'true');
      expect(posts).toHaveLength(1);
    });
    release();
    await expect(page.getByRole('alert')).toBeVisible();
    await expect(submit).toBeEnabled();
    expect(posts).toHaveLength(1);
    expect(posts[0]).toEqual({ principal: 'staff', staff_id: 'stf_synthetic', staff_role: 'internal_admin' });
    await submit.click();
    await proof(testInfo, staff({ kind: 'form-keyboard' }), '/internal/admin/login', 'error-retry', [O.retry], async () => {
      await expect.poll(() => posts.length).toBe(2);
      await expect(page.getByRole('alert')).toBeVisible();
      await expect(submit).toBeEnabled();
      expect(posts[1]).toEqual(posts[0]);
      await noSession(page);
      browser.assertClean();
    });
    await proof(testInfo, staff({ kind: 'form-keyboard' }), '/internal/admin/login', 'denial', [O.deniedExchange], async () => {
      await expect(page.getByRole('alert')).toBeVisible();
      expect(posts).toHaveLength(2);
      await noSession(page);
    });
  });

  test('the call to action names the SOC console for SOC roles', async ({ page }, testInfo) => {
    const browser = await collectPortalBrowserFailures(page, baseUrl);
    const writes = mutationRequests(page);
    await discovery(page, {
      ready: { status: 200, json: { status: 'ready', auth_mode: 'oidc-jwt' } },
      site: { status: 200, json: { ...PASSWORD_LANE, password_login_enabled: false, bundled_staging_login_enabled: true } },
    });
    await page.goto(`${baseUrl}/internal/admin/login`);
    await expect(page.getByText('Staff only. Customer accounts do not grant access here.')).toBeVisible();
    await expect(page.getByText('Staging only: no password is checked. Production staff sign-in uses your identity provider.')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Continue to internal admin' })).toBeVisible();
    await page.getByRole('button', { name: 'Staging staff role', exact: true }).click();
    await page.getByRole('listbox', { name: 'Staging staff role', exact: true }).getByRole('option', { name: 'SOC analyst', exact: true }).click();
    await proof(testInfo, staff({ kind: 'select' }), '/internal/admin/login', 'success', [O.local], async () => {
      await expect(page.getByRole('button', { name: 'Continue to SOC console' })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Continue to internal admin' })).toHaveCount(0);
      expect(writes).toHaveLength(0);
      await noSession(page);
      browser.assertClean();
    });
  });

  test('an empty staff ID is caught inline and focused without posting', async ({ page }, testInfo) => {
    const browser = await collectPortalBrowserFailures(page, baseUrl);
    await discovery(page, {
      ready: { status: 200, json: { status: 'ready', auth_mode: 'oidc-jwt' } },
      site: { status: 200, json: { ...PASSWORD_LANE, password_login_enabled: false, bundled_staging_login_enabled: true } },
    });
    const posts = recordPosts(page, '/v1/auth/bundled-staging-login');
    await page.goto(`${baseUrl}/internal/admin/login`);
    await page.getByRole('button', { name: 'Continue to internal admin' }).click();
    const staffId = page.getByLabel('Staff ID');
    await expect(page.locator('#staff-login-id-error')).toHaveText('Enter your staff ID.');
    await expect(staffId).toHaveAttribute('aria-invalid', 'true');
    await expect(staffId).toHaveAttribute('aria-describedby', 'staff-login-id-error');
    await expect(staffId).toBeFocused();
    expect(posts).toHaveLength(0);
    await proof(testInfo, staff({ kind: 'form-keyboard' }), '/internal/admin/login', 'invalid', [O.invalid], async () => {
      await expect(staffId).toHaveAttribute('aria-invalid', 'true');
      await expect(staffId).toBeFocused();
      expect(posts).toHaveLength(0);
      browser.assertClean();
    });
  });

  test('staff SSO without a sign-in link is an informational notice, not an error', async ({ page }, testInfo) => {
    const browser = await collectPortalBrowserFailures(page, baseUrl);
    await discovery(page, {
      ready: { status: 200, json: { status: 'ready', auth_mode: 'oidc-jwt' } },
      site: { status: 200, json: { ...PASSWORD_LANE, password_login_enabled: false, bundled_staging_login_enabled: false } },
    });
    const posts = recordPosts(page, '/v1/auth/bundled-staging-login');
    await page.goto(`${baseUrl}/internal/admin/login`);
    await expect(page.getByText('Staff sign-in uses your organization identity provider.')).toBeVisible();
    await expect(page.getByText('This deployment has no staff sign-in link configured', { exact: false })).toBeVisible();
    await expect(page.getByRole('alert')).toHaveCount(0);
    await expect(page.getByLabel('Staff ID')).toHaveCount(0);
    await expect(page.getByRole('button', { name: /Continue to/ })).toHaveCount(0);
    expect(posts).toHaveLength(0);
    browser.assertClean();
  });
});

function mutationRequests(page) {
  const requests = [];
  page.on('request', (request) => {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method())) requests.push({ method: request.method(), path: new URL(request.url()).pathname, body: request.postDataJSON() });
  });
  return requests;
}
const readyLane = (site) => ({ ready: { status: 200, json: { status: 'ready', auth_mode: site.auth_mode } }, site: { status: 200, json: site } });
const DEV_LANE = { ...PASSWORD_LANE, auth_mode: 'dev-headers', password_login_enabled: false };
const DEMO_EMAIL = 'admin@demo.astranull.local';
// These are the public sample-account values already rendered by the product, not deployed secrets.
const DEMO_PASSWORD = 'Astra-D1TrtI4HMTSrwKRW-9';
const DEMO_RESPONSE = { access_token: 'synthetic.jwt.value', principal: 'customer', tenant_id: 'ten_demo', user_id: 'usr_server_demo', role: 'viewer', expires_in: 600 };
async function mountedPortal(page) {
  await expect(page).toHaveURL(/\/app(?:#.*)?$/);
  await expect(page.locator('#portal-main h1')).toBeVisible();
  await expect(page.locator('#boot')).toHaveCount(0);
}

for (const route of ['/login', '/login.html']) {
  test(`password recovery navigation on ${route} abandons the credential draft, reloads safely and returns without a submission`, async ({ page }, testInfo) => {
    const browser = await collectPortalBrowserFailures(page, baseUrl);
    await discovery(page, readyLane(PASSWORD_LANE));
    const writes = mutationRequests(page);
    await page.goto(`${baseUrl}${route}`);
    await page.getByLabel('Work email').fill(SYNTHETIC_EMAIL);
    await page.locator('#login-password').fill(SYNTHETIC_PASSWORD);
    await page.getByRole('link', { name: 'Forgot password?' }).click();
    const query = customer({ kind: 'anchor', label: 'Forgot password?' });
    await proof(testInfo, query, route, 'success', [O.navigation, O.secrets], async () => {
      await expect(page.getByRole('heading', { level: 1, name: 'Reset your password' })).toBeVisible();
      expect(new URL(page.url()).searchParams.get('flow')).toBe('request-password-reset');
      expect(writes).toHaveLength(0);
      expect(await storageText(page)).not.toContain(SYNTHETIC_PASSWORD);
      expect(page.url()).not.toContain(SYNTHETIC_PASSWORD);
      await noSession(page);
      browser.assertClean();
    });
    await page.reload();
    await proof(testInfo, query, route, 'reload', [O.reload], async () => {
      await expect(page.getByRole('heading', { level: 1, name: 'Reset your password' })).toBeVisible();
      expect(writes).toHaveLength(0);
      await noSession(page);
      browser.assertClean();
    });
    await page.goBack();
    await proof(testInfo, query, route, 'cancel', [O.cancel, O.secrets], async () => {
      await expect(page).toHaveURL(`${baseUrl}${route}`);
      await expect(page.getByLabel('Work email')).toHaveValue('');
      await expect(page.locator('#login-password')).toHaveValue('');
      expect(writes).toHaveLength(0);
      expect(await storageText(page)).not.toContain(SYNTHETIC_PASSWORD);
      await noSession(page);
      browser.assertClean();
    });
  });

  test(`fill-demo on ${route} clears errors and both server challenges with zero unintended submissions`, async ({ page }, testInfo) => {
    const browser = await collectPortalBrowserFailures(page, baseUrl, { allowResponse: (response) => new URL(response.url()).pathname === '/v1/auth/login' && [400, 401].includes(response.status()) });
    await discovery(page, readyLane(PASSWORD_LANE));
    const writes = mutationRequests(page);
    await page.route('**/v1/auth/login', (request) => request.fulfill({ status: writes.length === 1 ? 400 : 401, json: { error: writes.length === 1 ? 'tenant_required' : writes.length === 2 ? 'mfa_required' : 'invalid_credentials' } }));
    await page.goto(`${baseUrl}${route}`);
    await noSession(page);
    await page.getByRole('button', { name: 'Continue to portal' }).click();
    await expect(page.locator('#login-user-id')).toHaveAttribute('aria-invalid', 'true');
    const fill = page.getByRole('button', { name: 'Fill demo credentials' });
    await fill.click();
    await expect(page.locator('#login-user-id')).toHaveValue(DEMO_EMAIL);
    await expect(page.locator('#login-password')).toHaveValue(DEMO_PASSWORD);
    expect(writes).toHaveLength(0);
    await page.getByRole('button', { name: 'Continue to portal' }).click();
    await expect(page.getByLabel('Workspace ID')).toBeVisible();
    await fill.click();
    await expect(page.getByLabel('Workspace ID')).toHaveCount(0);
    expect(writes).toHaveLength(1);
    await page.getByRole('button', { name: 'Continue to portal' }).click();
    await expect(page.getByLabel('Authenticator code')).toBeVisible();
    await fill.click();
    await expect(page.getByLabel('Authenticator code')).toHaveCount(0);
    expect(writes).toHaveLength(2);
    await page.getByRole('button', { name: 'Continue to portal' }).click();
    await expect(page.getByRole('alert')).toBeVisible();
    await fill.click();
    await proof(testInfo, customer({ label: 'Fill demo credentials' }), route, 'success', [O.demoFill, O.secrets], async () => {
      await expect(page.locator('#login-user-id')).toHaveValue(DEMO_EMAIL);
      await expect(page.locator('#login-password')).toHaveValue(DEMO_PASSWORD);
      await expect(page.locator('#login-password')).toHaveAttribute('type', 'password');
      await expect(page.getByRole('alert')).toHaveCount(0);
      await expect(page.locator('[aria-invalid="true"]')).toHaveCount(0);
      await noSession(page);
      expect(writes).toEqual(Array.from({ length: 3 }, () => ({ method: 'POST', path: '/v1/auth/login', body: { email: DEMO_EMAIL, password: DEMO_PASSWORD } })));
      expect(await storageText(page)).not.toContain(DEMO_PASSWORD);
      expect(page.url()).not.toContain(DEMO_PASSWORD);
      browser.assertClean();
    });
  });

  test(`dev-header skip on ${route} creates only the explicit local demo identity and reload never posts`, async ({ page }, testInfo) => {
    const browser = await collectPortalBrowserFailures(page, baseUrl);
    await discovery(page, readyLane(DEV_LANE));
    const writes = mutationRequests(page);
    await page.goto(`${baseUrl}${route}`);
    await noSession(page);
    await page.getByRole('button', { name: 'Skip: open as demo admin' }).click();
    const query = { owner: 'CredentialLoginPage', lane: 'dev-headers', label: 'Skip: open as demo admin' };
    await proof(testInfo, query, route, 'success', [O.demoLocal], async () => {
      await mountedPortal(page);
      expect(await session(page)).toEqual({ mode: 'dev-headers', principal: 'customer', tenant_id: 'ten_demo', user_id: 'usr_admin', role: 'admin' });
      expect(writes).toHaveLength(0);
      browser.assertClean();
    });
    await page.reload();
    await proof(testInfo, query, route, 'reload', [O.reload], async () => {
      await mountedPortal(page);
      expect(await session(page)).toMatchObject({ mode: 'dev-headers', user_id: 'usr_admin', role: 'admin' });
      expect(writes).toHaveLength(0);
      browser.assertClean();
    });
  });
}

for (const route of ['/', '/landing.html']) {
  const query = { owner: 'PublicLandingPage', label: 'Open demo workspace (sample data)' };
  test(`landing demo on ${route} exercises HTTP server identity and local configuration without visitor bootstrap`, async ({ page }, testInfo) => {
    const browser = await collectPortalBrowserFailures(page, baseUrl);
    const writes = mutationRequests(page);
    await discovery(page, readyLane(PASSWORD_LANE));
    await page.route('**/v1/auth/login', (request) => request.fulfill({ status: 200, json: DEMO_RESPONSE }));
    await proof(testInfo, query, route, 'success', [O.success, O.serverIdentity, O.demoLocal], async () => {
      await page.goto(`${baseUrl}${route}`);
      await noSession(page);
      await page.getByRole('button', { name: query.label, exact: true }).click();
      await mountedPortal(page);
      expect(writes).toEqual([{ method: 'POST', path: '/v1/auth/login', body: { email: DEMO_EMAIL, password: DEMO_PASSWORD } }]);
      expect(await session(page)).toMatchObject({ mode: 'oidc', principal: 'customer', tenant_id: 'ten_demo', user_id: 'usr_server_demo', role: 'viewer', access_token: DEMO_RESPONSE.access_token });
      expect(await storageText(page)).not.toContain(DEMO_PASSWORD);
      await page.reload();
      await mountedPortal(page);
      expect(writes).toHaveLength(1);
      expect(await session(page)).toMatchObject({ user_id: 'usr_server_demo', role: 'viewer' });
      await page.evaluate(() => { sessionStorage.clear(); localStorage.clear(); });
      await page.unroute('**/ready');
      await page.unroute('**/v1/public/site-config');
      await discovery(page, readyLane(DEV_LANE));
      await page.goto(`${baseUrl}${route}`);
      await noSession(page);
      await page.getByRole('button', { name: query.label, exact: true }).click();
      await mountedPortal(page);
      expect(await session(page)).toEqual({ mode: 'dev-headers', principal: 'customer', tenant_id: 'ten_demo', user_id: 'usr_admin', role: 'admin' });
      expect(writes).toHaveLength(1);
      browser.assertClean();
    });
    await proof(testInfo, query, route, 'reload', [O.reload], async () => {
      await page.reload();
      await mountedPortal(page);
      expect(writes).toHaveLength(1);
      expect(await session(page)).toMatchObject({ mode: 'dev-headers', role: 'admin' });
      await page.evaluate(() => { sessionStorage.clear(); localStorage.clear(); });
      await page.unroute('**/ready');
      await page.unroute('**/v1/public/site-config');
      await discovery(page, readyLane(PASSWORD_LANE));
      await page.goto(`${baseUrl}${route}`);
      await noSession(page);
      await page.getByRole('button', { name: query.label, exact: true }).click();
      await mountedPortal(page);
      expect(writes).toHaveLength(2);
      await page.reload();
      await mountedPortal(page);
      expect(writes).toHaveLength(2);
      expect(writes[1]).toEqual(writes[0]);
      expect(await session(page)).toMatchObject({ mode: 'oidc', user_id: 'usr_server_demo', role: 'viewer' });
      browser.assertClean();
    });
  });

  test(`landing demo on ${route} cannot duplicate a held credential exchange`, async ({ page }, testInfo) => {
    const browser = await collectPortalBrowserFailures(page, baseUrl);
    await discovery(page, readyLane(PASSWORD_LANE));
    const writes = mutationRequests(page);
    let release;
    const held = new Promise((resolve) => { release = resolve; });
    await page.route('**/v1/auth/login', async (request) => { await held; await request.fulfill({ status: 200, json: DEMO_RESPONSE }); });
    try {
      await page.goto(`${baseUrl}${route}`);
      const demo = page.getByRole('button', { name: /Open demo workspace \(sample data\)/ });
      await demo.click();
      await expect.poll(() => writes.length).toBe(1);
      // Real keyboard input while pending must not create a second exchange.
      await demo.press('Enter');
      await proof(testInfo, query, route, 'busy', [O.busy], async () => {
        await expect(demo).toBeDisabled();
        expect(writes).toHaveLength(1);
        await noSession(page);
      });
      release();
      await mountedPortal(page);
      expect(writes).toHaveLength(1);
      browser.assertClean();
    } finally { release(); }
  });

  for (const status of [401, 503]) {
    test(`landing demo HTTP ${status} on ${route} fails to login without a session and retries only on explicit activation`, async ({ page }, testInfo) => {
      const browser = await collectPortalBrowserFailures(page, baseUrl, { allowResponse: (response) => new URL(response.url()).pathname === '/v1/auth/login' && response.status() === status });
      await discovery(page, readyLane(PASSWORD_LANE));
      const writes = mutationRequests(page);
      await page.route('**/v1/auth/login', (request) => request.fulfill({ status, json: { error: status === 401 ? 'invalid_credentials' : 'service_unavailable' } }));
      await page.goto(`${baseUrl}${route}`);
      await noSession(page);
      await page.getByRole('button', { name: query.label, exact: true }).click();
      await expect(page).toHaveURL(`${baseUrl}/login`);
      await expect(page.getByRole('button', { name: 'Continue to portal' })).toBeVisible();
      await noSession(page);
      expect(writes).toHaveLength(1);
      if (status === 401) await proof(testInfo, query, route, 'denial', [O.demoFallback], async () => {
        await noSession(page);
        expect(writes).toEqual([{ method: 'POST', path: '/v1/auth/login', body: { email: DEMO_EMAIL, password: DEMO_PASSWORD } }]);
        await expect(page.getByRole('button', { name: 'Continue to portal' })).toBeVisible();
      });
      await page.goBack();
      await expect(page.getByRole('button', { name: query.label, exact: true })).toBeVisible();
      expect(writes).toHaveLength(1);
      await page.getByRole('button', { name: query.label, exact: true }).click();
      const assertRetry = async () => {
        await expect(page).toHaveURL(`${baseUrl}/login`);
        await expect(page.getByRole('button', { name: 'Continue to portal' })).toBeVisible();
        await noSession(page);
        expect(writes).toHaveLength(2);
        expect(writes[1]).toEqual(writes[0]);
        expect(await storageText(page)).not.toContain(DEMO_PASSWORD);
        browser.assertClean();
      };
      // One receipt per cell. The 401 case independently checks denial; the 503
      // case owns error/retry, so duplicate successful proofs cannot inflate coverage.
      if (status === 503) await proof(testInfo, query, route, 'error-retry', [O.demoFallback], assertRetry);
      else await assertRetry();
    });
  }
}
