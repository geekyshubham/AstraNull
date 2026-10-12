import { expect, test } from '@playwright/test';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import { collectPortalBrowserFailures } from '../../helpers/portal-browser-failures.mjs';

const SYNTHETIC_EMAIL = 'analyst@example.test';
const SYNTHETIC_PASSWORD = 'Harbor-lantern-42';
const SESSION_KEY = 'astranull.portal.session.v1';

let baseUrl = '';

test.describe.configure({ retries: 0 });

test.beforeAll(async () => {
  await startPortalPlaywrightServer();
  baseUrl = getPortalPlaywrightBaseUrl();
});

test.afterAll(async () => {
  await stopPortalPlaywrightServer();
});

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
  test('an empty or partial authenticator code is rejected locally and never burns a verification attempt', async ({ page }) => {
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
    await page.locator('#login-password').fill(SYNTHETIC_PASSWORD);
    await page.getByRole('button', { name: 'Continue to portal' }).click();
    const code = page.getByLabel('Authenticator code');
    await expect(code).toBeVisible();
    await expect(page.getByRole('alert')).toContainText('Enter the 6-digit code');
    expect(posts).toHaveLength(1);
    expect(posts[0]).toEqual({ email: SYNTHETIC_EMAIL, password: SYNTHETIC_PASSWORD });

    await page.getByRole('button', { name: 'Verify and continue' }).click();
    await expect(code).toHaveAttribute('aria-invalid', 'true');
    await expect(code).toBeFocused();
    expect(posts).toHaveLength(1);

    await code.fill('123');
    await code.press('Enter');
    await expect(code).toHaveAttribute('aria-invalid', 'true');
    expect(posts).toHaveLength(1);

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

  test('a required workspace ID is validated locally before resubmitting credentials', async ({ page }) => {
    const browser = await collectPortalBrowserFailures(page, baseUrl, {
      allowResponse: (response) => new URL(response.url()).pathname === '/v1/auth/login' && response.status() === 409,
    });
    await discovery(page, { ready: { status: 200, json: { status: 'ready', auth_mode: 'oidc-jwt' } }, site: { status: 200, json: PASSWORD_LANE } });
    const posts = recordPosts(page, '/v1/auth/login');
    await page.route('**/v1/auth/login', (route) => {
      const body = route.request().postDataJSON();
      if (body.tenant_id === 'ten_synthetic') {
        return route.fulfill({ status: 200, json: { access_token: 'synthetic.jwt.value', principal: 'customer', tenant_id: 'ten_synthetic', user_id: 'usr_synthetic', role: 'viewer', expires_in: 600 } });
      }
      return route.fulfill({ status: 409, json: { error: 'tenant_required' } });
    });

    await page.goto(`${baseUrl}/login`);
    await page.getByLabel('Work email').fill(SYNTHETIC_EMAIL);
    await page.locator('#login-password').fill(SYNTHETIC_PASSWORD);
    await page.getByRole('button', { name: 'Continue to portal' }).click();
    const workspace = page.getByLabel('Workspace ID');
    await expect(workspace).toBeVisible();
    expect(posts).toHaveLength(1);

    await page.getByRole('button', { name: 'Continue to portal' }).click();
    await expect(workspace).toHaveAttribute('aria-invalid', 'true');
    await expect(workspace).toBeFocused();
    expect(posts).toHaveLength(1);

    browser.assertClean();
    await workspace.fill('ten_synthetic');
    await workspace.press('Enter');
    await page.waitForURL((url) => url.pathname.startsWith('/app'));
    expect(posts).toHaveLength(2);
    expect(posts[1]).toEqual({ email: SYNTHETIC_EMAIL, password: SYNTHETIC_PASSWORD, tenant_id: 'ten_synthetic' });
    const session = await page.evaluate((key) => JSON.parse(sessionStorage.getItem(key) ?? 'null'), SESSION_KEY);
    expect(session).toMatchObject({ principal: 'customer', tenant_id: 'ten_synthetic', role: 'viewer' });
    expect(await storageText(page)).not.toContain(SYNTHETIC_PASSWORD);
  });
});

test.describe('staff sign-in', () => {
  test('unknown authentication mode fails closed: nothing can be submitted', async ({ page }) => {
    const browser = await collectPortalBrowserFailures(page, baseUrl, {
      allowResponse: (response) => ['/ready', '/v1/public/site-config'].includes(new URL(response.url()).pathname) && response.status() === 503,
    });
    await discovery(page, { ready: { status: 503, json: { status: 'not_ready' } }, site: { status: 503, json: {} } });
    const posts = recordPosts(page, '/v1/auth/bundled-staging-login');
    await page.goto(`${baseUrl}/internal/admin/login`);
    await expect(page.getByRole('alert')).toContainText('We could not confirm how this deployment signs staff in.');
    await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible();
    await expect(page.getByLabel('Staff ID')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Continue to internal admin' })).toHaveCount(0);
    expect(posts).toHaveLength(0);
    expect(await page.evaluate((key) => sessionStorage.getItem(key), SESSION_KEY)).toBeNull();
    browser.assertClean();
  });

  test('a pending bundled staging sign-in cannot be submitted twice from the keyboard and retries explicitly', async ({ page }) => {
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
    release();
    await expect(page.getByRole('alert')).toBeVisible();
    await expect(submit).toBeEnabled();
    expect(posts).toHaveLength(1);
    expect(posts[0]).toEqual({ principal: 'staff', staff_id: 'stf_synthetic', staff_role: 'internal_admin' });
    await submit.click();
    await expect.poll(() => posts.length).toBe(2);
    await expect(submit).toBeEnabled();
    expect(await page.evaluate((key) => sessionStorage.getItem(key), SESSION_KEY)).toBeNull();
    browser.assertClean();
  });
});
