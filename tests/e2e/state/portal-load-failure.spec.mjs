import { expect, test } from '@playwright/test';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  clearPortalSession,
  gotoPortalRoute,
  injectPortalDevHeadersSession,
  PORTAL_SESSION,
} from '../../helpers/portal-playwright-session.mjs';

const SESSION_KEY = 'astranull.portal.session.v1';

/** Read the persisted portal session exactly as the app stores it. */
async function readStoredSession(page) {
  return page.evaluate((key) => sessionStorage.getItem(key), SESSION_KEY);
}

/**
 * Seed sessionStorage ONCE, on the origin, without an init script.
 *
 * `injectPortalDevHeadersSession` uses page.addInitScript, which re-runs on every
 * subsequent document — including the login page we redirect to. That would
 * re-create the very session the app just cleared and make "was the credential
 * discarded?" untestable. Writing it directly leaves the app as the only thing
 * that touches storage after this point.
 */
async function seedSessionOnce(page, baseUrl, session) {
  // /login is public-only: it renders without hydrating and never mints a session.
  await page.goto(`${baseUrl}/login`, { waitUntil: 'domcontentloaded' });
  await page.evaluate(
    ([key, value]) => sessionStorage.setItem(key, JSON.stringify(value)),
    [SESSION_KEY, session],
  );
}

/**
 * Fail a request the way the hardened server now does: a 5xx that carries no
 * message, only a correlation id.
 */
async function fulfillInternalError(route, body = { error: 'internal_error', correlation_id: 'cid-test-0001' }) {
  await route.fulfill({
    status: 500,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

test.describe('portal load-failure and session states', () => {
  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('a 500 on /v1/audit-log renders an error affordance, not an empty table', async ({ page }) => {
    await startPortalPlaywrightServer();
    const baseUrl = getPortalPlaywrightBaseUrl();

    await page.route('**/v1/audit-log*', fulfillInternalError);
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'audit', baseUrl);

    // The operator must be told the dataset could not be read...
    const affordance = page.locator('.table-load-error').first();
    await expect(affordance).toBeVisible();
    await expect(affordance).toHaveAttribute('role', 'alert');
    await expect(affordance).toContainText('Could not load');
    // ...and be given a way to try again.
    await expect(affordance.getByRole('button', { name: 'Retry' })).toBeVisible();

    // ...and must NOT be told the audit log is simply empty, which is what the
    // silent empty state used to claim.
    await expect(page.getByText('No audit events', { exact: false })).toHaveCount(0);
  });

  test('a leaky 500 message is never rendered to the operator', async ({ page }) => {
    await startPortalPlaywrightServer();
    const baseUrl = getPortalPlaywrightBaseUrl();

    // A server that has not been hardened (or a proxy) may still return driver
    // text. The portal must refuse to display it.
    const leak = 'relation "audit_log" does not exist at db.internal:5432';
    await page.route('**/v1/audit-log*', (route) =>
      fulfillInternalError(route, { error: 'internal_error', message: leak }));

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'audit', baseUrl);

    const affordance = page.locator('.table-load-error').first();
    await expect(affordance).toBeVisible();
    await expect(affordance).toContainText('Something went wrong on the server');

    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toContain('relation "audit_log"');
    expect(bodyText).not.toContain('db.internal');
  });

  test('both discovery endpoints failing redirects to login instead of fabricating a session', async ({ page }) => {
    await startPortalPlaywrightServer();
    const baseUrl = getPortalPlaywrightBaseUrl();

    // Neither /ready nor /v1/public/site-config yields an auth_mode. The portal
    // used to default to dev-headers here and mint an unauthenticated admin.
    await page.route('**/ready', (route) => route.abort());
    await page.route('**/v1/public/site-config', (route) => route.abort());

    await clearPortalSession(page);
    await page.goto(`${baseUrl}/app#dashboard`, { waitUntil: 'commit' });

    await page.waitForURL(/\/login/, { timeout: 30_000 });
    // No session may have been written on the way there.
    expect(await readStoredSession(page)).toBeNull();
  });

  test('a 401 mid-session clears storage and redirects exactly once', async ({ page }) => {
    await startPortalPlaywrightServer();
    const baseUrl = getPortalPlaywrightBaseUrl();

    await seedSessionOnce(page, baseUrl, PORTAL_SESSION);

    // Every hydrate call rejects at once, which is what an expired or revoked
    // session actually looks like — the redirect must still happen only once.
    await page.route('**/v1/**', (route) =>
      route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'unauthorized' }),
      }));

    // Registered after seeding so the seed navigation is not counted.
    const loginNavigations = [];
    page.on('framenavigated', (frame) => {
      if (frame === page.mainFrame() && frame.url().includes('/login')) {
        loginNavigations.push(frame.url());
      }
    });

    await page.goto(`${baseUrl}/app#dashboard`, { waitUntil: 'commit' });

    await page.waitForURL(/\/login/, { timeout: 30_000 });
    // The dead credential is gone, so nothing can keep sending it.
    expect(await readStoredSession(page)).toBeNull();

    // Give any redundant redirect a chance to fire before asserting it did not.
    await page.waitForTimeout(1_500);
    expect(loginNavigations).toHaveLength(1);
  });

  test('an expired session sends no authorization header', async ({ page }) => {
    await startPortalPlaywrightServer();
    const baseUrl = getPortalPlaywrightBaseUrl();

    await seedSessionOnce(page, baseUrl, {
      ...PORTAL_SESSION,
      mode: 'oidc',
      access_token: 'expired-bearer-token-must-never-be-sent',
      // Already past.
      expires_at: Date.now() - 60_000,
    });

    const authorizationHeaders = [];
    page.on('request', (request) => {
      const header = request.headers().authorization;
      if (header) authorizationHeaders.push(`${request.url()} :: ${header}`);
    });

    await page.goto(`${baseUrl}/app#dashboard`, { waitUntil: 'commit' });
    await page.waitForURL(/\/login/, { timeout: 30_000 });

    expect(authorizationHeaders).toEqual([]);
    expect(await readStoredSession(page)).toBeNull();
  });
});
