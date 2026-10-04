import { expect, test } from '@playwright/test';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import { findingGroupHref, findingGroupKey } from '../../../apps/web/react/src/lib/finding-groups.mjs';

/**
 * Current-release public pages: landing, sign-in (with recovery), request access,
 * request status, invitation password setup.
 *
 * Runs against the in-process portal server (isolated ASTRANULL_DEV_DATA_DIR, no
 * persistence, built bundle) unless ASTRANULL_PUBLIC_UI_BASE_URL points at a local
 * Vite dev server proxied to an isolated API. Lanes the local server does not enable
 * (password sign-in, invitation activation) are exercised with page.route fixtures that
 * return the documented response codes. Every credential and token here is synthetic.
 */

const EXTERNAL_BASE = process.env.ASTRANULL_PUBLIC_UI_BASE_URL ?? '';
const SYNTHETIC_INVITE = 'pwi_synthetic-invite-token-for-ui-tests-only';
const SYNTHETIC_RESET = 'pwr_synthetic-reset-token-for-ui-tests-only';
const SYNTHETIC_PASSWORD = 'Harbor-lantern-42';

let baseUrl = '';

test.describe.configure({ mode: 'serial' });

test.beforeAll(async () => {
  if (EXTERNAL_BASE) {
    baseUrl = EXTERNAL_BASE.replace(/\/$/, '');
    return;
  }
  await startPortalPlaywrightServer();
  baseUrl = getPortalPlaywrightBaseUrl();
});

test.afterAll(async () => {
  if (!EXTERNAL_BASE) await stopPortalPlaywrightServer();
});

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    sessionStorage.removeItem('astranull.portal.session.v1');
  });
});

const PASSWORD_LANE_SITE_CONFIG = {
  product_name: 'AstraNull',
  promise: 'No-access-first DDoS readiness validation for customer-declared targets.',
  login_url: '/login',
  signup_enabled: true,
  signup_path: '/signup',
  customer_portal_path: '/app',
  auth_mode: 'oidc-jwt',
  bundled_staging_login_enabled: false,
  password_login_enabled: true,
};

async function usePasswordLane(page, overrides = {}) {
  await page.route('**/ready', (route) => route.fulfill({ status: 200, json: { status: 'ready', auth_mode: 'oidc-jwt' } }));
  await page.route('**/v1/public/site-config', (route) => route.fulfill({
    status: 200,
    json: { ...PASSWORD_LANE_SITE_CONFIG, ...overrides },
  }));
}

async function noPageOverflow(page) {
  const { scrollWidth, innerWidth } = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    innerWidth: window.innerWidth,
  }));
  expect(scrollWidth).toBeLessThanOrEqual(innerWidth);
}

async function storageText(page) {
  return page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }));
}

test.describe('landing', () => {
  test('leads with a labeled synthetic workflow, not a schema, and makes no deferred claims', async ({ page }) => {
    await page.goto(`${baseUrl}/`);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Prove DDoS readiness without handing over your cloud keys.');
    const example = page.getByRole('figure', { name: 'One check, start to finish' });
    await expect(example).toContainText('Example data');
    await expect(example).toContainText('Illustrative example with invented data. It is not a customer result.');
    await expect(example).toContainText('Prove ownership');
    await expect(example).toContainText('Run one bounded check');

    const body = await page.locator('body').innerText();
    expect(body).not.toMatch(/high-scale|kill switch|SOC lead|Escalate through the SOC/i);
    expect(body).toMatch(/does not certify protection or measure volumetric capacity/);

    const technical = page.locator('details.public-technical');
    await expect(technical).not.toHaveAttribute('open', '');
    await expect(page.locator('code', { hasText: 'reason_codes' })).toBeHidden();
    await technical.locator('summary').click();
    await expect(page.locator('code', { hasText: 'reason_codes' })).toBeVisible();
  });

  test('the example walkthrough advances only on intent and announces each step', async ({ page }) => {
    await page.goto(`${baseUrl}/`);
    const control = page.getByRole('button', { name: 'Walk through the example' });
    await control.focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('.public-example-progress')).toHaveText('Step 1 of 4: Declare a target');
    await expect(page.locator('.public-example-steps li[aria-current="step"]')).toHaveCount(1);
    await page.getByRole('button', { name: 'Next step' }).press('Enter');
    await expect(page.locator('.public-example-progress')).toHaveText('Step 2 of 4: Prove ownership');
  });

  test('stays readable at 375px with reduced motion', async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 375, height: 812 }, reducedMotion: 'reduce' });
    const page = await context.newPage();
    await page.goto(`${baseUrl}/`);
    await noPageOverflow(page);
    await expect(page.getByRole('heading', { name: 'How a check works.' })).toBeVisible();
    const hidden = await page.evaluate(() => [...document.querySelectorAll('.reveal, [data-reveal]')]
      .filter((node) => Number(getComputedStyle(node).opacity) < 1).length);
    expect(hidden).toBe(0);
    await context.close();
  });
});

test.describe('sign-in', () => {
  test('developer mode is labeled, the heading arrives first on mobile and empty submit focuses the field', async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 375, height: 812 } });
    const page = await context.newPage();
    await page.addInitScript(() => sessionStorage.removeItem('astranull.portal.session.v1'));
    await page.goto(`${baseUrl}/login`);
    await expect(page.getByRole('heading', { level: 1, name: 'Log in to AstraNull' })).toBeVisible();
    await expect(page.getByText('Developer mode: no password is checked.')).toBeVisible();
    const headingBox = await page.getByRole('heading', { level: 1 }).boundingBox();
    const formBox = await page.locator('form.auth-form').boundingBox();
    expect(headingBox.y).toBeLessThan(formBox.y);
    await page.getByRole('button', { name: 'Continue to portal', exact: true }).click();
    await expect(page.locator('#login-user-id')).toBeFocused();
    await expect(page.locator('#login-user-id-error')).toHaveText('Enter a user ID or work email.');
    await expect(page.locator('#login-user-id')).toHaveAttribute('aria-describedby', 'login-user-id-error');
    await noPageOverflow(page);
    await context.close();
  });

  test('password lane has no role picker and keeps the email after a rejected credential', async ({ page }) => {
    await usePasswordLane(page);
    await page.route('**/v1/auth/login', (route) => route.fulfill({ status: 401, json: { error: 'invalid_credentials' } }));
    await page.goto(`${baseUrl}/login`);
    await expect(page.locator('#login-password')).toBeVisible();
    await expect(page.getByText(/^Role$|Staging role/)).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Forgot password?' })).toBeVisible();

    await page.locator('#login-user-id').fill('analyst@company.test');
    await page.locator('#login-password').fill(SYNTHETIC_PASSWORD);
    await page.getByRole('button', { name: 'Continue to portal', exact: true }).click();
    const alert = page.locator('.public-form-error[role="alert"]');
    await expect(alert).toContainText('Email or password is incorrect.');
    await expect(alert.getByRole('link', { name: 'Reset your password' })).toBeVisible();
    await expect(page.locator('#login-user-id')).toHaveValue('analyst@company.test');
    await expect(page.locator('#login-password')).toHaveValue('');
    expect(await storageText(page)).not.toContain(SYNTHETIC_PASSWORD);
  });

  test('network failure and unknown auth configuration are distinct from bad credentials', async ({ page }) => {
    await usePasswordLane(page);
    await page.route('**/v1/auth/login', (route) => route.abort('failed'));
    await page.goto(`${baseUrl}/login`);
    await page.locator('#login-user-id').fill('analyst@company.test');
    await page.locator('#login-password').fill(SYNTHETIC_PASSWORD);
    await page.getByRole('button', { name: 'Continue to portal', exact: true }).click();
    await expect(page.locator('.public-form-error')).toContainText('Could not reach AstraNull');

    await page.unrouteAll({ behavior: 'ignoreErrors' });
    await page.route('**/ready', (route) => route.fulfill({ status: 503, json: {} }));
    await page.route('**/v1/public/site-config', (route) => route.fulfill({ status: 503, json: {} }));
    await page.goto(`${baseUrl}/login`);
    await expect(page.getByText('We could not confirm how this deployment signs people in.')).toBeVisible();
    await expect(page.locator('form.auth-form')).toHaveCount(0);
  });

  test('restores a real finding-group intent through sign-in and ignores unsafe ones', async ({ page }) => {
    await usePasswordLane(page);
    await page.route('**/v1/auth/login', (route) => route.fulfill({
      status: 200,
      json: { access_token: 'synthetic.jwt.value', principal: 'customer', tenant_id: 'ten_test', user_id: 'usr_test', role: 'viewer', expires_in: 600 },
    }));
    const key = findingGroupKey(
      { id: 'fnd_a', check_id: 'http.rate_limit.safe', target_id: 'tgt_1', title: 'Rate limiting missing on /login | burst (50%)' },
      { targets: [{ id: 'tgt_1', name: 'checkout.shop.example' }], checks: [] },
    );
    const intent = `${findingGroupHref(key)}&inspect=group_member&ev_finding=fnd_a&token=pwi_leak&raw_payload=x`;
    const login = `/login?${new URLSearchParams({ next: intent, reason: 'session_expired' })}`;
    await page.goto(`${baseUrl}${login}`);
    await expect(page.getByText('Your session ended. Log in again to continue.')).toBeVisible();
    await expect(page.getByText('After you log in, you return to Finding group.')).toBeVisible();
    await page.locator('#login-user-id').fill('analyst@company.test');
    await page.locator('#login-password').fill(SYNTHETIC_PASSWORD);
    await page.getByRole('button', { name: 'Continue to portal', exact: true }).click();

    let arrived = null;
    await page.waitForURL((url) => {
      if (url.pathname === '/app' && url.hash.startsWith('#finding-group-detail')) arrived = url;
      return Boolean(arrived);
    });
    const params = new URLSearchParams(arrived.hash.slice(arrived.hash.indexOf('?') + 1));
    expect(params.get('key')).toBe(key);
    expect(params.get('inspect')).toBe('group_member');
    expect(params.get('ev_finding')).toBe('fnd_a');
    expect(params.get('token')).toBeNull();
    expect(params.get('raw_payload')).toBeNull();

    const forged = `#finding-group-detail?key=${encodeURIComponent('http.rate_limit.safe|t%3Apwi_live-token')}`;
    for (const unsafe of ['#admin', 'https://evil.example/#findings', '#not-a-route']) {
      await page.evaluate(() => sessionStorage.clear());
      await page.goto(`${baseUrl}/login?next=${encodeURIComponent(unsafe)}`);
      await expect(page.getByText(/you return to|Log in to open/)).toHaveCount(0);
    }
    await page.evaluate(() => sessionStorage.clear());
    await page.goto(`${baseUrl}/login?next=${encodeURIComponent(forged)}`);
    await expect(page.getByText('Log in to open Finding group.')).toBeVisible();
  });

  test('recovery request stays enumeration-safe and recovery tokens leave the address bar', async ({ page }) => {
    await usePasswordLane(page);
    await page.route('**/v1/auth/request-password-reset', (route) => route.fulfill({ status: 200, json: { status: 'reset_requested' } }));
    await page.goto(`${baseUrl}/login?flow=request-password-reset`);
    await page.locator('#password-reset-email').fill('analyst@company.test');
    await page.getByRole('button', { name: 'Request recovery instructions' }).click();
    await expect(page.getByText('This response confirms neither condition.', { exact: false })).toBeVisible();

    await page.route('**/v1/auth/reset-password', (route) => route.fulfill({ status: 401, json: { error: 'invalid_reset_token' } }));
    await page.goto(`${baseUrl}/login?flow=password-reset&token=${SYNTHETIC_RESET}`);
    await expect(page).not.toHaveURL(/token=/);
    await expect(page.getByText('Recovery link detected.')).toBeVisible();
    await page.locator('#reset-password-new').fill(SYNTHETIC_PASSWORD);
    await page.locator('#reset-password-confirm').fill(SYNTHETIC_PASSWORD);
    await page.getByRole('button', { name: 'Change password' }).click();
    await expect(page.getByText('This recovery link cannot be used.')).toBeVisible();
    await expect(page.getByRole('link', { name: 'Request a new link' })).toBeVisible();
    expect(await page.content()).not.toContain(SYNTHETIC_RESET);
    expect(await storageText(page)).not.toContain(SYNTHETIC_RESET);
  });
});

test.describe('invitation password setup', () => {
  test('strips the invitation token, gives live requirements and ties confirm errors to the field', async ({ page }) => {
    await usePasswordLane(page);
    await page.goto(`${baseUrl}/set-password?token=${SYNTHETIC_INVITE}`);
    await expect(page).not.toHaveURL(/token=/);
    await expect(page.getByText('Invitation link detected.')).toBeVisible();
    await expect(page.locator('#set-password-token')).toHaveCount(0);

    const password = page.locator('#set-password-new');
    await expect(password).toHaveAttribute('autocomplete', 'new-password');
    const pasteBlocked = await password.evaluate((node) => {
      const event = new Event('paste', { bubbles: true, cancelable: true });
      node.dispatchEvent(event);
      return event.defaultPrevented;
    });
    expect(pasteBlocked).toBe(false);

    await password.fill('short');
    await expect(page.locator('.public-requirements li.is-met')).toHaveCount(0);
    await password.fill(SYNTHETIC_PASSWORD);
    await expect(page.locator('.public-requirements li.is-met')).toHaveCount(2);
    await expect(page.locator('.public-requirements li').first()).toContainText('Met:');

    const confirm = page.locator('#set-password-confirm');
    await confirm.fill('Harbor-lantern-41');
    await confirm.blur();
    await expect(page.locator('#set-password-confirm-error')).toHaveText('Passwords do not match.');
    await expect(confirm).toHaveAttribute('aria-describedby', 'set-password-confirm-error');
    await expect(confirm).toHaveAttribute('aria-invalid', 'true');
    await confirm.fill(SYNTHETIC_PASSWORD);
    await expect(page.locator('#set-password-confirm-error')).toHaveCount(0);
    expect(await page.content()).not.toContain(SYNTHETIC_INVITE);
  });

  test('server policy failures stay on the field and expired invitations end the flow', async ({ page }) => {
    await usePasswordLane(page);
    let calls = 0;
    await page.route('**/v1/auth/set-password', (route) => {
      calls += 1;
      return calls === 1
        ? route.fulfill({ status: 400, json: { error: 'weak_password', failures: ['contains_email_local_part'] } })
        : route.fulfill({ status: 410, json: { error: 'invite_expired' } });
    });
    await page.goto(`${baseUrl}/set-password?token=${SYNTHETIC_INVITE}`);
    await page.locator('#set-password-new').fill(SYNTHETIC_PASSWORD);
    await page.locator('#set-password-confirm').fill(SYNTHETIC_PASSWORD);
    await page.getByRole('button', { name: 'Set password' }).click();
    await expect(page.locator('#set-password-policy-error')).toContainText('Do not include the name part of your email address.');
    await expect(page.locator('#set-password-new')).toHaveAttribute('aria-invalid', 'true');

    await page.getByRole('button', { name: 'Set password' }).click();
    await expect(page.getByText('This invitation has expired.')).toBeVisible();
    await expect(page.getByText('No account was activated.', { exact: false })).toBeVisible();
    await expect(page.locator('#set-password-new')).toHaveCount(0);
  });

  test('a successful activation names the account and hands off to sign-in', async ({ page }) => {
    await usePasswordLane(page);
    await page.route('**/v1/auth/set-password', (route) => route.fulfill({ status: 200, json: { status: 'password_set', email: 'analyst@company.test' } }));
    await page.goto(`${baseUrl}/set-password?token=${SYNTHETIC_INVITE}`);
    await page.locator('#set-password-new').fill(SYNTHETIC_PASSWORD);
    await page.locator('#set-password-confirm').fill(SYNTHETIC_PASSWORD);
    await page.getByRole('button', { name: 'Set password' }).click();
    await expect(page.getByText('Your account is active.')).toBeVisible();
    await expect(page.getByText('analyst@company.test')).toBeVisible();
    await expect(page.getByRole('link', { name: 'Log in' }).last()).toHaveAttribute('href', '/login');
  });

  test('without a link the manual code field is a fallback, masked from screenshots', async ({ page }) => {
    await page.goto(`${baseUrl}/set-password`);
    await expect(page.locator('#set-password-token')).toHaveAttribute('type', 'password');
    await page.getByRole('button', { name: 'Set password' }).click();
    await expect(page.locator('.public-form-error')).toContainText('Enter the invitation code');
  });
});

test.describe('request access and status', () => {
  test('inline validation focuses the first problem and keeps answers', async ({ page }) => {
    await page.goto(`${baseUrl}/signup`);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Request access to AstraNull.');
    await expect(page.getByText(/high-scale/i)).toHaveCount(0);
    await page.locator('#signup-contact').fill('Rowan Achebe');
    await page.getByRole('button', { name: 'Submit request' }).click();
    await expect(page.locator('#signup-organization')).toBeFocused();
    await expect(page.locator('#signup-organization_name-error')).toBeVisible();
    await expect(page.locator('#signup-contact')).toHaveValue('Rowan Achebe');
  });

  test('a recorded request keeps its ID through confirmation, copy, reload and status', async ({ browser }) => {
    const context = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
    const page = await context.newPage();
    const suffix = Date.now().toString(36);
    await page.goto(`${baseUrl}/signup`);
    await page.locator('#signup-organization').fill(`Northwind Ferries ${suffix}`);
    await page.locator('#signup-contact').fill('Rowan Achebe');
    await page.locator('#signup-email').fill(`rowan@ferries-${suffix}.test`);
    await page.locator('#signup-intended-use').fill('Validate our public booking site and API from outside.');
    await page.getByRole('button', { name: 'Submit request' }).click();

    await expect(page.getByText('Request received.')).toBeVisible();
    await expect(page.getByText('No account exists yet.', { exact: false })).toBeVisible();
    const id = (await page.locator('.public-reference-value').textContent()).trim();
    expect(id).toMatch(/^sgn_/);
    await expect(page).toHaveURL(new RegExp(`[?&]id=${id}`));
    await expect(page.locator('.public-lifecycle li[aria-current="step"]')).toContainText('Received');

    await page.getByRole('button', { name: 'Copy ID' }).click();
    await expect(page.locator('.public-copy-status')).toHaveText('Request ID copied.');
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(id);

    await page.reload();
    await expect(page.locator('.public-reference-value')).toHaveText(id);

    await page.getByRole('link', { name: 'Check status' }).click();
    await expect(page.locator('#signup-status-request-id')).toHaveValue(id);
    await expect(page.getByRole('heading', { name: 'Received' })).toBeVisible();
    await expect(page.getByText('You cannot sign in yet.')).toBeVisible();

    await page.goto(`${baseUrl}/signup`);
    await page.locator('#signup-organization').fill(`Northwind Ferries ${suffix}`);
    await page.locator('#signup-contact').fill('Rowan Achebe');
    await page.locator('#signup-email').fill(`ops@ferries-${suffix}.test`);
    await page.locator('#signup-intended-use').fill('Validate our public booking site and API from outside.');
    await page.getByRole('button', { name: 'Submit request' }).click();
    await expect(page.locator('.public-form-error')).toContainText('already open');
    await expect(page.locator('#signup-email')).toHaveValue(`ops@ferries-${suffix}.test`);
    await expect(page.locator('.public-form-error')).not.toContainText(id);
    await context.close();
  });

  test('closed intake is explicit and links to status', async ({ page }) => {
    await page.route('**/v1/public/site-config', async (route) => {
      const response = await route.fetch();
      const json = await response.json();
      await route.fulfill({ status: 200, json: { ...json, signup_enabled: false } });
    });
    await page.goto(`${baseUrl}/signup`);
    await expect(page.getByText('Access requests are closed on this deployment.')).toBeVisible();
    await expect(page.locator('form')).toHaveCount(0);
  });

  test('status distinguishes not found, service failure and each recorded stage', async ({ page }) => {
    await page.goto(`${baseUrl}/signup-status?id=${encodeURIComponent('  sgn_doesnotexist  ')}`);
    await expect(page.locator('#signup-status-request-id-error')).toContainText('No request matches this ID');
    await expect(page.locator('#signup-status-request-id')).toHaveValue('sgn_doesnotexist');

    await page.route('**/v1/signup-requests/sgn_flaky', (route) => route.fulfill({ status: 500, json: { error: 'internal_error' } }));
    await page.goto(`${baseUrl}/signup-status?id=sgn_flaky`);
    await expect(page.locator('.public-form-error[role="alert"]')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible();
    await expect(page.locator('#signup-status-request-id')).toHaveValue('sgn_flaky');

    const cases = [
      ['approved', 'Approved', 'You cannot sign in yet.', false],
      ['provisioned', 'Workspace created', 'You cannot sign in yet.', false],
      ['customer_invited', 'Invitation issued', 'Set your password from the invitation, then log in.', true],
      ['rejected', 'Not approved', 'This request was not approved.', false],
    ];
    for (const [state, heading, headline, canSignIn] of cases) {
      await page.unrouteAll({ behavior: 'ignoreErrors' });
      await page.route('**/v1/signup-requests/sgn_fixture', (route) => route.fulfill({
        status: 200,
        json: {
          request: {
            id: 'sgn_fixture',
            organization_name: 'Northwind Ferries',
            state,
            requested_plan: 'professional',
            region: 'eu',
            created_at: '2026-09-30T10:00:00.000Z',
            updated_at: '2026-10-01T09:30:00.000Z',
            customer_notice: state === 'rejected' ? 'We could not verify the organization domain.' : null,
          },
        },
      }));
      await page.goto(`${baseUrl}/signup-status?id=sgn_fixture`);
      await expect(page.getByRole('heading', { level: 2, name: heading })).toBeVisible();
      await expect(page.getByText(headline)).toBeVisible();
      const loginAction = page.locator('.public-status-result').getByRole('link', { name: 'Log in' });
      await expect(loginAction).toHaveCount(canSignIn ? 1 : 0);
      if (state === 'rejected') {
        await expect(page.getByText('We could not verify the organization domain.')).toBeVisible();
        await expect(page.locator('.public-lifecycle')).toHaveCount(0);
      } else {
        await expect(page.locator('.public-lifecycle li[aria-current="step"]')).toContainText(heading);
        await expect(page.locator('.public-lifecycle li').last()).toContainText('Not tracked here');
      }
    }
  });
});
