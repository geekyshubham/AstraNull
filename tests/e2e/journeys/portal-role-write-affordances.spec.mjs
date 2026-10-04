import { expect, test } from '@playwright/test';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  injectPortalDevHeadersSession,
  PORTAL_SESSION,
} from '../../helpers/portal-playwright-session.mjs';

const VIEWER_SESSION = { ...PORTAL_SESSION, user_id: 'usr_viewer', role: 'viewer' };
const ENGINEER_SESSION = { ...PORTAL_SESSION, user_id: 'usr_engineer', role: 'engineer' };
const AUDITOR_SESSION = { ...PORTAL_SESSION, user_id: 'usr_auditor', role: 'auditor' };

async function expectNoButton(page, name) {
  await expect(page.getByRole('button', { name, exact: typeof name === 'string' })).toHaveCount(0);
}

test.describe('portal mutation affordances follow backend RBAC', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('viewer gets read-only list surfaces instead of controls that would return 403', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page, VIEWER_SESSION);

    await gotoPortalRoute(page, 'target-groups', baseUrl);
    await expectNoButton(page, 'Add target');
    await expectNoButton(page, 'Create target group');

    await gotoPortalRoute(page, 'targets', baseUrl);
    await expectNoButton(page, 'Add target');
    await expect(page.getByRole('button', { name: /^Remove target / })).toHaveCount(0);

    await gotoPortalRoute(page, 'test-policies', baseUrl);
    await expectNoButton(page, 'Create schedule');

    await gotoPortalRoute(page, 'reports', baseUrl);
    await expectNoButton(page, 'Review report');
    await expectNoButton(page, 'Generate report');
    await expect(page.getByText('Report generation is not available for your role.')).toBeVisible();

    await gotoPortalRoute(page, 'settings', baseUrl);
    await expectNoButton(page, 'Save organization');
    await expect(page.getByText('Organization settings are read-only for your role.')).toBeVisible();
    await page.getByRole('tab', { name: 'Privacy' }).click();
    await expectNoButton(page, 'Save retention policy');
    await expect(page.getByText('Retention settings are read-only for your role.')).toBeVisible();

    await gotoPortalRoute(page, 'runs', baseUrl);
    await expectNoButton(page, 'Request SOC-gated run');
    await expectNoButton(page, 'New request');

    await gotoPortalRoute(page, 'integrations', baseUrl);
    await expectNoButton(page, 'Add provider');
  });

  test('viewer gets read-only detail surfaces instead of latent mutation controls', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page, VIEWER_SESSION);

    // Cold load of the excluded SOC console: the existing access gate denies it in place and hydrates nothing from it.
    const socRequests = [];
    const onSocRequest = (request) => {
      const { pathname } = new URL(request.url());
      if (pathname.startsWith('/internal/') || pathname.startsWith('/v1/soc') || pathname.includes('high-scale')) socRequests.push(`${request.method()} ${pathname}`);
    };
    page.on('request', onSocRequest);
    await page.goto(`${baseUrl}/app#internal-soc`, { waitUntil: 'networkidle', timeout: 60_000 });
    await expect(page).toHaveURL(/#internal-soc$/);
    await expect(page.getByRole('heading', { level: 1, name: 'You do not have access to this page.' })).toBeVisible();
    await expect(page.getByText('SOC console is not available to the viewer role. Nothing from it was loaded.')).toBeVisible();
    await expect(page.getByRole('link', { name: 'Go to Dashboard' }).or(page.getByRole('button', { name: 'Go to Dashboard' }))).toBeVisible();
    for (const label of ['Kill switch', 'Approve', 'Schedule', 'Start execution', 'Stop']) await expectNoButton(page, label);
    await expect(page.getByRole('navigation').getByRole('button', { name: 'SOC console', exact: true })).toHaveCount(0);
    expect(socRequests, 'a denied SOC console loads none of its data').toEqual([]);
    page.off('request', onSocRequest);

    await gotoPortalRoute(page, 'target-group-detail', baseUrl);
    await expect(page.locator('.route-access-notice')).toHaveCount(0);
    await expectNoButton(page, 'Add target');
    await expectNoButton(page, 'Import DNS zones');
    await expect(page.getByRole('button', { name: /^Remove target / })).toHaveCount(0);
    await expectNoButton(page, 'Run test');

    await gotoPortalRoute(page, 'target-detail', baseUrl);
    await expectNoButton(page, 'Detect WAF and CDN');
    await expectNoButton(page, 'Detect again');
    await page.getByRole('tab', { name: /^Validate/ }).click();
    const validatePanel = page.locator('#td-panel-validate');
    await expect(validatePanel.getByText('Read-only role', { exact: true })).toBeVisible();
    for (const label of ['Run selected check', 'Start check', 'Start all checks', 'Start detection']) await expectNoButton(page, label);
    await expect(validatePanel.getByRole('button', { name: /^(Review|Run|Start)\b/ })).toHaveCount(0);
    await expect(page.locator('dialog[open]')).toHaveCount(0);

    await gotoPortalRoute(page, 'finding-detail', baseUrl);
    await expectNoButton(page, 'Save triage');
    await expectNoButton(page, 'Accept risk');
    await expectNoButton(page, 'Close finding');
    await expectNoButton(page, 'Review retest');
    await expectNoButton(page, 'Start retest');
    await expect(page.locator('dialog[open]')).toHaveCount(0);
    await expect(page.getByText('Finding triage is read-only for your role.')).toBeVisible();
  });

  test('keeps fine-grained permitted actions for engineer and auditor roles', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page, ENGINEER_SESSION);

    await gotoPortalRoute(page, 'target-groups', baseUrl);
    await expect(page.getByRole('button', { name: 'Create target group' })).toBeVisible();

    await gotoPortalRoute(page, 'integrations', baseUrl);
    await page.getByRole('button', { name: 'Add provider' }).click();
    await expect(page.getByRole('button', { name: 'Add single domain' })).toBeEnabled();
    await expect(page.getByRole('button', { name: 'Continue to connect' })).toBeDisabled();
  });

  test('auditor can generate reports but cannot mutate findings or tenant settings', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page, AUDITOR_SESSION);

    await gotoPortalRoute(page, 'reports', baseUrl);
    const review = page.getByRole('button', { name: 'Review report' });
    await expect(review).toBeDisabled();
    await page.getByRole('radio', { name: /Technical/ }).check();
    await expect(review).toBeEnabled();
    await expect(page.getByText('Report generation is not available for your role.')).toHaveCount(0);

    await gotoPortalRoute(page, 'finding-detail', baseUrl);
    await expectNoButton(page, 'Accept risk');
    await expectNoButton(page, 'Close finding');

    await gotoPortalRoute(page, 'settings', baseUrl);
    await expectNoButton(page, 'Save organization');
  });
});
