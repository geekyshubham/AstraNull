/**
 * Browser regression for the notification channels panel on Integrations
 * (UNCOMMITTED_CHANGES_REVIEW G03 / F04): connect dialog create, read, validation and server
 * errors, load error + Retry, role permission states, turn off/on and remove controls, and the
 * refresh race where an older response must never overwrite a newer one.
 *
 * The dev server stores rules in memory only; creating a rule does not send anything to the
 * destination. Every test restarts the server so rule state is isolated.
 */
import { expect, test } from '@playwright/test';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  PORTAL_AUDITOR_SESSION,
  gotoPortalRoute,
  injectPortalDevHeadersSession,
} from '../../helpers/portal-playwright-session.mjs';

const SLACK_URL = 'https://hooks.slack.com/services/T0000000/B0000000/testtoken000000';
const NOTIFICATIONS_PATH = /\/v1\/notifications(\?.*)?$/;

const PORTAL_VIEWER_SESSION = Object.freeze({
  mode: 'dev-headers',
  principal: 'customer',
  tenant_id: PORTAL_BASELINE_IDS.tenantId,
  user_id: 'usr_viewer',
  role: 'viewer',
});

const VIEWPORTS = [
  { name: 'mobile', width: 375, height: 812 },
  { name: 'desktop', width: 1440, height: 900 },
];
const THEMES = ['dark', 'light'];

/** @param {import('@playwright/test').Page} page */
function channelsPanel(page) {
  return page.getByRole('region', { name: 'Notification channels' });
}

/** @param {import('@playwright/test').Locator} panel */
function tiles(panel) {
  return panel.getByRole('list', { name: 'Available notification channels' });
}

/** @param {import('@playwright/test').Page} page */
function connectDialog(page) {
  return page.locator('dialog.form-modal[open]').filter({ has: page.getByRole('heading', { name: 'Connect Slack' }) });
}

/**
 * @param {import('@playwright/test').Page} page
 * @param {string} theme
 */
async function useTheme(page, theme) {
  await page.addInitScript((value) => {
    try { localStorage.setItem('astranull.theme', value); } catch { /* storage blocked */ }
  }, theme);
}

/** @param {import('@playwright/test').Page} page */
async function openIntegrations(page) {
  await gotoPortalRoute(page, 'integrations', getPortalPlaywrightBaseUrl());
  const panel = channelsPanel(page);
  await panel.scrollIntoViewIfNeeded();
  await expect(panel).toBeVisible();
  return panel;
}

/**
 * @param {import('@playwright/test').Page} page
 * @param {import('@playwright/test').Locator} panel
 */
async function connectSlackThroughDialog(page, panel) {
  await tiles(panel).getByRole('button', { name: 'Connect Slack', exact: true }).click();
  const dialog = connectDialog(page);
  await expect(dialog).toBeVisible();
  await dialog.getByLabel('Slack webhook URL').fill(SLACK_URL);
  await dialog.getByRole('button', { name: 'Connect Slack', exact: true }).click();
  await expect(dialog).toHaveCount(0);
}

test.describe('notification channels panel', () => {
  test.beforeEach(async () => {
    await startPortalPlaywrightServer();
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  for (const viewport of VIEWPORTS) {
    for (const theme of THEMES) {
      test(`connect, turn off/on and remove a Slack channel (${viewport.name}, ${theme})`, async ({ page }) => {
        const pageErrors = [];
        page.on('pageerror', (error) => pageErrors.push(error.message));
        await page.setViewportSize({ width: viewport.width, height: viewport.height });
        await useTheme(page, theme);
        await injectPortalDevHeadersSession(page);
        const panel = await openIntegrations(page);

        await expect(panel.getByText('No channels connected yet')).toBeVisible();
        await expect(tiles(panel).getByRole('button', { name: 'Connect Slack', exact: true })).toBeEnabled();

        await connectSlackThroughDialog(page, panel);
        await expect(panel.getByRole('status').filter({ hasText: 'Slack connected (' })).toBeVisible();
        await expect(panel.getByRole('button', { name: 'Add another Slack channel' })).toBeVisible();
        await expect(panel.getByText('No channels connected yet')).toHaveCount(0);
        // Only the redacted preview reaches the browser.
        await expect(panel).not.toContainText('testtoken000000');

        const turnOff = panel.getByRole('button', { name: /^Turn off Slack channel/ });
        await expect(turnOff).toBeVisible();
        await turnOff.click();
        await expect(panel.getByRole('status').filter({ hasText: 'Slack channel turned off.' })).toBeVisible();
        await expect(panel.getByText('0 of 1 enabled')).toBeVisible();
        await expect(panel.getByRole('row').filter({ hasText: 'Slack' }).filter({ hasText: 'Disabled' })).toHaveCount(1);

        const turnOn = panel.getByRole('button', { name: /^Turn on Slack channel/ });
        await turnOn.click();
        await expect(panel.getByRole('status').filter({ hasText: 'Slack channel turned on.' })).toBeVisible();
        await expect(panel.getByText('1 of 1 enabled')).toBeVisible();
        await expect(panel.getByRole('row').filter({ hasText: 'Slack' }).filter({ hasText: 'Enabled' })).toHaveCount(1);

        await panel.getByRole('button', { name: /^Remove Slack channel/ }).click();
        const confirm = page.locator('dialog.modal-confirm[open]').filter({ has: page.getByRole('heading', { name: 'Remove Slack channel?' }) });
        await expect(confirm).toBeVisible();
        await confirm.getByRole('button', { name: 'Remove channel' }).click();
        await expect(confirm).toHaveCount(0);
        await expect(panel.getByRole('status').filter({ hasText: 'Slack channel removed. Its delivery history is kept.' })).toBeVisible();
        await expect(panel.getByText('No channels connected yet')).toBeVisible();

        expect(pageErrors).toEqual([]);
      });
    }
  }

  test('connect dialog validates locally, shows server errors, and closes with Escape', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    let postMode = 'reject-400';
    await page.route(NOTIFICATIONS_PATH, async (route) => {
      if (route.request().method() !== 'POST') return route.fallback();
      if (postMode === 'reject-400') {
        return route.fulfill({ status: 400, json: { error: 'invalid_webhook_destination' } });
      }
      if (postMode === 'fail-500') {
        return route.fulfill({ status: 500, json: { error: 'internal_error', message: 'db host pg-internal-01 down' } });
      }
      return route.fallback();
    });
    const panel = await openIntegrations(page);

    // Keyboard: open the dialog from the tile button.
    await tiles(panel).getByRole('button', { name: 'Connect Slack', exact: true }).focus();
    await page.keyboard.press('Enter');
    const dialog = connectDialog(page);
    await expect(dialog).toBeVisible();
    const input = dialog.getByLabel('Slack webhook URL');
    const submit = dialog.getByRole('button', { name: 'Connect Slack', exact: true });

    // Defaults: high-severity and high-scale triggers on, channel on.
    await expect(dialog.getByRole('checkbox', { name: /High-severity finding/ })).toBeChecked();
    await expect(dialog.getByRole('checkbox', { name: /High-scale state change/ })).toBeChecked();
    await expect(dialog.getByRole('checkbox', { name: 'Turn this channel on now' })).toBeChecked();

    // Empty destination.
    await submit.click();
    await expect(dialog.locator('.nc-field-error[role="alert"]')).toContainText('Enter the slack webhook url');
    await expect(input).toBeFocused();
    await expect(input).toHaveAttribute('aria-invalid', 'true');

    // Plain http to a public host is rejected before any request is made.
    await input.fill('http://example.com/hook');
    await submit.click();
    await expect(dialog.locator('.nc-field-error[role="alert"]')).toContainText('Use an https:// URL');

    // No trigger selected.
    await input.fill(SLACK_URL);
    await dialog.getByRole('checkbox', { name: /High-severity finding/ }).uncheck();
    await dialog.getByRole('checkbox', { name: /High-scale state change/ }).uncheck();
    await submit.click();
    await expect(dialog.locator('.nc-field-error[role="alert"]')).toBeVisible();
    await dialog.getByRole('checkbox', { name: /High-severity finding/ }).check();

    // Server 4xx: humanized code, dialog stays open with the typed value.
    await submit.click();
    const banner = dialog.locator('.form-banner.error[role="alert"]');
    await expect(banner).toBeVisible();
    await expect(banner).toContainText(/webhook/i);
    await expect(input).toHaveValue(SLACK_URL);

    // Server 5xx: fixed safe copy, never server diagnostic text.
    postMode = 'fail-500';
    await submit.click();
    await expect(banner).toBeVisible();
    await expect(banner).not.toContainText('pg-internal-01');

    // Escape closes the native dialog without creating anything.
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
    await expect(panel.getByText('No channels connected yet')).toBeVisible();
  });

  test('a failed channel load shows an error with Retry that recovers', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    let failGets = true;
    await page.route(NOTIFICATIONS_PATH, async (route) => {
      if (route.request().method() === 'GET' && failGets) {
        return route.fulfill({ status: 503, json: { error: 'service_unavailable' } });
      }
      return route.fallback();
    });
    const panel = await openIntegrations(page);
    const loadError = panel.locator('.table-load-error[role="alert"]');
    await expect(loadError).toBeVisible();
    await expect(loadError).toContainText('Could not load');

    failGets = false;
    await loadError.getByRole('button', { name: 'Retry' }).click();
    await expect(loadError).toHaveCount(0);
    await expect(panel.getByText('No channels connected yet')).toBeVisible();
  });

  test('auditor can read channels but every write control is disabled', async ({ page }) => {
    await injectPortalDevHeadersSession(page, PORTAL_AUDITOR_SESSION);
    const panel = await openIntegrations(page);
    await expect(panel.getByText('No channels connected yet')).toBeVisible();
    for (const label of ['Connect Slack', 'Connect Microsoft Teams', 'Connect Email', 'Connect Webhook']) {
      await expect(tiles(panel).getByRole('button', { name: label, exact: true })).toBeDisabled();
    }
    await expect(panel.getByText('Owner or admin role is required to connect or change channels.').first()).toBeVisible();
    await expect(page.locator('dialog.form-modal[open]')).toHaveCount(0);
  });

  test('viewer sees a restricted card instead of channel data', async ({ page }) => {
    await injectPortalDevHeadersSession(page, PORTAL_VIEWER_SESSION);
    await gotoPortalRoute(page, 'integrations', getPortalPlaywrightBaseUrl());
    await expect(page.getByText('Notification channels are restricted')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Connect Slack', exact: true })).toHaveCount(0);
  });

  for (const staleOutcome of ['empty list', 'server failure']) {
    test(`an older refresh resolving last (${staleOutcome}) never overwrites a newer connect (F04)`, async ({ page }) => {
      await injectPortalDevHeadersSession(page);
      /** @type {null | (() => void)} */
      let releaseHeld = null;
      let holdNextGet = false;
      let heldStarted = false;
      await page.route(NOTIFICATIONS_PATH, async (route) => {
        if (route.request().method() !== 'GET' || !holdNextGet) return route.fallback();
        holdNextGet = false;
        heldStarted = true;
        await new Promise((resolve) => { releaseHeld = resolve; });
        if (staleOutcome === 'empty list') {
          return route.fulfill({ json: { rules: [], events: [], latest_deliveries: {} } });
        }
        return route.fulfill({ status: 500, json: { error: 'internal_error' } });
      });

      const panel = await openIntegrations(page);
      await expect(panel.getByText('No channels connected yet')).toBeVisible();

      // Older request: a manual refresh that stays in flight.
      holdNextGet = true;
      await panel.getByRole('button', { name: 'Refresh notification channels' }).click();
      await expect.poll(() => heldStarted).toBe(true);
      await expect(panel.getByRole('button', { name: 'Refreshing notification channels' })).toBeDisabled();

      // Newer request: connecting a channel reloads with the saved rule.
      await connectSlackThroughDialog(page, panel);
      await expect(panel.getByRole('button', { name: 'Add another Slack channel' })).toBeVisible();

      // Release the stale response, then give React time to (not) apply it.
      releaseHeld?.();
      await page.waitForTimeout(400);
      await expect(panel.getByRole('button', { name: 'Add another Slack channel' })).toBeVisible();
      await expect(panel.getByText('No channels connected yet')).toHaveCount(0);
      await expect(panel.locator('.table-load-error')).toHaveCount(0);
      await expect(panel.getByRole('button', { name: 'Refresh notification channels' })).toBeEnabled();
    });
  }
});
