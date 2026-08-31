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

/**
 * FT-CONFIRM-01 — destructive confirmations are in-app, and actions report back.
 *
 * `window.confirm` is not merely a style problem here: an automation/CDP session suppresses
 * the native dialog and the tab wedges inside confirm() forever, so the run-start, force-
 * finalize and retention-save paths were unreachable under automation and inconsistent with
 * the app's own state-driven confirm modal. These tests assert the modal shape AND that no
 * native dialog is ever raised — a regression to `window.confirm` fails on the second
 * assertion even if the first somehow passes.
 *
 * Also covers the connector Poll feedback path (banner + connector refetch) and a cold
 * deep-link into a role-gated route with the role already in sessionStorage.
 */

/**
 * Fails the test if the page ever raises a native dialog, and dismisses it so the run can
 * finish instead of hanging. Playwright auto-dismisses only when no handler is attached.
 */
function forbidNativeDialogs(page) {
  const raised = [];
  page.on('dialog', (dialog) => {
    raised.push(`${dialog.type()}: ${dialog.message()}`);
    void dialog.dismiss();
  });
  return raised;
}

function applyConfirmationFixture(store) {
  applyPortalBaselineReadinessBoost(store);
  const connector = store.wafConnectors.find((entry) => entry.provider === 'cloudflare');
  if (connector) {
    connector.secret_id = 'sec_playwright_credential';
    connector.config_json = { ...connector.config_json, read_only: true };
  }
}

test.describe('portal in-app confirmations (FT-CONFIRM-01)', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: applyConfirmationFixture });
  });
  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('Start safe run confirms in an in-app dialog and only POSTs after confirming', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);
    const nativeDialogs = forbidNativeDialogs(page);

    /** @type {string[]} */
    const runPosts = [];
    page.on('request', (req) => {
      if (req.method() === 'POST' && /\/v1\/test-runs$/.test(req.url())) runPosts.push(req.url());
    });

    await gotoPortalRoute(page, 'runs', baseUrl);
    const startBtn = page.getByRole('button', { name: 'Run checks' }).first();
    await expect(startBtn).toBeEnabled({ timeout: 15_000 });
    await startBtn.click();

    const confirm = page.locator('dialog.modal-confirm[open]');
    await expect(confirm).toBeVisible({ timeout: 10_000 });
    await expect(confirm).toContainText('Start a validation run?');
    // The confirmation still shows the immutable run scope before execution.
    await expect(confirm).toContainText(/Target group:/);
    await expect(confirm).toContainText(/Target:/);
    await expect(confirm).toContainText(/Check:/);
    expect(runPosts, 'opening the confirm must not start a run').toHaveLength(0);

    await confirm.getByRole('button', { name: 'Start run' }).click();
    await expect(confirm).toBeHidden({ timeout: 10_000 });
    await expect
      .poll(() => runPosts.length, { timeout: 10_000 })
      .toBeGreaterThan(0);
    expect(nativeDialogs, 'no native window.confirm may be raised').toEqual([]);
  });

  test('cancelling the safe-run confirm fires no request', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);
    const nativeDialogs = forbidNativeDialogs(page);

    /** @type {string[]} */
    const runPosts = [];
    page.on('request', (req) => {
      if (req.method() === 'POST' && /\/v1\/test-runs$/.test(req.url())) runPosts.push(req.url());
    });

    await gotoPortalRoute(page, 'runs', baseUrl);
    const startBtn = page.getByRole('button', { name: 'Run checks' }).first();
    await expect(startBtn).toBeEnabled({ timeout: 15_000 });
    await startBtn.click();

    const confirm = page.locator('dialog.modal-confirm[open]');
    await expect(confirm).toBeVisible({ timeout: 10_000 });
    await confirm.getByRole('button', { name: 'Cancel' }).click();
    await expect(confirm).toBeHidden({ timeout: 10_000 });
    expect(runPosts, 'declining the confirm must not start a run').toHaveLength(0);
    expect(nativeDialogs).toEqual([]);
  });

  test('retention save confirms in an in-app dialog and PATCHes only on confirm', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);
    const nativeDialogs = forbidNativeDialogs(page);

    /** @type {string[]} */
    const patches = [];
    page.on('request', (req) => {
      if (req.method() === 'PATCH' && /\/v1\/tenants\/current$/.test(req.url())) patches.push(req.url());
    });

    await gotoPortalRoute(page, 'settings', baseUrl);
    await page.getByRole('tab', { name: 'Privacy' }).click();
    const saveBtn = page.getByRole('button', { name: 'Save retention policy' }).first();
    await expect(saveBtn).toBeEnabled({ timeout: 15_000 });
    await saveBtn.click();

    const confirm = page.locator('dialog.modal-confirm[open]');
    await expect(confirm).toBeVisible({ timeout: 10_000 });
    await expect(confirm).toContainText('Save retention settings?');
    await expect(confirm).toContainText('Shorter windows can immediately purge stored metadata.');
    expect(patches, 'opening the confirm must not save').toHaveLength(0);

    await confirm.getByRole('button', { name: 'Save retention policy' }).click();
    await expect
      .poll(() => patches.length, { timeout: 10_000 })
      .toBeGreaterThan(0);
    expect(nativeDialogs).toEqual([]);
  });

  test('connector Poll reports back in a live-region banner and refetches connectors', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);
    await page.route('**/v1/connectors/*/poll', async (route) => {
      if (route.request().method() !== 'POST') return route.continue();
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          poll_job: { status: 'completed_empty', snapshot_count: 0, created_at: new Date().toISOString() },
          snapshots: [],
        }),
      });
    });

    /** @type {string[]} */
    const polls = [];
    /** @type {string[]} */
    const connectorReads = [];
    page.on('request', (req) => {
      const url = req.url();
      if (req.method() === 'POST' && /\/v1\/connectors\/[^/]+\/poll$/.test(url)) polls.push(url);
      if (req.method() === 'GET' && /\/v1\/connectors(\?|$)/.test(url)) connectorReads.push(url);
    });

    await gotoPortalRoute(page, 'integrations', baseUrl);
    const pollBtn = page.getByRole('button', { name: 'Poll', exact: true }).first();
    await expect(pollBtn).toBeEnabled({ timeout: 15_000 });
    const readsBefore = connectorReads.length;
    await pollBtn.click();

    // Feedback must reach assistive tech, not just the pixels: role=status|alert.
    const banner = page.locator('[role="status"], [role="alert"]').filter({ hasText: /poll/i }).first();
    await expect(banner).toBeVisible({ timeout: 15_000 });
    expect(polls, 'Poll must POST /v1/connectors/:id/poll').not.toHaveLength(0);
    // The LAST POLL cell is rendered from the connectors dataset, so it can only change if
    // the row is refetched after the action.
    await expect
      .poll(() => connectorReads.length, { timeout: 15_000 })
      .toBeGreaterThan(readsBefore);
    await expect(page.locator('table').filter({ hasText: 'Last poll' }).first()).toBeVisible();
  });

  test('cold deep-link into a role-gated route keeps the route when the role is already stored', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    // `release-evidence` is narrowed to the auditor role in lib/route-access; the access gate
    // redirects to #dashboard for anyone else. A cold load must evaluate that gate against the
    // stored session, never against a default one that has not hydrated yet.
    await injectPortalDevHeadersSession(page, { ...PORTAL_SESSION, role: 'auditor' });

    for (let attempt = 0; attempt < 5; attempt += 1) {
      await page.goto(`${baseUrl}/app#release-evidence`, { waitUntil: 'networkidle', timeout: 60_000 });
      await expect(page.locator('#root > *')).not.toHaveCount(0);
      // Give any late access-gate effect a chance to fire before asserting.
      await expect
        .poll(async () => new URL(page.url()).hash, { timeout: 5_000, intervals: [250, 250, 250, 500] })
        .toBe('#release-evidence');
    }
  });
});
