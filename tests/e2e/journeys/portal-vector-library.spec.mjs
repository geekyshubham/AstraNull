import path from 'node:path';
import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { createServer as createViteServer } from 'vite';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import {
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  injectPortalDevHeadersSession,
  PORTAL_SESSION,
} from '../../helpers/portal-playwright-session.mjs';

let sourceBaseUrl = '';
let vite;

async function chooseFirstRealOption(scope, label) {
  const trigger = scope.getByRole('button', { name: label, exact: true });
  await expect(trigger).toBeEnabled();
  await trigger.click();
  const listbox = scope.getByRole('listbox', { name: label, exact: true });
  const options = listbox.getByRole('option');
  await expect(options.nth(1)).toBeVisible();
  await options.nth(1).click();
}

test.describe('target-first check library workflow', () => {
  test.beforeAll(async () => {
    const { baseUrl: apiBaseUrl } = await startPortalPlaywrightServer();
    vite = await createViteServer({
      configFile: path.resolve('vite.config.ts'),
      logLevel: 'silent',
      server: {
        host: '127.0.0.1',
        port: 0,
        strictPort: false,
        proxy: { '/v1': apiBaseUrl, '/ready': apiBaseUrl, '/internal': apiBaseUrl },
      },
    });
    await vite.listen();
    const address = vite.httpServer?.address();
    if (!address || typeof address === 'string') throw new Error('Vite source server did not bind.');
    sourceBaseUrl = `http://127.0.0.1:${address.port}`;
  });

  test.afterAll(async () => {
    await vite?.close();
    await stopPortalPlaywrightServer();
  });

  test('renders bounded pages and launches only after exact scope and confirmation', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    const vectorReads = [];
    const runBodies = [];
    page.on('request', (request) => {
      if (request.method() === 'GET' && /\/v1\/vectors\?/.test(request.url())) vectorReads.push(request.url());
    });
    await page.route('**/v1/test-runs', async (route) => {
      if (route.request().method() !== 'POST') return route.continue();
      runBodies.push(route.request().postDataJSON());
      await route.fulfill({
        status: 201,
        contentType: 'application/json',
        body: JSON.stringify({ run: { id: 'run_vector_browser', status: 'running' } }),
      });
    });

    await gotoPortalRoute(page, 'checks', sourceBaseUrl);
    await expect(page.getByRole('heading', { level: 1, name: 'Check library' })).toBeVisible({ timeout: 20_000 });
    const counts = page.getByLabel('Catalog and check counts');
    await expect(counts.locator('div').filter({ hasText: 'Catalog vectors' }).locator('dd').first()).toHaveText('721', { timeout: 20_000 });
    await expect(counts.locator('div').filter({ hasText: 'Fit this target' }).locator('dd').first()).toHaveText('No target');
    await expect(page.locator('.design-variant-switch')).toHaveCount(0);
    await expect(page.locator('.vector-library-table tbody tr')).toHaveCount(25, { timeout: 20_000 });
    expect(vectorReads).toHaveLength(8);
    const axe = await new AxeBuilder({ page }).include('.vector-library-page').analyze();
    expect(axe.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact ?? ''))).toEqual([]);
    const uniqueVectorReads = [...new Set(vectorReads.map((value) => new URL(value).search))];
    expect(uniqueVectorReads).toHaveLength(8);
    expect(uniqueVectorReads.every((value) => new URLSearchParams(value).get('limit') === '100')).toBe(true);
    await expect(page.getByText(/Page 1 of 29/)).toBeVisible();

    await chooseFirstRealOption(page, 'Target');
    await expect(page.getByText('Target selected', { exact: true })).toBeVisible();
    await expect(page).toHaveURL(/#checks\?target=/);
    await expect(counts.locator('div').filter({ hasText: 'Fit this target' }).locator('dd').first()).toHaveText(/^\d+$/);

    const search = page.getByPlaceholder('Name, ID, protocol, exposure, control');
    await search.fill('APP-001');
    const appRow = page.locator('.vector-library-table tbody tr').filter({ hasText: 'APP-001' });
    await expect(appRow).toHaveCount(1);
    await expect(appRow).toContainText('Bounded check available');
    await appRow.getByRole('button', { name: 'Review' }).click();

    const detail = page.locator('dialog.form-modal[open]');
    await expect(detail).toContainText('What it checks');
    await expect(detail).toContainText('Why it matters');
    await expect(detail).toContainText('Expected protection');
    await expect(detail).toContainText('Semantic-safe evidence');
    await expect(detail.getByRole('heading', { name: 'Mapped checks' })).toBeVisible();
    await expect(detail.getByRole('link').first()).toHaveAttribute('href', new RegExp(`#check-detail\\?id=[^&]+&target=${PORTAL_BASELINE_IDS.targetId}`));
    await expect(detail.getByRole('button', { name: 'Review run' })).toBeDisabled();
    await chooseFirstRealOption(detail, 'Mapped bounded check');
    await detail.getByRole('button', { name: 'Review run' }).click();

    const confirm = page.locator('dialog.modal-confirm[open]');
    await expect(confirm).toContainText(PORTAL_BASELINE_IDS.targetId);
    await expect(confirm).toContainText('Evidence limit:');
    await expect(confirm).toContainText('rechecked by the server before anything is sent');
    expect(runBodies).toHaveLength(0);
    await confirm.getByRole('button', { name: 'Start bounded check' }).click();
    await expect.poll(() => runBodies.length).toBe(1);
    expect(runBodies[0]).toMatchObject({
      target_id: PORTAL_BASELINE_IDS.targetId,
    });
    expect(runBodies[0].check_id).toBeTruthy();
    expect(runBodies[0]).not.toHaveProperty('target_group_id');
    await expect(page.getByRole('status').filter({ hasText: 'started on' })).toBeVisible();
  });

  test('keeps SOC-governed and monitor-only vectors non-runnable', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    const runPosts = [];
    page.on('request', (request) => {
      if (request.method() === 'POST' && /\/v1\/test-runs$/.test(request.url())) runPosts.push(request.url());
    });
    await gotoPortalRoute(page, 'checks', sourceBaseUrl);
    const search = page.getByPlaceholder('Name, ID, protocol, exposure, control');

    await search.fill('NET-016');
    await page.locator('.vector-library-table tbody tr').filter({ hasText: 'NET-016' }).getByRole('button', { name: 'Review' }).click();
    let detail = page.locator('dialog.form-modal[open]');
    await expect(detail).toContainText('SOC-gated only');
    await expect(detail).toContainText('supplemental declaration or transport evidence is not an exposure result');
    await expect(detail.getByRole('button', { name: 'Review run' })).toHaveCount(0);
    await detail.getByRole('button', { name: 'Close dialog' }).click();

    await search.fill('AMP-073');
    await page.locator('.vector-library-table tbody tr').filter({ hasText: 'AMP-073' }).getByRole('button', { name: 'Review' }).click();
    detail = page.locator('dialog.form-modal[open]');
    await expect(detail).toContainText('Monitor only');
    await expect(detail).toContainText('no active outside-in result is claimed');
    await expect(detail.getByRole('button', { name: 'Review run' })).toHaveCount(0);
    expect(runPosts).toHaveLength(0);
  });


  test('clears a stale target on refresh without substituting another target', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    let removeTargets = false;
    await page.route('**/v1/targets', async (route) => {
      const response = await route.fetch();
      if (!removeTargets || route.request().method() !== 'GET') return route.fulfill({ response });
      const payload = await response.json();
      await route.fulfill({
        response,
        contentType: 'application/json',
        body: JSON.stringify({ ...payload, items: [] }),
      });
    });
    await gotoPortalRoute(page, 'checks', sourceBaseUrl);
    await chooseFirstRealOption(page, 'Target');
    await expect(page.getByText('Target selected', { exact: true })).toBeVisible();

    removeTargets = true;
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(page.getByText(/from the link is not visible in this workspace\. No other target was substituted\./)).toBeVisible();
    await expect(page.locator('.vector-target-note')).toContainText('Browsing without a target');
    await expect(page.getByRole('button', { name: 'Target', exact: true })).toBeDisabled();
    await page.getByRole('button', { name: 'Clear target' }).click();
    await expect(page).not.toHaveURL(/target=/);
  });

  test('restores the target, search, and page from a shared address', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await page.goto(`${sourceBaseUrl}/app#checks?target=${PORTAL_BASELINE_IDS.targetId}&q=AMP&page=2`, { waitUntil: 'networkidle' });
    await expect(page.locator('.vector-target-note')).toContainText('checkout.acme.com', { timeout: 20_000 });
    await expect(page.getByPlaceholder('Name, ID, protocol, exposure, control')).toHaveValue('AMP');
    await expect(page.getByText(/^Page 2 of /)).toBeVisible();
  });

  test('restores focus to Review after detail closes by button or Escape', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'checks', sourceBaseUrl);
    await page.getByPlaceholder('Name, ID, protocol, exposure, control').fill('APP-003');
    const review = page.locator('.vector-library-table tbody tr').filter({ hasText: 'APP-003' }).getByRole('button', { name: 'Review' });
    await review.click();
    let detail = page.locator('dialog.form-modal[open]');
    await detail.getByRole('button', { name: 'Close dialog' }).click();
    await expect(review).toBeFocused();

    await review.click();
    detail = page.locator('dialog.form-modal[open]');
    await expect(detail).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(detail).toBeHidden();
    await expect(review).toBeFocused();
  });
  test('keeps bounded launch controls hidden for read-only roles', async ({ page }) => {
    await injectPortalDevHeadersSession(page, { ...PORTAL_SESSION, role: 'viewer' });
    const runPosts = [];
    await page.setViewportSize({ width: 390, height: 740 });
    page.on('request', (request) => {
      if (request.method() === 'POST' && /\/v1\/test-runs$/.test(request.url())) runPosts.push(request.url());
    });
    await gotoPortalRoute(page, 'checks', sourceBaseUrl);
    await chooseFirstRealOption(page, 'Target');
    await expect(page.getByLabel('Catalog and check counts')).toContainText('Review only');
    const search = page.getByPlaceholder('Name, ID, protocol, exposure, control');
    await search.fill('APP-001');
    await page.locator('.vector-library-table tbody tr').filter({ hasText: 'APP-001' }).getByRole('button', { name: 'Review' }).click();
    const detail = page.locator('dialog.form-modal[open]');
    await expect(detail).toContainText('only owners, admins, and engineers can start bounded checks');
    await expect(detail.getByRole('button', { name: 'Mapped bounded check' })).toHaveCount(0);
    await expect(detail.getByRole('button', { name: 'Review run' })).toHaveCount(0);
    expect(runPosts).toHaveLength(0);
  });
});