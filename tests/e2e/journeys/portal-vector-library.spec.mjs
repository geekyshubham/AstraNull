import path from 'node:path';
import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { createPortalSourceServer as createViteServer } from '../../helpers/portal-playwright-server.mjs';
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

// Check-first catalog: a vector lives inside the check group that covers it. Search narrows the
// catalog to that vector's check(s); expand the surfaced groups, then act on the nested vector row.
async function openVectorAction(page, vectorId, actionLabel) {
  await page.getByPlaceholder('Name, ID, protocol, exposure, control').fill(vectorId);
  const groups = page.locator('.vector-check-group');
  await expect(groups.first()).toBeVisible({ timeout: 20_000 });
  const toggles = page.locator('.vector-check-toggle');
  for (let index = 0, total = await toggles.count(); index < total; index += 1) {
    const toggle = toggles.nth(index);
    if ((await toggle.getAttribute('aria-expanded')) !== 'true') await toggle.click();
  }
  await page.getByRole('button', { name: actionLabel, exact: true }).click();
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
    await expect(page.locator('.vector-check-group').first()).toBeVisible({ timeout: 20_000 });
    expect(vectorReads).toHaveLength(8);
    const axe = await new AxeBuilder({ page }).include('.vector-library-page').analyze();
    expect(axe.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact ?? ''))).toEqual([]);
    const uniqueVectorReads = [...new Set(vectorReads.map((value) => new URL(value).search))];
    expect(uniqueVectorReads).toHaveLength(8);
    expect(uniqueVectorReads.every((value) => new URLSearchParams(value).get('limit') === '100')).toBe(true);
    await expect(page.getByText(/Page 1 of \d+/)).toBeVisible();

    await chooseFirstRealOption(page, 'Target');
    await expect(page.getByText('Target selected', { exact: true })).toBeVisible();
    await expect(page).toHaveURL(/#checks\?target=/);
    await expect(counts.locator('div').filter({ hasText: 'Fit this target' }).locator('dd').first()).toHaveText(/^\d+$/);

    await expect(page.getByRole('button', { name: 'Fit for target', exact: true })).toContainText('Bounded check available');
    await openVectorAction(page, 'EVA-004', 'Details for EVA-004');

    const detail = page.locator('dialog.form-modal[open]');
    await expect(detail).toContainText('What it checks');
    await expect(detail).toContainText('Why it matters');
    await expect(detail).toContainText('Expected protection');
    await expect(detail).toContainText('Semantic-safe evidence');
    await expect(detail.getByRole('heading', { name: 'Mapped checks' })).toBeVisible();
    await expect(detail.locator('.vector-mapped-run').first()).toHaveText(/Not run on this target|·/);
    const railBeforeGrid = await detail.locator('.vector-detail').evaluate((root) => {
      const rail = root.querySelector('.vector-detail-rail');
      const grid = root.querySelector('.vector-detail-grid');
      return Boolean(rail && grid && (rail.compareDocumentPosition(grid) & Node.DOCUMENT_POSITION_FOLLOWING));
    });
    expect(railBeforeGrid).toBe(true);
    await expect(detail.getByRole('link').first()).toHaveAttribute('href', new RegExp(`#check-detail\\?id=[^&]+&target=${PORTAL_BASELINE_IDS.targetId}`));
    await expect(detail.getByRole('button', { name: 'Review run' })).toBeDisabled();
    await chooseFirstRealOption(detail, 'Mapped bounded check');
    await detail.getByRole('button', { name: 'Review run' }).click();

    const confirm = page.locator('dialog.modal-confirm[open]');
    await expect(confirm).toContainText(PORTAL_BASELINE_IDS.targetId);
    await expect(confirm.getByRole('heading')).toContainText(/^Start .+ on checkout\.acme\.com\?$/);
    const review = confirm.locator('dl.td-review-list');
    await expect(review.locator('dt')).toContainText(['Target', 'Check', 'Upper bound']);
    await expect(review).toContainText('Evidence limit');
    await expect(review).toContainText('Catalog vector');
    await expect(review.locator('div').filter({ hasText: 'Upper bound' }).locator('dd')).toHaveText(/^(\d[\d,]* requests?(, [\d,]+ ms timeout)?|Not recorded in the catalog)$/);
    await expect(confirm).toContainText('The server re-checks ownership, safe windows, rate and concurrency gates when you start.');
    await expect(confirm).toContainText('A bounded check does not measure volumetric capacity.');
    expect(runBodies).toHaveLength(0);
    await confirm.getByRole('button', { name: 'Start check', exact: true }).click();
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

    await openVectorAction(page, 'NET-016', 'Details for NET-016');
    let detail = page.locator('dialog.form-modal[open]');
    await expect(detail).toContainText('SOC-gated only');
    await expect(detail).toContainText('supplemental declaration or transport evidence is not an exposure result');
    await expect(detail.getByRole('button', { name: 'Review run' })).toHaveCount(0);
    await detail.getByRole('button', { name: 'Close dialog' }).click();

    await openVectorAction(page, 'AMP-073', 'Review AMP-073');
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
    await page.goto(`${sourceBaseUrl}/app#checks?target=${PORTAL_BASELINE_IDS.targetId}&fit=all&q=AMP&page=2`, { waitUntil: 'networkidle' });
    await expect(page.locator('.vector-target-note')).toContainText('checkout.acme.com', { timeout: 20_000 });
    await expect(page.getByRole('button', { name: 'Fit for target', exact: true })).toContainText('Any fit');
    await expect(page.getByPlaceholder('Name, ID, protocol, exposure, control')).toHaveValue('AMP');
    await expect(page.getByText(/^Page \d+ of \d+/)).toBeVisible();
  });

  test('narrows to bounded-check fit when a target is chosen and can show every fit', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'checks', sourceBaseUrl);
    await chooseFirstRealOption(page, 'Target');
    const fit = page.getByRole('button', { name: 'Fit for target', exact: true });
    await expect(fit).toContainText('Bounded check available');
    await expect(page).toHaveURL(/fit=safe_runnable/);
    await page.getByPlaceholder('Name, ID, protocol, exposure, control').fill('AMP-073');
    await expect(page.getByText('No checks match these filters.')).toBeVisible();
    await page.getByRole('button', { name: 'Show all fits', exact: true }).click();
    await expect(fit).toContainText('Any fit');
    // AMP-073 is monitor-only, so it is listed under "not mapped to a runnable check" rather than a check group.
    await expect(page.getByRole('button', { name: /not mapped to a runnable check/ })).toBeVisible();
    await expect(page).toHaveURL(/fit=all/);
  });

  test('restores focus to Details after detail closes by button or Escape', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'checks', sourceBaseUrl);
    await page.getByPlaceholder('Name, ID, protocol, exposure, control').fill('APP-003');
    const expandToggles = page.locator('.vector-check-toggle');
    await expect(expandToggles.first()).toBeVisible({ timeout: 20_000 });
    for (let index = 0, total = await expandToggles.count(); index < total; index += 1) {
      const toggle = expandToggles.nth(index);
      if ((await toggle.getAttribute('aria-expanded')) !== 'true') await toggle.click();
    }
    const review = page.getByRole('button', { name: 'Details for APP-003', exact: true });
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
    await openVectorAction(page, 'EVA-004', 'Details for EVA-004');
    const detail = page.locator('dialog.form-modal[open]');
    await expect(detail).toContainText('only owners, admins, and engineers can start bounded checks');
    await expect(detail.getByRole('button', { name: 'Mapped bounded check' })).toHaveCount(0);
    await expect(detail.getByRole('button', { name: 'Review run' })).toHaveCount(0);
    expect(runPosts).toHaveLength(0);
  });
});