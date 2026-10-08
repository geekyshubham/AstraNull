import { expect, test } from '@playwright/test';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import {
  fetchPortalReadinessScore,
  getPortalPlaywrightBaseUrl,
  portalOwnerHeaders,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  injectPortalDevHeadersSession,
} from '../../helpers/portal-playwright-session.mjs';

test.describe('portal core loop (Playwright)', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });
  test('dashboard renders readiness score from GET /v1/state', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    const apiScore = await fetchPortalReadinessScore(baseUrl);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', baseUrl);

    await expect(page.getByRole('heading', { name: 'Readiness overview', exact: true })).toBeVisible();
    await expect(page.getByText(String(apiScore), { exact: true }).first()).toBeVisible();
  });

  test('targets lists the exact baseline domain declared through the API', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    const targetsRes = await fetch(`${baseUrl}/v1/targets`, { headers: portalOwnerHeaders() });
    expect(targetsRes.ok).toBeTruthy();
    const targetsJson = await targetsRes.json();
    const seededTarget = (targetsJson.items ?? []).find((item) => item.id === PORTAL_BASELINE_IDS.targetId);
    expect(seededTarget?.value).toBe('checkout.acme.com');

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'targets', baseUrl);

    await expect(page.getByRole('heading', { name: 'Targets', exact: true })).toBeVisible();
    // The declared domain links directly to its target workspace.
    await expect(page.getByRole('link', { name: 'Open target checkout.acme.com', exact: true })).toBeVisible();
  });
});