import { expect, test } from '@playwright/test';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  injectPortalSessionForSurface,
} from '../../helpers/portal-playwright-session.mjs';
import { NAV_ROUTE_IDS } from '../../helpers/portal-routes.mjs';

// Measured 22 /v1 requests for boot + 7 navigations (2026-08, three consecutive runs, no
// variance). 45 keeps ~2x headroom so a fetch regression trips the budget instead of hiding
// under it; re-tune from the OBSERVED_V1_REQUESTS line this spec logs.
const REQUEST_BUDGET = 45;
const ROUTES_TO_NAVIGATE = [
  { routeId: 'target-groups', label: 'Target groups' },
  { routeId: 'agents', label: 'Agents' },
  { routeId: 'checks', label: 'Checks' },
  { routeId: 'test-policies', label: 'Test policies' },
  { routeId: 'runs', label: 'Test runs' },
  { routeId: 'findings', label: 'Findings' },
  { routeId: 'reports', label: 'Reports' },
];

test.describe('portal route request budget (WP1)', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('navigating across routes stays below the API budget without a 429', async ({ page }) => {
    const apiResponses = [];
    page.on('response', (response) => {
      if (new URL(response.url()).pathname.startsWith('/v1/')) {
        apiResponses.push({ status: response.status(), url: response.url() });
      }
    });

    for (const route of ROUTES_TO_NAVIGATE) {
      expect(NAV_ROUTE_IDS).toContain(route.routeId);
    }

    await injectPortalSessionForSurface(page, 'customer');
    await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());

    for (const route of ROUTES_TO_NAVIGATE) {
      await page.getByRole('button', { name: route.label, exact: true }).click();
      await expect(page.getByRole('button', { name: route.label, exact: true })).toHaveAttribute('aria-current', 'page');
      await page.waitForTimeout(250);
      await page.waitForLoadState('networkidle');
    }

    console.log(`OBSERVED_V1_REQUESTS=${apiResponses.length}`);
    const rateLimited = apiResponses.filter((response) => response.status === 429);
    expect(rateLimited, 'no /v1 request should be rate limited').toEqual([]);
    expect(
      apiResponses.length,
      `dashboard boot plus ${ROUTES_TO_NAVIGATE.length} route navigations must stay below ${REQUEST_BUDGET} /v1 requests`,
    ).toBeLessThan(REQUEST_BUDGET);
  });
});
