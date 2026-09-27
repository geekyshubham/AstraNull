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
import { ROUTES_TO_SCAN } from '../../helpers/portal-routes.mjs';
import { inspectVisibleLanguage } from '../../../scripts/live-portal-sweep.mjs';

async function waitForSettledPortal(page) {
  await page.waitForFunction(() => ![
    ...document.querySelectorAll(
      '#portal-main [aria-busy="true"], #portal-main .skeleton, #portal-main [class*="skeleton"]',
    ),
  ].some((node) => {
    const style = getComputedStyle(node);
    const rect = node.getBoundingClientRect();
    return style.display !== 'none'
      && style.visibility !== 'hidden'
      && rect.width > 0
      && rect.height > 0;
  }), undefined, { timeout: 15_000 });
  await page.waitForTimeout(250);
}

test.describe('portal visible language', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  for (const entry of ROUTES_TO_SCAN.filter((item) => item.surface !== 'public')) {
    test(`${entry.routeId} has no visible machine copy or implementation jargon`, async ({ page }) => {
      await injectPortalSessionForSurface(page, entry.surface);
      await gotoPortalRoute(page, entry.routeId, getPortalPlaywrightBaseUrl());
      await waitForSettledPortal(page);

      const text = await page.locator('#portal-main').innerText();
      const result = inspectVisibleLanguage(text, 'local');
      expect(result.machineTokens, `machine tokens on ${entry.routeId}`).toEqual([]);
      expect(result.jargon, `implementation jargon on ${entry.routeId}`).toEqual([]);
    });
  }
});
