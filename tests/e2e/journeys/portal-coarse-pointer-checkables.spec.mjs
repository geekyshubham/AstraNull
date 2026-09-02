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

/**
 * FT-TOUCH-02 — checkbox and radio targets behind component-specific size rules.
 *
 * `.product-form .check-row input` pinned 20px and `.domain-scope-option input` pinned
 * `min-height: 0`, both with higher specificity than the generic coarse-pointer rule, so these
 * controls stayed below the WCAG 2.5.8 minimum on touch even though the generic rule existed.
 * Both controls sit behind disclosure UI (a settings tab and a two-step modal), which is why
 * route-level scanning did not reach them.
 */

const MIN_TARGET = 24;

async function measureCheckables(page) {
  return page.evaluate(() => {
    const out = [];
    for (const el of document.querySelectorAll('input[type=checkbox], input[type=radio]')) {
      const rect = el.getBoundingClientRect();
      if (rect.width === 0 && rect.height === 0) continue;
      const style = getComputedStyle(el);
      if (style.visibility === 'hidden' || style.display === 'none' || style.pointerEvents === 'none') continue;
      out.push({
        type: el.getAttribute('type'),
        container: (el.closest('[class]')?.getAttribute('class') || '').split(' ')[0],
        width: Number(rect.width.toFixed(2)),
        height: Number(rect.height.toFixed(2)),
      });
    }
    return out;
  });
}

test.use({ hasTouch: true });

test.describe('portal coarse-pointer checkable controls (FT-TOUCH-02)', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  for (const width of [375, 768, 1440]) {
    test(`settings retention checkbox meets the coarse minimum at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await injectPortalSessionForSurface(page, 'customer');
      await gotoPortalRoute(page, 'settings', getPortalPlaywrightBaseUrl());

      const privacyTab = page.getByRole('tab', { name: /Privacy/i });
      if (await privacyTab.count()) await privacyTab.first().click();

      const measured = await measureCheckables(page);
      expect(measured.length, 'expected a retention checkbox to render').toBeGreaterThan(0);
      expect(
        measured.filter((item) => item.width + 0.5 < MIN_TARGET || item.height + 0.5 < MIN_TARGET),
        `undersized settings checkables at ${width}px`,
      ).toEqual([]);
    });

    test(`single-domain scope radios meet the coarse minimum at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await injectPortalSessionForSurface(page, 'customer');
      await gotoPortalRoute(page, 'integrations', getPortalPlaywrightBaseUrl());

      await page.getByRole('button', { name: /Add provider/i }).first().click();
      await page.getByRole('button', { name: /Add single domain/i }).first().click();
      await page.getByRole('radiogroup', { name: 'Target group destination' }).waitFor();

      const measured = await measureCheckables(page);
      const radios = measured.filter((item) => item.type === 'radio');
      expect(radios.length, 'expected the scope radios to render').toBeGreaterThanOrEqual(2);
      expect(
        measured.filter((item) => item.width + 0.5 < MIN_TARGET || item.height + 0.5 < MIN_TARGET),
        `undersized scope radios at ${width}px`,
      ).toEqual([]);
    });
  }
});
