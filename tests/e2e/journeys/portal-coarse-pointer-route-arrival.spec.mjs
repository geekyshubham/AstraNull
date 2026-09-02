import { expect, test } from '@playwright/test';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  gotoPublicPortalRoute,
  injectPortalSessionForSurface,
} from '../../helpers/portal-playwright-session.mjs';
import { ROUTES_TO_SCAN } from '../../helpers/portal-routes.mjs';

/**
 * FT-TOUCH-01 — coarse-pointer and route-arrival semantics for every reachable surface.
 *
 * Runs with touch emulation at a phone viewport, because the portal's 44px minimum
 * target rules are scoped to `@media (pointer: coarse)`. A fine-pointer desktop run
 * cannot observe them, which previously produced false "sub-44px target" reports.
 *
 * Guards: no document-level horizontal overflow, every visible interactive control
 * meets the coarse-pointer minimum, and each authenticated route announces itself with
 * a distinct document title while moving keyboard focus into the content region.
 */

test.use({ viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true });

test.describe('portal coarse-pointer and route arrival (FT-TOUCH-01)', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  for (const routeEntry of ROUTES_TO_SCAN) {
    const label = routeEntry.pathname ?? routeEntry.routeId;

    test(`${label} has no overflow and meets coarse-pointer target sizes`, async ({ page }) => {
      const baseUrl = getPortalPlaywrightBaseUrl();
      await injectPortalSessionForSurface(page, routeEntry.surface);

      if (routeEntry.surface === 'public') {
        await gotoPublicPortalRoute(page, routeEntry.pathname, baseUrl);
      } else {
        await gotoPortalRoute(page, routeEntry.routeId, baseUrl);
      }

      const report = await page.evaluate(() => {
        const selector = 'button, a[href], input:not([type=hidden]), select, textarea, [role="button"], [tabindex="0"]';
        const small = [];
        for (const el of document.querySelectorAll(selector)) {
          const rect = el.getBoundingClientRect();
          if (rect.width === 0 && rect.height === 0) continue;
          const style = getComputedStyle(el);
          if (style.visibility === 'hidden' || style.display === 'none') continue;
          // Visually hidden accessibility mirrors (e.g. the native select behind a custom
          // one) are not tap targets: the visible trigger is measured instead.
          if (style.pointerEvents === 'none' || Number(style.opacity) === 0) continue;

          const tag = el.tagName.toLowerCase();
          const type = (el.getAttribute('type') || '').toLowerCase();
          const isCheckable = tag === 'input' && (type === 'checkbox' || type === 'radio');
          // WCAG 2.5.8 exempts links rendered inline within a sentence or block of text.
          if (tag === 'a' && el.closest('p, li, dd, .muted, .kv-list, code')) continue;

          const minHeight = isCheckable ? 24 : 44;
          if (rect.height + 0.5 < minHeight || rect.width + 0.5 < 24) {
            small.push(`${tag}.${(el.getAttribute('class') || '').split(' ')[0]}` +
              `[${(el.getAttribute('aria-label') || el.textContent || '').trim().slice(0, 32)}] ` +
              `${Math.round(rect.width)}x${Math.round(rect.height)} min 24x${minHeight}`);
          }
        }
        return {
          small,
          scrollWidth: document.documentElement.scrollWidth,
          viewport: window.innerWidth,
          title: document.title,
        };
      });

      expect(report.scrollWidth, `${label} horizontal overflow`).toBeLessThanOrEqual(report.viewport + 1);
      expect(report.small, `${label} sub-coarse-pointer targets`).toEqual([]);
      expect(report.title.trim().length, `${label} document title`).toBeGreaterThan(0);
    });
  }

  /**
   * Regression guard for coarse-pointer specificity: `[data-ui='button'].btn-icon` pins
   * width to 40px, so a lower-specificity coarse override silently loses. Tablet widths keep
   * the shell chrome visible where phone widths collapse it, so they must be measured too.
   */
  for (const width of [768, 1024]) {
    test(`shell icon buttons meet the coarse-pointer minimum at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await injectPortalSessionForSurface(page, 'customer');
      await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());

      const chrome = await page.evaluate(() => {
        const results = [];
        for (const selector of ['.menu-btn', '.theme-toggle', '.sidebar-collapse', '.sidebar-close']) {
          for (const el of document.querySelectorAll(selector)) {
            const rect = el.getBoundingClientRect();
            if (rect.width === 0 && rect.height === 0) continue;
            results.push({ selector, w: Math.round(rect.width), h: Math.round(rect.height) });
          }
        }
        return results;
      });

      expect(chrome.length, 'expected shell chrome controls to be present').toBeGreaterThan(0);
      const undersized = chrome.filter((item) => item.w < 44 || item.h < 44);
      expect(undersized, `undersized shell chrome at ${width}px`).toEqual([]);
    });
  }

  test('authenticated route changes retitle the document and move focus to content', async ({ page }) => {    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalSessionForSurface(page, 'customer');
    await gotoPortalRoute(page, 'dashboard', baseUrl);

    const dashboardTitle = await page.title();
    expect(dashboardTitle).toMatch(/Dashboard/i);
    expect(await page.locator('.skip-link').getAttribute('href')).toBe('#portal-main');
    await expect(page.locator('#portal-main')).toHaveCount(1);

    await gotoPortalRoute(page, 'findings', baseUrl);
    const findingsTitle = await page.title();
    expect(findingsTitle).toMatch(/Findings/i);
    expect(findingsTitle).not.toBe(dashboardTitle);

    // Route arrival must land keyboard focus in the content region, not back at the nav.
    await page.evaluate(() => { window.location.hash = '#runs'; });
    await page.waitForFunction(() => /Runs/i.test(document.title));
    const focusedId = await page.evaluate(() => document.activeElement?.id ?? '');
    expect(focusedId).toBe('portal-main');
  });
});
