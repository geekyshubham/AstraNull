import { expect, test } from '@playwright/test';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, injectPortalSessionForSurface } from '../../helpers/portal-playwright-session.mjs';
import { DETAIL_ROUTE_IDS, NAV_ROUTE_IDS, STAFF_NAV_ROUTE_IDS } from '../../helpers/portal-routes.mjs';

const VIEWPORTS = Object.freeze([
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'mobile', width: 375, height: 812 },
]);

const STAFF_ADMIN_ROUTES = new Set(['admin', 'tenant-detail']);
const STAFF_SOC_ROUTES = new Set(['internal-soc', 'queue-detail']);

const ROUTES = Object.freeze([...new Set([...NAV_ROUTE_IDS, ...STAFF_NAV_ROUTE_IDS, ...DETAIL_ROUTE_IDS])]);

function surfaceForRoute(routeId) {
  if (STAFF_ADMIN_ROUTES.has(routeId)) return 'staff-admin';
  if (STAFF_SOC_ROUTES.has(routeId)) return 'staff-soc';
  return 'customer';
}

async function probeOpenMenu(page, listId) {
  return page.evaluate(async (id) => {
    const nextFrame = () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    const menu = document.getElementById(id);
    if (!menu) return [{ label: '(listbox missing)', ok: false, hit: null }];
    await nextFrame();
    const results = [];
    for (const option of menu.querySelectorAll('[role="option"]')) {
      option.scrollIntoView({ block: 'nearest' });
      await nextFrame();
      const rect = option.getBoundingClientRect();
      const x = rect.left + rect.width / 2;
      const y = rect.top + rect.height / 2;
      const hit = document.elementFromPoint(x, y);
      results.push({
        label: (option.textContent ?? '').trim().slice(0, 60),
        ok: Boolean(hit) && option.contains(hit),
        hit: hit ? `${hit.tagName.toLowerCase()}.${String(hit.className || '').split(' ').filter(Boolean).join('.')}` : null,
      });
    }
    return results;
  }, listId);
}

test.describe('custom Select menus are never clipped or covered (critique P0)', () => {
  test.describe.configure({ timeout: 180_000 });

  test.beforeAll(async () => {
    await startPortalPlaywrightServer();
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  for (const viewport of VIEWPORTS) {
    for (const routeId of ROUTES) {
      test(`${routeId} at ${viewport.width}px: every option of every enabled select is topmost at its centre`, async ({ page }) => {
        await page.setViewportSize({ width: viewport.width, height: viewport.height });
        await injectPortalSessionForSurface(page, surfaceForRoute(routeId));
        await gotoPortalRoute(page, routeId, getPortalPlaywrightBaseUrl());

        const triggers = page.locator('[data-ui="select"] .select-display:enabled:visible');
        const count = await triggers.count();
        const failures = [];

        for (let index = 0; index < count; index += 1) {
          const trigger = triggers.nth(index);
          if (!(await trigger.isVisible()) || !(await trigger.isEnabled())) continue;
          const name = await trigger.evaluate((element) => document.getElementById(element.getAttribute('aria-labelledby') ?? '')?.textContent?.trim() ?? '');
          await trigger.scrollIntoViewIfNeeded();
          await trigger.click();
          await expect(trigger).toHaveAttribute('aria-expanded', 'true');
          const listId = await trigger.getAttribute('aria-controls');
          expect(listId, `${routeId} "${name}" must reference its listbox only while open`).toBeTruthy();
          await expect(page.locator(`[id="${listId}"]`)).toBeVisible();
          for (const result of await probeOpenMenu(page, listId)) {
            if (!result.ok) failures.push(`${routeId} "${name}" option "${result.label}" is covered by ${result.hit ?? 'nothing'}`);
          }
          await page.keyboard.press('Escape');
          await expect(trigger).toHaveAttribute('aria-expanded', 'false');
          expect(await trigger.getAttribute('aria-controls'), `${routeId} "${name}" must drop aria-controls when closed`).toBeNull();
        }

        expect(failures, `${routeId} at ${viewport.width}px`).toEqual([]);
      });
    }
  }
});
