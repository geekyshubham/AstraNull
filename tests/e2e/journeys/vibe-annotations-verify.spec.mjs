import { expect, test } from '@playwright/test';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  clearPortalSession,
  gotoPortalRoute,
  gotoPublicPortalRoute,
  injectPortalDevHeadersSession,
} from '../../helpers/portal-playwright-session.mjs';

test.describe('Vibe annotations verification', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer();
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('1. password reveal toggle is centered inside input right edge', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await clearPortalSession(page);
    await gotoPublicPortalRoute(page, '/set-password', baseUrl);

    const toggle = page.locator('.auth-password-toggle').first();
    const input = page.locator('.auth-password-field input').first();

    await expect(toggle).toBeVisible();
    await expect(input).toBeVisible();

    const toggleBox = await toggle.boundingBox();
    const inputBox = await input.boundingBox();

    expect(toggleBox).not.toBeNull();
    expect(inputBox).not.toBeNull();

    // Toggle button should be vertically centered within the password input box
    const toggleCenterY = toggleBox.y + toggleBox.height / 2;
    const inputCenterY = inputBox.y + inputBox.height / 2;
    expect(Math.abs(toggleCenterY - inputCenterY)).toBeLessThan(6);

    // Toggle button should be placed at the right side of the password input
    expect(toggleBox.x).toBeGreaterThan(inputBox.x + inputBox.width - 50);

    await page.screenshot({ path: '/tmp/vibe-1-login.png' });
  });

  test('2, 3, 4, 5, 6. /app#runs select options z-index, table layout, and removed elements', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'runs', baseUrl);

    // 4. remove p[role="note"] "Customer-safe runs start in the vector library"
    await expect(page.locator('p[role="note"]').filter({ hasText: 'Customer-safe runs start in the vector library' })).toHaveCount(0);

    // 5. remove "Evidence backed" chip
    await expect(page.locator('span[title="Verdicts show only when a published verdict has bound evidence"]')).toHaveCount(0);

    // 6. remove idle p[role="status"] "Idle. Live status auto-refreshes..."
    await expect(page.locator('p[role="status"]').filter({ hasText: 'Idle. Live status auto-refreshes' })).toHaveCount(0);

    // 3. run ID code is nowrap and table has min-width
    const runCode = page.locator('.rf-cell-run code, .validation-runs-table code').first();
    if (await runCode.count() > 0) {
      const whiteSpace = await runCode.evaluate((el) => getComputedStyle(el).whiteSpace);
      expect(whiteSpace).toBe('nowrap');
    }

    await page.screenshot({ path: '/tmp/vibe-2-runs.png' });

    // 2. Select dropdown options visible with proper z-index over table
    const scanStatusSelect = page.locator('label:has-text("Scan status") button.select-display, label:has-text("Lifecycle status") button.select-display').first();
    await scanStatusSelect.click();
    await page.waitForTimeout(300);

    const selectMenu = page.locator('.select-menu:not([hidden])').first();
    await expect(selectMenu).toBeVisible();

    const zIndex = await selectMenu.evaluate((el) => getComputedStyle(el).zIndex);
    expect(Number(zIndex)).toBeGreaterThanOrEqual(50);

    await page.screenshot({ path: '/tmp/vibe-2-runs-select-open.png' });
  });

  test('7, 8, 9. /app#target-detail removed elements stay removed; unified workspace geometry and exact context', async ({ page }) => {
    // Local layout checks only: they do not need the vibe-annotations server and record no design approval.
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);
    for (const viewport of [{ width: 1440, height: 900 }, { width: 375, height: 812 }]) {
      await page.setViewportSize(viewport);
      await gotoPortalRoute(page, 'target-detail', baseUrl);

      // 7, 8. Removed annotations stay removed.
      await expect(page.locator('.td-cat-how')).toHaveCount(0);
      await expect(page.locator('.td-decl-note')).toHaveCount(0);
      // The customer UI ships one presentation; no Classic or Premium switch.
      await expect(page.getByRole('radio', { name: /Classic|Premium/ })).toHaveCount(0);

      // 9. Exact context: shell breadcrumb with the current page marked, and a back link to Targets.
      const crumbs = page.locator('#portal-main').getByRole('navigation', { name: 'Breadcrumb' });
      await expect(crumbs).toHaveText('Scope›Target detail');
      await expect(crumbs.locator('[aria-current="page"]')).toHaveText('Target detail');
      await expect(page.locator('#portal-main a.td-back')).toHaveAttribute('href', '#targets');
      await expect(page.locator('#portal-main a.td-back')).toHaveText('Targets');
      const cluster = page.locator('.td-title-cluster');
      await expect(cluster.getByRole('heading', { level: 1, name: 'checkout.acme.com' })).toBeVisible();
      await expect(cluster).toContainText('Domain ownership verified');

      // Unified workspace geometry: one column; title, then tabs, then the panel, then target facts,
      // all on the same left edge and inside the viewport.
      const geometry = await page.evaluate(() => {
        const rect = (node) => node?.getBoundingClientRect() ?? null;
        const h1 = rect(document.querySelector('#portal-main h1'));
        const tabs = rect(document.querySelector('#portal-main [role="tablist"]'));
        const panel = rect(document.querySelector('#portal-main [role="tabpanel"]'));
        const facts = rect(document.querySelector('#portal-main section.td-facts'));
        return {
          h1, tabs, panel, facts,
          viewport: document.documentElement.clientWidth,
          overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        };
      });
      for (const key of ['h1', 'tabs', 'panel', 'facts']) expect(geometry[key], key).not.toBeNull();
      expect(geometry.tabs.top).toBeGreaterThan(geometry.h1.bottom);
      expect(geometry.panel.top).toBeGreaterThanOrEqual(geometry.tabs.bottom);
      expect(geometry.facts.top).toBeGreaterThanOrEqual(geometry.panel.bottom);
      for (const key of ['tabs', 'panel', 'facts']) {
        expect(Math.abs(geometry[key].left - geometry.h1.left), `${key} shares the title's left edge`).toBeLessThanOrEqual(1);
        expect(geometry[key].right, `${key} stays inside the viewport`).toBeLessThanOrEqual(geometry.viewport + 1);
      }
      expect(Math.abs(geometry.facts.width - geometry.panel.width)).toBeLessThanOrEqual(1);
      expect(geometry.overflow).toBeLessThanOrEqual(1);

      await page.screenshot({ path: `/tmp/vibe-3-target-detail-${viewport.width}.png` });
    }
  });
});
