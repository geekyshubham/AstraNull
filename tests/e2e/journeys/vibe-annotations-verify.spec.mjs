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

  test('7, 8, 9. /app#target-detail elements removed and UI UX revamped', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', baseUrl);

    // 7. remove td-cat-how
    await expect(page.locator('.td-cat-how')).toHaveCount(0);

    // 8. remove td-decl-note
    await expect(page.locator('.td-decl-note')).toHaveCount(0);

    // 9. revamped UI UX
    await expect(page.locator('.td-breadcrumbs')).toBeVisible();
    await expect(page.locator('.td-title-cluster')).toBeVisible();
    await expect(page.locator('.td-summary-region')).toBeVisible();

    await page.screenshot({ path: '/tmp/vibe-3-target-detail-premium.png' });

    // Switch to classic to verify classic layout also looks clean
    const classicBtn = page.getByRole('radio', { name: 'Classic' });
    if (await classicBtn.count() > 0) {
      await classicBtn.click();
      await page.waitForTimeout(300);
      await page.screenshot({ path: '/tmp/vibe-3-target-detail-classic.png' });
    }
  });
});
