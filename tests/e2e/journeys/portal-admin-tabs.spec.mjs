/**
 * Staff admin console keeps its tab in the address, so returning from a tenant detail page lands
 * on the Tenants tab instead of the overview.
 */
import { expect, test } from '@playwright/test';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, injectPortalDevHeadersSession } from '../../helpers/portal-playwright-session.mjs';

const STAFF_ADMIN_SESSION = Object.freeze({
  mode: 'dev-headers',
  principal: 'staff',
  staff_role: 'internal_admin',
  role: 'internal_admin',
  staff_id: 'staff_internal_admin',
});

test.describe('staff admin console tabs', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer();
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('Tenants tab survives opening a tenant and going back', async ({ page }) => {
    await injectPortalDevHeadersSession(page, STAFF_ADMIN_SESSION);
    await gotoPortalRoute(page, 'admin', getPortalPlaywrightBaseUrl());
    await expect(page.locator('[aria-label="Staff operations summary"]')).toBeVisible();
    await expect(page.locator('.page-context-summary')).toHaveCount(0);

    await page.getByRole('tab', { name: 'Tenants', exact: true }).click();
    await expect(page).toHaveURL(/#admin\?tab=tenants$/);
    await expect(page.locator('.page-context-summary')).toHaveCount(1);
    await expect(page.getByText('Selected tenant', { exact: true })).toHaveCount(1);

    await page.getByRole('link', { name: 'Detail', exact: true }).first().click();
    await expect(page).toHaveURL(/#tenant-detail\?id=/);
    await page.getByRole('link', { name: /Back to tenants/ }).click();

    await expect(page).toHaveURL(/#admin\?tab=tenants$/);
    await expect(page.getByRole('tab', { name: 'Tenants', exact: true })).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByRole('heading', { name: 'Tenant directory' })).toBeVisible();
  });
});
