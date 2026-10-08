import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { startPortalPlaywrightServer, stopPortalPlaywrightServer, getPortalPlaywrightBaseUrl } from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, injectPortalDevHeadersSession, waitForPortalRouteSettled } from '../../helpers/portal-playwright-session.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';

test.beforeEach(async () => { await startPortalPlaywrightServer(); });
test.afterEach(async () => { await stopPortalPlaywrightServer(); });

for (const { width, theme } of [{ width: 375, theme: 'light' }, { width: 1440, theme: 'dark' }]) {
  test(`direct domain workflows have no grouping screens, selectors or reads at ${width}px`, async ({ page }) => {
    test.setTimeout(120_000);
    const errors = [];
    const groupReads = [];
    const writes = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('request', (request) => {
      if (request.url().includes('/v1/target-groups')) groupReads.push(request.url());
      if (/\/v1\//.test(request.url()) && request.method() !== 'GET') writes.push(request.url());
    });
    await injectPortalDevHeadersSession(page);
    await page.setViewportSize({ width, height: 950 });
    for (const route of ['targets', 'target-detail', 'checks', 'test-policies', 'findings', 'reports', 'integrations', 'runs', 'dashboard']) {
      await gotoPortalRoute(page, route, getPortalPlaywrightBaseUrl());
      await page.evaluate((value) => document.documentElement.setAttribute('data-theme', value), theme);
      await expect(page.locator('#portal-main')).toBeVisible();
      await expect(page.locator('#portal-main')).not.toContainText(/Target groups?|target groups?/);
      await expect(page.getByRole('button', { name: 'Target groups', exact: true })).toHaveCount(0);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), route).toBe(true);
    }
    expect(groupReads).toEqual([]);
    expect(writes, 'reading and selecting domain contexts is passive').toEqual([]);
    expect(errors).toEqual([]);
  });
}

test('CSV intake adds domains directly with no grouping field and shows invalid rows without partial writes', async ({ page }) => {
  await injectPortalDevHeadersSession(page);
  await gotoPortalRoute(page, 'targets', getPortalPlaywrightBaseUrl());
  await page.getByRole('button', { name: 'Import CSV', exact: true }).click();
  const modal = page.locator('dialog.form-modal[open]');
  await modal.getByLabel('CSV file').setInputFiles({ name: 'domains.csv', mimeType: 'text/csv', buffer: Buffer.from('kind,value\nfqdn,direct-first.example\nfqdn,direct-second.example') });
  const response = page.waitForResponse((res) => res.url().endsWith('/v1/targets:csv') && res.request().method() === 'POST');
  await modal.getByRole('button', { name: /Import \d+ targets|Import targets|Import CSV/, exact: false }).last().click();
  const result = await response;
  expect(result.status()).toBe(201);
  const body = await result.json();
  expect(body.created).toHaveLength(2);
  expect(body.created.every((target) => !Object.hasOwn(target, 'target_group_id'))).toBe(true);
  await expect(modal).toContainText('2');
});

test('domain assessment selection remains explicit and accessible before any traffic is started', async ({ page }) => {
  const posts = [];
  page.on('request', (request) => { if (request.method() === 'POST' && request.url().endsWith('/v1/validation-scans')) posts.push(request.postDataJSON()); });
  await injectPortalDevHeadersSession(page);
  await gotoPortalRoute(page, 'runs', getPortalPlaywrightBaseUrl());
  await page.getByRole('button', { name: 'Start validation scan' }).click();
  const modal = page.locator('dialog.form-modal[open]');
  await expect(modal.getByRole('button', { name: 'Review scan', exact: true })).toBeDisabled();
  await modal.locator('.domain-picker-option').filter({ hasText: /^checkout\.acme\.com/ }).getByRole('checkbox').check();
  await modal.locator('.domain-picker-option').filter({ hasText: /^pay\.acme\.com/ }).getByRole('checkbox').check();
  await expect(modal.locator('.domain-picker')).toContainText('2 selected');
  await expect(modal).not.toContainText(/target groups?/i);
  await waitForPortalRouteSettled(page);
  const accessibility = await new AxeBuilder({ page }).include('dialog.form-modal[open]').withTags(['wcag2a', 'wcag2aa']).analyze();
  expect(accessibility.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact)).map((violation) => ({ id: violation.id, nodes: violation.nodes.map((node) => node.target) }))).toEqual([]);
  expect(posts).toEqual([]);
  await modal.getByRole('button', { name: 'Cancel', exact: true }).click();
  expect(posts).toEqual([]);
});
