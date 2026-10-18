import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { startPortalPlaywrightServer, stopPortalPlaywrightServer, getPortalPlaywrightBaseUrl } from '../../helpers/portal-playwright-server.mjs';
import { injectPortalDevHeadersSession, gotoPortalRoute, waitForPortalRouteSettled } from '../../helpers/portal-playwright-session.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';

let sourceCalls = 0;
let sourceError = '';
let holdDiscovery = false;
test.beforeEach(async () => {
  sourceError = '';
  holdDiscovery = false;
  await startPortalPlaywrightServer({
    env: { ASTRANULL_VIRUSTOTAL_API_KEY: '', ASTRANULL_SUBDOMAIN_SOURCE: 'virustotal_ui' },
    services: { subdomainUiRun: async ({ domain }, { signal, onProgress }) => {
      sourceCalls += 1;
      if (holdDiscovery) {
        onProgress({ phase: 'fetching', pages: 1, records: 40 });
        return new Promise(resolve => signal.addEventListener('abort', () => resolve({ error: 'subdomain_discovery_cancelled' }), { once: true }));
      }
      return sourceError ? { error: sourceError }
        : { hostnames: [`api.${domain}`], pages: 1, reported_total: 1, truncated: false, stop_reason: null };
    } },
    mutate: (store) => {
      const parent = store.targets.find((target) => target.id === PORTAL_BASELINE_IDS.targetId);
      store.targetVerifications.push({ id: 'tv_subdomains', tenant_id: parent.tenant_id, target_id: parent.id,
        state: 'dns_verified', source_kind: 'dns_txt', transitioned_at: new Date(Date.now() + 1000).toISOString() });
    },
  });
});
test.afterEach(() => stopPortalPlaywrightServer());

for (const [theme, width] of [['dark', 1440], ['light', 375]]) {
  test(`target subdomains review, import and bounded detection (${theme}, ${width}px)`, async ({ page }) => {
    const errors = []; page.on('pageerror', (error) => errors.push(error.message));
    await page.setViewportSize({ width, height: 1000 });
    await injectPortalDevHeadersSession(page, { mode: 'dev-headers', principal: 'customer',
      tenant_id: PORTAL_BASELINE_IDS.tenantId, user_id: 'usr_admin', role: 'admin' });
    await page.addInitScript((value) => localStorage.setItem('astranull.theme', value), theme);
    await gotoPortalRoute(page, `target-detail?id=${PORTAL_BASELINE_IDS.targetId}&tab=subdomains`, getPortalPlaywrightBaseUrl());
    await waitForPortalRouteSettled(page);
    await expect(page.getByRole('tab', { name: 'Subdomains' })).toHaveAttribute('aria-selected', 'true');
    const panel = page.locator('#td-panel-subdomains');
    await expect(panel.getByRole('button', { name: 'Discover and add subdomains' })).toBeEnabled();
    const before = sourceCalls;
    await panel.getByRole('button', { name: 'Discover and add subdomains' }).click();
    await expect(page.getByRole('dialog')).toContainText('Initial WAF/CDN detection is queued automatically');
    await page.getByRole('dialog').getByRole('button', { name: 'Discover and add', exact: true }).click();
    await expect(panel.getByRole('status')).toContainText('Added');
    await expect(panel.locator('tbody')).toContainText('api.');
    expect(sourceCalls).toBe(before + 1);
    await expect(panel.locator('tbody')).toContainText('Verified through parent');
    await expect(panel.locator('tbody')).not.toContainText(/Protected|Exposed/);
    await panel.getByRole('button', { name: 'Detect unchecked hosts' }).click();
    await expect(page.getByRole('dialog')).toContainText('own ownership, signed-worker, rate and safety checks');
    await page.getByRole('dialog').getByRole('button', { name: 'Start bounded detection' }).click();
    await expect(panel.getByRole('status').first()).toContainText('Queued 1');
    await expect(panel.locator('tbody a').first()).toHaveAttribute('href', /target-detail\?id=/);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    expect(errors).toEqual([]);
    const axe = await new AxeBuilder({ page }).include('#td-panel-subdomains').analyze();
    expect(axe.violations).toEqual([]);
    await page.screenshot({ path: `/tmp/astranull-subdomains-${theme}-${width}.png`, fullPage: true });
    await panel.locator('tbody a').first().click();
    await waitForPortalRouteSettled(page);
    await expect(page.getByRole('tab', { name: /Validate/ })).toBeVisible();
    await expect(page.getByRole('tab', { name: 'Findings' })).toBeVisible();
    await expect(page.getByRole('tab', { name: 'Changes & history' })).toBeVisible();
    await page.getByRole('tab', { name: /Validate/ }).click();
    await expect(page.locator('.td-checks')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Plan validation' })).toBeEnabled();
  });
}

test('source failures show a neutral message without proxy, quota or credential details', async ({ page }) => {
  sourceError = 'subdomain_source_rate_limited';
  await injectPortalDevHeadersSession(page, { mode: 'dev-headers', principal: 'customer',
    tenant_id: PORTAL_BASELINE_IDS.tenantId, user_id: 'usr_admin', role: 'admin' });
  await gotoPortalRoute(page, `target-detail?id=${PORTAL_BASELINE_IDS.targetId}&tab=subdomains`, getPortalPlaywrightBaseUrl());
  await waitForPortalRouteSettled(page);
  const panel = page.locator('#td-panel-subdomains');
  await panel.getByRole('button', { name: 'Discover and add subdomains' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Discover and add', exact: true }).click();
  await expect(panel.getByRole('alert')).toContainText('Subdomain discovery could not be completed');
  await expect(panel.getByRole('alert')).toContainText('no hosts were added');
  await expect(panel).not.toContainText(/rate limit|quota|proxy|API key|ASTRANULL_/i);
  await expect(page.getByRole('dialog')).toHaveCount(0);
});

for (const outcome of ['stop', 'idle']) {
  test(`discovery shows progress, closes its dialog and handles ${outcome}`, async ({ page }) => {
    holdDiscovery = true;
    await page.setViewportSize({ width: outcome === 'stop' ? 1440 : 375, height: 1000 });
    if (outcome === 'idle') await page.clock.install();
    await injectPortalDevHeadersSession(page, { mode: 'dev-headers', principal: 'customer',
      tenant_id: PORTAL_BASELINE_IDS.tenantId, user_id: 'usr_admin', role: 'admin' });
    await gotoPortalRoute(page, `target-detail?id=${PORTAL_BASELINE_IDS.targetId}&tab=subdomains`, getPortalPlaywrightBaseUrl());
    await waitForPortalRouteSettled(page);
    const panel = page.locator('#td-panel-subdomains');
    await panel.getByRole('button', { name: 'Discover and add subdomains' }).click();
    await expect(page.getByRole('dialog')).not.toContainText('bounded list');
    await page.getByRole('dialog').getByRole('button', { name: 'Discover and add', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(panel.getByRole('status')).toContainText('40 source records read');
    await expect(panel).not.toContainText('up to a minute');
    await page.screenshot({ path: `/tmp/astranull-discovery-progress-${outcome}.png`, fullPage: true });
    if (outcome === 'stop') {
      await panel.getByRole('button', { name: 'Stop discovery' }).click();
      await expect(panel.getByRole('status')).toContainText('Discovery stopped');
    } else {
      await page.clock.fastForward(46_000);
      await expect(panel.getByRole('alert')).toContainText('no hosts were added');
    }
    await expect(panel.getByRole('button', { name: 'Stop discovery' })).toHaveCount(0);
    await expect(panel.getByRole('button', { name: 'Discover and add subdomains' })).toBeEnabled();
  });
}
