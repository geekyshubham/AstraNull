import { expect, test } from '@playwright/test';
import { startPortalPlaywrightServer, stopPortalPlaywrightServer } from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, injectPortalDevHeadersSession } from '../../helpers/portal-playwright-session.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import { collectPortalBrowserFailures } from '../../helpers/portal-browser-failures.mjs';
import { PORTAL_FONT_STYLESHEET } from '../../helpers/portal-browser-resources.mjs';
import AxeBuilder from '@axe-core/playwright';

const diagnostics = new WeakMap();
test.beforeEach(async ({ page }) => { diagnostics.set(page, await collectPortalBrowserFailures(page, webBaseUrl)); });
test.afterEach(async ({ page }) => { diagnostics.get(page).assertClean(); });

let webBaseUrl;
const TENANT = PORTAL_BASELINE_IDS.tenantId;
const TARGET = 'tgt_filters_browser';

test.describe.configure({ mode: 'serial' });
test.beforeAll(async () => {
  test.setTimeout(120_000);
  ({ webBaseUrl } = await startPortalPlaywrightServer({
    liveSource: true,
    env: { ASTRANULL_ASSISTANT_ENABLED: '1', ASTRANULL_ASSISTANT_TENANTS: TENANT },
    mutate(store) {
      store.targets.push({ id: TARGET, tenant_id: TENANT, target_group_id: PORTAL_BASELINE_IDS.targetGroupId, kind: 'fqdn', value: 'filter-preview.example.test' });
      for (let index = 0; index < 60; index += 1) store.findings.push({ id: `fnd_filter_browser_${index}`, tenant_id: TENANT, target_id: TARGET, check_id: 'browser.filter.check', status: 'open', severity: 'high', title: 'Filter preview browser finding', created_at: new Date(Date.now() - index * 1000).toISOString() });
    },
  }));
});
test.afterAll(async () => { await stopPortalPlaywrightServer(); });

async function open(page) {
  await injectPortalDevHeadersSession(page);
  await gotoPortalRoute(page, 'findings', webBaseUrl);
  await expect(page.getByRole('textbox', { name: 'Filter in plain language' })).toBeVisible({ timeout: 60_000 });
}

for (const mobile of [false, true]) {
  test(`explicit preview/apply/clear retains exact server totals and page 2 (${mobile ? 'mobile light' : 'desktop dark'})`, async ({ page }) => {
    await page.setViewportSize(mobile ? { width: 390, height: 844 } : { width: 1440, height: 1000 });
    await page.addInitScript((theme) => localStorage.setItem('astranull.theme', theme), mobile ? 'light' : 'dark');
    const reads = [];
    const writes = [];
    page.on('request', (request) => {
      const url = new URL(request.url());
      if (url.pathname === '/v1/findings') reads.push(Object.fromEntries(url.searchParams));
      if (url.pathname.startsWith('/v1/') && request.method() !== 'GET') writes.push(`${request.method()} ${url.pathname}`);
    });
    await open(page);
    const prompt = 'Show open high severity findings for target filter-preview.example.test';
    await page.getByRole('textbox', { name: 'Filter in plain language' }).fill(prompt);
    expect(writes).toEqual([]);
    await expect(page.getByRole('button', { name: 'Apply filters', exact: true })).toHaveCount(0);
    await page.getByRole('button', { name: 'Preview filters', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Apply filters', exact: true })).toBeVisible();
    expect(reads.some((row) => row.target_id === TARGET)).toBe(false);
    expect(page.url()).not.toContain(encodeURIComponent(prompt));
    await page.getByRole('button', { name: 'Apply filters', exact: true }).click();
    await expect(page.locator('.rf-result-count')).toContainText('60 matching findings');
    await expect(page.locator('.rf-findings-table tbody tr')).toHaveCount(25);
    await page.getByRole('button', { name: 'Next findings page' }).click();
    await expect(page.locator('.rf-pager .rf-toolbar .rf-pager-info')).toHaveText('Page 2 of 3');
    expect(reads.some((row) => row.target_id === TARGET && row.status === 'open' && row.severity === 'high' && row.page === '2')).toBe(true);
    await page.locator('.ai-filter-preview').getByRole('button', { name: 'Clear', exact: true }).click();
    await expect(page.getByRole('group', { name: 'Finding status filters' }).getByRole('button', { name: /^All/ })).toHaveAttribute('aria-pressed', 'true');
    await expect(page.getByRole('group', { name: 'Active filters' })).toHaveCount(0);
    expect(writes).toEqual(['POST /v1/assistant/filters']);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    const saved = await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }));
    expect(saved).not.toContain(prompt);
  });
}

test('cold links preserve the complete 200-character search and exact check/run predicate', async ({ page }) => {
  const q = `${'abc '.repeat(49)}abcd`;
  const reads = [];
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.pathname === '/v1/findings') reads.push(Object.fromEntries(url.searchParams));
  });
  await injectPortalDevHeadersSession(page);
  const query = new URLSearchParams({ q, check_id: 'browser.filter.check', test_run_id: 'run_no_match', target_id: TARGET });
  await gotoPortalRoute(page, `findings?${query}`, webBaseUrl);
  await expect(page.locator('.rf-result-count')).toContainText('0 matching findings');
  await expect(page.getByRole('group', { name: 'Active filters' })).toContainText('Run: run_no_match');
  expect(reads.some((row) => row.q === q && row.check_id === 'browser.filter.check' && row.test_run_id === 'run_no_match' && row.target_id === TARGET && !row.status)).toBe(true);
  const routeParams = new URLSearchParams(new URL(page.url()).hash.split('?')[1]);
  expect(routeParams.get('q')).toHaveLength(200);
});

test('prompt edits and scope changes discard late responses; queued fake answers require explicit Apply', async ({ page }) => {
  await open(page);
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  let received;
  const arrival = new Promise((resolve) => { received = resolve; });
  await page.route('**/v1/assistant/filters', async (route) => {
    received();
    await held;
    await route.fulfill({ json: { filters: { severity: 'critical' }, interpretation: 'Stale result', narrative: { status: 'not_requested' } } }).catch(() => undefined);
  });
  await page.getByRole('textbox', { name: 'Filter in plain language' }).fill('show critical findings');
  await page.getByRole('button', { name: 'Preview filters', exact: true }).click();
  await arrival;
  await page.getByRole('textbox', { name: 'Filter in plain language' }).fill('show low findings');
  release();
  await expect(page.getByRole('button', { name: 'Apply filters', exact: true })).toHaveCount(0);
  await page.unroute('**/v1/assistant/filters');

  await page.route('**/v1/assistant/filters', (route) => route.fulfill({ json: { filters: null, interpretation: 'Queued', narrative: { status: 'queued', job_id: 'asj_localfake' } } }));
  await page.route('**/v1/assistant/jobs/asj_localfake', (route) => route.fulfill({ json: { status: 'done', response: { filters: { filters: { check_id: 'browser.filter.check', target_id: TARGET }, explanation: 'Only the exact check and target.' } } } }));
  await page.getByRole('button', { name: 'Preview filters', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Apply filters', exact: true })).toBeVisible();
  await expect(page.getByRole('group', { name: 'Active filters' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Apply filters', exact: true }).click();
  await expect(page.locator('.rf-result-count')).toContainText('60 matching findings');
  await expect(page.getByRole('group', { name: 'Active filters' })).toContainText('Check: browser.filter.check');
  await page.getByRole('textbox', { name: 'Filter in plain language' }).fill('show low findings');
  await page.getByRole('button', { name: 'Preview filters', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Apply filters', exact: true })).toBeVisible();
  await page.getByRole('group', { name: 'Finding status filters' }).getByRole('button', { name: /^In progress/ }).click();
  await expect(page.getByRole('button', { name: 'Apply filters', exact: true })).toHaveCount(0);
  await expect(page.getByRole('textbox', { name: 'Filter in plain language' })).toHaveValue('');

  // In-flight polling belongs to its original queue scope, even when the answer arrives later.
  await page.unroute('**/v1/assistant/filters');
  let finishJob;
  const jobHeld = new Promise((resolve) => { finishJob = resolve; });
  let jobReceived;
  const jobArrival = new Promise((resolve) => { jobReceived = resolve; });
  await page.route('**/v1/assistant/filters', (route) => route.fulfill({ json: { filters: null, interpretation: 'Queued', narrative: { status: 'queued', job_id: 'asj_scopefake' } } }));
  await page.route('**/v1/assistant/jobs/asj_scopefake', async (route) => {
    jobReceived();
    await jobHeld;
    await route.fulfill({ json: { status: 'done', response: { filters: { filters: { severity: 'critical' }, explanation: 'Late queued answer' } } } }).catch(() => undefined);
  });
  await page.getByRole('textbox', { name: 'Filter in plain language' }).fill('show critical findings');
  await page.getByRole('button', { name: 'Preview filters', exact: true }).click();
  await jobArrival;
  await page.getByRole('group', { name: 'Finding status filters' }).getByRole('button', { name: /^All/ }).click();
  finishJob();
  await expect(page.getByRole('button', { name: 'Apply filters', exact: true })).toHaveCount(0);
  await expect(page.getByText('Late queued answer', { exact: true })).toHaveCount(0);
});

test('explicit cancel deletes late and running preview jobs without changing filters', async ({ page }) => {
  await open(page);
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const cancelled = [];
  await page.route('**/v1/assistant/filters', async (route) => {
    await held;
    return route.fulfill({ json: { filters: null, narrative: { status: 'queued', job_id: 'asj_cancel_filters' } } });
  });
  await page.route('**/v1/assistant/jobs/asj_cancel_filters', (route) => {
    if (route.request().method() === 'DELETE') { cancelled.push('asj_cancel_filters'); return route.fulfill({ json: { status: 'cancelled' } }); }
    return route.fulfill({ json: { status: 'running' } });
  });
  await page.getByRole('textbox', { name: 'Filter in plain language' }).fill('show high findings');
  await page.getByRole('button', { name: 'Preview filters', exact: true }).click();
  await page.getByRole('button', { name: 'Cancel preview', exact: true }).click();
  release();
  await expect.poll(() => cancelled.length).toBe(1);
  await expect(page.getByRole('button', { name: 'Apply filters', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Preview filters', exact: true }).click();
  await expect(page.getByText('Preparing filter preview…', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'Cancel preview', exact: true }).click();
  await expect.poll(() => cancelled.length).toBe(2);
  await expect(page.getByRole('group', { name: 'Active filters' })).toHaveCount(0);
});

test('exact filter preview fits four widths and both themes with reduced motion and scoped axe', async ({ page }, testInfo) => {
  test.setTimeout(120000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await open(page);
  await page.getByRole('textbox', { name: 'Filter in plain language' }).fill('show open high severity findings');
  await page.getByRole('button', { name: 'Preview filters', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Apply filters', exact: true })).toBeVisible();
  await page.evaluate((href) => { for (const link of document.querySelectorAll('link[rel="stylesheet"]')) if (link.href === href) { const style = document.createElement('style'); style.textContent = '/* system font fixture */'; link.replaceWith(style); } }, PORTAL_FONT_STYLESHEET);
  await page.getByRole('button', { name: 'Apply filters', exact: true }).focus();
  await expect(page.getByRole('button', { name: 'Apply filters', exact: true })).toBeFocused();
  for (const width of [375, 768, 1024, 1440]) for (const theme of ['light', 'dark']) {
    await page.setViewportSize({ width, height: 1000 });
    await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
    await page.evaluate((theme) => { document.documentElement.dataset.theme = theme; }, theme);
    const geometry = await page.locator('.ai-filter-preview').evaluate((node) => ({ width: node.getBoundingClientRect().width, scroll: node.scrollWidth, page: document.documentElement.scrollWidth, reduced: matchMedia('(prefers-reduced-motion: reduce)').matches }));
    expect(geometry.scroll).toBeLessThanOrEqual(geometry.width + 1); expect(geometry.page).toBeLessThanOrEqual(width + 1); expect(geometry.reduced).toBe(true);
    const result = await new AxeBuilder({ page }).include('.ai-filter-preview').withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
    expect(result.violations.filter((row) => ['serious', 'critical'].includes(row.impact)).map((row) => ({ id: row.id, nodes: row.nodes.map((node) => node.target) }))).toEqual([]);
    const path = testInfo.outputPath(`filters-${width}-${theme}.png`);
    // Keep sticky chrome at the document top rather than inside an offscreen component capture.
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path, fullPage: true, animations: 'disabled' });
    await testInfo.attach(`filters-${width}-${theme}`, { path, contentType: 'image/png' });
  }
});
