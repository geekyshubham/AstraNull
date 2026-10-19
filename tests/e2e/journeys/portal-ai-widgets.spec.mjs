import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { startPortalPlaywrightServer, stopPortalPlaywrightServer, seedPortalPlaywrightStore, getPortalPlaywrightBaseUrl } from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, injectPortalDevHeadersSession, PORTAL_SESSION } from '../../helpers/portal-playwright-session.mjs';
import { demoHeaders } from '../../helpers/http.mjs';
import { assistantStore } from '../../../src/services/assistant.mjs';
import { collectPortalBrowserFailures } from '../../helpers/portal-browser-failures.mjs';
import { PORTAL_FONT_STYLESHEET } from '../../helpers/portal-browser-resources.mjs';

const HEADERS = demoHeaders(PORTAL_SESSION.role, PORTAL_SESSION.tenant_id, PORTAL_SESSION.user_id);
const CONFIG = { name: 'High-priority review', question: 'Which observed findings should I review first?', template: 'finding_list', severity: 'high' };
const failures = new WeakMap();
const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

test.beforeAll(async () => {
  await startPortalPlaywrightServer({ liveSource: true, env: { ASTRANULL_ASSISTANT_ENABLED: '1', ASTRANULL_ASSISTANT_TENANTS: '*', ASTRANULL_ASSISTANT_RUNNER_TOKEN: 'widgets-browser-fake-runner-token-not-used' } });
});
test.afterAll(async () => { await stopPortalPlaywrightServer(); });
test.beforeEach(async ({ page }) => {
  test.setTimeout(120000);
  seedPortalPlaywrightStore(); assistantStore._reset();
  const state = { errors: [], allowed: new Set(), writes: [], aiRequests: [] }; failures.set(page, state);
  state.diagnostics = await collectPortalBrowserFailures(page, getPortalPlaywrightBaseUrl(), {
    allowResponse: (response) => state.allowed.has(`${response.request().method()} ${new URL(response.url()).pathname} ${response.status()}`),
  });
  page.on('request', (request) => {
    const path = new URL(request.url()).pathname;
    if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(request.method())) state.writes.push({ method: request.method(), path, body: request.postDataJSON() });
    if (request.method() === 'POST' && /\/assistant\/widgets\/[^/]+\/refresh$/.test(path) && request.postDataJSON()?.narrative === true) state.aiRequests.push(path);
  });
  // Browser resource fixtures intercept fonts. Anything else non-local is a test failure,
  // never an external probe or a real documentation/model request.
  await page.route('**/*', (route) => {
    const url = new URL(route.request().url());
    if (['127.0.0.1', 'localhost'].includes(url.hostname)) return route.fallback();
    if (url.href === PORTAL_FONT_STYLESHEET && route.request().method() === 'GET' && route.request().resourceType() === 'stylesheet') return route.fulfill({ contentType: 'text/css', body: '/* system-font browser fixture */' });
    state.errors.push(`external request blocked: ${url.origin}${url.pathname}`);
    return route.abort('blockedbyclient');
  });
  await injectPortalDevHeadersSession(page);
});
test.afterEach(async ({ page }, testInfo) => {
  const errors = failures.get(page)?.errors ?? [];
  if (errors.length) await testInfo.attach('unexpected-browser-failures', { body: JSON.stringify(errors, null, 2), contentType: 'application/json' });
  expect(errors, 'unexpected external-network failures').toEqual([]);
  failures.get(page).diagnostics.assertClean();
});

const collection = (page) => page.getByRole('region', { name: 'Personal AI widgets', exact: true });
const card = (page, name = CONFIG.name) => page.getByRole('article', { name, exact: true });
async function open(page) {
  await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());
  await expect(collection(page).getByRole('button', { name: 'Add widget', exact: true })).toBeEnabled();
}
async function seed(page, config = CONFIG) {
  const response = await page.request.post(`${getPortalPlaywrightBaseUrl()}/v1/assistant/widgets`, { headers: HEADERS, data: { config } });
  expect(response.status()).toBe(201);
  return (await response.json()).widget;
}
async function fillEditor(page, config = CONFIG) {
  await page.getByLabel('Widget name', { exact: true }).fill(config.name);
  await page.getByLabel('Question for optional AI commentary', { exact: true }).fill(config.question);
  await page.getByLabel('Display', { exact: true }).selectOption(config.template);
  await page.getByLabel('Severity', { exact: true }).selectOption(config.severity ?? '');
}
async function preview(page) {
  await collection(page).getByRole('button', { name: 'Preview data', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Widget preview' })).toBeVisible();
}
async function fakeAi(page, mode = 'done') {
  const cancelled = [];
  const jobs = new Map();
  let serial = 0;
  await page.route(/\/v1\/assistant\/widgets\/aw_[a-f0-9]{24}\/refresh$/, async (route) => {
    if (route.request().postDataJSON()?.narrative !== true) return route.fallback();
    // Read actual computed data, but explicitly disable the real AI queue.
    const response = await route.fetch({ postData: JSON.stringify({ narrative: false }) });
    const body = await response.json();
    const id = `asj_widget_${++serial}`; jobs.set(id, body.data);
    return route.fulfill({ json: { ...body, narrative: { status: 'queued', job_id: id } } });
  });
  await page.route(/\/v1\/assistant\/jobs\/asj_widget_\d+$/, async (route) => {
    const id = route.request().url().split('/').pop();
    if (route.request().method() === 'DELETE') { cancelled.push(id); return route.fulfill({ json: { status: 'cancelled' } }); }
    if (mode === 'hold') return route.fulfill({ json: { status: 'running' } });
    const data = jobs.get(id);
    return route.fulfill({ json: { status: 'done', response: { widget_commentary: { text: 'Review the observed high-severity findings. This is a bounded sample, not a protection claim.', citations: mode === 'invalid' ? ['fnd_foreign'] : data.citations.slice(0, 1) } } } });
  });
  return { cancelled };
}

test('create requires preview, saves a private definition, reloads and removes only that definition', async ({ page }) => {
  await open(page);
  await collection(page).getByRole('button', { name: 'Add widget', exact: true }).click();
  await expect(page.getByLabel('Widget name', { exact: true })).toBeFocused();
  await fillEditor(page);
  await expect(collection(page).getByRole('button', { name: 'Save widget', exact: true })).toBeDisabled();
  await preview(page);
  await collection(page).getByRole('button', { name: 'Save widget', exact: true }).click();
  await expect(card(page)).toBeVisible();
  await expect(card(page)).toContainText('matching findings');
  await expect(card(page)).not.toContainText('not a workspace total');
  await expect(card(page).getByRole('button', { name: 'Ask AI', exact: true })).toBeEnabled();
  await page.reload({ waitUntil: 'networkidle' });
  await expect(card(page)).toBeVisible();
  expect(failures.get(page).aiRequests).toEqual([]);
  expect(failures.get(page).writes.every((write) => write.path.startsWith('/v1/assistant/widgets'))).toBe(true);
  await card(page).getByRole('button', { name: `Remove ${CONFIG.name}`, exact: true }).click();
  await page.getByRole('dialog', { name: 'Remove personal widget?' }).getByRole('button', { name: 'Remove widget', exact: true }).click();
  await expect(card(page)).toHaveCount(0);
  const stored = await page.request.get(`${getPortalPlaywrightBaseUrl()}/v1/assistant/widgets`, { headers: HEADERS });
  expect((await stored.json()).widgets).toEqual([]);
});

test('optimistic edit conflict preserves the draft and requires explicit reload before a successful edit', async ({ page }) => {
  const widget = await seed(page);
  await open(page);
  await card(page).getByRole('button', { name: `Edit ${CONFIG.name}`, exact: true }).click();
  await page.getByLabel('Widget name', { exact: true }).fill('My unsaved widget draft');
  await preview(page);
  const concurrent = await page.request.patch(`${getPortalPlaywrightBaseUrl()}/v1/assistant/widgets/${widget.id}`, { headers: HEADERS, data: { config: { ...CONFIG, name: 'Saved in another tab' }, expected_version: widget.version } });
  expect(concurrent.status()).toBe(200);
  failures.get(page).allowed.add(`PATCH /v1/assistant/widgets/${widget.id} 409`);
  await collection(page).getByRole('button', { name: 'Save changes', exact: true }).click();
  await expect(collection(page).getByRole('alert')).toContainText('changed elsewhere');
  await expect(page.getByLabel('Widget name', { exact: true })).toHaveValue('My unsaved widget draft');
  await collection(page).getByRole('button', { name: 'Cancel', exact: true }).click();
  await page.reload({ waitUntil: 'networkidle' });
  await expect(card(page, 'Saved in another tab')).toBeVisible();
  await card(page, 'Saved in another tab').getByRole('button', { name: 'Edit Saved in another tab', exact: true }).click();
  await page.getByLabel('Widget name', { exact: true }).fill('Reviewed widget');
  await preview(page);
  await collection(page).getByRole('button', { name: 'Save changes', exact: true }).click();
  await expect(card(page, 'Reviewed widget')).toBeVisible();
  expect(failures.get(page).aiRequests).toEqual([]);
});

test('Ask AI is explicit, cancellation is sent, and invalid citations never render as evidence links', async ({ page }) => {
  await seed(page); const fake = await fakeAi(page, 'hold');
  await open(page);
  await expect(card(page).getByRole('button', { name: 'Ask AI', exact: true })).toBeEnabled();
  expect(failures.get(page).aiRequests).toEqual([]);
  await card(page).getByRole('button', { name: 'Ask AI', exact: true }).click();
  await expect(card(page).getByRole('button', { name: 'Cancel AI', exact: true })).toBeVisible();
  await card(page).getByRole('button', { name: 'Cancel AI', exact: true }).click();
  await expect.poll(() => fake.cancelled).toEqual(['asj_widget_1']);
  await expect(card(page).getByRole('button', { name: 'Cancel AI', exact: true })).toHaveCount(0);
  await fakeAi(page, 'invalid');
  await card(page).getByRole('button', { name: 'Ask AI', exact: true }).click();
  await expect(card(page)).toContainText('did not finish', { timeout: 15000 });
  await expect(card(page).locator('a[href*="fnd_foreign"]')).toHaveCount(0);
  await expect(card(page)).toContainText('matching findings');
});

test('valid fake commentary is advisory and session reload cannot inherit another user widget', async ({ page }) => {
  await seed(page); await fakeAi(page);
  await open(page);
  await card(page).getByRole('button', { name: 'Ask AI', exact: true }).click();
  await expect(card(page)).toContainText('AI commentary · advisory', { timeout: 15000 });
  await expect(card(page).getByRole('link', { name: 'Finding 1', exact: true })).toHaveAttribute('href', /^#finding-detail\?id=/);
  const otherSession = { ...PORTAL_SESSION, user_id: 'usr_widget_other' };
  await page.addInitScript((session) => sessionStorage.setItem('astranull.portal.session.v1', JSON.stringify(session)), otherSession);
  await page.reload({ waitUntil: 'networkidle' });
  await expect(collection(page)).toContainText('A focused view, without a new dashboard');
  await expect(card(page)).toHaveCount(0);
  await expect(collection(page)).not.toContainText('AI commentary · advisory');
  expect(await page.evaluate(() => JSON.parse(sessionStorage.getItem('astranull.portal.session.v1')).user_id)).toBe('usr_widget_other');
});

test('widget read failures leave the dashboard usable and expose an explicit retry', async ({ page }) => {
  let unavailable = true;
  failures.get(page).allowed.add('GET /v1/assistant/widgets 503');
  await page.route('**/v1/assistant/widgets', (route) => {
    if (route.request().method() !== 'GET' || !unavailable) return route.fallback();
    return route.fulfill({ status: 503, json: { error: 'assistant_widgets_unavailable' } });
  });
  await openUnavailable(page);
  await expect(collection(page).getByRole('alert')).toContainText('Existing dashboard data is unaffected');
  unavailable = false;
  await collection(page).getByRole('button', { name: 'Reload widgets', exact: true }).click();
  await expect(collection(page).getByRole('button', { name: 'Add widget', exact: true })).toBeEnabled();
  expect(failures.get(page).aiRequests).toEqual([]);
});
async function openUnavailable(page) {
  await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());
  await expect(collection(page)).toBeVisible();
}

test('incomplete snapshots stay labelled as samples and changed definitions cannot label a stale refresh', async ({ page }) => {
  const widget = await seed(page);
  await page.route(`**/v1/assistant/widgets/${widget.id}/refresh`, async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    return route.fulfill({ json: { ...body, data: { ...body.data, count_is_total: false, scope: { ...body.data.scope, complete: false, findings_complete: false } } } });
  });
  await open(page);
  await expect(card(page)).toContainText('findings in the bounded sample');
  await expect(card(page)).toContainText('not a workspace total');
  const changed = await page.request.patch(`${getPortalPlaywrightBaseUrl()}/v1/assistant/widgets/${widget.id}`, { headers: HEADERS, data: { config: { ...CONFIG, name: 'Changed elsewhere' }, expected_version: widget.version } });
  expect(changed.status()).toBe(200);
  await card(page).getByRole('button', { name: 'Refresh data', exact: true }).click();
  await expect(card(page).getByRole('alert')).toContainText('Reload widgets');
  await expect(card(page).locator('.personal-widget-result')).toHaveCount(0);
  await card(page).getByRole('button', { name: 'Reload widgets', exact: true }).click();
  await expect(card(page, 'Changed elsewhere')).toBeVisible();
  expect(failures.get(page).aiRequests).toEqual([]);
});

test('unavailable definitions reveal no saved scope and remain explicitly removable', async ({ page }) => {
  const widget = await seed(page, { ...CONFIG, target_id: 'tgt_checkout_2' });
  await page.route('**/v1/assistant/widgets', async (route) => {
    if (route.request().method() !== 'GET') return route.fallback();
    const response = await route.fetch();
    const body = await response.json();
    return route.fulfill({ json: { widgets: body.widgets.map((item) => ({ id: item.id, version: item.version, unavailable: true })) } });
  });
  await open(page);
  const hidden = page.getByRole('article', { name: 'Unavailable personal widget', exact: true });
  await expect(hidden).toContainText('still uses one slot');
  await expect(collection(page)).not.toContainText(CONFIG.name);
  await expect(collection(page)).not.toContainText(CONFIG.question);
  await expect(hidden.getByRole('button', { name: 'Ask AI' })).toHaveCount(0);
  await hidden.getByRole('button', { name: 'Remove unavailable widget', exact: true }).click();
  const confirmation = page.getByRole('dialog', { name: 'Remove personal widget?' });
  await confirmation.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(hidden).toBeVisible();
  await hidden.getByRole('button', { name: 'Remove unavailable widget', exact: true }).click();
  await confirmation.getByRole('button', { name: 'Remove widget', exact: true }).click();
  await expect(hidden).toHaveCount(0);
  const stored = await page.request.get(`${getPortalPlaywrightBaseUrl()}/v1/assistant/widgets`, { headers: HEADERS });
  expect((await stored.json()).widgets).toEqual([]);
  expect(failures.get(page).writes.filter((write) => write.path === `/v1/assistant/widgets/${widget.id}`)).toEqual([{ method: 'DELETE', path: `/v1/assistant/widgets/${widget.id}`, body: { expected_version: widget.version } }]);
  expect(failures.get(page).aiRequests).toEqual([]);
});

test('widget screenshot matrix is bounded, reduced-motion and axe checked at four widths in both themes', async ({ page }, testInfo) => {
  await seed(page);
  await seed(page, { name: 'Measured summary with a deliberately long title for narrow-width review', question: 'What does this bounded finding sample show, and which observations still need a manual review?', template: 'summary' });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await open(page);
  await expect(collection(page).locator('article')).toHaveCount(2);
  await collection(page).getByRole('button', { name: 'Add widget', exact: true }).click();
  await fillEditor(page, { ...CONFIG, name: 'Previewed widget awaiting an explicit Save', question: '<script>never execute this customer-defined question</script>' });
  await preview(page);
  await page.evaluate((href) => { for (const link of document.querySelectorAll('link[rel="stylesheet"]')) if (link.href === href) { const style = document.createElement('style'); style.textContent = '/* system font fixture */'; link.replaceWith(style); } }, PORTAL_FONT_STYLESHEET);
  const matrix = [];
  for (const width of [375, 768, 1024, 1440]) {
    for (const theme of ['light', 'dark']) {
      await page.setViewportSize({ width, height: 1000 });
      await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
      await page.evaluate((theme) => { document.documentElement.dataset.theme = theme; localStorage.setItem('astranull.theme', theme); }, theme);
      await collection(page).scrollIntoViewIfNeeded();
      await expect(collection(page).locator('script,img,iframe')).toHaveCount(0);
      const measurements = await page.evaluate(() => {
        const region = document.querySelector('.personal-widgets');
        const style = getComputedStyle(document.querySelector('.personal-widget-result'));
        return { viewport: innerWidth, pageWidth: document.documentElement.scrollWidth, widgetWidth: region.getBoundingClientRect().width, widgetScrollWidth: region.scrollWidth, animationName: style.animationName, animationDuration: style.animationDuration, reduced: matchMedia('(prefers-reduced-motion: reduce)').matches };
      });
      expect(measurements.pageWidth, `${width}/${theme}: no page overflow`).toBeLessThanOrEqual(width + 1);
      expect(measurements.widgetScrollWidth, `${width}/${theme}: no widget overflow`).toBeLessThanOrEqual(measurements.widgetWidth + 1);
      expect(measurements.reduced).toBe(true);
      expect(measurements.animationName === 'none' || /^0s(?:, 0s)*$/.test(measurements.animationDuration)).toBe(true);
      const axe = await new AxeBuilder({ page }).include('.personal-widgets').withTags(AXE_TAGS).analyze();
      const violations = axe.violations.filter((issue) => ['serious', 'critical'].includes(issue.impact)).map((issue) => ({ id: issue.id, nodes: issue.nodes.map((node) => node.target) }));
      expect(violations, `${width}/${theme}: scoped serious/critical axe findings`).toEqual([]);
      const screenshot = testInfo.outputPath(`widgets-${width}-${theme}.png`);
      // Full-document capture avoids stitching sticky chrome over a tall widget editor.
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({ path: screenshot, fullPage: true, animations: 'disabled' });
      await testInfo.attach(`widgets-${width}-${theme}`, { path: screenshot, contentType: 'image/png' });
      matrix.push({ width, theme, ...measurements, seriousCriticalAxe: violations.length, screenshot });
    }
  }
  await testInfo.attach('widget-matrix-measurements', { body: JSON.stringify(matrix, null, 2), contentType: 'application/json' });
  expect(failures.get(page).aiRequests).toEqual([]);
});
