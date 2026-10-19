import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { collectPortalBrowserFailures } from '../../helpers/portal-browser-failures.mjs';
import { PORTAL_FONT_STYLESHEET } from '../../helpers/portal-browser-resources.mjs';
import { startPortalPlaywrightServer, stopPortalPlaywrightServer, seedPortalPlaywrightStore, getPortalPlaywrightBaseUrl } from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, injectPortalDevHeadersSession, PORTAL_AUDITOR_SESSION } from '../../helpers/portal-playwright-session.mjs';
import { assistantStore } from '../../../src/services/assistant.mjs';

const TARGET = 'tgt_checkout_2';
const states = new WeakMap();
test.beforeAll(async () => {
  await startPortalPlaywrightServer({ liveSource: true, env: { ASTRANULL_ASSISTANT_ENABLED: '1', ASTRANULL_ASSISTANT_TENANTS: '*', ASTRANULL_PROBE_MODE: 'simulation' } });
});
test.afterAll(async () => { await stopPortalPlaywrightServer(); });
test.beforeEach(async ({ page }) => {
  test.setTimeout(120000);
  let targetValue;
  seedPortalPlaywrightStore((store) => {
    targetValue = store.targets.find((target) => target.id === TARGET).value;
    store.findings.push({ id: 'fnd_risk_browser', tenant_id: store.targets.find((target) => target.id === TARGET).tenant_id, target_id: TARGET, check_id: 'waf.http_baseline.safe', status: 'open', severity: 'high', title: 'Observed bounded gap', created_at: '2026-01-01T00:00:00Z', evidence_ids: ['ev_browser'] });
  });
  assistantStore._reset();
  const state = { targetValue, allowed: new Set(), mutations: [], requests: [], cancelled: [], snapshots: new Map() };
  state.diagnostics = await collectPortalBrowserFailures(page, getPortalPlaywrightBaseUrl(), { allowResponse: (response) => state.allowed.has(`${response.request().method()} ${new URL(response.url()).pathname} ${response.status()}`) });
  page.on('request', (request) => {
    if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(request.method())) state.mutations.push(new URL(request.url()).pathname);
  });
  states.set(page, state);
});
test.afterEach(async ({ page }) => { states.get(page).diagnostics.assertClean(); });
const panel = (page, purpose = 'validation-plan') => page.getByRole('region', { name: purpose === 'risk-stories' ? 'Risk stories' : 'Validation recommender', exact: true });
async function open(page, session) {
  await injectPortalDevHeadersSession(page, session);
  await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': TARGET } });
  await expect(panel(page).getByRole('button', { name: 'Generate', exact: true })).toBeVisible();
}
async function fakeModel(page, { mode = 'done', late = false } = {}) {
  const state = states.get(page);
  let release;
  const delayed = new Promise((resolve) => { release = resolve; });
  await page.route(/\/v1\/assistant\/(risk-stories|validation-plan)$/, async (route) => {
    const purpose = new URL(route.request().url()).pathname.split('/').pop();
    state.requests.push({ purpose, body: route.request().postDataJSON() });
    const response = await route.fetch();
    const body = await response.json();
    if (!body.computed) return route.fulfill({ response });
    const id = `asj_risk_browser_${state.requests.length}`;
    state.snapshots.set(id, { purpose, computed: body.computed });
    if (late) await delayed;
    return route.fulfill({ json: { ...body, narrative: { status: 'queued', job_id: id } } });
  });
  await page.route(/\/v1\/assistant\/jobs\/asj_risk_browser_\d+$/, (route) => {
    const id = route.request().url().split('/').pop();
    if (route.request().method() === 'DELETE') { state.cancelled.push(id); return route.fulfill({ json: { status: 'cancelled' } }); }
    if (mode === 'hold') return route.fulfill({ json: { status: 'running' } });
    const { purpose, computed } = state.snapshots.get(id);
    const annotation = { snapshot_id: computed.snapshot_id, target_id: computed.target_id, ai: true,
      ...(purpose === 'risk-stories' ? { stories: [{ source_finding_ids: mode === 'invalid' ? ['fnd_foreign'] : [computed.source_finding_ids[0]], hypothesis: '<script>window.riskExecuted = true</script> Conditional impact requires verification.' }] }
        : { check_ids: mode === 'invalid' ? ['invented.check'] : computed.check_ids.slice(0, 1), rationale: 'Review this exact observed-check candidate first.' }) };
    return route.fulfill({ json: { status: 'done', response: { [purpose === 'risk-stories' ? 'risk_story' : 'validation_plan']: annotation } } });
  });
  return { release };
}
function noExecution(page) {
  expect(states.get(page).mutations.filter((path) => !path.startsWith('/v1/assistant/'))).toEqual([]);
}

test('explicit risk generation separates facts from escaped hypotheses and cites original evidence', async ({ page }) => {
  await fakeModel(page); await open(page);
  expect(states.get(page).requests).toEqual([]);
  await panel(page, 'risk-stories').getByRole('button', { name: 'Generate', exact: true }).click();
  await expect(panel(page, 'risk-stories')).toContainText('Conditional impact requires verification.', { timeout: 15000 });
  await expect(panel(page, 'risk-stories')).toContainText('hypotheses, not observed facts');
  await expect(panel(page, 'risk-stories')).toContainText('fnd_risk_browser');
  await expect(panel(page, 'risk-stories').locator('script,img,iframe')).toHaveCount(0);
  expect(await page.evaluate(() => window.riskExecuted)).toBeUndefined();
  await panel(page, 'risk-stories').getByText('Observed facts and source evidence', { exact: false }).click();
  await expect(panel(page, 'risk-stories').getByRole('button', { name: 'View original finding evidence' }).first()).toBeVisible();
  noExecution(page);
});

test('recommendations require exact-check review and only prefill the ordinary launcher', async ({ page }) => {
  await fakeModel(page); await open(page);
  await panel(page).getByRole('button', { name: 'Generate', exact: true }).click();
  await expect(panel(page)).toContainText('Review this exact observed-check candidate first.', { timeout: 15000 });
  const review = panel(page).getByRole('button', { name: 'Review selected checks in scan launcher' });
  await expect(review).toBeDisabled();
  await panel(page).getByRole('button', { name: 'Use AI suggestion for review' }).click();
  await panel(page).getByLabel('I reviewed this target and these exact checks.', { exact: false }).check();
  await review.click();
  const dialog = page.getByRole('dialog', { name: 'Start validation scan', exact: true });
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText('Only selected domains are planned');
  const computed = states.get(page).snapshots.get('asj_risk_browser_1').computed;
  const suggested = computed.check_ids.slice(0, 1);
  await expect.poll(() => dialog.locator('.check-picker-row').evaluateAll((rows) => rows.filter((row) => row.querySelector('input')?.checked).map((row) => row.querySelector('.check-picker-row-id').textContent))).toEqual(suggested);
  await expect(dialog.locator('.domain-picker input[type="checkbox"]:checked')).toHaveCount(1);
  await expect(dialog.locator('.domain-picker-option').filter({ has: page.locator('input:checked') })).toContainText(states.get(page).targetValue);
  noExecution(page);
});

test('invalid annotation preserves the computed proposal and cancellation stops the owned job', async ({ page }) => {
  await fakeModel(page, { mode: 'invalid' }); await open(page);
  await panel(page).getByRole('button', { name: 'Generate', exact: true }).click();
  await expect(panel(page)).toContainText('did not finish', { timeout: 15000 });
  await expect(panel(page)).not.toContainText('invented.check');
  await expect(panel(page).getByRole('group', { name: 'Review exact checks for this target' })).toBeVisible();
  await fakeModel(page, { mode: 'hold' });
  await panel(page).getByRole('button', { name: 'Refresh proposal', exact: true }).click();
  await panel(page).getByRole('button', { name: 'Cancel AI annotation', exact: true }).click();
  await expect(panel(page)).toContainText('AI annotation cancelled');
  expect(states.get(page).cancelled.length).toBeGreaterThan(0);
  noExecution(page);
});

test('late creation after cancellation is deleted; route disposal never displays stale results', async ({ page }) => {
  const fake = await fakeModel(page, { late: true }); await open(page);
  await panel(page).getByRole('button', { name: 'Generate', exact: true }).click();
  await expect.poll(() => states.get(page).requests.length).toBe(1);
  await panel(page).getByRole('button', { name: 'Cancel request', exact: true }).click();
  fake.release();
  await expect.poll(() => states.get(page).cancelled).toEqual(['asj_risk_browser_1']);
  await expect(panel(page)).not.toContainText('Review exact checks for this target');
  await fakeModel(page, { mode: 'hold' });
  await panel(page).getByRole('button', { name: 'Generate', exact: true }).click();
  await expect(panel(page).getByRole('button', { name: 'Cancel AI annotation' })).toBeVisible();
  await page.evaluate(() => { window.location.hash = '#dashboard'; });
  await expect.poll(() => states.get(page).cancelled.length).toBeGreaterThanOrEqual(2);
  await expect(page.locator('.ai-risk-panel')).toHaveCount(0);
  noExecution(page);
});

test('read-only role sees offline computed candidates without a launch action', async ({ page }) => {
  await open(page, PORTAL_AUDITOR_SESSION);
  await panel(page).getByRole('button', { name: 'Generate', exact: true }).click();
  await expect(panel(page)).toContainText('Your role can review recommendations but cannot start scans.');
  await expect(panel(page)).toContainText('offline');
  await expect(panel(page).getByRole('button', { name: 'Review selected checks in scan launcher' })).toHaveCount(0);
  noExecution(page);
});

test('risk/plan surfaces fit four widths in both themes with keyboard, reduced motion and scoped axe', async ({ page }, testInfo) => {
  await page.emulateMedia({ reducedMotion: 'reduce' }); await open(page);
  for (const purpose of ['risk-stories', 'validation-plan']) await panel(page, purpose).getByRole('button', { name: 'Generate', exact: true }).click();
  await expect(panel(page).getByRole('group', { name: 'Review exact checks for this target' })).toBeVisible();
  // After clean navigation, replace only the locally empty font fixture; axe may
  // refetch external stylesheets as XHR, which application CSP correctly rejects.
  await page.evaluate((href) => { for (const link of document.querySelectorAll('link[rel="stylesheet"]')) if (link.href === href) { const style = document.createElement('style'); style.textContent = '/* system font fixture */'; link.replaceWith(style); } }, PORTAL_FONT_STYLESHEET);
  const disclosure = panel(page).getByText('Scope and limitations', { exact: true });
  await disclosure.focus(); await page.keyboard.press('Enter');
  await expect(panel(page).getByText('Scope and limitations', { exact: true }).locator('..')).toHaveAttribute('open', '');
  for (const width of [375, 768, 1024, 1440]) for (const theme of ['light', 'dark']) {
    await page.setViewportSize({ width, height: 1000 });
    await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
    await page.evaluate((theme) => { document.documentElement.dataset.theme = theme; }, theme);
    const geometry = await page.locator('.ai-risk-panel').evaluate((node) => ({ width: node.getBoundingClientRect().width, scroll: node.scrollWidth, page: document.documentElement.scrollWidth, viewport: innerWidth, reduced: matchMedia('(prefers-reduced-motion: reduce)').matches }));
    expect(geometry.scroll).toBeLessThanOrEqual(geometry.width + 1); expect(geometry.page).toBeLessThanOrEqual(width + 1); expect(geometry.reduced).toBe(true);
    const results = await new AxeBuilder({ page }).include('.ai-risk-panel').withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
    expect(results.violations.filter((row) => ['serious', 'critical'].includes(row.impact)).map((row) => ({ id: row.id, nodes: row.nodes.map((node) => node.target) }))).toEqual([]);
    const path = testInfo.outputPath(`risk-plan-${width}-${theme}.png`);
    // Keep the actual sticky header and surrounding workspace in their document positions.
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path, fullPage: true, animations: 'disabled' });
    await testInfo.attach(`risk-plan-${width}-${theme}`, { path, contentType: 'image/png' });
  }
  noExecution(page);
});
