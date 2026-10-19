import { expect, test } from '@playwright/test';
import { startPortalPlaywrightServer, stopPortalPlaywrightServer, getPortalPlaywrightBaseUrl } from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, injectPortalDevHeadersSession } from '../../helpers/portal-playwright-session.mjs';
import { projectMissingControl } from '../../../src/lib/missingControlProjection.mjs';
import { buildAssistantFixPack } from '../../../src/services/assistantFixPacks.mjs';
import { collectPortalBrowserFailures } from '../../helpers/portal-browser-failures.mjs';
import { PORTAL_FONT_STYLESHEET } from '../../helpers/portal-browser-resources.mjs';
import AxeBuilder from '@axe-core/playwright';

const diagnostics = new WeakMap();
test.beforeEach(async ({ page }, testInfo) => {
  diagnostics.set(page, await collectPortalBrowserFailures(page, getPortalPlaywrightBaseUrl(), {
    allowResponse: (response) => testInfo.title.startsWith('request errors') && response.request().method() === 'POST' && new URL(response.url()).pathname === '/v1/assistant/fix-packs' && response.status() === 503,
  }));
});
test.afterEach(async ({ page }) => { diagnostics.get(page).assertClean(); });

let finding;
let packs;
const missing = projectMissingControl({ checkId: 'l7.low_rate_rate_limit.safe', gap: true, edgeDetection: { waf: { status: 'detected', provider: 'cloudflare' } } });

test.beforeAll(async () => {
  await startPortalPlaywrightServer({ liveSource: true, mutate(store) {
    finding = store.findings[0];
    finding.check_id = 'l7.low_rate_rate_limit.safe';
    finding.status = 'open';
  } });
  packs = Object.fromEntries(await Promise.all(['cloudflare', 'generic'].map(async (provider) => {
    const built = await buildAssistantFixPack({ tenantId: finding.tenant_id, userId: 'usr_owner', role: 'owner' }, { finding_id: finding.id, provider }, { getFinding: async () => finding });
    return [provider, built.pack];
  })));
});
test.afterAll(async () => { await stopPortalPlaywrightServer(); });

async function open(page, mode = 'done') {
  const requests = [];
  const cancelled = [];
  const jobs = new Map();
  let release;
  const delayedCreation = new Promise((resolve) => { release = resolve; });
  await page.route('**/v1/assistant/status', (route) => route.fulfill({ json: { enabled: true, tenant_enabled: true, runner_online: true, capabilities: {} } }));
  await page.route(`**/v1/findings/${finding.id}`, async (route) => {
    if (route.request().method() !== 'GET') return route.fallback();
    const response = await route.fetch();
    return route.fulfill({ json: { ...await response.json(), missing_control: missing } });
  });
  await page.route('**/v1/assistant/fix-packs', async (route) => {
    const body = route.request().postDataJSON(); requests.push(body);
    if (mode === 'error' && requests.length === 1) return route.fulfill({ status: 503, json: { error: 'assistant_unavailable' } });
    const pack = packs[body.provider];
    const id = `asj_fix_${requests.length}`; jobs.set(id, pack);
    if (mode === 'late') await delayedCreation;
    return route.fulfill({ json: { pack, narrative: mode === 'offline' ? { status: 'unavailable', reason: 'assistant_runner_offline' } : { status: 'queued', job_id: id } } });
  });
  await page.route(/\/v1\/assistant\/jobs\/asj_fix_\d+$/, async (route) => {
    const id = route.request().url().split('/').pop();
    if (route.request().method() === 'DELETE') { cancelled.push(id); return route.fulfill({ json: { status: 'cancelled' } }); }
    if (mode === 'hold') return route.fulfill({ json: { status: 'running' } });
    const pack = jobs.get(id);
    const tailored = { ...pack, title: 'Reviewable provider fix pack', steps: ['<script>window.fixPackExecuted = true</script>', 'Review the published rate-limit scope.'] };
    return route.fulfill({ json: { status: 'done', response: { fix_pack: mode === 'invalid' ? { ...tailored, citations: ['foreign_id'] } : tailored } } });
  });
  const mutations = [];
  page.on('request', (request) => { if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(request.method())) mutations.push(new URL(request.url()).pathname); });
  await injectPortalDevHeadersSession(page);
  await gotoPortalRoute(page, 'finding-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'finding-detail': finding.id } });
  return { requests, cancelled, mutations, release, panel: page.getByRole('region', { name: 'Provider fix pack' }).first() };
}

test('generation is explicit, structured snippets are escaped and no changes or retest occur', async ({ page }) => {
  const { panel, requests, mutations } = await open(page);
  await expect(panel.getByRole('button', { name: 'Generate fix pack' })).toBeVisible();
  expect(requests).toEqual([]);
  await panel.getByRole('button', { name: 'Generate fix pack' }).click();
  await expect(panel).toContainText('Reviewable provider fix pack', { timeout: 15000 });
  await expect(panel).toContainText('AI-written');
  await expect(panel).toContainText('<script>window.fixPackExecuted = true</script>');
  await expect(panel.locator('script,img,iframe')).toHaveCount(0);
  expect(await page.evaluate(() => window.fixPackExecuted)).toBeUndefined();
  expect(requests).toEqual([{ finding_id: finding.id, provider: 'cloudflare' }]);
  expect(mutations.filter((path) => !path.startsWith('/v1/assistant/'))).toEqual([]);
  await expect(page.locator('.missing-control-steps').first()).toBeVisible();
  await expect(panel.getByRole('button', { name: /^Apply/ })).toHaveCount(0);
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  await panel.getByRole('button', { name: 'Copy fix pack' }).click();
  await expect(panel.getByRole('button', { name: 'Copied fix pack' })).toBeVisible();
});

test('offline and invalid AI output keep the published fallback and offer retry', async ({ page }) => {
  const { panel } = await open(page, 'invalid');
  await panel.getByRole('button', { name: 'Generate fix pack' }).click();
  await expect(panel).toContainText('did not finish', { timeout: 15000 });
  await expect(panel).toContainText(packs.cloudflare.title);
  await expect(panel).not.toContainText('Reviewable provider fix pack');
  await expect(panel.getByRole('button', { name: 'Retry fix pack' })).toBeEnabled();
});

test('cancel stops polling, retries explicitly and provider changes discard stale output', async ({ page }) => {
  const { panel, requests, cancelled } = await open(page, 'hold');
  await panel.getByRole('button', { name: 'Generate fix pack' }).click();
  await expect(panel.getByRole('button', { name: 'Cancel generation' })).toBeVisible();
  await panel.getByRole('button', { name: 'Cancel generation' }).click();
  await expect(panel).toContainText('Generation cancelled');
  await expect.poll(() => cancelled.length).toBe(1);
  await panel.getByRole('button', { name: 'Retry fix pack' }).click();
  await expect.poll(() => requests.length).toBe(2);
  await page.getByRole('tab', { name: 'Any provider', exact: true }).click();
  await expect(panel).not.toContainText(packs.cloudflare.title);
  await expect(panel.getByRole('button', { name: 'Generate fix pack' })).toBeVisible();
  await expect.poll(() => cancelled.length).toBeGreaterThanOrEqual(2);
});

test('cancelling before the POST returns cancels its late job without displaying it', async ({ page }) => {
  const { panel, requests, cancelled, release } = await open(page, 'late');
  await panel.getByRole('button', { name: 'Generate fix pack' }).click();
  await expect.poll(() => requests.length).toBe(1);
  await panel.getByRole('button', { name: 'Cancel generation' }).click();
  release();
  await expect.poll(() => cancelled).toEqual(['asj_fix_1']);
  await expect(panel).toContainText('Generation cancelled');
  await expect(panel).not.toContainText(packs.cloudflare.title);
  await expect(panel).not.toContainText('Reviewable provider fix pack');
});

test('request errors preserve original guidance and retry succeeds only on click', async ({ page }) => {
  const { panel, requests } = await open(page, 'error');
  await panel.getByRole('button', { name: 'Generate fix pack' }).click();
  await expect(panel).toContainText('could not be generated');
  await expect(page.locator('.missing-control-steps').first()).toBeVisible();
  expect(requests).toHaveLength(1);
  await panel.getByRole('button', { name: 'Retry fix pack' }).click();
  await expect(panel).toContainText('Reviewable provider fix pack', { timeout: 15000 });
  expect(requests).toHaveLength(2);
});

test('changing session clears pending output without persisting a fix pack', async ({ page }) => {
  const { panel, requests } = await open(page, 'hold');
  await panel.getByRole('button', { name: 'Generate fix pack' }).click();
  await expect(panel).toContainText(packs.cloudflare.title);
  await page.evaluate(() => {
    const session = JSON.parse(sessionStorage.getItem('astranull.portal.session.v1'));
    session.user_id = 'usr_different';
    sessionStorage.setItem('astranull.portal.session.v1', JSON.stringify(session));
  });
  // A new document consumes the changed authenticated session. No pack is persisted.
  await page.reload({ waitUntil: 'networkidle' });
  await expect(panel.getByRole('button', { name: 'Generate fix pack' })).toBeVisible();
  await expect(panel).not.toContainText(packs.cloudflare.title);
  expect(requests).toHaveLength(1);
});

test('offline static fallback is clear and never starts polling', async ({ page }) => {
  const { panel } = await open(page, 'offline');
  await panel.getByRole('button', { name: 'Generate fix pack' }).click();
  await expect(panel).toContainText('runner is offline');
  await expect(panel).toContainText(packs.cloudflare.title);
  await expect(panel).toContainText('Computed');
  await expect(panel.getByRole('button', { name: 'Cancel generation' })).toHaveCount(0);
});

test('provider fallback fits four widths and both themes with keyboard, reduced motion and scoped axe', async ({ page }, testInfo) => {
  test.setTimeout(120000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const { panel } = await open(page, 'offline');
  await panel.getByRole('button', { name: 'Generate fix pack' }).focus();
  await page.keyboard.press('Enter');
  await expect(panel).toContainText(packs.cloudflare.title);
  await page.evaluate((href) => { for (const link of document.querySelectorAll('link[rel="stylesheet"]')) if (link.href === href) { const style = document.createElement('style'); style.textContent = '/* system font fixture */'; link.replaceWith(style); } }, PORTAL_FONT_STYLESHEET);
  for (const width of [375, 768, 1024, 1440]) for (const theme of ['light', 'dark']) {
    await page.setViewportSize({ width, height: 1000 });
    await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
    await page.evaluate((theme) => { document.documentElement.dataset.theme = theme; }, theme);
    const geometry = await panel.evaluate((node) => ({ width: node.getBoundingClientRect().width, scroll: node.scrollWidth, page: document.documentElement.scrollWidth, reduced: matchMedia('(prefers-reduced-motion: reduce)').matches }));
    expect(geometry.scroll).toBeLessThanOrEqual(geometry.width + 1); expect(geometry.page).toBeLessThanOrEqual(width + 1); expect(geometry.reduced).toBe(true);
    const result = await new AxeBuilder({ page }).include('.provider-fix-pack').withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
    expect(result.violations.filter((row) => ['serious', 'critical'].includes(row.impact)).map((row) => ({ id: row.id, nodes: row.nodes.map((node) => node.target) }))).toEqual([]);
    const path = testInfo.outputPath(`fix-pack-${width}-${theme}.png`);
    // Capture the document from its real top so sticky chrome cannot be stitched across an offscreen panel.
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path, fullPage: true, animations: 'disabled' });
    await testInfo.attach(`fix-pack-${width}-${theme}`, { path, contentType: 'image/png' });
  }
});
