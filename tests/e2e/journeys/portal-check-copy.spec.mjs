import { readFile } from 'node:fs/promises';
import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { CHECK_CATALOG } from '../../../src/contracts/checks.mjs';
import { checkPresentation } from '../../../src/lib/checkPresentation.mjs';
import { getPortalPlaywrightBaseUrl, seedPortalPlaywrightStore, startPortalPlaywrightServer, stopPortalPlaywrightServer } from '../../helpers/portal-playwright-server.mjs';
import { injectPortalDevHeadersSession } from '../../helpers/portal-playwright-session.mjs';
import { assertPortalInitialLoad } from '../../helpers/portal-browser-failures.mjs';

const TARGET = 'tgt_checkout_2';
const BASE64 = 'waf.evasion_base64_wrap.safe';
const OLD_EXPLANATION = 'The baseline harmless marker was allowed. Requests were sent, but evasion or inspection-limit resistance cannot be assessed without a blocked baseline.';

test.beforeAll(async ({ browser }) => {
  test.setTimeout(120000);
  await startPortalPlaywrightServer({ liveSource: true, env: { ASTRANULL_PROBE_MODE: 'simulation' } });
  const warm = await browser.newPage();
  try { await injectPortalDevHeadersSession(warm); await assertPortalInitialLoad(warm, getPortalPlaywrightBaseUrl()); }
  finally { await warm.close(); }
});
test.beforeEach(() => seedPortalPlaywrightStore());
test.afterAll(async () => { await stopPortalPlaywrightServer(); });

test('every one of the 275 published check cards contains its own complete explanation', async ({ page }) => {
  const html = await readFile(new URL('../../../docs/check-library.html', import.meta.url), 'utf8');
  await page.setContent(html);
  const cards = await page.locator('article.check').evaluateAll((nodes) => nodes.map((node) => ({
    id: node.id, name: node.querySelector('h3')?.textContent, text: node.textContent,
  })));
  expect(cards).toHaveLength(CHECK_CATALOG.length);
  expect(new Set(cards.map((card) => card.id)).size).toBe(CHECK_CATALOG.length);
  for (const check of CHECK_CATALOG) {
    const card = cards.find((entry) => entry.id === check.check_id);
    const copy = checkPresentation(check);
    expect(card?.name).toBe(copy.name);
    for (const field of ['purpose', 'mechanism', 'limitations', 'next_step']) expect(card?.text).toContain(copy[field]);
  }
});

test('the app shows separate purpose, steps, limits and next steps across every execution type', async ({ page }) => {
  test.setTimeout(120000);
  const writes = [];
  page.on('request', (request) => { if (request.method() === 'POST') writes.push(request.url()); });
  await injectPortalDevHeadersSession(page);
  for (const id of [BASE64, 'waf.evasion_parser_hpp.safe', 'waf.evasion_parser_json_dup.safe', 'waf.sqli_managed_marker.safe',
    'waf.ssrf_marker.safe', 'exploit.teardrop.posture', 'high_scale.volumetric.request_only', 'dns.zone_transfer_exposure.safe',
    'reflect.stun_turn_exposure.safe', 'tls.renegotiation.readiness', 'nfw.declared_deny_udp.safe', 'origin.identity_pair.get.v1']) {
    const copy = checkPresentation(id);
    await page.goto(`${getPortalPlaywrightBaseUrl()}/app#check-detail?id=${id}`);
    await expect(page.locator('#portal-main h1')).toHaveText(copy.name);
    const explainer = page.locator('.check-explainer');
    for (const field of ['purpose', 'mechanism', 'limitations', 'next_step']) await expect(page.locator('#portal-main')).toContainText(copy[field]);
    await expect(explainer.getByText('How it works', { exact: true })).toBeVisible();
    await expect(explainer.getByText('Limits', { exact: true })).toBeVisible();
    await expect(explainer).not.toContainText(/benign control|plain inert|supported transformed/i);
    expect(copy.purpose).not.toBe(copy.mechanism);
  }
  expect(writes).toEqual([]);
});

test('the Base64 row explains the old result in plain language and fits mobile and desktop', async ({ page }) => {
  test.setTimeout(90000);
  const now = new Date().toISOString();
  await page.route('**/v1/test-runs?*', async (route) => {
    if (new URL(route.request().url()).searchParams.get('target_id') !== TARGET) return route.fallback();
    await route.fulfill({ json: { items: [{ id: 'run_copy_history', check_id: BASE64, target_id: TARGET, status: 'verdicted', created_at: now,
      completed_at: now, summary: { requests_sent: 4 }, verdict: { verdict: 'inconclusive', explanation: OLD_EXPLANATION } }], count: 1 } });
  });
  await page.route('**/v1/validation-scans?*', (route) => route.fulfill({ json: { items: [], count: 0 } }));
  await injectPortalDevHeadersSession(page);
  await page.goto(`${getPortalPlaywrightBaseUrl()}/app#target-detail?id=${TARGET}&tab=validate&check=${BASE64}`);
  const row = page.locator('.td-check[data-selected=true]');
  const copy = checkPresentation(BASE64);
  await expect(row).toContainText(copy.name);
  for (const field of ['purpose', 'mechanism', 'limitations', 'next_step']) await expect(row).toContainText(copy[field]);
  await expect(row).toContainText('Your site allowed the original test text.');
  await expect(row).not.toContainText('baseline harmless');
  for (const theme of ['dark', 'light']) for (const width of [375, 1440]) {
    await page.setViewportSize({ width, height: 1100 });
    await page.evaluate((value) => document.documentElement.setAttribute('data-theme', value), theme);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
    const axe = await new AxeBuilder({ page }).include('.td-check[data-selected=true]').withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
    expect(axe.violations.filter((item) => ['serious', 'critical'].includes(item.impact ?? '')).map((item) => item.id)).toEqual([]);
    await row.screenshot({ path: `/tmp/astranull-check-copy-${theme}-${width}.png` });
  }
});
