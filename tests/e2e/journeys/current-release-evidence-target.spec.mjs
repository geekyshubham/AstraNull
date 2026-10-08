/**
 * Current release journeys: shared evidence inspector, return state, grouped-member stepping,
 * unified target workspace and governed retest review.
 *
 * The API is the in-process portal server over an isolated ASTRANULL_DEV_DATA_DIR with a seeded
 * synthetic store (simulated probes, dev-headers auth). The UI is served by Vite from live source
 * so the journeys exercise the current React code without rebuilding tracked bundles. Nothing is
 * sent to any external target; a request log asserts inspection never issues a mutating call.
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { createServer as createViteServer } from 'vite';
import AxeBuilder from '@axe-core/playwright';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import { applyPortalBaselineReadinessBoost as applyReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import { injectPortalDevHeadersSession } from '../../helpers/portal-playwright-session.mjs';
import { getStore } from '../../../src/store.mjs';
import { acceptTargetObservation } from '../../../src/services/targetHistory.mjs';
import { archiveOriginBinding, createOriginBinding } from '../../../src/services/originBindings.mjs';
import { registerRetestLineage } from '../../../src/services/retestLineage.mjs';

const ids = PORTAL_BASELINE_IDS;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
let vite = null;
let webBase = '';

const LONG_TARGET_ID = `tgt_${'longid'.repeat(18)}`.slice(0, 120);
const LONG_HOST = `${'deeply-nested-service-label-'.repeat(4)}checkout.example.test`;

function seed(store) {
  const base = store.targets.find((target) => target.id === ids.targetId);
  store.targets.push({ ...base, id: LONG_TARGET_ID, value: LONG_HOST, metadata: { ...(base.metadata ?? {}), tags: ['env:prod', 'team:payments-platform-edge-reliability'] } });
  store.findings.push({
    id: 'fnd_member_pay',
    tenant_id: ids.tenantId,
    target_group_id: ids.targetGroupId,
    target_id: 'tgt_checkout_2',
    test_run_id: 'run_checkout_1',
    check_id: ids.checkId,
    severity: 's2',
    title: 'Origin direct bypass',
    state: 'open',
    opened_at: ids.frozenAt,
  });
}

/** Records every /v1 call so a test can prove inspection stayed read-only. */
function trackApi(page) {
  const calls = [];
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith('/v1/')) calls.push({ method: request.method(), path: url.pathname });
  });
  return calls;
}

function mutating(calls) {
  return calls.filter((call) => call.method !== 'GET' && call.method !== 'HEAD');
}

async function open(page, hash, { theme = 'dark' } = {}) {
  await page.addInitScript((value) => {
    try { localStorage.setItem('astranull.theme', value); } catch { /* storage blocked */ }
  }, theme);
  await injectPortalDevHeadersSession(page);
  await page.goto(`${webBase}/app#${hash}`, { waitUntil: 'networkidle', timeout: 120_000 });
  await page.locator('#portal-main').waitFor({ timeout: 60_000 });
}

function inspector(page) {
  return page.locator('.inspector-panel');
}

test.describe.configure({ mode: 'serial' });

test.describe('current release: evidence inspector and target workspace', () => {
  test.beforeAll(async ({ browser }) => {
    test.setTimeout(240_000);
    await startPortalPlaywrightServer({ mutate: seed });
    const apiBase = getPortalPlaywrightBaseUrl();
    vite = await createViteServer({
      configFile: path.join(ROOT, 'vite.config.ts'),
      root: path.join(ROOT, 'apps/web/react'),
      logLevel: 'error',
      server: { host: '127.0.0.1', port: 0, strictPort: false, hmr: false, proxy: { '/v1': apiBase, '/ready': apiBase, '/internal': apiBase } },
    });
    await vite.listen();
    webBase = `http://127.0.0.1:${vite.httpServer.address().port}`;
    // Vite optimizes dependencies on the first page load and reloads once; absorb that here.
    const warm = await browser.newPage();
    await injectPortalDevHeadersSession(warm);
    await warm.goto(`${webBase}/app#dashboard`, { waitUntil: 'networkidle', timeout: 180_000 }).catch(() => undefined);
    await warm.waitForTimeout(6000);
    await warm.reload({ waitUntil: 'networkidle' }).catch(() => undefined);
    await warm.locator('#portal-main').waitFor({ timeout: 120_000 }).catch(() => undefined);
    await warm.close();
  });

  test.afterAll(async () => {
    await vite?.close();
    await stopPortalPlaywrightServer();
  });

  test('finding row opens its original evidence in one action; Escape and Back restore the list (EI-01, EI-05, EI-08)', async ({ page }) => {
    test.setTimeout(180_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    const calls = trackApi(page);
    await open(page, 'findings');
    await page.getByRole('button', { name: 'Each finding' }).click();
    const row = page.locator('a.finding-card[data-focus-key="finding-fnd_checkout_1"]');
    await expect(row).toBeVisible();
    const before = calls.length;
    await row.click();

    await expect(inspector(page)).toBeVisible();
    await expect(inspector(page).getByRole('heading', { name: 'Finding evidence' })).toBeVisible();
    await expect(page).toHaveURL(/#findings\?.*inspect=finding&ev_finding=fnd_checkout_1/);
    await expect(inspector(page).getByText(/Original evidence/)).toBeVisible();
    await expect(page.locator('tr.is-selected')).toHaveCount(1);
    expect(mutating(calls.slice(before)), 'opening the inspector is read-only').toEqual([]);
    expect(calls.slice(before).some((call) => call.path === '/v1/evidence-context' || call.path.startsWith('/v1/findings/'))).toBe(true);
    expect(calls.slice(before).some((call) => call.path.startsWith('/v1/validation-scans'))).toBe(false);

    await page.keyboard.press('Escape');
    await expect(inspector(page)).toHaveCount(0);
    await expect(page).not.toHaveURL(/inspect=/);
    await expect(row).toBeFocused();

    await row.click();
    await expect(inspector(page)).toBeVisible();
    await page.goBack();
    await expect(inspector(page)).toHaveCount(0);
    await expect(page).toHaveURL(/#findings/);
    await expect(page.getByRole('button', { name: 'Each finding' })).toHaveAttribute('aria-pressed', 'true');
  });

  test('a failed legacy fallback shows its error and can retry instead of staying loading', async ({ page }) => {
    test.setTimeout(120_000);
    const calls = trackApi(page);
    await page.route('**/v1/evidence-context*', (route) => route.fulfill({
      status: 404, contentType: 'application/json', body: JSON.stringify({ error: 'not_found' }),
    }));
    const recordPath = '**/v1/findings/fnd_checkout_1';
    await page.route(recordPath, (route) => route.fulfill({
      status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'unavailable' }),
    }));
    await open(page, 'findings?inspect=finding&ev_finding=fnd_checkout_1');
    await expect(inspector(page).getByText('Evidence unavailable', { exact: true })).toBeVisible();
    await expect(inspector(page).locator('[data-state="loading"]')).toHaveCount(0);
    await page.unroute(recordPath);
    await inspector(page).getByRole('button', { name: 'Retry', exact: true }).click();
    await expect(inspector(page).getByText('Evidence unavailable', { exact: true })).toHaveCount(0);
    await expect(inspector(page)).toContainText('Origin direct bypass');
    expect(mutating(calls)).toEqual([]);
  });

  test('cold deep links resolve their own record and never substitute another (EI-05, EI-06)', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await open(page, 'findings?inspect=finding&ev_finding=fnd_checkout_1');
    await expect(inspector(page).getByRole('heading', { name: 'Finding evidence' })).toBeVisible();
    await expect(inspector(page)).toContainText('Origin Leak Scan');

    await page.goto(`${webBase}/app#findings?inspect=finding&ev_finding=fnd_does_not_exist`, { waitUntil: 'networkidle' });
    await expect(inspector(page).getByText('No longer available')).toBeVisible();
    await expect(inspector(page)).not.toContainText('Origin direct bypass');
  });

  test('group member Next and Previous change only the selected member, bounded at the ends (EI-04, TF-08)', async ({ page }) => {
    test.setTimeout(180_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    const calls = trackApi(page);
    await open(page, 'findings');
    await page.locator('a.rf-alert-link').filter({ hasText: /Origin direct bypass/ }).first().click();
    await expect(page).toHaveURL(/#finding-group-detail\?key=/);
    const viewButtons = page.getByRole('button', { name: /View evidence for the open finding on/ });
    await expect(viewButtons).toHaveCount(2);
    await viewButtons.first().click();

    const sequence = inspector(page).getByRole('navigation', { name: /Step through/ });
    await expect(sequence).toContainText('1 of 2');
    await expect(sequence.getByRole('button', { name: /No previous record/ })).toBeDisabled();
    const firstMember = new URL(page.url()).hash.match(/ev_finding=([^&]+)/)?.[1];
    await sequence.getByRole('button', { name: /^Next:/ }).click();
    await expect(sequence).toContainText('2 of 2');
    const secondMember = new URL(page.url()).hash.match(/ev_finding=([^&]+)/)?.[1];
    expect(secondMember).toBeTruthy();
    expect(secondMember).not.toBe(firstMember);
    await expect(sequence.getByRole('button', { name: /No next record/ })).toBeDisabled();
    await expect(page.locator('[aria-pressed="true"][data-focus-key^="member-"]')).toHaveAttribute('data-focus-key', `member-${secondMember}`);
    expect(mutating(calls)).toEqual([]);
  });

  test('opening a target never starts a probe; providers stay family-specific; tab aliases resolve (TF-02, doc 06)', async ({ page }) => {
    test.setTimeout(180_000);
    await page.setViewportSize({ width: 1440, height: 1000 });
    const calls = trackApi(page);
    await open(page, `target-detail?id=${ids.targetId}&tab=protection`);
    await expect(page.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByRole('heading', { name: 'Protection observations' })).toBeVisible();
    await page.waitForTimeout(1500);
    expect(mutating(calls), 'viewing a target issues no POST').toEqual([]);

    await page.getByRole('button', { name: 'How CDN was identified' }).click();
    await expect(inspector(page).getByRole('heading', { name: /How this was identified: CDN/ })).toBeVisible();
    await expect(inspector(page)).toContainText('CDN only. Other layers are reported separately.');
    expect(mutating(calls)).toEqual([]);
    await inspector(page).getByRole('button', { name: /Close/ }).click();

    await page.goto(`${webBase}/app#target-detail?id=${ids.targetId}&tab=runs`, { waitUntil: 'networkidle' });
    await expect(page.getByRole('tab', { name: 'Changes & history' })).toHaveAttribute('aria-selected', 'true');
  });

  test('selected check survives reload and its start requires a reviewed confirmation (direct flow AC 1, 2, 4)', async ({ page }) => {
    test.setTimeout(180_000);
    await page.setViewportSize({ width: 1440, height: 1000 });
    const calls = trackApi(page);
    await open(page, `target-detail?id=${ids.targetId}&tab=validate`);
    await page.locator('details.td-cat > summary').filter({ hasText: 'Origin exposure' }).click();
    await page.getByRole('radio', { name: /Select Origin Leak Scan/ }).check();
    await expect(page).toHaveURL(/check=origin\.leak_scan\.safe/);
    await page.reload({ waitUntil: 'networkidle' });
    await expect(page.getByRole('radio', { name: /Select Origin Leak Scan/ })).toBeChecked();
    await expect(page.getByRole('tab', { name: /Validate/ })).toHaveAttribute('aria-selected', 'true');

    await page.getByRole('button', { name: 'Review and start' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Upper bound');
    await expect(dialog).toContainText('checkout.acme.com');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    expect(mutating(calls), 'reviewing does not start the check').toEqual([]);
  });

  test('retest opens a scoped review and cancelling sends nothing (EI-08, T11)', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    const calls = trackApi(page);
    await open(page, `finding-detail?id=${ids.findingId}&retest=review`);
    const dialog = page.getByRole('dialog', { name: 'Review this retest' });
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText('Origin Leak Scan');
    await expect(dialog).toContainText('never closes other domains');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(page).not.toHaveURL(/retest=review/);
    expect(mutating(calls)).toEqual([]);
  });

  test('phone sheet keeps Back reachable and returns to the target (EI-10)', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 375, height: 812 });
    await open(page, `target-detail?id=${ids.targetId}&tab=validate&check=${ids.checkId}`, { theme: 'light' });
    await page.locator(`[data-focus-key="check-evidence-${ids.checkId}"]`).click();
    const sheet = page.locator('dialog.inspector-panel[data-mode="sheet"]');
    await expect(sheet).toBeVisible();
    const back = sheet.getByRole('button', { name: 'Back' });
    await expect(back).toBeInViewport();
    await back.click();
    await expect(sheet).toHaveCount(0);
    await expect(page).toHaveURL(new RegExp(`check=${ids.checkId.replace(/\./g, '\\.')}`));
    const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(scrollWidth).toBeLessThanOrEqual(375);
  });

  test('dashboard counts open the same predicate they report (TF-01)', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await open(page, 'dashboard');
    await page.getByRole('link', { name: /Open the open findings queue/ }).click();
    await expect(page).toHaveURL(/#findings\?status=open/);
    await expect(page.getByRole('group', { name: 'Finding status filters' }).getByRole('button', { name: /^Open/ })).toHaveAttribute('aria-pressed', 'true');

    await page.goto(`${webBase}/app#dashboard`, { waitUntil: 'networkidle' });
    await page.getByRole('link', { name: /Open targets with ownership pending/ }).click();
    await expect(page).toHaveURL(/#targets\?verification=unverified/);
    await expect(page.locator('.targets-filter select').first()).toHaveValue('unverified');
  });

  test('a delayed refresh never moves the hovered row; updates wait behind Show updates (LIVE-01)', async ({ page }) => {
    test.setTimeout(180_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await open(page, 'findings');
    await page.getByRole('button', { name: 'Each finding' }).click();
    const rows = page.locator('.rf-findings-table tbody tr');
    await expect(rows).toHaveCount(2);
    const firstId = await rows.first().locator('a.finding-card').getAttribute('data-focus-key');

    // The refresh response is delayed and carries a new, more severe finding that would sort first.
    getStore().findings.push({
      id: 'fnd_live_new', tenant_id: ids.tenantId, target_group_id: ids.targetGroupId, target_id: ids.targetId,
      check_id: 'edge.rate_limit.safe', severity: 's1', title: 'Rate limit bypass', state: 'open', opened_at: ids.frozenAt,
    });
    await page.route('**/v1/findings*', async (route) => {
      await new Promise((resolve) => setTimeout(resolve, 2000));
      await route.continue();
    });
    await page.getByRole('button', { name: 'Refresh' }).click();
    // While the response is in flight the user points at the first row.
    await rows.first().hover();
    const before = await rows.first().boundingBox();
    await expect(page.getByRole('status').filter({ hasText: 'Newer results arrived' })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole('status').filter({ hasText: 'Newer results arrived' })).toContainText('1 new');
    await expect(rows).toHaveCount(2);
    await expect(rows.first().locator('a.finding-card')).toHaveAttribute('data-focus-key', firstId);
    expect((await rows.first().boundingBox()).y).toBe(before.y);
    // Moving away does not apply it on its own either; only the explicit action does.
    await page.mouse.move(5, 5);
    await expect(rows).toHaveCount(2);
    await page.unroute('**/v1/findings*');
    await page.getByRole('button', { name: 'Show updates' }).click();
    await expect(rows).toHaveCount(3);
    await expect(page.locator('a.finding-card[data-focus-key="finding-fnd_live_new"]')).toBeVisible();
    getStore().findings = getStore().findings.filter((finding) => finding.id !== 'fnd_live_new');
  });

  test('a refresh while inspecting keeps the inspector open and the list held (LIVE-01)', async ({ page }) => {
    test.setTimeout(180_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await open(page, 'findings');
    await page.getByRole('button', { name: 'Each finding' }).click();
    await page.locator('a.finding-card[data-focus-key="finding-fnd_checkout_1"]').click();
    await expect(inspector(page)).toBeVisible();
    getStore().findings.push({
      id: 'fnd_live_two', tenant_id: ids.tenantId, target_group_id: ids.targetGroupId, target_id: ids.targetId,
      check_id: 'edge.rate_limit.safe', severity: 's1', title: 'Rate limit bypass', state: 'open', opened_at: ids.frozenAt,
    });
    await page.getByRole('button', { name: 'Refresh' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Newer results arrived' })).toBeVisible({ timeout: 15_000 });
    await expect(inspector(page)).toBeVisible();
    await expect(page).toHaveURL(/ev_finding=fnd_checkout_1/);
    await expect(page.locator('tr.is-selected a.finding-card')).toHaveAttribute('data-focus-key', 'finding-fnd_checkout_1');
    await expect(page.locator('a.finding-card[data-focus-key="finding-fnd_live_two"]')).toHaveCount(0);
    getStore().findings = getStore().findings.filter((finding) => finding.id !== 'fnd_live_two');
  });

  test('switching role hides the previous scope payload until the new read lands (EI-R06)', async ({ page }) => {
    test.setTimeout(180_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await open(page, `findings?inspect=finding&ev_finding=${ids.findingId}`);
    await expect(inspector(page).getByText(/Original evidence/)).toBeVisible();
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    await page.route('**/v1/evidence-context*', async (route) => {
      await gate;
      await route.continue();
    });
    await page.getByRole('button', { name: /Role \(dev\)/ }).click();
    await page.getByRole('option', { name: /viewer/i }).click();
    // The owner's model must not be readable for the viewer scope, even for one render.
    await expect(inspector(page).locator('.ei-loading')).toBeVisible();
    await expect(inspector(page).getByText(/Original evidence/)).toHaveCount(0);
    release();
    await expect(inspector(page).getByText(/Original evidence/)).toBeVisible({ timeout: 15_000 });
  });

  test('credential-like address parameters never survive inspector rewrites (NAV-02)', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await open(page, 'findings?status=open&invite_token=pwi_synthetic_value&debug=1');
    await page.getByRole('button', { name: 'Each finding' }).click();
    await page.locator('a.finding-card[data-focus-key="finding-fnd_checkout_1"]').click();
    await expect(inspector(page)).toBeVisible();
    const hash = new URL(page.url()).hash;
    expect(hash).toContain('status=open');
    expect(hash).toContain('inspect=finding');
    expect(hash).not.toMatch(/invite_token|pwi_|debug/);
  });

  test('unknown routes, denied routes and missing records stay distinct (TF-18)', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await open(page, 'no-such-page');
    await expect(page.locator('[data-unavailable-kind="not-found"]')).toBeVisible();

    await page.goto(`${webBase}/app#target-detail?id=tgt_does_not_exist`, { waitUntil: 'networkidle' });
    const missing = page.locator('[data-unavailable-kind="record-missing"]');
    await expect(missing).toBeVisible();
    await expect(missing.getByRole('link', { name: 'Back to targets' })).toBeVisible();
    await expect(page.locator('.target-detail-view')).toHaveCount(0);

    await page.getByRole('button', { name: /Role \(dev\)/ }).click();
    await page.getByRole('option', { name: /viewer/i }).click();
    const calls = [];
    page.on('request', (request) => { if (new URL(request.url()).pathname.startsWith('/v1/audit')) calls.push(request.url()); });
    await page.goto(`${webBase}/app#audit`, { waitUntil: 'networkidle' });
    const denied = page.locator('[data-unavailable-kind="access-denied"]');
    await expect(denied).toBeVisible();
    await expect(denied).toContainText('viewer');
    await page.waitForTimeout(9000);
    await expect(denied, 'the denial persists rather than swapping to a healthy page').toBeVisible();
    await expect(page).toHaveURL(/#audit$/);
    expect(calls, 'nothing from the denied route is loaded').toEqual([]);
  });

  test('long identifiers and 200% zoom keep the target workspace and inspector usable (EI-10)', async ({ page }) => {
    test.setTimeout(180_000);
    for (const theme of ['dark', 'light']) {
      // 640 CSS px is a 1280px window at 200% zoom.
      await page.setViewportSize({ width: 640, height: 900 });
      await open(page, `target-detail?id=${LONG_TARGET_ID}`, { theme });
      await expect(page.getByRole('heading', { level: 1 })).toContainText('deeply-nested-service-label');
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(overflow, `page-level horizontal overflow (${theme})`).toBeLessThanOrEqual(0);
      await expect(page.getByRole('tab', { name: 'Overview' })).toBeVisible();
      await page.getByRole('button', { name: 'How CDN was identified' }).click();
      const panel = page.locator('.inspector-panel');
      await expect(panel).toBeVisible();
      const panelOverflow = await panel.evaluate((node) => node.scrollWidth - node.clientWidth);
      expect(panelOverflow, `inspector horizontal overflow (${theme})`).toBeLessThanOrEqual(1);
      await page.keyboard.press('Escape');
    }
  });
});

const BULK = 55;

function seedCohorts(store) {
  const base = store.targets.find((target) => target.id === ids.targetId);
  for (let index = 0; index < BULK; index += 1) {
    const host = `bulk-${String(index).padStart(2, '0')}.example.test`;
    store.targets.push({ ...structuredClone(base), id: `tgt_bulk_${String(index).padStart(2, '0')}`, value: host, normalized_value: host });
  }
  // A URL target on the same host as the baseline FQDN: one hostname, two declared targets.
  store.targets.push({ ...structuredClone(base), id: 'tgt_checkout_login_url', kind: 'url', value: `https://${base.value}/login`, normalized_value: `https://${base.value}/login` });
}

async function startUi(browser, mutate) {
  await startPortalPlaywrightServer({ mutate });
  const apiBase = getPortalPlaywrightBaseUrl();
  vite = await createViteServer({
    configFile: path.join(ROOT, 'vite.config.ts'),
    root: path.join(ROOT, 'apps/web/react'),
    logLevel: 'error',
    server: { host: '127.0.0.1', port: 0, strictPort: false, hmr: false, proxy: { '/v1': apiBase, '/ready': apiBase, '/internal': apiBase } },
  });
  await vite.listen();
  webBase = `http://127.0.0.1:${vite.httpServer.address().port}`;
  const warm = await browser.newPage();
  await injectPortalDevHeadersSession(warm);
  await warm.goto(`${webBase}/app#dashboard`, { waitUntil: 'networkidle', timeout: 180_000 }).catch(() => undefined);
  await warm.waitForTimeout(6000);
  await warm.reload({ waitUntil: 'networkidle' }).catch(() => undefined);
  await warm.locator('#portal-main').waitFor({ timeout: 120_000 }).catch(() => undefined);
  await warm.close();
}

/** Records the query string of each GET /v1/targets read. */
function trackTargetReads(page) {
  const reads = [];
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (request.method() === 'GET' && url.pathname === '/v1/targets' && url.search) reads.push(Object.fromEntries(url.searchParams));
  });
  return reads;
}

function cohort(page) {
  return page.locator('section.cohort-panel');
}

test.describe('current release: server cohorts from dashboard analytics', () => {
  test.beforeAll(async ({ browser }) => {
    test.setTimeout(240_000);
    await startUi(browser, seedCohorts);
  });

  test.afterAll(async () => {
    await vite?.close();
    vite = null;
    await stopPortalPlaywrightServer();
  });

  test('a coverage segment opens the exact server cohort with the same count and unit', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1440, height: 1000 });
    const reads = trackTargetReads(page);
    await open(page, 'dashboard');
    const segment = page.getByRole('link', { name: /^WAF observations not checked: [\d,]+ distinct hostnames/ });
    const label = await segment.getAttribute('aria-label');
    const dashboardCount = Number(label.match(/: ([\d,]+) /)[1].replaceAll(',', ''));
    expect(dashboardCount).toBeGreaterThan(50);
    await segment.click();
    await expect(page).toHaveURL(/#targets\?family=waf&family_status=not_checked&unit=hostname$/);
    await expect(cohort(page).getByRole('heading', { name: 'Matching hostnames' })).toBeVisible();
    await expect(cohort(page).locator('.cohort-count')).toContainText(`Showing 1 to 50 of ${dashboardCount} distinct hostnames.`);
    await expect(cohort(page).locator('.cohort-count')).toContainText(`Same scope: ${dashboardCount + 1} declared target records and ${dashboardCount} distinct hostnames.`);
    await expect(cohort(page).getByRole('list', { name: 'Applied filters' })).toContainText('Counted as Distinct hostnames');
    expect(reads.at(-1)).toMatchObject({ family: 'waf', family_status: 'not_checked', unit: 'hostname', limit: '50' });
    await expect(page.locator('.targets-summary, .inventory-card')).toHaveCount(0);

    await page.goto(`${webBase}/app#dashboard`, { waitUntil: 'networkidle' });
    await page.getByRole('group', { name: 'Count by' }).getByRole('button', { name: 'Declared target records' }).click();
    const records = page.getByRole('link', { name: /^WAF observations not checked: \d+ declared target records/ });
    await expect(records).toHaveAttribute('aria-label', new RegExp(`: ${dashboardCount + 1} declared target records`));
    await records.click();
    await expect(page).toHaveURL(/unit=target$/);
    await expect(cohort(page).locator('.cohort-count')).toContainText(`of ${dashboardCount + 1} declared target records.`);
  });

  test('paging follows server cursors and a clock mismatch restarts at page one with the same filters', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1440, height: 1000 });
    const reads = trackTargetReads(page);
    await open(page, 'targets?family=waf&unit=hostname');
    const pager = cohort(page).getByRole('navigation', { name: 'Matching targets pages' });
    await expect(pager).toContainText('Page 1 of 2');
    await pager.getByRole('button', { name: 'Next' }).click();
    await expect(pager).toContainText('Page 2 of 2');
    await expect(cohort(page).locator('.cohort-count')).toContainText(/Showing 51 to \d+ of \d+ distinct hostnames/);
    expect(reads.at(-1).cursor).toBeTruthy();
    expect(reads.at(-1)).toMatchObject({ family: 'waf', unit: 'hostname' });
    await expect(pager.getByRole('button', { name: 'Next' })).toBeDisabled();
    await pager.getByRole('button', { name: 'Previous' }).click();
    await expect(pager).toContainText('Page 1 of 2');

    // The real server rejects a cursor read at another clock; the list restarts, filters intact.
    await page.route('**/v1/targets?*cursor=*', (route) => route.continue({ url: `${route.request().url()}&as_of=2020-01-01T00:00:00.000Z` }), { times: 1 });
    await pager.getByRole('button', { name: 'Next' }).click();
    await expect(cohort(page).getByRole('status')).toHaveText(/Paging restarted at the first page .* Your filters are unchanged\./);
    await expect(pager).toContainText('Page 1 of 2');
    await expect(page).toHaveURL(/#targets\?family=waf&unit=hostname$/);
    expect(reads.at(-1).cursor).toBeUndefined();
  });

  test('a changed cohort refreshes the same filters without claiming a snapshot', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1440, height: 1000 });
    const reads = trackTargetReads(page);
    await open(page, 'targets?q=late-arrival&unit=target');
    await expect(cohort(page).getByRole('heading', { name: 'No targets match these filters' })).toBeVisible();
    const base = getStore().targets.find((target) => target.id === ids.targetId);
    getStore().targets.push({ ...structuredClone(base), id: 'tgt_late_arrival', value: 'late-arrival.example.test', normalized_value: 'late-arrival.example.test' });
    try {
      await cohort(page).getByRole('button', { name: 'Refresh' }).click();
      await expect(cohort(page).getByRole('status')).toHaveText(/changed since this list loaded\. Showing the current set for the same filters; earlier rows are not kept as a snapshot\./);
      await expect(cohort(page).locator('.cohort-count')).toContainText('Showing 1 to 1 of 1 declared target records.');
      const versioned = reads.find((read) => read.cohort_version);
      expect(versioned).toMatchObject({ q: 'late-arrival', unit: 'target' });
      expect(reads.at(-1)).toMatchObject({ q: 'late-arrival', unit: 'target' });
      expect(reads.at(-1).cohort_version).toBeUndefined();
      await expect(page.getByText(/snapshot as of|historical/i)).toHaveCount(0);
    } finally {
      getStore().targets = getStore().targets.filter((target) => target.id !== 'tgt_late_arrival');
    }
  });

  test('a shared hostname lists every declared target and never picks one for the user', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1440, height: 1000 });
    const host = getStore().targets.find((target) => target.id === ids.targetId).value;
    await open(page, `targets?q=${encodeURIComponent(host)}&unit=hostname`);
    const row = cohort(page).locator('tbody tr').filter({ hasText: host });
    await expect(row).toHaveCount(1);
    await expect(row.getByRole('link', { name: /^Open target / })).toHaveCount(0);
    await expect(row.getByText('Per declared target', { exact: true }).first()).toBeVisible();
    await row.getByText('2 declared targets share this hostname').click();
    const members = row.locator('.cohort-members li');
    await expect(members).toHaveCount(2);
    await expect(row.getByRole('link', { name: /^Open declared target / })).toHaveCount(2);
    await expect(row.getByText('none is chosen for you', { exact: false })).toBeVisible();
    const hrefs = await row.getByRole('link', { name: /^Open declared target / }).evaluateAll((links) => links.map((link) => link.getAttribute('href')));
    expect(hrefs.sort()).toEqual([`/app#target-detail?id=${ids.targetId}`, '/app#target-detail?id=tgt_checkout_login_url'].sort());

    await open(page, `targets?q=${encodeURIComponent(host)}&unit=target`);
    await expect(cohort(page).locator('.cohort-count')).toContainText('of 2 declared target records.');
    await expect(cohort(page).locator('.cohort-count')).toContainText('2 declared target records and 1 distinct hostnames.');
  });

  test('switching role reloads the cohort for the new scope and keeps its filters', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1440, height: 1000 });
    const reads = trackTargetReads(page);
    await open(page, 'targets?family=cdn&family_status=not_checked&unit=hostname');
    await expect(cohort(page).locator('.cohort-count')).toContainText('distinct hostnames');
    const before = reads.length;
    await page.getByRole('button', { name: /Role \(dev\)/ }).click();
    await page.getByRole('option', { name: /viewer/i }).click();
    await expect.poll(() => reads.length).toBeGreaterThan(before);
    expect(reads.at(-1)).toMatchObject({ family: 'cdn', family_status: 'not_checked', unit: 'hostname' });
    await expect(cohort(page).locator('.cohort-count')).toContainText('distinct hostnames');
    await expect(page).toHaveURL(/#targets\?family=cdn&family_status=not_checked&unit=hostname$/);
  });

  test('an unsupported filter is rejected visibly instead of showing the whole inventory', async ({ page }) => {
    test.setTimeout(120_000);
    await page.route('**/v1/targets?*family=waf*', (route) => route.continue({ url: `${route.request().url()}&origin_status=exposed` }));
    await open(page, 'targets?family=waf&unit=hostname');
    await expect(cohort(page).getByRole('alert')).toContainText('The server rejected these filters (unknown_query_param)');
    await expect(cohort(page).locator('tbody tr')).toHaveCount(0);
  });

  test('the findings domain alias applies the exact server target predicate', async ({ page }) => {
    test.setTimeout(120_000);
    const findingReads = [];
    page.on('request', (request) => {
      const url = new URL(request.url());
      if (url.pathname === '/v1/findings' && url.searchParams.has('target_id')) findingReads.push(url.searchParams.get('target_id'));
    });
    await open(page, `findings?target=${ids.targetId}`);
    await expect(page.getByRole('button', { name: 'Domain', exact: true })).toContainText('checkout.acme.com');
    // A linked domain predicate is exact: every status, no remembered search, and every read carries it.
    await expect(page.getByRole('group', { name: 'Finding status filters' }).getByRole('button', { name: /^All/ })).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('.rf-result-count').first()).toContainText(/matching findings?\./);
    expect(findingReads).toContain(ids.targetId);
  });

  test('audit filters survive inspector rewrites while credential-like params are dropped', async ({ page }) => {
    test.setTimeout(120_000);
    await open(page, `audit?actor=usr_owner&category=target_change&from=2026-01-01&to=2026-12-31&api_token=abc123&metadata=%7B%7D&inspect=finding&ev_finding=${ids.findingId}`);
    await expect(inspector(page)).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(inspector(page)).toHaveCount(0);
    const hash = new URL(page.url()).hash;
    expect(hash).toContain('actor=usr_owner');
    expect(hash).toContain('from=2026-01-01');
    expect(hash).toContain('to=2026-12-31');
    expect(hash).toContain('category=target_change');
    expect(hash).not.toContain('api_token');
    expect(hash).not.toContain('metadata');
    expect(hash).not.toContain('inspect=');
  });
});

const ORIGIN_IP = 'tgt_origin_ip';
const ORIGIN_PENDING = 'tgt_origin_pending';
const MULTI_PORT = 'tgt_multi_port';
const ORIGIN_CHECKS = ['origin.direct_reachability.safe', 'origin.direct_bypass.safe', 'origin.host_sni_bypass.safe', 'waf.origin_bypass.safe'];

function seedHistory(store) {
  const base = store.targets.find((target) => target.id === ids.targetId);
  // Synthetic documentation-range origins (TEST-NET-3); nothing is ever sent to them.
  store.targets.push({ ...structuredClone(base), id: ORIGIN_IP, kind: 'ip', value: '203.0.113.10', normalized_value: '203.0.113.10' });
  store.targets.push({ ...structuredClone(base), id: ORIGIN_PENDING, kind: 'ip', value: '203.0.113.11', normalized_value: '203.0.113.11', verify_state: 'pending' });
  store.targetVerifications.push({ id: 'tv_origin_ip_dns', tenant_id: ids.tenantId, target_id: ORIGIN_IP, state: 'dns_verified', source_kind: 'dns_txt', source_ref: {}, transitioned_at: '2026-07-02T00:00:00.000Z', transitioned_by: 'system' });
  const run = store.testRuns.find((entry) => entry.id === 'run_checkout_1');
  store.testRuns.push({ ...structuredClone(run), id: 'run_checkout_retest', started_at: '2026-09-01T00:00:00.000Z', created_at: '2026-09-01T00:00:00.000Z', completed_at: '2026-09-01T00:05:00.000Z' });
  store.testRuns.push({ ...structuredClone(run), id: 'run_checkout_later', started_at: '2026-09-05T00:00:00.000Z', created_at: '2026-09-05T00:00:00.000Z', completed_at: '2026-09-05T00:05:00.000Z' });
  // A newer finished run on another target with a bare verdict string and no recorded verdict.
  store.testRuns.push({ id: 'run_unbacked_newer', tenant_id: ids.tenantId, target_group_id: ids.targetGroupId, target_id: 'tgt_checkout_2', check_id: ids.checkId, verdict: 'pass', status: 'completed', started_at: '2026-09-20T00:00:00.000Z', created_at: '2026-09-20T00:00:00.000Z' });
  const finding = store.findings.find((entry) => entry.id !== 'fnd_member_pay') ?? store.findings[0];
  store.findings.push({ ...structuredClone(finding), id: 'fnd_closed_history', status: 'closed', closed_at: '2026-09-12T08:00:00.000Z', title: 'Closed origin exposure' });
}

function seedObservations() {
  const ctx = { tenantId: ids.tenantId, userId: 'usr_owner', role: 'owner' };
  const stamp = { corpus_version: 'corpus-2026.08', scenario_version: 'edge-fingerprint.v1', check_version: 'sha256:edge-v1' };
  const add = (input, nonce) => {
    const result = acceptTargetObservation(ctx, { target_id: ids.targetId, source_kind: 'edge_detection', producer_kind: 'signed_probe', nonce, ...input }, { internal: true });
    if (result?.error) throw new Error(`seed observation ${nonce}: ${result.error}`);
  };
  add({ family: 'waf', check_id: 'waf.fingerprint.safe', outcome: 'detected', observed_at: '2026-08-01T10:00:00.000Z', source_completed_at: '2026-08-01T10:00:05.000Z', ...stamp }, 'waf-1');
  add({ family: 'waf', check_id: 'waf.fingerprint.safe', outcome: 'not_detected', observed_at: '2026-08-10T10:00:00.000Z', source_completed_at: '2026-08-10T10:00:05.000Z', ...stamp }, 'waf-2');
  add({ family: 'waf', check_id: 'waf.fingerprint.safe', outcome: 'timeout', observed_at: '2026-08-12T10:00:00.000Z', ...stamp }, 'waf-3');
  add({ family: 'cdn', check_id: 'waf.fingerprint.safe', outcome: 'detected', observed_at: '2026-08-01T11:00:00.000Z', source_completed_at: '2026-08-01T11:00:05.000Z', ...stamp }, 'cdn-1');
  add({ family: 'cdn', check_id: 'waf.fingerprint.safe', outcome: 'detected', observed_at: '2026-08-10T11:00:00.000Z', source_completed_at: '2026-08-10T11:00:05.000Z', ...stamp, check_version: 'sha256:edge-v2' }, 'cdn-2');
  for (let index = 0; index < 52; index += 1) {
    const at = new Date(Date.parse('2026-07-05T00:00:00.000Z') + index * 3_600_000).toISOString();
    add({ family: 'dns', check_id: 'dns.authoritative_response.safe', outcome: 'detected', observed_at: at, source_completed_at: at, ...stamp }, `dns-${index}`);
  }
  const lineage = registerRetestLineage(ctx, { finding_id: 'fnd_checkout_1', test_run_id: 'run_checkout_retest', intent: 'retest' });
  if (lineage?.error) throw new Error(`seed lineage: ${lineage.error}`);
}

/** Captures run starts and answers without dispatching anything. */
async function captureRunStarts(page, starts) {
  await page.route('**/v1/test-runs', (route) => {
    if (route.request().method() !== 'POST') return route.continue();
    starts.push(route.request().postDataJSON());
    return route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ id: 'run_captured_not_dispatched', status: 'pending' }) });
  });
}

test.describe('current release: target history, origin relations and retest lineage', () => {
  test.beforeAll(async ({ browser }) => {
    test.setTimeout(240_000);
    await startUi(browser, (store) => {
      applyReadinessBoost(store);
      seedHistory(store);
    });
    seedObservations();
  });

  test.afterAll(async () => {
    await vite?.close();
    vite = null;
    await stopPortalPlaywrightServer();
  });

  test('history shows retained layer state, a confirmed change, paging and a stable selection', async ({ page }) => {
    test.setTimeout(150_000);
    await page.setViewportSize({ width: 1440, height: 1000 });
    const calls = trackApi(page);
    await open(page, `target-detail?id=${ids.targetId}&tab=history`);

    const states = page.locator('.td-family-states');
    const waf = states.locator('.td-family-state').filter({ hasText: 'WAF' });
    await expect(waf).toContainText('Last completed observation');
    await expect(waf).toContainText('Not detected');
    await expect(waf).toContainText('Timed out');
    await expect(waf).toContainText('A later attempt failed. It does not replace the last completed observation');
    await expect(page.locator('.td-change-list')).toContainText('Disappeared');
    // The real observation route serves the comparison gaps: a changed CDN check definition, and
    // two DNS detections with no recorded vendor, which cannot confirm a provider change.
    const gaps = page.locator('.td-change-list li').filter({ hasText: 'Not compared' });
    await expect(gaps).toHaveCount(2);
    await expect(gaps.filter({ hasText: 'CDN' })).toContainText('The check definition changed between them.');
    await expect(gaps.filter({ hasText: 'DNS' })).toContainText('A provider is not recorded on one side, so a provider change cannot be confirmed.');

    const list = page.getByRole('list', { name: 'Recorded observations' });
    await expect(list.locator('li')).toHaveCount(50);
    await expect(page.getByText(/Showing 50 loaded observations; older ones are available\./)).toBeVisible();
    const target = list.locator('li').filter({ hasText: 'Timed out' });
    await target.getByRole('button', { name: /^Select WAF observation, Timed out/ }).click();
    await expect(target.getByRole('button', { name: /Timed out/ })).toHaveAttribute('aria-pressed', 'true');
    const detail = page.getByRole('complementary', { name: 'Selected observation' });
    await expect(detail).toContainText('WAF: Timed out');
    await expect(detail).toContainText('Failed attempt');
    await expect(detail).toContainText('Not finalized');
    await expect(detail).toContainText('Check sha256:edge-v1');
    expect(new URL(page.url()).hash).toMatch(/obs=/);

    await page.getByRole('button', { name: 'Load older observations' }).click();
    await expect(list.locator('li')).toHaveCount(57);
    await expect(page.getByText(/This is the full retained history for this filter\./)).toBeVisible();
    await expect(detail).toContainText('WAF: Timed out');

    await page.getByRole('combobox', { name: 'Layer' }).selectOption('dns');
    await expect(list.locator('li').first()).toContainText('DNS provider');
    await expect(detail).toContainText('WAF: Timed out');
    await expect(detail).toContainText('Kept from an earlier page or filter.');
    expect(mutating(calls)).toEqual([]);
  });

  test('a failed history read shows an error with Retry and recovers without losing layer state', async ({ page }) => {
    test.setTimeout(120_000);
    await page.route(/\/v1\/targets\/[^/?]+\/observations/, (route) => route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'unavailable', message: 'History store is unavailable.' }) }));
    await open(page, `target-detail?id=${ids.targetId}&tab=history`);
    const alert = page.locator('section[aria-labelledby="td-observations-history-title"]').getByRole('alert');
    await expect(alert).toBeVisible();
    await expect(page.locator('.td-family-states')).toContainText('WAF');
    await page.unroute(/\/v1\/targets\/[^/?]+\/observations/);
    await alert.getByRole('button', { name: 'Retry' }).click();
    await expect(page.getByRole('list', { name: 'Recorded observations' }).locator('li')).toHaveCount(50);
  });

  test('declaring an origin relation offers only verified declared origins and records the exact pair', async ({ page }) => {
    test.setTimeout(150_000);
    await page.setViewportSize({ width: 1440, height: 1000 });
    const writes = [];
    page.on('request', (request) => {
      const path = new URL(request.url()).pathname;
      if (request.method() === 'POST' && path.startsWith('/v1/origin-bindings')) writes.push({ path, body: request.postDataJSON() });
    });
    await open(page, `target-detail?id=${ids.targetId}`);
    const section = page.locator('section.td-origin-relations');
    await expect(section.getByText('No origin relation is declared for this hostname.')).toBeVisible();
    await section.getByRole('button', { name: 'Declare origin relation' }).click();
    const choice = section.getByRole('combobox', { name: 'Origin target' });
    await expect(choice.locator('option')).toHaveText(['Choose a verified origin target', `203.0.113.10 (${ORIGIN_IP})`]);
    await expect(section).toContainText(`Not available until ownership is verified: 203.0.113.11 (${ORIGIN_PENDING})`);

    await section.getByRole('button', { name: 'Review relation' }).click();
    await expect(section.getByText('Choose a verified origin target.', { exact: true })).toBeVisible();
    await choice.selectOption(ORIGIN_IP);
    await section.getByRole('textbox', { name: 'Port (optional)' }).fill('80;1');
    await section.getByRole('button', { name: 'Review relation' }).click();
    await expect(section.getByText('Enter a port from 1 to 65535.')).toBeVisible();
    expect(writes).toEqual([]);
    await section.getByRole('textbox', { name: 'Port (optional)' }).fill('');
    await section.getByRole('button', { name: 'Review relation' }).click();

    const dialog = page.getByRole('dialog', { name: 'Record this origin relation?' });
    await expect(dialog).toContainText(ids.targetId);
    await expect(dialog).toContainText(ORIGIN_IP);
    await expect(dialog).toContainText('does not claim the origin is locked down');
    await dialog.getByRole('button', { name: 'Record relation' }).click();
    await expect(section.getByRole('status')).toContainText('It is a declared relation, not a lockdown result.');
    expect(writes).toEqual([{ path: '/v1/origin-bindings', body: { protected_target_id: ids.targetId, origin_target_id: ORIGIN_IP } }]);
    const item = section.locator('.td-origin-item');
    await expect(item).toContainText('203.0.113.10');
    await expect(item).toContainText('Declared relation, no lockdown claim');
    await expect(item).toContainText('Results under this relation are recorded on the origin target.');

    await item.getByRole('button', { name: 'Archive relation' }).click();
    await page.getByRole('dialog', { name: 'Archive this origin relation?' }).getByRole('button', { name: 'Archive relation' }).click();
    await expect(section).toContainText('1 archived relation kept for history.');
    expect(writes.at(-1).path).toMatch(/^\/v1\/origin-bindings\/obind_[a-f0-9]+\/archive$/);
  });

  test('a different scope for an existing pair is a conflict: the form is kept and nothing is replaced', async ({ page }) => {
    test.setTimeout(150_000);
    await page.setViewportSize({ width: 1440, height: 1000 });
    const ctx = { tenantId: ids.tenantId, userId: 'usr_owner', role: 'owner' };
    // A hostname that declares two ports, present only for this test so other journeys keep their rows.
    const store = getStore();
    const base = store.targets.find((target) => target.id === ids.targetId);
    store.targets.push({ ...structuredClone(base), id: MULTI_PORT, value: 'multi.acme.com', normalized_value: 'multi.acme.com', declaration: { allowed_scope: { ports: [443, 8443] } } });
    const existing = createOriginBinding(ctx, { protected_target_id: MULTI_PORT, origin_target_id: ORIGIN_IP, scope: { port: 443 } });
    expect(existing.error).toBeUndefined();
    const responses = [];
    page.on('response', async (response) => {
      const url = new URL(response.url());
      if (response.request().method() === 'POST' && url.pathname === '/v1/origin-bindings') responses.push({ status: response.status(), body: await response.json().catch(() => null) });
    });
    await open(page, `target-detail?id=${MULTI_PORT}`);
    const section = page.locator('section.td-origin-relations');
    await expect(section.locator('.td-origin-item')).toHaveCount(1);
    await section.getByRole('button', { name: 'Declare origin relation' }).click();
    await section.getByRole('combobox', { name: 'Origin target' }).selectOption(ORIGIN_IP);
    await section.getByRole('textbox', { name: 'Port (optional)' }).fill('8443');
    await section.getByRole('button', { name: 'Review relation' }).click();
    await page.getByRole('dialog', { name: 'Record this origin relation?' }).getByRole('button', { name: 'Record relation' }).click();

    await expect.poll(() => responses.length).toBe(1);
    expect(responses[0]).toMatchObject({ status: 409, body: { error: 'scope_conflict', existing_id: existing.id } });
    await expect(page.getByRole('dialog', { name: 'Record this origin relation?' })).toHaveCount(0);
    const alert = section.getByRole('alert').filter({ hasText: 'already have an active relation with a different port or path' });
    await expect(alert).toContainText(`Existing relation: ${existing.id}.`);
    await expect(alert).toContainText('Nothing was changed.');
    await expect(section.getByRole('textbox', { name: 'Port (optional)' })).toHaveValue('8443');
    await expect(section.getByRole('combobox', { name: 'Origin target' })).toHaveValue(ORIGIN_IP);
    await expect(section.locator('.td-origin-item')).toHaveCount(1);
    await expect(section.locator('.td-origin-item')).toContainText('port 443');

    // The identical scope is an exact replay: recorded once, nothing changed.
    await section.getByRole('textbox', { name: 'Port (optional)' }).fill('443');
    await section.getByRole('button', { name: 'Review relation' }).click();
    const dialog = page.getByRole('dialog', { name: 'Record this origin relation?' });
    await expect(dialog.getByRole('alert')).toHaveCount(0);
    await dialog.getByRole('button', { name: 'Record relation' }).click();
    await expect.poll(() => responses.length).toBe(2);
    expect(responses[1].status).toBe(200);
    expect(responses[1].body).toMatchObject({ id: existing.id, replayed: true });
    await expect(section.getByRole('status')).toContainText('This relation was already recorded; nothing changed.');
    await expect(section.locator('.td-origin-item')).toHaveCount(1);
    archiveOriginBinding(ctx, existing.id);
    store.targets.splice(store.targets.findIndex((target) => target.id === MULTI_PORT), 1);
  });

  test('a read-only role sees relations without any declare or archive control', async ({ page }) => {
    test.setTimeout(120_000);
    await page.addInitScript((value) => sessionStorage.setItem('astranull.portal.session.v1', JSON.stringify(value)), { mode: 'dev-headers', principal: 'customer', tenant_id: ids.tenantId, user_id: 'usr_viewer', role: 'viewer' });
    await page.goto(`${webBase}/app#target-detail?id=${ids.targetId}`, { waitUntil: 'networkidle' });
    const section = page.locator('section.td-origin-relations');
    await expect(section.getByRole('heading', { name: 'Origin relations' })).toBeVisible();
    await expect(section.getByRole('button', { name: 'Declare origin relation' })).toHaveCount(0);
    await expect(section.getByRole('button', { name: 'Archive relation' })).toHaveCount(0);
  });

  test('the origin check runs only under one exact relation and a chosen approved check', async ({ page }) => {
    test.setTimeout(150_000);
    await page.setViewportSize({ width: 1440, height: 1000 });
    const binding = createOriginBinding({ tenantId: ids.tenantId, userId: 'usr_owner', role: 'owner' }, { protected_target_id: ids.targetId, origin_target_id: ORIGIN_IP });
    expect(binding.error).toBeUndefined();
    const starts = [];
    await captureRunStarts(page, starts);
    // The global catalog list leaves out setup-input checks; the section reads this target's own
    // compatible pairs and each exact definition. Record those reads to prove nothing else is used.
    const reads = [];
    page.on('request', (request) => {
      const url = new URL(request.url());
      if (request.method() === 'GET' && (url.pathname.endsWith('/compatible-checks') || url.pathname.startsWith('/v1/checks/'))) reads.push(url.pathname);
    });
    await open(page, `target-detail?id=${ORIGIN_IP}`);
    const section = page.locator('section.td-origin-relations');
    const item = section.locator('.td-origin-item').filter({ hasText: 'checkout.acme.com' });
    await expect(item).toContainText('No finished origin check has run under this relation yet.');
    const review = item.getByRole('button', { name: 'Review origin check' });
    await expect(review).toBeDisabled();
    const choice = item.getByRole('combobox', { name: 'Approved origin check' });
    const offered = await choice.locator('option').evaluateAll((options) => options.map((option) => option.value).filter(Boolean));
    // Only the IP-compatible host/SNI definitions; the hostname-only one is not offered on an IP origin.
    expect(offered.sort()).toEqual(ORIGIN_CHECKS.filter((checkId) => checkId !== 'origin.host_sni_bypass.safe').sort());
    expect(reads).toContain(`/v1/targets/${ORIGIN_IP}/compatible-checks`);
    for (const checkId of offered) expect(reads).toContain(`/v1/checks/${checkId}`);
    await choice.selectOption('origin.direct_bypass.safe');
    await review.click();
    const dialog = page.getByRole('dialog', { name: 'Start the origin check under this relation?' });
    await expect(dialog).toContainText(binding.id);
    await expect(dialog).toContainText('Host checkout.acme.com · SNI checkout.acme.com');
    await expect(dialog).toContainText('origin.direct_bypass.safe');
    await expect(dialog).toContainText('1 requests');
    await dialog.getByRole('button', { name: 'Start origin check' }).click();
    await expect.poll(() => starts.length).toBe(1);
    expect(starts[0]).toEqual({ check_id: 'origin.direct_bypass.safe', target_id: ORIGIN_IP, origin_binding_id: binding.id });
    archiveOriginBinding({ tenantId: ids.tenantId, userId: 'usr_owner', role: 'owner' }, binding.id);
  });

  test('without an approved origin check for the target, or when the read fails, the start stays disabled', async ({ page }) => {
    test.setTimeout(120_000);
    const binding = createOriginBinding({ tenantId: ids.tenantId, userId: 'usr_owner', role: 'owner' }, { protected_target_id: ids.targetId, origin_target_id: ORIGIN_IP });
    let mode = 'none';
    // Negative cases only: the real pairs minus their setup-required entries, then a failed read.
    await page.route(/\/v1\/targets\/[^/?]+\/compatible-checks$/, async (route) => {
      if (mode === 'error') return route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'internal_error', message: 'Catalog read failed.' }) });
      const response = await route.fetch();
      const body = await response.json();
      const keep = (pair) => pair.exclusion_reason !== 'setup_required';
      return route.fulfill({ response, json: { ...body, checks: body.checks.filter(keep), coverage: { ...body.coverage, pairs: body.coverage.pairs.filter(keep) } } });
    });
    await open(page, `target-detail?id=${ORIGIN_IP}`);
    const item = page.locator('section.td-origin-relations .td-origin-item').first();
    await expect(item.getByRole('button', { name: 'Review origin check' })).toBeDisabled();
    await expect(item).toContainText('No approved origin check is available for this target.');

    mode = 'error';
    await page.reload({ waitUntil: 'networkidle' });
    const failed = page.locator('section.td-origin-relations .td-origin-item').first();
    await expect(failed.getByRole('button', { name: 'Review origin check' })).toBeDisabled();
    await expect(failed).toContainText('Approved origin checks could not load');
    mode = 'none';
    await failed.getByRole('button', { name: 'Retry loading checks' }).click();
    await expect(failed).toContainText('No approved origin check is available for this target.');
    archiveOriginBinding({ tenantId: ids.tenantId, userId: 'usr_owner', role: 'owner' }, binding.id);
  });

  test('finding lineage separates retests from later runs and the retest start carries its finding', async ({ page }) => {
    test.setTimeout(150_000);
    await page.setViewportSize({ width: 1440, height: 1000 });
    const starts = [];
    await captureRunStarts(page, starts);
    await open(page, 'finding-detail?id=fnd_checkout_1');
    const lineage = page.getByRole('region', { name: 'Original evidence and later results' });
    const retests = lineage.locator('.finding-lineage-item').filter({ hasText: 'Retests of this finding' });
    await expect(retests.getByRole('button', { name: 'View result of retest run run_checkout_retest' })).toBeVisible();
    await expect(retests).toContainText('Most recent retest');
    const later = lineage.locator('.finding-lineage-item').filter({ hasText: 'Later runs, same target and check' });
    await expect(later.getByRole('button', { name: 'View result of run run_checkout_later' })).toBeVisible();
    await expect(later.getByRole('button', { name: /run_checkout_retest/ })).toHaveCount(0);
    await later.getByRole('button', { name: 'View result of run run_checkout_later' }).click();
    await expect(inspector(page)).toBeVisible();
    expect(new URL(page.url()).hash).toContain('ev_run=run_checkout_later');
    await page.keyboard.press('Escape');
    await expect(later.getByRole('button', { name: 'View result of run run_checkout_later' })).toBeFocused();
    await expect(lineage.locator('.finding-lineage-item').filter({ hasText: 'Closure' })).toContainText('Not closed.');
    await expect(lineage.locator('.finding-lineage-item').filter({ hasText: 'Original evidence' })).toContainText('run_checkout_1');

    await page.getByRole('button', { name: 'Review retest' }).click();
    const dialog = page.getByRole('dialog', { name: 'Review this retest' });
    await expect(dialog).toContainText('Retest of this finding (same target and check)');
    await dialog.getByRole('button', { name: 'Start retest' }).click();
    await expect.poll(() => starts.length).toBe(1);
    expect(starts[0]).toMatchObject({ retest_of_finding_id: 'fnd_checkout_1', target_id: ids.targetId, check_id: ids.checkId });
  });

  test('a closed finding shows its recorded closure time without claiming a fix', async ({ page }) => {
    test.setTimeout(120_000);
    await open(page, 'finding-detail?id=fnd_closed_history');
    const closure = page.getByRole('region', { name: 'Original evidence and later results' }).locator('.finding-lineage-item').filter({ hasText: 'Closure' });
    await expect(closure).toContainText(/Closed Sep 12/);
    await expect(closure).toContainText('not proof of a fix');
  });

  test('artifact rows are not controls; the View button is the keyboard target and focus returns to it', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await open(page, 'finding-detail?id=fnd_checkout_1');
    const row = page.locator('tr.finding-artifact-row').first();
    await expect(row).toBeVisible();
    await expect(row).not.toHaveAttribute('role', 'button');
    await expect(row).not.toHaveAttribute('tabindex', /.*/);
    const view = row.getByRole('button', { name: /^View artifact .* in the evidence inspector$/ });
    await view.focus();
    await page.keyboard.press('Enter');
    await expect(inspector(page)).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(inspector(page)).toHaveCount(0);
    await expect(view).toBeFocused();
  });

  test('populated history, origin relations and finding lineage pass axe at 375 and 1440 in both themes', async ({ page }) => {
    test.setTimeout(240_000);
    const binding = createOriginBinding({ tenantId: ids.tenantId, userId: 'usr_owner', role: 'owner' }, { protected_target_id: ids.targetId, origin_target_id: ORIGIN_IP });
    await page.emulateMedia({ reducedMotion: 'reduce' });
    const serious = async (include) => {
      const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).include(include).analyze();
      return results.violations.filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')
        .map((violation) => `${violation.id}: ${violation.nodes.slice(0, 2).map((node) => node.target.join(' ')).join(' | ')}`);
    };
    try {
      for (const width of [375, 1440]) {
        for (const theme of ['dark', 'light']) {
          await page.setViewportSize({ width, height: 900 });
          await open(page, `target-detail?id=${ids.targetId}&tab=history`, { theme });
          await expect(page.getByRole('list', { name: 'Recorded observations' }).locator('li').first()).toBeVisible();
          await page.getByRole('list', { name: 'Recorded observations' }).getByRole('button').first().click();
          expect(await serious('.td-panel'), `history ${width} ${theme}`).toEqual([]);
          expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), `history overflow ${width} ${theme}`).toBeLessThanOrEqual(0);
          await open(page, `target-detail?id=${ids.targetId}`, { theme });
          await expect(page.locator('section.td-origin-relations .td-origin-item')).toBeVisible();
          await page.getByRole('button', { name: 'Declare origin relation' }).click();
          expect(await serious('section.td-origin-relations'), `origin relations ${width} ${theme}`).toEqual([]);
          await open(page, `target-detail?id=${ORIGIN_IP}`, { theme });
          await expect(page.locator('section.td-origin-relations .td-origin-item')).toBeVisible();
          expect(await serious('section.td-origin-relations'), `origin side ${width} ${theme}`).toEqual([]);
          await open(page, 'finding-detail?id=fnd_checkout_1', { theme });
          await expect(page.locator('tr.finding-artifact-row').first()).toBeVisible();
          expect(await serious('#portal-main'), `finding detail ${width} ${theme}`).toEqual([]);
        }
      }
    } finally {
      archiveOriginBinding({ tenantId: ids.tenantId, userId: 'usr_owner', role: 'owner' }, binding.id);
    }
  });

  test('a finished run without a recorded verdict never reads as passed on the dashboard', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await open(page, 'dashboard');
    const row = page.getByRole('row').filter({ hasText: 'pay.acme.com' });
    await expect(row.getByText('Not recorded', { exact: true })).toBeVisible();
    await expect(row.getByText(/^Passed/)).toHaveCount(0);
  });
});
