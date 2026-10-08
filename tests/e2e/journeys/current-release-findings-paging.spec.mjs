/**
 * Current release findings paging against the real dev API: more than one server page of findings,
 * exact predicate totals, page 2, search, status filters, grouped and group-member reads past the
 * first page, Direct domain predicates and exact Findings counts. Isolated dev store; UI from
 * live source via Vite. Reads only: no write, probe or notification is issued.
 */
import path from 'node:path';
import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { createServer as createViteServer } from 'vite';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import {
  portalOwnerHeaders,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, injectPortalDevHeadersSession } from '../../helpers/portal-playwright-session.mjs';

const T = PORTAL_BASELINE_IDS.tenantId;
const GROUP = PORTAL_BASELINE_IDS.targetGroupId;
const SIDE_GROUP = 'tg_paging_side';
const BULK_CHECK = 'paging.bulk.check';
const BULK_TITLE = 'Bulk paging finding';
const BULK_COUNT = 230;
const NEEDLE_TITLE = 'Needle oldest finding';
const MEMBER_TARGETS = ['tgt_checkout_1', 'tgt_checkout_2', 'tgt_checkout_3', 'tgt_checkout_4', 'tgt_checkout_5'];
const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

let apiBaseUrl = '';
let sourceBaseUrl = '';
let vite;
const expected = {};

function stamp(minutesAgo) {
  return new Date(Date.UTC(2026, 8, 1, 12, 0, 0) - minutesAgo * 60_000).toISOString();
}

function bulkStatus(index) {
  const slot = index % 5;
  if (slot <= 2) return 'open';
  return slot === 3 ? 'in_progress' : 'resolved';
}

function applyPagingFixture(store) {
  store.targetGroups.push({
    id: SIDE_GROUP,
    tenant_id: T,
    environment_id: PORTAL_BASELINE_IDS.environmentId,
    name: 'paging-side',
    description: 'Findings recorded on the group with no member targets',
    expected_behavior_default: 'cloud_baseline',
    created_at: stamp(5000),
  });
  for (let index = 0; index < BULK_COUNT; index += 1) {
    store.findings.push({
      id: `fnd_pg_bulk_${String(index).padStart(3, '0')}`,
      tenant_id: T,
      target_group_id: GROUP,
      target_id: MEMBER_TARGETS[index % MEMBER_TARGETS.length],
      check_id: BULK_CHECK,
      severity: index % 2 ? 's2' : 's3',
      title: BULK_TITLE,
      status: bulkStatus(index),
      created_at: stamp(index + 10),
      opened_at: stamp(index + 10),
    });
  }
  store.targets.push({ id: 'tgt_paging_side', tenant_id: T, target_group_id: SIDE_GROUP, kind: 'fqdn', value: 'paging-side.example.test' });
  for (let index = 0; index < 10; index += 1) {
    store.findings.push({
      id: `fnd_pg_side_${index}`,
      tenant_id: T,
      target_group_id: SIDE_GROUP,
      target_id: 'tgt_paging_side',
      check_id: 'paging.side.check',
      severity: 's3',
      title: 'Side group finding',
      status: index < 7 ? 'open' : 'in_progress',
      created_at: stamp(index + 400),
      opened_at: stamp(index + 400),
    });
  }
  for (let index = 0; index < 4; index += 1) {
    store.findings.push({
      id: `fnd_pg_padded_high_${index}`,
      tenant_id: T,
      target_group_id: GROUP,
      target_id: MEMBER_TARGETS[index],
      check_id: 'paging.padded.check',
      severity: ' High ',
      title: 'Padded high severity finding',
      status: 'open',
      created_at: stamp(index + 600),
      opened_at: stamp(index + 600),
    });
  }
  store.findings.push({
    id: 'fnd_pg_needle',
    tenant_id: T,
    target_group_id: GROUP,
    target_id: MEMBER_TARGETS[0],
    check_id: 'paging.needle.check',
    severity: 's2',
    title: NEEDLE_TITLE,
    status: 'open',
    created_at: stamp(90_000),
    opened_at: stamp(90_000),
  });
}

async function apiJson(pathAndQuery) {
  const response = await fetch(`${apiBaseUrl}${pathAndQuery}`, { headers: portalOwnerHeaders() });
  expect(response.ok, `${pathAndQuery} ${response.status}`).toBe(true);
  return response.json();
}

async function total(query) {
  const body = await apiJson(`/v1/findings?${query}&limit=1`);
  expect(typeof body.total).toBe('number');
  return body.total;
}

function recordFindingsReads(page) {
  const reads = [];
  const writes = [];
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (!url.pathname.startsWith('/v1/')) return;
    if (request.method() !== 'GET') writes.push(`${request.method()} ${url.pathname}`);
    else if (url.pathname === '/v1/findings') reads.push(Object.fromEntries(url.searchParams));
  });
  return { reads, writes };
}

async function blockingViolations(page) {
  await page.evaluate(() => Promise.all(document.getAnimations().map((animation) => animation.finished.catch(() => undefined))));
  const results = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
  return results.violations
    .filter((violation) => violation.impact === 'critical' || violation.impact === 'serious')
    .map((violation) => `${violation.id}: ${violation.nodes.slice(0, 3).map((node) => node.target.join(' ')).join(' | ')}`);
}

function statusChip(page, name) {
  return page.getByRole('group', { name: 'Finding status filters' }).getByRole('button', { name: new RegExp(`^${name}`) });
}

test.describe.configure({ mode: 'serial' });

test.describe('current-release findings paging against the real API', () => {
  test.beforeAll(async ({ browser }) => {
    test.setTimeout(300_000);
    ({ baseUrl: apiBaseUrl } = await startPortalPlaywrightServer({ mutate: applyPagingFixture }));
    expected.open = await total('status=open');
    expected.inProgress = await total('status=in_progress');
    expected.all = await total('status=all');
    expected.groupOpen = await total(`status=open&target_group_id=${GROUP}`);
    expected.groupInProgress = await total(`status=in_progress&target_group_id=${GROUP}`);
    expected.bulk = await total(`check_id=${BULK_CHECK}`);
    const state = await apiJson('/v1/state');
    expected.stateOpen = state.open_findings;
    const groups = await apiJson('/v1/target-groups');
    expected.groupCounts = Object.fromEntries(groups.items.map((group) => [group.id, group.open_findings_count]));

    expect(expected.open).toBeGreaterThan(50);
    expect(expected.all).toBeGreaterThan(200);
    expect(expected.bulk).toBe(BULK_COUNT);
    // One effective status everywhere: the workspace state, the list and the group counter agree.
    expect(expected.stateOpen).toBe(expected.open);
    // A group count is exact `open` only and equals its linked `status=open` list total.
    expect(expected.groupCounts[GROUP]).toBe(expected.groupOpen);
    expect(expected.groupCounts[SIDE_GROUP]).toBe(7);
    // Severity aliases fold to one class on the server: `S2` and `high` select the same rows.
    expected.openHigh = await total('status=open&severity=high');
    expect(await total('status=open&severity=S2')).toBe(expected.openHigh);
    // The four padded ' High ' rows and the S2 bulk rows are both in the high class.
    expect(await total('status=open&severity=S2&q=Padded')).toBe(4);
    expect(expected.openHigh).toBeGreaterThan(4);

    vite = await createViteServer({
      configFile: path.resolve('vite.config.ts'),
      logLevel: 'silent',
      server: { host: '127.0.0.1', port: 0, strictPort: false, hmr: false, proxy: { '/v1': apiBaseUrl, '/ready': apiBaseUrl, '/internal': apiBaseUrl } },
    });
    await vite.listen();
    const address = vite.httpServer?.address();
    if (!address || typeof address === 'string') throw new Error('Vite source server did not bind a TCP port.');
    sourceBaseUrl = `http://127.0.0.1:${address.port}`;
    // Warm the source server once so the first journey does not time out on the cold module graph.
    const warm = await browser.newPage();
    await injectPortalDevHeadersSession(warm);
    await warm.goto(`${sourceBaseUrl}/app#findings`, { waitUntil: 'networkidle', timeout: 180_000 }).catch(() => undefined);
    await warm.getByRole('group', { name: 'Finding status filters' }).waitFor({ timeout: 120_000 }).catch(() => undefined);
    await warm.close();
  });

  test.afterAll(async () => {
    await vite?.close();
    await stopPortalPlaywrightServer();
  });

  test('each-finding view: exact totals, a real page 2, search and single-status filters', async ({ page }) => {
    const { reads, writes } = recordFindingsReads(page);
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'findings', sourceBaseUrl);

    await expect(statusChip(page, 'Open').locator('.rf-tab-count')).toHaveText(String(expected.open));
    await expect(statusChip(page, 'In progress').locator('.rf-tab-count')).toHaveText(String(expected.inProgress));
    await expect(statusChip(page, 'All').locator('.rf-tab-count')).toHaveText(String(expected.all));
    const summaryOpen = page.getByRole('region', { name: 'Finding summary' }).locator('.rf-stat').filter({ has: page.locator('.rf-stat-label', { hasText: /^Open$/ }) });
    await expect(summaryOpen.locator('.rf-stat-value')).toHaveText(String(expected.open));

    const pageOne = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === '/v1/findings' && url.searchParams.get('limit') === '25' && !url.searchParams.get('page');
    });
    await page.getByRole('button', { name: 'Each finding' }).click();
    const firstIds = (await (await pageOne).json()).items.map((item) => item.id);
    const resultCount = page.locator('.rf-result-count').first();
    await expect(resultCount).toContainText(`${expected.open} matching findings`);
    const pages = Math.ceil(expected.open / 25);
    await expect(page.locator('.rf-pager .rf-toolbar .rf-pager-info')).toHaveText(`Page 1 of ${pages}`);
    await expect(page.locator('.rf-findings-table tbody tr')).toHaveCount(25);

    const pageTwo = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === '/v1/findings' && url.searchParams.get('page') === '2' && url.searchParams.get('status') === 'open' && url.searchParams.get('limit') === '25';
    });
    await page.getByRole('button', { name: 'Next findings page' }).click();
    const pageTwoBody = await (await pageTwo).json();
    expect(pageTwoBody.total).toBe(expected.open);
    expect(pageTwoBody.items).toHaveLength(25);
    expect(pageTwoBody.items.some((item) => firstIds.includes(item.id))).toBe(false);
    await expect(page.locator('.rf-pager .rf-toolbar .rf-pager-info')).toHaveText(`Page 2 of ${pages}`);
    await expect(page.locator('.rf-pager > .rf-pager-info')).toHaveText(`Showing 26 to 50 of ${expected.open} findings`);
    await expect(page.locator('.rf-findings-table tbody tr')).toHaveCount(25);

    // The oldest open finding is far past the first page; the server search still reaches it.
    await page.getByRole('searchbox', { name: /Search findings/ }).fill('Needle');
    await expect(resultCount).toContainText('1 matching finding');
    await expect(page.locator('.rf-findings-table tbody')).toContainText(NEEDLE_TITLE);
    expect(reads.some((query) => query.q === 'Needle' && query.status === 'open')).toBe(true);

    await page.getByRole('searchbox', { name: /Search findings/ }).fill('');
    await statusChip(page, 'In progress').click();
    await expect(statusChip(page, 'In progress')).toHaveAttribute('aria-pressed', 'true');
    await expect(resultCount).toContainText(`${expected.inProgress} matching findings`);
    await expect(page.locator('.rf-findings-table tbody tr').first()).toContainText('in progress');
    expect(reads.every((query) => !query.status || ['open', 'in_progress', 'accepted_risk', 'accepted', 'resolved', 'closed', 'false_positive'].includes(query.status))).toBe(true);
    expect(reads.every((query) => !query.limit || Number(query.limit) <= 200)).toBe(true);
    expect(writes).toEqual([]);
  });

  test('grouped view and group detail read later server pages on request and label partial groups', async ({ page }) => {
    const { reads, writes } = recordFindingsReads(page);
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'findings', sourceBaseUrl);
    await statusChip(page, 'All').click();

    const resultCount = page.locator('.rf-result-count').first();
    await expect(resultCount).toContainText(`of ${expected.all} matching findings`);
    await expect(resultCount).toContainText('Groups and their counts are partial until every matching finding is read.');
    const bulkRow = page.getByRole('row').filter({ hasText: BULK_TITLE });
    await expect(bulkRow.locator('td').nth(2)).toContainText('+');

    const pageTwo = page.waitForRequest((request) => new URL(request.url()).searchParams.get('page') === '2');
    await page.getByRole('button', { name: /^Read the next \d+ findings$/ }).click();
    await pageTwo;
    await expect(resultCount).toContainText('Every matching finding is read, so groups and their counts are complete.');
    await expect(page.getByRole('button', { name: /^Read the next/ })).toHaveCount(0);

    await bulkRow.getByRole('link', { name: new RegExp(`^Open finding group ${BULK_TITLE}`) }).click();
    await expect(page).toHaveURL(/#finding-group-detail/);
    const partial = page.getByText(/^Partial group: built from/);
    await expect(partial).toContainText(`200 of ${BULK_COUNT} findings for this check`);
    await page.getByRole('button', { name: 'Read more members' }).click();
    await expect(partial).toHaveCount(0);
    expect(reads.some((query) => query.check_id === BULK_CHECK && query.page === '2' && query.limit === '200')).toBe(true);
    expect(writes).toEqual([]);
  });

  test('a linked domain predicate replaces remembered filters and clears from the address once changed', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'findings', sourceBaseUrl);
    await page.getByRole('searchbox', { name: /Search findings/ }).fill('Needle');
    await expect(page.locator('.rf-result-count').first()).toContainText('1 matching finding');

    await page.goto(`${sourceBaseUrl}/app#findings?target_id=tgt_paging_side&status=open`, { waitUntil: 'networkidle' });
    await expect(page.getByRole('searchbox', { name: /Search findings/ })).toHaveValue('');
    await expect(statusChip(page, 'Open').locator('.rf-tab-count')).toHaveText('7');
    await expect(statusChip(page, 'In progress').locator('.rf-tab-count')).toHaveText('3');

    await statusChip(page, 'In progress').click();
    await expect(page).not.toHaveURL(/target_id=/);
  });

  test('severity filter offers each server class once and folds S2 and high together', async ({ page }) => {
    const { reads } = recordFindingsReads(page);
    await injectPortalDevHeadersSession(page);
    await page.goto(`${sourceBaseUrl}/app#findings?status=open&severity=S2`, { waitUntil: 'networkidle' });
    await expect(page.getByRole('button', { name: 'Severity', exact: true })).toContainText('High');
    await page.getByRole('button', { name: 'Each finding' }).click();
    await expect(page.locator('.rf-result-count').first()).toContainText(`${expected.openHigh} matching findings`);
    expect(reads.filter((query) => query.severity).every((query) => query.severity === 'high')).toBe(true);
    await page.getByRole('button', { name: 'Severity', exact: true }).click();
    const options = await page.getByRole('listbox', { name: 'Severity' }).getByRole('option').allTextContents();
    expect(options.map((text) => text.trim())).toEqual(['All severities', 'Critical', 'High', 'Medium', 'Low', 'Info', 'Not recorded or unrecognized']);
  });

  test('dashboard open count is the exact server total, not the first page', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', sourceBaseUrl);
    const dashboardOpen = page.locator('.dashboard-kpi').filter({ hasText: 'Open findings' });
    await expect(dashboardOpen.locator('.dashboard-kpi-value')).toHaveText(String(expected.open));
  });

  for (const mode of [
    { route: 'targets', width: 1440, theme: 'dark' },
    { route: 'targets', width: 375, theme: 'light' },
    { route: 'findings', width: 1440, theme: 'light' },
    { route: 'findings', width: 375, theme: 'dark' },
  ]) {
    test(`a11y: ${mode.route} with paged data at ${mode.width}px, ${mode.theme}`, async ({ page }) => {
      await page.setViewportSize({ width: mode.width, height: 900 });
      await page.addInitScript((value) => {
        try { localStorage.setItem('astranull.theme', value); } catch { /* storage blocked */ }
      }, mode.theme);
      await injectPortalDevHeadersSession(page);
      await gotoPortalRoute(page, mode.route, sourceBaseUrl);
      if (mode.route === 'findings') await expect(page.locator('.rf-result-count').first()).toContainText('matching');
      else await expect(page.getByRole('row').filter({ hasText: 'paging-side' })).toBeVisible();
      expect(await blockingViolations(page)).toEqual([]);
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(overflow).toBeLessThanOrEqual(1);
    });
  }
});
