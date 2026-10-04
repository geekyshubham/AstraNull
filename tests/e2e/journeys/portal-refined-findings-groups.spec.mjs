/**
 * Browser regression for Refined grouped findings and related SLA / detail wording
 * (UNCOMMITTED_CHANGES_REVIEW G03, F06, F08, F09, F12):
 *  - grouped alert navigation to every historical finding on one target (F06),
 *  - Refined queue lifecycle filters and group-detail asset lifecycle filters,
 *  - accepted-risk-only groups never read as closed in Classic (F08),
 *  - undated and mixed dated/undated open findings never read as "Within SLA" (F09),
 *  - finding-detail cold deep link resolves target group names, and a failed
 *    target-group load says so instead of guessing (F12).
 *
 * Findings are seeded into the in-memory dev store; nothing is sent to any target.
 */
import { expect, test } from '@playwright/test';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import { injectPortalDevHeadersSession, waitForPortalRouteSettled } from '../../helpers/portal-playwright-session.mjs';

const ids = PORTAL_BASELINE_IDS;
const FROZEN = ids.frozenAt;

function finding(overrides) {
  return {
    tenant_id: ids.tenantId,
    target_group_id: ids.targetGroupId,
    severity: 's2',
    owner_group: 'edge-sre',
    ...overrides,
  };
}

/** Seeded findings, keyed by scenario. */
function seededFindings() {
  const recent = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  return [
    // F06: one target with open, accepted and closed history for the same alert, plus a second target.
    finding({ id: 'fnd_hist_open', target_id: ids.targetId, check_id: ids.checkId, title: 'Origin direct bypass', state: 'open', opened_at: FROZEN }),
    finding({ id: 'fnd_hist_accepted', target_id: ids.targetId, check_id: ids.checkId, title: 'Origin direct bypass', state: 'accepted_risk', opened_at: '2026-05-01T12:00:00.000Z' }),
    finding({ id: 'fnd_hist_closed', target_id: ids.targetId, check_id: ids.checkId, title: 'Origin direct bypass', state: 'closed', opened_at: '2026-04-01T12:00:00.000Z' }),
    finding({ id: 'fnd_hist_closed_2', target_id: 'tgt_checkout_2', check_id: ids.checkId, title: 'Origin direct bypass', state: 'closed', opened_at: '2026-04-02T12:00:00.000Z' }),
    // F08: accepted-risk-only alert.
    finding({ id: 'fnd_acc_only', target_id: 'tgt_checkout_3', check_id: 'edge.rate_limit.safe', title: 'Rate limit drift', severity: 's3', state: 'accepted_risk', opened_at: '2026-05-10T12:00:00.000Z' }),
    // F09: all-undated open alert.
    finding({ id: 'fnd_undated', target_id: 'tgt_checkout_4', check_id: 'edge.cache_bypass.safe', title: 'Cache bypass header', severity: 's3', state: 'open' }),
    // F09: mixed dated (not breached) and undated open alert. The SLA clock reads created_at only.
    finding({ id: 'fnd_mixed_dated', target_id: 'tgt_checkout_5', check_id: 'edge.tls_gap.safe', title: 'TLS handshake gap', severity: 's4', state: 'open', created_at: recent, opened_at: recent }),
    finding({ id: 'fnd_mixed_undated', target_id: 'tgt_checkout_2', check_id: 'edge.tls_gap.safe', title: 'TLS handshake gap', severity: 's4', state: 'open' }),
  ];
}

const COMBOS = [
  { name: 'mobile, light', width: 390, height: 844, theme: 'light' },
  { name: 'desktop, dark', width: 1440, height: 900, theme: 'dark' },
];

/**
 * @param {import('@playwright/test').Page} page
 * @param {{ theme?: string, variant?: string }} [options]
 */
async function prepare(page, { theme = 'dark', variant } = {}) {
  await page.addInitScript(({ themeValue, variantValue }) => {
    try {
      localStorage.setItem('astranull.theme', themeValue);
      localStorage.setItem('astranull.findings-refined.view', 'grouped');
      if (variantValue) localStorage.setItem('astranull.design-variant.findings', variantValue);
    } catch { /* storage blocked */ }
  }, { themeValue: theme, variantValue: variant ?? null });
  await injectPortalDevHeadersSession(page);
}

/**
 * @param {import('@playwright/test').Page} page
 * @param {string} hash
 */
async function gotoHash(page, hash) {
  await page.goto(`${getPortalPlaywrightBaseUrl()}/app#${hash}`, { waitUntil: 'networkidle', timeout: 60_000 });
  await waitForPortalRouteSettled(page);
}

/**
 * @param {import('@playwright/test').Page} page
 * @param {RegExp} title
 */
function alertLink(page, title) {
  return page.locator('a.rf-alert-link').filter({ hasText: title });
}

/** Table row containing the given text. */
function rowWith(page, text) {
  return page.getByRole('row').filter({ hasText: text });
}

test.describe('Refined grouped findings, SLA wording and detail group names', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({
      mutate: (store) => {
        store.findings = seededFindings();
      },
    });
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  for (const combo of COMBOS) {
    test(`grouped alert reaches every historical finding on one target (${combo.name})`, async ({ page }) => {
      const pageErrors = [];
      page.on('pageerror', (error) => pageErrors.push(error.message));
      await page.setViewportSize({ width: combo.width, height: combo.height });
      await prepare(page, { theme: combo.theme });
      await gotoHash(page, 'findings?variant=refined');

      const link = alertLink(page, /Origin direct bypass/i);
      await expect(link).toBeVisible();
      // The default Open filter counts only targets with an open member.
      await expect(link).toHaveAttribute('aria-label', /1 affected target$/);

      // Keyboard: Enter on the focused alert link opens the group detail.
      await link.focus();
      await page.keyboard.press('Enter');
      await expect(page).toHaveURL(/#finding-group-detail\?key=/);
      await waitForPortalRouteSettled(page);

      const summary = page.getByRole('region', { name: 'Finding group summary' });
      await expect(summary).toContainText('Affected targets');
      await expect(summary).toContainText('4 findings');

      const filters = page.getByRole('group', { name: 'Affected target status filter' });
      const filterButton = (label) => filters.getByRole('button', { name: new RegExp(`^${label}`) });
      await expect(filterButton('All').locator('.rf-tab-count')).toHaveText('2');
      await expect(filterButton('Open').locator('.rf-tab-count')).toHaveText('1');
      await expect(filterButton('Accepted').locator('.rf-tab-count')).toHaveText('1');
      await expect(filterButton('Closed').locator('.rf-tab-count')).toHaveText('2');

      // All filter: one explicit evidence action per historical finding (each member's own proof).
      const member = (findingId) => page.locator(`[data-focus-key="member-${findingId}"]`);
      for (const findingId of ['fnd_hist_open', 'fnd_hist_accepted', 'fnd_hist_closed', 'fnd_hist_closed_2']) {
        await expect(member(findingId)).toHaveCount(1);
      }
      await expect(page.getByText(/3 findings:/)).toBeVisible();

      // Lifecycle filter narrows the actions to that lifecycle only.
      await filterButton('Accepted').click();
      await expect(filterButton('Accepted')).toHaveAttribute('aria-pressed', 'true');
      await expect(member('fnd_hist_accepted')).toHaveCount(1);
      await expect(member('fnd_hist_open')).toHaveCount(0);
      await expect(member('fnd_hist_closed_2')).toHaveCount(0);

      await filterButton('Closed').click();
      await expect(member('fnd_hist_closed')).toHaveCount(1);
      await expect(member('fnd_hist_closed_2')).toHaveCount(1);
      await expect(member('fnd_hist_accepted')).toHaveCount(0);

      // A non-representative member opens its own evidence in place, never the lead finding's.
      await member('fnd_hist_closed').click();
      await expect(page).toHaveURL(/inspect=group_member&ev_finding=fnd_hist_closed(&|$)/);
      await expect(page.locator('.inspector-panel')).toBeVisible();
      await page.keyboard.press('Escape');
      await expect(page.locator('.inspector-panel')).toHaveCount(0);

      // The full finding stays one explicit link away.
      await page.getByRole('link', { name: /Open full finding for/ }).first().click();
      await expect(page).toHaveURL(/#finding-detail\?id=fnd_hist_/);
      await waitForPortalRouteSettled(page);
      const ruleAssets = page.getByRole('region', { name: 'Affected assets for this rule' });
      await expect(ruleAssets).toBeVisible();
      await expect(ruleAssets).toContainText('edge-checkout');
      await expect(ruleAssets).not.toContainText('Group name unavailable');

      expect(pageErrors).toEqual([]);
    });
  }

  test('Refined queue lifecycle filters show accepted and closed alerts only under their filter', async ({ page }) => {
    await prepare(page);
    await gotoHash(page, 'findings?variant=refined');
    const statusFilters = page.getByRole('group', { name: 'Finding status filters' });
    const pick = (label) => statusFilters.getByRole('button', { name: new RegExp(`^${label}`) });

    await expect(pick('Open')).toHaveAttribute('aria-pressed', 'true');
    await expect(alertLink(page, /Rate limit drift/i)).toHaveCount(0);
    await expect(alertLink(page, /Origin direct bypass/i)).toHaveCount(1);

    // Status chips are exact single server statuses; these rows are accepted_risk.
    await pick('Accepted risk').click();
    await expect(alertLink(page, /Rate limit drift/i)).toHaveCount(1);
    await expect(alertLink(page, /Cache bypass header/i)).toHaveCount(0);

    await pick('Closed').click();
    await expect(alertLink(page, /Origin direct bypass/i)).toHaveCount(1);
    await expect(alertLink(page, /Rate limit drift/i)).toHaveCount(0);

    await pick('All').click();
    for (const title of [/Origin direct bypass/i, /Rate limit drift/i, /Cache bypass header/i, /TLS handshake gap/i]) {
      await expect(alertLink(page, title)).toHaveCount(1);
    }
  });

  test('undated open findings read as SLA unknown or partially assessed, never within SLA (F09)', async ({ page }) => {
    await prepare(page);
    await gotoHash(page, 'findings?variant=refined');

    const undatedRow = rowWith(page, /Cache bypass header/i);
    await expect(undatedRow).toContainText('SLA unknown');
    await expect(undatedRow).toContainText('No opened date recorded');
    const mixedRow = rowWith(page, /TLS handshake gap/i);
    await expect(mixedRow).toContainText('Partially assessed');
    await expect(mixedRow).toContainText('1 not dated');

    await alertLink(page, /Cache bypass header/i).click();
    await waitForPortalRouteSettled(page);
    const summary = page.getByRole('region', { name: 'Finding group summary' });
    await expect(summary).toContainText('SLA unknown');
    await expect(summary).toContainText('1 open finding not dated');
    await expect(summary).not.toContainText('Within SLA');

    await page.goBack();
    await waitForPortalRouteSettled(page);
    await alertLink(page, /TLS handshake gap/i).click();
    await waitForPortalRouteSettled(page);
    await expect(summary).toContainText('Partially assessed');
    await expect(summary).toContainText('1 open finding not dated');
    await expect(summary).not.toContainText('Within SLA');
  });

  test('accepted-risk-only group reads accepted risk, never closed, even from a legacy classic link (F08)', async ({ page }) => {
    // The customer UI ships one presentation; the legacy ?variant=classic address still resolves.
    await prepare(page, { variant: 'classic' });
    await gotoHash(page, 'findings?variant=classic');
    await expect(page.getByRole('button', { name: /Classic|Refined/ })).toHaveCount(0);
    const statusFilters = page.getByRole('group', { name: 'Finding status filters' });
    await statusFilters.getByRole('button', { name: /^Accepted risk/ }).click();

    const row = rowWith(page, /Rate limit drift/i);
    await expect(row).toBeVisible();
    await expect(row).toContainText(/accepted risk/i);
    await expect(row).toContainText('No SLA clock');
    await expect(row).not.toContainText(/closed/i);
  });

  test('finding-detail cold deep link shows target group names (F12)', async ({ page }) => {
    await prepare(page);
    await gotoHash(page, 'finding-detail?id=fnd_hist_open');
    const ruleAssets = page.getByRole('region', { name: 'Affected assets for this rule' });
    await expect(ruleAssets).toBeVisible();
    await expect(ruleAssets).toContainText('edge-checkout');
    await expect(ruleAssets).toContainText(ids.targetGroupId);
    await expect(ruleAssets).not.toContainText('Group name unavailable');
  });

  test('finding-detail with a failed target-group load says names are unavailable (F12)', async ({ page }) => {
    await prepare(page);
    await page.route(/\/v1\/target-groups(\?.*)?$/, (route) => (
      route.request().method() === 'GET'
        ? route.fulfill({ status: 503, json: { error: 'service_unavailable' } })
        : route.fallback()
    ));
    await gotoHash(page, 'finding-detail?id=fnd_hist_open');
    const ruleAssets = page.getByRole('region', { name: 'Affected assets for this rule' });
    await expect(ruleAssets).toBeVisible();
    await expect(ruleAssets.getByText('Group name unavailable').first()).toBeVisible();
    await expect(ruleAssets.getByRole('status').filter({ hasText: 'Target group names are unavailable' })).toBeVisible();
    await expect(ruleAssets).not.toContainText('edge-checkout');
  });
});
