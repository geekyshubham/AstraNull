import { expect, test } from '@playwright/test';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import { plainInlineText } from '../../../apps/web/react/src/lib/plain-language.mjs';
import {
  isPortalScaleEnabled,
  PORTAL_SCALE_PROFILE,
} from '../../fixtures/portal-scale/seed.mjs';
import {
  getPortalPlaywrightBaseUrl,
  portalOwnerHeaders,
  restartPortalPlaywrightServer,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  injectPortalDevHeadersSession,
} from '../../helpers/portal-playwright-session.mjs';

/**
 * FT-DASH-01..03 — Dashboard Overview panels bound to GET /v1/state (docs/ux/14 §4.1).
 *
 * Covers the weighted-factors panel (one row per published readiness factor) and the
 * customer kill-switch alert, both of which read fields the API already returns.
 */

const KILL_SWITCH_REASON = 'Provider escalation in progress; validation paused.';
const KILL_SWITCH_UPDATED_AT = '2026-08-02T11:30:00.000Z';
const KILL_SWITCH_HEADLINE = 'SOC kill switch is armed';
const SCALE_OPEN_FINDINGS = Math.ceil(PORTAL_SCALE_PROFILE.findings / 3);

/** Baseline store plus an armed SOC kill switch (shape matches src/store.mjs socKillSwitch). */
function applyArmedKillSwitch(store) {
  applyPortalBaselineReadinessBoost(store);
  store.socKillSwitch = {
    active: true,
    tenant_id: PORTAL_BASELINE_IDS.tenantId,
    reason: KILL_SWITCH_REASON,
    updated_at: KILL_SWITCH_UPDATED_AT,
  };
}

function applyPortalScaleCounts(store) {
  const tenantId = PORTAL_BASELINE_IDS.tenantId;
  const firstGroup = store.targetGroups.find((group) => group.tenant_id === tenantId) ?? {};
  const environmentId = firstGroup.environment_id ?? PORTAL_BASELINE_IDS.environmentId;
  const frozenAt = PORTAL_BASELINE_IDS.frozenAt;
  const groups = Array.from({ length: PORTAL_SCALE_PROFILE.targetGroups }, (_, index) => ({
    ...(index === 0 ? firstGroup : {}),
    id: index === 0 ? PORTAL_BASELINE_IDS.targetGroupId : `tg_dom_scale_${index}`,
    tenant_id: tenantId,
    environment_id: environmentId,
    name: `DOM scale group ${index}`,
    criticality: index % 10 === 0 ? 'critical' : 'medium',
    created_at: frozenAt,
  }));
  store.targetGroups = groups;
  store.targets = Array.from({ length: PORTAL_SCALE_PROFILE.targets }, (_, index) => ({
    id: `tgt_dom_scale_${index}`,
    tenant_id: tenantId,
    target_group_id: groups[index].id,
    kind: 'fqdn',
    value: `host-${index}.dom-scale.test`,
    normalized_value: `host-${index}.dom-scale.test`,
    expected_behavior: 'cloud_baseline',
    created_at: frozenAt,
  }));
  // Real finding rows behind the rollup: every third one open, as in the shared scale fixture, so the
  // state count, the open list total and the dashboard link all describe the same rows.
  store.findings = Array.from({ length: PORTAL_SCALE_PROFILE.findings }, (_, index) => {
    const target = store.targets[index % store.targets.length];
    return {
      id: `fnd_dom_scale_${index}`,
      tenant_id: tenantId,
      target_group_id: target.target_group_id,
      target_id: target.id,
      check_id: 'chk_l7_rate',
      severity: 's3',
      title: `Scale finding ${index}`,
      status: index % 3 === 0 ? 'open' : 'closed',
      opened_at: frozenAt,
      created_at: frozenAt,
    };
  });
  store.stateRollups = {
    ...(store.stateRollups ?? {}),
    [tenantId]: {
      ...(store.stateRollups?.[tenantId] ?? {}),
      target_groups: PORTAL_SCALE_PROFILE.targetGroups,
      open_findings: SCALE_OPEN_FINDINGS,
    },
  };
}

async function fetchPortalState(baseUrl) {
  const res = await fetch(`${baseUrl}/v1/state`, { headers: portalOwnerHeaders() });
  if (!res.ok) throw new Error(`GET /v1/state failed (${res.status})`);
  return res.json();
}

test.describe('portal dashboard overview panels', () => {
  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('FT-DASH-01 weighted factors panel renders one row per /v1/state readiness factor', async ({ page }) => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const state = await fetchPortalState(baseUrl);
    const factors = Array.isArray(state?.readiness?.factors) ? state.readiness.factors : [];
    expect(factors.length, 'seeded /v1/state must publish readiness factors').toBeGreaterThan(0);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', baseUrl);

    await expect(page.getByText('Weighted factors', { exact: true })).toBeVisible();
    const rows = page.getByTestId('readiness-factors').getByTestId('readiness-factor-row');
    await expect(rows).toHaveCount(factors.length);

    for (const factor of factors) {
      const row = rows.filter({ hasText: factor.label });
      await expect(row, `one row for factor ${factor.key}`).toHaveCount(1);
      // Score renders as `${score}/${scale}` in the compact factor row.
      await expect(row.locator('.factor-score')).toContainText(String(factor.score));
      await expect(row).toContainText(plainInlineText(factor.detail));
    }
  });

  test('FT-DASH-02 no kill switch alert renders while the SOC kill switch is clear', async ({ page }) => {
    await restartPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const state = await fetchPortalState(baseUrl);
    expect(state?.kill_switch?.active ?? false).toBe(false);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', baseUrl);

    await expect(page.getByText('Weighted factors', { exact: true })).toBeVisible();
    await expect(page.getByText(KILL_SWITCH_HEADLINE)).toHaveCount(0);
  });

  test('FT-DASH-03 armed kill switch raises a dashboard alert with reason and timestamp', async ({ page }) => {
    await restartPortalPlaywrightServer({ mutate: applyArmedKillSwitch });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const state = await fetchPortalState(baseUrl);
    expect(state?.kill_switch?.active).toBe(true);
    expect(state?.kill_switch?.reason).toBe(KILL_SWITCH_REASON);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', baseUrl);

    const alert = page.getByRole('alert').filter({ hasText: KILL_SWITCH_HEADLINE });
    await expect(alert).toHaveCount(1);
    await expect(alert).toContainText(KILL_SWITCH_REASON);
    await expect(alert.getByTitle(/kill_switch\.updated_at/)).toBeVisible();
  });
  test('FT-DASH-04 served bundle counts the scale estate from server totals and links each count to its exact list', async ({ page }) => {
    test.skip(!isPortalScaleEnabled(), 'Set ASTRANULL_PORTAL_SCALE=1 for the full served-DOM scale assertion.');
    test.setTimeout(300_000);
    expect(PORTAL_SCALE_PROFILE.targetGroups).toBe(10_000);
    expect(PORTAL_SCALE_PROFILE.targets).toBe(5_000);
    expect(SCALE_OPEN_FINDINGS).toBe(33_334);

    await restartPortalPlaywrightServer({ mutate: applyPortalScaleCounts });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const read = async (path) => {
      const response = await fetch(`${baseUrl}${path}`, { headers: portalOwnerHeaders() });
      expect(response.ok, `${path} ${response.status}`).toBe(true);
      return response.json();
    };
    const state = await fetchPortalState(baseUrl);
    expect(state.target_groups).toBe(10_000);
    expect(state.open_findings).toBe(33_334);
    expect(state).not.toHaveProperty('targets');
    expect(state).not.toHaveProperty('target_count');

    // The rows agree with the rollup: the open list total is the full predicate, not a page.
    const openPage = await read('/v1/findings?status=open&limit=50');
    expect(openPage.items).toHaveLength(50);
    expect(openPage.total).toBe(33_334);
    expect(openPage.pages).toBe(Math.ceil(33_334 / 50));
    expect((await read('/v1/findings?limit=1')).total).toBe(PORTAL_SCALE_PROFILE.findings);

    // A bounded target page carries the full denominator; target records and hostnames stay separate units.
    const targetPage = await read('/v1/targets?unit=target&limit=50');
    expect(targetPage.items).toHaveLength(50);
    expect(targetPage.total).toBe(5_000);
    expect(targetPage.units).toMatchObject({ target_records: 5_000, normalized_hosts: 5_000 });
    const waf = await read('/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&limit=1');
    expect(waf.units).toMatchObject({ target_records: 5_000, normalized_hosts: 5_000 });
    const wafNotChecked = waf.segments.find((segment) => segment.key === 'not_checked');
    expect(wafNotChecked.count).toBe(5_000);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', baseUrl);

    const kpis = page.getByRole('group', { name: 'Readiness key metrics' });
    const declared = kpis.getByRole('link', { name: /^Declared targets/ });
    await expect(declared.locator('.dashboard-kpi-value')).toHaveText('5,000');
    await expect(declared).toContainText('5,000 distinct hostnames');
    const open = kpis.getByRole('link', { name: /^Open findings/ });
    await expect(open.locator('.dashboard-kpi-value')).toHaveText('33,334');
    await expect(open).toHaveAttribute('href', '#findings?status=open');
    // Group counts never turn into a target sentence.
    await expect(page.getByText('10,000 targets', { exact: true })).toHaveCount(0);

    // The WAF cohort count opens the exact server list with the same count and unit.
    const cohortLink = page.getByRole('link', { name: 'WAF observations not checked: 5,000 distinct hostnames. Open the matching list.' });
    await expect(cohortLink).toHaveAttribute('href', '#targets?family=waf&family_status=not_checked&unit=hostname');
    await cohortLink.click();
    const cohort = page.locator('.cohort-count');
    await expect(cohort).toContainText('Showing 1 to 50 of 5,000 distinct hostnames.');
    await expect(cohort).toContainText('Same scope: 5,000 declared target records and 5,000 distinct hostnames.');

    // The open-findings count opens the same predicate with the same full total and real paging.
    await gotoPortalRoute(page, 'dashboard', baseUrl);
    await kpis.getByRole('link', { name: /^Open findings/ }).click();
    await expect(page).toHaveURL(/#findings\?status=open$/);
    const openChip = page.getByRole('group', { name: 'Finding status filters' }).getByRole('button', { name: /^Open/ });
    await expect(openChip).toHaveAttribute('aria-pressed', 'true');
    await expect(openChip.locator('.rf-tab-count')).toHaveText('33,334');
    await page.getByRole('button', { name: 'Each finding' }).click();
    await expect(page.locator('.rf-pager > .rf-pager-info')).toHaveText('Showing 1 to 25 of 33,334 findings');
    await expect(page.locator('.rf-pager .rf-toolbar .rf-pager-info')).toHaveText(`Page 1 of ${Math.ceil(33_334 / 25).toLocaleString('en-US')}`);
  });
});
