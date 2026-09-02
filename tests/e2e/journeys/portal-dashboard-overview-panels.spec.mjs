import { expect, test } from '@playwright/test';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
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
      await expect(row.locator('.lg-pct')).toHaveText(String(factor.score));
      await expect(row).toContainText(factor.detail);
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
  test('FT-DASH-04 served bundle keeps scale target groups, targets, and findings distinct', async ({ page }) => {
    test.skip(!isPortalScaleEnabled(), 'Set ASTRANULL_PORTAL_SCALE=1 for the full served-DOM scale assertion.');
    expect(PORTAL_SCALE_PROFILE.targetGroups).toBe(10_000);
    expect(PORTAL_SCALE_PROFILE.targets).toBe(5_000);
    expect(SCALE_OPEN_FINDINGS).toBe(33_334);

    await restartPortalPlaywrightServer({ mutate: applyPortalScaleCounts });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const state = await fetchPortalState(baseUrl);
    expect(state.target_groups).toBe(10_000);
    expect(state.open_findings).toBe(33_334);
    expect(state).not.toHaveProperty('targets');
    expect(state).not.toHaveProperty('target_count');

    const inventoryResponse = await fetch(`${baseUrl}/v1/targets`, { headers: portalOwnerHeaders() });
    expect(inventoryResponse.ok).toBe(true);
    const inventory = await inventoryResponse.json();
    expect(inventory.items).toHaveLength(5_000);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', baseUrl);

    const coverage = page.locator('.kpi-cell').filter({ hasText: 'Coverage' });
    await expect(coverage.locator('.kpi-delta')).toHaveText('10,000 target groups');
    const findings = page.locator('.kpi-cell').filter({ hasText: 'Open findings' });
    await expect(findings.locator('.kpi-value')).toHaveText('33,334');
    await expect(page.getByText('10,000 targets', { exact: true })).toHaveCount(0);
    await expect(page.getByText('5,000 targets', { exact: true })).toHaveCount(0);

    await gotoPortalRoute(page, 'targets', baseUrl);
    const targetSummary = page.getByLabel('Target inventory summary');
    await expect(
      targetSummary.locator('.targets-summary-cell').filter({ hasText: 'Declared targets' }).locator('strong'),
    ).toHaveText('5,000');
  });
});
