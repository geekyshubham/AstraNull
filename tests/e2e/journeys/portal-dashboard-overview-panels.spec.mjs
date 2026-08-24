import { expect, test } from '@playwright/test';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
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
});
