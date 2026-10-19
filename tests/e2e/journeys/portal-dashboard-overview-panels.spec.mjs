import { expect, test } from '@playwright/test';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import { plainInlineText } from '../../../apps/web/react/src/lib/plain-language.mjs';
import { collectPortalBrowserFailures } from '../../helpers/portal-browser-failures.mjs';
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
const KILL_SWITCH_HEADLINE = 'AstraNull SOC has paused testing for this workspace';
const KILL_SWITCH_EFFECT = 'New validation runs and scans are blocked, and runs in progress were cancelled. Contact support for status.';
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

/** The score text a factor row shows: scored factors as points of their weight, penalties as deducted points, context as not scored. */
function expectedFactorScoreText(factor) {
  const weight = factor.weight;
  if (typeof weight !== 'number' || !Number.isFinite(weight) || weight > 0) {
    return `${factor.score}/${typeof weight === 'number' && weight > 0 ? weight : 100}`;
  }
  if (factor.score < 0) return `\u2212${Math.abs(factor.score)} pts`;
  return 'Not scored';
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
    const factors = (Array.isArray(state?.readiness?.factors) ? state.readiness.factors : [])
      .filter((factor) => typeof factor.score === 'number' && Number.isFinite(factor.score));
    expect(factors.length, 'seeded /v1/state must publish readiness factors').toBeGreaterThan(0);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', baseUrl);

    await expect(page.getByText('Weighted factors', { exact: true })).toBeVisible();
    const rows = page.getByTestId('readiness-factors').getByTestId('readiness-factor-row');
    await expect(rows).toHaveCount(factors.length);

    await expect(page.getByText('Scored factors add points and penalties subtract them; context factors are shown for transparency and do not change the score.')).toBeVisible();
    for (const factor of factors) {
      const row = rows.filter({ hasText: factor.label });
      await expect(row, `one row for factor ${factor.key}`).toHaveCount(1);
      const scoreText = expectedFactorScoreText(factor);
      await expect(row.locator('.factor-score')).toHaveText(scoreText);
      // Only scored factors draw a bar; a penalty or context factor is never shown as a share of 100.
      await expect(row.locator('.factor-track')).toHaveCount(scoreText.includes('/') ? 1 : 0);
      if (factor.score < 0) {
        await expect(row.getByRole('img', { name: `${plainInlineText(factor.label)}: penalty of ${Math.abs(factor.score)} points` })).toHaveCount(1);
      }
      await expect(row).toContainText(plainInlineText(factor.detail));
      if (factor.key === 'soc_readiness') expect(factor.detail).not.toMatch(/\bhs_[a-z0-9_]+/i);
    }
    const contextFactors = factors.filter((factor) => expectedFactorScoreText(factor) === 'Not scored');
    if (contextFactors.length > 0) await expect(page.getByRole('heading', { name: 'Context (not part of the score)' })).toBeVisible();
    if (typeof state.readiness.score === 'number') {
      await expect(page.getByTestId('readiness-published-score')).toContainText(`Published score${state.readiness.score}/100`);
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

  test('FT-DASH-03 active kill switch raises a paused-testing alert with effect, reason and timestamp', async ({ page }) => {
    await restartPortalPlaywrightServer({ mutate: applyArmedKillSwitch });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const state = await fetchPortalState(baseUrl);
    expect(state?.kill_switch?.active).toBe(true);
    expect(state?.kill_switch?.reason).toBe(KILL_SWITCH_REASON);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', baseUrl);

    const alert = page.getByRole('alert').filter({ hasText: KILL_SWITCH_HEADLINE });
    await expect(alert).toHaveCount(1);
    await expect(alert).toContainText(KILL_SWITCH_EFFECT);
    await expect(alert).toContainText(`Reason: ${KILL_SWITCH_REASON}`);
    await expect(alert).toContainText('Paused');
    await expect(alert.getByTitle(/kill_switch\.updated_at/)).toBeVisible();
  });
  test('FT-DASH-05 at 375px the recorded verdict and ownership stay on screen with no page overflow', async ({ page }) => {
    await restartPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
    const baseUrl = getPortalPlaywrightBaseUrl();
    await page.setViewportSize({ width: 375, height: 812 });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', baseUrl);

    const posture = page.locator('.dash-area-targets');
    await expect(posture.locator('td[data-label="Recorded verdict"]').first()).toBeVisible();
    await expect(page.locator('.dash-area-activity'), 'the recent activity widget was removed').toHaveCount(0);
    for (const [card, label] of [[posture, 'Recorded verdict'], [posture, 'Ownership']]) {
      const cell = card.locator(`td[data-label="${label}"]`).first();
      await cell.scrollIntoViewIfNeeded();
      await expect(cell, `${label} cell is visible at 375px`).toBeVisible();
      const box = await cell.boundingBox();
      expect(box, `${label} cell has a layout box`).not.toBeNull();
      expect(box.x, `${label} starts on screen`).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width, `${label} ends on screen`).toBeLessThanOrEqual(375 + 1);
    }
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow, 'no horizontal page scroll at 375px').toBeLessThanOrEqual(0);
  });

  for (const [unit, noun] of [['hostname', 'distinct hostnames'], ['target', 'declared target records']]) {
    test(`coverage retains each server status and exact link in ${noun}`, async ({ page }, testInfo) => {
      await restartPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
      const baseUrl = getPortalPlaywrightBaseUrl();
      const diagnostics = await collectPortalBrowserFailures(page, baseUrl);
      const statuses = [
        ['detected', 'Detected'], ['not_detected', 'Not detected in the last observation'],
        ['not_checked', 'Not checked'], ['not_recorded', 'Not recorded'],
        ['inconclusive', 'Inconclusive'], ['stale', 'Stale observation'],
        ['conflict', 'Conflicting signals'], ['unknown', 'Unknown'],
      ].map(([key, label], index) => ({ key, label, count: index + 1 + (unit === 'target' ? 1 : 0) }));
      await page.route('**/v1/analytics/declared-hosts?**', (route) => {
        if (route.request().method() !== 'GET') return route.fallback();
        const family = new URL(route.request().url()).searchParams.get('family');
        const query = { family, unit };
        return route.fulfill({ json: {
          canonical_unit: unit, complete: true, scope: 'current', historical: false,
          as_of: PORTAL_BASELINE_IDS.frozenAt,
          denominator: statuses.reduce((sum, part) => sum + part.count, 0),
          units: { target_records: 44, normalized_hosts: 36 },
          list_query: { query },
          segments: statuses.filter((part) => part.key !== 'unknown').map((part) => ({
            key: part.key, count: part.count, list_query: { query: { ...query, family_status: part.key } },
          })),
          unknown_count: statuses.find((part) => part.key === 'unknown').count,
        } });
      });
      await page.setViewportSize({ width: 375, height: 812 });
      await injectPortalDevHeadersSession(page);
      await gotoPortalRoute(page, 'dashboard', baseUrl);
      const denominator = statuses.reduce((sum, part) => sum + part.count, 0);
      await expect(page.locator('.declared-coverage-head')).toContainText(`Across ${denominator} ${noun}`);
      for (const family of ['waf', 'cdn']) {
        for (const part of statuses) {
          const link = page.getByRole('link', { name: `${family.toUpperCase()} observations ${part.label.toLowerCase()}: ${part.count} ${noun}. Open the matching list.`, exact: true });
          await expect(link).toBeVisible();
          await expect(link).toHaveAttribute('href', `#targets?family=${family}&family_status=${part.key}&unit=${unit}`);
          await expect(link).toContainText(part.label);
          await expect(link.locator('strong')).toHaveText(String(part.count));
        }
      }
      expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);
      await page.screenshot({ path: testInfo.outputPath(`coverage-${unit}.png`), fullPage: true, animations: 'disabled' });
      await page.setViewportSize({ width: 1440, height: 1000 });
      expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);
      await page.screenshot({ path: testInfo.outputPath(`coverage-${unit}-desktop.png`), fullPage: true, animations: 'disabled' });
      diagnostics.assertClean();
    });
  }

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

    const diagnostics = await collectPortalBrowserFailures(page, baseUrl);

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
    diagnostics.assertClean();
  });
});
