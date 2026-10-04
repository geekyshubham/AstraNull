import { expect, test } from '@playwright/test';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import {
  getPortalPlaywrightBaseUrl,
  portalOwnerHeaders,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  injectPortalDevHeadersSession,
} from '../../helpers/portal-playwright-session.mjs';

const VIEWPORTS = [
  { width: 375, height: 812 },
  { width: 768, height: 1024 },
  { width: 1024, height: 900 },
  { width: 1440, height: 900 },
];

// A declaration-only readiness check from the real catalog (metadata marker, evidence tier E1).
const E1_CHECK_ID = 'l3.icmp_flood.readiness';
const E1_RUN_ID = 'run_exec_e1_declaration';

// Server segment keys and the plain-language label each one reads as on the dashboard.
const SEGMENT_LABELS = {
  detected: 'detected',
  not_detected: 'not detected in the last observation',
  inconclusive: 'inconclusive',
  stale: 'stale observation',
  conflict: 'conflicting signals',
  not_checked: 'not checked',
  not_recorded: 'not recorded',
};

function seedDeclarationOnlyRun(store) {
  store.testRuns.push({
    id: E1_RUN_ID,
    tenant_id: PORTAL_BASELINE_IDS.tenantId,
    target_group_id: PORTAL_BASELINE_IDS.targetGroupId,
    target_id: PORTAL_BASELINE_IDS.targetId,
    check_id: E1_CHECK_ID,
    status: 'completed',
    created_at: '2026-07-02T09:00:00.000Z',
    started_at: '2026-07-02T09:00:00.000Z',
    completed_at: '2026-07-02T09:00:01.000Z',
  });
}

async function api(path) {
  const response = await fetch(`${getPortalPlaywrightBaseUrl()}${path}`, { headers: portalOwnerHeaders() });
  expect(response.ok, `${path} ${response.status}`).toBe(true);
  return response.json();
}

async function expectNoPageOverflow(page) {
  const overflow = await page.evaluate(() => (
    document.documentElement.scrollWidth - document.documentElement.clientWidth
  ));
  expect(overflow, 'page-level horizontal overflow').toBeLessThanOrEqual(1);
}

test.describe('portal executive clarity', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: seedDeclarationOnlyRun });
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('Dashboard answers readiness targets-first from server counts, with no defense path or inferred cloud stage', async ({ page }) => {
    const waf = await api('/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&limit=1');
    const openTotal = (await api('/v1/findings?status=open&limit=1')).total;
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());

    await expect(page.getByRole('heading', { level: 1, name: 'Readiness overview' })).toBeVisible();
    const kpis = page.getByRole('group', { name: 'Readiness key metrics' });
    const declared = kpis.getByRole('link', { name: /^Declared targets/ });
    await expect(declared).toHaveAttribute('href', '#targets');
    await expect(declared).toContainText(`Declared targets${waf.units.target_records}`);
    const open = kpis.getByRole('link', { name: /^Open findings/ });
    await expect(open).toHaveAttribute('href', '#findings?status=open');
    await expect(open).toContainText(`Open findings${openTotal}`);

    const posture = page.locator('[data-ui="card"]').filter({ has: page.getByRole('heading', { name: 'Target posture', exact: true }) });
    await expect(posture).toContainText('checkout.acme.com');
    await expect(page.locator('[data-ui="card"]').filter({ has: page.getByRole('heading', { name: 'What to fix first', exact: true }) })).toBeVisible();
    const activity = page.locator('[data-ui="card"]').filter({ has: page.getByRole('heading', { name: 'Recent validation activity', exact: true }) });
    await expect(activity).toContainText(PORTAL_BASELINE_IDS.readinessRunId);

    // The old Internet → Edge/CDN → WAF → Origin path inferred stages the server never observed.
    await expect(page.locator('.defense-path, .defense-stage')).toHaveCount(0);
    const mainText = await page.locator('#portal-main').innerText();
    expect(mainText).not.toMatch(/Where does attack traffic get stopped|Edge \/ CDN/);
    expect(mainText).not.toMatch(/Agent health|Agents healthy|Environment status/);
    await expect(page.locator('#portal-main .evidence-guide')).toHaveCount(0);
  });

  test('Dashboard WAF and CDN observations are the server counts in plain language, detection never read as blocking', async ({ page }) => {
    const families = {
      WAF: await api('/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&limit=1'),
      CDN: await api('/v1/analytics/declared-hosts?family=cdn&unit=normalized_hostname&limit=1'),
    };
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());

    const region = page.getByRole('region', { name: 'Declared host protection observations' });
    await expect(region).toContainText('Detection is not effectiveness, and unknown stays unknown.');
    for (const [label, body] of Object.entries(families)) {
      expect(body.complete).toBe(true);
      for (const segment of body.segments) {
        const name = `${label} observations ${SEGMENT_LABELS[segment.key]}: ${segment.count} distinct ${segment.count === 1 ? 'hostname' : 'hostnames'}. Open the matching list.`;
        const link = region.getByRole('link', { name, exact: true });
        await expect(link, name).toHaveCount(1);
        await expect(link).toHaveAttribute('href', `#targets?family=${label.toLowerCase()}&family_status=${segment.key}&unit=hostname`);
      }
    }
    // Only WAF and CDN have observation cohorts; no cloud or origin stage is inferred from them.
    const regionText = await region.innerText();
    expect(regionText).not.toMatch(/\bcloud\b|\borigin\b|blocked|protected/i);
    expect(regionText).not.toMatch(/\b(?:not_checked|not_detected|not_recorded|normalized_hostname|coverage_summary_not_populated)\b/);

    await region.getByRole('group', { name: 'Count by' }).getByRole('button', { name: 'Declared target records' }).click();
    const records = families.WAF.units.target_records;
    await expect(region).toContainText(`of ${records} declared target ${records === 1 ? 'record' : 'records'}`);
  });

  test('Dashboard and Target Detail do not overflow at 375, 768, 1024, or 1440 pixels', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    for (const viewport of VIEWPORTS) {
      await page.setViewportSize(viewport);
      await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());
      await expect(page.getByRole('heading', { level: 1, name: 'Readiness overview' })).toBeVisible();
      await expect(page.getByRole('region', { name: 'Declared host protection observations' })).toBeVisible();
      await expectNoPageOverflow(page);
      if (viewport.width === 1440) {
        const postureCard = page.locator('[data-ui="card"]').filter({ has: page.getByRole('heading', { name: 'Target posture' }) });
        const tableWrap = postureCard.locator('.table-wrap');
        // DESIGN.md: data tables own their horizontal scroll; the region stays keyboard-focusable.
        const tableGeometry = await tableWrap.evaluate((node) => ({
          overflowX: getComputedStyle(node).overflowX,
          tabIndex: node.getAttribute('tabindex'),
          hasVerdict: /Pass|Gap|Review|No result/.test(node.textContent ?? ''),
        }));
        expect(tableGeometry.overflowX).toBe('auto');
        expect(tableGeometry.tabIndex).toBe('0');
        expect(tableGeometry.hasVerdict, 'Recorded verdict column must be present').toBe(true);
      }

      await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl());
      await expect(page.getByRole('heading', { level: 1, name: 'checkout.acme.com' })).toBeVisible();
      await expect(page.getByRole('region', { name: 'Protection observations' })).toBeVisible();
      await expectNoPageOverflow(page);
    }
  });

  test('Target Detail leads with identity, ownership, declaration, compatible checks and proof, and keeps E1 declaration-only', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl());

    const main = page.locator('#portal-main');
    const heading = page.getByRole('heading', { level: 1, name: 'checkout.acme.com' });
    await expect(heading).toBeVisible();
    await expect(main).toContainText('Domain ownership verified');
    await expect(main).toContainText('Validation unlocked');
    for (const term of ['Purpose', 'Service roles', 'Owner', 'Criticality']) {
      await expect(main.getByRole('term').filter({ hasText: new RegExp(`^${term}$`) })).toBeVisible();
    }
    await expect(page.getByRole('link', { name: 'Group: edge-checkout' })).toHaveAttribute('href', /target-group-detail\?id=tg_checkout$/);
    // Identity and declared context come before the workspace tabs.
    const order = await page.evaluate(() => {
      const h1 = document.querySelector('#portal-main h1');
      const tabs = document.querySelector('#portal-main [role="tablist"]');
      return Boolean(h1 && tabs && (h1.compareDocumentPosition(tabs) & Node.DOCUMENT_POSITION_FOLLOWING));
    });
    expect(order).toBe(true);

    // Proof of ownership is recorded fact, not inferred.
    const facts = page.getByRole('region', { name: 'Target facts' });
    await expect(facts.getByRole('row', { name: /Ownership method DNS TXT record/ })).toBeVisible();
    await expect(facts.getByRole('row', { name: /Declaration source Manual declaration/ })).toBeVisible();

    // Detection is never proof of blocking.
    const observations = page.getByRole('region', { name: 'Protection observations' });
    await expect(observations).toContainText('Detection is a signal, not proof of blocking.');
    await expect(observations).toContainText('Not measured. Detection alone does not show whether anything is blocked.');

    await page.getByRole('tab', { name: /^Validate/ }).click();
    const checks = page.getByRole('region', { name: 'Checks for this target' });
    await expect(checks).toContainText(/\d+ bounded external checks are compatible with this target kind\./);
    await expect(checks.getByRole('button', { name: /^Review all \d+$/ })).toBeVisible();

    // A recorded run of a declaration-only (E1) check never reads as live traffic.
    await page.getByRole('tab', { name: /^Changes/ }).click();
    const executions = page.getByRole('region', { name: 'Recorded check executions' });
    const e1Row = executions.getByRole('row').filter({ hasText: E1_CHECK_ID });
    await expect(e1Row).toContainText('Declaration only');
    await expect(e1Row.getByText('Declaration only')).toHaveAttribute('title', 'No live traffic was sent for this check.');
    await expect(e1Row).toContainText('No evidence-backed result');

    const visible = await main.innerText();
    expect(visible).not.toMatch(/\b(?:not_detected|not_tested|must_block_before_origin|coverage_summary_not_populated)\b/);
    expect(visible).not.toMatch(/\b(?:API|hydrator|canonical)\b|producer attribution/i);
    // ADR-0008: no internal-agent "observed from inside" language on the target detail.
    expect(visible).not.toMatch(/Observed from inside/);
  });

  test('Target Detail shows a server empty reason once, never repeated as body copy', async ({ page }) => {
    const detail = await api('/v1/targets/tgt_checkout_2');
    const reason = String(detail.meta?.runs_empty_reason ?? '').trim();
    expect(reason.length).toBeGreaterThan(0);
    const title = reason.replace(/[.!?]+$/, '');

    await injectPortalDevHeadersSession(page);
    await page.goto(`${getPortalPlaywrightBaseUrl()}/app#target-detail?id=tgt_checkout_2&tab=history`, { waitUntil: 'networkidle' });
    const executions = page.getByRole('region', { name: 'Recorded check executions' });
    const emptyState = executions.getByRole('region', { name: title });
    await expect(emptyState.getByRole('heading', { name: title })).toHaveCount(1);
    await expect(emptyState.locator('p')).toHaveCount(0);
  });
});
