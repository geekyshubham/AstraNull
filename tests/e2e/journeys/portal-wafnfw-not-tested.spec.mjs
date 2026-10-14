import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { assertPortalInitialLoad } from '../../helpers/portal-browser-failures.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import {
  getPortalPlaywrightBaseUrl,
  seedPortalPlaywrightStore,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import { injectPortalDevHeadersSession, waitForPortalRouteSettled } from '../../helpers/portal-playwright-session.mjs';

/** T8f: a run that finished as required_input_missing reads as a neutral "Not tested", never as a failure. */

const RUN_ID = 'run_t8f_not_tested';
const CHECK_ID = 'nfw.declared_deny_udp.safe';
const MESSAGE = 'No denied port is declared, so there was nothing to probe.';

function seedNotTested(store) {
  applyPortalBaselineReadinessBoost(store, { observedAt: PORTAL_BASELINE_IDS.frozenAt });
  const at = PORTAL_BASELINE_IDS.frozenAt;
  store.testRuns = (store.testRuns ?? []).filter((run) => run.id !== RUN_ID);
  store.verdicts = (store.verdicts ?? []).filter((verdict) => verdict.test_run_id !== RUN_ID);
  store.testRuns.push({
    id: RUN_ID,
    tenant_id: PORTAL_BASELINE_IDS.tenantId,
    target_group_id: PORTAL_BASELINE_IDS.targetGroupId,
    target_id: PORTAL_BASELINE_IDS.targetId,
    check_id: CHECK_ID,
    vector_family: 'l3_l4',
    status: 'verdicted',
    created_at: at,
    started_at: at,
    completed_at: at,
    validation_mode: 'external_only',
    probe_external_result: 'unsupported_target',
    summary: { requests_sent: 0, required_input_missing: 'declared_udp_deny_required' },
  });
  store.verdicts.push({
    id: 'evidence_t8f_not_tested',
    tenant_id: PORTAL_BASELINE_IDS.tenantId,
    test_run_id: RUN_ID,
    target_id: PORTAL_BASELINE_IDS.targetId,
    check_id: CHECK_ID,
    verdict: 'inconclusive',
    confidence: 'external_only',
    explanation: MESSAGE,
    explanation_reason: 'required_input_missing',
    evidence_ids: [],
    severity: 'info',
    placement_confidence: { explanation_reason: 'required_input_missing', reason: 'required_input_missing', requests_sent: 0 },
    created_at: at,
  });
}

test.describe('required input missing reads as Not tested (T8f)', () => {
  test.beforeAll(async ({ browser }) => {
    test.setTimeout(180000);
    await startPortalPlaywrightServer({ liveSource: true, mutate: seedNotTested, env: { ASTRANULL_PROBE_MODE: 'simulation' } });
    const warm = await browser.newPage();
    try {
      await injectPortalDevHeadersSession(warm);
      await assertPortalInitialLoad(warm, getPortalPlaywrightBaseUrl());
    } finally {
      await warm.close();
    }
  });
  test.beforeEach(async ({ page }) => {
    test.setTimeout(90000);
    seedPortalPlaywrightStore(seedNotTested);
    await injectPortalDevHeadersSession(page);
  });
  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('run detail names what is missing, links to Controls and stays neutral', async ({ page }) => {
    await page.goto(`${getPortalPlaywrightBaseUrl()}/app#run-detail?id=${RUN_ID}`, { waitUntil: 'networkidle', timeout: 60_000 });
    await waitForPortalRouteSettled(page);
    const main = page.locator('#portal-main');
    await expect(main.locator('.metric-grid')).toContainText('Not tested');
    const note = main.locator('.not-tested-note').first();
    await expect(note).toContainText(MESSAGE);
    await expect(note).toContainText('No requests were sent');
    const cta = note.getByRole('link', { name: 'Declare a denied UDP port' });
    await expect(cta).toHaveAttribute('href', /tab=controls/);
    await expect(cta).toHaveAttribute('href', /section=network/);
    await expect(main).not.toContainText('required_input_missing');
    await expect(main.locator('.metric-grid')).not.toContainText(/gap found|inconclusive/i);
    await expect(main.locator('.verdict-explanation')).toContainText(`Not tested. ${MESSAGE}`);
    const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).include('#portal-main').analyze();
    const blocking = results.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact ?? ''));
    expect(blocking.map((violation) => violation.id)).toEqual([]);
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(note).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  });
});
