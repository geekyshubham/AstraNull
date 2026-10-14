import { expect, test } from '@playwright/test';
import { assertPortalInitialLoad } from '../../helpers/portal-browser-failures.mjs';
import AxeBuilder from '@axe-core/playwright';
import { assessmentChecks, withTargetRunnableChecks } from '../../../apps/web/react/src/lib/domain-checks.mjs';
import { targetRunnableIndex } from '../../../apps/web/react/src/lib/control-declarations.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
  seedPortalPlaywrightStore,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  injectPortalDevHeadersSession,
  waitForPortalRouteSettled,
} from '../../helpers/portal-playwright-session.mjs';

/**
 * FT-DOMAIN-01 (current release) — target workspace: recorded WAF/CDN attribution per family, the
 * evidence behind it, per-check status with evidence in place, no probe on page load, ownership
 * gating, and a reviewed multi-check start with live progress and stop.
 *
 * Runs against the real in-process dev-json backend. Only the verdict-bearing payloads that the
 * simulation runtime cannot produce (signed edge fingerprints, exposed/protected verdicts) are
 * layered onto real responses. The server protection profile is removed in those overrides so the
 * page reads the legacy edge observation, family by family.
 */

const VERIFIED_FRESH_TARGET = 'tgt_checkout_2';
const UNVERIFIED_TARGET = 'tgt_checkout_4';
const GRADED_PASS_CHECK = 'waf.http_method_policy_marker.safe';
const GRADED_GAP_CHECK = 'waf.crlf_injection_marker.safe';

const EDGE_DETECTION = {
  status: 'detected',
  reason: null,
  waf: { status: 'detected', provider: 'cloudflare', type: 'response_fingerprint' },
  cdn: { status: 'detected', provider: 'cloudflare', type: 'address_range' },
  cloud: { status: 'not_detected' },
  layers: [
    { family: 'cdn', provider: 'cloudflare', display_name: null, sources: ['address_range', 'cname_suffix'], confidence: 0.8, evidence_consistency: 'agreement', matched_signal_count: 0, conflicting: false },
    { family: 'waf', provider: 'cloudflare', display_name: 'Cloudflare', sources: ['response_fingerprint'], confidence: 0.95, evidence_consistency: 'single_source', matched_signal_count: 2, conflicting: false },
  ],
  effectiveness: { status: 'effective_for_tested_probes', tested_count: 3, blocked_count: 3, passed_count: 0 },
  network_firewall: { status: 'not_tested', direct_origin_reachability: { status: 'not_tested' } },
  observed_at: '2030-01-01T00:00:00.000Z',
  evidence: {
    vendor_matches: [{ vendor: 'cloudflare', matched_signals: [{ signal: 'server=cloudflare', tier: 'passive' }, { signal: 'cf-ray', tier: 'passive' }] }],
    dns_cname_chain: ['pay.acme.com', 'pay.acme.com.cdn.cloudflare.net'],
    dns_resolved_ips: ['104.18.32.7'],
    wafw00f: { detected: true, firewall: 'Cloudflare', manufacturer: 'Cloudflare Inc.' },
    cdncheck: { matched: true, provider: 'cloudflare', item_type: 'cdn', source: 'ip' },
  },
};

function verdictStep(checkId, position, verdict, explanation) {
  return {
    step_id: `step_fx_${position}`,
    position,
    check_id: checkId,
    status: 'verdicted',
    test_run_id: `run_fx_${position}`,
    request: { kind: 'waf_class_marker_probe', method: 'GET', path: '/', protocol: 'https', max_requests: 2, timeout_ms: 5000 },
    response: { external_result: verdict === 'edge_exposed' ? 'connected' : 'blocked', status_code: verdict === 'edge_exposed' ? 200 : 403 },
    requests_sent: 2,
    requests_simulated: false,
    verdict: { verdict, confidence: 'external_only', explanation, evidence_ids: [`evt_fx_${position}`] },
  };
}

function completedScan(targetId) {
  return {
    id: 'scan_fx_run_all',
    tenant_id: PORTAL_BASELINE_IDS.tenantId,
    status: 'completed',
    name: 'Run all checks',
    target_group_id: PORTAL_BASELINE_IDS.targetGroupId,
    target_id: targetId,
    created_at: '2030-01-01T00:00:00.000Z',
    completed_at: '2030-01-01T00:20:00.000Z',
    summary: { total: 3, completed: 3 },
    steps: [
      verdictStep(GRADED_PASS_CHECK, 0, 'edge_protected', 'The evaluated bounded marker was blocked at the edge.'),
      verdictStep(GRADED_GAP_CHECK, 1, 'edge_exposed', 'The evaluated marker reached the declared path; the edge did not block this scenario.'),
      verdictStep('origin.leak_scan.safe', 2, 'inconclusive', 'Recorded leak-scan observations do not prove origin exposure or protection.'),
    ],
  };
}

async function expectNoBlockingAxeViolations(page, selector) {
  await waitForPortalRouteSettled(page);
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).include(selector).analyze();
  const blocking = results.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact ?? ''));
  expect(blocking.map((violation) => ({ id: violation.id, nodes: violation.nodes.map((node) => ({ target: node.target, summary: node.failureSummary })) }))).toEqual([]);
}

test.describe('target workspace: recorded attribution, checks and reviewed runs (FT-DOMAIN-01)', () => {
  test.beforeAll(async ({ browser }) => {
    test.setTimeout(180000);
    await startPortalPlaywrightServer({ liveSource: true, env: { ASTRANULL_PROBE_MODE: 'simulation' } });
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
    page.on('pageerror', (error) => console.error('browser-runtime-error:', error.stack));
    seedPortalPlaywrightStore(applyPortalBaselineReadinessBoost);
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('shows recorded per-family attribution, its sources, and per-check status with evidence in place', async ({ page }) => {
    await page.route(`**/v1/targets/${VERIFIED_FRESH_TARGET}`, async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      await route.fulfill({ response, json: { ...payload, edge_detection: EDGE_DETECTION, protection_profile: null } });
    });
    await page.route('**/v1/validation-scans?*', async (route) => {
      const response = await route.fetch();
      await route.fulfill({ response, json: { items: [completedScan(VERIFIED_FRESH_TARGET)], count: 1, meta: {} } });
    });
    const edgePosts = [];
    page.on('request', (request) => {
      if (request.method() === 'POST' && request.url().includes('/v1/waf/edge-detection')) edgePosts.push(request.url());
    });

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': VERIFIED_FRESH_TARGET } });

    const observations = page.locator('.td-observations');
    const wafRow = observations.locator('.td-provider-row').filter({ hasText: 'WAF' }).first();
    const cdnRow = observations.locator('.td-provider-row').filter({ hasText: /^CDN/ });
    await expect(wafRow).toContainText('Detected');
    await expect(wafRow).toContainText('Cloudflare');
    await expect(wafRow).toContainText('WAF fingerprint');
    await expect(cdnRow).toContainText('Cloudflare');
    await expect(cdnRow).toContainText('IP address range');
    await expect(cdnRow).toContainText('DNS CNAME');
    // Origin hosting and DNS are never borrowed from the edge vendor.
    await expect(observations.locator('.td-provider-row').filter({ hasText: 'Origin hosting' })).toContainText('Unknown');
    await expect(observations.locator('.td-provider-row').filter({ hasText: 'DNS provider' })).toContainText('Unknown');
    // Detection is not efficacy: only recorded marker counts appear, no client-side protection label.
    await expect(observations.locator('.td-efficacy')).toContainText('3 markers blocked');
    await expect(observations.locator('.td-efficacy')).toContainText('fresh concluded WAF checks');
    await expect(page.locator('.target-detail-view')).not.toContainText(/Sources agree/);

    await page.getByRole('tab', { name: /Validate/ }).click();
    const panel = page.locator('.td-checks');
    await expect(panel.getByRole('button', { name: /^Gap found/ })).toBeVisible();
    await panel.getByRole('button', { name: /^Gap found/ }).click();
    const gapRow = panel.locator('.td-check[data-status="failed"]');
    await expect(gapRow).toHaveCount(1);
    await gapRow.locator('.td-check-summary').click();
    await expect(gapRow).toContainText('How it works');
    await expect(gapRow).toContainText('Upper bound');
    await expect(gapRow).toContainText('HTTP 200');
    await expect(gapRow).toContainText('the edge did not block this scenario');
    await expect(page).toHaveURL(/check=waf\.crlf_injection_marker\.safe/);
    await gapRow.getByRole('button', { name: 'View evidence' }).click();
    await expect(page.locator('.inspector-panel').getByRole('heading', { name: 'Check result' })).toBeVisible();
    await expect(page.locator('.inspector-panel')).not.toContainText(/wafw00f|cdncheck/i);
    await expect(page.locator('.target-detail-view')).not.toContainText(/wafw00f|cdncheck/i);
    await expect(page).toHaveURL(/inspect=check_result&ev_target=tgt_checkout_2&ev_check=waf\.crlf_injection_marker\.safe&ev_run=run_fx_1/);
    await page.keyboard.press('Escape');
    await panel.getByRole('button', { name: /^All/ }).click();
    await expect(panel.locator('.td-cat').filter({ hasText: 'Origin exposure' })).toBeVisible();

    expect(edgePosts, 'an existing detection is never re-queued automatically').toEqual([]);
    await expectNoBlockingAxeViolations(page, '.target-detail-view');
  });

  test('current inconclusive and unfinished checks are not mislabeled as invalid retained results', async ({ page }) => {
    await page.route(`**/v1/targets/${VERIFIED_FRESH_TARGET}`, async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      await route.fulfill({ response, json: { ...payload, coverage: {
        ...payload.coverage,
        evaluated_count: 1, inconclusive_count: 1, partial_count: 0, unknown_count: 1,
        pairs: [
          { check_id: 'waf.fingerprint.safe', state: 'inconclusive', live_external: false, retained: { verdict: 'inconclusive', provenance: 'external' } },
          { check_id: 'waf.marker_rule.safe', state: 'unknown', live_external: false, retained: { verdict: null, run_status: 'collecting' } },
        ],
      } } });
    });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': VERIFIED_FRESH_TARGET } });
    await expect(page.locator('.td-coverage')).toBeVisible();
    await expect(page.locator('.td-retained')).toHaveCount(0);
    await expect(page.locator('.td-count-grid')).toContainText('Inconclusive');
  });

  test('coverage explains inconclusive comparisons and separates transport observations across themes and widths', async ({ page }) => {
    await page.route(`**/v1/targets/${VERIFIED_FRESH_TARGET}`, async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      await route.fulfill({ response, json: { ...payload, coverage: {
        ...payload.coverage, observation_only_count: 35,
        inconclusive_reasons: [{ reason: 'baseline_comparison_unavailable', label: 'Blocking comparison unavailable', count: 40, check_ids: ['waf.evasion_base64_wrap.safe'], next_step: 'Review the baseline marker evidence and configure a rule that blocks that harmless marker, then rerun the comparison.' }],
      } } });
    });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': VERIFIED_FRESH_TARGET } });
    for (const theme of ['light', 'dark']) {
      await page.evaluate(value => document.documentElement.setAttribute('data-theme', value), theme);
      for (const width of [375, 1440]) {
        await page.setViewportSize({ width, height: 950 });
        const coverage = page.locator('.td-coverage');
        await expect(coverage).toContainText('35 runnable checks are observations only; they run under Validate but are not scored for readiness.');
        await expect(coverage).toContainText(/Catalog \d+ · Runnable on this target \d+ · Scored for readiness \d+/);
        await expect(coverage.locator('.td-coverage-figure')).toHaveCount(0);
        await expect(coverage).toContainText('40 · Blocking comparison unavailable');
        await expect(coverage).toContainText('configure a rule that blocks that harmless marker');
        await expectNoBlockingAxeViolations(page, '.td-coverage');
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      }
    }
    await page.getByRole('button', { name: 'Review check evidence', exact: true }).click();
    await expect(page.getByRole('tab', { name: /Validate/ })).toHaveAttribute('aria-selected', 'true');
  });

  test('opening a verified domain is passive; manually requested detection starts only after review', async ({ page }) => {
    const edgePosts = [];
    page.on('request', (request) => {
      if (request.method() === 'POST' && request.url().includes('/v1/waf/edge-detection')) edgePosts.push(request.postDataJSON());
    });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': VERIFIED_FRESH_TARGET } });

    const observations = page.locator('.td-observations');
    await expect(observations).not.toContainText('Initial WAF/CDN detection is queued when this domain is added');
    await expect(page.locator('.td-last-check')).toHaveText(/^(Last check .+|No checks recorded yet)$/);
    await page.waitForTimeout(800);
    expect(edgePosts, 'opening a target never starts a probe').toEqual([]);

    await observations.getByRole('button', { name: 'Detect WAF and CDN' }).click();
    let dialog = page.locator('dialog.modal-confirm[open]');
    await expect(dialog).toContainText('One bounded fingerprint run against this exact target');
    await expect(dialog).toContainText('It identifies providers only');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    expect(edgePosts, 'cancelling the review sends nothing').toEqual([]);

    await observations.getByRole('button', { name: 'Detect WAF and CDN' }).click();
    dialog = page.locator('dialog.modal-confirm[open]');
    const acceptedResponse = page.waitForResponse((response) => response.request().method() === 'POST' && new URL(response.url()).pathname === '/v1/waf/edge-detection');
    await dialog.getByRole('button', { name: 'Start detection' }).click();
    const accepted = await (await acceptedResponse).json();
    await expect(page.locator('.inspector-panel .probe-activity-run')).toHaveText(accepted.detection_request.test_run_id);
    await page.locator('.inspector-panel').getByRole('button', { name: 'Close Check result' }).click();
    await expect.poll(() => edgePosts.length).toBe(1);
    expect(edgePosts[0]).toEqual({ target_id: VERIFIED_FRESH_TARGET });
    await expect(page.getByRole('tab', { name: /^Validate/ })).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('.probe-activity')).toBeVisible();
    await expect(page.locator('.td-check[data-selected="true"][data-focus-key="check-waf.fingerprint.safe"]')).toHaveCount(1);
    await expect(page.locator('input[name=target-run-check][value="waf.fingerprint.safe"]')).not.toBeChecked();
    await expect(page.locator('.td-checks')).toContainText('WAF and CDN Fingerprint (Safe)');
    await expect(page.getByText(/The linked check.*is not compatible/)).toHaveCount(0);
  });

  test('an unverified domain stays locked: no check, scan or detection can start until ownership is proven', async ({ page }) => {
    const posts = [];
    page.on('request', (request) => {
      if (request.method() === 'POST' && /\/v1\/(waf\/edge-detection|validation-scans|test-runs)/.test(request.url())) posts.push(request.url());
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': UNVERIFIED_TARGET } });

    const header = page.locator('.td-page-head');
    await expect(header).toContainText('Ownership pending · checks locked');
    await expect(header).not.toContainText('Validation unlocked');
    await expect(page.locator('.td-next[data-kind="ownership"]')).toContainText('Prove ownership to unlock validation');
    await expect(page.locator('.td-observations').getByRole('button', { name: 'Detect WAF and CDN' })).toHaveCount(0);

    await header.getByRole('button', { name: 'Prove ownership', exact: true }).click();
    const ownershipAction = page.locator('#td-ownership-panel').getByRole('button', { name: /^(Check now|Issue DNS TXT record|Issue a new record)$/ });
    await expect(ownershipAction).toBeFocused();
    await expect(ownershipAction).toBeInViewport();
    await page.setViewportSize({ width: 1440, height: 950 });

    await page.getByRole('tab', { name: /Validate/ }).click();
    const reviewAll = page.locator('.td-checks').getByRole('button', { name: /^Review all/ });
    await expect(reviewAll).toBeDisabled();
    await expect(page.locator('#td-run-all-reason')).toHaveText('Prove ownership first.');
    await expect(reviewAll).toHaveAttribute('aria-describedby', 'td-run-all-reason');
    const startBar = page.locator('.td-start-bar');
    await expect(startBar.getByRole('button', { name: /^Review and start/ })).toBeDisabled();
    await expect(startBar).toContainText('Prove ownership first. External checks stay blocked until this target is verified.');
    await startBar.getByRole('button', { name: 'Go to ownership step' }).click();
    await expect(page.locator('#td-validate-ownership').getByRole('button', { name: /^(Check now|Issue DNS TXT record|Issue a new record)$/ })).toBeFocused();
    await page.waitForTimeout(500);
    expect(posts, 'an unverified target never starts a probe').toEqual([]);
  });

  test('Review all waits while a single check holds the execution slot', async ({ page }) => {
    await page.route('**/v1/validation-scans?*', (route) => route.fulfill({ json: { items: [], count: 0, meta: {} } }));
    await page.route('**/v1/test-runs?*', async (route) => {
      if (new URL(route.request().url()).searchParams.get('target_id') !== VERIFIED_FRESH_TARGET) return route.fallback();
      await route.fulfill({ json: { items: [{ id: 'run_fx_slot', target_id: VERIFIED_FRESH_TARGET, check_id: GRADED_PASS_CHECK, status: 'running', created_at: '2030-01-01T00:00:00.000Z' }], count: 1, meta: {} } });
    });
    await page.route('**/v1/test-runs/run_fx_slot/activity?*', (route) => route.fulfill({ json: { run_id: 'run_fx_slot', target_id: VERIFIED_FRESH_TARGET, check_id: GRADED_PASS_CHECK, status: 'running', items: [], count: 0 } }));
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': VERIFIED_FRESH_TARGET } });
    await page.getByRole('tab', { name: /Validate/ }).click();
    const reviewAll = page.locator('.td-checks').getByRole('button', { name: /^Review all/ });
    await expect(reviewAll).toBeDisabled();
    await expect(page.locator('#td-run-all-reason')).toContainText('is running on this target. Wait for it to finish or stop it before starting all checks.');
    await expect(page.locator('.td-scan-terminal')).toHaveCount(0);
  });

  test('a completed scan leaves no stale console, and a later single check does not reopen it', async ({ page }) => {
    let runs = [];
    await page.route('**/v1/validation-scans?*', (route) => route.fulfill({ json: { items: [completedScan(VERIFIED_FRESH_TARGET)], count: 1, meta: {} } }));
    await page.route('**/v1/test-runs?*', async (route) => {
      if (new URL(route.request().url()).searchParams.get('target_id') !== VERIFIED_FRESH_TARGET) return route.fallback();
      await route.fulfill({ json: { items: runs, count: runs.length, meta: {} } });
    });
    await page.route('**/v1/test-runs', async (route) => {
      if (route.request().method() !== 'POST') return route.fallback();
      runs = [{ id: 'run_fx_single', target_id: VERIFIED_FRESH_TARGET, check_id: 'l7.cors_posture.safe', status: 'running', created_at: '2030-01-02T00:00:00.000Z' }];
      await route.fulfill({ status: 201, json: { run: runs[0], jobs_dispatched: 0 } });
    });
    await page.route('**/v1/test-runs/run_fx_single/activity?*', (route) => route.fulfill({ json: { run_id: 'run_fx_single', target_id: VERIFIED_FRESH_TARGET, check_id: 'l7.cors_posture.safe', status: 'running', items: [], count: 0 } }));
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': VERIFIED_FRESH_TARGET } });
    await page.getByRole('tab', { name: /Validate/ }).click();
    const panel = page.locator('.td-checks');
    await expect(panel.locator('.td-live-text')).toContainText('Last scan completed');
    await expect(page.locator('.td-scan-terminal')).toHaveCount(0);
    await expect(page.locator('.td-validate .probe-activity')).toHaveCount(0);
    await expect(page.locator('.td-start-bar')).toContainText('No check selected');

    await page.goto(`${getPortalPlaywrightBaseUrl()}/app#target-detail?id=${VERIFIED_FRESH_TARGET}&tab=validate&check=l7.cors_posture.safe`);
    await page.locator('.td-start-bar').getByRole('button', { name: 'Review and start', exact: true }).click();
    const dialog = page.locator('dialog.modal-confirm[open]');
    await expect(dialog).toContainText('Result type');
    await expect(dialog).toContainText('What your team will see');
    await expect(dialog).toContainText('Source addresses');
    await dialog.getByRole('button', { name: 'Start check', exact: true }).click();
    await expect(page).toHaveURL(/ev_run=run_fx_single/);
    await expect(page.locator('.td-scan-terminal')).toHaveCount(0);
  });

  test('a filtered selection starts exactly the selected checks, and category select-all stays in its category', async ({ page }) => {
    const scanBodies = [];
    await page.route('**/v1/validation-scans?*', (route) => route.fulfill({ json: { items: [completedScan(VERIFIED_FRESH_TARGET)], count: 1, meta: {} } }));
    await page.route('**/v1/validation-scans', async (route) => {
      if (route.request().method() !== 'POST') return route.fallback();
      scanBodies.push(route.request().postDataJSON());
      await route.fulfill({ status: 201, json: { id: 'scan_fx_selected', target_id: VERIFIED_FRESH_TARGET, status: 'running', steps: [] } });
    });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': VERIFIED_FRESH_TARGET } });
    await page.getByRole('tab', { name: /Validate/ }).click();
    const panel = page.locator('.td-checks');

    const category = panel.locator('.td-cat-shell').filter({ has: page.getByRole('checkbox', { name: 'Select all in DNS' }) });
    await category.getByRole('checkbox', { name: 'Select all in DNS' }).check();
    const categoryIds = await category.locator('input[name=target-run-check]').evaluateAll((inputs) => inputs.map((input) => input.value));
    expect(categoryIds.length).toBeGreaterThan(0);
    const checkedIds = await panel.locator('input[name=target-run-check]:checked').evaluateAll((inputs) => inputs.map((input) => input.value));
    expect(checkedIds.sort()).toEqual([...categoryIds].sort());
    await expect(page.locator('.td-start-bar')).toContainText(categoryIds.length > 1 ? `${categoryIds.length} checks selected` : '1 check selected');
    await page.locator('.td-start-bar').getByRole('button', { name: 'Clear', exact: true }).click();
    await expect(panel.locator('input[name=target-run-check]:checked')).toHaveCount(0);

    await panel.getByRole('button', { name: /^Not run/ }).click();
    const notRunIds = await panel.locator('.td-check[data-status="not_run"] input[name=target-run-check]:not([disabled])').evaluateAll((inputs) => inputs.map((input) => input.value));
    expect(notRunIds.length).toBeGreaterThan(1);
    await panel.getByRole('button', { name: `Select not run (${notRunIds.length})`, exact: true }).click();
    await page.locator('.td-start-bar').getByRole('button', { name: `Review and start ${notRunIds.length}`, exact: true }).click();
    const dialog = page.locator('dialog.modal-confirm[open]');
    await expect(dialog).toContainText(`Start ${notRunIds.length} selected checks on`);
    await expect(dialog).toContainText('one at a time inside your safe-run limits');
    await expect(dialog).toContainText('What your team will see');
    expect(scanBodies).toEqual([]);
    await dialog.getByRole('button', { name: `Start ${notRunIds.length} checks`, exact: true }).click();
    await expect.poll(() => scanBodies.length).toBe(1);
    expect(scanBodies[0].target_id).toBe(VERIFIED_FRESH_TARGET);
    expect([...scanBodies[0].check_ids].sort()).toEqual([...notRunIds].sort());
    expect(scanBodies[0].name).toMatch(/^Selected checks · /);
  });

  test('the header shows when this target was last checked', async ({ page }) => {
    await page.route(`**/v1/targets/${VERIFIED_FRESH_TARGET}`, async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      const target = { ...payload.target, last_validation_at: null, last_validated_at: null };
      await route.fulfill({ response, json: { ...payload, target } });
    });
    await page.route('**/v1/test-runs?*', async (route) => {
      if (new URL(route.request().url()).searchParams.get('target_id') !== VERIFIED_FRESH_TARGET) return route.fallback();
      await route.fulfill({ json: { items: [
        { id: 'run_fx_old', target_id: VERIFIED_FRESH_TARGET, check_id: GRADED_PASS_CHECK, status: 'completed', started_at: '2030-01-01T00:00:00.000Z' },
        { id: 'run_fx_new', target_id: VERIFIED_FRESH_TARGET, check_id: GRADED_GAP_CHECK, status: 'completed', created_at: '2031-06-01T00:00:00.000Z' },
      ], count: 2, meta: {} } });
    });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': VERIFIED_FRESH_TARGET } });
    const lastCheck = page.locator('.td-page-head .td-last-check');
    await expect(lastCheck).toContainText('Last check');
    await expect(lastCheck.locator('time')).toHaveAttribute('datetime', '2031-06-01T00:00:00.000Z');
    await expect(page.getByRole('link', { name: 'Back to targets' })).toHaveAttribute('href', '#targets');
  });

  test('review all confirms the plan, starts one scan for the exact domain, and shows live progress', async ({ page }) => {
    await page.route(`**/v1/targets/${PORTAL_BASELINE_IDS.targetId}`, async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      await route.fulfill({ response, json: { ...payload, edge_detection: EDGE_DETECTION, protection_profile: null } });
    });
    const scanBodies = [];
    page.on('request', (request) => {
      if (request.method() === 'POST' && request.url().endsWith('/v1/validation-scans')) scanBodies.push(request.postDataJSON());
    });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl());

    await page.getByRole('tab', { name: /Validate/ }).click();
    const panel = page.locator('.td-checks');
    const catalog = await page.request.get(`${getPortalPlaywrightBaseUrl()}/v1/checks?scope=all`, { headers: { 'x-tenant-id': PORTAL_BASELINE_IDS.tenantId, 'x-user-id': 'usr_owner', 'x-role': 'owner' } }).then((response) => response.json());
    await expect(panel).toContainText(`${catalog.items.length} checks in the catalog.`);
    await expect(panel).toContainText('runnable on this target, including observation checks');
    await expect(panel.locator('.td-catalog-requirements summary')).toContainText('catalog checks not runnable on this target · requirements');
    await panel.locator('.td-catalog-requirements summary').click();
    await expect(panel.locator('.td-catalog-requirements')).toContainText('origin.direct_bypass.safe');
    await expect(panel.locator('.td-catalog-requirements')).toContainText('Requires SOC approval');
    await expect(panel.locator('input[name=target-run-check][value="dns.authoritative_response.safe"]')).toHaveCount(1);
    await page.setViewportSize({ width: 375, height: 950 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.setViewportSize({ width: 1440, height: 950 });
    await panel.getByRole('button', { name: /^Review all/ }).click();
    const dialog = page.locator('dialog.modal-confirm[open]');
    await expect(dialog).toContainText(/Start \d+ checks on checkout\.acme\.com\?/);
    await expect(dialog).toContainText('one at a time inside your safe-run limits');
    await expect(dialog).toContainText('The server re-checks ownership');
    await expect(dialog).toContainText("holds this target's execution slot");
    await expect(dialog).toContainText('What your team will see');
    const acceptedResponse = page.waitForResponse((response) => response.request().method() === 'POST' && new URL(response.url()).pathname === '/v1/validation-scans');
    await dialog.getByRole('button', { name: 'Start all checks' }).click();
    const accepted = await (await acceptedResponse).json();
    await expect(page).toHaveURL(new RegExp(`ev_scan=${accepted.id}`));
    await expect(page.locator('.inspector-panel')).toContainText(accepted.id);
    await page.locator('.inspector-panel').getByRole('button', { name: /^Close / }).first().click();

    await expect.poll(() => scanBodies.length).toBe(1);
    const body = scanBodies[0];
    expect(body.target_group_id).toBeUndefined();
    expect(body.target_id).toBe(PORTAL_BASELINE_IDS.targetId);
    expect(body.check_ids).toContain('waf.fingerprint.safe');
    expect(body.check_ids[0]).toBe('waf.fingerprint.safe');
    expect(body.check_ids.length).toBeGreaterThan(112);
    expect(body.check_ids).toContain('dns.authoritative_response.safe');
    const headers = { 'x-tenant-id': PORTAL_BASELINE_IDS.tenantId, 'x-user-id': 'usr_owner', 'x-role': 'owner' };
    const selectable = await page.request.get(`${getPortalPlaywrightBaseUrl()}/v1/checks`, { headers }).then((response) => response.json());
    const target = await page.request.get(`${getPortalPlaywrightBaseUrl()}/v1/targets/${PORTAL_BASELINE_IDS.targetId}`, { headers }).then((response) => response.json());
    const targetCatalog = await page.request.get(`${getPortalPlaywrightBaseUrl()}/v1/checks?scope=all&target_id=${encodeURIComponent(PORTAL_BASELINE_IDS.targetId)}`, { headers }).then((response) => response.json());
    const expected = assessmentChecks(withTargetRunnableChecks(selectable.items, targetCatalog.items), target.target, {
      declarations: { version: 1 },
      perspectiveCount: 1,
      serverRunnableIndex: targetRunnableIndex(targetCatalog.items),
    });
    expect(body.check_ids).toEqual(expected.map((check) => check.check_id));
    expect(new Set(body.check_ids).size).toBe(body.check_ids.length);
    expect(accepted.steps.map((step) => step.check_id)).toEqual(body.check_ids);
    expect(new Set(accepted.steps.map((step) => step.target_id))).toEqual(new Set([PORTAL_BASELINE_IDS.targetId]));

    await expect(panel.locator('.td-live-text')).toContainText(/Running 1 of \d+: WAF and CDN Fingerprint/);
    await expect(panel.getByRole('button', { name: 'Stop scan' })).toBeVisible();
    await expect(page.locator('.td-scan-terminal')).toHaveCount(1);
    await expect(panel.locator('.td-check[data-status="running"]')).toHaveCount(1);

    await panel.getByRole('button', { name: 'Stop scan' }).click();
    const stop = page.locator('dialog.modal-confirm[open]');
    await stop.getByRole('button', { name: /Stop/ }).last().click();
    await expect(page.getByText('Scan stop requested. Queued checks cannot start; finished results are kept. Worker acknowledgment remains separate.')).toBeVisible();
    await expect(panel.getByRole('button', { name: /^Review all/ })).toBeVisible();
  });
});
