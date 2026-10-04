import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
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
    verdict: { verdict, confidence: 'external_only', explanation },
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
      verdictStep('waf.fingerprint.safe', 0, 'edge_protected', 'External probe was blocked at the edge.'),
      verdictStep('waf.marker_rule.safe', 1, 'edge_exposed', 'External probe reached the declared path; the edge did not block traffic before origin.'),
      verdictStep('origin.leak_scan.safe', 2, 'edge_protected', 'Origin was not reachable directly.'),
    ],
  };
}

async function expectNoBlockingAxeViolations(page, selector) {
  await waitForPortalRouteSettled(page);
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).include(selector).analyze();
  const blocking = results.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact ?? ''));
  expect(blocking.map((violation) => `${violation.id}: ${violation.help}`)).toEqual([]);
}

test.describe('target workspace: recorded attribution, checks and reviewed runs (FT-DOMAIN-01)', () => {
  test.beforeEach(async () => {
    await startPortalPlaywrightServer();
  });

  test.afterEach(async () => {
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
    await expect(observations.locator('.td-effectiveness')).toContainText('3 blocked');
    await expect(page.locator('.target-detail-view')).not.toContainText(/Partially protecting|Protecting|Sources agree/);

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
    await expect(gapRow).toContainText('the edge did not block traffic before origin');
    await expect(page).toHaveURL(/check=waf\.marker_rule\.safe/);
    await gapRow.getByRole('button', { name: 'View evidence' }).click();
    await expect(page.locator('.inspector-panel').getByRole('heading', { name: 'Check result' })).toBeVisible();
    await expect(page.locator('.inspector-panel')).not.toContainText(/wafw00f|cdncheck/i);
    await expect(page.locator('.target-detail-view')).not.toContainText(/wafw00f|cdncheck/i);
    await expect(page).toHaveURL(/inspect=check_result&ev_target=tgt_checkout_2&ev_check=waf\.marker_rule\.safe&ev_run=run_fx_1/);
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

  test('a freshly onboarded verified domain does not probe on load; detection starts only after review', async ({ page }) => {
    const edgePosts = [];
    page.on('request', (request) => {
      if (request.method() === 'POST' && request.url().includes('/v1/waf/edge-detection')) edgePosts.push(request.postDataJSON());
    });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': VERIFIED_FRESH_TARGET } });

    const observations = page.locator('.td-observations');
    await expect(observations).toContainText('It starts only when someone chooses Detect WAF and CDN');
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
    await dialog.getByRole('button', { name: 'Start detection' }).click();
    await expect.poll(() => edgePosts.length).toBe(1);
    expect(edgePosts[0]).toEqual({ target_group_id: PORTAL_BASELINE_IDS.targetGroupId, target_id: VERIFIED_FRESH_TARGET });
  });

  test('an unverified domain never probes: detection and runs wait for ownership', async ({ page }) => {
    const posts = [];
    page.on('request', (request) => {
      if (request.method() === 'POST' && /\/v1\/(waf\/edge-detection|validation-scans|test-runs)/.test(request.url())) posts.push(request.url());
    });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': UNVERIFIED_TARGET } });

    // The ownership step leads the overview when the domain is not yet verified.
    await expect(page.locator('.td-next[data-kind="ownership"]')).toContainText('Prove ownership to unlock validation');
    await expect(page.locator('.td-observations')).toContainText('Detection is available once ownership is proven');
    await expect(page.locator('.td-observations').getByRole('button', { name: /Detect/ })).toHaveCount(0);

    await page.getByRole('tab', { name: /Validate/ }).click();
    await expect(page.locator('.td-checks')).toContainText('Prove ownership first');
    await expect(page.locator('.td-checks').getByRole('button', { name: /^Review all/ })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Review and start' })).toBeDisabled();
    await page.waitForTimeout(500);
    expect(posts).toEqual([]);
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
    await panel.getByRole('button', { name: /^Review all/ }).click();
    const dialog = page.locator('dialog.modal-confirm[open]');
    await expect(dialog).toContainText(/Start \d+ checks on checkout\.acme\.com\?/);
    await expect(dialog).toContainText('one at a time inside your safe-run limits');
    await expect(dialog).toContainText('The server re-checks ownership');
    await dialog.getByRole('button', { name: 'Start all checks' }).click();

    await expect.poll(() => scanBodies.length).toBe(1);
    const body = scanBodies[0];
    expect(body.target_group_id).toBe(PORTAL_BASELINE_IDS.targetGroupId);
    expect(body.target_id).toBe(PORTAL_BASELINE_IDS.targetId);
    expect(body.check_ids[0]).toBe('waf.fingerprint.safe');
    expect(body.check_ids.length).toBeGreaterThan(50);

    await expect(panel.locator('.td-live-text')).toContainText(/Running 1 of \d+: Outside-In WAF Scanner/);
    await expect(panel.getByRole('button', { name: 'Stop run' })).toBeVisible();
    await expect(panel.locator('.td-check[data-status="running"]')).toHaveCount(1);

    await panel.getByRole('button', { name: 'Stop run' }).click();
    const stop = page.locator('dialog.modal-confirm[open]');
    await stop.getByRole('button', { name: /Stop/ }).last().click();
    await expect(page.getByText('Multi-check run stopped. Finished results are kept.')).toBeVisible();
    await expect(panel.getByRole('button', { name: /^Review all/ })).toBeVisible();
  });
});
