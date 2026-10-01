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
 * FT-DOMAIN-01 — target (domain) page: Run all checks, live per-check status, automatic WAF/CDN
 * detection with an evaluating state, the evidence behind it, and WAF/CDN efficacy.
 *
 * Runs against the real in-process dev-json backend. Only the verdict-bearing payloads that the
 * simulation runtime cannot produce (signed edge fingerprints, exposed/protected verdicts) are
 * layered onto real responses.
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

test.describe('domain page: run all checks and WAF/CDN efficacy (FT-DOMAIN-01)', () => {
  test.beforeEach(async () => {
    await startPortalPlaywrightServer();
  });

  test.afterEach(async () => {
    await stopPortalPlaywrightServer();
  });

  test('shows detected edge, how it was found, per-check status, and efficacy from verdicts', async ({ page }) => {
    await page.route(`**/v1/targets/${VERIFIED_FRESH_TARGET}`, async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      await route.fulfill({ response, json: { ...payload, edge_detection: EDGE_DETECTION } });
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

    const hero = page.locator('.td-edge-hero');
    await expect(hero.getByText('Edge detected')).toBeVisible();
    const waf = hero.locator('.td-shield').filter({ hasText: 'Web application firewall' });
    const cdn = hero.locator('.td-shield').filter({ hasText: 'CDN and edge network' });
    await expect(waf.getByText('Detected · Cloudflare')).toBeVisible();
    await expect(cdn.getByText('Detected · Cloudflare')).toBeVisible();
    // One WAF check reached the application: the WAF is only partly protecting.
    await expect(waf.locator('.td-shield-verdict')).toContainText('Partially protecting');
    await expect(waf).toContainText('Blocked 1 of 2 tested attack classes');
    await expect(waf.locator('.td-shield-gaps')).toContainText('WAF Marker Rule Posture');
    await expect(cdn.locator('.td-shield-verdict')).toContainText('Detected · not measured yet');

    await hero.locator('.td-evidence > summary').click();
    const evidence = hero.locator('.td-evidence-body');
    await expect(evidence.getByText('DNS CNAME')).toBeVisible();
    await expect(evidence.getByText('IP address range')).toBeVisible();
    await expect(evidence.getByText('WAF fingerprint')).toBeVisible();
    await expect(evidence).toContainText('pay.acme.com.cdn.cloudflare.net');
    await expect(evidence).toContainText('Cloudflare (Cloudflare Inc.)');

    const panel = page.locator('.td-checks');
    await expect(panel.getByRole('button', { name: /^Exposed/ })).toBeVisible();
    await panel.getByRole('button', { name: /^Exposed/ }).click();
    const exposedRow = panel.locator('.td-check[data-status="failed"]');
    await expect(exposedRow).toHaveCount(1);
    await exposedRow.locator('summary').click();
    await expect(exposedRow).toContainText('How it works');
    await expect(exposedRow).toContainText('What it sends');
    await expect(exposedRow).toContainText('HTTP 200');
    await expect(exposedRow).toContainText('the edge did not block traffic before origin');
    await expect(exposedRow.getByRole('link', { name: 'Open run evidence' })).toBeVisible();
    await panel.getByRole('button', { name: /^All/ }).click();
    await expect(panel.locator('.td-cat').filter({ hasText: 'Origin exposure' })).toBeVisible();

    expect(edgePosts, 'an existing detection is never re-queued automatically').toEqual([]);
    await expectNoBlockingAxeViolations(page, '.target-detail-view');
  });

  test('a freshly onboarded verified domain starts WAF/CDN detection immediately and shows Evaluating', async ({ page }) => {
    const edgePosts = [];
    page.on('request', (request) => {
      if (request.method() === 'POST' && request.url().includes('/v1/waf/edge-detection')) edgePosts.push(request.postDataJSON());
    });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': VERIFIED_FRESH_TARGET } });

    await expect.poll(() => edgePosts.length).toBe(1);
    expect(edgePosts[0]).toEqual({ target_group_id: PORTAL_BASELINE_IDS.targetGroupId, target_id: VERIFIED_FRESH_TARGET });
    const hero = page.locator('.td-edge-hero');
    await expect(hero.getByText('Evaluating', { exact: true })).toBeVisible();
    await expect(hero.locator('.td-evaluating').first()).toContainText('Evaluating with live fingerprint probes');
    // Run all waits for the detection run to finish rather than colliding with it.
    await expect(page.locator('.td-head-actions').getByRole('button', { name: 'Run all checks' })).toBeDisabled();
  });

  test('an unverified domain never probes: detection and Run all wait for ownership', async ({ page }) => {
    const posts = [];
    page.on('request', (request) => {
      if (request.method() === 'POST' && /\/v1\/(waf\/edge-detection|validation-scans|test-runs)/.test(request.url())) posts.push(request.url());
    });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': UNVERIFIED_TARGET } });

    const hero = page.locator('.td-edge-hero');
    await expect(hero.getByText('Waiting for ownership')).toBeVisible();
    await expect(hero).toContainText('Detection starts automatically as soon as ownership is proven');
    await expect(page.locator('.td-head-actions').getByRole('button', { name: 'Run all checks' })).toBeDisabled();
    await expect(page.locator('.td-checks')).toContainText('Prove ownership first');
    // The ownership ladder leads when the domain is not yet verified.
    const order = await page.evaluate(() => {
      const validate = [...document.querySelectorAll('.card-title')].findIndex((node) => node.textContent === 'Validate this target');
      const edge = [...document.querySelectorAll('.card-title')].findIndex((node) => node.textContent === 'Edge protection');
      return { validate, edge };
    });
    expect(order.validate).toBeLessThan(order.edge);
    await page.waitForTimeout(500);
    expect(posts).toEqual([]);
  });

  test('Run all checks confirms the plan, starts one scan for the exact domain, and shows live progress', async ({ page }) => {
    await page.route(`**/v1/targets/${PORTAL_BASELINE_IDS.targetId}`, async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      await route.fulfill({ response, json: { ...payload, edge_detection: EDGE_DETECTION } });
    });
    const scanBodies = [];
    page.on('request', (request) => {
      if (request.method() === 'POST' && request.url().endsWith('/v1/validation-scans')) scanBodies.push(request.postDataJSON());
    });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl());

    await page.locator('.td-head-actions').getByRole('button', { name: 'Run all checks' }).click();
    const dialog = page.locator('dialog.modal-confirm[open]');
    await expect(dialog).toContainText(/Run all \d+ checks on checkout\.acme\.com\?/);
    await expect(dialog).toContainText('WAF/CDN detection and origin exposure run first');
    await expect(dialog).toContainText('declaration-only checks are skipped');
    await dialog.getByRole('button', { name: 'Run all checks' }).click();

    await expect.poll(() => scanBodies.length).toBe(1);
    const body = scanBodies[0];
    expect(body.target_group_id).toBe(PORTAL_BASELINE_IDS.targetGroupId);
    expect(body.target_id).toBe(PORTAL_BASELINE_IDS.targetId);
    expect(body.check_ids[0]).toBe('waf.fingerprint.safe');
    expect(body.check_ids.length).toBeGreaterThan(50);

    const panel = page.locator('.td-checks');
    await expect(panel.locator('.td-live-text')).toContainText(/Running 1 of \d+: Outside-In WAF Scanner/);
    await expect(panel.getByRole('button', { name: 'Stop run' })).toBeVisible();
    await expect(panel.locator('.td-check[data-status="running"]')).toHaveCount(1);
    await expect(page.locator('.td-head-actions')).toContainText('Running all checks');

    await panel.getByRole('button', { name: 'Stop run' }).click();
    const stop = page.locator('dialog.modal-confirm[open]');
    await stop.getByRole('button', { name: /Stop/ }).last().click();
    await expect(page.getByText('Run all checks stopped. Finished results are kept.')).toBeVisible();
    await expect(page.locator('.td-head-actions').getByRole('button', { name: 'Run all checks' })).toBeVisible();
  });
});
