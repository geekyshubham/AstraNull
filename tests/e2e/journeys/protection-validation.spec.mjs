import { expect, test } from '@playwright/test';
import { assertPortalInitialLoad } from '../../helpers/portal-browser-failures.mjs';
import AxeBuilder from '@axe-core/playwright';
import { getPortalPlaywrightBaseUrl, startPortalPlaywrightServer, stopPortalPlaywrightServer, seedPortalPlaywrightStore } from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, injectPortalDevHeadersSession, PORTAL_SESSION, waitForPortalRouteSettled } from '../../helpers/portal-playwright-session.mjs';

// PV-07: protection-validation routes are an in-browser fake with the documented shapes; everything else is the real dev-json backend.

const TARGET = 'tgt_checkout_2';
const UNVERIFIED = 'tgt_checkout_4';
const LONG_HOST = 'legacy-partner-integration-endpoint-with-an-unusually-long-hostname-label.eu-west.partners.api.acme.example';
const NOW = Date.now();
const iso = (offsetMs) => new Date(NOW + offsetMs).toISOString();
const DAY = 86_400_000;
const DIGEST = 'a'.repeat(64);
const PATH_LIMITS = ['external_only', 'not_capacity_assurance', 'firewall_traversal_not_established', 'stacked_layer_attribution_not_established', 'marker_scope_only', 'untested_paths_not_covered'];
const FW_LIMITS = ['external_only', 'sampled_public_ingress_only', 'rule_table_equivalence_not_established', 'routing_nat_egress_east_west_not_established', 'not_capacity_assurance', 'appliance_traversal_not_established', 'transport_reachability_not_enforcement'];

const ref = (runId, targetId, checkId = 'waf.marker.sqli') => ({
  test_run_id: runId, check_id: checkId, check_version: '1.1.0', scenario_version: 's1', verdict_id: `verdict_${runId}`, evidence_ids: [`ev_${runId}`],
  target_id: targetId, observed_at: iso(-DAY), run_status: 'verdicted', finalized: true, source_perspective: 'public-worker-eu', worker_id: 'worker_eu_1',
});

const ENTRY_PATHS = [
  { id: 'ep_primary', anchor_target_id: TARGET, entry_target_id: TARGET, entry_target_value: 'pay.acme.com', relation_kind: 'primary_route', owner: 'Payments', purpose: 'Customer checkout', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf', 'cdn_edge'], origin_binding_id: null, status: 'active', declaration_version: 1, declaration_digest: DIGEST, currently_authorized: true, created_at: iso(-3 * DAY) },
  { id: 'ep_alt', anchor_target_id: TARGET, entry_target_id: 'tgt_checkout_3', entry_target_value: LONG_HOST, relation_kind: 'alternate_hostname', owner: 'Partner team', purpose: 'Legacy hostname kept for partner integrations', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'], origin_binding_id: null, status: 'active', declaration_version: 1, declaration_digest: DIGEST, currently_authorized: true, created_at: iso(-2 * DAY) },
  { id: 'ep_login', anchor_target_id: TARGET, entry_target_id: UNVERIFIED, entry_target_value: 'cdn.acme.com', relation_kind: 'declared_login_url', owner: 'Identity', purpose: 'Login page', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'], origin_binding_id: null, status: 'active', declaration_version: 1, declaration_digest: DIGEST, currently_authorized: false, created_at: iso(-2 * DAY) },
];

function layer(name, observed, extra = {}) {
  return {
    layer: name, declared_intent: extra.declared_intent ?? 'required', vendor_detection: 'unknown', observed_enforcement: observed,
    application_identity: extra.application_identity ?? 'not_tested', suspected_bypass: extra.suspected_bypass ?? 'unknown', confirmed_scoped_bypass: 'unknown',
    attribution: 'not_applicable', evidence_limitations: name === 'ddos' ? ['external_only', 'not_capacity_assurance'] : ['external_only'], evidence_refs: extra.refs ?? [], freshness: extra.freshness ?? null,
  };
}

const MATRIX = {
  target_id: TARGET, contract_version: 'protection-validation-v1', generated_at: iso(0), connectors_required: false, limitations: ['external_only', 'not_capacity_assurance'],
  paths: [
    { entry_path_id: 'ep_primary', entry_target_id: TARGET, entry_target_value: 'pay.acme.com', relation_kind: 'primary_route', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf', 'cdn_edge'], status: 'active', outcome: 'consistent_enforcement', attribution: 'unattributed',
      layers: [layer('waf', 'enforced', { refs: [ref('run_primary', TARGET)] }), layer('cdn_edge', 'not_tested'), layer('network_firewall', 'not_tested', { declared_intent: 'not_required' }), layer('ddos', 'not_tested', { declared_intent: 'not_required' })],
      evidence_refs: [ref('run_primary', TARGET)], freshness: { fresh: true, expires_at: iso(20 * DAY) }, limitations: PATH_LIMITS },
    { entry_path_id: 'ep_alt', entry_target_id: 'tgt_checkout_3', entry_target_value: LONG_HOST, relation_kind: 'alternate_hostname', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'], status: 'active', outcome: 'suspected_alternate_application_route', attribution: 'unattributed', observation: 'response_observed',
      layers: [layer('waf', 'not_enforced', { refs: [ref('run_alt', 'tgt_checkout_3')], application_identity: 'suspected', suspected_bypass: 'suspected' }), layer('cdn_edge', 'not_tested', { declared_intent: 'not_required' }), layer('network_firewall', 'not_tested', { declared_intent: 'not_required' }), layer('ddos', 'not_tested', { declared_intent: 'not_required' })],
      evidence_refs: [ref('run_alt', 'tgt_checkout_3')], freshness: { fresh: false, expires_at: iso(-DAY) }, limitations: PATH_LIMITS },
    { entry_path_id: 'ep_login', entry_target_id: UNVERIFIED, entry_target_value: 'cdn.acme.com', relation_kind: 'declared_login_url', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'], status: 'active', outcome: 'inconclusive', attribution: 'unattributed', observation: 'no_response',
      layers: [layer('waf', 'inconclusive'), layer('cdn_edge', 'not_tested', { declared_intent: 'not_required' }), layer('network_firewall', 'not_tested', { declared_intent: 'not_required' }), layer('ddos', 'not_tested', { declared_intent: 'not_required' })],
      evidence_refs: [], freshness: null, limitations: PATH_LIMITS },
  ],
};

const PLAN = {
  mode: 'plan', plan_digest: 'b'.repeat(64), anchor_target_id: TARGET, primary_entry_path_id: 'ep_primary',
  expectation: { id: 'pvx_1', scenario: 'waf.sqli.marker', layer_outcomes: { waf: 'enforce' }, expectation_version: 1, digest: DIGEST },
  items: [
    { entry_path_id: 'ep_primary', target_id: TARGET, declaration_digest: DIGEST, check_id: 'waf.marker_rule.safe', check_version: '1.1.0', origin_binding_id: null, eligible: true, ineligible_reason: null },
    { entry_path_id: 'ep_alt', target_id: 'tgt_checkout_3', declaration_digest: DIGEST, check_id: 'waf.marker_rule.safe', check_version: '1.1.0', origin_binding_id: null, eligible: true, ineligible_reason: null },
    { entry_path_id: 'ep_login', target_id: UNVERIFIED, declaration_digest: DIGEST, check_id: 'waf.marker_rule.safe', check_version: '1.1.0', origin_binding_id: null, eligible: false, ineligible_reason: 'ownership_not_verified' },
  ],
  expectation_conflicts: [], limitations: PATH_LIMITS,
};

const EXPECTATIONS = [
  { id: 'fwx_1', kind: 'firewall_change', destination_target_id: TARGET, protocol: 'tcp', port: 443, service_endpoint: null, expected: 'allow', source_perspective: 'public-worker-eu', change_id: 'CHG-1001', owner: 'Network Team', pre_post_mapping: null, status: 'active', expectation_version: 1, digest: DIGEST, created_at: iso(-5 * DAY) },
  { id: 'fwx_2', kind: 'firewall_change', destination_target_id: TARGET, protocol: 'udp', port: 53, service_endpoint: null, expected: 'deny', source_perspective: 'public-worker-eu', change_id: 'CHG-1001', owner: 'Network Team', pre_post_mapping: null, status: 'active', expectation_version: 1, digest: DIGEST, created_at: iso(-5 * DAY) },
];

const BASELINES = [
  { id: 'fwb_1', kind: 'firewall_change', change_id: 'CHG-1001', captured_at: iso(-2 * DAY), freshness_window_seconds: 2_592_000, immutable: true, baseline_digest: DIGEST, status: 'active',
    entries: [{ kind: 'firewall_change', expectation_id: 'fwx_1', expectation_version: 1, target_id: TARGET, references: [ref('run_pre_1', TARGET, 'net.tcp.reachability')], captured_at: iso(-2 * DAY) }] },
  { id: 'fwb_old', kind: 'firewall_change', change_id: 'CHG-1001', captured_at: iso(-200 * DAY), freshness_window_seconds: 3600, immutable: true, baseline_digest: 'c'.repeat(64), status: 'active', entries: [] },
];

const COMPARISON = {
  id: 'fwc_1', kind: 'firewall_change', baseline_id: 'fwb_1', baseline_digest: DIGEST,
  compatibility: { comparable: false, stale: false, reasons: ['source_mismatch'] },
  items: [
    { expectation_id: 'fwx_1', status: 'regression', gap_kind: 'required_service_newly_unavailable', expectation_met: false, pre_state: 'satisfied', post_state: 'not_observed', reasons: [], compatibility_reasons: [], evidence_refs: [ref('run_post_1', TARGET, 'net.tcp.reachability')], limitations: FW_LIMITS },
    { expectation_id: 'fwx_2', status: 'not_comparable', gap_kind: null, expectation_met: null, pre_state: 'unverified', post_state: 'unverified', reasons: [], compatibility_reasons: ['source_mismatch'], evidence_refs: [], limitations: FW_LIMITS },
  ],
  summary: { total: 2, evaluated: 2, by_status: { regression: 1, not_comparable: 1 }, gaps: { required_service_newly_unavailable: 1 }, accepted: false },
  limitations: FW_LIMITS, evaluated_at: iso(-DAY), evaluation_digest: DIGEST,
};

const RUNS = [
  { id: 'run_pre_1', target_id: TARGET, check_id: 'net.tcp.reachability', status: 'verdicted', created_at: iso(-3 * DAY), completed_at: iso(-3 * DAY) },
  { id: 'run_post_1', target_id: TARGET, check_id: 'net.tcp.reachability', status: 'verdicted', created_at: iso(-DAY), completed_at: iso(-DAY) },
  { id: 'run_live', target_id: TARGET, check_id: 'net.tcp.reachability', status: 'running', created_at: iso(-60_000) },
];

const PV_PATH = /^\/v1\/(targets\/[^/]+\/(entry-paths|protection-validation)|entry-paths\/|entry-path-comparisons|firewall-)/;

async function installFake(page, options = {}) {
  const calls = [];
  const state = { comparison: null, cancels: [], retests: [], evaluateConflict: options.evaluateConflict ?? false };
  const firewallComparison = options.retestTarget ? { ...COMPARISON, items: COMPARISON.items.map((item) => ({ ...item, evidence_refs: item.evidence_refs.map((ref) => ({ ...ref, target_id: options.retestTarget })) })) } : COMPARISON;
  await page.route('**/v1/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    const pathname = url.pathname;
    const body = method === 'POST' ? request.postDataJSON() : null;
    if (PV_PATH.test(pathname)) calls.push({ method, pathname, body });

    if (method === 'GET' && pathname === '/v1/targets' && url.searchParams.get('unit') === 'target') {
      const cursor = url.searchParams.get('cursor');
      const items = cursor
        ? [{ id: UNVERIFIED, value: 'cdn.acme.com', kind: 'fqdn', verification_state: 'pending' }]
        : [{ id: 'tgt_checkout_3', value: 'api.acme.com', kind: 'fqdn', verification_state: 'dns_verified' }, { id: 'tgt_checkout_1', value: 'www.acme.com', kind: 'fqdn', verification_state: 'dns_verified' }];
      return route.fulfill({ json: { items, count: items.length, page: { items, count: items.length, next_cursor: cursor ? null : 'cur_2', limit: 25 } } });
    }
    if (method === 'GET' && pathname === '/v1/test-runs' && url.searchParams.get('target_id') === TARGET && url.searchParams.get('limit') === '100') {
      return route.fulfill({ json: { items: RUNS, count: RUNS.length, meta: {} } });
    }
    if (method === 'POST' && /^\/v1\/test-runs\/[^/]+\/cancel$/.test(pathname)) {
      state.cancels.push(pathname.split('/')[3]);
      return route.fulfill({ json: { id: pathname.split('/')[3], status: 'cancelled' } });
    }
    if (method === 'POST' && pathname === '/v1/test-runs') {
      state.retests.push(body);
      return route.fulfill({ status: 201, json: options.retestResponse ?? { run: { id: 'run_retest_1', ...body, status: 'running' }, jobs_dispatched: 0 } });
    }
    if (!PV_PATH.test(pathname)) return route.continue();

    if (options.failure === 'unsupported') return route.fulfill({ status: 404, json: { error: 'not_found' } });
    if (options.failure === 'forbidden') return route.fulfill({ status: 403, json: { error: 'forbidden' } });
    if (options.failure === 'transport') return route.abort('failed');

    if (pathname === `/v1/targets/${TARGET}/entry-paths` || pathname === `/v1/targets/${UNVERIFIED}/entry-paths`) {
      if (method === 'POST') return route.fulfill({ status: 201, json: { ...ENTRY_PATHS[1], id: 'ep_new', entry_target_id: body.entry_target_id, relation_kind: body.relation_kind } });
      const items = pathname.includes(UNVERIFIED) ? [] : ENTRY_PATHS.map((item) => options.driftedPathsAfterStart && state.comparison && item.id === 'ep_alt' ? { ...item, entry_target_id: 'tgt_current_metadata_drift' } : item);
      return route.fulfill({ json: { items, count: items.length, next_cursor: null } });
    }
    if (pathname.endsWith('/protection-validation')) return route.fulfill({ json: pathname.includes(UNVERIFIED) ? { ...MATRIX, target_id: UNVERIFIED, paths: [] } : MATRIX });
    if (pathname === '/v1/entry-path-comparisons' && method === 'POST') {
      if (body.mode === 'plan') return route.fulfill({ json: PLAN });
      state.comparison = { id: 'epc_1', status: 'running', plan_digest: body.reviewed_plan_digest, anchor_target_id: TARGET, primary_entry_path_id: 'ep_primary', expectation: PLAN.expectation,
        items: [{ entry_path_id: 'ep_primary', test_run_id: 'run_cmp_primary', outcome: 'consistent_enforcement', evidence_refs: [ref('run_cmp_primary', TARGET)], reasons: [], compatibility_reasons: [], limitations: PATH_LIMITS },
          { entry_path_id: 'ep_alt', test_run_id: 'run_cmp_alt', outcome: 'not_tested', evidence_refs: [], reasons: [], compatibility_reasons: [], limitations: PATH_LIMITS },
          { entry_path_id: 'ep_login', test_run_id: null, outcome: 'skipped', evidence_refs: [], reasons: ['ownership_not_verified'], compatibility_reasons: [], limitations: PATH_LIMITS }],
        compatibility: null, summary: { total: 3, evaluated: 1, by_status: {}, gaps: {}, accepted: false }, evaluated_at: null, created_at: iso(0) };
      if (options.noChildIds) state.comparison.items = state.comparison.items.map((item) => ({ ...item, test_run_id: null }));
      if (options.noComparisonId) state.comparison.id = '';
      return route.fulfill({ status: 202, json: state.comparison });
    }
    if (pathname === '/v1/entry-path-comparisons') return route.fulfill({ json: { items: state.comparison ? [state.comparison] : [], count: state.comparison ? 1 : 0, next_cursor: null } });
    if (pathname === '/v1/entry-path-comparisons/epc_1') {
      const current = state.comparison && state.cancels.length ? { ...state.comparison, status: 'cancelled' } : state.comparison;
      return current ? route.fulfill({ json: current }) : route.fulfill({ status: 404, json: { error: 'not_found' } });
    }
    if (pathname === '/v1/firewall-expectations' && method === 'GET') {
      const items = url.searchParams.get('destination_target_id') === TARGET ? EXPECTATIONS : [];
      return route.fulfill({ json: { items, count: items.length, next_cursor: null } });
    }
    if (pathname === '/v1/firewall-expectations' && method === 'POST') return route.fulfill({ status: 201, json: { ...EXPECTATIONS[0], ...body, id: 'fwx_new' } });
    if (pathname === '/v1/firewall-baselines' && method === 'GET') return route.fulfill({ json: { items: BASELINES, count: BASELINES.length, next_cursor: null } });
    if (pathname === '/v1/firewall-baselines' && method === 'POST') return route.fulfill({ status: 201, json: { ...BASELINES[0], id: 'fwb_new' } });
    if (pathname === '/v1/firewall-comparisons' && method === 'GET') {
      const items = url.searchParams.get('baseline_id') === 'fwb_1' ? [firewallComparison] : [];
      return route.fulfill({ json: { items, count: items.length, next_cursor: null } });
    }
    if (pathname === '/v1/firewall-comparisons' && method === 'POST') {
      if (state.evaluateConflict) return route.fulfill({ status: 409, json: { error: 'baseline_not_comparable', message: 'not comparable' } });
      return route.fulfill({ status: 201, json: COMPARISON });
    }
    if (pathname === '/v1/firewall-comparisons/fwc_1') return route.fulfill({ json: firewallComparison });
    return route.fulfill({ status: 404, json: { error: 'not_found' } });
  });
  return { calls, state, writes: () => calls.filter((call) => call.method === 'POST') };
}

async function openTarget(page, { role = 'owner', target = TARGET, tab } = {}) {
  await injectPortalDevHeadersSession(page, { ...PORTAL_SESSION, role });
  await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': target } });
  if (tab) await page.getByRole('tab', { name: tab }).click();
  else await openSetupFold(page);
}

async function openSetupFold(page) {
  const fold = page.locator('details.td-fold', { has: page.locator(':scope > summary', { hasText: 'Setup' }) });
  await fold.waitFor({ state: 'attached' });
  if (!(await fold.evaluate((node) => node.open))) await fold.locator(':scope > summary').click();
}

async function expectNoBlockingAxe(page, selector) {
  await waitForPortalRouteSettled(page);
  const results = await new AxeBuilder({ page }).include(selector).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
  expect(results.violations.filter((item) => ['serious', 'critical'].includes(item.impact ?? '')).map((item) => `${item.id}: ${item.help}`)).toEqual([]);
}

test.describe('protection validation in the target workspace (PV-07)', () => {
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
  test.beforeEach(() => { test.setTimeout(90000); seedPortalPlaywrightStore(); });
  test.afterAll(async () => { await stopPortalPlaywrightServer(); });

  test('declared paths and per-layer evidence load passively, with scoped labels, partial and stale states', async ({ page }) => {
    const fake = await installFake(page);
    await openTarget(page);
    const section = page.locator('.td-entry-paths');
    await expect(section.getByRole('heading', { name: 'Declared entry paths' })).toBeVisible();
    await expect(section.locator('[data-entry-path-id="ep_alt"]')).toContainText(LONG_HOST);
    await expect(section.locator('[data-entry-path-id="ep_login"]')).toContainText('Ownership not current; checks on this path are skipped');
    await expect(section.locator('.pv-matrix')).toContainText('Allowed for this scenario');
    await expect(section.locator('.pv-matrix')).toContainText('Response observed');
    await expect(section.locator('.pv-matrix')).not.toContainText('Origin response observed');
    await expect(section.locator('.pv-matrix')).toContainText('No response; enforcement unverified');
    await expect(section).toContainText('Partial: 1 of 3 paths not conclusively tested');
    await expect(section.locator('.pv-matrix')).toContainText('Stale');
    await expect(section).toContainText('No connector required');
    await expect(page.locator('.target-detail-view')).not.toContainText(/all controls bypassed|ddos protected/i);

    await section.getByRole('button', { name: /^WAF on .*Allowed for this scenario/ }).click();
    const detail = section.locator('.pv-detail').first();
    await expect(detail.getByRole('heading', { level: 3 })).toBeFocused();
    await expect(detail).toContainText('Suspected; not confirmed');
    await expect(detail).toContainText('run run_alt');
    await expect(detail.getByRole('button', { name: 'Inspect evidence' })).toBeVisible();
    expect(fake.writes()).toEqual([]);

    const box = await section.locator('[data-entry-path-id="ep_alt"]').boundingBox();
    const viewport = page.viewportSize();
    expect(box && viewport ? box.x + box.width <= viewport.width + 1 : false).toBe(true);

    await page.reload({ waitUntil: 'networkidle' });
    await expect(page.locator('.td-entry-paths .pv-detail').first()).toContainText('run run_alt');
    expect(fake.writes()).toEqual([]);
  });

  test('matrix finding exclusions preserve unknown paths and configuration stays explanation-only and permission-gated', async ({ page }) => {
    const fake = await installFake(page);
    let redacted = false;
    const matrix = structuredClone(MATRIX);
    matrix.configuration_access = 'granted';
    matrix.paths[2].scenarios = [{ scenario: 'waf.http_method_policy_marker.safe', outcome: 'inconclusive', ignored_for_findings: true, compatibility_reasons: ['source_mismatch'], reasons: [], evidence_refs: [] }];
    matrix.paths[2].layers[0].configuration = { evidence_role: 'explanation_only', status: 'configuration_evidence_available', record_count: null, coverage: 'monitor_only', provider_labels: ['PRIVATE_CONFIGURATION_LABEL'], markers: ['stale_snapshot', 'incomplete_inventory', 'ambiguous_ordering'] };
    await page.route(`**/v1/targets/${TARGET}/protection-validation`, (route) => route.fulfill({ json: { ...matrix, configuration_access: redacted ? 'redacted' : 'granted' } }));
    await openTarget(page);
    const section = page.locator('.td-entry-paths');
    await expect(section.locator('.pv-matrix tbody tr')).toHaveCount(3);
    await expect(section.locator('.pv-matrix')).toContainText('Inconclusive');
    await section.getByRole('button', { name: /^WAF on cdn.acme.com: Inconclusive/ }).click();
    const detail = section.locator('.pv-detail').first();
    await expect(detail).toContainText('Excluded from findings');
    await expect(detail).toContainText(/source/i);
    await expect(detail).toContainText('This path stays visible in unknown or not-tested coverage');
    const context = detail.getByRole('region', { name: 'Optional configuration context' });
    await expect(context).toContainText('explanation only');
    await expect(context).toContainText('Monitor only');
    await expect(context).toContainText('Snapshot recordsNot reported');
    await expect(context).toContainText('Stale snapshot');
    await expect(context).toContainText('Ambiguous ordering');
    await expect(context).toContainText('PRIVATE_CONFIGURATION_LABEL');
    await expect(section.locator('.pv-matrix')).toContainText('Inconclusive');
    redacted = true;
    await page.reload({ waitUntil: 'networkidle' });
    await expect(section.locator('.pv-detail')).toContainText('Your role cannot read connector configuration.');
    await expect(section).not.toContainText('PRIVATE_CONFIGURATION_LABEL');
    expect(fake.writes()).toEqual([]);
  });

  test('passive protection report exposes ignored conclusions and not-tested coverage without certifying retained results', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    const writes = [];
    const reads = [];
    page.on('request', (request) => { if (request.method() !== 'GET') writes.push(request.url()); });
    const report = {
      report_kind: 'protection_validation', tenant_id: PORTAL_SESSION.tenant_id, generated_at: iso(0),
      passive: true, executes_checks: false, sends_notifications: false, scope: { source_records_complete: false },
      conclusions_total: 5, conclusions_truncated: true,
      unknowns: { statement: 'Unknown and not-tested evidence does not create findings or count as validated.', by_reason: { evidence_not_finalized: 2 } },
      incomplete_scope: { reasons: ['source_records_truncated', 'entry_paths_not_tested'], not_tested_paths: { ids: ['ep_untested'], total: 4, truncated: true }, untested_firewall_expectations: { ids: ['fwx_untested'], total: 1, truncated: false } },
      conclusions: [
        { id: 'pvc_missing', subject: { entry_path_id: 'ep_missing' }, comparison_kind: 'path_validation', scenario: 'waf.http_method_policy_marker.safe', result: 'inconclusive', ignored_for_findings: true, reasons: [], compatibility_reasons: ['source_mismatch'], evidence_refs: [], readiness_eligible: false, readiness_exclusion_reason: 'no_evidence', current_assurance: { status: 'not_established', reasons: ['no_evidence'] } },
        { id: 'pvc_retained', subject: { entry_path_id: 'ep_retained' }, comparison_kind: 'path_validation', scenario: 'waf.http_method_policy_marker.safe', result: 'consistent_enforcement', ignored_for_findings: false, reasons: [], compatibility_reasons: [], evidence_refs: [ref('run_primary', TARGET)], readiness_eligible: false, readiness_exclusion_reason: 'current_scope_changed', current_assurance: { status: 'not_established', reasons: ['current_scope_changed'] } },
      ],
    };
    await page.route('**/v1/reports/protection-validation', (route) => { reads.push(route.request().method()); return route.fulfill({ json: report }); });
    await gotoPortalRoute(page, 'reports', getPortalPlaywrightBaseUrl());
    const panel = page.getByRole('region', { name: 'Current protection validation report' });
    await expect(panel).toContainText('Partial view');
    await expect(panel.locator('tbody tr')).toHaveCount(2);
    await expect(panel.locator('[data-conclusion-id="pvc_missing"]')).toContainText('Excluded from findings');
    await expect(panel.locator('[data-conclusion-id="pvc_missing"]')).toContainText(/source/i);
    await expect(panel.locator('[data-conclusion-id="pvc_retained"]')).toContainText('Not established');
    await expect(panel).toContainText('ep_untested');
    await expect(panel).toContainText('partial identifiers; 4 total');
    await expect(panel).toContainText('fwx_untested');
    await expect(panel).toContainText('Showing 2 of 5 conclusions');
    for (const [width, theme] of [[375, 'dark'], [1440, 'light']]) {
      await page.setViewportSize({ width, height: 950 });
      await page.evaluate((value) => document.documentElement.setAttribute('data-theme', value), theme);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
      const result = await new AxeBuilder({ page }).include('.protection-validation-report').withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
      expect(result.violations.filter((item) => ['serious', 'critical'].includes(item.impact ?? '')).map((item) => item.id)).toEqual([]);
    }
    await panel.getByRole('button', { name: 'Refresh current coverage' }).click();
    await expect(panel.locator('tbody tr')).toHaveCount(2);
    expect(reads.length).toBeGreaterThan(1);
    expect(reads.every((method) => method === 'GET')).toBe(true);
    expect(writes).toEqual([]);
  });

  test('protection coverage without declared scope says why and links to declaring an entry path', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await page.route('**/v1/reports/protection-validation', (route) => route.fulfill({ json: {
      report_kind: 'protection_validation', tenant_id: PORTAL_SESSION.tenant_id, generated_at: iso(0),
      passive: true, executes_checks: false, sends_notifications: false, scope: { source_records_complete: true },
      incomplete_scope: { reasons: ['no_declared_scope'], not_tested_paths: { ids: [], total: 0, truncated: false }, untested_firewall_expectations: { ids: [], total: 0, truncated: false } },
      conclusions: [],
    } }));
    await gotoPortalRoute(page, 'reports', getPortalPlaywrightBaseUrl());
    const panel = page.getByRole('region', { name: 'Current protection validation report' });
    await expect(panel).toContainText('Protection coverage from recorded comparisons');
    await expect(panel).toContainText('No entry paths or firewall expectations are declared yet, so there is nothing to compare.');
    await expect(panel.getByRole('link', { name: 'Declare an entry path on a target' })).toHaveAttribute('href', '#targets');
    await expect(panel).toContainText('No comparison conclusions are recorded yet.');
    await expect(panel).not.toContainText('not hidden');
    await expect(panel).not.toContainText('Incomplete coverage');
  });

  test('passive report revocation clears previously read conclusions and exposes the permission state', async ({ page }) => {
    await injectPortalDevHeadersSession(page, { ...PORTAL_SESSION, role: 'viewer', user_id: 'usr_viewer' });
    let denied = false;
    await page.route('**/v1/reports/protection-validation', (route) => route.fulfill(denied
      ? { status: 403, json: { error: 'forbidden' } }
      : { json: { tenant_id: PORTAL_SESSION.tenant_id, generated_at: iso(0), scope: { source_records_complete: true }, conclusions: [{ id: 'pvc_private', subject: { entry_path_id: 'ep_previous' }, result: 'not_tested', ignored_for_findings: true }] } }));
    await gotoPortalRoute(page, 'reports', getPortalPlaywrightBaseUrl());
    const panel = page.getByRole('region', { name: 'Current protection validation report' });
    await expect(panel).toContainText('ep_previous');
    denied = true;
    await panel.getByRole('button', { name: 'Refresh current coverage' }).click();
    await expect(panel).toContainText('Your role cannot read');
    await expect(panel).not.toContainText('ep_previous');
    await expect(page.getByRole('button', { name: 'Generate report', exact: true })).toHaveCount(0);
  });

  test('declares an entry path from paged existing targets after an explicit review', async ({ page }) => {
    const fake = await installFake(page);
    await openTarget(page);
    const section = page.locator('.td-entry-paths');
    await section.getByRole('button', { name: 'Declare entry path' }).first().click();
    const form = section.locator('form.pv-form');
    await expect(form.getByRole('heading', { name: 'Declare an entry path' })).toBeFocused();
    await form.getByRole('button', { name: 'Review declaration' }).click();
    await expect(form).toContainText('Choose how this path relates to the application.');
    await form.getByLabel('Relation').selectOption('alternate_hostname');
    await expect(form.getByRole('radio')).toHaveCount(2);
    await form.getByRole('button', { name: 'Load more targets' }).click();
    await expect(form.getByRole('radio')).toHaveCount(3);
    await expect(form).toContainText('All matching declared targets are shown.');
    await form.getByRole('radio', { name: /api\.acme\.com/ }).check();
    await form.getByLabel('Expected behavior').selectOption('must_be_protected_by_layers');
    await form.getByRole('checkbox', { name: 'WAF' }).check();
    await form.getByLabel('Owner').fill('Partner team');
    await form.getByLabel('Purpose').fill('Legacy hostname kept for partner integrations');
    await form.getByRole('button', { name: 'Review declaration' }).click();
    expect(fake.writes()).toEqual([]);
    const dialog = page.getByRole('dialog', { name: 'Record this entry path?' });
    await expect(dialog).toContainText('It sends no traffic');
    await dialog.getByRole('button', { name: 'Record entry path' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Entry path declared and audited' })).toBeVisible();
    const [write] = fake.writes();
    expect(write.pathname).toBe(`/v1/targets/${TARGET}/entry-paths`);
    expect(write.body).toEqual({ entry_target_id: 'tgt_checkout_3', relation_kind: 'alternate_hostname', owner: 'Partner team', purpose: 'Legacy hostname kept for partner integrations', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'], origin_binding_id: null });
  });

  test('discards a late pagination response after the target search changes without an unhandled rejection', async ({ page }) => {
    await page.addInitScript(() => {
      window.__pickerUnhandledRejections = [];
      window.addEventListener('unhandledrejection', (event) => {
        window.__pickerUnhandledRejections.push(String(event.reason?.message ?? event.reason));
      });
    });
    await installFake(page);
    let releasePage;
    const held = new Promise((resolve) => { releasePage = resolve; });
    let requestedPage;
    const requested = new Promise((resolve) => { requestedPage = resolve; });
    await page.route('**/v1/targets?**', async (route) => {
      const url = new URL(route.request().url());
      if (url.searchParams.get('unit') !== 'target') return route.fallback();
      if (url.searchParams.get('q') === 'fresh') return route.fulfill({ json: { items: [{ id: 'tgt_fresh', value: 'fresh.example.test', kind: 'fqdn', verification_state: 'dns_verified' }], next_cursor: null } });
      if (!url.searchParams.get('cursor')) return route.fallback();
      requestedPage();
      await held;
      await route.fulfill({ json: { items: [{ id: 'tgt_obsolete', value: 'obsolete.example.test', kind: 'fqdn', verification_state: 'dns_verified' }], next_cursor: null } }).catch(() => undefined);
    });
    await openTarget(page);
    await page.locator('.td-entry-paths').getByRole('button', { name: 'Declare entry path' }).first().click();
    const form = page.locator('.td-entry-paths form.pv-form');
    await form.getByLabel('Relation').selectOption('alternate_hostname');
    await form.getByRole('button', { name: 'Load more targets' }).click();
    await requested;
    await form.getByLabel('Search declared targets').fill('fresh');
    await expect(form.getByRole('radio', { name: /fresh.example.test/ })).toBeVisible();
    releasePage();
    await expect(form.getByRole('radio', { name: /obsolete.example.test/ })).toHaveCount(0);
    await expect(form.getByRole('radio')).toHaveCount(1);
    expect(await page.evaluate(() => window.__pickerUnhandledRejections)).toEqual([]);
  });

  test('keeps pagination errors visible and retries without losing the selected target', async ({ page }) => {
    const fake = await installFake(page);
    let fail = true;
    await page.route('**/v1/targets?**', (route) => {
      const url = new URL(route.request().url());
      if (url.searchParams.get('unit') !== 'target' || !url.searchParams.get('cursor')) return route.fallback();
      if (fail) { fail = false; return route.fulfill({ status: 503, json: { error: 'fixture_unavailable' } }); }
      return route.fallback();
    });
    await openTarget(page);
    await page.locator('.td-entry-paths').getByRole('button', { name: 'Declare entry path' }).first().click();
    const form = page.locator('.td-entry-paths form.pv-form');
    await form.getByLabel('Relation').selectOption('alternate_hostname');
    await expect(form.getByRole('radio')).toHaveCount(2);
    const selected = await form.getByRole('radio').first().getAttribute('value');
    await form.getByRole('radio').first().check();
    await form.getByRole('button', { name: 'Load more targets' }).click();
    await expect(form.getByRole('alert')).toHaveText('More targets could not load. Retry.');
    await expect(form.getByRole('radio')).toHaveCount(2);
    await expect(form.locator(`input[type=radio][value="${selected}"]`)).toBeChecked();
    await form.getByRole('button', { name: 'Load more targets' }).click();
    await expect(form.getByRole('radio')).toHaveCount(3);
    await expect(form.getByRole('alert')).toHaveCount(0);
    await expect(form.locator(`input[type=radio][value="${selected}"]`)).toBeChecked();
    expect(fake.writes()).toEqual([]);
  });

  test('plans passively, starts only the reviewed plan, shows progress, and Stop cancels running checks', async ({ page }) => {
    const fake = await installFake(page, { driftedPathsAfterStart: true });
    await openTarget(page);
    const section = page.locator('.td-entry-paths');
    await section.getByRole('button', { name: 'Plan a comparison' }).click();
    const form = section.locator('form.pv-form');
    await form.getByRole('checkbox', { name: new RegExp(LONG_HOST.slice(0, 20)) }).check();
    await form.getByLabel('Scenario').fill('waf.sqli.marker');
    await form.getByRole('button', { name: 'Review plan' }).click();
    const dialog = page.getByRole('dialog', { name: 'Start these reviewed checks?' });
    await expect(dialog).toContainText('Skipped: ownership not verified');
    await expect(dialog).toContainText('b'.repeat(64));
    expect(fake.writes().map((call) => call.body.mode)).toEqual(['plan']);
    await dialog.getByRole('button', { name: 'Start reviewed checks' }).click();
    await expect.poll(() => fake.writes().map((call) => call.body.mode)).toEqual(['plan', 'start']);
    expect(fake.writes()[1].body.reviewed_plan_digest).toBe('b'.repeat(64));
    await expect(page.locator('.inspector-panel')).toBeVisible();
    await expect.poll(() => Object.fromEntries(new URLSearchParams(new URL(page.url()).hash.split('?')[1]))).toMatchObject({ inspect: 'check_result', ev_run: 'run_cmp_primary', ev_check: 'waf.marker_rule.safe', ev_target: TARGET });
    await page.keyboard.press('Escape');
    const executions = page.getByRole('region', { name: 'Accepted comparison executions' });
    await expect(executions.getByRole('button')).toHaveCount(2);
    await executions.getByRole('button', { name: 'Inspect execution run_cmp_alt', exact: true }).click();
    await expect(page.locator('.inspector-panel')).toBeVisible();
    await expect.poll(() => Object.fromEntries(new URLSearchParams(new URL(page.url()).hash.split('?')[1]))).toMatchObject({ inspect: 'check_result', ev_run: 'run_cmp_alt', ev_check: 'waf.marker_rule.safe', ev_target: 'tgt_checkout_3' });
    await page.keyboard.press('Escape');
    await expect(executions).not.toContainText('tgt_current_metadata_drift');
    await executions.getByRole('button', { name: 'Inspect execution run_cmp_primary', exact: true }).click();
    await expect.poll(() => Object.fromEntries(new URLSearchParams(new URL(page.url()).hash.split('?')[1]))).toMatchObject({ inspect: 'check_result', ev_run: 'run_cmp_primary', ev_check: 'waf.marker_rule.safe', ev_target: TARGET });
    await page.keyboard.press('Escape');
    const result = section.locator('.pv-detail').filter({ hasText: 'Results for' });
    await expect(result).toContainText('1 of 2 started checks finished; 1 skipped');
    await expect(result).toContainText('Skipped; not executed');
    await result.getByRole('button', { name: 'Stop' }).click();
    await page.getByRole('dialog', { name: /Stop the running checks/ }).getByRole('button', { name: 'Stop checks' }).click();
    await expect.poll(() => fake.state.cancels).toEqual(['run_cmp_alt']);
    await expect(result).toContainText('Stopped before every path finished');
  });

  test('firewall change: selecting a baseline or loading a comparison never runs a check; gaps, stale and incompatible states are visible; retest is exact and reviewed', async ({ page }) => {
    const fake = await installFake(page);
    await openTarget(page, { tab: 'Changes & history' });
    const section = page.locator('.td-firewall-change');
    await expect(section).toContainText('TCP port 443');
    await expect(section).toContainText('UDP port 53');
    await expect(section.locator('.pv-card').filter({ hasText: 'fwb_old' })).toContainText('Stale baseline');
    await section.locator('.pv-card').filter({ hasText: 'fwb_old' }).getByRole('button', { name: 'Select baseline' }).click();
    await expect(section.locator('[data-state="stale"]')).toBeVisible();
    await section.locator('.pv-card').filter({ hasText: 'fwb_1' }).getByRole('button', { name: 'Select baseline' }).click();
    await section.getByRole('group', { name: 'Recorded comparisons' }).getByRole('button').first().click();
    const result = section.locator('.pv-detail').filter({ hasText: 'Comparison recorded' });
    await expect(result).toContainText('Regression observed');
    await expect(result).toContainText('Required service newly unavailable');
    await expect(result).toContainText('Not comparable with the selected baseline');
    await expect(result).toContainText('Different source perspective');
    await expect(result).toContainText('Rule-table equivalence not established');
    expect(fake.writes()).toEqual([]);
    expect(fake.state.retests).toEqual([]);

    await result.locator('[data-status="regression"]').getByRole('button', { name: 'Inspect' }).click();
    await expect(result).toContainText('The responsible rule or root cause is not identified');
    await result.getByRole('button', { name: 'Review exact retest' }).click();
    const dialog = page.getByRole('dialog', { name: 'Start this retest?' });
    await expect(dialog).toContainText('net.tcp.reachability');
    expect(fake.state.retests).toEqual([]);
    await dialog.getByRole('button', { name: 'Start retest' }).click();
    await expect.poll(() => fake.state.retests.length).toBe(1);
    expect(fake.state.retests[0]).toMatchObject({ check_id: 'net.tcp.reachability', target_id: TARGET });
    expect(Object.keys(fake.state.retests[0]).sort()).toEqual(['check_id', 'target_id']);
    await expect(page.locator('.inspector-panel')).toBeVisible();
    await expect.poll(() => Object.fromEntries(new URLSearchParams(new URL(page.url()).hash.split('?')[1]))).toMatchObject({ inspect: 'check_result', ev_run: 'run_retest_1', ev_check: fake.state.retests[0].check_id, ev_target: fake.state.retests[0].target_id });
    await expect(page.locator('.inspector-panel')).toContainText('run_retest_1');
  });

  test('firewall references outside the reviewed target cannot become a retest', async ({ page }) => {
    const fake = await installFake(page, { retestTarget: 'tgt_checkout_3' });
    await openTarget(page, { tab: 'Changes & history' });
    const section = page.locator('.td-firewall-change');
    await section.locator('.pv-card').filter({ hasText: 'fwb_1' }).getByRole('button', { name: 'Select baseline' }).click();
    await section.getByRole('group', { name: 'Recorded comparisons' }).getByRole('button').first().click();
    const result = section.locator('.pv-detail').filter({ hasText: 'Comparison recorded' });
    await result.locator('[data-status="regression"]').getByRole('button', { name: 'Inspect' }).click();
    await expect(result).toContainText('tgt_checkout_3');
    await expect(result.getByRole('button', { name: 'Review exact retest' })).toHaveCount(0);
    expect(fake.state.retests).toEqual([]);
    await expect(page.locator('.inspector-panel')).toHaveCount(0);
  });

  test('accepted firewall retest with a mismatched target never opens another execution', async ({ page }) => {
    const fake = await installFake(page, { retestResponse: { run: { id: 'run_wrong_target', target_id: 'tgt_unreviewed', check_id: 'net.tcp.reachability' } } });
    await openTarget(page, { tab: 'Changes & history' });
    const section = page.locator('.td-firewall-change');
    await section.locator('.pv-card').filter({ hasText: 'fwb_1' }).getByRole('button', { name: 'Select baseline' }).click();
    await section.getByRole('group', { name: 'Recorded comparisons' }).getByRole('button').first().click();
    const result = section.locator('.pv-detail').filter({ hasText: 'Comparison recorded' });
    await result.locator('[data-status="regression"]').getByRole('button', { name: 'Inspect' }).click();
    await result.getByRole('button', { name: 'Review exact retest' }).click();
    await page.getByRole('dialog', { name: 'Start this retest?' }).getByRole('button', { name: 'Start retest' }).click();
    await expect.poll(() => fake.state.retests.length).toBe(1);
    await expect(section.getByRole('alert')).toContainText('did not match the reviewed target/check');
    await expect(page.locator('.inspector-panel')).toHaveCount(0);
    expect(new URL(page.url()).hash).not.toContain('ev_run=');
  });

  test('accepted firewall retest without an execution ID does not substitute a recorded run', async ({ page }) => {
    const fake = await installFake(page, { retestResponse: { run: { status: 'planned' }, jobs_dispatched: 0 } });
    await openTarget(page, { tab: 'Changes & history' });
    const section = page.locator('.td-firewall-change');
    await section.locator('.pv-card').filter({ hasText: 'fwb_1' }).getByRole('button', { name: 'Select baseline' }).click();
    await section.getByRole('group', { name: 'Recorded comparisons' }).getByRole('button').first().click();
    const result = section.locator('.pv-detail').filter({ hasText: 'Comparison recorded' });
    await result.locator('[data-status="regression"]').getByRole('button', { name: 'Inspect' }).click();
    await result.getByRole('button', { name: 'Review exact retest' }).click();
    await page.getByRole('dialog', { name: 'Start this retest?' }).getByRole('button', { name: 'Start retest' }).click();
    await expect.poll(() => fake.state.retests.length).toBe(1);
    await expect(section.getByRole('alert')).toContainText('accepted without a recorded run ID');
    await expect(page.locator('.inspector-panel')).toHaveCount(0);
    expect(new URL(page.url()).hash).not.toContain('ev_run=');
  });

  for (const noComparisonId of [false, true]) {
    test(`accepted comparison ${noComparisonId ? 'without comparison ID' : 'without child IDs'} never substitutes historical executions`, async ({ page }) => {
      const fake = await installFake(page, { noChildIds: true, noComparisonId });
      await openTarget(page);
      const section = page.locator('.td-entry-paths');
      await section.getByRole('button', { name: 'Plan a comparison' }).click();
      const form = section.locator('form.pv-form');
      await form.getByRole('checkbox', { name: new RegExp(LONG_HOST.slice(0, 20)) }).check();
      await form.getByLabel('Scenario').fill('waf.sqli.marker');
      await form.getByRole('button', { name: 'Review plan' }).click();
      await page.getByRole('dialog', { name: 'Start these reviewed checks?' }).getByRole('button', { name: 'Start reviewed checks' }).click();
      await expect.poll(() => fake.writes().map((call) => call.body.mode)).toEqual(['plan', 'start']);
      if (noComparisonId) await expect(section.getByRole('alert')).toContainText('accepted without a recorded comparison ID');
      else {
        await expect(page.locator('#portal-main')).toContainText('no child execution ID was returned yet');
        await expect(section.locator('.pv-card').filter({ hasText: 'epc_1' })).toContainText('epc_1');
      }
      await expect(page.locator('.inspector-panel')).toHaveCount(0);
      expect(new URL(page.url()).hash).not.toContain('ev_run=');
    });
  }

  test('firewall change: baseline capture uses finalized runs only, and an incompatible evaluation is reported', async ({ page }) => {
    const fake = await installFake(page, { evaluateConflict: true });
    await openTarget(page, { tab: 'Changes & history' });
    const section = page.locator('.td-firewall-change');
    await section.getByRole('button', { name: 'Capture baseline' }).click();
    const form = section.locator('form.pv-form');
    await expect(form.getByRole('checkbox', { name: /run_live/ })).toBeDisabled();
    await form.getByRole('checkbox', { name: /run_pre_1/ }).check();
    await form.getByRole('button', { name: 'Review baseline' }).click();
    await page.getByRole('dialog', { name: 'Capture this pre-change baseline?' }).getByRole('button', { name: 'Capture baseline' }).click();
    await expect.poll(() => fake.writes().map((call) => call.pathname)).toEqual(['/v1/firewall-baselines']);
    expect(fake.writes()[0].body).toEqual({ change_id: 'CHG-1001', expectation_ids: ['fwx_1', 'fwx_2'], test_run_ids: ['run_pre_1'], freshness_window_seconds: 2_592_000 });

    await section.locator('.pv-card').filter({ hasText: 'fwb_1' }).getByRole('button', { name: /Select baseline|Selected/ }).first().click();
    await section.getByRole('button', { name: 'Compare post-change runs' }).click();
    await section.locator('form.pv-form').getByRole('checkbox', { name: /run_post_1/ }).check();
    await section.locator('form.pv-form').getByRole('button', { name: 'Review comparison' }).click();
    await page.getByRole('dialog', { name: 'Record this post-change comparison?' }).getByRole('button', { name: 'Record comparison' }).click();
    await expect(section.locator('[data-state="incompatible-baseline"]')).toContainText('not comparable with the baseline');
    await expect(section.locator('section[aria-labelledby="pv-fw-compare-title"] [data-state="incompatible-baseline"]')).toBeVisible();
  });

  test('at 375px long endpoints and change ids wrap inside the page and the matrix keeps each path visible while scrolled', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 900 });
    const longUrl = `https://${LONG_HOST}/api/v2/checkout/session-handoff`;
    const longChange = `CHG-2026-10-06/${'edge-allowlist-migration-'.repeat(3)}`.slice(0, 64);
    await installFake(page);
    await page.route(`**/v1/targets/${TARGET}/protection-validation`, (route) => route.fulfill({ json: { ...MATRIX, paths: MATRIX.paths.map((path) => (path.entry_path_id === 'ep_alt' ? { ...path, entry_target_value: longUrl } : path)) } }));
    await page.route((url) => url.pathname === '/v1/firewall-expectations', (route) => route.fulfill({ json: { items: EXPECTATIONS.map((item) => ({ ...item, change_id: longChange })), count: 2, next_cursor: null } }));
    await openTarget(page);
    const section = page.locator('.td-entry-paths');
    await expect(section.locator('.pv-matrix')).toContainText(longUrl.slice(0, 30));
    expect(longUrl.length).toBeGreaterThan(120);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
    expect(await section.locator('.pv-break').first().evaluate((el) => getComputedStyle(el).wordBreak)).not.toBe('break-all');
    const pathSize = await section.locator('.pv-cell-path').first().evaluate((el) => parseFloat(getComputedStyle(el).fontSize));
    const metaSize = await section.locator('.pv-cell-meta').first().evaluate((el) => parseFloat(getComputedStyle(el).fontSize));
    expect(pathSize).toBeGreaterThanOrEqual(metaSize);
    const wrap = section.locator('.pv-matrix-wrap');
    await wrap.evaluate((el) => { el.scrollLeft = el.scrollWidth; });
    const wrapBox = await wrap.boundingBox();
    const headerBox = await section.locator('.pv-matrix tbody th').nth(1).boundingBox();
    expect(wrapBox && headerBox ? headerBox.x >= wrapBox.x - 1 && headerBox.x + headerBox.width <= wrapBox.x + wrapBox.width : false).toBe(true);
    await page.getByRole('tab', { name: 'Changes & history' }).click();
    const firewall = page.locator('.td-firewall-change');
    await expect(firewall.getByRole('combobox', { name: 'Change', exact: true })).toHaveValue(longChange);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
    const sectionBox = await firewall.boundingBox();
    const selectBox = await firewall.getByRole('combobox', { name: 'Change', exact: true }).boundingBox();
    expect(sectionBox && selectBox ? selectBox.x + selectBox.width <= sectionBox.x + sectionBox.width + 1 : false).toBe(true);
  });

  test('with reduced motion the workflow and its dialogs render without transitions or animations', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await installFake(page);
    await openTarget(page);
    const section = page.locator('.td-entry-paths');
    await section.getByRole('button', { name: /^WAF on .*Allowed for this scenario/ }).click();
    await section.getByRole('button', { name: 'Declare entry path' }).first().click();
    const moving = () => page.evaluate(() => [...document.querySelectorAll('.td-entry-paths, .td-entry-paths *, .td-firewall-change, .td-firewall-change *, dialog, dialog *')]
      .filter((el) => {
        const style = getComputedStyle(el);
        const transition = style.transitionDuration.split(',').some((value) => parseFloat(value) > 0.02);
        const animation = style.animationName !== 'none' && style.animationDuration.split(',').some((value) => parseFloat(value) > 0.02);
        return transition || animation;
      })
      .map((el) => `${el.tagName}.${String(el.className)}`));
    expect(await moving()).toEqual([]);
    await page.getByRole('tab', { name: 'Changes & history' }).click();
    await page.locator('.td-firewall-change .pv-card').filter({ hasText: 'fwx_1' }).getByRole('button', { name: 'Archive' }).click();
    const dialog = page.getByRole('dialog', { name: 'Archive this expectation?' });
    await expect(dialog).toBeVisible();
    expect(await dialog.evaluate((el) => getComputedStyle(el).opacity)).toBe('1');
    expect(await moving()).toEqual([]);
    await page.keyboard.press('Escape');
    await expect(page.locator('.td-firewall-change .pv-card').filter({ hasText: 'fwx_1' }).getByRole('button', { name: 'Archive' })).toBeFocused();
  });

  for (const [failure, text] of [
    ['unsupported', 'not available from this server yet'],
    ['forbidden', 'Your role cannot read'],
    ['transport', 'could not be reached'],
  ]) {
    test(`renders the ${failure} state without starting anything`, async ({ page }) => {
      const fake = await installFake(page, { failure });
      await openTarget(page);
      await expect(page.locator('.td-entry-paths')).toContainText(text);
      await expect(page.locator('.td-entry-paths .pv-notice')).toHaveCount(1);
      await page.getByRole('tab', { name: 'Changes & history' }).click();
      await expect(page.locator('.td-firewall-change')).toContainText(text);
      expect(fake.writes()).toEqual([]);
    });
  }

  test('hides the workflow with a notice and calls no protection-validation route when the tenant gate is off', async ({ page }) => {
    const fake = await installFake(page);
    await page.route('**/v1/tenant/deployment-features', (route) => route.fulfill({
      json: { waf_posture: true, external_discovery: false, connectors: true, protection_validation: false },
    }));
    await openTarget(page);
    await expect(page.getByTestId('protection-validation-disabled')).toHaveCount(0);
    await expect(page.locator('.td-entry-paths')).toHaveCount(0);
    await page.getByRole('tab', { name: 'Changes & history' }).click();
    await expect(page.locator('.td-firewall-change')).toHaveCount(0);
    expect(fake.calls).toEqual([]);
  });

  test('a viewer can read evidence but has no declare, plan, or retest controls', async ({ page }) => {
    await installFake(page);
    await openTarget(page, { role: 'viewer' });
    const section = page.locator('.td-entry-paths');
    await expect(section.locator('.pv-matrix')).toBeVisible();
    await expect(section.getByRole('button', { name: 'Declare entry path' })).toHaveCount(0);
    await expect(section.getByRole('button', { name: 'Plan a comparison' })).toBeDisabled();
    await page.getByRole('tab', { name: 'Changes & history' }).click();
    await expect(page.locator('.td-firewall-change').getByRole('button', { name: 'Declare expectation' })).toHaveCount(0);
  });

  test('an unverified anchor shows the ownership state and an empty declaration list', async ({ page }) => {
    await installFake(page);
    await openTarget(page, { target: UNVERIFIED });
    const section = page.locator('.td-entry-paths');
    await expect(section.locator('[data-state="unverified-target"]')).toBeVisible();
    await expect(section.locator('[data-state="empty"]')).toContainText('No entry path is declared');
    await expect(section.getByRole('button', { name: 'Declare entry path' })).toHaveCount(1);
  });

  for (const width of [375, 768, 1024, 1440]) {
    for (const theme of ['dark', 'light']) {
      test(`stays contained and accessible at ${width}px in ${theme}`, async ({ page }, testInfo) => {
        await page.setViewportSize({ width, height: 1000 });
        await page.addInitScript((mode) => localStorage.setItem('astranull.theme', mode), theme);
        await installFake(page);
        await openTarget(page);
        await page.locator('.td-entry-paths').getByRole('button', { name: /^WAF on .*Allowed for this scenario/ }).click();
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 2)).toBe(true);
        await expectNoBlockingAxe(page, '.td-entry-paths');
        if (process.env.ASTRANULL_PV_REVIEW_SCREENSHOTS === '1') await page.locator('.td-entry-paths').screenshot({ path: testInfo.outputPath(`entry-paths-${width}-${theme}.png`) });
        await page.getByRole('tab', { name: 'Changes & history' }).click();
        await page.locator('.td-firewall-change .pv-card').filter({ hasText: 'fwb_1' }).getByRole('button', { name: 'Select baseline' }).click();
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 2)).toBe(true);
        await expectNoBlockingAxe(page, '.td-firewall-change');
        if (process.env.ASTRANULL_PV_REVIEW_SCREENSHOTS === '1') await page.locator('.td-firewall-change').screenshot({ path: testInfo.outputPath(`firewall-${width}-${theme}.png`) });
      });
    }
  }
});
