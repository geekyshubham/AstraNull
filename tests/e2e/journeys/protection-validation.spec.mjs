import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { getPortalPlaywrightBaseUrl, startPortalPlaywrightServer, stopPortalPlaywrightServer } from '../../helpers/portal-playwright-server.mjs';
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
      return route.fulfill({ status: 201, json: { id: 'run_retest_1', status: 'running' } });
    }
    if (!PV_PATH.test(pathname)) return route.continue();

    if (options.failure === 'unsupported') return route.fulfill({ status: 404, json: { error: 'not_found' } });
    if (options.failure === 'forbidden') return route.fulfill({ status: 403, json: { error: 'forbidden' } });
    if (options.failure === 'transport') return route.abort('failed');

    if (pathname === `/v1/targets/${TARGET}/entry-paths` || pathname === `/v1/targets/${UNVERIFIED}/entry-paths`) {
      if (method === 'POST') return route.fulfill({ status: 201, json: { ...ENTRY_PATHS[1], id: 'ep_new', entry_target_id: body.entry_target_id, relation_kind: body.relation_kind } });
      const items = pathname.includes(UNVERIFIED) ? [] : ENTRY_PATHS;
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
      const items = url.searchParams.get('baseline_id') === 'fwb_1' ? [COMPARISON] : [];
      return route.fulfill({ json: { items, count: items.length, next_cursor: null } });
    }
    if (pathname === '/v1/firewall-comparisons' && method === 'POST') {
      if (state.evaluateConflict) return route.fulfill({ status: 409, json: { error: 'baseline_not_comparable', message: 'not comparable' } });
      return route.fulfill({ status: 201, json: COMPARISON });
    }
    if (pathname === '/v1/firewall-comparisons/fwc_1') return route.fulfill({ json: COMPARISON });
    return route.fulfill({ status: 404, json: { error: 'not_found' } });
  });
  return { calls, state, writes: () => calls.filter((call) => call.method === 'POST') };
}

async function openTarget(page, { role = 'owner', target = TARGET, tab } = {}) {
  await injectPortalDevHeadersSession(page, { ...PORTAL_SESSION, role });
  await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': target } });
  if (tab) await page.getByRole('tab', { name: tab }).click();
}

async function expectNoBlockingAxe(page, selector) {
  await waitForPortalRouteSettled(page);
  const results = await new AxeBuilder({ page }).include(selector).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
  expect(results.violations.filter((item) => ['serious', 'critical'].includes(item.impact ?? '')).map((item) => `${item.id}: ${item.help}`)).toEqual([]);
}

test.describe('protection validation in the target workspace (PV-07)', () => {
  test.beforeEach(async () => { await startPortalPlaywrightServer(); });
  test.afterEach(async () => { await stopPortalPlaywrightServer(); });

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

  test('discards a late pagination response after the target search changes', async ({ page }) => {
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
  });

  test('plans passively, starts only the reviewed plan, shows progress, and Stop cancels running checks', async ({ page }) => {
    const fake = await installFake(page);
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
  });

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
    await expect(page.getByTestId('protection-validation-disabled')).toContainText('not enabled for this workspace');
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
