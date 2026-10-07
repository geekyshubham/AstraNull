import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  COMPATIBILITY_REASONS,
  ENTRY_PATH_EXPECTED_BEHAVIORS,
  ENTRY_PATH_RELATION_KINDS,
  FINALIZED_RUN_STATUSES,
  FIREWALL_COMPARISON_STATUSES,
  FIREWALL_GAP_KINDS,
  FIREWALL_OBSERVATION_CLASSES,
  FIREWALL_SIDE_STATES,
  LAYER_EVIDENCE_STATES,
  PATH_ENTRY_OBSERVATIONS,
  PATH_LAYER_EXPECTED_OUTCOMES,
  PATH_VALIDATION_OUTCOMES,
  PROTECTION_LAYERS,
  PROTECTION_VALIDATION_LIMITATIONS,
  PROTECTION_VALIDATION_ROUTES,
  findBannedScopeKey,
  normalizeEntryPathDeclaration,
  normalizeFirewallExpectation,
} from '../../src/contracts/protectionValidation.mjs';
import { EXTERNAL_OBSERVATION_LABELS, PATH_OBSERVATION_LABELS } from '../../src/lib/externalObservationOutcomes.mjs';
import * as presenter from '../../apps/web/react/src/components/targets/entry-paths/presenter.mjs';

const ROOT = process.cwd();
const UI_DIR = path.join(ROOT, 'apps/web/react/src/components/targets/entry-paths');
const API_FILE = path.join(ROOT, 'apps/web/react/src/lib/protection-validation-api.ts');
const keys = (map) => Object.keys(map).sort();
const sorted = (list) => [...list].sort();

describe('protection-validation UI vocabulary parity with the PV-02 contract', () => {
  it('labels every contract enum value and nothing else', () => {
    assert.deepEqual([...presenter.PROTECTION_LAYERS], [...PROTECTION_LAYERS]);
    assert.deepEqual(keys(presenter.LAYER_LABELS), sorted(PROTECTION_LAYERS));
    assert.deepEqual(keys(presenter.RELATION_KIND_LABELS), sorted(ENTRY_PATH_RELATION_KINDS));
    assert.deepEqual(keys(presenter.EXPECTED_BEHAVIOR_LABELS), sorted(ENTRY_PATH_EXPECTED_BEHAVIORS));
    assert.deepEqual(keys(presenter.LAYER_OUTCOME_LABELS), sorted(PATH_LAYER_EXPECTED_OUTCOMES));
    assert.deepEqual(keys(presenter.PATH_OUTCOME_LABELS), sorted(PATH_VALIDATION_OUTCOMES));
    assert.deepEqual(keys(presenter.PATH_OUTCOME_TONES), sorted(PATH_VALIDATION_OUTCOMES));
    assert.deepEqual(keys(presenter.FIREWALL_STATUS_LABELS), sorted(FIREWALL_COMPARISON_STATUSES));
    assert.deepEqual(keys(presenter.FIREWALL_STATUS_TONES), sorted(FIREWALL_COMPARISON_STATUSES));
    assert.deepEqual(keys(presenter.FIREWALL_GAP_LABELS), sorted(FIREWALL_GAP_KINDS));
    assert.deepEqual(keys(presenter.FIREWALL_SIDE_STATE_LABELS), sorted(FIREWALL_SIDE_STATES));
    assert.deepEqual(keys(presenter.FIREWALL_OBSERVATION_LABELS), sorted(FIREWALL_OBSERVATION_CLASSES));
    assert.deepEqual(keys(presenter.LIMITATION_LABELS), sorted(PROTECTION_VALIDATION_LIMITATIONS));
    assert.deepEqual(keys(presenter.COMPATIBILITY_REASON_LABELS), sorted(COMPATIBILITY_REASONS));
    assert.deepEqual([...presenter.FINALIZED_RUN_STATUSES], [...FINALIZED_RUN_STATUSES]);
    for (const [dimension, states] of Object.entries(LAYER_EVIDENCE_STATES)) {
      assert.deepEqual(keys(presenter.LAYER_STATE_LABELS[dimension]), sorted(states), dimension);
      assert.ok(presenter.LAYER_DIMENSION_LABELS[dimension], dimension);
    }
  });

  it('reuses the PV-01 external observation labels for entry observations', () => {
    assert.deepEqual(keys(presenter.PATH_OBSERVATION_LABELS), sorted(PATH_ENTRY_OBSERVATIONS));
    for (const outcome of PATH_ENTRY_OBSERVATIONS) {
      assert.equal(presenter.PATH_OBSERVATION_LABELS[outcome], PATH_OBSERVATION_LABELS[outcome]);
      assert.equal(presenter.pathObservationLabels('origin')[outcome], EXTERNAL_OBSERVATION_LABELS[outcome]);
    }
  });

  it('keeps origin wording off non-origin entry paths', () => {
    for (const kind of ENTRY_PATH_RELATION_KINDS.filter((value) => value !== 'origin')) {
      for (const label of Object.values(presenter.pathObservationLabels(kind))) assert.equal(/origin/i.test(label), false, `${kind}: ${label}`);
    }
    assert.match(presenter.pathObservationLabels('origin').response_observed, /^Origin response observed/);
  });

  it('uses the scoped customer labels and never a universal protection or bypass claim', () => {
    assert.equal(presenter.layerStateLabel('observed_enforcement', 'not_enforced'), 'Allowed for this scenario');
    assert.equal(presenter.PATH_OBSERVATION_LABELS.response_observed, 'Response observed');
    assert.equal(presenter.pathObservationLabels('origin').response_observed, 'Origin response observed');
    assert.equal(presenter.PATH_OBSERVATION_LABELS.no_response, 'No response; enforcement unverified');
    assert.equal(presenter.FIREWALL_OBSERVATION_LABELS.no_response, 'No response; enforcement unverified');
    const allLabels = [
      presenter.PATH_OUTCOME_LABELS, presenter.FIREWALL_STATUS_LABELS, presenter.FIREWALL_GAP_LABELS, presenter.FIREWALL_SIDE_STATE_LABELS,
      presenter.FIREWALL_OBSERVATION_LABELS, presenter.LIMITATION_LABELS, presenter.COMPATIBILITY_REASON_LABELS,
      ...Object.values(presenter.LAYER_STATE_LABELS),
    ].flatMap((map) => Object.values(map));
    for (const label of allLabels) assert.equal(presenter.containsForbiddenClaim(label), false, label);
    assert.equal(presenter.containsForbiddenClaim('All controls bypassed'), true);
    assert.equal(presenter.containsForbiddenClaim('DDoS protected'), true);
  });

  it('keeps forbidden claim text out of every shipped UI file', () => {
    const files = [...readdirSync(UI_DIR).map((name) => path.join(UI_DIR, name)), API_FILE];
    for (const file of files) {
      const source = readFileSync(file, 'utf8').toLowerCase();
      assert.equal(source.includes('all controls bypassed'), false, file);
      assert.equal(source.includes('ddos protected'), false, file);
    }
  });
});

describe('protection-validation API client pins the documented routes', () => {
  const source = readFileSync(API_FILE, 'utf8');
  const documented = new Set(PROTECTION_VALIDATION_ROUTES.map((route) => route.path));
  const existing = new Set(['/v1/targets', '/v1/test-runs', '/v1/test-runs/:id', '/v1/test-runs/:id/cancel']);

  it('only calls documented protection-validation routes or existing target/run routes', () => {
    const paths = [...source.matchAll(/[`'](\/v1\/[^`'\n]*)[`']/g)]
      .map((match) => match[1].split('${query(')[0].replace(/\$\{enc\((\w+)\)\}/g, (_, name) => `:${name}`))
      .map((value) => value.replace(/:runId/g, ':id'));
    assert.ok(paths.length >= 10);
    for (const value of paths) assert.ok(documented.has(value) || existing.has(value), `unexpected route ${value}`);
    for (const route of PROTECTION_VALIDATION_ROUTES) assert.ok(paths.includes(route.path), `client does not cover ${route.method} ${route.path}`);
  });

  it('sends start only with a reviewed plan digest and plans in passive mode', () => {
    assert.match(source, /mode: 'plan'/);
    assert.match(source, /mode: 'start', \.\.\.body, reviewed_plan_digest: reviewedPlanDigest/);
  });
});

describe('declaration drafts produce contract-valid bodies without destinations', () => {
  const base = { relation_kind: 'alternate_hostname', entry_target_id: 'tgt_alt', expected_behavior: 'must_be_protected_by_layers', required_layers: ['cdn_edge', 'waf'], origin_binding_id: '', owner: 'App Team', purpose: 'Partner hostname' };

  it('validates relation, layer and origin rules before review', () => {
    assert.deepEqual(presenter.entryPathDraftErrors(base, 'tgt_app'), {});
    assert.ok(presenter.entryPathDraftErrors({ ...base, required_layers: [] }, 'tgt_app').required_layers);
    assert.ok(presenter.entryPathDraftErrors({ ...base, expected_behavior: 'intentionally_public' }, 'tgt_app').required_layers);
    assert.ok(presenter.entryPathDraftErrors({ ...base, relation_kind: 'origin' }, 'tgt_app').origin_binding_id);
    assert.ok(presenter.entryPathDraftErrors({ ...base, entry_target_id: 'tgt_app' }, 'tgt_app').entry_target_id);
    assert.ok(presenter.entryPathDraftErrors({ ...base, relation_kind: 'primary_route' }, 'tgt_app').entry_target_id);
    assert.ok(presenter.entryPathDraftErrors({ ...base, owner: 'x'.repeat(121) }, 'tgt_app').owner);
  });

  it('builds bodies the contract accepts', () => {
    const body = presenter.entryPathCreateBody(base);
    assert.equal(findBannedScopeKey(body), null);
    const record = normalizeEntryPathDeclaration(body, { tenantId: 'ten_1', anchorTargetId: 'tgt_app', declarationVersion: 1 });
    assert.deepEqual(record.required_layers, ['waf', 'cdn_edge']);
    const origin = presenter.entryPathCreateBody({ ...base, relation_kind: 'origin', entry_target_id: 'tgt_origin', origin_binding_id: 'ob_1' });
    assert.equal(normalizeEntryPathDeclaration(origin, { tenantId: 'ten_1', anchorTargetId: 'tgt_app', declarationVersion: 1 }).origin_binding_id, 'ob_1');
    assert.equal(presenter.entryPathCreateBody({ ...base, origin_binding_id: 'ob_1' }).origin_binding_id, null);
  });

  it('builds firewall expectations the contract accepts, with a mapping only when declared', () => {
    const draft = { destination_target_id: 'tgt_fw', protocol: 'tcp', port: '443', expected: 'allow', source_perspective: 'public-worker-eu', change_id: 'CHG-1001', owner: '', service: '', service_port: '', service_path: '', pre_destination_target_id: '' };
    assert.deepEqual(presenter.firewallDraftErrors(draft), {});
    const tcp = presenter.firewallExpectationBody(draft);
    assert.equal(tcp.pre_post_mapping, undefined);
    assert.equal(normalizeFirewallExpectation(tcp, { tenantId: 'ten_1', expectationVersion: 1 }).port, 443);
    const service = presenter.firewallExpectationBody({ ...draft, protocol: 'service', service: 'https', service_port: '8443', service_path: '/health' });
    assert.deepEqual(normalizeFirewallExpectation(service, { tenantId: 'ten_1', expectationVersion: 1 }).service_endpoint, { service: 'https', port: 8443, path: '/health' });
    const mapped = presenter.firewallExpectationBody({ ...draft, pre_destination_target_id: 'tgt_old' });
    assert.deepEqual(normalizeFirewallExpectation(mapped, { tenantId: 'ten_1', expectationVersion: 1 }).pre_post_mapping, { pre_destination_target_id: 'tgt_old', post_destination_target_id: 'tgt_fw', declared_by_customer: true });
    assert.ok(presenter.firewallDraftErrors({ ...draft, port: '70000' }).port);
    assert.ok(presenter.firewallDraftErrors({ ...draft, protocol: 'service', service_path: '/x?y=1' }).service_port);
    assert.ok(presenter.firewallDraftErrors({ ...draft, source_perspective: 'Spoofed Source' }).source_perspective);
    assert.ok(presenter.firewallDraftErrors({ ...draft, pre_destination_target_id: 'tgt_fw' }).pre_destination_target_id);
    for (const body of [tcp, service, mapped]) assert.equal(findBannedScopeKey(body), null);
  });
});

describe('comparison read models never overstate results', () => {
  it('reports stale, incompatible, comparable and unknown compatibility', () => {
    assert.equal(presenter.compatibilityView(null).state, 'unknown');
    assert.equal(presenter.compatibilityView({ comparable: true, stale: false, reasons: [] }).state, 'comparable');
    assert.equal(presenter.compatibilityView({ comparable: false, stale: true, reasons: ['baseline_stale'] }).state, 'stale');
    const incompatible = presenter.compatibilityView({ comparable: false, stale: false, reasons: ['source_mismatch', 'check_version_mismatch'] });
    assert.equal(incompatible.state, 'incompatible');
    assert.deepEqual(incompatible.reasons.map((reason) => reason.id), ['source_mismatch', 'check_version_mismatch']);
  });

  it('never accepts zero evaluated items and marks partial evaluations', () => {
    assert.equal(presenter.summaryView({ total: 0, evaluated: 0, accepted: true }, 'firewall_change').accepted, false);
    assert.match(presenter.summaryView({ total: 0, evaluated: 0 }, 'firewall_change').label, /Nothing was evaluated/);
    const partial = presenter.summaryView({ total: 4, evaluated: 2, accepted: false }, 'path_validation');
    assert.equal(partial.partial, true);
    assert.equal(presenter.summaryView(null, 'path_validation').total, null);
  });

  it('treats missing freshness as unknown and expired windows as stale', () => {
    assert.equal(presenter.freshnessView(null).state, 'unknown');
    assert.equal(presenter.freshnessView({ fresh: false }).state, 'stale');
    assert.equal(presenter.freshnessView({ expires_at: new Date(Date.now() - 1000).toISOString() }).state, 'stale');
    assert.equal(presenter.freshnessView({ fresh: true }).state, 'fresh');
  });

  it('only offers finalized runs on the allowed targets as evidence', () => {
    assert.equal(presenter.runSelectionBlocker({ id: 'r1', status: 'verdicted', target_id: 't1' }, ['t1']), '');
    assert.match(presenter.runSelectionBlocker({ id: 'r1', status: 'running', target_id: 't1' }, ['t1']), /Not finalized/);
    assert.match(presenter.runSelectionBlocker({ id: 'r1', status: 'completed', target_id: 't2' }, ['t1']), /different target/);
  });

  it('derives progress and the runs Stop may cancel only while running', () => {
    const running = { status: 'running', items: [
      { entry_path_id: 'a', test_run_id: 'run_a', outcome: 'consistent_enforcement' },
      { entry_path_id: 'b', test_run_id: 'run_b', outcome: 'not_tested' },
      { entry_path_id: 'c', test_run_id: null, outcome: 'skipped' },
    ] };
    assert.deepEqual(presenter.comparisonProgress(running), { total: 3, started: 2, finished: 1, running: 1, skipped: 1, activeRunIds: ['run_b'], status: 'running' });
    assert.deepEqual(presenter.comparisonProgress({ ...running, status: 'completed' }).activeRunIds, []);
    assert.equal(presenter.comparisonProgress(running, { run_b: 'cancelled' }).finished, 2);
  });

  it('describes unsupported, forbidden and transport failures without implying a start', () => {
    assert.match(presenter.failureCopy({ state: 'unsupported' }, 'declared entry paths'), /not available from this server yet/);
    assert.match(presenter.failureCopy({ state: 'forbidden' }, 'declared entry paths'), /Your role cannot read/);
    assert.match(presenter.failureCopy({ state: 'transport_error' }, 'declared entry paths'), /No check was started/);
    assert.match(presenter.writeErrorCopy('reviewed_plan_mismatch', ''), /Nothing started/);
    assert.equal(presenter.authorizationView({ currently_authorized: false }).authorized, false);
  });
});

describe('target workspace mounts the protection-validation sections', () => {
  it('adds declared entry paths to the overview and the firewall comparison to Changes & history', () => {
    const page = readFileSync(path.join(ROOT, 'apps/web/react/src/pages/target-detail-view.tsx'), 'utf8');
    assert.match(page, /import \{ DeclaredEntryPaths, FirewallChangeComparison \} from '\.\.\/components\/targets\/entry-paths';/);
    const overview = page.slice(page.indexOf("tab === 'overview'"), page.indexOf("tab === 'validate'"));
    assert.match(overview, /<DeclaredEntryPaths/);
    const history = page.slice(page.indexOf("tab === 'history'"));
    assert.match(history, /<FirewallChangeComparison/);
  });
});

describe('entry-path workspace keeps other applications’ relations out of this application', () => {
  it('splits relations by anchor so referenced paths are never archived or compared here', () => {
    const items = [
      { id: 'ep_own', anchor_target_id: 'tgt_a', entry_target_id: 'tgt_a', status: 'active' },
      { id: 'ep_x', anchor_target_id: 'tgt_b', entry_target_id: 'tgt_a', status: 'active' },
      { id: 'ep_own_alt', anchor_target_id: 'tgt_a', entry_target_id: 'tgt_c', status: 'archived' },
    ];
    const { anchored, referenced } = presenter.splitEntryPathsByAnchor(items, 'tgt_a');
    assert.deepEqual(anchored.map((row) => row.id), ['ep_own', 'ep_own_alt']);
    assert.deepEqual(referenced.map((row) => row.id), ['ep_x']);
    assert.deepEqual(presenter.splitEntryPathsByAnchor(items, '').anchored, []);
    const workspace = readFileSync(path.join(UI_DIR, 'entry-paths-workspace.tsx'), 'utf8');
    assert.match(workspace, /paths=\{anchored\}/);
    assert.match(workspace, /referencedActive\.map\(\(path\) => <EntryPathCard key=\{path\.id\} path=\{path\} canArchive=\{false\}/);
  });
});

describe('plan expectation conflicts keep the server object shape', () => {
  it('parses the planner output per path and never drops conflicts', async () => {
    const { parseExpectationConflicts, expectationConflictLabel } = await import('../../apps/web/react/src/lib/expectation-conflicts.mjs');
    const { planEntryPathComparison } = await import('../../src/lib/entryPathComparison.mjs');
    const { normalizeEntryPathComparisonRequest } = await import('../../src/contracts/protectionValidation.mjs');
    const { CHECK_CATALOG } = await import('../../src/contracts/checks.mjs');
    const tenantId = 'ten_ui_conflicts';
    const targets = [
      { id: 'tgt_app', tenant_id: tenantId, target_group_id: 'tg', kind: 'fqdn', value: 'app.example' },
      { id: 'tgt_alt', tenant_id: tenantId, target_group_id: 'tg', kind: 'fqdn', value: 'alt.example' },
    ];
    const declare = (id, entry, kind) => ({
      id,
      ...normalizeEntryPathDeclaration({ entry_target_id: entry, relation_kind: kind, owner: 'App', purpose: 'Route', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'] }, { tenantId, anchorTargetId: 'tgt_app' }),
    });
    const relations = [declare('ep_primary', 'tgt_app', 'primary_route'), declare('ep_alt', 'tgt_alt', 'alternate_hostname')];
    const plan = planEntryPathComparison({
      tenantId,
      request: normalizeEntryPathComparisonRequest({ mode: 'plan', anchor_target_id: 'tgt_app', primary_entry_path_id: 'ep_primary', entry_path_ids: ['ep_primary', 'ep_alt'], expectation: { scenario: 'waf.ssrf_marker.safe', layer_outcomes: { waf: 'no_expectation' } } }),
      anchorTarget: targets[0],
      relations,
      targets,
      originBindings: [],
      catalog: CHECK_CATALOG,
    });
    assert.ok(plan.expectation_conflicts.length >= 2);
    const parsed = parseExpectationConflicts(JSON.parse(JSON.stringify(plan.expectation_conflicts)));
    assert.deepEqual(parsed, plan.expectation_conflicts);
    assert.deepEqual(parsed.find((row) => row.entry_path_id === 'ep_alt').conflicts, ['required_layer_not_enforced:waf']);
    assert.match(expectationConflictLabel('required_layer_not_enforced:waf'), /WAF/);
    assert.deepEqual(parseExpectationConflicts(['legacy_string', null, { entry_path_id: 'ep', conflicts: [] }]), []);
    const api = readFileSync(API_FILE, 'utf8');
    assert.match(api, /expectation_conflicts: parseExpectationConflicts\(payload\.expectation_conflicts\)/);
  });
});
