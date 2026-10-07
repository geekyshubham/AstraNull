import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import {
  REQUIRED_LIMITATIONS,
  classifyFirewallComparisonItem,
  classifyPathValidationItem,
  normalizeComparisonEvaluation,
  normalizeEntryPathDeclaration,
  normalizeFirewallExpectation,
  normalizePathValidationExpectation,
} from '../../src/contracts/protectionValidation.mjs';
import {
  PATH_OUTCOME_PRECEDENCE,
  buildProtectionValidationReport,
  evidenceReadinessClass,
  projectProtectionMatrixRows,
  protectionValidationReportCsv,
  rollupPathOutcome,
  selectCurrentFirewallItems,
  selectCurrentPathItems,
  verifyProtectionReportConclusion,
} from '../../src/lib/protectionValidationReport.mjs';
import { deriveProtectionFindingCandidates } from '../../src/lib/protectionValidationFindings.mjs';

const TENANT = 'ten_pvr';
const OTHER = 'ten_pvr_other';
const SCENARIO = 'waf.sqli.marker';
const T0 = '2026-10-01T00:00:00.000Z';
const T1 = '2026-10-02T00:00:00.000Z';
const T2 = '2026-10-03T00:00:00.000Z';
const NOW = '2026-10-04T00:00:00.000Z';

function target(id, extra = {}) {
  return { id, tenant_id: TENANT, kind: 'fqdn', value: `${id}.example.test`, ...extra };
}

const TARGETS = [
  target('tgt_app'), target('tgt_alt'), target('tgt_origin'), target('tgt_hidden'), target('tgt_api'),
  target('tgt_login'), target('tgt_shop'), target('tgt_shop_alt'), target('tgt_fw'),
  target('tgt_gone', { deleted_at: T0 }),
];

function relation(id, anchor, body, tenantId = TENANT) {
  return { ...normalizeEntryPathDeclaration({ owner: 'App Team', purpose: 'Declared path', ...body }, { tenantId, anchorTargetId: anchor }), id };
}

const PATHS = {
  primary: relation('ep_primary', 'tgt_app', { entry_target_id: 'tgt_app', relation_kind: 'primary_route', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf', 'cdn_edge'] }),
  alt: relation('ep_alt', 'tgt_app', { entry_target_id: 'tgt_alt', relation_kind: 'alternate_hostname', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf', 'cdn_edge'] }),
  origin: relation('ep_origin', 'tgt_app', { entry_target_id: 'tgt_origin', relation_kind: 'origin', origin_binding_id: 'ob_1', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'] }),
  hidden: relation('ep_hidden', 'tgt_app', { entry_target_id: 'tgt_hidden', relation_kind: 'fallback_backend_route', expected_behavior: 'must_not_be_reachable' }),
  api: relation('ep_api', 'tgt_app', { entry_target_id: 'tgt_api', relation_kind: 'declared_api_url', expected_behavior: 'intentionally_public' }),
  login: relation('ep_login', 'tgt_app', { entry_target_id: 'tgt_login', relation_kind: 'declared_login_url', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'] }),
  shopPrimary: relation('ep_shop', 'tgt_shop', { entry_target_id: 'tgt_shop', relation_kind: 'primary_route', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'] }),
  shopShared: relation('ep_shop_alt_shared', 'tgt_shop', { entry_target_id: 'tgt_alt', relation_kind: 'alternate_hostname', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'] }),
  shopUntested: relation('ep_shop_alt', 'tgt_shop', { entry_target_id: 'tgt_shop_alt', relation_kind: 'alternate_hostname', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf', 'ddos'] }),
  archived: { ...relation('ep_archived', 'tgt_app', { entry_target_id: 'tgt_login', relation_kind: 'alternate_hostname', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'] }), status: 'archived' },
  gone: relation('ep_gone', 'tgt_app', { entry_target_id: 'tgt_gone', relation_kind: 'alternate_hostname', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'] }),
  foreign: relation('ep_foreign', 'tgt_app', { entry_target_id: 'tgt_foreign', relation_kind: 'alternate_hostname', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'] }, OTHER),
};
const ENTRY_PATHS = Object.values(PATHS);
const PATH_EXPECTATIONS = [
  { ...normalizePathValidationExpectation({ scenario: SCENARIO, layer_outcomes: { waf: 'enforce', cdn_edge: 'enforce' } }, { tenantId: TENANT, anchorTargetId: 'tgt_app' }), id: 'pvx_app' },
  { ...normalizePathValidationExpectation({ scenario: SCENARIO, layer_outcomes: { waf: 'enforce' } }, { tenantId: TENANT, anchorTargetId: 'tgt_shop' }), id: 'pvx_shop' },
];

const CATALOG = [
  { check_id: 'waf.marker.sqli', probe_profile: { kind: 'waf_class_marker_probe' } },
  { check_id: 'origin.host_sni_bypass.safe', probe_profile: { kind: 'host_sni_bypass' } },
  { check_id: 'net.tcp.reachability', probe_profile: { kind: 'tcp_connect' } },
];

function ref(run, targetId, observedAt, checkId = 'waf.marker.sqli') {
  return {
    test_run_id: run, check_id: checkId, check_version: '1.1.0', scenario_version: 's1', verdict_id: `vrd_${run}`,
    evidence_ids: [`ev_${run}`], target_id: targetId, observed_at: observedAt, run_status: 'verdicted',
    source_perspective: 'public-worker-eu', worker_id: 'worker_eu_1',
  };
}

function pathItem(rel, args, refs) {
  return { entry_path_id: rel.id, scenario: SCENARIO, ...classifyPathValidationItem({ relation: rel, primaryBaselineHealth: 'healthy', primaryEnforcement: 'enforced', ...args }), evidence_refs: refs };
}

function evaluation(kind, id, at, items, extra = {}, tenantId = TENANT) {
  return { ...normalizeComparisonEvaluation({ kind, tenant_id: tenantId, evaluated_at: at, items, ...extra }), id };
}

const OLD_APP_EVAL = evaluation('path_validation', 'pvc_old', T0, [
  pathItem(PATHS.alt, { observation: 'explicit_denial_observed', enforcement: 'enforced' }, [ref('run_alt_old', 'tgt_alt', T0)]),
]);
const APP_EVAL = evaluation('path_validation', 'pvc_app', T1, [
  pathItem(PATHS.primary, { observation: 'explicit_denial_observed', enforcement: 'enforced' }, [ref('run_primary', 'tgt_app', T1)]),
  pathItem(PATHS.alt, { observation: 'application_identity_confirmed', enforcement: 'not_enforced' }, [ref('run_alt', 'tgt_alt', T1)]),
  pathItem(PATHS.origin, { observation: 'response_observed' }, [ref('run_origin', 'tgt_origin', T1, 'origin.host_sni_bypass.safe')]),
  pathItem(PATHS.hidden, { observation: 'explicit_denial_observed' }, [ref('run_hidden', 'tgt_hidden', T1, 'origin.host_sni_bypass.safe')]),
  pathItem(PATHS.api, { observation: 'response_observed' }, [ref('run_api', 'tgt_api', T1)]),
  pathItem(PATHS.login, { observation: 'no_response' }, []),
  pathItem(PATHS.gone, { observation: 'response_observed', enforcement: 'not_enforced' }, [ref('run_gone', 'tgt_gone', T1)]),
], { anchor_target_id: 'tgt_app' });
const SHOP_EVAL = evaluation('path_validation', 'pvc_shop', T1, [
  pathItem(PATHS.shopPrimary, { observation: 'explicit_denial_observed', enforcement: 'enforced' }, [ref('run_shop', 'tgt_shop', T1, 'net.tcp.reachability')]),
  pathItem(PATHS.shopShared, { observation: 'explicit_denial_observed', enforcement: 'enforced' }, [ref('run_shared', 'tgt_alt', T1)]),
]);
const TAMPERED = (() => {
  const base = evaluation('path_validation', 'pvc_tampered', T2, [pathItem(PATHS.login, { observation: 'explicit_denial_observed', enforcement: 'enforced' }, [ref('run_t', 'tgt_login', T2)])]);
  return { ...base, items: base.items.map((item) => ({ ...item, entry_path_id: 'ep_api' })) };
})();
const FOREIGN_EVAL = evaluation('path_validation', 'pvc_foreign', T2, [pathItem(PATHS.foreign, { observation: 'application_identity_confirmed', enforcement: 'not_enforced' }, [ref('run_f', 'tgt_foreign', T2)])], {}, OTHER);
const PATH_EVALS = [OLD_APP_EVAL, APP_EVAL, SHOP_EVAL, TAMPERED, FOREIGN_EVAL];

function fwExpectation(id, body, extra = {}) {
  return { ...normalizeFirewallExpectation({ destination_target_id: 'tgt_fw', source_perspective: 'public-worker-eu', change_id: 'CHG-9', ...body }, { tenantId: TENANT }), id, ...extra };
}
const FW = [
  fwExpectation('fwx_ok', { protocol: 'service', service_endpoint: { service: 'https', port: 443 }, expected: 'allow' }),
  fwExpectation('fwx_gap', { protocol: 'tcp', port: 22, expected: 'deny' }),
  fwExpectation('fwx_mixed', { protocol: 'udp', port: 53, expected: 'deny' }),
  fwExpectation('fwx_untested', { protocol: 'tcp', port: 25, expected: 'deny' }),
  fwExpectation('fwx_archived', { protocol: 'tcp', port: 21, expected: 'deny' }, { status: 'archived' }),
];
function fwItem(expectation, pre, post, compatibility = { comparable: true, stale: false, reasons: [] }, checkId = 'net.tcp.reachability') {
  return { expectation_id: expectation.id, ...classifyFirewallComparisonItem({ expectation, baseline: pre, candidate: post, compatibility }), evidence_refs: [ref(`run_${expectation.id}`, 'tgt_fw', T2, checkId)] };
}
const FW_EVAL = evaluation('firewall_change', 'fwc_1', T2, [
  fwItem(FW[0], ['service_response_observed'], ['service_response_observed'], undefined, 'waf.marker.sqli'),
  fwItem(FW[1], ['explicit_denial_observed'], ['reachable_transport_only']),
  { ...fwItem(FW[2], ['explicit_denial_observed'], ['udp_silence'], { comparable: false, stale: false, reasons: ['source_mismatch'] }), evidence_refs: [] },
], { baseline_id: 'fwb_1', baseline_digest: 'b'.repeat(64) });

const DETECTIONS = [
  { tenant_id: TENANT, target_id: 'tgt_alt', layer: 'waf', provider: 'provider_a', state: 'detected' },
  { tenant_id: TENANT, target_id: 'tgt_alt', layer: 'waf', provider: 'provider_b', state: 'detected' },
  { tenant_id: TENANT, target_id: 'tgt_alt', layer: 'cdn_edge', provider: 'provider_a', state: 'detected' },
  { tenant_id: TENANT, target_id: 'tgt_app', layer: 'waf', provider: 'provider_a', state: 'detected' },
  { tenant_id: TENANT, target_id: 'tgt_shop_alt', layer: 'waf', provider: 'provider_c', state: 'detected' },
  { tenant_id: TENANT, target_id: 'tgt_origin', layer: 'waf', provider: 'provider_a', state: 'not_detected' },
  { tenant_id: OTHER, target_id: 'tgt_alt', layer: 'waf', provider: 'provider_z', state: 'detected' },
];

function build(overrides = {}) {
  return buildProtectionValidationReport({
    tenantId: TENANT,
    generatedAt: NOW,
    targets: TARGETS,
    entryPaths: ENTRY_PATHS,
    pathEvaluations: PATH_EVALS,
    pathExpectations: PATH_EXPECTATIONS,
    firewallExpectations: FW,
    firewallEvaluations: [FW_EVAL],
    detections: DETECTIONS,
    checkCatalog: CATALOG,
    ...overrides,
  });
}

describe('protection validation report predicates', () => {
  it('rolls up scenario outcomes so unknowns outrank passes', () => {
    assert.equal(rollupPathOutcome(['consistent_enforcement', 'inconclusive']), 'inconclusive');
    assert.equal(rollupPathOutcome(['consistent_enforcement', 'scoped_application_bypass']), 'scoped_application_bypass');
    assert.equal(rollupPathOutcome([]), 'not_tested');
    assert.equal(PATH_OUTCOME_PRECEDENCE.at(-1), 'intentional_public_access');
  });

  it('selects the latest verified item per path and scenario and drops tampered or foreign evaluations', () => {
    const { selected, exclusions } = selectCurrentPathItems(PATH_EVALS, { tenantId: TENANT });
    assert.equal(selected.get(`ep_alt|${SCENARIO}`).evaluation.id, 'pvc_app');
    assert.equal(selected.has(`ep_foreign|${SCENARIO}`), false);
    assert.deepEqual(exclusions.records, [{ kind: 'evaluation', id: 'pvc_tampered', reason: 'evaluation_digest_mismatch' }]);
    assert.equal(exclusions.cross_tenant_or_invalid, 1);
  });

  it('classifies evidence tiers so observation-only checks never support readiness', () => {
    const catalog = new Map(CATALOG.map((check) => [check.check_id, check]));
    assert.deepEqual(evidenceReadinessClass({ check_id: 'waf.marker.sqli' }, catalog), { eligible: true, reason: null, tier: 'E3' });
    assert.deepEqual(evidenceReadinessClass({ check_id: 'net.tcp.reachability' }, catalog), { eligible: false, reason: 'observation_only_check', tier: 'E2' });
    assert.equal(evidenceReadinessClass({ check_id: 'unknown.check' }, catalog).reason, 'check_not_in_catalog');
  });

  it('projects matrix rows with detection separate from unattributed path enforcement', () => {
    const { rows } = projectProtectionMatrixRows({ tenantId: TENANT, entryPaths: ENTRY_PATHS.filter((row) => row.status === 'active' && row.tenant_id === TENANT), pathEvaluations: PATH_EVALS, pathExpectations: PATH_EXPECTATIONS, detections: DETECTIONS, checkCatalog: CATALOG, now: NOW });
    const row = (id) => rows.find((entry) => entry.entry_path_id === id);
    const layer = (id, name) => row(id).layers.find((entry) => entry.layer === name);
    assert.equal(row('ep_alt').outcome, 'scoped_application_bypass');
    assert.equal(layer('ep_alt', 'waf').observed_enforcement, 'not_enforced');
    assert.equal(layer('ep_alt', 'waf').attribution, 'unattributed');
    assert.equal(layer('ep_alt', 'waf').confirmed_scoped_bypass, 'confirmed');
    assert.ok(layer('ep_alt', 'waf').evidence_limitations.includes('stacked_layer_attribution_not_established'));
    assert.ok(layer('ep_alt', 'waf').evidence_limitations.includes('vendor_label_not_proof'));
    assert.equal(layer('ep_alt', 'waf').evidence_refs[0].test_run_id, 'run_alt');
    assert.equal(layer('ep_shop_alt', 'waf').vendor_detection, 'detected');
    assert.equal(layer('ep_shop_alt', 'waf').observed_enforcement, 'not_tested');
    assert.ok(layer('ep_shop_alt', 'ddos').evidence_limitations.includes('not_capacity_assurance'));
    assert.equal(layer('ep_origin', 'waf').vendor_detection, 'not_detected');
    assert.equal(layer('ep_origin', 'waf').observed_enforcement, 'inconclusive');
    assert.equal(row('ep_login').outcome, 'inconclusive');
    assert.equal(row('ep_alt').latest_comparison_id, 'pvc_app');
    for (const entry of rows) {
      for (const layerRow of entry.layers) {
        if (['enforced', 'partially_enforced', 'not_enforced'].includes(layerRow.observed_enforcement)) assert.ok(layerRow.evidence_refs.length > 0);
      }
    }
  });
});

describe('per-layer enforcement is only projected onto layers the scenario measures', () => {
  const stacked = relation('ep_stacked', 'tgt_app', { entry_target_id: 'tgt_alt', relation_kind: 'alternate_hostname', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf', 'network_firewall', 'ddos'] });
  const hidden = relation('ep_hidden_layers', 'tgt_app', { entry_target_id: 'tgt_hidden', relation_kind: 'alternate_hostname', expected_behavior: 'must_not_be_reachable', required_layers: ['waf', 'network_firewall', 'ddos'] });
  const project = (rel, args, checkId) => projectProtectionMatrixRows({
    tenantId: TENANT,
    entryPaths: [rel],
    pathEvaluations: [evaluation('path_validation', `pvc_${rel.id}`, T1, [pathItem(rel, args, [ref(`run_${rel.id}`, rel.entry_target_id, T1, checkId)])])],
    checkCatalog: CATALOG,
    now: NOW,
  }).rows[0];
  const layer = (row, name) => row.layers.find((entry) => entry.layer === name);

  it('never turns a WAF marker result into firewall or DDoS enforcement', () => {
    const row = project(stacked, { observation: 'explicit_denial_observed', enforcement: 'enforced' }, 'waf.marker.sqli');
    assert.equal(row.outcome, 'consistent_enforcement');
    assert.equal(layer(row, 'waf').observed_enforcement, 'enforced');
    for (const name of ['network_firewall', 'ddos']) {
      assert.equal(layer(row, name).observed_enforcement, 'not_tested', name);
      assert.ok(layer(row, name).evidence_limitations.includes('layer_not_measured_by_scenario'), name);
      assert.deepEqual(layer(row, name).evidence_refs, []);
    }
    assert.ok(layer(row, 'ddos').evidence_limitations.includes('not_capacity_assurance'));
  });

  it('never projects a must_not_be_reachable denial onto firewall or DDoS layers', () => {
    const row = project(hidden, { observation: 'explicit_denial_observed' }, 'origin.host_sni_bypass.safe');
    assert.equal(row.outcome, 'consistent_enforcement');
    assert.equal(layer(row, 'network_firewall').observed_enforcement, 'not_tested');
    assert.equal(layer(row, 'ddos').observed_enforcement, 'not_tested');
  });

  it('credits no layer from a check outside the catalog', () => {
    const row = project(stacked, { observation: 'explicit_denial_observed', enforcement: 'enforced' }, 'unknown.check');
    for (const name of ['waf', 'network_firewall', 'ddos']) assert.equal(layer(row, name).observed_enforcement, 'not_tested', name);
  });
});

describe('buildProtectionValidationReport', () => {
  const report = build();

  it('is a passive read model that never runs checks or sends notifications', () => {
    assert.equal(report.passive, true);
    assert.equal(report.executes_checks, false);
    assert.equal(report.sends_notifications, false);
    assert.equal(report.connectors_required, false);
    for (const file of ['src/lib/protectionValidationReport.mjs', 'src/lib/protectionValidationFindings.mjs']) {
      const source = readFileSync(new URL(`../../${file}`, import.meta.url), 'utf8');
      const imports = [...source.matchAll(/from '([^']+)'/g)].map((match) => match[1]);
      assert.deepEqual(imports.filter((path) => /services|store|notification|probe(Jobs|Worker)|worker|outbox|testRuns|fetch|http/i.test(path)), [], file);
    }
    const snapshot = JSON.stringify([ENTRY_PATHS, PATH_EVALS, FW, FW_EVAL, DETECTIONS]);
    build();
    assert.equal(JSON.stringify([ENTRY_PATHS, PATH_EVALS, FW, FW_EVAL, DETECTIONS]), snapshot);
  });

  it('keeps separate units for applications, hosts, entry paths, and target/check pairs', () => {
    assert.equal(report.units.applications.denominator, 2);
    assert.equal(report.units.applications.gap, 1);
    assert.equal(report.units.applications.incomplete, 1);
    assert.equal(report.units.hosts.denominator, 8);
    assert.equal(report.units.hosts.gap, 2);
    assert.equal(report.units.entry_paths.denominator, 9);
    assert.equal(report.units.entry_paths.by_outcome.scoped_application_bypass, 1);
    assert.equal(report.units.entry_paths.by_outcome.not_tested, 1);
    assert.equal(report.units.entry_paths.by_status.validated, 4);
    assert.equal(report.units.entry_paths.by_status.observation_only, 1);
    assert.equal(report.units.target_check_pairs.denominator, 8);
    assert.equal(report.units.target_check_pairs.observation_only, 2);
    assert.equal(report.units.target_check_pairs.readiness_eligible, 6);
    assert.equal(report.readiness.conclusions_excluded, 4);
  });

  it('does not double-count hosts detected by several providers and never treats detection as enforcement', () => {
    const waf = report.detection.layers.waf;
    assert.equal(report.detection.counts_as_enforcement, false);
    assert.equal(waf.unit, 'unique_host');
    assert.equal(waf.denominator, 8);
    assert.equal(waf.detected, 3);
    assert.equal(waf.not_detected, 1);
    assert.equal(waf.hosts_with_multiple_providers, 1);
    assert.deepEqual(waf.by_provider, { provider_a: 2, provider_b: 1, provider_c: 1 });
    assert.equal(waf.provider_counts_overlap, true);
    assert.equal(JSON.stringify(report).includes('provider_z'), false);
    const enforcement = report.enforcement.layers.waf;
    assert.equal(enforcement.attribution, 'unattributed');
    assert.equal(enforcement.denominator, 7);
    assert.equal(enforcement.not_tested, 2);
    assert.equal(enforcement.not_enforced, 1);
    assert.equal(report.enforcement.layers.ddos.denominator, 1);
    assert.equal(report.enforcement.layers.ddos.enforced, 0);
  });

  it('deduplicates hostname and URL target records in host and provider counts', () => {
    const duplicate = target('tgt_api', { kind: 'url', value: 'https://tgt_app.example.test/api' });
    const result = build({ targets: TARGETS.map((row) => row.id === duplicate.id ? duplicate : row) });
    assert.equal(result.units.entry_paths.denominator, report.units.entry_paths.denominator);
    assert.equal(result.units.hosts.denominator, report.units.hosts.denominator - 1);
    assert.equal(result.detection.layers.waf.denominator, report.detection.layers.waf.denominator - 1);
  });

  it('deduplicates IPv6 origin and bracketed URL records without confusing their paths', () => {
    const overrides = { tgt_origin: { kind: 'ip', value: '2001:db8::1' }, tgt_api: { kind: 'url', value: 'https://[2001:db8::1]/api' } };
    const result = build({ targets: TARGETS.map((row) => ({ ...row, ...(overrides[row.id] ?? {}) })) });
    assert.equal(result.units.hosts.denominator, report.units.hosts.denominator - 1);
    assert.equal(result.units.entry_paths.denominator, report.units.entry_paths.denominator);
  });

  it('excludes declaration and control-plane checks from external readiness eligibility', () => {
    const catalog = new Map([{ check_id: 'declared', probe_profile: { kind: 'metadata_marker' } }, { check_id: 'ops', probe_profile: { kind: 'ops_readiness' } }].map((row) => [row.check_id, row]));
    for (const check_id of ['declared', 'ops']) {
      const classification = evidenceReadinessClass({ check_id }, catalog);
      assert.equal(classification.eligible, false);
      assert.equal(classification.reason, 'declaration_only_check');
    }
  });

  it('does not validate an application when a required control layer has not been measured', () => {
    const primary = relation('ep_primary', 'tgt_app', { entry_target_id: 'tgt_app', relation_kind: 'primary_route', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf', 'ddos'] });
    const result = build({ entryPaths: [primary], pathEvaluations: [APP_EVAL], firewallExpectations: [], firewallEvaluations: [] });
    assert.equal(result.enforcement.layers.waf.enforced, 1);
    assert.equal(result.enforcement.layers.ddos.enforced, 0);
    assert.equal(result.units.entry_paths.by_status.validated, 0);
    assert.equal(result.units.applications.validated, 0);
    assert.equal(result.incomplete_scope.complete, false);
  });

  it('does not describe capped source records as a complete estate', () => {
    const result = build({ scope: { source_truncation: { evaluations: true } } });
    assert.equal(result.scope.source_records_complete, false);
    assert.equal(result.incomplete_scope.complete, false);
    assert.ok(result.incomplete_scope.reasons.includes('source_records_truncated'));
  });

  it('uses the expectation captured by an evaluation rather than newer layer declarations', () => {
    const old = { ...normalizePathValidationExpectation({ anchor_target_id: 'tgt_app', scenario: SCENARIO, layer_outcomes: { waf: 'enforce' } }, { tenantId: TENANT }), id: 'pvx_old' };
    const latest = { ...normalizePathValidationExpectation({ anchor_target_id: 'tgt_app', scenario: SCENARIO, layer_outcomes: { waf: 'enforce', cdn_edge: 'enforce' } }, { tenantId: TENANT, expectationVersion: 2 }), id: 'pvx_new' };
    const projected = projectProtectionMatrixRows({ tenantId: TENANT, entryPaths: [PATHS.primary], pathEvaluations: [{ ...APP_EVAL, expectation_id: old.id }], pathExpectations: [old, latest], checkCatalog: CATALOG, now: NOW });
    assert.equal(projected.rows[0].layers.find((layer) => layer.layer === 'waf').observed_enforcement, 'enforced');
    assert.equal(projected.rows[0].layers.find((layer) => layer.layer === 'cdn_edge').observed_enforcement, 'not_tested');
  });

  it('shows freshness, unknowns, exclusions, incomplete scope, and not-tested paths', () => {
    assert.equal(report.freshness.fresh, 9);
    assert.equal(report.freshness.no_evidence, 3);
    assert.equal(report.freshness.newest_observed_at, T2);
    assert.equal(report.unknowns.total, 4);
    assert.equal(report.unknowns.unresolved_conclusions, 2);
    assert.deepEqual(report.unknowns.by_reason, { no_finalized_evidence: 2, no_response_enforcement_unverified: 1, source_mismatch: 1 });
    assert.deepEqual(report.exclusions.by_reason, {
      entry_path_archived: 1,
      evaluation_digest_mismatch: 1,
      expectation_archived: 1,
      observation_only_check: 2,
      target_not_active: 1,
    });
    assert.ok(report.exclusions.other_tenant_or_invalid_rows >= 2);
    assert.equal(report.exclusions.evaluation_items_for_inactive_paths, 1);
    assert.equal(report.incomplete_scope.complete, false);
    assert.deepEqual(report.incomplete_scope.not_tested_paths, { ids: ['ep_shop_alt'], total: 1, truncated: false });
    assert.deepEqual(report.incomplete_scope.inconclusive_paths.ids, ['ep_login']);
    assert.deepEqual(report.incomplete_scope.untested_firewall_expectations.ids, ['fwx_untested']);
    assert.ok(report.incomplete_scope.reasons.includes('observation_only_evidence'));
    assert.ok(report.incomplete_scope.reasons.includes('firewall_expectations_unresolved'));
    assert.equal(JSON.stringify(report).includes('ep_foreign'), false);
    assert.equal(JSON.stringify(report).includes('tgt_foreign'), false);
  });

  it('keeps evidence-less results visible with denominators while marking them ignored for findings', () => {
    const ignored = report.conclusions.filter((conclusion) => conclusion.ignored_for_findings);
    assert.deepEqual(ignored.map((conclusion) => conclusion.subject.entry_path_id ?? conclusion.subject.expectation_id).sort(), ['ep_login', 'fwx_mixed']);
    assert.deepEqual(ignored.map((conclusion) => conclusion.result).sort(), ['inconclusive', 'not_comparable']);
    assert.ok(report.conclusions.filter((conclusion) => !conclusion.ignored_for_findings).every((conclusion) => conclusion.evidence_refs.length > 0));
    assert.equal(report.unknowns.ignored_for_findings, 3);
    assert.equal(report.unknowns.creates_findings, false);
    assert.equal(report.unknowns.counts_as_validated, false);
    assert.match(report.unknowns.statement, /never count as validated and do not create findings/);
    assert.ok(report.statements.includes(report.unknowns.statement));
    assert.equal(report.units.entry_paths.denominator, 9);
    assert.equal(report.units.entry_paths.by_status.unknown, 1);
    assert.equal(report.units.entry_paths.by_status.not_tested, 1);
    assert.equal(report.units.firewall_expectations.denominator, 4);
    assert.equal(report.units.firewall_expectations.by_status.not_comparable, 1);
    assert.equal(report.units.firewall_expectations.by_status.not_tested, 1);
    assert.equal(report.units.entry_paths.by_status.validated + report.units.firewall_expectations.by_status.accepted, 5);
    const pathFindings = deriveProtectionFindingCandidates({ evaluation: APP_EVAL, entryPaths: ENTRY_PATHS, expectations: PATH_EXPECTATIONS }).candidates;
    const fwFindings = deriveProtectionFindingCandidates({ evaluation: FW_EVAL, expectations: FW }).candidates;
    assert.equal(pathFindings.some((candidate) => candidate.observed_route.entry_path_id === 'ep_login'), false);
    assert.equal(fwFindings.some((candidate) => candidate.failed_expectation.expectation_id === 'fwx_mixed'), false);
    assert.ok(pathFindings.some((candidate) => candidate.observed_route.entry_path_id === 'ep_alt'));
  });

  it('never counts a passing outcome without finalized evidence as validated', () => {
    const unfinalized = evaluation('path_validation', 'pvc_unfinal', T2, [
      pathItem(PATHS.shopPrimary, { observation: 'explicit_denial_observed', enforcement: 'enforced' }, [{ ...ref('run_unfinal', 'tgt_shop', T2), run_status: 'running' }]),
    ]);
    const shop = build({ pathEvaluations: [unfinalized], firewallExpectations: [], firewallEvaluations: [], scope: { anchor_target_ids: ['tgt_shop'] } });
    const conclusion = shop.conclusions.find((entry) => entry.subject.entry_path_id === 'ep_shop');
    assert.equal(conclusion.result, 'consistent_enforcement');
    assert.equal(conclusion.ignored_for_findings, true);
    assert.equal(shop.units.entry_paths.by_status.validated, 0);
    assert.equal(shop.units.entry_paths.by_status.unknown, 1);
    assert.equal(shop.units.applications.validated, 0);
    assert.equal(shop.unknowns.by_reason.evidence_not_finalized, 1);
    const row = projectProtectionMatrixRows({ tenantId: TENANT, entryPaths: [PATHS.shopPrimary], pathEvaluations: [unfinalized], pathExpectations: PATH_EXPECTATIONS, checkCatalog: CATALOG, now: NOW }).rows[0];
    assert.equal(row.layers.find((entry) => entry.layer === 'waf').observed_enforcement, 'inconclusive');
    assert.deepEqual(deriveProtectionFindingCandidates({ evaluation: unfinalized, entryPaths: ENTRY_PATHS }).passing, []);
  });

  it('reports firewall expectations without inflating acceptance or readiness', () => {
    assert.deepEqual(report.units.firewall_expectations.by_status, { accepted: 1, gap: 1, inconclusive: 0, not_tested: 1, stale: 0, not_comparable: 1 });
    assert.equal(report.units.firewall_expectations.gaps.forbidden_service_newly_reachable, 1);
    assert.equal(report.readiness.inflates_readiness, false);
    const gap = report.conclusions.find((conclusion) => conclusion.subject.expectation_id === 'fwx_gap');
    assert.equal(gap.readiness_eligible, false);
    assert.equal(gap.readiness_exclusion_reason, 'observation_only_check');
    for (const limitation of REQUIRED_LIMITATIONS.firewall_change) assert.ok(report.limitations.includes(limitation));
    assert.ok(report.statements.some((statement) => /rule-table, routing, NAT, egress, east-west/i.test(statement)));
    assert.doesNotMatch(JSON.stringify(report), /ddos protected|all controls bypassed/i);
  });

  it('marks passing evidence stale outside the freshness window instead of validated', () => {
    const later = build({ generatedAt: '2026-12-31T00:00:00.000Z' });
    assert.equal(later.units.entry_paths.by_status.validated, 0);
    assert.equal(later.units.entry_paths.by_status.stale, 5);
    assert.equal(later.units.entry_paths.by_status.observation_only, 0);
    assert.equal(later.units.firewall_expectations.by_status.stale, 1);
    assert.ok(later.incomplete_scope.reasons.includes('stale_evidence'));
  });

  it('reconstructs every conclusion from the captured evaluation references', () => {
    assert.equal(report.conclusions.length, report.conclusions_total);
    for (const conclusion of report.conclusions) {
      assert.deepEqual(verifyProtectionReportConclusion(conclusion, [...PATH_EVALS, FW_EVAL]), { ok: true, reason: null }, conclusion.id);
      assert.ok(conclusion.evaluation_digest);
      assert.equal(conclusion.attribution, 'unattributed');
    }
    const sample = report.conclusions.find((conclusion) => conclusion.subject.entry_path_id === 'ep_alt');
    assert.equal(sample.result, 'scoped_application_bypass');
    assert.equal(verifyProtectionReportConclusion({ ...sample, result: 'consistent_enforcement' }, PATH_EVALS).reason, 'result_mismatch');
    assert.equal(verifyProtectionReportConclusion({ ...sample, evidence_refs: [] }, PATH_EVALS).reason, 'evidence_refs_mismatch');
    assert.equal(verifyProtectionReportConclusion(sample, []).reason, 'evaluation_missing');
    assert.equal(verifyProtectionReportConclusion({ ...sample, evaluation_id: 'pvc_tampered' }, PATH_EVALS).reason, 'evaluation_digest_mismatch');
  });

  it('scopes by anchor and reports empty scope explicitly', () => {
    const shop = build({ scope: { anchor_target_ids: ['tgt_shop'] } });
    assert.equal(shop.units.applications.denominator, 1);
    assert.equal(shop.units.entry_paths.denominator, 3);
    const empty = buildProtectionValidationReport({ tenantId: TENANT, generatedAt: NOW });
    assert.equal(empty.units.applications.denominator, 0);
    assert.equal(empty.incomplete_scope.complete, false);
    assert.deepEqual(empty.incomplete_scope.reasons, ['no_declared_scope']);
    assert.deepEqual(empty.conclusions, []);
  });

  it('exports CSV with formula-injection protection', () => {
    const csv = protectionValidationReportCsv(report);
    const lines = csv.trim().split('\n');
    assert.equal(lines.length, report.conclusions.length + 1);
    assert.match(lines[0], /^conclusion_id,comparison_kind/);
    assert.ok(lines[0].split(',').includes('ignored_for_findings'));
    const crafted = protectionValidationReportCsv({ conclusions: [{ id: '=HYPERLINK("x")', comparison_kind: 'path_validation', unit: 'entry_path', subject: { entry_path_id: '+1', entry_target_id: '@t' }, result: '-x', evaluation_id: 'e', item_index: 0, evidence_refs: [] }] });
    const row = crafted.trim().split('\n')[1];
    assert.ok(row.startsWith(`"'=HYPERLINK(""x"")"`));
    assert.ok(row.includes(",'+1,'@t,"));
    assert.ok(row.includes(",'-x,"));
  });
});

describe('firewall report selection (D11c)', () => {
  it('keeps an earlier sampled firewall result when a later partial comparison never sampled that expectation', () => {
    const later = evaluation('firewall_change', 'fwc_2', NOW, [
      { expectation_id: FW[0].id, status: 'not_tested', gap_kind: null, expectation_met: null, pre_state: null, post_state: null, reasons: ['post_change_not_sampled'], compatibility_reasons: [], limitations: [...REQUIRED_LIMITATIONS.firewall_change], evidence_refs: [] },
      fwItem(FW[1], ['explicit_denial_observed'], ['explicit_denial_observed']),
    ], { baseline_id: 'fwb_1', baseline_digest: 'b'.repeat(64) });
    const { selected } = selectCurrentFirewallItems([FW_EVAL, later], { tenantId: TENANT });
    assert.equal(selected.get(FW[0].id).evaluation.id, 'fwc_1');
    assert.equal(selected.get(FW[1].id).evaluation.id, 'fwc_2');
    const reversed = selectCurrentFirewallItems([later, FW_EVAL], { tenantId: TENANT }).selected;
    assert.equal(reversed.get(FW[0].id).evaluation.id, 'fwc_1');
  });
});
