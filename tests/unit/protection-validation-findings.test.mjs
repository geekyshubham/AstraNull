import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import {
  REQUIRED_LIMITATIONS,
  classifyFirewallComparisonItem,
  classifyPathValidationItem,
  normalizeComparisonEvaluation,
  normalizeEntryPathDeclaration,
  normalizeFirewallExpectation,
  normalizePathValidationExpectation,
} from '../../src/contracts/protectionValidation.mjs';
import { findingMatchesListQuery, findingSeverityClass, parseFindingListQuery } from '../../src/lib/findingList.mjs';
import {
  CANDIDATE_EXPLANATIONS,
  LEGACY_PROTECTION_FINDING_CLASSES,
  PROTECTION_FINDING_CLASSES,
  UNAVAILABLE_EVIDENCE_SKIP_REASON,
  applyProtectionFindingPatch,
  assessProtectionRetestAuthorization,
  dedupeProtectionFindingCandidates,
  deriveProtectionFindingCandidates,
  isProtectionValidationFinding,
  planProtectionFindingUpsert,
  protectionFindingClosureSignal,
  protectionRetestContext,
  protectionRetestRunScopeMatches,
  toProtectionFindingRow,
  verifyProtectionEvaluation,
} from '../../src/lib/protectionValidationFindings.mjs';
import {
  listFindingLineage,
  planRetestRegistration,
  presentFindingLineage,
  registerRetestLineage,
} from '../../src/services/retestLineage.mjs';
import { upsertProtectionFindingsFromEvaluation } from '../../src/services/findings.mjs';
import { getStore } from '../../src/store.mjs';

const TENANT = 'ten_pvf';
const OTHER = 'ten_pvf_other';
const SCENARIO = 'waf.sqli.marker';
const T1 = '2026-10-01T10:00:00.000Z';
const T2 = '2026-10-03T10:00:00.000Z';
const ENGINEER = { tenantId: TENANT, userId: 'usr_eng', role: 'engineer' };

it('cannot register an origin finding retest against an unbound or different origin run', () => {
  const finding = { id: 'fnd_origin_bound', tenant_id: TENANT, target_id: 'tgt_origin', check_id: 'origin.host_sni_bypass.safe', source: 'protection_validation',
    protection_validation: { comparison_kind: 'path_validation', observed_route: { origin_binding_id: 'ob_1' } } };
  const run = { id: 'run_origin_retest', tenant_id: TENANT, target_id: finding.target_id, check_id: finding.check_id };
  assert.equal(protectionRetestRunScopeMatches(finding, { ...run, origin_binding_id: 'ob_1' }), true);
  for (const origin_binding_id of [undefined, 'ob_other']) {
    const result = planRetestRegistration({ finding, run: { ...run, origin_binding_id }, intent: 'retest', authorization: { ok: true } });
    assert.equal(result.error, 'retest_not_authorized');
    assert.equal(result.reason, 'retest_scope_mismatch');
  }
});
const VIEWER = { tenantId: TENANT, userId: 'usr_view', role: 'viewer' };

function relation(id, body, version = 1, tenantId = TENANT) {
  const record = normalizeEntryPathDeclaration(body, { tenantId, anchorTargetId: 'tgt_app', declarationVersion: version });
  return { ...record, id };
}

const PATHS = {
  primary: relation('ep_primary', { entry_target_id: 'tgt_app', relation_kind: 'primary_route', owner: 'App Team', purpose: 'Main site', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf', 'cdn_edge'] }),
  alt: relation('ep_alt', { entry_target_id: 'tgt_alt', relation_kind: 'alternate_hostname', owner: 'App Team', purpose: 'Legacy host', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf', 'cdn_edge'] }),
  origin: relation('ep_origin', { entry_target_id: 'tgt_origin', relation_kind: 'origin', origin_binding_id: 'ob_1', owner: 'Platform', purpose: 'Origin', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'] }),
  hidden: relation('ep_hidden', { entry_target_id: 'tgt_hidden', relation_kind: 'fallback_backend_route', owner: 'Platform', purpose: 'Backend', expected_behavior: 'must_not_be_reachable' }),
  api: relation('ep_api', { entry_target_id: 'tgt_api', relation_kind: 'declared_api_url', owner: 'API Team', purpose: 'Public API', expected_behavior: 'intentionally_public' }),
  login: relation('ep_login', { entry_target_id: 'tgt_login', relation_kind: 'declared_login_url', owner: 'Identity', purpose: 'Login', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'] }),
};
const ENTRY_PATHS = Object.values(PATHS);
const PATH_EXPECTATION = { ...normalizePathValidationExpectation({ scenario: SCENARIO, layer_outcomes: { waf: 'enforce', cdn_edge: 'enforce' } }, { tenantId: TENANT, anchorTargetId: 'tgt_app' }), id: 'pvx_1' };

function ref(run, targetId, observedAt, checkId = 'waf.marker.sqli') {
  return {
    test_run_id: run,
    check_id: checkId,
    check_version: '1.1.0',
    scenario_version: 's1',
    verdict_id: `vrd_${run}`,
    evidence_ids: [`ev_${run}`],
    target_id: targetId,
    observed_at: observedAt,
    run_status: 'verdicted',
    source_perspective: 'public-worker-eu',
    worker_id: 'worker_eu_1',
  };
}

function pathItem(rel, args, refs, scenario = SCENARIO) {
  const classified = classifyPathValidationItem({ relation: rel, primaryBaselineHealth: 'healthy', primaryEnforcement: 'enforced', ...args });
  return { entry_path_id: rel.id, scenario, ...classified, evidence_refs: refs };
}

function pathEvaluation({ id, at, suffix = '1', tenantId = TENANT, items }) {
  const evaluation = normalizeComparisonEvaluation({
    kind: 'path_validation',
    tenant_id: tenantId,
    evaluated_at: at,
    items: items ?? [
      pathItem(PATHS.primary, { observation: 'explicit_denial_observed', enforcement: 'enforced' }, [ref(`run_p${suffix}`, 'tgt_app', at)]),
      pathItem(PATHS.alt, { observation: 'application_identity_confirmed', enforcement: 'not_enforced' }, [ref(`run_a${suffix}`, 'tgt_alt', at)]),
      pathItem(PATHS.origin, { observation: 'response_observed', enforcement: 'unknown' }, [ref(`run_o${suffix}`, 'tgt_origin', at, 'origin.host_sni_bypass.safe')]),
      pathItem(PATHS.hidden, { observation: 'response_observed' }, [ref(`run_h${suffix}`, 'tgt_hidden', at, 'origin.direct_reachability.safe')]),
      pathItem(PATHS.api, { observation: 'response_observed' }, [ref(`run_api${suffix}`, 'tgt_api', at)]),
      pathItem(PATHS.login, { observation: 'no_response' }, []),
    ],
  });
  return { ...evaluation, id, anchor_target_id: 'tgt_app', primary_entry_path_id: 'ep_primary', reviewed_plan_digest: 'a'.repeat(64) };
}

function byPath(candidates, entryPathId) {
  return candidates.find((candidate) => candidate.observed_route.entry_path_id === entryPathId);
}

const FW_DENY = { ...normalizeFirewallExpectation({ destination_target_id: 'tgt_fw', protocol: 'tcp', port: 22, expected: 'deny', source_perspective: 'public-worker-eu', change_id: 'CHG-1', owner: 'Network Team' }, { tenantId: TENANT }), id: 'fwx_deny' };
const FW_ALLOW = { ...normalizeFirewallExpectation({ destination_target_id: 'tgt_fw', protocol: 'service', service_endpoint: { service: 'https', port: 443, path: '/health' }, expected: 'allow', source_perspective: 'public-worker-eu', change_id: 'CHG-1' }, { tenantId: TENANT }), id: 'fwx_allow' };
const FW_STILL = { ...normalizeFirewallExpectation({ destination_target_id: 'tgt_fw', protocol: 'tcp', port: 3389, expected: 'deny', source_perspective: 'public-worker-eu', change_id: 'CHG-1' }, { tenantId: TENANT }), id: 'fwx_still' };
const FW_IMPROVED = { ...normalizeFirewallExpectation({ destination_target_id: 'tgt_fw', protocol: 'tcp', port: 23, expected: 'deny', source_perspective: 'public-worker-eu', change_id: 'CHG-1' }, { tenantId: TENANT }), id: 'fwx_improved' };
const FW_MISMATCH = { ...normalizeFirewallExpectation({ destination_target_id: 'tgt_fw', protocol: 'udp', port: 53, expected: 'deny', source_perspective: 'public-worker-eu', change_id: 'CHG-1' }, { tenantId: TENANT }), id: 'fwx_mismatch' };
const FW_EXPECTATIONS = [FW_DENY, FW_ALLOW, FW_STILL, FW_IMPROVED, FW_MISMATCH];
const COMPATIBLE = { comparable: true, stale: false, reasons: [] };
const FW_BASELINE = {
  id: 'fwb_1',
  change_id: 'CHG-1',
  baseline_digest: 'b'.repeat(64),
  captured_at: T1,
  entries: FW_EXPECTATIONS.map((exp) => ({ expectation_id: exp.id, expectation_version: 1, expectation_digest: exp.digest, baseline_digest: exp.digest.replace(/^./, 'c'), captured_at: T1, destination_mapping: null })),
};

function fwItem(expectation, baseline, candidate, compatibility = COMPATIBLE, run = 'run_fw') {
  const classified = classifyFirewallComparisonItem({ expectation, baseline, candidate, compatibility });
  return { expectation_id: expectation.id, ...classified, evidence_refs: [ref(`${run}_${expectation.id}`, 'tgt_fw', T2, 'net.tcp.reachability')] };
}

function firewallEvaluation(id = 'fwc_1') {
  const evaluation = normalizeComparisonEvaluation({
    kind: 'firewall_change',
    tenant_id: TENANT,
    baseline_id: 'fwb_1',
    baseline_digest: 'b'.repeat(64),
    evaluated_at: T2,
    items: [
      fwItem(FW_DENY, ['explicit_denial_observed'], ['reachable_transport_only']),
      fwItem(FW_ALLOW, ['service_response_observed'], ['no_response', 'no_response']),
      fwItem(FW_STILL, ['service_response_observed'], ['service_response_observed']),
      fwItem(FW_IMPROVED, ['service_response_observed'], ['explicit_denial_observed']),
      { ...fwItem(FW_MISMATCH, ['explicit_denial_observed'], ['udp_silence'], { comparable: false, stale: false, reasons: ['source_mismatch'] }), evidence_refs: [] },
    ],
  });
  return { ...evaluation, id };
}

const ASSERTIVE_EXPLANATION = /monitor|disabled|rule is|routing|bypass(es|ed) the (waf|firewall)|ddos protected|all controls/i;

describe('protection finding candidates from path evaluations', () => {
  const evaluation = pathEvaluation({ id: 'pvc_1', at: T1 });
  const derived = deriveProtectionFindingCandidates({ evaluation, entryPaths: ENTRY_PATHS, expectations: [PATH_EXPECTATION] });

  it('keeps a finding check id paired with its selected newest run when evidence includes multiple checks', () => {
    const mixed = pathEvaluation({ id: 'pvc_mixed', at: T2, items: [pathItem(PATHS.alt,
      { observation: 'application_identity_confirmed', enforcement: 'not_enforced' },
      [ref('run_old', 'tgt_alt', T1, 'aaa.old.safe'), ref('run_new', 'tgt_alt', T2, 'zzz.new.safe')])],
    });
    const candidate = deriveProtectionFindingCandidates({ evaluation: mixed, entryPaths: ENTRY_PATHS, expectations: [PATH_EXPECTATION] }).candidates[0];
    assert.equal(candidate.test_run_id, 'run_new');
    assert.equal(candidate.check_id, 'zzz.new.safe');
    assert.equal(candidate.verdict_id, 'vrd_run_new');
  });

  it('verifies the recorded evaluation digest before deriving anything', () => {
    assert.equal(verifyProtectionEvaluation(evaluation).ok, true);
    assert.equal(derived.ok, true);
    const tampered = { ...evaluation, items: evaluation.items.map((item, index) => (index === 1 ? { ...item, outcome: 'consistent_enforcement' } : item)) };
    assert.deepEqual(deriveProtectionFindingCandidates({ evaluation: tampered, entryPaths: ENTRY_PATHS }), { ok: false, error: 'evaluation_digest_mismatch', candidates: [], passing: [], skipped: [] });
    const unrecorded = { ...evaluation };
    delete unrecorded.id;
    assert.equal(deriveProtectionFindingCandidates({ evaluation: unrecorded }).error, 'evaluation_not_recorded');
  });

  it('distinguishes confirmed exposure and suspected bypass, and ignores unavailable evidence', () => {
    assert.equal(byPath(derived.candidates, 'ep_alt').finding_class, 'confirmed_exposure');
    assert.equal(byPath(derived.candidates, 'ep_alt').observed.outcome, 'scoped_application_bypass');
    assert.equal(byPath(derived.candidates, 'ep_alt').priority, 'p1');
    assert.equal(byPath(derived.candidates, 'ep_alt').severity, 'critical');
    assert.equal(byPath(derived.candidates, 'ep_origin').finding_class, 'suspected_bypass');
    assert.deepEqual(byPath(derived.candidates, 'ep_origin').observed.reasons, ['enforcement_not_measured']);
    assert.equal(byPath(derived.candidates, 'ep_hidden').finding_class, 'confirmed_exposure');
    assert.equal(byPath(derived.candidates, 'ep_hidden').observed.outcome, 'reachability_exposure');
    assert.equal(byPath(derived.candidates, 'ep_login'), undefined);
    assert.deepEqual(derived.skipped, [{ item_index: 5, reason: UNAVAILABLE_EVIDENCE_SKIP_REASON, observation: 'inconclusive' }]);
    assert.equal(byPath(derived.candidates, 'ep_primary'), undefined);
    assert.equal(byPath(derived.candidates, 'ep_api'), undefined);
    assert.deepEqual(derived.passing.map((row) => row.observation).sort(), ['consistent_enforcement', 'intentional_public_access']);
    assert.ok(derived.passing.every((row) => row.closes_findings === false));
    for (const candidate of derived.candidates) assert.ok(PROTECTION_FINDING_CLASSES.includes(candidate.finding_class));
    assert.equal(PROTECTION_FINDING_CLASSES.includes('unavailable_evidence'), false);
    assert.deepEqual(LEGACY_PROTECTION_FINDING_CLASSES, ['unavailable_evidence']);
  });

  it('classifies suspected routes and weaker enforcement without promoting them', () => {
    const evaluationB = pathEvaluation({
      id: 'pvc_weak',
      at: T1,
      items: [
        pathItem(PATHS.alt, { observation: 'response_observed', enforcement: 'not_enforced' }, [ref('run_s', 'tgt_alt', T1)]),
        pathItem(PATHS.login, { observation: 'response_observed', enforcement: 'partial' }, [ref('run_w', 'tgt_login', T1)]),
        pathItem(PATHS.origin, { skipped: true }, []),
      ],
    });
    const result = deriveProtectionFindingCandidates({ evaluation: evaluationB, entryPaths: ENTRY_PATHS, expectations: [PATH_EXPECTATION] });
    assert.equal(byPath(result.candidates, 'ep_alt').finding_class, 'suspected_bypass');
    assert.equal(byPath(result.candidates, 'ep_alt').observed.outcome, 'suspected_alternate_application_route');
    assert.equal(byPath(result.candidates, 'ep_login').finding_class, 'observed_enforcement_gap');
    assert.equal(byPath(result.candidates, 'ep_origin'), undefined);
    assert.deepEqual(result.skipped, [{ item_index: 2, reason: UNAVAILABLE_EVIDENCE_SKIP_REASON, observation: 'skipped' }]);
    const legacyOptIn = deriveProtectionFindingCandidates({ evaluation: evaluationB, entryPaths: ENTRY_PATHS, includeUnavailableEvidence: true });
    assert.equal(byPath(legacyOptIn.candidates, 'ep_origin'), undefined, 'the retired opt-in cannot bring unavailable-evidence findings back');
  });

  it('carries application, expectation, scenario, layers, route, evidence, limitations, owner, and priority', () => {
    const bypass = byPath(derived.candidates, 'ep_alt');
    assert.equal(bypass.tenant_id, TENANT);
    assert.deepEqual(bypass.application, { anchor_target_id: 'tgt_app' });
    assert.equal(bypass.target_id, 'tgt_alt');
    assert.equal(bypass.check_id, 'waf.marker.sqli');
    assert.equal(bypass.test_run_id, 'run_a1');
    assert.deepEqual(bypass.evidence_ids, ['ev_run_a1']);
    assert.equal(bypass.scenario, SCENARIO);
    assert.deepEqual(bypass.required_layers, ['waf', 'cdn_edge']);
    assert.equal(bypass.failed_expectation.expectation_id, 'pvx_1');
    assert.equal(bypass.failed_expectation.expectation_digest, PATH_EXPECTATION.digest);
    assert.deepEqual(bypass.failed_expectation.layer_outcomes, { waf: 'enforce', cdn_edge: 'enforce' });
    assert.deepEqual(bypass.observed_route, { entry_path_id: 'ep_alt', anchor_target_id: 'tgt_app', entry_target_id: 'tgt_alt', relation_kind: 'alternate_hostname', origin_binding_id: null });
    assert.equal(bypass.evidence_refs.length, 1);
    assert.deepEqual(Object.keys(bypass.evidence_refs[0]).sort(), ['check_id', 'check_version', 'evidence_ids', 'finalized', 'observed_at', 'run_status', 'scenario_version', 'source_perspective', 'target_id', 'test_run_id', 'verdict_id', 'worker_id']);
    for (const limitation of REQUIRED_LIMITATIONS.path_validation) assert.ok(bypass.limitations.includes(limitation));
    assert.equal(bypass.owner, 'App Team');
    assert.equal(bypass.attribution, 'unattributed');
    assert.equal(bypass.control_identified, false);
    assert.equal(bypass.comparison_context.declaration_digest, PATHS.alt.declaration_digest);
    assert.equal(bypass.comparison_context.declaration_version, 1);
    assert.equal(bypass.comparison_context.evaluation_digest, evaluation.evaluation_digest);
    assert.equal(bypass.reconstruction.item_index, 1);
    assert.equal(evaluation.items[bypass.reconstruction.item_index].outcome, bypass.observed.outcome);
  });

  it('only offers monitor mode, disabled rules, or routing as uncorroborated candidates', () => {
    for (const candidate of derived.candidates) {
      assert.doesNotMatch(`${candidate.title} ${candidate.summary}`, ASSERTIVE_EXPLANATION);
      for (const explanation of candidate.candidate_explanations) {
        assert.equal(explanation.status, 'candidate');
        assert.equal(explanation.corroborated, false);
        assert.match(explanation.label, /^Not established:/);
        assert.ok(Object.hasOwn(CANDIDATE_EXPLANATIONS, explanation.code));
      }
    }
    assert.ok(byPath(derived.candidates, 'ep_alt').candidate_explanations.some((entry) => entry.code === 'waf_policy_monitor_mode'));
  });

  it('keeps the dedupe key stable across retests and declaration versions', () => {
    const retest = pathEvaluation({ id: 'pvc_2', at: T2, suffix: '2' });
    const again = deriveProtectionFindingCandidates({ evaluation: retest, entryPaths: ENTRY_PATHS, expectations: [PATH_EXPECTATION] });
    assert.equal(byPath(again.candidates, 'ep_alt').dedupe_key, byPath(derived.candidates, 'ep_alt').dedupe_key);
    assert.notEqual(byPath(again.candidates, 'ep_alt').test_run_id, byPath(derived.candidates, 'ep_alt').test_run_id);
    assert.equal(byPath(derived.candidates, 'ep_alt').dedupe_basis, 'entry_path_scope');
    const v2 = relation('ep_alt_v2', { entry_target_id: 'tgt_alt', relation_kind: 'alternate_hostname', owner: 'New Owner', purpose: 'Legacy host', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'] }, 2);
    const v2Eval = pathEvaluation({ id: 'pvc_3', at: T2, items: [pathItem(v2, { observation: 'application_identity_confirmed', enforcement: 'not_enforced' }, [ref('run_v2', 'tgt_alt', T2)])] });
    const v2Candidate = deriveProtectionFindingCandidates({ evaluation: v2Eval, entryPaths: [v2] }).candidates[0];
    assert.equal(v2Candidate.dedupe_key, byPath(derived.candidates, 'ep_alt').dedupe_key);
    const otherScenario = pathEvaluation({ id: 'pvc_4', at: T2, items: [pathItem(PATHS.alt, { observation: 'application_identity_confirmed', enforcement: 'not_enforced' }, [ref('run_x', 'tgt_alt', T2)], 'waf.xss.marker')] });
    assert.notEqual(deriveProtectionFindingCandidates({ evaluation: otherScenario, entryPaths: ENTRY_PATHS }).candidates[0].dedupe_key, byPath(derived.candidates, 'ep_alt').dedupe_key);
    const otherAlt = relation('ep_alt', { entry_target_id: 'tgt_alt', relation_kind: 'alternate_hostname', owner: 'App Team', purpose: 'Legacy host', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf', 'cdn_edge'] }, 1, OTHER);
    const otherTenant = pathEvaluation({ id: 'pvc_5', at: T2, tenantId: OTHER, items: [pathItem(otherAlt, { observation: 'application_identity_confirmed', enforcement: 'not_enforced' }, [ref('run_t', 'tgt_alt', T2)])] });
    assert.notEqual(deriveProtectionFindingCandidates({ evaluation: otherTenant, entryPaths: [otherAlt] }).candidates[0].dedupe_key, byPath(derived.candidates, 'ep_alt').dedupe_key);
  });

  it('ignores relations and expectations from another tenant', () => {
    const foreign = { ...PATHS.alt, tenant_id: OTHER, owner: 'Foreign' };
    const result = deriveProtectionFindingCandidates({ evaluation, entryPaths: [foreign] });
    assert.equal(byPath(result.candidates, 'ep_alt').owner, null);
    assert.equal(byPath(result.candidates, 'ep_alt').dedupe_basis, 'entry_path_id');
  });

  it('dedupes candidates across evaluations, keeping the latest observation and the strongest class seen', () => {
    const later = pathEvaluation({
      id: 'pvc_later',
      at: T2,
      items: [pathItem(PATHS.alt, { observation: 'response_observed', enforcement: 'not_enforced' }, [ref('run_later', 'tgt_alt', T2)])],
    });
    const laterCandidates = deriveProtectionFindingCandidates({ evaluation: later, entryPaths: ENTRY_PATHS }).candidates;
    const merged = dedupeProtectionFindingCandidates([...derived.candidates, ...laterCandidates]);
    const alt = merged.filter((candidate) => candidate.observed_route.entry_path_id === 'ep_alt');
    assert.equal(alt.length, 1);
    assert.equal(alt[0].comparison_context.evaluation_id, 'pvc_later');
    assert.equal(alt[0].finding_class, 'suspected_bypass');
    assert.equal(alt[0].strongest_observed_class, 'confirmed_exposure');
    assert.deepEqual(alt[0].source_evaluation_ids, ['pvc_1', 'pvc_later']);
    assert.equal(merged.length, derived.candidates.length);
  });

  it('creates zero findings when every item lacks evidence', () => {
    const empty = pathEvaluation({
      id: 'pvc_empty',
      at: T2,
      items: [
        pathItem(PATHS.alt, { observation: 'no_response' }, []),
        pathItem(PATHS.origin, { skipped: true }, []),
        pathItem(PATHS.login, { observation: 'no_response' }, []),
      ],
    });
    const result = deriveProtectionFindingCandidates({ evaluation: empty, entryPaths: ENTRY_PATHS, expectations: [PATH_EXPECTATION] });
    assert.equal(result.ok, true);
    assert.deepEqual(result.candidates, []);
    assert.deepEqual(result.passing, []);
    assert.deepEqual(result.skipped.map((row) => row.reason), [UNAVAILABLE_EVIDENCE_SKIP_REASON, UNAVAILABLE_EVIDENCE_SKIP_REASON, UNAVAILABLE_EVIDENCE_SKIP_REASON]);
    assert.deepEqual(dedupeProtectionFindingCandidates(result.candidates), []);
  });

  it('never counts a passing outcome without finalized evidence as success', () => {
    const evaluationU = pathEvaluation({ id: 'pvc_unfinal', at: T2, items: [pathItem(PATHS.alt, { observation: 'explicit_denial_observed', enforcement: 'enforced' }, [{ ...ref('run_u', 'tgt_alt', T2), run_status: 'running' }])] });
    assert.equal(evaluationU.items[0].outcome, 'consistent_enforcement');
    assert.equal(evaluationU.items[0].evidence_refs[0].finalized, false);
    const result = deriveProtectionFindingCandidates({ evaluation: evaluationU, entryPaths: ENTRY_PATHS });
    assert.deepEqual(result.passing, []);
    assert.deepEqual(result.candidates, []);
    assert.equal(result.skipped[0].reason, UNAVAILABLE_EVIDENCE_SKIP_REASON);
  });
});

it('binds a firewall migration finding and its retest to the mapped post-change target', () => {
  const expectation = { ...normalizeFirewallExpectation({
    destination_target_id: 'tgt_pre', protocol: 'tcp', port: 443, expected: 'deny', source_perspective: 'public-worker-eu', change_id: 'CHG-mapped',
    pre_post_mapping: { pre_destination_target_id: 'tgt_pre', post_destination_target_id: 'tgt_post', declared_by_customer: true },
  }, { tenantId: TENANT }), id: 'fwx_mapped' };
  const reference = { test_run_id: 'run_mapped_post', check_id: 'l3.basic_deny_rule.safe', check_version: '1.0.0', scenario_version: null,
    verdict_id: 'vrd_mapped_post', evidence_ids: ['evt_mapped_post'], target_id: 'tgt_post', observed_at: T2, run_status: 'verdicted',
    source_perspective: 'public-worker-eu', worker_id: 'worker_1' };
  const evaluation = { ...normalizeComparisonEvaluation({ kind: 'firewall_change', tenant_id: TENANT, evaluated_at: T2,
    items: [{ expectation_id: expectation.id, ...classifyFirewallComparisonItem({ expectation, baseline: ['explicit_denial_observed'], candidate: ['reachable_transport_only'], compatibility: { comparable: true, reasons: [] } }), evidence_refs: [reference] }],
  }), id: 'fwc_mapped' };
  const derived = deriveProtectionFindingCandidates({ evaluation, expectations: [expectation] });
  assert.equal(derived.candidates[0].target_id, 'tgt_post');
  assert.equal(derived.candidates[0].test_run_id, reference.test_run_id);
  const finding = toProtectionFindingRow(derived.candidates[0], { id: 'fnd_mapped', now: T2 });
  assert.equal(assessProtectionRetestAuthorization({ finding, tenantId: TENANT, expectation, destinationTarget: { id: 'tgt_post', tenant_id: TENANT }, ownershipVerified: true }).ok, true);
});

describe('protection finding candidates from firewall evaluations', () => {
  const evaluation = firewallEvaluation();
  const derived = deriveProtectionFindingCandidates({ evaluation, expectations: FW_EXPECTATIONS, baseline: FW_BASELINE });
  const byExpectation = (id) => derived.candidates.find((candidate) => candidate.failed_expectation.expectation_id === id);

  it('classifies regressions and unchanged failures as observed gaps without inventing a cause', () => {
    assert.equal(derived.ok, true);
    assert.equal(byExpectation('fwx_deny').finding_class, 'confirmed_exposure');
    assert.equal(byExpectation('fwx_deny').observed.gap_kind, 'forbidden_service_newly_reachable');
    assert.equal(byExpectation('fwx_deny').observed.change_effect, 'regression');
    assert.equal(byExpectation('fwx_allow').finding_class, 'observed_availability_gap');
    assert.equal(byExpectation('fwx_allow').observed.gap_kind, 'required_service_newly_unavailable');
    assert.equal(byExpectation('fwx_still').finding_class, 'confirmed_exposure');
    assert.equal(byExpectation('fwx_still').observed.change_effect, 'unchanged_failure');
    assert.equal(byExpectation('fwx_improved'), undefined);
    assert.equal(byExpectation('fwx_mismatch'), undefined);
    assert.deepEqual(derived.skipped, [{ item_index: 4, reason: UNAVAILABLE_EVIDENCE_SKIP_REASON, observation: 'not_comparable' }]);
    for (const candidate of derived.candidates) {
      assert.doesNotMatch(`${candidate.title} ${candidate.summary}`, ASSERTIVE_EXPLANATION);
      assert.equal(candidate.observed.rule_id, undefined);
      assert.ok(candidate.candidate_explanations.every((entry) => entry.corroborated === false));
      for (const limitation of REQUIRED_LIMITATIONS.firewall_change) assert.ok(candidate.limitations.includes(limitation));
    }
  });

  it('retains baseline versions, expectation digests, route, owner, and change context', () => {
    const deny = byExpectation('fwx_deny');
    assert.equal(deny.target_id, 'tgt_fw');
    assert.equal(deny.owner, 'Network Team');
    assert.deepEqual(deny.required_layers, ['network_firewall']);
    assert.equal(deny.observed_route.port, 22);
    assert.equal(deny.observed_route.source_perspective, 'public-worker-eu');
    assert.equal(deny.failed_expectation.expected, 'deny');
    assert.equal(deny.failed_expectation.change_id, 'CHG-1');
    assert.equal(deny.comparison_context.baseline_id, 'fwb_1');
    assert.equal(deny.comparison_context.baseline_digest, 'b'.repeat(64));
    assert.equal(deny.comparison_context.baseline_entry_digest, FW_BASELINE.entries[0].baseline_digest);
    assert.equal(deny.comparison_context.expectation_version, 1);
    assert.equal(deny.comparison_context.expectation_digest, FW_DENY.digest);
    assert.match(deny.title, /CHG-1/);
  });

  it('keeps the firewall dedupe key stable across retests and changes of the same scope', () => {
    const retest = firewallEvaluation('fwc_2');
    const again = deriveProtectionFindingCandidates({ evaluation: retest, expectations: FW_EXPECTATIONS, baseline: FW_BASELINE });
    assert.equal(again.candidates.find((c) => c.failed_expectation.expectation_id === 'fwx_deny').dedupe_key, byExpectation('fwx_deny').dedupe_key);
    assert.notEqual(byExpectation('fwx_deny').dedupe_key, byExpectation('fwx_still').dedupe_key);
  });
});

describe('protection finding lifecycle planning', () => {
  const derived = deriveProtectionFindingCandidates({ evaluation: pathEvaluation({ id: 'pvc_1', at: T1 }), entryPaths: ENTRY_PATHS, expectations: [PATH_EXPECTATION] });
  const bypass = byPath(derived.candidates, 'ep_alt');
  const unavailable = { ...bypass, finding_class: 'unavailable_evidence', priority: 'p4', severity: 'low' };
  const suspected = { ...bypass, finding_class: 'suspected_bypass', priority: 'p2', severity: 'high' };
  const row = (status, extra = {}) => ({ ...toProtectionFindingRow(suspected, { id: `fnd_${status}`, now: T1 }), status, ...extra });

  it('creates a new finding only when no finding exists for the dedupe key', () => {
    assert.equal(planProtectionFindingUpsert({ existingFindings: [], candidate: bypass }).action, 'create');
    assert.equal(planProtectionFindingUpsert({ existingFindings: [{ ...row('open'), tenant_id: OTHER }], candidate: bypass }).action, 'create');
  });

  it('escalates an open finding but never downgrades or closes it', () => {
    const escalated = planProtectionFindingUpsert({ existingFindings: [row('open')], candidate: bypass });
    assert.equal(escalated.action, 'escalate');
    assert.equal(escalated.patch.finding_class, 'confirmed_exposure');
    assert.equal(escalated.patch.severity, 'critical');
    assert.equal(escalated.patch.escalated_from_class, 'suspected_bypass');
    const observed = planProtectionFindingUpsert({ existingFindings: [row('in_progress')], candidate: { ...suspected, severity: 'low' } });
    assert.equal(observed.action, 'record_observation');
    assert.equal(observed.patch.severity, 'high');
    assert.equal(observed.patch.finding_class, undefined);
    assert.equal(observed.patch.latest_observation.finding_class, 'suspected_bypass');
    for (const plan of [escalated, observed]) {
      assert.equal(plan.closes_findings, false);
      assert.equal(plan.sibling_closure, false);
      assert.equal(plan.status_unchanged, true);
      assert.equal(plan.patch.status, undefined);
      assert.equal(plan.patch.closed_at, undefined);
    }
  });

  it('respects exceptions and records recurrence after closure', () => {
    assert.equal(planProtectionFindingUpsert({ existingFindings: [row('accepted_risk')], candidate: suspected }).action, 'exception_retained');
    const beyond = planProtectionFindingUpsert({ existingFindings: [row('false_positive')], candidate: bypass });
    assert.equal(beyond.action, 'create');
    assert.equal(beyond.escalated_from_finding_id, 'fnd_false_positive');
    const recurrence = planProtectionFindingUpsert({ existingFindings: [row('resolved')], candidate: suspected });
    assert.equal(recurrence.action, 'create');
    assert.equal(recurrence.recurrence_of_finding_id, 'fnd_resolved');
  });

  it('refuses to create, update, or close anything from an unavailable-evidence candidate', () => {
    for (const status of ['open', 'in_progress', 'accepted_risk', 'resolved', 'closed']) {
      const plan = planProtectionFindingUpsert({ existingFindings: [row(status)], candidate: unavailable });
      assert.deepEqual(plan, { action: 'none', reason: UNAVAILABLE_EVIDENCE_SKIP_REASON, closes_findings: false, sibling_closure: false }, status);
    }
    assert.equal(planProtectionFindingUpsert({ existingFindings: [], candidate: unavailable }).action, 'none');
    assert.equal(planProtectionFindingUpsert({ existingFindings: [], candidate: { ...bypass, finding_class: 'made_up' } }).reason, 'invalid_candidate');
  });

  it('still escalates a legacy unavailable-evidence finding when real evidence arrives', () => {
    const legacy = { ...row('open'), finding_class: 'unavailable_evidence', severity: 'low', protection_validation: { ...row('open').protection_validation, finding_class: 'unavailable_evidence' } };
    const plan = planProtectionFindingUpsert({ existingFindings: [legacy], candidate: suspected });
    assert.equal(plan.action, 'escalate');
    assert.equal(plan.patch.escalated_from_class, 'unavailable_evidence');
    assert.equal(plan.patch.finding_class, 'suspected_bypass');
    const patched = applyProtectionFindingPatch(legacy, plan.patch, T2);
    assert.equal(patched.status, 'open');
  });

  it('never closes a finding or its siblings from a newer passing run or a closed external ticket', () => {
    const finding = row('open');
    const signal = protectionFindingClosureSignal({
      finding,
      passingObservation: { dedupe_key: finding.dedupe_key, observation: 'consistent_enforcement' },
      externalTicket: { status: 'Closed' },
    });
    assert.deepEqual(signal, {
      finding_id: finding.id,
      action: 'none',
      close: false,
      sibling_closure: false,
      can_advance_remediation: false,
      requires_explicit_lifecycle_action: true,
      signals: ['newer_passing_observation', 'external_ticket_closed'],
    });
  });

  it('projects a list-compatible finding row', () => {
    const findingRow = toProtectionFindingRow(bypass, { id: 'fnd_pv_1', now: T1 });
    assert.equal(findingRow.status, 'open');
    assert.equal(findingRow.source, 'protection_validation');
    assert.equal(findingRow.target_id, 'tgt_alt');
    assert.equal(findingRow.check_id, 'waf.marker.sqli');
    assert.equal(findingRow.notes, bypass.summary);
    assert.equal(findingSeverityClass(findingRow.severity), 'critical');
    assert.equal(findingRow.protection_validation.dedupe_key, bypass.dedupe_key);
    assert.equal(findingRow.protection_validation.title, undefined);
    assert.ok(isProtectionValidationFinding(findingRow));
    assert.equal(isProtectionValidationFinding({ id: 'fnd_legacy', check_id: 'x' }), false);
    const query = parseFindingListQuery({ target_id: 'tgt_alt', status: 'open', severity: 'critical' });
    assert.equal(findingMatchesListQuery(findingRow, query, new Set()), true);
  });
});

describe('protection findings ignore unavailable evidence in the dev store', () => {
  const CTX = { tenantId: TENANT, userId: 'usr_eng', role: 'engineer' };
  beforeEach(() => {
    const store = getStore();
    for (const key of ['findings', 'auditLog']) {
      if (!Array.isArray(store[key])) store[key] = [];
      store[key] = store[key].filter((row) => row.tenant_id !== TENANT);
    }
  });

  it('creates zero findings from an evaluation whose results all lack evidence', () => {
    const empty = pathEvaluation({ id: 'pvc_store_empty', at: T1, items: [pathItem(PATHS.alt, { observation: 'no_response' }, []), pathItem(PATHS.login, { observation: 'no_response' }, [])] });
    const result = upsertProtectionFindingsFromEvaluation(CTX, empty, { entryPaths: ENTRY_PATHS, expectations: [PATH_EXPECTATION], now: T1 });
    assert.equal(result.ok, true);
    assert.deepEqual(result.created, []);
    assert.deepEqual(result.updated, []);
    assert.equal(result.skipped, 2);
    assert.equal(getStore().findings.filter((row) => row.tenant_id === TENANT).length, 0);
    assert.equal(getStore().auditLog.filter((row) => row.tenant_id === TENANT).length, 0);
    const fw = firewallEvaluation('fwc_store');
    const fwResult = upsertProtectionFindingsFromEvaluation(CTX, fw, { expectations: FW_EXPECTATIONS, baseline: FW_BASELINE, now: T2 });
    const mismatch = getStore().findings.filter((row) => row.tenant_id === TENANT && row.protection_validation?.failed_expectation?.expectation_id === 'fwx_mismatch');
    assert.equal(fwResult.created.length, 3);
    assert.deepEqual(mismatch, []);
  });

  it('leaves an existing finding untouched when later evidence is unavailable', () => {
    const first = upsertProtectionFindingsFromEvaluation(CTX, pathEvaluation({ id: 'pvc_store_1', at: T1 }), { entryPaths: ENTRY_PATHS, expectations: [PATH_EXPECTATION], now: T1 });
    const altId = first.created.find((id) => getStore().findings.find((row) => row.id === id).protection_validation.observed_route.entry_path_id === 'ep_alt');
    assert.ok(altId);
    const before = structuredClone(getStore().findings.find((row) => row.id === altId));
    const auditBefore = getStore().auditLog.filter((row) => row.tenant_id === TENANT).length;
    const later = pathEvaluation({ id: 'pvc_store_2', at: T2, items: [pathItem(PATHS.alt, { observation: 'no_response' }, [])] });
    const result = upsertProtectionFindingsFromEvaluation(CTX, later, { entryPaths: ENTRY_PATHS, expectations: [PATH_EXPECTATION], now: T2 });
    assert.deepEqual(result.created, []);
    assert.deepEqual(result.updated, []);
    assert.deepEqual(result.retained, []);
    const after = getStore().findings.find((row) => row.id === altId);
    assert.deepEqual(after, before);
    assert.equal(after.status, 'open');
    assert.equal(after.closed_at, null);
    assert.equal(after.protection_validation.last_evaluation_id, undefined);
    assert.equal(getStore().auditLog.filter((row) => row.tenant_id === TENANT).length, auditBefore);
  });
});

describe('protection retest authorization and lineage', () => {
  const derived = deriveProtectionFindingCandidates({ evaluation: pathEvaluation({ id: 'pvc_1', at: T1 }), entryPaths: ENTRY_PATHS, expectations: [PATH_EXPECTATION] });
  const finding = toProtectionFindingRow(byPath(derived.candidates, 'ep_alt'), { id: 'fnd_pv_alt', now: T1 });
  const anchorTarget = { id: 'tgt_app', tenant_id: TENANT };
  const entryTarget = { id: 'tgt_alt', tenant_id: TENANT };
  const authorize = (overrides = {}) => assessProtectionRetestAuthorization({
    finding,
    tenantId: TENANT,
    entryPath: PATHS.alt,
    anchorTarget,
    entryTarget,
    ownershipVerified: true,
    ...overrides,
  });

  it('rechecks the current relation, target lifecycle, and ownership before a retest', () => {
    assert.deepEqual(authorize(), { ok: true, error: null, status: 200, drift: [], comparable_with_original: true });
    assert.equal(authorize({ entryPath: { ...PATHS.alt, status: 'archived' } }).error, 'entry_path_archived');
    assert.equal(authorize({ entryPath: null }).error, 'entry_path_archived');
    assert.equal(authorize({ entryTarget: { ...entryTarget, deleted_at: T2 } }).error, 'target_not_active');
    assert.equal(authorize({ entryTarget: { ...entryTarget, tenant_id: OTHER } }).error, 'unknown_target');
    assert.equal(authorize({ ownershipVerified: false }).error, 'target_not_authorized');
    assert.equal(authorize({ entryPath: PATHS.login, entryTarget: { id: 'tgt_login', tenant_id: TENANT } }).error, 'retest_scope_mismatch');
    assert.equal(authorize({ tenantId: OTHER }).error, 'unknown_finding');
    assert.equal(authorize({ entryPath: { ...PATHS.alt, owner: 'Tampered' } }).field, 'declaration_digest');
  });

  it('flags a changed declaration as drift so the retest is not compared with the original baseline', () => {
    const v2 = relation('ep_alt_v2', { entry_target_id: 'tgt_alt', relation_kind: 'alternate_hostname', owner: 'App Team', purpose: 'Legacy host v2', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'] }, 2);
    const result = authorize({ entryPath: v2 });
    assert.equal(result.ok, true);
    assert.deepEqual(result.drift, ['declaration_changed', 'entry_path_version_changed']);
    assert.equal(result.comparable_with_original, false);
  });

  it('rechecks firewall expectation and destination authorization', () => {
    const fw = deriveProtectionFindingCandidates({ evaluation: firewallEvaluation(), expectations: FW_EXPECTATIONS, baseline: FW_BASELINE });
    const fwFinding = toProtectionFindingRow(fw.candidates.find((c) => c.failed_expectation.expectation_id === 'fwx_deny'), { id: 'fnd_fw', now: T2 });
    const destination = { id: 'tgt_fw', tenant_id: TENANT };
    const base = { finding: fwFinding, tenantId: TENANT, expectation: FW_DENY, destinationTarget: destination, ownershipVerified: true };
    assert.equal(assessProtectionRetestAuthorization(base).ok, true);
    assert.equal(assessProtectionRetestAuthorization({ ...base, expectation: { ...FW_DENY, status: 'archived' } }).error, 'expectation_not_active');
    assert.equal(assessProtectionRetestAuthorization({ ...base, expectation: FW_STILL }).error, 'retest_scope_mismatch');
    assert.equal(assessProtectionRetestAuthorization({ ...base, destinationTarget: { ...destination, status: 'deleted' } }).error, 'target_not_active');
    const context = protectionRetestContext(fwFinding, assessProtectionRetestAuthorization(base));
    assert.equal(context.baseline_id, 'fwb_1');
    assert.equal(context.baseline_entry_digest, FW_BASELINE.entries[0].baseline_digest);
    assert.equal(context.expectation_version, 1);
    assert.equal(context.change_id, 'CHG-1');
    assert.equal(context.authorization_rechecked, true);
  });

  it('refuses to register a protection retest without a current authorization recheck', () => {
    const run = { id: 'run_retest', tenant_id: TENANT, target_id: 'tgt_alt', check_id: 'waf.marker.sqli', status: 'running' };
    assert.deepEqual(planRetestRegistration({ finding, run, intent: 'retest' }), { error: 'retest_not_authorized', status: 409, reason: 'authorization_not_rechecked' });
    assert.equal(planRetestRegistration({ finding, run, intent: 'retest', authorization: authorize({ ownershipVerified: false }) }).reason, 'target_not_authorized');
    const planned = planRetestRegistration({ finding, run, intent: 'retest', authorization: authorize() });
    assert.equal(planned.replayed, false);
    assert.equal(planned.comparison_context.evaluation_id, 'pvc_1');
    assert.equal(planned.comparison_context.declaration_digest, PATHS.alt.declaration_digest);
    assert.equal(planned.comparison_context.scenario, SCENARIO);
    const legacy = { id: 'fnd_legacy', tenant_id: TENANT, target_id: 'tgt_alt', check_id: 'waf.marker.sqli' };
    assert.deepEqual(planRetestRegistration({ finding: legacy, run, intent: 'retest' }), { replayed: false });
  });
});

describe('protection retest lineage in the dev store', () => {
  beforeEach(() => {
    const store = getStore();
    for (const key of ['findings', 'testRuns', 'findingRetestLineage', 'auditLog']) {
      if (!Array.isArray(store[key])) store[key] = [];
      store[key] = store[key].filter((row) => row.tenant_id !== TENANT);
    }
  });

  it('retains comparison context and leaves the finding and siblings open', () => {
    const derived = deriveProtectionFindingCandidates({ evaluation: pathEvaluation({ id: 'pvc_1', at: T1 }), entryPaths: ENTRY_PATHS, expectations: [PATH_EXPECTATION] });
    const finding = toProtectionFindingRow(byPath(derived.candidates, 'ep_alt'), { id: 'fnd_pv_alt', now: T1 });
    const sibling = { id: 'fnd_sibling', tenant_id: TENANT, target_id: 'tgt_other', check_id: 'waf.marker.sqli', status: 'open', closed_at: null };
    const store = getStore();
    store.findings.push(finding, sibling);
    store.testRuns.push(
      { id: 'run_a1', tenant_id: TENANT, target_id: 'tgt_alt', check_id: 'waf.marker.sqli', status: 'verdicted' },
      { id: 'run_pass', tenant_id: TENANT, target_id: 'tgt_alt', check_id: 'waf.marker.sqli', status: 'verdicted' },
      { id: 'run_retest', tenant_id: TENANT, target_id: 'tgt_alt', check_id: 'waf.marker.sqli', status: 'running' },
    );
    const denied = registerRetestLineage(ENGINEER, { finding_id: finding.id, test_run_id: 'run_retest', intent: 'retest' });
    assert.equal(denied.error, 'retest_not_authorized');
    assert.equal(store.findingRetestLineage.filter((row) => row.tenant_id === TENANT).length, 0);
    let calls = 0;
    const registered = registerRetestLineage(ENGINEER, { finding_id: finding.id, test_run_id: 'run_retest', intent: 'retest' }, {
      now: T2,
      resolveProtectionRetestAuthorization: (ctx, row, run) => {
        calls += 1;
        assert.equal(ctx.tenantId, TENANT);
        assert.equal(row.id, finding.id);
        assert.equal(run.id, 'run_retest');
        return assessProtectionRetestAuthorization({ finding: row, tenantId: ctx.tenantId, entryPath: PATHS.alt, anchorTarget: { id: 'tgt_app', tenant_id: TENANT }, entryTarget: { id: 'tgt_alt', tenant_id: TENANT }, ownershipVerified: true });
      },
    });
    assert.equal(calls, 1);
    assert.equal(registered.relation, 'retest');
    assert.equal(registered.sibling_closure, false);
    assert.equal(registered.comparison_context.evaluation_id, 'pvc_1');
    assert.equal(registered.comparison_context.authorization_rechecked, true);
    const lineage = listFindingLineage(VIEWER, finding.id);
    assert.equal(lineage.retests[0].comparison_context.declaration_version, 1);
    assert.equal(lineage.comparison_context.dedupe_key, finding.dedupe_key);
    assert.equal(lineage.closed_at, null);
    assert.equal(lineage.sibling_closure, false);
    assert.equal(lineage.latest.can_advance_remediation, false);
    assert.ok(lineage.later_same_pair.every((row) => row.can_advance_remediation === false));
    assert.equal(store.findings.find((row) => row.id === finding.id).status, 'open');
    assert.equal(store.findings.find((row) => row.id === 'fnd_sibling').status, 'open');
    assert.equal(JSON.stringify(lineage).includes('verdict":'), false);
  });

  it('keeps legacy lineage output unchanged', () => {
    const finding = { id: 'fnd_plain', tenant_id: TENANT, target_id: 'tgt_alt', check_id: 'waf.marker.sqli', test_run_id: 'run_a1', status: 'open' };
    const presented = presentFindingLineage({ finding, runs: [], lineage: [{ id: 'rtln_1', test_run_id: 'run_x', target_id: 'tgt_alt', check_id: 'waf.marker.sqli', created_at: T2 }], siblings: [] });
    assert.equal(Object.hasOwn(presented, 'comparison_context'), false);
    assert.equal(Object.hasOwn(presented.retests[0], 'comparison_context'), false);
  });
});
