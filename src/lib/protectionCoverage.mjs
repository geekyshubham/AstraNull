/** Pure recorded target/check projection shared by profiles and tenant assessment. Never dispatches. */
import { CHECK_CATALOG, checkRequiresAdditionalInput, isCustomerRunnable } from '../contracts/checks.mjs';
import { targetKindCompatibilityError } from '../contracts/checkTargetCompatibility.mjs';
import { evidenceBackedVerdict } from './targetDetailRows.mjs';
import { approvedScenarioVersion, deriveCheckDefinitionVersion, gradingSignatureVersionGap } from './checkDefinitionVersion.mjs';
import { currentAssuranceGap } from './assuranceScope.mjs';
import { OBSERVATION_ONLY_PROBE_KINDS } from './probeEvidenceTiers.mjs';
import { inconclusiveReason } from './inconclusiveReasons.mjs';

export const COVERAGE_FRESHNESS_POLICY = Object.freeze({ id: 'protection-profile.coverage.v2', version: 2, max_age_ms: 7 * 24 * 60 * 60 * 1000, unit: 'target_check_pair' });
const PLAN_VERSION = 'catalog+policy.v2';
const DIMENSIONS = ['application', 'origin', 'network', 'dns', 'operations', 'other'];
const DIMENSION_BY_FAMILY = { l7: 'application', waf: 'application', path: 'application', pattern: 'application', exploit: 'application', origin: 'origin', l3_l4: 'network', protocol: 'network', tls: 'network', reflection: 'network', amplification: 'network', dns: 'dns', operations: 'operations' };
const PASS_VERDICTS = new Set(['protected', 'pass', 'passed', 'success', 'ok', 'allowed_as_expected']);
const GAP_VERDICTS = new Set(['exposed', 'unprotected', 'gap', 'fail', 'failed', 'bypassable', 'penetrated', 'edge_exposed']);
const text = (value) => typeof value === 'string' && value.trim() ? value.trim() : null;
const summaryOf = (run) => run?.summary_json ?? run?.summary ?? {};
function recordedText(run, verdict, key) {
  const readinessMetadata = Array.isArray(run?.readiness_result_metadata)
    ? run.readiness_result_metadata
    : (run?.readiness_result_metadata && typeof run.readiness_result_metadata === 'object' ? [run.readiness_result_metadata] : []);
  let readinessVal = null;
  for (const entry of readinessMetadata) {
    if (entry && entry[key] != null) {
      readinessVal = text(entry[key]);
      if (readinessVal) break;
    }
  }
  return text(run?.probe_metadata?.[key])
    ?? text(run?.probe_external_result?.metadata?.[key])
    ?? readinessVal
    ?? text(verdict?.[key])
    ?? text((verdict?.metadata_json ?? verdict?.metadata ?? {})[key])
    ?? text(verdict?.placement_confidence?.[key])
    ?? text(run?.[key])
    ?? text(summaryOf(run)[key])
    ?? text(run?.provenance_json?.[key]);
}

export function versionGapFor(check, run, verdict) {
  const current = deriveCheckDefinitionVersion(check);
  const recorded = recordedText(run, verdict, 'check_version');
  if (!recorded) return 'missing_check_version';
  if (recorded !== current.check_version) return 'check_version_mismatch';
  const recordedDigest = run?.provenance_json?.digest;
  if (recordedDigest && recordedDigest !== current.digest) return 'check_definition_changed';
  const scenario = approvedScenarioVersion(check);
  if (scenario && !recordedText(run, verdict, 'scenario_version')) return 'missing_scenario_version';
  if (scenario && recordedText(run, verdict, 'scenario_version') !== scenario) return 'scenario_version_mismatch';
  const isWaf = String(check?.check_id ?? run?.check_id ?? '').startsWith('waf.')
    || check?.vector_family === 'waf'
    || check?.family === 'waf'
    || ['waf_class_marker_probe', 'waf_evasion_marker_probe', 'outside_in_waf_scan', 'waf_method_policy_probe'].includes(run?.probe_profile?.kind ?? check?.probe_profile?.kind);
  const status = String(run?.status ?? '').toLowerCase();
  const isCompleted = ['completed', 'verdicted'].includes(status) || Boolean(verdict?.verdict);
  if (isWaf && isCompleted) {
    const gap = gradingSignatureVersionGap(run, verdict, check);
    if (gap) return gap;
  } else {
    const grading = recordedText(run, verdict, 'grading_version');
    const corpus = recordedText(run, verdict, 'signature_corpus_version');
    if (grading || corpus || run?.provenance_json?.grading_version || run?.provenance_json?.signature_corpus_version) {
      const gap = gradingSignatureVersionGap(run, verdict, check);
      if (gap) return gap;
    }
  }
  return null;
}

export function observationAssuranceGap(run, verdict, check = null) {
  const summary = summaryOf(run);
  const sources = [summary, summary.metadata, summary.probe_metadata, run?.probe_metadata, run?.probe_external_result?.metadata, verdict?.metadata_json, verdict?.metadata, ...(run?.readiness_result_metadata ?? [])].filter(Boolean);
  if (sources.some((source) => source.observation_only === true || source.readiness_conclusion === false)) return 'observation_only_result';
  if (sources.some((source) => source.complete === false || source.comparison_complete === false || source.evidence_complete === false || source.planned_legs_complete === false || source.capture_complete === false)) return 'incomplete_evidence';
  if (check?.requires_complete_comparison === true || ['waf_class_marker_probe', 'waf_evasion_marker_probe', 'outside_in_waf_scan'].includes(check?.probe_profile?.kind)) {
    const proof = sources.filter((source) => source.classifier_version === 'marker-comparison-v4');
    if (!proof.length || proof.some((source) => source.comparison_complete !== true || !Number.isInteger(source.planned_marker_legs) || source.planned_marker_legs <= 0 || source.completed_marker_legs !== source.planned_marker_legs || (source.permitted_baseline_health ?? source.permitted_baseline?.health ?? source.baseline_health) !== 'healthy')) return 'complete_marker_comparison_missing';
  }
  return null;
}

/** Actual resolved result metadata must agree with a retained positive label. */
function positiveOutcomeGap(run, verdict, check, context) {
  const value = String(verdict?.verdict ?? '').trim().toLowerCase();
  if (!PASS_VERDICTS.has(value) && value !== 'edge_protected') return null;
  const actual = Array.isArray(run?.readiness_result_metadata) ? run.readiness_result_metadata : [];
  if (context.evidence_verified !== true || !actual.length) return 'actual_positive_outcome_missing';
  if (value === 'allowed_as_expected') {
    const expected = context.target?.expected_behavior ?? context.policy?.expected_behavior
      ?? context.targetGroup?.expected_behavior_default ?? run.expected_behavior ?? check?.default_expected_behavior;
    return expected === 'must_reach_canary' && actual.every((metadata) => metadata.application_identity?.confirmed === true
      && metadata.application_identity.method === 'nonce_canary') ? null : 'actual_allow_expectation_unverified';
  }
  return actual.every((metadata) => metadata.enforcement === 'enforced') ? null : 'actual_positive_outcome_mismatch';
}

function provenanceOf(run, verdict) {
  const summary = summaryOf(run);
  const producer = recordedText(run, verdict, 'producer_kind');
  if (producer === 'internal_simulation' || run?.simulation === 'SAFE_PROBE_SIMULATION' || summary.simulation === 'SAFE_PROBE_SIMULATION' || run?.probe_mode === 'simulation' || summary.probe_mode === 'simulation') return 'internal_simulation';
  if (['manual', 'customer_declaration'].includes(producer)) return 'manual_declaration';
  return ['signed_probe', 'live_external'].includes(producer) ? 'external' : 'unspecified';
}

export function pairState(run, verdict, check, nowMs, context = {}) {
  if (!run) return { state: 'not_run', observed_at: null, freshness: 'not_recorded', provenance: 'not_recorded', live_external: false, pair_reason: 'no_run', retained: null, current_assurance: 'not_established', retest_required: false };
  const provenance = provenanceOf(run, verdict);
  // The earliest required immutable observation controls expiry; a newer completion never renews it.
  const completed = Date.parse(run.completed_at ?? '');
  const evidenceTime = Date.parse(context.observed_at ?? run.completed_at ?? '');
  const observedMs = Math.min(completed, evidenceTime);
  const observedAt = Number.isFinite(observedMs) ? new Date(observedMs).toISOString() : null;
  const retained = { verdict: text(verdict?.verdict), observed_at: observedAt, provenance, check_version: recordedText(run, verdict, 'check_version'), scenario_version: recordedText(run, verdict, 'scenario_version'), run_status: text(run.status) };
  const base = { prior_state: null, observed_at: observedAt, provenance, retained, live_external: false, current_assurance: 'not_established', retest_required: false };
  const unknown = (reason) => ({ ...base, state: 'unknown', freshness: 'unknown', pair_reason: reason });
  if (['cancelled', 'canceled'].includes(run.status)) return unknown('canceled');
  if (!['completed', 'verdicted'].includes(run.status)) return unknown('unfinalized');
  if (!observedAt) return unknown('observation_time_unknown');
  if (completed > nowMs || evidenceTime > nowMs) return unknown('future_observation');
  if (!evidenceBackedVerdict(verdict) || context.evidence_verified === false) return unknown('no_evidence');
  if (provenance !== 'external') return unknown(provenance);
  const stale = nowMs - observedMs > COVERAGE_FRESHNESS_POLICY.max_age_ms;
  const recordedScope = run.safety_constraints?.assurance_scope ?? run.provenance_json?.assurance_scope;
  const gap = versionGapFor(check, run, verdict)
    ?? (context.require_recorded_scope === true && !recordedScope?.target?.definition_digest ? 'recorded_target_scope_missing' : null)
    ?? (context.target ? currentAssuranceGap({ run, target: context.target, policy: context.policy, targetGroup: context.targetGroup }) : null)
    ?? observationAssuranceGap(run, verdict, check)
    ?? positiveOutcomeGap(run, verdict, check, context);
  if (gap) return { ...base, state: 'partial', freshness: stale ? 'stale' : 'unknown', pair_reason: gap, current_assurance: 'retest_required', retest_required: true };
  const value = String(verdict.verdict).trim().toLowerCase();
  // Edge denial earns only scoped scenario credit when actual signed results were
  // resolved and the reviewed complete marker comparison passed every gate above.
  // Generic edge blocks, fingerprints, and retained verdict strings never qualify.
  const scopedEdgePass = value === 'edge_protected' && context.evidence_verified === true
    && check?.requires_complete_comparison === true;
  const passing = PASS_VERDICTS.has(value) || scopedEdgePass;
  const prior = passing || GAP_VERDICTS.has(value) ? 'conclusive' : 'inconclusive';
  const outcome = passing ? 'pass' : GAP_VERDICTS.has(value) ? 'gap' : 'review';
  if (stale) return { ...base, state: 'stale', prior_state: prior, outcome, freshness: 'stale', pair_reason: 'stale', current_assurance: 'expired', retest_required: true };
  return { ...base, state: prior, outcome, freshness: 'current', pair_reason: prior === 'inconclusive' ? 'inconclusive_result' : null, live_external: prior === 'conclusive', current_assurance: prior === 'conclusive' ? 'current' : 'not_established' };
}

export function summarizePairs(pairs, weightOf = () => 1) {
  const counts = { applicable_count: 0, evaluated_count: 0, conclusive_count: 0, passed_count: 0,
    gap_count: 0, inconclusive_count: 0, not_run_count: 0, stale_count: 0, unknown_count: 0,
    partial_count: 0, setup_required_count: 0, excluded_count: 0 };
  for (const pair of pairs) {
    const weight = weightOf(pair);
    if (pair.exclusion_reason === 'setup_required') counts.setup_required_count += weight;
    if (pair.state === 'excluded') { counts.excluded_count += weight; continue; }
    counts.applicable_count += weight;
    const key = `${pair.state}_count`;
    if (Object.hasOwn(counts, key)) counts[key] += weight;
    if (['conclusive', 'inconclusive', 'stale'].includes(pair.state)) counts.evaluated_count += weight;
    if (pair.state === 'conclusive' && pair.outcome === 'pass') counts.passed_count += weight;
    if (pair.state === 'conclusive' && pair.outcome === 'gap') counts.gap_count += weight;
  }
  return { ...counts, percentage: counts.applicable_count ? Math.round(100 * counts.conclusive_count / counts.applicable_count) : null,
    percentage_reason: counts.applicable_count ? 'conclusive_over_applicable' : 'not_applicable' };
}

function dimensionStatus(summary) {
  if (!summary.applicable_count) return 'not_applicable';
  if (summary.conclusive_count === summary.applicable_count) return 'conclusive';
  if (summary.conclusive_count) return 'partial';
  if (!summary.evaluated_count && !summary.unknown_count && !summary.partial_count) return 'not_run';
  if (summary.stale_count && !summary.inconclusive_count && !summary.partial_count && !summary.unknown_count) return 'stale';
  if (summary.unknown_count && !summary.inconclusive_count && !summary.stale_count && !summary.partial_count) return 'unknown';
  return summary.inconclusive_count || summary.stale_count ? 'inconclusive' : 'partial';
}

function policyForCheck(policies, target, checkId, run) {
  const eligible = (policies ?? []).filter((policy) => !policy.archived_at && policy.state !== 'archived' && policy.check_id === checkId && (!policy.tenant_id || policy.tenant_id === target.tenant_id) && (!policy.target_group_id || policy.target_group_id === target.target_group_id) && (!policy.target_id || policy.target_id === target.id));
  return eligible.find((policy) => policy.id === run?.policy_id) ?? eligible.find((policy) => policy.target_id) ?? eligible[0] ?? null;
}

function attemptOrder(entry) {
  return Date.parse(entry?.run?.started_at ?? entry?.run?.created_at ?? entry?.run?.completed_at ?? '') || 0;
}

export function coverageFrom({ target, policies = [], targetGroup = null, observations = [], catalog = CHECK_CATALOG, nowMs = Date.now() }) {
  const byCheck = new Map();
  for (const entry of observations) {
    const run = entry?.run;
    if (run?.target_id && run.target_id !== target.id || run?.tenant_id && target.tenant_id && run.tenant_id !== target.tenant_id) continue;
    const checkId = entry?.check_id ?? run?.check_id;
    const prior = byCheck.get(checkId);
    if (checkId && (!prior || attemptOrder(entry) > attemptOrder(prior) || attemptOrder(entry) === attemptOrder(prior) && String(run?.id).localeCompare(String(prior.run?.id)) > 0)) byCheck.set(checkId, entry);
  }
  const pairs = [];
  const reasons = new Map();
  for (const check of catalog) {
    if (!check?.check_id || !isCustomerRunnable(check) || targetKindCompatibilityError(check, target)) continue;
    const declarationOnly = check.evidence_tier === 'E1' || ['metadata_marker', 'ops_readiness'].includes(check.probe_profile?.kind);
    const observationOnly = check.evidence_tier === 'E2' || check.observation_only === true || check.readiness_conclusion === false || check.probe_profile?.observation_only === true || check.probe_profile?.readiness_conclusion === false || OBSERVATION_ONLY_PROBE_KINDS.includes(check.probe_profile?.kind);
    const excluded = declarationOnly || observationOnly || checkRequiresAdditionalInput(check, { target });
    const exclusionReason = declarationOnly ? 'declaration_only' : observationOnly ? 'observation_only' : 'setup_required';
    const entry = byCheck.get(check.check_id);
    const policy = policyForCheck(policies, target, check.check_id, entry?.run);
    const launch = { launch_eligibility: { status: 'not_evaluated', reason: 'runtime_gates_not_evaluated' }, launchable: null, launch_block_reason: 'not_evaluated', policy_binding: !policy ? 'no_policy' : policy.target_id ? 'bound' : 'test_policy_target_binding_missing' };
    const outcome = excluded ? { state: 'excluded', observed_at: null, freshness: 'not_applicable', provenance: 'not_recorded', live_external: false, pair_reason: exclusionReason, retained: null, current_assurance: 'not_applicable', retest_required: false }
      : pairState(entry?.run, entry?.verdict, check, nowMs, { ...entry, target, policy, targetGroup });
    pairs.push({ target_id: target.id, check_id: check.check_id, scenario_version: approvedScenarioVersion(check), mechanism: check.probe_profile?.kind ?? null, dimension: DIMENSION_BY_FAMILY[check.vector_family] ?? 'other', ...outcome, prior_state: outcome.prior_state ?? null, exclusion_reason: excluded ? exclusionReason : null, last_run_id: excluded ? null : entry?.run?.id ?? null, policy_id: policy?.id ?? null, ...launch });
    if (outcome.state === 'inconclusive') {
      const reason = inconclusiveReason({ probeKind: check.probe_profile?.kind, externalResult: entry?.run?.probe_external_result, metadata: entry?.run?.probe_metadata ?? {} });
      const group = reasons.get(reason.reason) ?? { ...reason, count: 0, check_ids: [] };
      group.count += 1;
      group.check_ids.push(check.check_id);
      reasons.set(reason.reason, group);
    }
  }
  pairs.sort((a, b) => a.check_id.localeCompare(b.check_id));
  const rolled = rollupCustomCanaryPairs(pairs);
  return {
    coverage: { unit: 'target_check_pair', plan_version: PLAN_VERSION, as_of: new Date(nowMs).toISOString(), freshness_policy: COVERAGE_FRESHNESS_POLICY, runtime_launch_gates: 'not_evaluated', scope: { target_id: target.id, plan_version: PLAN_VERSION }, ...summarizePairs(rolled), observation_only_count: rolled.filter((pair) => pair.exclusion_reason === 'observation_only').length, inconclusive_reasons: [...reasons.values()].sort((a, b) => b.count - a.count || a.reason.localeCompare(b.reason)), pairs, custom_canary_rollups: rolled.filter((pair) => pair.custom_canary_rollup === true) },
    dimensions: DIMENSIONS.map((id) => { const summary = summarizePairs(rolled.filter((pair) => pair.dimension === id)); return { id, unit: 'target_check_pair', status: dimensionStatus(summary), ...summary, freshness_policy_id: COVERAGE_FRESHNESS_POLICY.id, scope: { target_id: target.id, plan_version: PLAN_VERSION } }; }),
  };
}

const MANAGED_MARKER_CHECK_IDS = new Set([
  'waf.sqli_managed_marker.safe',
  'waf.xss_managed_marker.safe',
  'waf.path_traversal_managed_marker.safe',
  'waf.scanner_signature_marker.safe',
  ...CHECK_CATALOG.filter((c) =>
    c.rule_family === 'managed' || c.probe_profile?.assurance_scope === 'managed_rule_marker'
  ).map((c) => c.check_id),
]);

export function isCustomCanaryCheckId(checkId) {
  const id = typeof checkId === 'object' && checkId !== null ? (checkId.check_id ?? checkId.checkId) : checkId;
  if (typeof id !== 'string') return false;
  if (MANAGED_MARKER_CHECK_IDS.has(id)) return false;
  if (/^waf\.test_marker_\d+\.safe$/.test(id)) return false;
  if (typeof checkId === 'object' && checkId !== null) {
    if (checkId.rule_family === 'managed') return false;
    if (checkId.assurance_scope === 'managed_rule_marker' || checkId.probe_profile?.assurance_scope === 'managed_rule_marker') return false;
  }
  return /^waf\..+_marker\.safe$/.test(id);
}

function rollupRank(pair) {
  if (pair.outcome === 'gap' || pair.state === 'conclusive' && pair.outcome === 'gap') return 0;
  if (pair.outcome === 'pass' && pair.state === 'conclusive') return 1;
  if (pair.state === 'stale') return 2;
  if (pair.state === 'inconclusive') return 3;
  if (pair.state === 'partial') return 4;
  return 5;
}

const VERSION_GAP_REASONS = new Set([
  'missing_check_version', 'check_version_mismatch', 'check_definition_changed',
  'missing_scenario_version', 'scenario_version_mismatch', 'missing_grading_version',
  'grading_version_mismatch', 'missing_signature_corpus_version', 'signature_corpus_version_mismatch',
]);

/** Server freshness and version-gap answer for one rolled-up member pair. */
function rolledUpPairSummary(pair) {
  return {
    check_id: pair.check_id,
    last_run_id: pair.last_run_id ?? null,
    state: pair.state,
    fresh: pair.freshness === 'current',
    version_gap: VERSION_GAP_REASONS.has(pair.pair_reason) ? pair.pair_reason : null,
    verdict: pair.retained?.verdict ?? null,
    observed_at: pair.observed_at ?? null,
  };
}

function rollupCustomCanaryPairs(pairs) {
  const groups = new Map();
  const out = [];
  for (const pair of pairs) {
    if (pair.exclusion_reason || !isCustomCanaryCheckId(pair.check_id)) {
      out.push(pair);
      continue;
    }
    const list = groups.get(pair.target_id) ?? [];
    list.push(pair);
    groups.set(pair.target_id, list);
  }
  for (const list of groups.values()) {
    const chosen = [...list].sort((a, b) => rollupRank(a) - rollupRank(b) || a.check_id.localeCompare(b.check_id))[0];
    out.push({
      ...chosen,
      rolled_up_check_ids: list.map((pair) => pair.check_id),
      rolled_up_pairs: list.map(rolledUpPairSummary),
      custom_canary_rollup: true,
    });
  }
  out.sort((a, b) => a.check_id.localeCompare(b.check_id));
  return out;
}
