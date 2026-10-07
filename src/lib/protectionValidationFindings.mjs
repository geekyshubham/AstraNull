import {
  COMPARISON_KINDS,
  PROTECTION_VALIDATION_CONTRACT_VERSION,
  REQUIRED_LIMITATIONS,
  comparisonEvaluationDigest,
  entryPathAuthorizesExecution,
  normalizeLimitations,
  sha256Digest,
} from '../contracts/protectionValidation.mjs';

export const PROTECTION_FINDING_SOURCE = 'protection_validation';
export const PROTECTION_FINDING_SEMANTICS_VERSION = 'protection-findings-v1';

export const PROTECTION_FINDING_CLASSES = Object.freeze([
  'confirmed_exposure',
  'observed_enforcement_gap',
  'observed_availability_gap',
  'suspected_bypass',
]);

export const LEGACY_PROTECTION_FINDING_CLASSES = Object.freeze(['unavailable_evidence']);
export const UNAVAILABLE_EVIDENCE_SKIP_REASON = 'unavailable_evidence_ignored';

const CLASS_RANK = Object.freeze({
  unavailable_evidence: 0,
  suspected_bypass: 1,
  observed_enforcement_gap: 2,
  observed_availability_gap: 2,
  confirmed_exposure: 3,
});

export const PROTECTION_FINDING_PRIORITIES = Object.freeze(['p1', 'p2', 'p3', 'p4']);
const PRIORITY_SEVERITY = Object.freeze({ p1: 'critical', p2: 'high', p3: 'medium', p4: 'low' });
const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });

export const PATH_GAP_OUTCOMES = Object.freeze([
  'scoped_application_bypass',
  'reachability_exposure',
  'suspected_alternate_application_route',
  'weaker_observed_enforcement',
]);
export const PATH_PASSING_OUTCOMES = Object.freeze(['consistent_enforcement', 'intentional_public_access']);
export const PATH_UNRESOLVED_OUTCOMES = Object.freeze(['inconclusive', 'not_tested', 'skipped']);
export const FIREWALL_UNRESOLVED_STATUSES = Object.freeze(['inconclusive', 'not_tested', 'stale', 'not_comparable']);

function hasFinalizedEvidence(item) {
  return Array.isArray(item?.evidence_refs) && item.evidence_refs.some((ref) => ref && ref.finalized !== false);
}

export function isUnavailableEvidenceItem(kind, item) {
  if (!isObject(item)) return true;
  const unresolved = kind === 'firewall_change'
    ? FIREWALL_UNRESOLVED_STATUSES.includes(item.status)
    : PATH_UNRESOLVED_OUTCOMES.includes(item.outcome);
  return unresolved || !hasFinalizedEvidence(item);
}

const OPEN_STATUSES = new Set(['open', 'in_progress']);
const EXCEPTION_STATUSES = new Set(['accepted_risk', 'false_positive', 'accepted']);

export const CANDIDATE_EXPLANATIONS = Object.freeze({
  waf_policy_monitor_mode: 'Not established: a protection policy may be in a log-only or monitoring mode for this scenario.',
  rule_disabled_or_excluded: 'Not established: a rule or rule group may be disabled or excluded for this path.',
  route_not_attached_to_protection: 'Not established: this route may not be attached to the protection that serves the primary route.',
  origin_not_restricted_to_edge: 'Not established: the origin may accept traffic that does not pass through the edge.',
  firewall_rule_changed: 'Not established: a firewall rule may have been added, removed, or reordered by the change.',
  routing_or_nat_change: 'Not established: routing or address translation may differ after the change.',
  service_moved_or_stopped: 'Not established: the service may have moved, stopped, or be listening elsewhere.',
});

const RELATION_LABELS = Object.freeze({
  primary_route: 'primary route',
  alternate_hostname: 'alternate hostname',
  declared_api_url: 'declared API URL',
  declared_login_url: 'declared login URL',
  origin: 'origin route',
  fallback_backend_route: 'fallback/backend route',
});

function explanations(codes) {
  return codes.map((code) => ({ code, status: 'candidate', corroborated: false, label: CANDIDATE_EXPLANATIONS[code] }));
}

function isObject(value) {
  return value != null && typeof value === 'object' && !Array.isArray(value);
}

export function protectionFindingClassRank(findingClass) {
  return CLASS_RANK[findingClass] ?? -1;
}

export function protectionPrioritySeverity(priority) {
  return PRIORITY_SEVERITY[priority] ?? 'low';
}

export function verifyProtectionEvaluation(evaluation) {
  if (!isObject(evaluation)) return { ok: false, reason: 'evaluation_missing' };
  if (typeof evaluation.id !== 'string' || !evaluation.id) return { ok: false, reason: 'evaluation_not_recorded' };
  if (!COMPARISON_KINDS.includes(evaluation.kind)) return { ok: false, reason: 'evaluation_kind_invalid' };
  if (!Array.isArray(evaluation.items)) return { ok: false, reason: 'evaluation_items_missing' };
  if (typeof evaluation.evaluation_digest !== 'string') return { ok: false, reason: 'evaluation_digest_missing' };
  let digest;
  try {
    digest = comparisonEvaluationDigest(evaluation);
  } catch {
    return { ok: false, reason: 'evaluation_digest_mismatch' };
  }
  if (digest !== evaluation.evaluation_digest) return { ok: false, reason: 'evaluation_digest_mismatch' };
  return { ok: true, reason: null };
}

function pathDedupeBasis(tenantId, relation, item) {
  if (relation) {
    return {
      basis: 'entry_path_scope',
      value: {
        tenant_id: tenantId,
        anchor_target_id: relation.anchor_target_id,
        entry_target_id: relation.entry_target_id,
        relation_kind: relation.relation_kind,
        origin_binding_id: relation.origin_binding_id ?? null,
        scenario: item.scenario,
      },
    };
  }
  return { basis: 'entry_path_id', value: { tenant_id: tenantId, entry_path_id: item.entry_path_id, scenario: item.scenario } };
}

function firewallDedupeBasis(tenantId, expectation, item) {
  if (expectation) {
    const endpoint = expectation.protocol === 'service'
      ? { service: expectation.service_endpoint?.service ?? null, port: expectation.service_endpoint?.port ?? null, path: expectation.service_endpoint?.path ?? null }
      : { port: expectation.port ?? null };
    return {
      basis: 'firewall_expectation_scope',
      value: {
        tenant_id: tenantId,
        destination_target_id: expectation.destination_target_id,
        protocol: expectation.protocol,
        endpoint,
        source_perspective: expectation.source_perspective,
        expected: expectation.expected,
      },
    };
  }
  return { basis: 'expectation_id', value: { tenant_id: tenantId, expectation_id: item.expectation_id } };
}

export function protectionFindingDedupeKey({ kind, tenantId, relation = null, expectation = null, item }) {
  const { basis, value } = kind === 'firewall_change'
    ? firewallDedupeBasis(tenantId, expectation, item)
    : pathDedupeBasis(tenantId, relation, item);
  return { dedupe_key: `pvf_${sha256Digest({ v: PROTECTION_FINDING_SEMANTICS_VERSION, kind, basis, value })}`, dedupe_basis: basis };
}

function classifyPathItem(item, relation) {
  const kindLabel = RELATION_LABELS[relation?.relation_kind] ?? 'entry path';
  const scenario = item.scenario;
  const originLike = relation?.relation_kind === 'origin' || relation?.relation_kind === 'fallback_backend_route';
  const bypassExplanations = ['waf_policy_monitor_mode', 'rule_disabled_or_excluded', 'route_not_attached_to_protection', ...(originLike ? ['origin_not_restricted_to_edge'] : [])];
  switch (item.outcome) {
    case 'scoped_application_bypass':
      return {
        finding_class: 'confirmed_exposure',
        priority: 'p1',
        title: `Scoped application bypass observed on ${kindLabel} for scenario ${scenario}`,
        summary: 'A nonce-bound application response was observed on this declared path while the primary route enforced the same scenario. The conclusion is limited to the tested path, source, scenario, and time; the responsible control is not identified.',
        explanations: bypassExplanations,
      };
    case 'reachability_exposure': {
      const declaredUnreachable = relation ? relation.expected_behavior === 'must_not_be_reachable' : !(item.reasons ?? []).includes('enforcement_not_measured');
      if (declaredUnreachable) {
        return {
          finding_class: 'confirmed_exposure',
          priority: 'p2',
          title: `Response observed on ${kindLabel} declared not reachable`,
          summary: 'A response was observed on a path the customer declared must not be reachable. This is an observed reachability exposure for the tested path, source, and time; the responsible control is not identified.',
          explanations: originLike ? ['origin_not_restricted_to_edge', 'route_not_attached_to_protection'] : ['route_not_attached_to_protection'],
        };
      }
      return {
        finding_class: 'suspected_bypass',
        priority: 'p2',
        title: `Response observed on ${kindLabel} with unmeasured enforcement for scenario ${scenario}`,
        summary: 'A response was observed on this declared path but enforcement of the scenario was not measured. Treat this as a suspected bypass until application identity and enforcement are established.',
        explanations: bypassExplanations,
      };
    }
    case 'suspected_alternate_application_route':
      return {
        finding_class: 'suspected_bypass',
        priority: 'p2',
        title: `Suspected alternate application route on ${kindLabel} for scenario ${scenario}`,
        summary: 'The primary route enforced this scenario and this path returned a non-enforced response, but application identity was not confirmed by a nonce-bound canary. This is suspected, not a confirmed bypass.',
        explanations: bypassExplanations,
      };
    case 'weaker_observed_enforcement':
      return {
        finding_class: 'observed_enforcement_gap',
        priority: 'p3',
        title: `Weaker observed enforcement on ${kindLabel} for scenario ${scenario}`,
        summary: 'The scenario was only partially enforced on this path while the primary route enforced it. The conclusion is limited to the tested path, source, scenario, and time.',
        explanations: bypassExplanations,
      };
    default:
      return null;
  }
}

function classifyFirewallItem(item, expectation, changeId) {
  const changeText = changeId ? ` after change ${changeId}` : '';
  const expected = expectation?.expected ?? null;
  const unmetUnchanged = item.status === 'matched' && item.expectation_met === false;
  if (item.status === 'regression' && item.gap_kind === 'forbidden_service_newly_reachable') {
    return {
      finding_class: 'confirmed_exposure',
      priority: 'p2',
      change_effect: 'regression',
      title: `Forbidden service newly reachable${changeText}`,
      summary: 'Sampled public-ingress evidence observed reachability where the declared expectation is deny, and the pre-change baseline did not. Reachability does not establish which rule or device is responsible.',
      explanations: ['firewall_rule_changed', 'routing_or_nat_change'],
    };
  }
  if (item.status === 'regression' && item.gap_kind === 'required_service_newly_unavailable') {
    return {
      finding_class: 'observed_availability_gap',
      priority: 'p2',
      change_effect: 'regression',
      title: `Required service newly unavailable${changeText}`,
      summary: 'Sampled public-ingress evidence did not observe the required service response after the change, and the pre-change baseline did. No rule or root cause is established.',
      explanations: ['firewall_rule_changed', 'routing_or_nat_change', 'service_moved_or_stopped'],
    };
  }
  if (unmetUnchanged && expected === 'deny') {
    return {
      finding_class: 'confirmed_exposure',
      priority: 'p2',
      change_effect: 'unchanged_failure',
      title: `Forbidden service reachable before and${changeText || ' after the change'}`,
      summary: 'Sampled public-ingress evidence observed reachability on both sides of the change where the declared expectation is deny.',
      explanations: ['firewall_rule_changed', 'routing_or_nat_change'],
    };
  }
  if (unmetUnchanged) {
    return {
      finding_class: 'observed_availability_gap',
      priority: 'p3',
      change_effect: 'unchanged_failure',
      title: `Required service not observed before and${changeText || ' after the change'}`,
      summary: 'Sampled public-ingress evidence did not observe the required service response on either side of the change.',
      explanations: ['firewall_rule_changed', 'service_moved_or_stopped'],
    };
  }
  return null;
}

function isPassing(kind, item) {
  if (kind === 'firewall_change') {
    return (item.status === 'matched' || item.status === 'improvement') && item.expectation_met === true;
  }
  return PATH_PASSING_OUTCOMES.includes(item.outcome);
}

function refsForTarget(refs, targetId) {
  const scoped = targetId ? refs.filter((ref) => ref.target_id === targetId) : refs;
  return scoped.length ? scoped : refs;
}

function latestRef(refs) {
  return [...refs].sort((a, b) => String(b.observed_at ?? '').localeCompare(String(a.observed_at ?? '')) || String(b.test_run_id).localeCompare(String(a.test_run_id)))[0] ?? null;
}

function resolvePathExpectation(expectations, evaluation, item) {
  const list = (expectations ?? []).filter((exp) => exp?.kind === 'path_validation' || exp?.scenario != null);
  const byId = evaluation.expectation_id ? list.find((exp) => exp.id === evaluation.expectation_id) : null;
  if (byId) return byId;
  const anchor = evaluation.anchor_target_id ?? null;
  const matches = list.filter((exp) => exp.scenario === item.scenario && (!anchor || exp.anchor_target_id === anchor));
  return matches.sort((a, b) => (b.expectation_version ?? 0) - (a.expectation_version ?? 0))[0] ?? null;
}

function baselineEntryFor(baseline, expectationId) {
  if (!isObject(baseline)) return null;
  if (Array.isArray(baseline.entries)) return baseline.entries.find((entry) => entry.expectation_id === expectationId) ?? null;
  return baseline.expectation_id === expectationId ? baseline : null;
}

function buildCandidate({ evaluation, item, index, relation, expectation, baseline, classification }) {
  const kind = evaluation.kind;
  const tenantId = evaluation.tenant_id;
  const { dedupe_key: dedupeKey, dedupe_basis: dedupeBasis } = protectionFindingDedupeKey({ kind, tenantId, relation, expectation, item });
  const refs = Array.isArray(item.evidence_refs) ? item.evidence_refs : [];
  const targetId = kind === 'firewall_change'
    ? (expectation?.pre_post_mapping?.post_destination_target_id ?? expectation?.destination_target_id ?? latestRef(refs)?.target_id ?? null)
    : (relation?.entry_target_id ?? latestRef(refs)?.target_id ?? null);
  const scopedRefs = refsForTarget(refs, targetId);
  const newest = latestRef(scopedRefs);
  const checkIds = [...new Set(scopedRefs.map((ref) => ref.check_id))].sort();
  const evidenceIds = [...new Set(scopedRefs.flatMap((ref) => ref.evidence_ids ?? []))].sort();
  const entry = kind === 'firewall_change' ? baselineEntryFor(baseline, item.expectation_id) : null;
  const pathExpectation = kind === 'path_validation' ? expectation : null;
  const limitations = normalizeLimitations([...REQUIRED_LIMITATIONS[kind], ...(item.limitations ?? [])]);
  const priority = classification.priority;
  const failedExpectation = kind === 'firewall_change'
    ? {
        expectation_id: item.expectation_id,
        expectation_version: expectation?.expectation_version ?? entry?.expectation_version ?? null,
        expectation_digest: expectation?.digest ?? expectation?.expectation_digest ?? entry?.expectation_digest ?? null,
        expected: expectation?.expected ?? null,
        protocol: expectation?.protocol ?? null,
        port: expectation?.port ?? null,
        service_endpoint: expectation?.service_endpoint ?? null,
        source_perspective: expectation?.source_perspective ?? null,
        change_id: expectation?.change_id ?? baseline?.change_id ?? null,
      }
    : {
        expectation_id: pathExpectation?.id ?? null,
        expectation_version: pathExpectation?.expectation_version ?? null,
        expectation_digest: pathExpectation?.digest ?? pathExpectation?.expectation_digest ?? null,
        expected_behavior: relation?.expected_behavior ?? null,
        scenario: item.scenario,
        layer_outcomes: pathExpectation?.layer_outcomes ?? null,
      };
  const requiredLayers = kind === 'firewall_change'
    ? ['network_firewall']
    : (relation?.required_layers?.length
        ? [...relation.required_layers]
        : Object.entries(pathExpectation?.layer_outcomes ?? {}).filter(([, outcome]) => outcome === 'enforce').map(([layer]) => layer));
  const observedRoute = kind === 'firewall_change'
    ? {
        destination_target_id: expectation?.destination_target_id ?? targetId,
        protocol: expectation?.protocol ?? null,
        port: expectation?.port ?? null,
        service_endpoint: expectation?.service_endpoint ?? null,
        source_perspective: expectation?.source_perspective ?? null,
        pre_post_mapping: expectation?.pre_post_mapping ?? entry?.destination_mapping ?? null,
      }
    : {
        entry_path_id: item.entry_path_id,
        anchor_target_id: relation?.anchor_target_id ?? evaluation.anchor_target_id ?? null,
        entry_target_id: relation?.entry_target_id ?? targetId,
        relation_kind: relation?.relation_kind ?? null,
        origin_binding_id: relation?.origin_binding_id ?? null,
      };
  const observed = kind === 'firewall_change'
    ? {
        status: item.status,
        gap_kind: item.gap_kind ?? null,
        expectation_met: item.expectation_met ?? null,
        pre_state: item.pre_state ?? null,
        post_state: item.post_state ?? null,
        change_effect: classification.change_effect,
        reasons: [...(item.reasons ?? [])],
        compatibility_reasons: [...(item.compatibility_reasons ?? [])],
      }
    : {
        outcome: item.outcome,
        reasons: [...(item.reasons ?? [])],
        compatibility_reasons: [...(item.compatibility_reasons ?? [])],
      };
  const comparisonContext = {
    comparison_kind: kind,
    evaluation_id: evaluation.id,
    evaluation_digest: evaluation.evaluation_digest,
    evaluated_at: evaluation.evaluated_at,
    item_index: index,
    contract_version: evaluation.contract_version ?? PROTECTION_VALIDATION_CONTRACT_VERSION,
    baseline_id: evaluation.baseline_id ?? baseline?.id ?? null,
    baseline_digest: evaluation.baseline_digest ?? baseline?.baseline_digest ?? null,
    baseline_entry_digest: entry?.baseline_digest ?? null,
    baseline_captured_at: entry?.captured_at ?? baseline?.captured_at ?? null,
    change_id: failedExpectation.change_id ?? null,
    expectation_id: failedExpectation.expectation_id,
    expectation_version: failedExpectation.expectation_version,
    expectation_digest: failedExpectation.expectation_digest,
    entry_path_id: kind === 'path_validation' ? item.entry_path_id : null,
    primary_entry_path_id: evaluation.primary_entry_path_id ?? null,
    reviewed_plan_digest: evaluation.reviewed_plan_digest ?? null,
    declaration_version: relation?.declaration_version ?? null,
    declaration_digest: relation?.declaration_digest ?? null,
    scenario: kind === 'path_validation' ? item.scenario : null,
    dedupe_key: dedupeKey,
  };
  return {
    source: PROTECTION_FINDING_SOURCE,
    semantics_version: PROTECTION_FINDING_SEMANTICS_VERSION,
    contract_version: comparisonContext.contract_version,
    dedupe_key: dedupeKey,
    dedupe_basis: dedupeBasis,
    tenant_id: tenantId,
    comparison_kind: kind,
    finding_class: classification.finding_class,
    title: classification.title,
    summary: classification.summary,
    priority,
    severity: protectionPrioritySeverity(priority),
    application: { anchor_target_id: observedRoute.anchor_target_id ?? null },
    target_id: targetId,
    check_id: newest?.check_id ?? checkIds[0] ?? null,
    check_ids: checkIds,
    test_run_id: newest?.test_run_id ?? null,
    verdict_id: newest?.verdict_id ?? null,
    evidence_ids: evidenceIds,
    failed_expectation: failedExpectation,
    scenario: kind === 'path_validation' ? item.scenario : null,
    required_layers: requiredLayers,
    observed_route: observedRoute,
    observed,
    evidence_refs: refs.map((ref) => ({ ...ref, evidence_ids: [...(ref.evidence_ids ?? [])] })),
    observed_at: newest?.observed_at ?? null,
    limitations,
    owner: (kind === 'firewall_change' ? expectation?.owner : relation?.owner) ?? null,
    attribution: 'unattributed',
    control_identified: false,
    candidate_explanations: explanations(classification.explanations),
    comparison_context: comparisonContext,
    reconstruction: {
      evaluation_id: evaluation.id,
      evaluation_digest: evaluation.evaluation_digest,
      item_index: index,
      digest_verified: true,
    },
  };
}

export function deriveProtectionFindingCandidates({
  evaluation,
  entryPaths = [],
  expectations = [],
  baseline = null,
} = {}) {
  const verified = verifyProtectionEvaluation(evaluation);
  if (!verified.ok) return { ok: false, error: verified.reason, candidates: [], passing: [], skipped: [] };
  const kind = evaluation.kind;
  const tenantId = evaluation.tenant_id;
  const relations = new Map((entryPaths ?? []).filter((row) => row?.tenant_id == null || row.tenant_id === tenantId).map((row) => [row.id, row]));
  const firewallExpectations = new Map((expectations ?? []).filter((row) => row?.tenant_id == null || row.tenant_id === tenantId).map((row) => [row.id, row]));
  const changeId = baseline?.change_id ?? null;
  const candidates = [];
  const passing = [];
  const skipped = [];
  evaluation.items.forEach((item, index) => {
    const relation = kind === 'path_validation' ? relations.get(item.entry_path_id) ?? null : null;
    const expectation = kind === 'firewall_change'
      ? firewallExpectations.get(item.expectation_id) ?? null
      : resolvePathExpectation(expectations, evaluation, item);
    if (isUnavailableEvidenceItem(kind, item)) {
      skipped.push({ item_index: index, reason: UNAVAILABLE_EVIDENCE_SKIP_REASON, observation: kind === 'firewall_change' ? item.status : item.outcome });
      return;
    }
    if (isPassing(kind, item)) {
      const { dedupe_key: dedupeKey } = protectionFindingDedupeKey({ kind, tenantId, relation, expectation, item });
      passing.push({
        dedupe_key: dedupeKey,
        evaluation_id: evaluation.id,
        item_index: index,
        observation: kind === 'firewall_change' ? item.status : item.outcome,
        evaluated_at: evaluation.evaluated_at,
        closes_findings: false,
      });
      return;
    }
    const classification = kind === 'firewall_change'
      ? classifyFirewallItem(item, expectation, expectation?.change_id ?? changeId)
      : classifyPathItem(item, relation);
    if (!classification) {
      skipped.push({ item_index: index, reason: 'no_failed_expectation' });
      return;
    }
    candidates.push(buildCandidate({ evaluation, item, index, relation, expectation, baseline, classification }));
  });
  return { ok: true, error: null, candidates, passing, skipped };
}

function candidateOrder(a, b) {
  return String(b.comparison_context.evaluated_at ?? '').localeCompare(String(a.comparison_context.evaluated_at ?? ''))
    || protectionFindingClassRank(b.finding_class) - protectionFindingClassRank(a.finding_class)
    || String(b.comparison_context.evaluation_id).localeCompare(String(a.comparison_context.evaluation_id))
    || a.comparison_context.item_index - b.comparison_context.item_index;
}

export function dedupeProtectionFindingCandidates(candidates = []) {
  const groups = new Map();
  for (const candidate of candidates) {
    if (!candidate?.dedupe_key) continue;
    const key = `${candidate.tenant_id}|${candidate.dedupe_key}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(candidate);
  }
  return [...groups.values()].map((group) => {
    const sorted = [...group].sort(candidateOrder);
    const strongest = [...group].sort((a, b) => protectionFindingClassRank(b.finding_class) - protectionFindingClassRank(a.finding_class))[0];
    return {
      ...sorted[0],
      strongest_observed_class: strongest.finding_class,
      source_evaluation_ids: [...new Set(group.map((row) => row.comparison_context.evaluation_id))].sort(),
      observation_count: group.length,
    };
  }).sort((a, b) => a.dedupe_key.localeCompare(b.dedupe_key));
}

export function isProtectionValidationFinding(finding) {
  return Boolean(finding) && (finding.source === PROTECTION_FINDING_SOURCE || isObject(finding.protection_validation));
}

/** A retest must retain the declared origin relation; an unbound run is a different test. */
export function protectionRetestRunScopeMatches(finding, run) {
  if (!isProtectionValidationFinding(finding)) return true;
  const pv = finding.protection_validation ?? {};
  if ((pv.comparison_kind ?? pv.comparison_context?.comparison_kind) !== 'path_validation') return true;
  return (pv.observed_route?.origin_binding_id ?? null) === (run?.origin_binding_id || null);
}

function findingDedupeKey(row) {
  return row?.dedupe_key ?? row?.protection_validation?.dedupe_key ?? null;
}

function findingClassOf(row) {
  return row?.finding_class ?? row?.protection_validation?.finding_class ?? null;
}

function rowStatus(row) {
  const value = row?.status ?? row?.state;
  return value == null || String(value).trim() === '' ? 'open' : String(value).trim().toLowerCase();
}

function latestObservation(candidate) {
  return {
    finding_class: candidate.finding_class,
    observed: candidate.observed,
    evaluation_id: candidate.comparison_context.evaluation_id,
    evaluation_digest: candidate.comparison_context.evaluation_digest,
    item_index: candidate.comparison_context.item_index,
    evaluated_at: candidate.comparison_context.evaluated_at,
    test_run_id: candidate.test_run_id,
  };
}

export function planProtectionFindingUpsert({ existingFindings = [], candidate } = {}) {
  if (!candidate?.dedupe_key) return { action: 'none', reason: 'invalid_candidate', closes_findings: false, sibling_closure: false };
  if (!PROTECTION_FINDING_CLASSES.includes(candidate.finding_class)) {
    const reason = LEGACY_PROTECTION_FINDING_CLASSES.includes(candidate.finding_class) ? UNAVAILABLE_EVIDENCE_SKIP_REASON : 'invalid_candidate';
    return { action: 'none', reason, closes_findings: false, sibling_closure: false };
  }
  const matches = (existingFindings ?? [])
    .filter((row) => row?.tenant_id === candidate.tenant_id && findingDedupeKey(row) === candidate.dedupe_key)
    .sort((a, b) => String(b.created_at ?? '').localeCompare(String(a.created_at ?? '')));
  const base = { closes_findings: false, sibling_closure: false };
  const open = matches.find((row) => OPEN_STATUSES.has(rowStatus(row)));
  if (open) {
    const currentClass = findingClassOf(open);
    const escalate = protectionFindingClassRank(candidate.finding_class) > protectionFindingClassRank(currentClass);
    const currentSeverity = open.severity ?? 'low';
    const severity = (SEVERITY_RANK[candidate.severity] ?? 0) > (SEVERITY_RANK[currentSeverity] ?? 0) ? candidate.severity : currentSeverity;
    const patch = {
      latest_observation: latestObservation(candidate),
      last_evaluation_id: candidate.comparison_context.evaluation_id,
      severity,
    };
    if (escalate) {
      Object.assign(patch, {
        finding_class: candidate.finding_class,
        priority: candidate.priority,
        title: candidate.title,
        escalated_from_class: currentClass,
      });
    }
    return { ...base, action: escalate ? 'escalate' : 'record_observation', finding_id: open.id, status_unchanged: true, patch };
  }
  const excepted = matches.find((row) => EXCEPTION_STATUSES.has(rowStatus(row)));
  if (excepted) {
    if (protectionFindingClassRank(candidate.finding_class) <= protectionFindingClassRank(findingClassOf(excepted))) {
      return { ...base, action: 'exception_retained', finding_id: excepted.id, status_unchanged: true, patch: { latest_observation: latestObservation(candidate) } };
    }
    return { ...base, action: 'create', escalated_from_finding_id: excepted.id };
  }
  const closed = matches[0];
  if (closed) {
    return { ...base, action: 'create', recurrence_of_finding_id: closed.id };
  }
  return { ...base, action: 'create' };
}

const PROTECTION_PATCH_TOP_LEVEL = Object.freeze(['severity', 'title', 'finding_class', 'priority']);

/** Apply a planned upsert patch: lifecycle status and closure are never touched here. */
export function applyProtectionFindingPatch(row, patch = {}, now = new Date().toISOString()) {
  const next = { ...row, protection_validation: { ...(row.protection_validation ?? {}) } };
  for (const [key, value] of Object.entries(patch)) {
    if (PROTECTION_PATCH_TOP_LEVEL.includes(key)) next[key] = value;
    else next.protection_validation[key] = value;
  }
  if (patch.finding_class) next.protection_validation.finding_class = patch.finding_class;
  if (patch.priority) next.protection_validation.priority = patch.priority;
  next.updated_at = now;
  return next;
}

export function protectionFindingClosureSignal({ finding, passingObservation = null, externalTicket = null } = {}) {
  const signals = [];
  if (passingObservation && findingDedupeKey(finding) === passingObservation.dedupe_key) signals.push('newer_passing_observation');
  if (externalTicket && ['closed', 'resolved', 'done'].includes(String(externalTicket.status ?? '').toLowerCase())) signals.push('external_ticket_closed');
  return {
    finding_id: finding?.id ?? null,
    action: 'none',
    close: false,
    sibling_closure: false,
    can_advance_remediation: false,
    requires_explicit_lifecycle_action: true,
    signals,
  };
}

export function toProtectionFindingRow(candidate, { id, now = new Date(), upsert = null } = {}) {
  const timestamp = new Date(now).toISOString();
  const { title, summary, severity, tenant_id: tenantId, target_id: targetId, check_id: checkId, test_run_id: testRunId, verdict_id: verdictId, evidence_ids: evidenceIds, dedupe_key: dedupeKey } = candidate;
  const protection = { ...candidate };
  for (const field of ['title', 'summary', 'severity', 'tenant_id', 'target_id', 'check_id', 'test_run_id', 'verdict_id', 'evidence_ids']) delete protection[field];
  return {
    id,
    tenant_id: tenantId,
    target_group_id: null,
    target_id: targetId,
    check_id: checkId,
    test_run_id: testRunId,
    verdict_id: verdictId,
    title,
    severity,
    status: 'open',
    assignee: null,
    notes: summary,
    evidence_ids: evidenceIds,
    source: PROTECTION_FINDING_SOURCE,
    dedupe_key: dedupeKey,
    finding_class: candidate.finding_class,
    priority: candidate.priority,
    protection_validation: {
      ...protection,
      recurrence_of_finding_id: upsert?.recurrence_of_finding_id ?? null,
      escalated_from_finding_id: upsert?.escalated_from_finding_id ?? null,
    },
    closed_at: null,
    created_at: timestamp,
    updated_at: timestamp,
  };
}

function targetUsable(target, tenantId) {
  return Boolean(target) && target.tenant_id === tenantId && !target.deleted_at && !target.archived_at && target.status !== 'archived' && target.status !== 'deleted';
}

function deny(error, status, extra = {}) {
  return { ok: false, error, status, drift: [], comparable_with_original: false, ...extra };
}

export function assessProtectionRetestAuthorization({
  finding,
  tenantId,
  entryPath = null,
  anchorTarget = null,
  entryTarget = null,
  originBinding = null,
  expectation = null,
  destinationTarget = null,
  ownershipVerified = false,
} = {}) {
  if (!isProtectionValidationFinding(finding)) return deny('not_protection_finding', 400);
  if (!tenantId || finding.tenant_id !== tenantId) return deny('unknown_finding', 404);
  const pv = finding.protection_validation ?? {};
  const context = pv.comparison_context ?? {};
  const kind = pv.comparison_kind ?? context.comparison_kind;
  const drift = [];
  if (kind === 'path_validation') {
    if (!entryPath || entryPath.tenant_id !== tenantId) return deny('entry_path_archived', 409);
    const route = pv.observed_route ?? {};
    const sameScope = entryPath.anchor_target_id === route.anchor_target_id
      && entryPath.entry_target_id === route.entry_target_id
      && (route.relation_kind == null || entryPath.relation_kind === route.relation_kind)
      && (entryPath.origin_binding_id ?? null) === (route.origin_binding_id ?? null);
    if (!sameScope) return deny('retest_scope_mismatch', 409);
    const authorized = entryPathAuthorizesExecution(entryPath, { anchorTarget, entryTarget, originBinding, tenantId });
    if (!authorized.ok) return deny(authorized.error, authorized.status, { field: authorized.field ?? null });
    if (entryTarget?.id !== finding.target_id) return deny('retest_scope_mismatch', 409);
    if (context.declaration_digest && context.declaration_digest !== entryPath.declaration_digest) drift.push('declaration_changed');
    if (context.entry_path_id && context.entry_path_id !== entryPath.id) drift.push('entry_path_version_changed');
  } else if (kind === 'firewall_change') {
    if (!expectation || expectation.tenant_id !== tenantId || expectation.status !== 'active') return deny('expectation_not_active', 409);
    const route = pv.observed_route ?? {};
    if (expectation.destination_target_id !== route.destination_target_id
      || expectation.protocol !== route.protocol
      || (expectation.port ?? null) !== (route.port ?? null)
      || JSON.stringify(expectation.service_endpoint ?? null) !== JSON.stringify(route.service_endpoint ?? null)
      || expectation.source_perspective !== route.source_perspective) return deny('retest_scope_mismatch', 409);
    const postTargetId = expectation.pre_post_mapping?.post_destination_target_id ?? expectation.destination_target_id;
    if (!destinationTarget || destinationTarget.id !== postTargetId || destinationTarget.id !== finding.target_id) return deny('unknown_target', 404);
    if (!targetUsable(destinationTarget, tenantId)) return deny('target_not_active', 409);
    const digest = expectation.digest ?? expectation.expectation_digest ?? null;
    if (context.expectation_digest && context.expectation_digest !== digest) drift.push('expectation_changed');
    if (context.expectation_id && context.expectation_id !== expectation.id) drift.push('expectation_version_changed');
  } else {
    return deny('comparison_context_missing', 409);
  }
  if (ownershipVerified !== true) return deny('target_not_authorized', 409);
  return { ok: true, error: null, status: 200, drift, comparable_with_original: drift.length === 0 };
}

export function protectionRetestContext(finding, authorization = null) {
  if (!isProtectionValidationFinding(finding)) return null;
  const context = finding.protection_validation?.comparison_context ?? {};
  return {
    comparison_kind: context.comparison_kind ?? finding.protection_validation?.comparison_kind ?? null,
    dedupe_key: context.dedupe_key ?? findingDedupeKey(finding),
    evaluation_id: context.evaluation_id ?? null,
    evaluation_digest: context.evaluation_digest ?? null,
    item_index: context.item_index ?? null,
    baseline_id: context.baseline_id ?? null,
    baseline_digest: context.baseline_digest ?? null,
    baseline_entry_digest: context.baseline_entry_digest ?? null,
    baseline_captured_at: context.baseline_captured_at ?? null,
    change_id: context.change_id ?? null,
    expectation_id: context.expectation_id ?? null,
    expectation_version: context.expectation_version ?? null,
    expectation_digest: context.expectation_digest ?? null,
    entry_path_id: context.entry_path_id ?? null,
    declaration_version: context.declaration_version ?? null,
    declaration_digest: context.declaration_digest ?? null,
    scenario: context.scenario ?? null,
    authorization_rechecked: authorization?.ok === true,
    drift: [...(authorization?.drift ?? [])],
    comparable_with_original: authorization?.comparable_with_original === true,
  };
}
