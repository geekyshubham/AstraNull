import { isIP } from 'node:net';
import {
  DEFAULT_FRESHNESS_WINDOW_SECONDS,
  PROTECTION_LAYERS,
  PROTECTION_VALIDATION_CONTRACT_VERSION,
  PROTECTION_VALIDATION_LIMITATIONS,
  REQUIRED_LIMITATIONS,
  assessFreshness,
  emptyProtectionMatrixRow,
  normalizeLimitations,
  sha256Digest,
} from '../contracts/protectionValidation.mjs';
import { OBSERVATION_ONLY_PROBE_KINDS, evidenceTierForProbeKind } from './probeEvidenceTiers.mjs';
import {
  FIREWALL_UNRESOLVED_STATUSES,
  PATH_GAP_OUTCOMES,
  PATH_PASSING_OUTCOMES,
  PATH_UNRESOLVED_OUTCOMES,
  isUnavailableEvidenceItem,
  verifyProtectionEvaluation,
} from './protectionValidationFindings.mjs';

export const PROTECTION_REPORT_SEMANTICS_VERSION = 'protection-validation-report-v1';
export const MAX_REPORT_CONCLUSIONS = 500;
export const MAX_REPORT_LISTED_IDS = 200;

export const PATH_OUTCOME_PRECEDENCE = Object.freeze([
  'scoped_application_bypass',
  'reachability_exposure',
  'suspected_alternate_application_route',
  'weaker_observed_enforcement',
  'inconclusive',
  'skipped',
  'not_tested',
  'consistent_enforcement',
  'intentional_public_access',
]);

export const REPORT_STATEMENTS = Object.freeze({
  path_validation: 'Entry-path results describe sampled external behavior on each tested declared path, source, scenario, and time. Untested paths are not covered and stacked layers are not attributed.',
  firewall_change: 'Firewall change results describe sampled public-ingress behavior only. Rule-table, routing, NAT, egress, east-west, appliance-traversal, and capacity equivalence are not established.',
  detection: 'Provider or vendor detection is reported separately and is not evidence of enforcement.',
  readiness: 'Observation-only and transport-only evidence is excluded from readiness and never counts as validated protection.',
  unknowns: 'Results with missing, unfinalized, stale, or incompatible evidence stay visible as unknown or not tested. They never count as validated and do not create findings.',
});

const OBSERVATION_ONLY = new Set(OBSERVATION_ONLY_PROBE_KINDS);

function list(value) {
  return Array.isArray(value) ? value : [];
}

function capped(ids) {
  const sorted = [...new Set(ids)].sort();
  return { ids: sorted.slice(0, MAX_REPORT_LISTED_IDS), total: sorted.length, truncated: sorted.length > MAX_REPORT_LISTED_IDS };
}

function targetActive(target) {
  return Boolean(target) && !target.deleted_at && !target.archived_at && target.status !== 'archived' && target.status !== 'deleted';
}

export function rollupPathOutcome(outcomes) {
  const present = new Set(list(outcomes));
  return PATH_OUTCOME_PRECEDENCE.find((outcome) => present.has(outcome)) ?? 'not_tested';
}

export function evidenceReadinessClass(ref, catalogById) {
  const check = catalogById.get(ref?.check_id);
  const kind = check?.probe_profile?.kind;
  if (typeof kind !== 'string') return { eligible: false, reason: 'check_not_in_catalog', tier: null };
  if (kind === 'metadata_marker' || kind === 'ops_readiness') return { eligible: false, reason: 'declaration_only_check', tier: evidenceTierForProbeKind(kind) };
  if (OBSERVATION_ONLY.has(kind)) return { eligible: false, reason: 'observation_only_check', tier: evidenceTierForProbeKind(kind) };
  return { eligible: true, reason: null, tier: evidenceTierForProbeKind(kind) };
}

function newestObservedAt(refs) {
  return list(refs).map((ref) => ref.observed_at).filter(Boolean).sort().at(-1) ?? null;
}

function itemFreshness(refs, windowSeconds, now) {
  const newest = newestObservedAt(refs);
  if (!newest) return { state: 'no_evidence', observed_at: null, age_seconds: null, expires_at: null };
  const fresh = assessFreshness(newest, windowSeconds, now);
  return { state: fresh.fresh ? 'fresh' : 'stale', observed_at: newest, age_seconds: fresh.age_seconds, expires_at: fresh.expires_at };
}

function verifiedEvaluations(evaluations, kind, tenantId, exclusions) {
  const out = [];
  for (const evaluation of list(evaluations)) {
    if (!evaluation || evaluation.tenant_id !== tenantId) {
      exclusions.cross_tenant_or_invalid += 1;
      continue;
    }
    if (evaluation.kind !== kind) continue;
    const verified = verifyProtectionEvaluation(evaluation);
    if (!verified.ok) {
      exclusions.records.push({ kind: 'evaluation', id: evaluation.id ?? null, reason: verified.reason });
      continue;
    }
    out.push(evaluation);
  }
  return out;
}

function newerSelection(current, candidate) {
  if (!current) return true;
  const order = String(candidate.evaluation.evaluated_at).localeCompare(String(current.evaluation.evaluated_at));
  if (order !== 0) return order > 0;
  return String(candidate.evaluation.id).localeCompare(String(current.evaluation.id)) > 0;
}

export function selectCurrentPathItems(evaluations, { tenantId } = {}) {
  const exclusions = { cross_tenant_or_invalid: 0, records: [] };
  const selected = new Map();
  for (const evaluation of verifiedEvaluations(evaluations, 'path_validation', tenantId, exclusions)) {
    evaluation.items.forEach((item, index) => {
      const key = `${item.entry_path_id}|${item.scenario}`;
      const candidate = { key, item, item_index: index, evaluation };
      if (newerSelection(selected.get(key), candidate)) selected.set(key, candidate);
    });
  }
  return { selected, exclusions };
}

/** A later evaluation that never sampled an expectation does not hide an earlier sampled result for it. */
function preferredFirewallSelection(current, candidate) {
  if (!current) return true;
  const currentSampled = current.item.status !== 'not_tested';
  const candidateSampled = candidate.item.status !== 'not_tested';
  if (currentSampled !== candidateSampled) return candidateSampled;
  return newerSelection(current, candidate);
}

export function selectCurrentFirewallItems(evaluations, { tenantId } = {}) {
  const exclusions = { cross_tenant_or_invalid: 0, records: [] };
  const selected = new Map();
  for (const evaluation of verifiedEvaluations(evaluations, 'firewall_change', tenantId, exclusions)) {
    evaluation.items.forEach((item, index) => {
      const candidate = { key: item.expectation_id, item, item_index: index, evaluation };
      if (preferredFirewallSelection(selected.get(item.expectation_id), candidate)) selected.set(item.expectation_id, candidate);
    });
  }
  return { selected, exclusions };
}

function layerObservedEnforcement(outcome, relation, reasons) {
  switch (outcome) {
    case 'consistent_enforcement': return 'enforced';
    case 'weaker_observed_enforcement': return 'partially_enforced';
    case 'suspected_alternate_application_route':
    case 'scoped_application_bypass': return 'not_enforced';
    case 'reachability_exposure':
      return relation.expected_behavior === 'must_not_be_reachable' && !list(reasons).includes('enforcement_not_measured') ? 'not_enforced' : 'inconclusive';
    case 'inconclusive': return 'inconclusive';
    default: return 'not_tested';
  }
}

const L7_EDGE_LAYERS = Object.freeze(['waf', 'cdn_edge']);

/** Layers whose enforcement a probe kind can observe from outside; ddos capacity is never measured. */
export const LAYERS_MEASURED_BY_PROBE_KIND = Object.freeze({
  waf_class_marker_probe: L7_EDGE_LAYERS,
  waf_evasion_marker_probe: L7_EDGE_LAYERS,
  waf_inspection_limit_probe: L7_EDGE_LAYERS,
  waf_enforcement_probe: L7_EDGE_LAYERS,
  outside_in_waf_scan: L7_EDGE_LAYERS,
  host_sni_bypass: L7_EDGE_LAYERS,
  http_head: L7_EDGE_LAYERS,
  port_scan_bounded: Object.freeze(['network_firewall']),
});

function measuredLayers(refs, catalogById) {
  const kinds = list(refs).map((ref) => catalogById.get(ref?.check_id)?.probe_profile?.kind);
  if (!kinds.length) return null;
  if (kinds.some((kind) => typeof kind !== 'string')) return new Set();
  const sets = kinds.map((kind) => new Set(LAYERS_MEASURED_BY_PROBE_KIND[kind] ?? []));
  return new Set([...sets[0]].filter((layer) => sets.every((set) => set.has(layer))));
}

function detectionIndex(detections, tenantId) {
  const index = new Map();
  for (const signal of list(detections)) {
    if (!signal || (signal.tenant_id != null && signal.tenant_id !== tenantId)) continue;
    if (!PROTECTION_LAYERS.includes(signal.layer)) continue;
    const key = `${signal.target_id}|${signal.layer}`;
    if (!index.has(key)) index.set(key, []);
    index.get(key).push(signal);
  }
  return index;
}

function vendorDetectionState(signals) {
  if (!signals?.length) return 'unknown';
  if (signals.some((signal) => signal.state === 'detected')) return 'detected';
  if (signals.every((signal) => signal.state === 'not_detected')) return 'not_detected';
  return 'unknown';
}

export function projectProtectionMatrixRows({
  tenantId,
  entryPaths = [],
  pathEvaluations = [],
  pathExpectations = [],
  detections = [],
  checkCatalog = [],
  now = new Date(),
  freshnessWindowSeconds = DEFAULT_FRESHNESS_WINDOW_SECONDS,
} = {}) {
  const catalogById = new Map(list(checkCatalog).map((check) => [check?.check_id ?? check?.id, check]));
  const { selected, exclusions } = selectCurrentPathItems(pathEvaluations, { tenantId });
  const detectionsByKey = detectionIndex(detections, tenantId);
  const expectationById = new Map(list(pathExpectations).filter((exp) => exp?.tenant_id == null || exp.tenant_id === tenantId).map((exp) => [exp.id, exp]));
  const rows = [];
  for (const relation of list(entryPaths)) {
    if (!relation || relation.tenant_id !== tenantId) continue;
    const row = emptyProtectionMatrixRow(relation);
    const current = [...selected.values()].filter((entry) => entry.item.entry_path_id === relation.id)
      .sort((a, b) => a.item.scenario.localeCompare(b.item.scenario));
    row.scenarios = current.map((entry) => {
      const freshness = itemFreshness(entry.item.evidence_refs, freshnessWindowSeconds, now);
      return {
        scenario: entry.item.scenario,
        outcome: entry.item.outcome,
        reasons: [...list(entry.item.reasons)],
        compatibility_reasons: [...list(entry.item.compatibility_reasons)],
        evaluation_id: entry.evaluation.id,
        evaluation_digest: entry.evaluation.evaluation_digest,
        evaluated_at: entry.evaluation.evaluated_at,
        item_index: entry.item_index,
        evidence_refs: list(entry.item.evidence_refs),
        limitations: [...list(entry.item.limitations)],
        freshness,
      };
    });
    row.outcome = rollupPathOutcome(row.scenarios.map((scenario) => scenario.outcome));
    const driving = row.scenarios.find((scenario) => scenario.outcome === row.outcome) ?? null;
    row.evidence_refs = driving ? driving.evidence_refs : [];
    row.latest_comparison_id = row.scenarios.map((scenario) => ({ id: scenario.evaluation_id, at: scenario.evaluated_at }))
      .sort((a, b) => String(b.at).localeCompare(String(a.at)))[0]?.id ?? null;
    row.freshness = driving ? driving.freshness : null;
    row.limitations = normalizeLimitations([...REQUIRED_LIMITATIONS.path_validation, ...row.scenarios.flatMap((scenario) => scenario.limitations)]);
    const drivingEvaluation = driving ? current.find((entry) => entry.evaluation.id === driving.evaluation_id)?.evaluation : null;
    const pinnedExpectationId = drivingEvaluation?.expectation_id ?? drivingEvaluation?.provenance?.expectation_id;
    const drivingExpectation = pinnedExpectationId
      ? expectationById.get(pinnedExpectationId) ?? null
      : driving ? [...expectationById.values()]
        .filter((exp) => exp.scenario === driving.scenario && exp.anchor_target_id === relation.anchor_target_id)
        .sort((a, b) => (b.expectation_version ?? 0) - (a.expectation_version ?? 0))[0] ?? null
      : null;
    const enforceLayers = new Set(drivingExpectation
      ? Object.entries(drivingExpectation.layer_outcomes ?? {}).filter(([, outcome]) => outcome === 'enforce').map(([layer]) => layer)
      : list(relation.required_layers));
    const measured = driving ? measuredLayers(driving.evidence_refs, catalogById) : null;
    row.layers = row.layers.map((layer) => {
      const next = { ...layer, evidence_limitations: [...layer.evidence_limitations] };
      next.vendor_detection = vendorDetectionState(detectionsByKey.get(`${relation.entry_target_id}|${layer.layer}`));
      if (next.vendor_detection !== 'unknown') next.evidence_limitations = normalizeLimitations([...next.evidence_limitations, 'vendor_label_not_proof']);
      if (!driving || !enforceLayers.has(layer.layer)) return next;
      if (measured && !measured.has(layer.layer)) {
        next.observed_enforcement = 'not_tested';
        next.evidence_limitations = normalizeLimitations([...next.evidence_limitations, 'layer_not_measured_by_scenario']);
        return next;
      }
      const observed = layerObservedEnforcement(row.outcome, relation, driving.reasons);
      const hasRefs = driving.evidence_refs.some((ref) => ref?.finalized !== false);
      next.observed_enforcement = hasRefs || ['inconclusive', 'not_tested'].includes(observed) ? observed : 'inconclusive';
      next.application_identity = row.outcome === 'scoped_application_bypass' ? 'confirmed' : (row.outcome === 'suspected_alternate_application_route' ? 'not_established' : 'not_tested');
      next.suspected_bypass = ['scoped_application_bypass', 'suspected_alternate_application_route'].includes(row.outcome) ? 'suspected' : (row.outcome === 'consistent_enforcement' ? 'not_suspected' : 'unknown');
      next.confirmed_scoped_bypass = row.outcome === 'scoped_application_bypass' ? 'confirmed' : (['consistent_enforcement', 'suspected_alternate_application_route', 'weaker_observed_enforcement'].includes(row.outcome) ? 'not_confirmed' : 'unknown');
      next.attribution = 'unattributed';
      next.evidence_refs = hasRefs ? driving.evidence_refs : [];
      next.freshness = driving.freshness;
      if ([...enforceLayers].filter((name) => !measured || measured.has(name)).length > 1) next.evidence_limitations = normalizeLimitations([...next.evidence_limitations, 'stacked_layer_attribution_not_established']);
      return next;
    });
    rows.push(row);
  }
  rows.sort((a, b) => String(a.anchor_target_id).localeCompare(String(b.anchor_target_id)) || String(a.entry_path_id).localeCompare(String(b.entry_path_id)));
  return { rows, exclusions };
}

function readinessSupport(refs, catalogById) {
  const classes = list(refs).map((ref) => evidenceReadinessClass(ref, catalogById));
  if (!classes.length) return { eligible: false, reason: 'no_evidence' };
  if (classes.every((entry) => entry.eligible)) return { eligible: true, reason: null };
  if (classes.some((entry) => entry.reason === 'check_not_in_catalog')) return { eligible: false, reason: 'check_not_in_catalog' };
  if (classes.some((entry) => entry.reason === 'declaration_only_check')) return { eligible: false, reason: 'declaration_only_check' };
  return { eligible: false, reason: 'observation_only_check' };
}

function conclusionId(parts) {
  return `pvc_${sha256Digest(parts).slice(0, 32)}`;
}

function pathRowStatus(row, catalogById) {
  if (row.status !== 'active') return 'excluded';
  if (PATH_GAP_OUTCOMES.includes(row.outcome)) return 'gap';
  if (row.outcome === 'not_tested' || row.outcome === 'skipped') return row.outcome;
  if (row.outcome === 'inconclusive') return 'unknown';
  if (PATH_PASSING_OUTCOMES.includes(row.outcome)) {
    if (row.scenarios.some((scenario) => isUnavailableEvidenceItem('path_validation', scenario))) return 'unknown';
    if (row.scenarios.some((scenario) => scenario.freshness.state !== 'fresh')) return 'stale';
    const support = row.scenarios.map((scenario) => readinessSupport(scenario.evidence_refs, catalogById));
    if (support.some((entry) => entry.reason === 'observation_only_check')) return 'observation_only';
    if (support.some((entry) => !entry.eligible)) return 'unclassified_check';
    if (row.required_layers.some((name) => row.layers.find((layer) => layer.layer === name)?.observed_enforcement !== 'enforced')) return 'unknown';
    return 'validated';
  }
  return 'unknown';
}

function firewallItemStatus(item) {
  if (!item) return 'not_tested';
  if (item.status === 'regression' || (item.status === 'matched' && item.expectation_met === false)) return 'gap';
  if ((item.status === 'matched' || item.status === 'improvement') && item.expectation_met === true) return isUnavailableEvidenceItem('firewall_change', item) ? 'inconclusive' : 'accepted';
  return FIREWALL_UNRESOLVED_STATUSES.includes(item.status) ? item.status : 'inconclusive';
}

function countBy(values, keys) {
  const out = Object.fromEntries(keys.map((key) => [key, 0]));
  for (const value of values) out[value] = (out[value] ?? 0) + 1;
  return out;
}

export function buildProtectionValidationReport({
  tenantId,
  generatedAt = new Date(),
  targets = [],
  entryPaths = [],
  pathEvaluations = [],
  pathExpectations = [],
  firewallExpectations = [],
  firewallEvaluations = [],
  detections = [],
  checkCatalog = [],
  freshnessWindowSeconds = DEFAULT_FRESHNESS_WINDOW_SECONDS,
  scope = {},
} = {}) {
  const now = new Date(generatedAt);
  const generated = now.toISOString();
  const catalogById = new Map(list(checkCatalog).map((check) => [check.check_id, check]));
  const targetById = new Map(list(targets).filter((target) => target?.tenant_id === tenantId).map((target) => [target.id, target]));
  const anchorScope = Array.isArray(scope.anchor_target_ids) && scope.anchor_target_ids.length ? new Set(scope.anchor_target_ids) : null;
  const exclusionRecords = [];
  let crossTenant = 0;

  const scopedPaths = [];
  for (const relation of list(entryPaths)) {
    if (!relation || relation.tenant_id !== tenantId) {
      crossTenant += 1;
      continue;
    }
    if (anchorScope && !anchorScope.has(relation.anchor_target_id)) continue;
    if (relation.status !== 'active') {
      exclusionRecords.push({ kind: 'entry_path', id: relation.id, reason: 'entry_path_archived' });
      continue;
    }
    const anchor = targetById.get(relation.anchor_target_id);
    const entry = targetById.get(relation.entry_target_id);
    if (!targetActive(anchor) || !targetActive(entry)) {
      exclusionRecords.push({ kind: 'entry_path', id: relation.id, reason: 'target_not_active' });
      continue;
    }
    scopedPaths.push(relation);
  }

  const projection = projectProtectionMatrixRows({
    tenantId,
    entryPaths: scopedPaths,
    pathEvaluations,
    pathExpectations,
    detections,
    checkCatalog,
    now,
    freshnessWindowSeconds,
  });
  crossTenant += projection.exclusions.cross_tenant_or_invalid;
  exclusionRecords.push(...projection.exclusions.records);
  const rows = projection.rows;
  const activePathIds = new Set(rows.map((row) => row.entry_path_id));
  const orphanItems = new Set();
  for (const evaluation of list(pathEvaluations)) {
    if (evaluation?.tenant_id !== tenantId) continue;
    for (const item of list(evaluation.items)) {
      if (!activePathIds.has(item.entry_path_id)) orphanItems.add(item.entry_path_id);
    }
  }

  const rowStatuses = new Map(rows.map((row) => [row.entry_path_id, pathRowStatus(row, catalogById)]));

  const applications = new Map();
  for (const row of rows) {
    if (!applications.has(row.anchor_target_id)) applications.set(row.anchor_target_id, []);
    applications.get(row.anchor_target_id).push(row);
  }
  const applicationStatus = [...applications.entries()].map(([anchorId, appRows]) => {
    const statuses = appRows.map((row) => rowStatuses.get(row.entry_path_id));
    const status = statuses.includes('gap') ? 'gap'
      : statuses.every((value) => value === 'validated') ? 'validated'
        : statuses.every((value) => value === 'not_tested' || value === 'skipped') ? 'not_tested'
          : 'incomplete';
    return { anchor_target_id: anchorId, status, has_primary_route: appRows.some((row) => row.relation_kind === 'primary_route') };
  });

  const hosts = new Map();
  const hostKey = (targetId) => {
    const target = targetById.get(targetId);
    const value = String(target?.value ?? '').trim();
    try {
      const authority = isIP(value) === 6 ? `[${value}]` : value;
      return new URL(/^https?:\/\//i.test(value) ? value : `https://${authority}`).hostname.toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
    } catch {
      return targetId;
    }
  };
  for (const row of rows) {
    const status = rowStatuses.get(row.entry_path_id);
    const host = hostKey(row.entry_target_id);
    const current = hosts.get(host) ?? new Set();
    current.add(status);
    hosts.set(host, current);
  }
  const hostStatus = [...hosts.entries()].map(([targetId, statuses]) => ({
    target_id: targetId,
    status: statuses.has('gap') ? 'gap'
      : [...statuses].every((value) => value === 'validated') ? 'validated'
        : [...statuses].every((value) => value === 'not_tested' || value === 'skipped') ? 'not_tested'
          : 'incomplete',
  }));

  const scopedExpectations = [];
  for (const expectation of list(firewallExpectations)) {
    if (!expectation || expectation.tenant_id !== tenantId) {
      crossTenant += 1;
      continue;
    }
    if (expectation.status !== 'active') {
      exclusionRecords.push({ kind: 'firewall_expectation', id: expectation.id, reason: 'expectation_archived' });
      continue;
    }
    if (!targetActive(targetById.get(expectation.destination_target_id))) {
      exclusionRecords.push({ kind: 'firewall_expectation', id: expectation.id, reason: 'target_not_active' });
      continue;
    }
    scopedExpectations.push(expectation);
  }
  const firewallSelection = selectCurrentFirewallItems(firewallEvaluations, { tenantId });
  crossTenant += firewallSelection.exclusions.cross_tenant_or_invalid;
  exclusionRecords.push(...firewallSelection.exclusions.records);
  const firewallRows = scopedExpectations.map((expectation) => {
    const current = firewallSelection.selected.get(expectation.id) ?? null;
    const item = current?.item ?? null;
    const freshness = item ? itemFreshness(item.evidence_refs, freshnessWindowSeconds, now) : { state: 'no_evidence', observed_at: null, age_seconds: null, expires_at: null };
    let status = firewallItemStatus(item);
    if (status === 'accepted' && freshness.state !== 'fresh') status = 'stale';
    return { expectation, current, item, status, freshness };
  });

  const pairs = new Map();
  const addPairs = (refs) => {
    for (const ref of list(refs)) {
      const key = `${ref.target_id}|${ref.check_id}`;
      if (!pairs.has(key)) pairs.set(key, { target_id: ref.target_id, check_id: ref.check_id, ...evidenceReadinessClass(ref, catalogById) });
    }
  };
  rows.forEach((row) => row.scenarios.forEach((scenario) => addPairs(scenario.evidence_refs)));
  firewallRows.forEach((row) => addPairs(row.item?.evidence_refs));
  const pairList = [...pairs.values()];

  const layerDetection = Object.fromEntries(PROTECTION_LAYERS.map((layer) => {
    const states = new Map();
    const providers = new Map();
    for (const row of rows) {
      const signals = detectionIndexForLayer(detections, tenantId, row.entry_target_id, layer);
      const state = vendorDetectionState(signals);
      const host = hostKey(row.entry_target_id);
      const prior = states.get(host);
      if (!prior || prior === 'unknown' || state === 'detected') states.set(host, state);
      for (const signal of signals.filter((entry) => entry.state === 'detected' && entry.provider)) {
        if (!providers.has(signal.provider)) providers.set(signal.provider, new Set());
        providers.get(signal.provider).add(host);
      }
    }
    const values = [...states.values()];
    const multi = [...states.keys()].filter((targetId) => [...providers.values()].filter((set) => set.has(targetId)).length > 1).length;
    return [layer, {
      unit: 'unique_host',
      denominator: states.size,
      ...countBy(values, ['detected', 'not_detected', 'unknown']),
      hosts_with_multiple_providers: multi,
      by_provider: Object.fromEntries([...providers.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([provider, set]) => [provider, set.size])),
      provider_counts_overlap: multi > 0,
    }];
  }));

  const layerEnforcement = Object.fromEntries(PROTECTION_LAYERS.map((layer) => {
    const required = rows.filter((row) => row.required_layers.includes(layer));
    const states = required.map((row) => row.layers.find((entry) => entry.layer === layer)?.observed_enforcement ?? 'not_tested');
    return [layer, {
      unit: 'entry_path',
      attribution: 'unattributed',
      denominator: required.length,
      ...countBy(states, ['enforced', 'partially_enforced', 'not_enforced', 'inconclusive', 'not_tested']),
    }];
  }));

  const conclusions = [];
  for (const row of rows) {
    for (const scenario of row.scenarios) {
      const support = readinessSupport(scenario.evidence_refs, catalogById);
      conclusions.push({
        id: conclusionId({ kind: 'path_validation', evaluation_id: scenario.evaluation_id, item_index: scenario.item_index }),
        unit: 'entry_path',
        comparison_kind: 'path_validation',
        subject: { anchor_target_id: row.anchor_target_id, entry_path_id: row.entry_path_id, entry_target_id: row.entry_target_id, relation_kind: row.relation_kind },
        scenario: scenario.scenario,
        result: scenario.outcome,
        reasons: scenario.reasons,
        compatibility_reasons: scenario.compatibility_reasons,
        evaluation_id: scenario.evaluation_id,
        evaluation_digest: scenario.evaluation_digest,
        item_index: scenario.item_index,
        evidence_refs: scenario.evidence_refs,
        freshness: scenario.freshness,
        readiness_eligible: support.eligible,
        readiness_exclusion_reason: support.reason,
        ignored_for_findings: isUnavailableEvidenceItem('path_validation', scenario),
        attribution: 'unattributed',
        limitations: scenario.limitations,
      });
    }
  }
  for (const row of firewallRows) {
    if (!row.item) continue;
    const support = readinessSupport(row.item.evidence_refs, catalogById);
    conclusions.push({
      id: conclusionId({ kind: 'firewall_change', evaluation_id: row.current.evaluation.id, item_index: row.current.item_index }),
      unit: 'firewall_expectation',
      comparison_kind: 'firewall_change',
      subject: { expectation_id: row.expectation.id, destination_target_id: row.expectation.destination_target_id, change_id: row.expectation.change_id },
      scenario: null,
      result: row.item.status,
      gap_kind: row.item.gap_kind ?? null,
      expectation_met: row.item.expectation_met ?? null,
      reasons: [...list(row.item.reasons)],
      compatibility_reasons: [...list(row.item.compatibility_reasons)],
      evaluation_id: row.current.evaluation.id,
      evaluation_digest: row.current.evaluation.evaluation_digest,
      baseline_id: row.current.evaluation.baseline_id ?? null,
      baseline_digest: row.current.evaluation.baseline_digest ?? null,
      item_index: row.current.item_index,
      evidence_refs: list(row.item.evidence_refs),
      freshness: row.freshness,
      readiness_eligible: support.eligible,
      readiness_exclusion_reason: support.reason,
      ignored_for_findings: isUnavailableEvidenceItem('firewall_change', row.item),
      attribution: 'unattributed',
      limitations: [...list(row.item.limitations)],
    });
  }
  conclusions.sort((a, b) => a.id.localeCompare(b.id));

  const pathStatusValues = [...rowStatuses.values()];
  const notTestedPaths = rows.filter((row) => rowStatuses.get(row.entry_path_id) === 'not_tested').map((row) => row.entry_path_id);
  const skippedPaths = rows.filter((row) => rowStatuses.get(row.entry_path_id) === 'skipped').map((row) => row.entry_path_id);
  const unknownPaths = rows.filter((row) => rowStatuses.get(row.entry_path_id) === 'unknown').map((row) => row.entry_path_id);
  const untestedExpectations = firewallRows.filter((row) => row.status === 'not_tested').map((row) => row.expectation.id);
  const appsWithoutPrimary = applicationStatus.filter((app) => !app.has_primary_route).map((app) => app.anchor_target_id);

  const unknownReasons = {};
  let unresolvedCount = 0;
  for (const conclusion of conclusions) {
    if (!conclusion.ignored_for_findings) continue;
    unresolvedCount += 1;
    const unresolvedStatus = conclusion.comparison_kind === 'path_validation'
      ? PATH_UNRESOLVED_OUTCOMES.includes(conclusion.result)
      : FIREWALL_UNRESOLVED_STATUSES.includes(conclusion.result);
    const reasons = [...conclusion.reasons, ...conclusion.compatibility_reasons];
    const fallback = unresolvedStatus ? conclusion.result : 'evidence_not_finalized';
    for (const reason of reasons.length && unresolvedStatus ? reasons : [fallback]) unknownReasons[reason] = (unknownReasons[reason] ?? 0) + 1;
  }

  const freshnessStates = [...rows.flatMap((row) => row.scenarios.map((scenario) => scenario.freshness)), ...firewallRows.map((row) => row.freshness)];
  const observedTimes = freshnessStates.map((entry) => entry.observed_at).filter(Boolean).sort();

  const kindsPresent = [rows.length ? 'path_validation' : null, firewallRows.length ? 'firewall_change' : null].filter(Boolean);
  const limitations = normalizeLimitations([
    'external_only',
    ...kindsPresent.flatMap((kind) => REQUIRED_LIMITATIONS[kind]),
    ...(list(detections).length ? ['vendor_label_not_proof'] : []),
  ].filter((value) => PROTECTION_VALIDATION_LIMITATIONS.includes(value)));

  const incompleteReasons = [];
  const sourceTruncation = scope.source_truncation ?? {};
  const sourcesComplete = !Object.values(sourceTruncation).some(Boolean);
  if (!sourcesComplete) incompleteReasons.push('source_records_truncated');
  if (notTestedPaths.length) incompleteReasons.push('entry_paths_not_tested');
  if (skippedPaths.length) incompleteReasons.push('entry_paths_skipped');
  if (unknownPaths.length) incompleteReasons.push('entry_paths_inconclusive');
  if (untestedExpectations.length) incompleteReasons.push('firewall_expectations_not_tested');
  if (firewallRows.some((row) => ['inconclusive', 'stale', 'not_comparable'].includes(row.status))) incompleteReasons.push('firewall_expectations_unresolved');
  if (appsWithoutPrimary.length) incompleteReasons.push('applications_without_primary_route');
  if (pathStatusValues.includes('stale') || firewallRows.some((row) => row.status === 'stale')) incompleteReasons.push('stale_evidence');
  if (pathStatusValues.includes('observation_only')) incompleteReasons.push('observation_only_evidence');
  if (pathStatusValues.includes('unclassified_check')) incompleteReasons.push('unclassified_check_evidence');
  if (!rows.length && !firewallRows.length) incompleteReasons.push('no_declared_scope');

  const exclusionCounts = {};
  for (const record of exclusionRecords) exclusionCounts[record.reason] = (exclusionCounts[record.reason] ?? 0) + 1;
  const excludedPairs = pairList.filter((pair) => !pair.eligible);
  for (const pair of excludedPairs) exclusionCounts[pair.reason] = (exclusionCounts[pair.reason] ?? 0) + 1;

  return {
    report_kind: 'protection_validation',
    semantics_version: PROTECTION_REPORT_SEMANTICS_VERSION,
    contract_version: PROTECTION_VALIDATION_CONTRACT_VERSION,
    tenant_id: tenantId,
    generated_at: generated,
    passive: true,
    executes_checks: false,
    sends_notifications: false,
    connectors_required: false,
    scope: {
      anchor_target_ids: anchorScope ? [...anchorScope].sort() : null,
      freshness_window_seconds: freshnessWindowSeconds,
      source_records_complete: sourcesComplete,
      source_truncation: sourceTruncation,
    },
    units: {
      applications: {
        unit: 'unique_anchor_target',
        denominator: applicationStatus.length,
        ...countBy(applicationStatus.map((app) => app.status), ['validated', 'gap', 'incomplete', 'not_tested']),
      },
      hosts: {
        unit: 'unique_entry_target',
        denominator: hostStatus.length,
        ...countBy(hostStatus.map((host) => host.status), ['validated', 'gap', 'incomplete', 'not_tested']),
      },
      entry_paths: {
        unit: 'declared_entry_path',
        denominator: rows.length,
        by_status: countBy(pathStatusValues, ['validated', 'gap', 'unknown', 'not_tested', 'skipped', 'stale', 'observation_only', 'unclassified_check']),
        by_outcome: countBy(rows.map((row) => row.outcome), PATH_OUTCOME_PRECEDENCE),
      },
      target_check_pairs: {
        unit: 'target_check_pair',
        denominator: pairList.length,
        readiness_eligible: pairList.filter((pair) => pair.eligible).length,
        observation_only: pairList.filter((pair) => pair.reason === 'observation_only_check').length,
        not_in_catalog: pairList.filter((pair) => pair.reason === 'check_not_in_catalog').length,
      },
      firewall_expectations: {
        unit: 'firewall_expectation',
        denominator: firewallRows.length,
        by_status: countBy(firewallRows.map((row) => row.status), ['accepted', 'gap', 'inconclusive', 'not_tested', 'stale', 'not_comparable']),
        gaps: countBy(firewallRows.filter((row) => row.item?.gap_kind).map((row) => row.item.gap_kind), ['forbidden_service_newly_reachable', 'required_service_newly_unavailable']),
      },
    },
    detection: {
      statement: REPORT_STATEMENTS.detection,
      counts_as_enforcement: false,
      layers: layerDetection,
    },
    enforcement: {
      statement: REPORT_STATEMENTS.path_validation,
      attribution: 'unattributed',
      layers: layerEnforcement,
    },
    freshness: {
      window_seconds: freshnessWindowSeconds,
      ...countBy(freshnessStates.map((entry) => entry.state), ['fresh', 'stale', 'no_evidence']),
      oldest_observed_at: observedTimes[0] ?? null,
      newest_observed_at: observedTimes.at(-1) ?? null,
    },
    unknowns: {
      statement: REPORT_STATEMENTS.unknowns,
      counts_as_validated: false,
      creates_findings: false,
      ignored_for_findings: conclusions.filter((conclusion) => conclusion.ignored_for_findings).length + untestedExpectations.length,
      total: unresolvedCount + notTestedPaths.length + untestedExpectations.length,
      unresolved_conclusions: unresolvedCount,
      not_tested_entry_paths: notTestedPaths.length,
      not_tested_firewall_expectations: untestedExpectations.length,
      by_reason: Object.fromEntries(Object.entries({
        ...unknownReasons,
        ...(notTestedPaths.length + untestedExpectations.length ? { no_finalized_evidence: (unknownReasons.no_finalized_evidence ?? 0) + notTestedPaths.length + untestedExpectations.length } : {}),
      }).sort(([a], [b]) => a.localeCompare(b))),
    },
    exclusions: {
      by_reason: Object.fromEntries(Object.entries(exclusionCounts).sort(([a], [b]) => a.localeCompare(b))),
      records: exclusionRecords.slice(0, MAX_REPORT_LISTED_IDS),
      records_truncated: exclusionRecords.length > MAX_REPORT_LISTED_IDS,
      other_tenant_or_invalid_rows: crossTenant,
      evaluation_items_for_inactive_paths: orphanItems.size,
    },
    incomplete_scope: {
      complete: incompleteReasons.length === 0,
      reasons: incompleteReasons,
      not_tested_paths: capped(notTestedPaths),
      skipped_paths: capped(skippedPaths),
      inconclusive_paths: capped(unknownPaths),
      untested_firewall_expectations: capped(untestedExpectations),
      applications_without_primary_route: capped(appsWithoutPrimary),
    },
    readiness: {
      statement: REPORT_STATEMENTS.readiness,
      inflates_readiness: false,
      eligible_pairs: pairList.filter((pair) => pair.eligible).length,
      excluded_pairs: excludedPairs.length,
      conclusions_counted: conclusions.filter((conclusion) => conclusion.readiness_eligible).length,
      conclusions_excluded: conclusions.filter((conclusion) => !conclusion.readiness_eligible).length,
    },
    conclusions: conclusions.slice(0, MAX_REPORT_CONCLUSIONS),
    conclusions_total: conclusions.length,
    conclusions_truncated: conclusions.length > MAX_REPORT_CONCLUSIONS,
    statements: [
      ...(rows.length ? [REPORT_STATEMENTS.path_validation] : []),
      ...(firewallRows.length ? [REPORT_STATEMENTS.firewall_change] : []),
      REPORT_STATEMENTS.detection,
      REPORT_STATEMENTS.readiness,
      REPORT_STATEMENTS.unknowns,
    ],
    limitations,
  };
}

function detectionIndexForLayer(detections, tenantId, targetId, layer) {
  return list(detections).filter((signal) => signal
    && (signal.tenant_id == null || signal.tenant_id === tenantId)
    && signal.target_id === targetId
    && signal.layer === layer);
}

export function verifyProtectionReportConclusion(conclusion, evaluations = []) {
  const evaluation = list(evaluations).find((entry) => entry?.id === conclusion?.evaluation_id) ?? null;
  if (!evaluation) return { ok: false, reason: 'evaluation_missing' };
  const verified = verifyProtectionEvaluation(evaluation);
  if (!verified.ok) return { ok: false, reason: verified.reason };
  if (evaluation.evaluation_digest !== conclusion.evaluation_digest) return { ok: false, reason: 'evaluation_digest_mismatch' };
  const item = evaluation.items[conclusion.item_index];
  if (!item) return { ok: false, reason: 'item_missing' };
  const result = evaluation.kind === 'firewall_change' ? item.status : item.outcome;
  if (result !== conclusion.result) return { ok: false, reason: 'result_mismatch' };
  const refKey = (refs) => sha256Digest(list(refs).map((ref) => [ref.test_run_id, ref.check_id, ref.target_id, ref.observed_at, [...list(ref.evidence_ids)]]));
  if (refKey(item.evidence_refs) !== refKey(conclusion.evidence_refs)) return { ok: false, reason: 'evidence_refs_mismatch' };
  return { ok: true, reason: null };
}

const CSV_COLUMNS = Object.freeze(['conclusion_id', 'comparison_kind', 'unit', 'subject_id', 'target_id', 'scenario', 'result', 'readiness_eligible', 'ignored_for_findings', 'freshness', 'evaluation_id', 'item_index', 'test_run_ids', 'source_records_complete']);

function csvCell(value) {
  let text = value == null ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\n\r]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

export function protectionValidationReportCsv(report) {
  const lines = [CSV_COLUMNS.join(',')];
  for (const conclusion of list(report?.conclusions)) {
    const subject = conclusion.subject ?? {};
    lines.push([
      conclusion.id,
      conclusion.comparison_kind,
      conclusion.unit,
      subject.entry_path_id ?? subject.expectation_id ?? '',
      subject.entry_target_id ?? subject.destination_target_id ?? '',
      conclusion.scenario ?? '',
      conclusion.result,
      conclusion.readiness_eligible ? 'true' : 'false',
      conclusion.ignored_for_findings ? 'true' : 'false',
      conclusion.freshness?.state ?? '',
      conclusion.evaluation_id,
      conclusion.item_index,
      [...new Set(list(conclusion.evidence_refs).map((ref) => ref.test_run_id))].sort().join(' '),
      report.scope?.source_records_complete === false ? 'false' : 'true',
    ].map(csvCell).join(','));
  }
  return `${lines.join('\n')}\n`;
}
