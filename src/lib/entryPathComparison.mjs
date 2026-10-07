// PV-04 pure planner/evaluator: destinations come only from declared targets and the approved scope hash.
import { checkRequiresAdditionalInput, isCustomerRunnable } from '../contracts/checks.mjs';
import { effectiveTargetKind, targetKindCompatibilityError } from '../contracts/checkTargetCompatibility.mjs';
import {
  PROTECTION_VALIDATION_CONTRACT_VERSION,
  REQUIRED_LIMITATIONS,
  SOURCE_PERSPECTIVE_PATTERN,
  assessComparisonCompatibility,
  checkExpectationAgainstRelation,
  classifyPathValidationItem,
  entryPathAuthorizesExecution,
  entryPathComparisonPlanDigest,
  isFinalizedRunStatus,
  normalizeComparisonEvaluation,
  normalizeComparisonEvidenceSet,
  normalizeEvidenceReference,
  normalizePathValidationExpectation,
  sha256Digest,
} from '../contracts/protectionValidation.mjs';
import { approvedScenarioVersion, deriveCheckDefinitionVersion } from './checkDefinitionVersion.mjs';
import {
  baselineHealth,
  classifyTransportFailure,
  externalObservationLabel,
  originObservationOf,
  unsignedStatusOutcome,
} from './externalObservationOutcomes.mjs';
import { computeScopeHashFromTargets } from './scopeHash.mjs';

export const ENTRY_PATH_COMPARISON_STATUSES = Object.freeze(['running', 'completed', 'cancelled']);
export const ENTRY_PATH_ITEM_EXECUTION_STATES = Object.freeze(['pending', 'deferred', 'started', 'finalized', 'skipped']);
export const ORIGIN_PROBE_KIND = 'host_sni_bypass';
export const DEFAULT_SOURCE_PERSPECTIVE = 'astranull-signed-public-worker';

/** Probe kinds that never send a body or a state-changing method to a declared login or API URL. */
export const ENTRY_PATH_SAFE_PROBE_KINDS = Object.freeze([
  'waf_class_marker_probe',
  'waf_evasion_marker_probe',
  'waf_enforcement_probe',
  'http_head',
]);
export const LOGIN_SAFE_PROBE_KINDS = ENTRY_PATH_SAFE_PROBE_KINDS;

const STATE_CHANGE_RISK_REASONS = Object.freeze({
  declared_login_url: 'login_path_state_change_risk',
  declared_api_url: 'api_path_state_change_risk',
});

export const ENTRY_PATH_SCENARIO_BY_RELATION = Object.freeze({
  declared_login_url: 'declared_login_path',
  declared_api_url: 'declared_api_path',
});

const MARKER_PROBE_KINDS = new Set([
  'waf_class_marker_probe',
  'waf_evasion_marker_probe',
  'waf_inspection_limit_probe',
  'waf_enforcement_probe',
  'outside_in_waf_scan',
]);

const SCENARIO_ONLY_REASONS = new Set(['check_mismatch', 'check_version_mismatch', 'scenario_version_mismatch']);
const REACHABILITY_ONLY_BEHAVIORS = new Set(['intentionally_public', 'must_not_be_reachable']);
const REACHABILITY_ROUTE_KINDS = new Set(['origin', 'fallback_backend_route']);
const UNRESOLVED_OUTCOMES = new Set(['inconclusive', 'not_tested', 'skipped']);
const EVIDENCE_GAP_OBSERVATIONS = new Set(['misdirected_request', 'probe_path_error', 'not_applicable']);
const LEG_REASON_BY_RESPONSE_REASON = Object.freeze({
  authentication_challenge: 'authentication_gate_precedes_inspection',
  unattributed_denial: 'unattributed_denial',
  generic_error_response: 'error_not_attributable',
});
const MARKER_LEG_REASONS = Object.freeze([
  'authentication_gate_precedes_inspection',
  'unattributed_denial',
  'error_not_attributable',
  'misdirected_request',
  'probe_path_error',
  'rst_or_drop_unattributed',
]);
const PUBLIC_PATH_INCONCLUSIVE_LEG_REASONS = new Set(['unattributed_denial', 'error_not_attributable']);

function stripBrackets(host) {
  return String(host ?? '').replace(/^\[|\]$/g, '');
}

function addressFamily(host) {
  const value = stripBrackets(host);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return 'ipv4';
  if (value.includes(':') && /^[0-9a-f:.]+$/i.test(value)) return 'ipv6';
  return value ? 'hostname' : null;
}

/** Display-only description of an exact declared target. It never selects a destination. */
export function describeEntryTarget(target) {
  if (!target) return null;
  const kind = effectiveTargetKind(target);
  const raw = String(target.value ?? '').trim();
  if (kind === 'url') {
    try {
      const url = new URL(raw);
      return {
        kind,
        address_family: addressFamily(url.hostname),
        host: stripBrackets(url.hostname).toLowerCase(),
        port: url.port ? Number(url.port) : null,
        path: url.pathname || '/',
        scheme: url.protocol.replace(/:$/, ''),
      };
    } catch {
      return { kind, address_family: null, host: null, port: null, path: null, scheme: null };
    }
  }
  return {
    kind,
    address_family: addressFamily(raw),
    host: stripBrackets(raw).toLowerCase() || null,
    port: Number.isInteger(target.port) ? target.port : null,
    path: null,
    scheme: null,
  };
}

/** Exact-target scope hash: the same id:kind:value digest used for run scope elsewhere. */
export function entryTargetScopeHash(target) {
  if (!target?.id) return null;
  return computeScopeHashFromTargets(target.target_group_id ?? '', [{ id: target.id, kind: target.kind, value: target.value }]);
}

export function checkMatchesScenario(check, scenario) {
  if (!check || typeof scenario !== 'string') return false;
  return check.check_id === scenario || approvedScenarioVersion(check) === scenario;
}

function rankCandidates(candidates, scenario, preferredEntryScenario) {
  if (preferredEntryScenario) {
    const scoped = candidates.filter((check) => check.probe_profile?.entry_path_scenario === preferredEntryScenario);
    if (scoped.length) return [...scoped.filter((check) => check.check_id === scenario), ...scoped.filter((check) => check.check_id !== scenario)];
  }
  const exact = candidates.filter((check) => check.check_id === scenario);
  if (exact.length) return exact;
  return candidates;
}

/** Generic marker scenarios whose declared login/API variant measures the same marker under the same scenario version. */
const GENERIC_MARKER_SCENARIO_KINDS = new Set(['waf_enforcement_probe', 'outside_in_waf_scan']);

function entryPathVariantMatches(entryCheck, scenario, scenarioChecks) {
  const version = approvedScenarioVersion(entryCheck);
  if (!version) return false;
  if (version === scenario) return true;
  return scenarioChecks.some((check) => approvedScenarioVersion(check) === version && (
    GENERIC_MARKER_SCENARIO_KINDS.has(check.probe_profile?.kind)
    || (check.probe_profile?.kind === entryCheck.probe_profile?.kind
      && check.probe_profile?.marker_class != null
      && check.probe_profile.marker_class === entryCheck.probe_profile?.marker_class)
  ));
}

/** Origin relations use approved host/SNI checks; others need a scenario check for the exact target kind. */
export function selectEntryPathCheck({ relation, entryTarget, scenario, catalog = [] } = {}) {
  if (!relation || !entryTarget) return { check: null, reason: 'unknown_target' };
  const isOrigin = relation.relation_kind === 'origin';
  const preferredEntryScenario = ENTRY_PATH_SCENARIO_BY_RELATION[relation.relation_kind] ?? null;
  let candidates = catalog.filter((check) => (isOrigin
    ? check?.probe_profile?.kind === ORIGIN_PROBE_KIND
    : check?.probe_profile?.kind !== ORIGIN_PROBE_KIND
      && checkMatchesScenario(check, scenario)
      && !checkRequiresAdditionalInput(check)));
  if (preferredEntryScenario) {
    const variants = catalog.filter((check) => check?.probe_profile?.entry_path_scenario === preferredEntryScenario
      && !candidates.includes(check)
      && !checkRequiresAdditionalInput(check)
      && entryPathVariantMatches(check, scenario, candidates));
    candidates = [...variants, ...candidates];
  }
  if (!candidates.length) return { check: null, reason: 'no_eligible_check' };
  candidates = candidates.filter((check) => isCustomerRunnable(check));
  if (!candidates.length) return { check: null, reason: 'check_not_customer_runnable' };
  const stateChangeReason = STATE_CHANGE_RISK_REASONS[relation.relation_kind];
  if (stateChangeReason) {
    candidates = candidates.filter((check) => ENTRY_PATH_SAFE_PROBE_KINDS.includes(check.probe_profile?.kind));
    if (!candidates.length) return { check: null, reason: stateChangeReason };
  }
  const compatible = candidates.filter((check) => !targetKindCompatibilityError(check, entryTarget));
  if (!compatible.length) return { check: null, reason: 'target_kind_not_supported' };
  const ranked = isOrigin
    ? [...compatible.filter((check) => check.check_id === scenario), ...compatible.filter((check) => check.check_id !== scenario)]
    : rankCandidates(compatible, scenario, preferredEntryScenario);
  return { check: ranked[0], reason: null };
}

function relationById(relations, tenantId) {
  const map = new Map();
  for (const relation of relations ?? []) {
    if (relation?.id && (tenantId == null || relation.tenant_id === tenantId)) map.set(relation.id, relation);
  }
  return map;
}

function byId(rows, tenantId) {
  const map = new Map();
  for (const row of rows ?? []) {
    if (row?.id && (tenantId == null || row.tenant_id === tenantId)) map.set(row.id, row);
  }
  return map;
}

function ineligibleItem(base, reason) {
  return { ...base, eligible: false, ineligible_reason: reason };
}

/** Passive plan; `authorize(relation, entryTarget)` adds execution-time gates such as ownership. */
export function planEntryPathComparison({
  tenantId,
  request,
  anchorTarget,
  relations = [],
  targets = [],
  originBindings = [],
  catalog = [],
  authorize = null,
  expectationVersion = 1,
} = {}) {
  const expectation = normalizePathValidationExpectation(request.expectation, {
    tenantId,
    anchorTargetId: request.anchor_target_id,
    expectationVersion,
  });
  const relationMap = relationById(relations, tenantId);
  const targetMap = byId(targets, tenantId);
  const bindingMap = byId(originBindings, tenantId);
  const anchor = anchorTarget && anchorTarget.tenant_id === tenantId ? anchorTarget : null;
  const items = [];
  const conflicts = [];

  for (const entryPathId of request.entry_path_ids) {
    const relation = relationMap.get(entryPathId) ?? null;
    const isPrimary = entryPathId === request.primary_entry_path_id;
    const base = {
      entry_path_id: entryPathId,
      is_primary: isPrimary,
      relation_kind: relation?.relation_kind ?? null,
      expected_behavior: relation?.expected_behavior ?? null,
      required_layers: [...(relation?.required_layers ?? [])],
      target_id: relation?.entry_target_id ?? null,
      target_group_id: null,
      target: null,
      target_scope_hash: null,
      declaration_digest: relation?.declaration_digest ?? null,
      check_id: null,
      check_version: null,
      scenario_version: null,
      origin_binding_id: relation?.origin_binding_id ?? null,
    };
    if (!relation) {
      items.push(ineligibleItem(base, 'unknown_entry_path'));
      continue;
    }
    if (relation.anchor_target_id !== request.anchor_target_id) {
      items.push(ineligibleItem(base, 'entry_path_not_in_anchor'));
      continue;
    }
    const entryTarget = targetMap.get(relation.entry_target_id) ?? null;
    const originBinding = relation.origin_binding_id ? bindingMap.get(relation.origin_binding_id) ?? null : null;
    const authorized = entryPathAuthorizesExecution(relation, { anchorTarget: anchor, entryTarget, originBinding, tenantId });
    if (!authorized.ok) {
      items.push(ineligibleItem(base, authorized.error));
      continue;
    }
    const scoped = {
      ...base,
      target_group_id: entryTarget.target_group_id ?? null,
      target: describeEntryTarget(entryTarget),
      target_scope_hash: entryTargetScopeHash(entryTarget),
    };
    const relationConflicts = checkExpectationAgainstRelation(expectation, relation);
    if (!relationConflicts.ok) conflicts.push({ entry_path_id: entryPathId, conflicts: relationConflicts.conflicts });
    const selected = selectEntryPathCheck({ relation, entryTarget, scenario: expectation.scenario, catalog });
    if (!selected.check) {
      items.push(ineligibleItem(scoped, selected.reason));
      continue;
    }
    const version = deriveCheckDefinitionVersion(selected.check);
    const withCheck = {
      ...scoped,
      check_id: selected.check.check_id,
      check_version: version.check_version ?? null,
      scenario_version: approvedScenarioVersion(selected.check),
    };
    const gate = typeof authorize === 'function' ? authorize(relation, entryTarget) : { ok: true };
    if (!gate?.ok) {
      items.push(ineligibleItem(withCheck, gate?.error ?? 'not_authorized'));
      continue;
    }
    items.push({ ...withCheck, eligible: true, ineligible_reason: null });
  }

  const plan = {
    contract_version: PROTECTION_VALIDATION_CONTRACT_VERSION,
    mode: request.mode ?? 'plan',
    tenant_id: tenantId,
    anchor_target_id: request.anchor_target_id,
    primary_entry_path_id: request.primary_entry_path_id,
    expectation,
    expectation_digest: expectation.digest,
    items,
    expectation_conflicts: conflicts,
    eligible_count: items.filter((item) => item.eligible).length,
    primary_eligible: items.some((item) => item.is_primary && item.eligible),
    limitations: [...REQUIRED_LIMITATIONS.path_validation],
  };
  plan.plan_digest = entryPathComparisonPlanDigest(plan);
  return plan;
}

export function reviewedPlanMatches(plan, reviewedPlanDigest) {
  return typeof reviewedPlanDigest === 'string' && plan?.plan_digest === reviewedPlanDigest;
}

const SCOPE_ITEM_FIELDS = Object.freeze([
  'entry_path_id', 'is_primary', 'relation_kind', 'expected_behavior', 'required_layers', 'target_id',
  'target_group_id', 'target_scope_hash', 'declaration_digest', 'check_id', 'check_version', 'scenario_version',
  'origin_binding_id', 'eligible', 'ineligible_reason',
]);

function scopeItem(item) {
  return Object.fromEntries(SCOPE_ITEM_FIELDS.map((field) => [field, item[field] ?? (field === 'required_layers' ? [] : null)]));
}

export function approvedScopeDigest(scope) {
  return sha256Digest({
    contract_version: scope.contract_version,
    comparison_id: scope.comparison_id,
    tenant_id: scope.tenant_id,
    anchor_target_id: scope.anchor_target_id,
    primary_entry_path_id: scope.primary_entry_path_id,
    plan_digest: scope.plan_digest,
    expectation_digest: scope.expectation_digest,
    scenario: scope.scenario,
    approved_at: scope.approved_at,
    approved_by: scope.approved_by,
    items: (scope.items ?? []).map(scopeItem),
  });
}

/** Freeze the reviewed plan as the immutable approved execution scope. */
export function buildApprovedScope(plan, { comparisonId, approvedAt, approvedBy } = {}) {
  const scope = {
    contract_version: PROTECTION_VALIDATION_CONTRACT_VERSION,
    comparison_id: comparisonId,
    tenant_id: plan.tenant_id,
    anchor_target_id: plan.anchor_target_id,
    primary_entry_path_id: plan.primary_entry_path_id,
    plan_digest: plan.plan_digest,
    expectation_digest: plan.expectation_digest,
    scenario: plan.expectation.scenario,
    approved_at: approvedAt,
    approved_by: approvedBy ?? null,
    items: plan.items.map(scopeItem),
  };
  scope.scope_digest = approvedScopeDigest(scope);
  return scope;
}

export function verifyApprovedScope(scope) {
  if (!scope || typeof scope.scope_digest !== 'string') return false;
  try {
    return scope.scope_digest === approvedScopeDigest(scope);
  } catch {
    return false;
  }
}

/** Execution-time recheck: same active declaration, exact target scope hash, and active binding. */
export function revalidateScopeItem(item, { relation, anchorTarget, entryTarget, originBinding, tenantId } = {}) {
  if (!item?.eligible) return { ok: false, error: item?.ineligible_reason ?? 'not_eligible' };
  const authorized = entryPathAuthorizesExecution(relation, { anchorTarget, entryTarget, originBinding, tenantId });
  if (!authorized.ok) return authorized;
  if (relation.declaration_digest !== item.declaration_digest) return { ok: false, error: 'declaration_changed' };
  if (relation.entry_target_id !== item.target_id) return { ok: false, error: 'attempt_target_mismatch' };
  if ((relation.origin_binding_id ?? null) !== (item.origin_binding_id ?? null)) return { ok: false, error: 'attempt_binding_mismatch' };
  if (entryTargetScopeHash(entryTarget) !== item.target_scope_hash) return { ok: false, error: 'attempt_scope_hash_mismatch' };
  return { ok: true };
}

/** The exact run start body for an approved item; nothing else can reach the signed job. */
export function runStartBodyForScopeItem(item) {
  return {
    check_id: item.check_id,
    target_group_id: item.target_group_id,
    target_id: item.target_id,
    ...(item.origin_binding_id ? { origin_binding_id: item.origin_binding_id } : {}),
  };
}

/** Map one executed attempt back to its approved item; any drift makes the attempt unusable. */
export function attemptScopeMatches(item, attempt) {
  const reasons = [];
  if (!attempt) return { ok: false, reasons: ['attempt_missing'] };
  if (attempt.target_id !== item.target_id) reasons.push('attempt_target_mismatch');
  if (attempt.check_id !== item.check_id) reasons.push('attempt_check_mismatch');
  if ((attempt.origin_binding_id ?? null) !== (item.origin_binding_id ?? null)) reasons.push('attempt_binding_mismatch');
  if (item.check_version && attempt.check_version !== item.check_version) reasons.push('attempt_check_version_mismatch');
  if (!attempt.signed_target) {
    reasons.push('attempt_signed_scope_missing');
  } else {
    const signedHash = computeScopeHashFromTargets(item.target_group_id ?? '', [{
      id: attempt.signed_target.id,
      kind: attempt.signed_target.kind,
      value: attempt.signed_target.value,
    }]);
    if (signedHash !== item.target_scope_hash) reasons.push('attempt_scope_hash_mismatch');
  }
  return { ok: reasons.length === 0, reasons };
}

function sourcePerspectiveOf(attempt) {
  if (attempt && Object.prototype.hasOwnProperty.call(attempt, 'source_perspective')) return attempt.source_perspective ?? null;
  const declared = attempt?.probe_metadata?.source_perspective;
  if (typeof declared === 'string' && SOURCE_PERSPECTIVE_PATTERN.test(declared)) return declared;
  return attempt?.worker_id ? DEFAULT_SOURCE_PERSPECTIVE : null;
}

/** Reference-only evidence link for an attempt; headers, bodies and raw metadata are dropped. */
export function evidenceReferenceForAttempt(attempt) {
  if (!attempt?.test_run_id) return null;
  try {
    return normalizeEvidenceReference({
      test_run_id: attempt.test_run_id,
      check_id: attempt.check_id,
      check_version: attempt.check_version ?? null,
      scenario_version: attempt.scenario_version ?? null,
      verdict_id: attempt.verdict_id ?? null,
      evidence_ids: (attempt.evidence_ids ?? []).slice(0, 32),
      target_id: attempt.target_id,
      observed_at: attempt.observed_at,
      run_status: attempt.run_status,
      source_perspective: sourcePerspectiveOf(attempt),
      worker_id: attempt.worker_id ?? null,
    });
  } catch {
    return null;
  }
}

function markerEnforcement(entries) {
  const graded = (entries ?? []).filter((row) => row && !row.inconclusive && !row.block_suspected && !row.error_class && !row.transport_error);
  const blocked = graded.filter((row) => row.blocked === true).length;
  const allowed = graded.filter((row) => row.allowed === true || (row.blocked === false && row.allowed == null)).length;
  if (blocked + allowed === 0) return 'unknown';
  if (allowed === 0) return 'enforced';
  if (blocked === 0) return 'not_enforced';
  return 'partial';
}

/** Why an ungraded marker leg is inconclusive, from the excluded rows (G4). */
function markerLegReason(entries) {
  const reasons = new Set((entries ?? []).map((row) => row?.reason).filter(Boolean));
  return MARKER_LEG_REASONS.find((reason) => reasons.has(reason)) ?? null;
}

function permittedBaselineStatus(kind, metadata) {
  if (metadata.permitted_baseline && Number.isInteger(metadata.permitted_baseline.status_code)) {
    return metadata.permitted_baseline.status_code;
  }
  if (kind === 'waf_class_marker_probe') {
    const phase = (metadata.phases ?? []).find((row) => row?.phase === 'baseline');
    return Number.isInteger(phase?.status_code) ? phase.status_code : null;
  }
  if (kind === 'outside_in_waf_scan') {
    return Number.isInteger(metadata.baseline_status_code) && metadata.baseline_status_code > 0 ? metadata.baseline_status_code : null;
  }
  if (kind === 'waf_evasion_marker_probe' && Number.isInteger(metadata.permitted_baseline_status)) {
    return metadata.permitted_baseline_status;
  }
  return null;
}

const RECORDED_ENFORCEMENT = new Set(['enforced', 'partial', 'not_enforced', 'unknown']);

/** Control-specific signature on the permitted (no-marker) baseline of a marker probe, or null. */
function permittedBaselineSignature(metadata) {
  const signature = metadata?.permitted_baseline?.denial_signature;
  if (!signature || typeof signature !== 'object' || Array.isArray(signature)) return null;
  return typeof signature.id === 'string' && signature.id ? signature : null;
}

function httpStatusOf(value) {
  return Number.isInteger(value) && value >= 100 && value <= 599 ? value : null;
}

function stackedEdges(metadata) {
  const signature = metadata?.edge_signature;
  if (!signature || typeof signature !== 'object') return false;
  if (signature.stacked_vendor_signals === true) return true;
  return Array.isArray(signature.layers) && signature.layers.length > 1;
}

/** Silence never implies enforcement; a status code alone is never a denial; only a nonce-bound canary confirms identity. */
export function deriveAttemptObservation(attempt) {
  const reasons = [];
  if (!attempt) return { observation: 'not_tested', enforcement: 'unknown', baseline_health: 'not_available', reasons, stacked_edges: false };
  const metadata = attempt.probe_metadata && typeof attempt.probe_metadata === 'object' ? attempt.probe_metadata : {};
  const kind = metadata.profile_kind ?? metadata.probe_kind ?? attempt.probe_kind ?? null;
  const external = attempt.external_result ?? metadata.external_result ?? null;
  const stacked = stackedEdges(metadata);
  const originPath = kind === ORIGIN_PROBE_KIND;
  const finish = (observation, enforcement, health, extra = [], fields = {}) => ({
    observation,
    enforcement,
    baseline_health: health,
    reasons: [...reasons, ...extra],
    stacked_edges: stacked,
    origin_path: originPath,
    leg_reason: null,
    denial_signature: null,
    ...fields,
  });

  if (kind === ORIGIN_PROBE_KIND) {
    const observed = originObservationOf(metadata);
    if (!observed) return finish(null, 'unknown', 'not_available', ['observation_semantics_unsupported']);
    let outcome = observed.outcome;
    if (EVIDENCE_GAP_OBSERVATIONS.has(outcome)) return finish(null, 'unknown', observed.baseline ?? 'not_available', [outcome]);
    if (outcome === 'application_identity_confirmed' && observed.application_identity?.method !== 'nonce_canary') {
      outcome = 'response_observed';
      reasons.push('marker_echo_not_nonce_bound');
    }
    const fields = {
      leg_reason: LEG_REASON_BY_RESPONSE_REASON[observed.response_reason] ?? null,
      denial_signature: observed.denial_signature ?? null,
    };
    const unconfirmedDenial = outcome === 'explicit_denial_observed'
      && !(observed.origin_lockdown_confirmed === true && observed.baseline === 'healthy');
    const derived = finish(outcome, 'unknown', observed.baseline ?? 'not_available', unconfirmedDenial ? ['origin_lockdown_not_confirmed'] : [], fields);
    return unconfirmedDenial ? { ...derived, unconfirmed_origin_denial: true } : derived;
  }

  if (external === 'timeout') return finish('no_response', 'unknown', 'not_available', ['no_response_enforcement_unverified']);
  if (external === 'error' || external === 'stopped') {
    const outcome = classifyTransportFailure({ code: metadata.error_class ?? '' });
    return finish(outcome, 'unknown', 'not_available', [`${outcome}_enforcement_unverified`]);
  }

  const baselineStatus = permittedBaselineStatus(kind, metadata);
  const health = baselineStatus == null ? 'not_available' : baselineHealth({ status_code: baselineStatus });

  if (!MARKER_PROBE_KINDS.has(kind)) {
    const ownStatus = httpStatusOf(metadata.status_code);
    if (ownStatus == null && (metadata.error_class || metadata.connection_closed_by_server === true)) {
      const outcome = classifyTransportFailure({ code: metadata.error_class ?? 'connection_closed_by_server' });
      return finish(outcome, 'unknown', health, [`${outcome}_enforcement_unverified`]);
    }
    const status = ownStatus ?? baselineStatus;
    if (status == null) return finish(null, 'unknown', health, ['response_evidence_not_recorded']);
    const signature = metadata.denial_signature && typeof metadata.denial_signature === 'object' ? metadata.denial_signature : null;
    if (signature) return finish('explicit_denial_observed', 'unknown', health, ['enforcement_not_measured'], { denial_signature: signature });
    const unsigned = unsignedStatusOutcome(status);
    if (unsigned.outcome !== 'response_observed') return finish(null, 'unknown', health, [unsigned.outcome]);
    return finish('response_observed', 'unknown', health, ['enforcement_not_measured'], {
      leg_reason: LEG_REASON_BY_RESPONSE_REASON[unsigned.response_reason] ?? null,
    });
  }

  const baselineSignature = permittedBaselineSignature(metadata);
  if (baselineSignature) {
    return finish('explicit_denial_observed', 'unknown', 'unhealthy', ['permitted_baseline_signed_denial'], { denial_signature: baselineSignature });
  }
  let legReason = null;
  if (baselineStatus != null) {
    const unsigned = unsignedStatusOutcome(baselineStatus);
    if (unsigned.outcome !== 'response_observed') return finish(null, 'unknown', health, [unsigned.outcome]);
    legReason = LEG_REASON_BY_RESPONSE_REASON[unsigned.response_reason] ?? null;
  }
  let observation = 'response_observed';

  let enforcement = 'unknown';
  if (kind === 'waf_evasion_marker_probe') {
    if (metadata.baseline_blocked !== true) {
      reasons.push('evasion_blocked_baseline_missing');
    } else {
      if (Array.isArray(metadata.variant_results)) {
        const transformed = metadata.variant_results.filter((row) => row?.label !== 'baseline' && row?.label !== 'permitted_baseline' && !row?.transport_error && !row?.inconclusive);
        enforcement = transformed.length === 0 ? 'unknown' : transformed.every((row) => row.blocked) ? 'enforced' : 'partial';
      } else {
        enforcement = external === 'blocked' ? 'enforced' : external === 'connected' ? 'partial' : 'unknown';
      }
    }
  } else if (kind === 'waf_inspection_limit_probe') {
    if (metadata.baseline_blocked !== true) reasons.push('inspection_limit_blocked_baseline_missing');
    else if (metadata.inspection_limit_bypass_suspected === true) enforcement = 'partial';
    else if (metadata.comparison_complete === true) enforcement = 'enforced';
  } else if (kind === 'waf_enforcement_probe') {
    enforcement = external === 'blocked' ? 'enforced' : external === 'connected' ? 'not_enforced' : 'unknown';
    if (enforcement === 'unknown' && typeof metadata.inconclusive_reason === 'string') legReason ??= metadata.inconclusive_reason;
  } else if (kind === 'outside_in_waf_scan') {
    enforcement = markerEnforcement(metadata.marker_probes);
    if (enforcement === 'unknown') legReason ??= markerLegReason(metadata.marker_probes);
  } else if (Array.isArray(metadata.marker_results)) {
    enforcement = markerEnforcement(metadata.marker_results);
    if (enforcement === 'unknown') legReason ??= markerLegReason(metadata.marker_results);
  } else {
    enforcement = RECORDED_ENFORCEMENT.has(metadata.enforcement) ? metadata.enforcement : 'unknown';
  }
  if (health === 'unhealthy' && enforcement !== 'unknown') {
    reasons.push('permitted_baseline_not_healthy');
    enforcement = 'unknown';
  }
  const identity = metadata.application_identity;
  if (observation === 'response_observed' && health === 'healthy' && identity?.confirmed === true && identity.method === 'nonce_canary') {
    observation = 'application_identity_confirmed';
  }
  return finish(observation, enforcement, health, [], { leg_reason: legReason });
}

/** A leg that answered without usable evidence keeps its gap outcome (for example a CDN edge) instead of reading as not tested. */
function evidenceGapObservation(derived) {
  if (!derived || derived.observation != null) return null;
  return (derived.reasons ?? []).find((reason) => EVIDENCE_GAP_OBSERVATIONS.has(reason)) ?? null;
}

function evidenceSetFor({ tenantId, scope, expectation, item, attempt, reference }) {
  return normalizeComparisonEvidenceSet({
    kind: 'path_validation',
    tenant_id: tenantId,
    anchor_target_id: scope.anchor_target_id,
    entry_path_id: item.entry_path_id,
    expectation_id: expectation.id,
    expectation_version: expectation.expectation_version,
    expectation_digest: expectation.digest,
    declaration_digest: item.declaration_digest,
    target_id: item.target_id,
    references: reference ? [reference] : [],
    captured_at: attempt?.observed_at ?? scope.approved_at,
  });
}

function relationSnapshot(item) {
  return {
    status: 'active',
    relation_kind: item.relation_kind,
    expected_behavior: item.expected_behavior,
    required_layers: item.required_layers ?? [],
  };
}

function itemResult(item, scenario, classified, extra = {}) {
  return {
    entry_path_id: item.entry_path_id,
    scenario,
    outcome: classified.outcome,
    attribution: 'unattributed',
    reasons: [...new Set([...(classified.reasons ?? []), ...(extra.reasons ?? [])])].slice(0, 16),
    compatibility_reasons: classified.compatibility_reasons ?? [],
    evidence_refs: extra.evidence_refs ?? [],
    limitations: classified.limitations ?? [...REQUIRED_LIMITATIONS.path_validation],
  };
}

/** Evaluate approved-scope items from attempts and execution state keyed by entry_path_id. */
export function evaluateEntryPathComparison({
  scope,
  expectation,
  attempts = {},
  execution = {},
  currentDeclarationDigests = null,
  now = null,
  evaluatedAt,
} = {}) {
  const scopeValid = verifyApprovedScope(scope);
  const tenantId = scope?.tenant_id;
  const scenario = expectation.scenario;
  const items = scope?.items ?? [];
  const primaryItem = items.find((item) => item.is_primary) ?? null;
  const details = [];
  const prepared = new Map();

  for (const item of items) {
    const attempt = attempts[item.entry_path_id] ?? null;
    const state = execution[item.entry_path_id] ?? {};
    const reference = evidenceReferenceForAttempt(attempt);
    const matched = attempt ? attemptScopeMatches(item, attempt) : { ok: false, reasons: [] };
    const derived = attempt && matched.ok ? deriveAttemptObservation(attempt) : null;
    prepared.set(item.entry_path_id, { item, attempt, state, reference, matched, derived });
  }

  const primary = primaryItem ? prepared.get(primaryItem.entry_path_id) : null;
  const primaryUsable = Boolean(primary?.derived && primary.attempt && isFinalizedRunStatus(primary.attempt.run_status));
  const primaryHealth = primaryUsable ? primary.derived.baseline_health : 'not_available';
  const primaryEnforcement = primaryUsable ? primary.derived.enforcement : 'unknown';
  const primarySet = primaryItem
    ? evidenceSetFor({ tenantId, scope, expectation, item: primaryItem, attempt: primaryUsable ? primary.attempt : null, reference: primaryUsable ? primary.reference : null })
    : null;
  const compatOptions = { currentDeclarationDigests, ...(now ? { now } : {}) };

  const results = items.map((item) => {
    const { attempt, state, reference, matched, derived } = prepared.get(item.entry_path_id);
    const refs = reference ? [reference] : [];
    const observed = derived?.observation ?? evidenceGapObservation(derived) ?? 'not_tested';
    const detail = {
      entry_path_id: item.entry_path_id,
      test_run_id: attempt?.test_run_id ?? null,
      target_id: item.target_id,
      check_id: item.check_id,
      observation: observed,
      observation_label: externalObservationLabel(observed, { originPath: derived?.origin_path === true }),
      enforcement: derived?.enforcement ?? 'unknown',
      baseline_health: derived?.baseline_health ?? 'not_available',
      scope_reasons: matched.reasons ?? [],
    };
    details.push(detail);
    if (!scopeValid) {
      return itemResult(item, scenario, { outcome: 'inconclusive', reasons: ['approved_scope_invalid'] });
    }
    if (!item.eligible || state.state === 'skipped') {
      return itemResult(item, scenario, classifyPathValidationItem({ skipped: true }), { reasons: [item.ineligible_reason ?? state.skip_reason ?? 'skipped'] });
    }
    if (!attempt || !isFinalizedRunStatus(attempt.run_status)) {
      return itemResult(item, scenario, classifyPathValidationItem({ relation: relationSnapshot(item), observation: 'not_tested' }), { reasons: attempt ? ['evidence_not_finalized'] : [] });
    }
    if (!matched.ok) {
      return itemResult(item, scenario, { outcome: 'inconclusive', reasons: matched.reasons }, { evidence_refs: refs });
    }
    const signedUnreachableDenial = derived.unconfirmed_origin_denial
      && item.expected_behavior === 'must_not_be_reachable'
      && Boolean(derived.denial_signature);
    if (derived.observation == null || (derived.unconfirmed_origin_denial && !signedUnreachableDenial)) {
      return itemResult(item, scenario, { outcome: 'inconclusive', reasons: derived.reasons }, { evidence_refs: refs });
    }
    if (derived.leg_reason && derived.observation !== 'explicit_denial_observed') {
      const publicPathGap = item.expected_behavior === 'intentionally_public' && PUBLIC_PATH_INCONCLUSIVE_LEG_REASONS.has(derived.leg_reason);
      const comparisonGap = !item.is_primary && !REACHABILITY_ONLY_BEHAVIORS.has(item.expected_behavior) && derived.enforcement === 'unknown';
      if (publicPathGap || comparisonGap) {
        return itemResult(item, scenario, { outcome: 'inconclusive', reasons: [derived.leg_reason] }, { evidence_refs: refs, reasons: derived.reasons });
      }
    }
    if (!reference) {
      return itemResult(item, scenario, { outcome: 'inconclusive', reasons: ['evidence_reference_unavailable'] });
    }
    const candidateSet = evidenceSetFor({ tenantId, scope, expectation, item, attempt, reference });
    const isPrimary = item.is_primary;
    const reachabilityOnly = REACHABILITY_ONLY_BEHAVIORS.has(item.expected_behavior);
    let compatibility;
    let strippedScenarioReasons = [];
    if (isPrimary || reachabilityOnly) {
      compatibility = assessComparisonCompatibility(candidateSet, candidateSet, compatOptions);
    } else {
      const sameCheck = primaryItem?.check_id === item.check_id;
      compatibility = assessComparisonCompatibility(primarySet, candidateSet, {
        ...compatOptions,
        ...(sameCheck ? {} : { matchBy: 'scenario_version' }),
      });
      if (REACHABILITY_ROUTE_KINDS.has(item.relation_kind) && !compatibility.comparable) {
        strippedScenarioReasons = compatibility.reasons.filter((reason) => SCENARIO_ONLY_REASONS.has(reason));
        const remaining = compatibility.reasons.filter((reason) => !SCENARIO_ONLY_REASONS.has(reason));
        compatibility = { ...compatibility, comparable: remaining.length === 0, reasons: remaining };
      }
    }
    const classified = classifyPathValidationItem({
      relation: relationSnapshot(item),
      compatibility,
      primaryBaselineHealth: isPrimary ? derived.baseline_health : primaryHealth,
      primaryEnforcement: isPrimary ? derived.enforcement : primaryEnforcement,
      observation: derived.observation,
      enforcement: derived.enforcement,
    });
    const extraReasons = [...derived.reasons];
    if (derived.stacked_edges) extraReasons.push('stacked_edges_observed');
    if (strippedScenarioReasons.length) {
      if (classified.outcome === 'reachability_exposure') {
        extraReasons.push('reachability_only_comparison');
      } else if (!UNRESOLVED_OUTCOMES.has(classified.outcome)) {
        return itemResult(item, scenario, {
          outcome: 'inconclusive',
          reasons: ['scenario_not_comparable', ...(derived.observation === 'explicit_denial_observed' ? ['explicit_denial_observed'] : [])],
          compatibility_reasons: strippedScenarioReasons,
        }, { evidence_refs: refs, reasons: extraReasons });
      }
    }
    return itemResult(item, scenario, classified, { evidence_refs: refs, reasons: extraReasons });
  });

  const evaluation = normalizeComparisonEvaluation({
    kind: 'path_validation',
    tenant_id: tenantId,
    items: results,
    evaluated_at: evaluatedAt,
  });
  return {
    evaluation,
    attempts: details,
    primary_evidence_set: primaryUsable ? primarySet : null,
    scope_valid: scopeValid,
  };
}
