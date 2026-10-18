/**
 * Pure protection profile for one declared target.
 * Reads recorded rows only. Does not score readiness, start probes, or copy one
 * provider family onto another.
 */
import { assessOriginReachability, currentOriginBindingAuthorization } from './originBindings.mjs';
import { COVERAGE_FRESHNESS_POLICY, coverageFrom } from '../lib/protectionCoverage.mjs';
export { COVERAGE_FRESHNESS_POLICY } from '../lib/protectionCoverage.mjs';
import {
  assessComparability,
  classifyAttempt,
  compareObservationOrder,
  projectObservation,
} from './targetHistory.mjs';

export const PROTECTION_PROFILE_VERSION = 'protection-profile.v2';

/** Per-family observation age. Not the 30-day group readiness window. */
export const OBSERVATION_FRESHNESS_POLICY = Object.freeze({
  id: 'protection-profile.observation.v1',
  version: 1,
  max_age_ms: 7 * 24 * 60 * 60 * 1000,
  unit: 'family_observation',
});

const OBSERVED_FAMILY_STATUSES = new Set(['detected', 'not_detected', 'inconclusive']);
const FAMILY_STATUSES = new Set([
  'detected',
  'not_detected',
  'inconclusive',
  'not_checked',
  'not_recorded',
  'unknown',
]);
function asRecord(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function text(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function finiteNumber(value) {
  if (value == null || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function confidenceOrNull(value) {
  const number = finiteNumber(value);
  if (number == null) return null;
  return Math.min(1, Math.max(0, number));
}

function isoOrNull(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function stringList(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((entry) => text(entry)).filter(Boolean))];
}

function evidenceOf(row) {
  return asRecord(row?.evidence_json) ?? asRecord(row?.evidence) ?? {};
}

function layerFor(evidence, family) {
  const layers = Array.isArray(evidence.layers) ? evidence.layers : [];
  return layers.find((layer) => text(layer?.family)?.toLowerCase() === family) ?? null;
}

function blankFamily(status, reason) {
  return {
    status,
    reason,
    provider: null,
    product: null,
    confidence: null,
    observed_at: null,
    test_run_id: null,
    evidence_ids: [],
    sources: [],
    freshness: 'unknown',
    freshness_policy_id: OBSERVATION_FRESHNESS_POLICY.id,
  };
}

function familyStatus(value, fallback) {
  const status = text(value);
  if (status && FAMILY_STATUSES.has(status)) return status;
  return fallback;
}

function freshnessFor(status, observedAt, nowMs) {
  if (!OBSERVED_FAMILY_STATUSES.has(status)) return 'unknown';
  if (!observedAt) return 'unknown';
  const observedMs = Date.parse(observedAt);
  if (!Number.isFinite(observedMs)) return 'unknown';
  if (observedMs > nowMs) return 'unknown';
  return nowMs - observedMs > OBSERVATION_FRESHNESS_POLICY.max_age_ms ? 'stale' : 'current';
}

function explicitRecord(evidence, key) {
  const record = asRecord(evidence[key]);
  if (!record || !text(record.provider) && !text(record.status)) return null;
  return record;
}

/**
 * DNS provider and origin hosting are read only from an explicit recorded object
 * or a layer of that family. CNAME chains, resolved addresses, WAF vendors, CDN
 * providers, and cloud layers are not substitutes.
 */
function explicitFamily(evidence, family, absentStatus, absentReason, nowMs) {
  const record = explicitRecord(evidence, family) ?? explicitRecord(evidence, `${family}_provider`);
  const layer = layerFor(evidence, family);
  if (!record && !layer) return blankFamily(absentStatus, absentReason);
  const source = record ?? layer;
  const provider = text(source.provider) ?? text(layer?.provider);
  const status = familyStatus(source.status, provider || layer ? 'detected' : 'not_recorded');
  const observedAt = isoOrNull(source.observed_at);
  return {
    status,
    reason: text(source.reason) ?? (provider ? null : 'provider_not_recorded'),
    provider,
    product: text(source.product),
    confidence: confidenceOrNull(source.confidence ?? layer?.confidence),
    observed_at: observedAt,
    test_run_id: text(source.test_run_id),
    evidence_ids: stringList(source.evidence_ids),
    sources: stringList(source.sources ?? layer?.sources),
    freshness: freshnessFor(status, observedAt, nowMs),
    freshness_policy_id: OBSERVATION_FRESHNESS_POLICY.id,
  };
}

function scanFamily(row, family, nowMs) {
  const evidence = evidenceOf(row);
  const layer = layerFor(evidence, family);
  const status = familyStatus(row?.[`${family}_status`], null);
  if (!status) return blankFamily('not_recorded', 'family_not_in_observation');
  const providers = stringList(row?.[`${family}_providers`]);
  // The WAF column is waf_vendor. CDN stays on cdn_provider and must not borrow waf_vendor.
  const namedProvider = family === 'waf' ? text(row?.waf_vendor) : text(row?.[`${family}_provider`]);
  const provider = namedProvider ?? providers[0] ?? text(layer?.provider);
  const observedAt = OBSERVED_FAMILY_STATUSES.has(status) ? isoOrNull(row.observed_at) : null;
  const sources = stringList(layer?.sources);
  const recordedType = text(row?.[`${family}_type`]);
  if (recordedType && !sources.includes(recordedType)) sources.push(recordedType);
  return {
    status,
    reason: provider || status !== 'detected' ? text(row.reason) : 'provider_not_recorded',
    provider,
    product: text(layer?.product),
    confidence: confidenceOrNull(layer?.confidence),
    observed_at: observedAt,
    test_run_id: observedAt ? text(row.test_run_id) : null,
    evidence_ids: stringList(evidence.evidence_ids),
    sources,
    freshness: freshnessFor(status, observedAt, nowMs),
    freshness_policy_id: OBSERVATION_FRESHNESS_POLICY.id,
  };
}

function cloudSources(cloud, layer) {
  const sources = stringList(cloud?.sources ?? layer?.sources);
  const recordedType = text(cloud?.type);
  if (recordedType && !sources.includes(recordedType)) sources.push(recordedType);
  return sources;
}

function cloudFamily(row, nowMs) {
  const evidence = evidenceOf(row);
  const cloud = asRecord(evidence.cloud);
  const layer = layerFor(evidence, 'cloud');
  const providers = stringList(evidence.cloud_providers);
  if (!cloud && !layer && providers.length === 0) {
    return blankFamily('not_recorded', 'no_cloud_observation');
  }
  const status = familyStatus(cloud?.status, 'detected');
  const provider = text(cloud?.provider) ?? text(layer?.provider) ?? providers[0] ?? null;
  const observedAt = isoOrNull(cloud?.observed_at) ?? (OBSERVED_FAMILY_STATUSES.has(status) ? isoOrNull(row.observed_at) : null);
  return {
    status,
    reason: text(cloud?.reason) ?? 'observed_edge_or_cloud_layer',
    provider,
    product: text(cloud?.product) ?? text(layer?.product),
    confidence: confidenceOrNull(cloud?.confidence ?? layer?.confidence),
    observed_at: observedAt,
    test_run_id: text(cloud?.test_run_id) ?? (observedAt ? text(row.test_run_id) : null),
    evidence_ids: stringList(cloud?.evidence_ids ?? evidence.evidence_ids),
    sources: cloudSources(cloud, layer),
    freshness: freshnessFor(status, observedAt, nowMs),
    freshness_policy_id: OBSERVATION_FRESHNESS_POLICY.id,
  };
}

function familiesFromRow(row, nowMs) {
  if (!row) {
    return {
      waf: blankFamily('not_checked', 'no_edge_observation'),
      cdn: blankFamily('not_checked', 'no_edge_observation'),
      cloud: blankFamily('not_checked', 'no_edge_observation'),
      dns: blankFamily('not_recorded', 'no_dns_provider_observation'),
      origin_hosting: blankFamily('unknown', 'no_origin_hosting_observation'),
    };
  }
  return {
    waf: scanFamily(row, 'waf', nowMs),
    cdn: scanFamily(row, 'cdn', nowMs),
    cloud: cloudFamily(row, nowMs),
    dns: explicitFamily(evidenceOf(row), 'dns', 'not_recorded', 'no_dns_provider_observation', nowMs),
    origin_hosting: explicitFamily(
      evidenceOf(row),
      'origin_hosting',
      'unknown',
      'no_origin_hosting_observation',
      nowMs,
    ),
  };
}

function effectivenessFrom(row) {
  const raw = asRecord(evidenceOf(row).effectiveness);
  if (!raw) {
    return {
      unit: 'definitive_marker',
      status: 'not_recorded',
      blocked_count: null,
      allowed_count: null,
      inconclusive_count: null,
      not_run_count: null,
      tested_count: null,
      percentage: null,
      percentage_reason: 'not_recorded',
    };
  }
  const tested = finiteNumber(raw.tested_count);
  const blocked = finiteNumber(raw.blocked_count);
  const denominator = tested ?? 0;
  return {
    unit: 'definitive_marker',
    status: text(raw.status) ?? 'recorded',
    blocked_count: blocked,
    allowed_count: finiteNumber(raw.passed_count ?? raw.allowed_count),
    inconclusive_count: finiteNumber(raw.inconclusive_count),
    not_run_count: raw.not_run_count == null ? null : finiteNumber(raw.not_run_count),
    tested_count: tested,
    percentage: denominator > 0 && blocked != null ? Math.round((blocked / denominator) * 100) : null,
    percentage_reason: denominator > 0 ? 'definitive_markers_only' : 'not_applicable',
  };
}

/**
 * A recorded direct-origin probe is not an origin binding. Status stays
 * not_tested or unknown until a later slice supplies an authorized binding id.
 */
function originFrom(row) {
  const direct = asRecord(asRecord(evidenceOf(row).network_firewall)?.direct_origin_reachability);
  const recorded = text(direct?.status);
  const observed = Boolean(recorded && recorded !== 'not_tested' && recorded !== 'unknown');
  return {
    status: observed ? 'unknown' : 'not_tested',
    binding_id: null,
    reason: 'no_origin_binding_recorded',
    assurance: 'none',
    reachability: {
      status: recorded || 'not_tested',
      source: observed ? 'edge_detection.network_firewall' : null,
      tested_target_id: observed ? (text(direct?.target_id) ?? text(row?.target_id)) : null,
      scenario_id: observed
        ? (text(direct?.scenario_id) ?? text(direct?.scenario) ?? text(direct?.check_id))
        : null,
      limitations: observed
        ? [
          'tested_target_and_scenario_only',
          'not_an_authorized_origin_binding',
          'does_not_prove_host_origin_lockdown',
        ]
        : [],
    },
  };
}

/**
 * @param {{
 *   now?: Date | string | number,
 *   target: { id: string, kind?: string, value?: string, tenant_id?: string, target_group_id?: string },
 *   edgeRow?: object | null,
 *   policies?: object[],
 *   observations?: Array<{ check_id?: string, run?: object, verdict?: object }>,
 *   catalog?: object[],
 * }} input
 */
export function deriveProtectionProfile(input) {
  const nowMs = input.now == null ? Date.now() : new Date(input.now).getTime();
  const clock = Number.isFinite(nowMs) ? nowMs : Date.now();
  const families = familiesFromRow(input.edgeRow ?? null, clock);
  const { coverage, dimensions } = coverageFrom({
    target: input.target,
    policies: input.policies ?? [],
    targetGroup: input.targetGroup ?? null,
    observations: input.observations ?? [],
    catalog: input.catalog,
    nowMs: clock,
  });
  return {
    protection_profile: {
      derivation_version: PROTECTION_PROFILE_VERSION,
      as_of: new Date(clock).toISOString(),
      freshness_policy: OBSERVATION_FRESHNESS_POLICY,
      families,
      effectiveness: effectivenessFrom(input.edgeRow ?? null),
      origin: originFrom(input.edgeRow ?? null),
      dimensions,
    },
    coverage,
  };
}

function successfulRows(rows, family) {
  return rows
    .filter((row) => row.family === family && (row.attempt_class === 'successful' || classifyAttempt(row.outcome) === 'successful'))
    .sort((left, right) => compareObservationOrder(right, left));
}

/**
 * Additive history read model. Comparable changes use the two newest successful
 * observations of one family. Omitted history leaves deriveProtectionProfile unchanged.
 */
export function historyReadModel({ observations = [], bindingObservations = observations, bindings = [], proofFor = () => null,
  records = null, runs = [], targetId } = {}) {
  const rows = observations.map((row) => projectObservation(row) ?? row).filter((row) => row?.family);
  const families = [...new Set(rows.map((row) => row.family))];
  const retained_family_states = families.map((family) => {
    const last = successfulRows(rows, family)[0] ?? null;
    const failed = rows
      .filter((row) => row.family === family && (row.attempt_class === 'failed_attempt' || classifyAttempt(row.outcome) === 'failed_attempt'))
      .sort((left, right) => compareObservationOrder(right, left))[0] ?? null;
    return {
      family,
      last_successful: last,
      latest_failed_attempt: failed,
      fresh_negative: last?.outcome === 'not_detected',
      provider_loss: false,
    };
  });
  const comparable_changes = [];
  const comparison_gaps = [];
  for (const family of families) {
    const pair = successfulRows(rows, family);
    if (pair.length < 2) continue;
    const compared = assessComparability(pair[1], pair[0]);
    const entry = {
      family,
      previous_id: pair[1].id,
      observation_id: pair[0].id,
      ...compared,
    };
    if (compared.comparable && compared.change === 'changed') comparable_changes.push(entry);
    else if (!compared.comparable) comparison_gaps.push(entry);
  }
  const related = bindings.filter((row) => row
    && (row.origin_target_id === targetId || row.protected_target_id === targetId));
  const active = related.filter((row) => row.status === 'active');
  const authorizationFor = (binding) => records ? currentOriginBindingAuthorization(binding, records) : {
    verified: Boolean(proofFor(binding.origin_target_id)?.verified && proofFor(binding.protected_target_id)?.verified),
  };
  const origin_bindings = related.map((binding) => {
    const proof = authorizationFor(binding);
    const reach = assessOriginReachability(binding, bindingObservations, proof, { runs });
    return {
      id: binding.id,
      protected_target_id: binding.protected_target_id,
      origin_target_id: binding.origin_target_id,
      host: binding.host,
      sni: binding.sni,
      port: binding.port ?? null,
      path: binding.path ?? null,
      status: binding.status,
      assurance: 'none',
      lockdown: reach?.lockdown ?? 'not_tested',
      currently_authorized: reach.currently_authorized ?? false,
      authorization_reason: reach.authorization_reason ?? null,
      reachability: reach,
    };
  });
  const originCandidates = active.filter((row) => row.origin_target_id === targetId);
  const originBinding = originCandidates.length === 1 ? originCandidates[0] : null;
  let origin = null;
  if (originBinding) {
    const proof = authorizationFor(originBinding);
    const reach = assessOriginReachability(originBinding, bindingObservations, proof, { runs });
    origin = {
      status: reach.status === 'not_tested' ? 'not_tested' : 'unknown',
      binding_id: originBinding.id,
      reason: reach.reason ?? 'bound_origin_evidence',
      assurance: 'none',
      reachability: {
        status: reach.status,
        source: 'origin_binding',
        tested_target_id: reach.target_id ?? null,
        scenario_id: null,
        limitations: reach.limitations ?? ['authorized_binding_only', 'does_not_prove_host_origin_lockdown'],
      },
    };
  }
  if (originCandidates.length > 1) origin = { status: 'unknown', binding_id: null,
    reason: 'origin_binding_ambiguous', assurance: 'none', reachability: { status: 'not_tested',
      source: 'origin_binding', tested_target_id: null, limitations: ['explicit_binding_selection_required'] } };
  return { retained_family_states, comparable_changes, comparison_gaps, origin_bindings, origin };
}

export function attachHistoryReadModel(derived, history) {
  const protection_profile = {
    ...derived.protection_profile,
    retained_family_states: history.retained_family_states,
    comparable_changes: history.comparable_changes,
    comparison_gaps: history.comparison_gaps,
    origin_bindings: history.origin_bindings,
  };
  if (history.origin) protection_profile.origin = history.origin;
  return {
    protection_profile,
    coverage: {
      ...derived.coverage,
      retained_family_states: history.retained_family_states,
      comparable_changes: history.comparable_changes,
      comparison_gaps: history.comparison_gaps,
      origin_bindings: history.origin_bindings,
    },
  };
}

/**
 * Optional PV-08 configuration context, kept beside the derived profile. It never feeds
 * families, effectiveness, vendor detection, readiness, or coverage denominators.
 */
export function attachConfigurationContext(payload, configuration) {
  if (!payload?.protection_profile || !configuration || typeof configuration !== 'object') return payload;
  return { ...payload, protection_profile: { ...payload.protection_profile, configuration } };
}
