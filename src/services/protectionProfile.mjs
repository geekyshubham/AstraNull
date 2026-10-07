/**
 * Pure protection profile for one declared target.
 * Reads recorded rows only. Does not score readiness, start probes, or copy one
 * provider family onto another.
 */
import { CHECK_CATALOG, checkRequiresAdditionalInput, isCustomerRunnable } from '../contracts/checks.mjs';
import { targetKindCompatibilityError } from '../contracts/checkTargetCompatibility.mjs';
import { evidenceBackedVerdict } from '../lib/targetDetailRows.mjs';
import { approvedScenarioVersion, deriveCheckDefinitionVersion } from '../lib/checkDefinitionVersion.mjs';
import { assessOriginReachability } from './originBindings.mjs';
import { OBSERVATION_ONLY_PROBE_KINDS } from '../lib/probeEvidenceTiers.mjs';
import { inconclusiveReason } from '../lib/inconclusiveReasons.mjs';
import {
  assessComparability,
  classifyAttempt,
  compareObservationOrder,
  projectObservation,
} from './targetHistory.mjs';

export const PROTECTION_PROFILE_VERSION = 'protection-profile.v1';

/** Per-family observation age. Not the 30-day group readiness window. */
export const OBSERVATION_FRESHNESS_POLICY = Object.freeze({
  id: 'protection-profile.observation.v1',
  version: 1,
  max_age_ms: 7 * 24 * 60 * 60 * 1000,
  unit: 'family_observation',
});

/** Applicable target/check pair age. Separate from marker effectiveness. */
export const COVERAGE_FRESHNESS_POLICY = Object.freeze({
  id: 'protection-profile.coverage.v1',
  version: 1,
  max_age_ms: 7 * 24 * 60 * 60 * 1000,
  unit: 'target_check_pair',
});

const PLAN_VERSION = 'catalog+policy';
const OBSERVED_FAMILY_STATUSES = new Set(['detected', 'not_detected', 'inconclusive']);
const FAMILY_STATUSES = new Set([
  'detected',
  'not_detected',
  'inconclusive',
  'not_checked',
  'not_recorded',
  'unknown',
]);
const OPEN_RUN_STATUSES = new Set(['planned', 'running', 'collecting', 'queued', 'pending']);
const DIMENSION_BY_FAMILY = Object.freeze({
  l7: 'application',
  waf: 'application',
  path: 'application',
  pattern: 'application',
  exploit: 'application',
  origin: 'origin',
  l3_l4: 'network',
  protocol: 'network',
  tls: 'network',
  reflection: 'network',
  amplification: 'network',
  dns: 'dns',
  operations: 'operations',
});
const DIMENSIONS = Object.freeze(['application', 'origin', 'network', 'dns', 'operations', 'other']);

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
    sources: stringList(cloud?.sources ?? layer?.sources),
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

function summaryOf(run) {
  return asRecord(run?.summary_json) ?? asRecord(run?.summary) ?? {};
}

function recordedText(run, verdict, key) {
  const summary = summaryOf(run);
  const verdictMeta = asRecord(verdict?.metadata) ?? asRecord(verdict?.metadata_json) ?? {};
  return text(run?.[key]) ?? text(summary[key]) ?? text(verdict?.[key]) ?? text(verdictMeta[key]);
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

function percentage(numerator, denominator) {
  if (!denominator) return null;
  return Math.round((numerator / denominator) * 100);
}

function summarizePairs(pairs) {
  const applicable = pairs.filter((pair) => pair.state !== 'excluded');
  const count = (state) => applicable.filter((pair) => pair.state === state).length;
  const conclusive = count('conclusive');
  const inconclusive = count('inconclusive');
  const notRun = count('not_run');
  const stale = count('stale');
  const unknown = count('unknown');
  const partial = count('partial');
  const applicableCount = applicable.length;
  return {
    applicable_count: applicableCount,
    evaluated_count: conclusive + inconclusive + stale,
    conclusive_count: conclusive,
    inconclusive_count: inconclusive,
    not_run_count: notRun,
    stale_count: stale,
    unknown_count: unknown,
    partial_count: partial,
    excluded_count: pairs.filter((pair) => pair.state === 'excluded').length,
    percentage: percentage(conclusive, applicableCount),
    percentage_reason: applicableCount === 0 ? 'not_applicable' : 'conclusive_over_applicable',
  };
}

function dimensionStatus(summary) {
  if (summary.applicable_count === 0) return 'not_applicable';
  if (summary.conclusive_count === summary.applicable_count) return 'conclusive';
  if (summary.conclusive_count > 0) return 'partial';
  if (
    summary.evaluated_count === 0
    && summary.unknown_count === 0
    && summary.partial_count === 0
  ) return 'not_run';
  if (
    summary.stale_count > 0
    && summary.inconclusive_count === 0
    && summary.partial_count === 0
    && summary.unknown_count === 0
  ) return 'stale';
  if (
    summary.unknown_count > 0
    && summary.inconclusive_count === 0
    && summary.stale_count === 0
    && summary.partial_count === 0
  ) return 'unknown';
  if (summary.conclusive_count === 0 && summary.inconclusive_count === 0 && summary.stale_count === 0) {
    return 'partial';
  }
  if (summary.conclusive_count === 0) return 'inconclusive';
  return 'partial';
}

function policyForCheck(policies, target, checkId) {
  const matches = (policies ?? []).filter((policy) => {
    if (!policy || policy.archived_at || policy.state === 'archived') return false;
    if (policy.check_id !== checkId) return false;
    if (policy.tenant_id && target.tenant_id && policy.tenant_id !== target.tenant_id) return false;
    if (policy.target_group_id && target.target_group_id && policy.target_group_id !== target.target_group_id) return false;
    return !policy.target_id || policy.target_id === target.id;
  });
  return matches.find((policy) => policy.target_id) ?? matches[0] ?? null;
}

const FINALIZED_RUN_STATUSES = new Set(['completed', 'verdicted']);
const CANCELED_RUN_STATUSES = new Set(['cancelled', 'canceled']);

function provenanceOf(run, verdict) {
  const summary = summaryOf(run);
  const producer = text(run?.producer_kind) ?? text(summary.producer_kind);
  const simulation = text(run?.simulation) ?? text(summary.simulation);
  const label = text(run?.evidence_label) ?? text(summary.evidence_label);
  const source = text(run?.source) ?? text(summary.source) ?? text(summary.provenance) ?? text(verdict?.source_kind);
  // ponytail: only recorded producer/simulation/label marks a run as simulated.
  // Unmarked rows are not re-probed. Upgrade path: stamp producer_kind on the run row.
  if (
    producer === 'internal_simulation'
    || simulation === 'SAFE_PROBE_SIMULATION'
    || label === 'probe_simulation_evidence'
    || text(run?.probe_mode) === 'simulation'
    || text(summary.probe_mode) === 'simulation'
  ) return 'internal_simulation';
  if (
    producer === 'customer_declaration'
    || producer === 'manual'
    || source === 'manual_declaration'
    || source === 'customer_declaration'
  ) return 'manual_declaration';
  if (producer === 'signed_probe' || producer === 'live_external') return 'external';
  return 'unspecified';
}

function retainedFacts(run, verdict, provenance, observedAt) {
  if (!run) return null;
  return {
    verdict: text(verdict?.verdict),
    observed_at: observedAt,
    provenance,
    check_version: recordedText(run, verdict, 'check_version'),
    scenario_version: recordedText(run, verdict, 'scenario_version'),
    run_status: text(run.status),
  };
}

function versionGapFor(check, run, verdict) {
  const catalogVersion = deriveCheckDefinitionVersion(check).check_version;
  const recordedCheck = recordedText(run, verdict, 'check_version');
  if (!recordedCheck) return 'missing_check_version';
  if (!catalogVersion || recordedCheck !== catalogVersion) return 'check_version_mismatch';
  const scenario = approvedScenarioVersion(check);
  if (!scenario) return null;
  const recordedScenario = recordedText(run, verdict, 'scenario_version');
  if (!recordedScenario) return 'missing_scenario_version';
  if (recordedScenario !== scenario) return 'scenario_version_mismatch';
  return null;
}

function pairOutcome(state, fields) {
  return {
    state,
    prior_state: fields.prior_state ?? null,
    observed_at: fields.observed_at ?? null,
    freshness: fields.freshness,
    provenance: fields.provenance,
    live_external: fields.live_external === true,
    pair_reason: fields.pair_reason ?? null,
    retained: fields.retained ?? null,
  };
}

function pairState(run, verdict, check, nowMs) {
  if (!run) {
    return pairOutcome('not_run', {
      freshness: 'not_recorded',
      provenance: 'not_recorded',
      pair_reason: 'no_run',
    });
  }
  const provenance = provenanceOf(run, verdict);
  const observedAt = isoOrNull(run.completed_at);
  const retained = retainedFacts(run, verdict, provenance, observedAt);
  const runStatus = String(run.status ?? '').trim().toLowerCase();
  const base = { observed_at: observedAt, provenance, retained, live_external: false };
  if (CANCELED_RUN_STATUSES.has(runStatus)) {
    return pairOutcome('unknown', { ...base, freshness: 'unknown', pair_reason: 'canceled' });
  }
  if (!FINALIZED_RUN_STATUSES.has(runStatus) || OPEN_RUN_STATUSES.has(runStatus)) {
    return pairOutcome('unknown', { ...base, freshness: 'unknown', pair_reason: 'unfinalized' });
  }
  if (!observedAt) {
    return pairOutcome('unknown', { ...base, freshness: 'unknown', pair_reason: 'observation_time_unknown' });
  }
  const backed = evidenceBackedVerdict(verdict);
  if (!backed) {
    return pairOutcome('unknown', { ...base, freshness: 'unknown', pair_reason: 'no_evidence' });
  }
  const observedMs = Date.parse(observedAt);
  const stale = Number.isFinite(observedMs) && nowMs - observedMs > COVERAGE_FRESHNESS_POLICY.max_age_ms;
  if (provenance === 'internal_simulation' || provenance === 'manual_declaration') {
    return pairOutcome('unknown', {
      ...base,
      freshness: stale ? 'stale' : 'unknown',
      pair_reason: provenance,
    });
  }
  const versionGap = versionGapFor(check, run, verdict);
  if (versionGap) {
    return pairOutcome('partial', {
      ...base,
      freshness: stale ? 'stale' : 'unknown',
      pair_reason: versionGap,
    });
  }
  const inconclusive = /inconclusive|unknown|error|pending/i.test(backed);
  const prior = inconclusive ? 'inconclusive' : 'conclusive';
  if (stale) {
    return pairOutcome('stale', { ...base, prior_state: prior, freshness: 'stale', pair_reason: 'stale' });
  }
  return pairOutcome(prior, {
    ...base,
    freshness: 'current',
    live_external: prior === 'conclusive',
  });
}

function coverageFrom({ target, policies, observations, catalog, nowMs }) {
  const byCheck = new Map();
  for (const entry of observations ?? []) {
    const checkId = entry?.check_id ?? entry?.run?.check_id;
    if (checkId) byCheck.set(checkId, entry);
  }
  const pairs = [];
  const inconclusiveReasons = new Map();
  for (const check of catalog ?? CHECK_CATALOG) {
    if (!check?.check_id || !isCustomerRunnable(check)) continue;
    if (targetKindCompatibilityError(check, target)) continue;
    const declarationOnly = text(check.evidence_tier)?.toUpperCase() === 'E1'
      || check.probe_profile?.kind === 'metadata_marker'
      || check.probe_profile?.kind === 'ops_readiness';
    const observationOnly = text(check.evidence_tier)?.toUpperCase() === 'E2'
      || OBSERVATION_ONLY_PROBE_KINDS.includes(check.probe_profile?.kind);
    const excluded = declarationOnly || observationOnly || checkRequiresAdditionalInput(check);
    const exclusionReason = declarationOnly ? 'declaration_only' : observationOnly ? 'observation_only' : 'setup_required';
    const policy = policyForCheck(policies, target, check.check_id);
    const policyBinding = !policy
      ? 'no_policy'
      : (typeof policy.target_id === 'string' && policy.target_id.trim()
        ? 'bound'
        : 'test_policy_target_binding_missing');
    const launch = {
      launch_eligibility: { status: 'not_evaluated', reason: 'runtime_gates_not_evaluated' },
      launchable: null,
      launch_block_reason: 'not_evaluated',
      policy_binding: policyBinding,
    };
    const dimension = DIMENSION_BY_FAMILY[check.vector_family] ?? 'other';
    if (excluded) {
      pairs.push({
        check_id: check.check_id,
        dimension,
        state: 'excluded',
        prior_state: null,
        exclusion_reason: exclusionReason,
        last_run_id: null,
        observed_at: null,
        freshness: 'not_applicable',
        provenance: 'not_recorded',
        live_external: false,
        pair_reason: exclusionReason,
        retained: null,
        policy_id: policy?.id ?? null,
        ...launch,
      });
      continue;
    }
    const entry = byCheck.get(check.check_id) ?? null;
    const outcome = pairState(entry?.run ?? null, entry?.verdict ?? null, check, nowMs);
    if (outcome.state === 'inconclusive') {
      const reason = inconclusiveReason({ probeKind: check.probe_profile?.kind, externalResult: entry?.run?.probe_external_result, metadata: entry?.run?.probe_metadata ?? {} });
      const group = inconclusiveReasons.get(reason.reason) ?? { reason: reason.reason, label: reason.label, next_step: reason.next_step, count: 0, check_ids: [] };
      group.count += 1;
      group.check_ids.push(check.check_id);
      inconclusiveReasons.set(reason.reason, group);
    }
    pairs.push({
      check_id: check.check_id,
      dimension,
      state: outcome.state,
      prior_state: outcome.prior_state,
      exclusion_reason: null,
      last_run_id: entry?.run?.id ?? null,
      observed_at: outcome.observed_at,
      freshness: outcome.freshness,
      provenance: outcome.provenance,
      live_external: outcome.live_external,
      pair_reason: outcome.pair_reason,
      retained: outcome.retained,
      policy_id: policy?.id ?? null,
      ...launch,
    });
  }
  pairs.sort((left, right) => left.check_id.localeCompare(right.check_id));
  const summary = summarizePairs(pairs);
  const dimensions = DIMENSIONS.map((id) => {
    const scoped = pairs.filter((pair) => pair.dimension === id);
    const dimensionSummary = summarizePairs(scoped);
    return {
      id,
      unit: 'target_check_pair',
      status: dimensionStatus(dimensionSummary),
      ...dimensionSummary,
      freshness_policy_id: COVERAGE_FRESHNESS_POLICY.id,
      scope: { target_id: target.id, plan_version: PLAN_VERSION },
    };
  });
  return {
    coverage: {
      unit: 'target_check_pair',
      plan_version: PLAN_VERSION,
      as_of: new Date(nowMs).toISOString(),
      freshness_policy: COVERAGE_FRESHNESS_POLICY,
      runtime_launch_gates: 'not_evaluated',
      scope: { target_id: target.id, plan_version: PLAN_VERSION },
      ...summary,
      observation_only_count: pairs.filter((pair) => pair.exclusion_reason === 'observation_only').length,
      inconclusive_reasons: [...inconclusiveReasons.values()].sort((a, b) => b.count - a.count || a.reason.localeCompare(b.reason)),
      pairs,
    },
    dimensions,
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
export function historyReadModel({ observations = [], bindings = [], proofFor = () => null, targetId } = {}) {
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
  const active = bindings.filter((row) => row?.status === 'active'
    && (row.origin_target_id === targetId || row.protected_target_id === targetId));
  const origin_bindings = active.map((binding) => {
    const onOrigin = binding.origin_target_id === targetId;
    const proof = proofFor(binding.origin_target_id);
    const reach = onOrigin ? assessOriginReachability(binding, rows, proof) : null;
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
      currently_authorized: Boolean(proof?.verified) && binding.status === 'active',
      reachability: onOrigin ? reach : {
        status: 'not_tested',
        assurance: 'none',
        lockdown: 'not_tested',
        reason: 'bound_origin_evidence_is_on_origin_target',
        observation_id: null,
      },
    };
  });
  const originBinding = active.find((row) => row.origin_target_id === targetId) ?? null;
  let origin = null;
  if (originBinding) {
    const proof = proofFor(originBinding.origin_target_id);
    const reach = assessOriginReachability(originBinding, rows, proof);
    origin = {
      status: reach.status === 'not_tested' ? 'not_tested' : 'unknown',
      binding_id: originBinding.id,
      reason: reach.reason ?? 'bound_origin_evidence',
      assurance: 'none',
      reachability: {
        status: reach.status,
        source: 'origin_binding',
        tested_target_id: targetId,
        scenario_id: null,
        limitations: reach.limitations ?? ['authorized_binding_only', 'does_not_prove_host_origin_lockdown'],
      },
    };
  }
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
