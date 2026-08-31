import { EXTERNAL_WAF_PASS } from './wafBoundRunCorrelation.mjs';
import { isTrustedProducerEvent } from './trustedEventProvenance.mjs';

function normalizeExternalResult(value) {
  return String(value ?? '').trim().toLowerCase();
}

function hasWafFingerprintHint(metadata) {
  const md = metadata ?? {};
  return Boolean(
    md.waf_fingerprint_detected === true
    || (typeof md.block_page_fingerprint_hash === 'string' && md.block_page_fingerprint_hash.trim())
    || (typeof md.waf_product_hint === 'string' && md.waf_product_hint.trim())
    || (typeof md.detected_vendor === 'string' && md.detected_vendor.trim()),
  );
}

function isWafMarkerAgentMetadata(metadata) {
  const md = metadata ?? {};
  if (md.waf_marker === true || md.waf_validation_marker === true) return true;
  if (typeof md.marker_type === 'string' && md.marker_type.trim()) return true;
  if (md.scenario_family === 'marker') return true;
  if (md.canary_observation === true && (md.waf_marker === true || md.waf_validation_marker === true)) {
    return true;
  }
  return false;
}

/**
 * @param {{ probes?: object[], agents?: object[] }} input
 */
export function buildWafEvidenceCorroboration({ probes = [], agents = [] } = {}) {
  const probesById = new Map();
  const probesByNonce = new Map();
  const agentsByNonce = new Map();

  for (const probe of probes) {
    if (!isTrustedProducerEvent(probe)) continue;
    if (probe?.id) {
      probesById.set(String(probe.id), probe);
    }
    if (probe?.nonce_hash) {
      const bucket = probesByNonce.get(probe.nonce_hash) ?? [];
      bucket.push(probe);
      probesByNonce.set(probe.nonce_hash, bucket);
    }
  }

  for (const agent of agents) {
    if (!isTrustedProducerEvent(agent)) continue;
    if (!agent?.nonce_hash) continue;
    const bucket = agentsByNonce.get(agent.nonce_hash) ?? [];
    bucket.push(agent);
    agentsByNonce.set(agent.nonce_hash, bucket);
  }

  return { probesById, probesByNonce, agentsByNonce };
}

function matchingVerifiedExternalProbePass(scenario, corroboration) {
  if (!scenario || scenario.passed !== true) return false;
  const evidence = scenario.evidence_summary_json ?? scenario.evidence_summary ?? {};
  const nonceHash = typeof evidence.nonce_hash === 'string' ? evidence.nonce_hash.trim() : '';
  if (!nonceHash) return false;
  const matchingProbes = corroboration.probesByNonce.get(nonceHash) ?? [];
  return matchingProbes.some((probe) => {
    const external = normalizeExternalResult(probe.metadata?.external_result);
    if (!EXTERNAL_WAF_PASS.has(external) || !hasWafFingerprintHint(probe.metadata)) return false;
    if (evidence.request_id) {
      const linkedProbe = corroboration.probesById.get(String(evidence.request_id));
      if (!linkedProbe || linkedProbe.nonce_hash !== nonceHash) return false;
    }
    if (evidence.test_run_id && probe.metadata?.test_run_id
      && String(probe.metadata.test_run_id) !== String(evidence.test_run_id)) return false;
    if (evidence.probe_job_id && probe.metadata?.probe_job_id
      && String(probe.metadata.probe_job_id) !== String(evidence.probe_job_id)
      && String(probe.id) !== String(evidence.probe_job_id)) return false;
    return true;
  });
}

function agentConfirmsEdgeBlock(agent) {
  const metadata = agent?.metadata ?? {};
  const observed = normalizeExternalResult(metadata.observed_action);
  return observed === 'block'
    || observed === 'blocked'
    || observed === 'not_reached_origin'
    || metadata.waf_blocked === true
    || metadata.reached_origin === false
    || metadata.origin_reached === false;
}

function agentShowsMarkerLeak(agent) {
  const metadata = agent?.metadata ?? {};
  const observed = normalizeExternalResult(metadata.observed_action);
  return observed === 'allow'
    || observed === 'allowed'
    || observed === 'reached_origin'
    || observed === 'delivered'
    || metadata.reached_origin === true
    || metadata.origin_reached === true
    || !agentConfirmsEdgeBlock(agent);
}

/**
 * Full protected means the bound external block is corroborated by a matching internal/origin
 * observation. External-only evidence is handled by corroborateEdgeProtectedScenarioEvidence.
 */
export function corroborateProtectedScenarioEvidence(scenario, corroboration) {
  if (!matchingVerifiedExternalProbePass(scenario, corroboration)) return false;
  const evidence = scenario.evidence_summary_json ?? scenario.evidence_summary ?? {};
  const nonceHash = String(evidence.nonce_hash).trim();
  const wafMarkerAgents = (corroboration.agentsByNonce.get(nonceHash) ?? [])
    .filter((agent) => isWafMarkerAgentMetadata(agent.metadata));
  if (wafMarkerAgents.length === 0) return false;
  if (wafMarkerAgents.some((agent) => agentShowsMarkerLeak(agent))) return false;
  return wafMarkerAgents.some((agent) => agentConfirmsEdgeBlock(agent));
}

export function corroborateEdgeProtectedScenarioEvidence(scenario, corroboration) {
  return matchingVerifiedExternalProbePass(scenario, corroboration);
}

/**
 * @param {object[]} normalizedScenarios
 * @param {ReturnType<typeof buildWafEvidenceCorroboration>} corroboration
 */
export function scenarioSetSupportsProtectedClaim(normalizedScenarios, corroboration) {
  return normalizedScenarios.some(
    (scenario) => corroborateProtectedScenarioEvidence(scenario, corroboration),
  );
}

export function scenarioSetSupportsEdgeProtectedClaim(normalizedScenarios, corroboration) {
  return normalizedScenarios.some(
    (scenario) => corroborateEdgeProtectedScenarioEvidence(scenario, corroboration),
  );
}

/**
 * @param {{
 *   validationPassed: boolean,
 *   normalizedScenarios: object[],
 *   corroboration: ReturnType<typeof buildWafEvidenceCorroboration>,
 * }} input
 */
export function protectedFinalizeEvidenceRequired({
  validationPassed,
  normalizedScenarios,
  corroboration,
}) {
  if (!validationPassed) return null;
  if (scenarioSetSupportsProtectedClaim(normalizedScenarios, corroboration)) return null;
  if (scenarioSetSupportsEdgeProtectedClaim(normalizedScenarios, corroboration)) {
    return { downgrade_to_edge_protected: true };
  }
  return {
    error: 'waf_validation_evidence_required',
    status: 400,
  };
}

/**
 * Remove client-asserted agent observation flags; corroboration derives these from stored events.
 *
 * @param {Record<string, unknown>} evidenceSummary
 */
export function stripClientAssertedAgentEvidence(evidenceSummary = {}) {
  if (!evidenceSummary || typeof evidenceSummary !== 'object' || Array.isArray(evidenceSummary)) {
    return evidenceSummary;
  }
  const { observed_at_agent: _ignored, ...rest } = evidenceSummary;
  return rest;
}

const FINALIZE_CORROBORATION_EVENT_LIMIT = 500;

/**
 * Corroboration is trusted only when events are scoped to an explicitly bound test run.
 * An unbound client nonce must never join arbitrary same-tenant target evidence.
 *
 * @param {object[]} events
 * @param {string | null | undefined} testRunId
 */
export function buildCorroborationFromEvents(events, testRunId) {
  const scoped = testRunId
    ? (Array.isArray(events) ? events : [])
      .filter((event) => event.test_run_id === testRunId)
    : [];

  return buildWafEvidenceCorroboration({
    probes: scoped.filter((event) => event.signal_type === 'probe_result'),
    agents: scoped.filter((event) => event.signal_type === 'agent_observation'),
  });
}

/**
 * @param {object} validationEvidence
 * @param {{ tenantId: string }} ctx
 * @param {string | null | undefined} testRunId
 */
export async function buildCorroborationFromValidationEvidence(
  validationEvidence,
  ctx,
  testRunId,
) {
  if (!testRunId || typeof validationEvidence?.listRunEvents !== 'function') {
    return buildWafEvidenceCorroboration({ probes: [], agents: [] });
  }

  const [probes, agents] = await Promise.all([
    validationEvidence.listRunEvents(ctx, testRunId, {
      signalType: 'probe_result',
      limit: FINALIZE_CORROBORATION_EVENT_LIMIT,
    }),
    validationEvidence.listRunEvents(ctx, testRunId, {
      signalType: 'agent_observation',
      limit: FINALIZE_CORROBORATION_EVENT_LIMIT,
    }),
  ]);

  const events = [
    ...(Array.isArray(probes) ? probes : []),
    ...(Array.isArray(agents) ? agents : []),
  ];
  return buildCorroborationFromEvents(events, testRunId);
}
