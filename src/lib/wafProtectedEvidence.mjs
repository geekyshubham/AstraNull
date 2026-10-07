import { metadataConfirmsOriginLockdown } from './externalObservationOutcomes.mjs';
import { EXTERNAL_WAF_PASS } from './wafBoundRunCorrelation.mjs';
import { isTrustedProducerEvent } from './trustedEventProvenance.mjs';

function normalizeExternalResult(value) {
  return String(value ?? '').trim().toLowerCase();
}

function hasWafFingerprintHint(metadata) {
  const md = metadata ?? {};
  const external = normalizeExternalResult(md.external_result);
  const effectiveness = md.waf_effectiveness?.status ?? md.effectiveness?.status;
  if (
    md.simulation === 'SAFE_PROBE_SIMULATION'
    || external === 'error'
    || external === 'timeout'
    || (typeof md.error_class === 'string' && md.error_class.trim())
    || md.validation_failed === true
    || md.probe_validation_passed === false
    || (effectiveness && effectiveness !== 'effective_for_tested_probes')
  ) return false;

  const edgeSignature = md.edge_signature && typeof md.edge_signature === 'object'
    ? md.edge_signature
    : null;
  return Boolean(
    md.waf_fingerprint_detected === true
    || edgeSignature?.waf_present === true
    || (typeof md.block_page_signature_id === 'string'
      && /^block_sig_[a-z0-9_]+_v\d+$/.test(md.block_page_signature_id.trim())
      && md.block_page_signature_id.trim() !== 'block_sig_generic_waf_v1'),
  );
}

/**
 * Full "protected" is corroborated only by explicit direct-origin denial over a healthy baseline (ADR-0008, PV-01).
 *
 * @param {{ probes?: object[] }} input
 */
export function buildWafEvidenceCorroboration({ probes = [] } = {}) {
  const probesById = new Map();
  const probesByNonce = new Map();
  let originLockdownConfirmed = false;

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
    if (metadataConfirmsOriginLockdown(probe?.metadata)) {
      originLockdownConfirmed = true;
    }
  }

  return { probesById, probesByNonce, originLockdownConfirmed };
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
      if (String(probe.id ?? '') !== String(evidence.request_id)) return false;
    }
    if (evidence.test_run_id) {
      const probeRunId = probe.test_run_id ?? probe.metadata?.test_run_id;
      if (String(probeRunId ?? '') !== String(evidence.test_run_id)) return false;
    }
    if (evidence.probe_job_id && probe.metadata?.probe_job_id
      && String(probe.metadata.probe_job_id) !== String(evidence.probe_job_id)
      && String(probe.id) !== String(evidence.probe_job_id)) return false;
    return true;
  });
}

/**
 * Full protected means the bound external edge block is corroborated by external origin-lockdown
 * evidence in the same run (explicit direct-origin denial). External edge-only evidence is handled by
 * corroborateEdgeProtectedScenarioEvidence.
 */
export function corroborateProtectedScenarioEvidence(scenario, corroboration) {
  if (!matchingVerifiedExternalProbePass(scenario, corroboration)) return false;
  return corroboration.originLockdownConfirmed === true;
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
 * Remove client-asserted origin/agent observation flags; corroboration derives these from
 * stored external probe events only.
 *
 * @param {Record<string, unknown>} evidenceSummary
 */
export function stripClientAssertedAgentEvidence(evidenceSummary = {}) {
  if (!evidenceSummary || typeof evidenceSummary !== 'object' || Array.isArray(evidenceSummary)) {
    return evidenceSummary;
  }
  const { observed_at_agent: _ignoredAgent, origin_lockdown_confirmed: _ignoredLockdown, ...rest } =
    evidenceSummary;
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
    return buildWafEvidenceCorroboration({ probes: [] });
  }

  const probes = await validationEvidence.listRunEvents(ctx, testRunId, {
    signalType: 'probe_result',
    limit: FINALIZE_CORROBORATION_EVENT_LIMIT,
  });

  return buildCorroborationFromEvents(
    Array.isArray(probes) ? probes : [],
    testRunId,
  );
}
