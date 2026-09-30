import { isTrustedProducerEvent } from './trustedEventProvenance.mjs';

export const EXTERNAL_WAF_PASS = new Set([
  'blocked',
  'challenge',
  'challenged',
  'rate_limited',
  'filtered',
]);
export const EXTERNAL_WAF_FAIL = new Set([
  'allowed',
  'reached_origin',
  'delivered',
  'connected',
]);

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

/**
 * Outside-in only (ADR-0008): origin lockdown is proven by an external origin-bypass probe that
 * could not reach the direct origin, not by an internal agent. The scanner records this on the
 * probe metadata as `origin_lockdown_confirmed`.
 */
function probeConfirmsOriginLockdown(metadata) {
  return (metadata ?? {}).origin_lockdown_confirmed === true;
}

/**
 * Derive WAF validation signals from metadata-only probe events correlated by nonce_hash.
 *
 * "Edge protected" comes from an external edge block on a fingerprinted WAF. Full "protected"
 * additionally requires external origin-lockdown evidence in the same bound run (an origin-bypass
 * probe that did not reach the direct origin). No agent/internal corroboration is used.
 *
 * @param {{ probes: Array<{ id: string, nonce_hash?: string|null, metadata?: object }> }} input
 */
export function deriveWafSignalsFromBoundEvents({ probes = [] } = {}) {
  const trustedProbes = probes.filter(isTrustedProducerEvent);

  // Origin lockdown is a run-level external signal: any trusted probe in the bound run whose
  // origin-bypass leg found the origin unreachable proves the origin is not directly exposed.
  const originLockdownConfirmed = trustedProbes.some(
    (probe) => probeConfirmsOriginLockdown(probe.metadata),
  );

  let wafDetected = false;
  let anyPass = false;
  let anyEdgePass = false;
  let validationFailed = false;
  let originBypassConfirmed = false;
  let hasExternalProbeEvidence = false;
  const scenarioResults = [];

  for (const probe of trustedProbes) {
    if (hasWafFingerprintHint(probe.metadata)) {
      wafDetected = true;
    }

    const external = normalizeExternalResult(probe.metadata?.external_result);
    if (!external) continue;
    hasExternalProbeEvidence = true;

    const nonce = probe.nonce_hash ?? null;

    let passed = null;
    let observed_action = 'inconclusive';
    if (EXTERNAL_WAF_FAIL.has(external)) {
      validationFailed = true;
      passed = false;
      observed_action = 'allow';
      // Origin bypass is confirmed by the external probe itself reaching the origin.
      if ((external === 'reached_origin' || external === 'delivered' || external === 'connected')
        && probe.metadata?.origin_bypass_confirmed === true) {
        originBypassConfirmed = true;
      }
    } else if (EXTERNAL_WAF_PASS.has(external)) {
      wafDetected = true;
      if (nonce && hasWafFingerprintHint(probe.metadata)) {
        anyEdgePass = true;
        passed = true;
        observed_action = 'block';
        // Full "protected" requires external origin-lockdown evidence in the same run.
        if (originLockdownConfirmed) anyPass = true;
      } else {
        passed = null;
        observed_action = 'inconclusive';
      }
    }

    const evidence_summary = {
      request_id: probe.id,
      nonce_hash: nonce ?? undefined,
      marker_result: external,
      blocked: EXTERNAL_WAF_PASS.has(external),
      origin_lockdown_confirmed: probeConfirmsOriginLockdown(probe.metadata),
      test_run_id: probe.metadata?.test_run_id ?? undefined,
      probe_job_id: probe.metadata?.probe_job_id ?? probe.id,
    };

    scenarioResults.push({
      scenario_family: 'marker',
      expected_action: 'block',
      observed_action,
      passed,
      confidence: passed === true ? 0.85 : passed === false ? 0.8 : 0,
      evidence_summary,
    });
  }

  const validationPassed = hasExternalProbeEvidence && anyPass && !validationFailed;
  const edgeProtected = hasExternalProbeEvidence && anyEdgePass && !validationFailed;

  return {
    wafDetected,
    validationPassed,
    edgeProtected,
    validationFailed,
    originBypassConfirmed,
    originLockdownConfirmed,
    scenarioResults,
    source_external: hasExternalProbeEvidence,
  };
}

export function booleanFieldExplicit(body, snake, camel) {
  return Object.prototype.hasOwnProperty.call(body, snake)
    || Object.prototype.hasOwnProperty.call(body, camel);
}
