import {
  OBSERVATION_ONLY_PROBE_KINDS,
  verdictSupportsReadiness,
} from '../lib/readinessVerdicts.mjs';

export { OBSERVATION_ONLY_PROBE_KINDS, verdictSupportsReadiness };

/**
 * Correlation truth table — evidence-backed verdicts (metadata-only developer validation).
 */

const OBSERVATION_ONLY_PROBE_KIND_SET = new Set(OBSERVATION_ONLY_PROBE_KINDS);
export function isObservationOnlyProbeKind(probeKind) {
  return OBSERVATION_ONLY_PROBE_KIND_SET.has(probeKind);
}

export function probeEventHasProbeIo(probeEvent) {
  const metadata = probeEvent?.metadata ?? probeEvent?.metadata_json;
  const probeRequestsSent = metadata?.safety_attestation?.probe_requests_sent;
  return Number.isSafeInteger(probeRequestsSent) && probeRequestsSent > 0;
}

function correlateObservationOnlyVerdict(probeKind) {
  const noIo = probeKind === 'metadata_marker';
  return {
    verdict: 'inconclusive',
    confidence: 'external_only',
    explanation: noIo
      ? 'Metadata-only check performed no network I/O and cannot establish readiness or exposure.'
      : `${probeKind} recorded transport or liveness metadata only; it did not establish this check's verdict logic.`,
    createsFinding: false,
  };
}

function correlateProbeFailure(externalResult, probeKind) {
  const knownKindTimedOut = externalResult === 'timeout' && typeof probeKind === 'string';
  if (!['error', 'not_run'].includes(externalResult) && !knownKindTimedOut) return null;
  const resultLabel = externalResult === 'not_run' ? 'was not run' : `ended with ${externalResult}`;
  return {
    verdict: 'inconclusive',
    confidence: 'external_only',
    explanation: `The ${probeKind ?? 'external'} probe ${resultLabel}; transport failure or an execution deadline cannot establish protection or exposure.`,
    createsFinding: false,
  };
}

/**
 * Correlate a verdict from external probe evidence only (ADR-0008: no agents).
 */
export function correlateExternalOnlyVerdict({
  externalResult,
  expectedBehavior,
  probeKind,
  probeIoObserved = false,
}) {
  if (isObservationOnlyProbeKind(probeKind)) {
    return correlateObservationOnlyVerdict(probeKind);
  }

  const probeFailure = correlateProbeFailure(externalResult, probeKind);
  if (probeFailure) return probeFailure;

  const blocked = externalResult === 'blocked' || externalResult === 'timeout';
  const connected = externalResult === 'connected' || externalResult === 'allowed';

  if (blocked && probeIoObserved !== true) {
    return {
      verdict: 'inconclusive',
      confidence: 'external_only',
      explanation: 'Blocked/timeout metadata had no attested probe I/O and cannot establish edge protection.',
      createsFinding: false,
    };
  }

  if (expectedBehavior === 'must_block_before_origin') {
    if (blocked) {
      return {
        verdict: 'edge_protected',
        confidence: 'external_only',
        explanation:
          'External probe was blocked at the edge; the declared path did not respond as reachable.',
        createsFinding: false,
      };
    }
    if (connected) {
      return {
        verdict: 'edge_exposed',
        confidence: 'external_only',
        explanation:
          'External probe reached the declared path; the edge did not block traffic before origin.',
        createsFinding: true,
        severity: 'medium',
      };
    }
  }

  if (expectedBehavior === 'must_reach_canary') {
    if (connected) {
      return {
        verdict: 'allowed_as_expected',
        confidence: 'external_only',
        explanation: 'Protected-path canary traffic reached the declared path as expected.',
        createsFinding: false,
      };
    }
    if (blocked) {
      return {
        verdict: 'inconclusive',
        confidence: 'external_only',
        explanation: 'Canary path did not complete — protected path or canary may be unreachable.',
        createsFinding: false,
      };
    }
  }

  return {
    verdict: 'inconclusive',
    confidence: 'external_only',
    explanation: 'Insufficient external probe evidence for a definitive verdict.',
    createsFinding: false,
  };
}

/**
 * Ops-readiness verdict — control-plane self-check with no agent/external target traffic.
 * Reuses the existing verdict vocabulary ('protected' / 'inconclusive') the UI handles.
 * Never creates a customer target finding.
 *
 * @param {{ externalResult?: string, opsValidationOk?: boolean }} params
 */
export function correlateOpsReadinessVerdict({ externalResult, opsValidationOk } = {}) {
  const validated =
    opsValidationOk === true || (externalResult === 'connected' && opsValidationOk === true);
  if (validated) {
    return {
      verdict: 'protected',
      confidence: 'high',
      createsFinding: false,
      explanation: 'Operational readiness control validated by control-plane self-check.',
    };
  }
  return {
    verdict: 'inconclusive',
    confidence: 'low',
    createsFinding: false,
    explanation:
      'Operational readiness could not be validated (no recorded operational evidence).',
  };
}

export function withinCorrelationWindow(probeTs, obsTs, windowMs = 120_000) {
  const a = new Date(probeTs).getTime();
  const b = new Date(obsTs).getTime();
  return Math.abs(b - a) <= windowMs;
}