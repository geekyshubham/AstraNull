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

function correlateObservationOnlyVerdict(probeKind, { externalOnly = false } = {}) {
  const noIo = probeKind === 'metadata_marker';
  return {
    verdict: 'inconclusive',
    confidence: externalOnly ? 'external_only' : 'low',
    ...(externalOnly ? { placement: 'unverified', strengthen_hint: 'deploy_agent' } : {}),
    explanation: noIo
      ? 'Metadata-only check performed no network I/O and cannot establish readiness or exposure.'
      : `${probeKind} recorded transport or liveness metadata only; it did not establish this check's verdict logic.`,
    createsFinding: false,
  };
}

function correlateProbeFailure(externalResult, probeKind, { externalOnly = false } = {}) {
  const knownKindTimedOut = externalResult === 'timeout' && typeof probeKind === 'string';
  if (!['error', 'not_run'].includes(externalResult) && !knownKindTimedOut) return null;
  const resultLabel = externalResult === 'not_run' ? 'was not run' : `ended with ${externalResult}`;
  return {
    verdict: 'inconclusive',
    confidence: externalOnly ? 'external_only' : 'low',
    ...(externalOnly ? { placement: 'unverified', strengthen_hint: 'deploy_agent' } : {}),
    explanation: `The ${probeKind ?? 'external'} probe ${resultLabel}; transport failure or an execution deadline cannot establish protection or exposure.`,
    createsFinding: false,
  };
}

export function correlateVerdict({
  externalResult,
  agentObserved,
  expectedBehavior,
  agentOnline,
  agentBound,
  probeKind,
  probeIoObserved = false,
}) {
  if (isObservationOnlyProbeKind(probeKind)) {
    return correlateObservationOnlyVerdict(probeKind);
  }

  const probeFailure = correlateProbeFailure(externalResult, probeKind);
  if (probeFailure) return probeFailure;

  if (!agentOnline || !agentBound) {
    return {
      verdict: 'inconclusive',
      confidence: 'low',
      explanation:
        'Agent is offline or not bound to the target group; internal observation evidence is unavailable.',
      createsFinding: false,
    };
  }

  const blocked = externalResult === 'blocked' || externalResult === 'timeout';
  const connected = externalResult === 'connected' || externalResult === 'allowed';

  if (blocked && probeIoObserved !== true) {
    return {
      verdict: 'inconclusive',
      confidence: 'low',
      explanation: 'Blocked/timeout metadata had no attested probe I/O and cannot establish protection.',
      createsFinding: false,
    };
  }

  if (expectedBehavior === 'must_block_before_origin') {
    if (blocked && !agentObserved) {
      return {
        verdict: 'protected',
        confidence: 'medium',
        explanation:
          'Simulated external probe was blocked or timed out and the agent did not observe traffic — consistent with protection.',
        createsFinding: false,
      };
    }
    if (connected && agentObserved) {
      return {
        verdict: 'bypassable',
        confidence: 'high',
        explanation:
          'Simulated external probe reached the target path and the agent observed matching traffic — bypass risk.',
        createsFinding: true,
        severity: 'high',
      };
    }
    if (blocked && agentObserved) {
      return {
        verdict: 'penetrated',
        confidence: 'high',
        explanation:
          'External response indicated block/timeout but the agent observed traffic — possible penetration with silent drop downstream.',
        createsFinding: true,
        severity: 'high',
      };
    }
    if (connected && !agentObserved) {
      return {
        verdict: 'misplaced_agent',
        confidence: 'low',
        explanation:
          'External probe succeeded but no agent observation — inconclusive placement or downstream block.',
        createsFinding: false,
      };
    }
  }

  if (expectedBehavior === 'must_reach_canary') {
    if (connected && agentObserved) {
      return {
        verdict: 'allowed_as_expected',
        confidence: 'high',
        explanation: 'Protected-path canary traffic reached the observation point as expected.',
        createsFinding: false,
      };
    }
    if (blocked && !agentObserved) {
      return {
        verdict: 'inconclusive',
        confidence: 'low',
        explanation: 'Canary path did not complete — protected path or canary may be unreachable.',
        createsFinding: false,
      };
    }
  }

  return {
    verdict: 'inconclusive',
    confidence: 'low',
    explanation: 'Insufficient correlated evidence for a definitive verdict.',
    createsFinding: false,
  };
}

export function correlateExternalOnlyVerdict({
  externalResult,
  expectedBehavior,
  probeKind,
  probeIoObserved = false,
}) {
  if (isObservationOnlyProbeKind(probeKind)) {
    return correlateObservationOnlyVerdict(probeKind, { externalOnly: true });
  }

  const probeFailure = correlateProbeFailure(externalResult, probeKind, { externalOnly: true });
  if (probeFailure) return probeFailure;

  const blocked = externalResult === 'blocked' || externalResult === 'timeout';
  const connected = externalResult === 'connected' || externalResult === 'allowed';

  if (blocked && probeIoObserved !== true) {
    return {
      verdict: 'inconclusive',
      confidence: 'external_only',
      placement: 'unverified',
      explanation: 'Blocked/timeout metadata had no attested probe I/O and cannot establish edge protection.',
      createsFinding: false,
      strengthen_hint: 'deploy_agent',
    };
  }

  if (expectedBehavior === 'must_block_before_origin') {
    if (blocked) {
      return {
        verdict: 'edge_protected',
        confidence: 'external_only',
        placement: 'unverified',
        explanation:
          'External-only probe was blocked at the edge; origin reachability not proven without an agent.',
        createsFinding: false,
        strengthen_hint: 'deploy_agent',
      };
    }
    if (connected) {
      return {
        verdict: 'edge_exposed',
        confidence: 'external_only',
        placement: 'unverified',
        explanation:
          'External-only probe reached the declared path; deploy an agent to confirm whether traffic reached origin.',
        createsFinding: true,
        severity: 'medium',
        strengthen_hint: 'deploy_agent',
      };
    }
  }

  return {
    verdict: 'inconclusive',
    confidence: 'external_only',
    placement: 'unverified',
    explanation: 'Insufficient external-only evidence.',
    createsFinding: false,
    strengthen_hint: 'deploy_agent',
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