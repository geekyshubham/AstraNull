import {
  OBSERVATION_ONLY_PROBE_KINDS,
  verdictSupportsReadiness,
} from '../lib/readinessVerdicts.mjs';

export { OBSERVATION_ONLY_PROBE_KINDS, verdictSupportsReadiness };
import { inconclusiveReason } from '../lib/inconclusiveReasons.mjs';
import { originObservationOf } from '../lib/externalObservationOutcomes.mjs';

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

function correlateProbeFailure(externalResult, probeKind, metadata) {
  const knownKindTimedOut = externalResult === 'timeout' && typeof probeKind === 'string';
  if (!['error', 'not_run'].includes(externalResult) && !knownKindTimedOut) return null;
  const reason = inconclusiveReason({ externalResult, probeKind, metadata });
  return {
    verdict: 'inconclusive',
    confidence: 'external_only',
    explanation: reason.explanation,
    createsFinding: false,
  };
}

const IDENTITY_METHOD_LABELS = Object.freeze({
  nonce_canary: 'a nonce-bound canary echo',
  marker_echo: 'a static marker echo',
});

function statusPhrase(observation) {
  return Number.isInteger(observation?.status_code) ? ` (HTTP ${observation.status_code})` : '';
}

function directOriginIdentityPhrase(observation) {
  const method = IDENTITY_METHOD_LABELS[observation?.application_identity?.method] ?? null;
  if (method && observation?.application_bypass_confirmed === true) {
    return `application identity was confirmed by ${method} over a healthy permitted-path baseline.`;
  }
  if (method) {
    return `${method} matched, but no healthy permitted-path baseline was captured, so an application bypass remains suspected rather than confirmed.`;
  }
  if (observation?.application_bypass_suspected === true) {
    return 'supporting signals such as a shared Server header suggest the application, but application identity was not confirmed.';
  }
  return 'application identity was not confirmed.';
}

function observationConfirmsLockdown(observation) {
  return observation?.origin_lockdown_confirmed === true
    && observation.baseline === 'healthy'
    && observation.denial_signature?.kind === 'declared';
}

const EVIDENCE_GAP_EXPLANATIONS = Object.freeze({
  misdirected_request: 'The direct-origin request received HTTP 421 (misdirected request). That reflects how the probe connection was routed, not a control decision, so the result is a coverage gap and is ignored for verdicts. Retest on a fresh connection whose SNI matches the Host.',
  probe_path_error: 'The direct-origin request received HTTP 407, meaning a proxy sits between the probe and the target. This is a probe-path problem, so the result is a coverage gap and is ignored for verdicts.',
  not_applicable: 'A CDN or WAF edge answered the direct-origin request, so it is not an origin observation. The result is ignored for verdicts; declare a non-edge origin address to test origin lockdown.',
});

const MARKER_GAP_EXPLANATIONS = Object.freeze({
  authentication_gate_precedes_inspection: 'The marker request received HTTP 401. An authentication gate answered before any inspection could be observed, so a WAF block cannot be told apart from the login challenge. The result is ignored for verdicts.',
  unattributed_denial: 'The marker request was denied without a vendor or customer-declared block signature. A block is suspected but not attributed, so it counts neither as enforcement nor as a gap.',
  baseline_not_available: 'The marker request was denied without a vendor or customer-declared block signature and no permitted baseline was captured, so the result is ignored for verdicts.',
  misdirected_request: 'The marker request received HTTP 421 (misdirected request), a connection-routing artifact. The result is ignored for verdicts.',
  probe_path_error: 'The marker request received HTTP 407 from a proxy on the probe path. The result is ignored for verdicts.',
  error_not_attributable: 'The marker request received a server error. A 5xx cannot be attributed to a control and may be an application failure, so the result is ignored for verdicts.',
});

function evidenceGapVerdict(explanation) {
  return { verdict: 'inconclusive', confidence: 'external_only', explanation, createsFinding: false };
}

// Direct-origin verdicts follow the shared observation outcome; bare status codes, silence, and legacy results never pass.
function correlateDirectOriginVerdict({ blocked, connected, probeMetadata }) {
  const observation = originObservationOf(probeMetadata);
  const responded = observation?.outcome === 'response_observed' || observation?.outcome === 'application_identity_confirmed';
  if (blocked && !responded) {
    if (observation?.outcome === 'explicit_denial_observed' && observationConfirmsLockdown(observation)) {
      return {
        verdict: 'edge_protected',
        confidence: 'external_only',
        explanation: `The direct-origin request for the tested host and path received the customer-declared lockdown response${statusPhrase(observation)} from this probe source at the recorded time while the permitted path was healthy. The responsible rule is not identified, and origin lockdown beyond this request is not established.`,
        createsFinding: false,
      };
    }
    if (observation?.outcome === 'explicit_denial_observed') {
      const declared = observation.denial_signature?.kind === 'declared';
      return {
        verdict: 'inconclusive',
        confidence: 'external_only',
        explanation: declared
          ? `The direct-origin request for the tested host and path received the declared lockdown response${statusPhrase(observation)}, but no healthy permitted-path baseline was captured, so origin lockdown is not confirmed and no protection credit is given.`
          : `The direct-origin request for the tested host and path received a vendor block signature${statusPhrase(observation)}, but only a customer-declared lockdown response confirms origin lockdown, so no protection credit is given.`,
        createsFinding: false,
      };
    }
    return evidenceGapVerdict('No response; enforcement unverified. A refusal, timeout, transport error, or result without a control-specific denial signature cannot establish protection. Run a retest with the current check version.');
  }
  if (connected || responded) {
    const reason = observation?.response_reason ?? null;
    if (reason === 'unattributed_denial') {
      return evidenceGapVerdict(`The direct-origin request for the tested host and path was denied${statusPhrase(observation)}, so an HTTP service answered on the direct path, but the response matched no declared lockdown or vendor signature. Origin lockdown stays unconfirmed; declare the expected lockdown response to evaluate it.`);
    }
    if (reason === 'generic_error_response') {
      return evidenceGapVerdict(`The direct-origin request for the tested host and path received a server error${statusPhrase(observation)}. A 5xx is neither lockdown nor bypass evidence.`);
    }
    if (reason === 'authentication_challenge') {
      return {
        verdict: 'edge_exposed',
        confidence: 'external_only',
        explanation: `Origin HTTP service reachable directly; authentication challenge observed${statusPhrase(observation)} for the tested host and path from this probe source at the recorded time. An authentication challenge is not origin lockdown, so exposure is suspected; ${directOriginIdentityPhrase(observation)}`,
        createsFinding: true,
        severity: 'low',
      };
    }
    return {
      verdict: 'edge_exposed',
      confidence: 'external_only',
      explanation: `Origin response observed${statusPhrase(observation)} on the direct path for the tested host and path, so the direct path is reachable from this probe source at the recorded time; ${directOriginIdentityPhrase(observation)}`,
      createsFinding: true,
      severity: 'medium',
    };
  }
  return evidenceGapVerdict('Insufficient external probe evidence for a definitive verdict.');
}

/** G4: results without usable evidence are coverage gaps with a reason code, never pass, fail, or partial. */
function correlateEvidenceGap(probeKind, probeMetadata) {
  if (probeKind === 'host_sni_bypass') {
    const outcome = originObservationOf(probeMetadata)?.outcome;
    return EVIDENCE_GAP_EXPLANATIONS[outcome] ? evidenceGapVerdict(EVIDENCE_GAP_EXPLANATIONS[outcome]) : null;
  }
  const reason = probeMetadata?.inconclusive_reason;
  return typeof reason === 'string' && MARKER_GAP_EXPLANATIONS[reason] ? evidenceGapVerdict(MARKER_GAP_EXPLANATIONS[reason]) : null;
}

const WEB_SERVICE_PORTS = new Set([80, 443]);

/** A completed TLS handshake is a TLS-profile observation, never an edge block. */
function correlateTlsProfileVerdict(externalResult, metadata = {}) {
  const protocol = typeof metadata.tls_protocol === 'string' ? metadata.tls_protocol : '';
  if (!protocol || metadata.error_class) return null;
  const issues = Array.isArray(metadata.tls_issues) ? metadata.tls_issues.filter((row) => typeof row === 'string') : [];
  if (externalResult === 'blocked' && issues.length === 0) {
    return {
      verdict: 'protected',
      confidence: 'external_only',
      explanation: `The TLS handshake completed with ${protocol} and an authorized certificate chain. This is a TLS profile observation; it says nothing about edge blocking.`,
      createsFinding: false,
    };
  }
  if (externalResult === 'connected' && issues.length > 0) {
    return {
      verdict: 'exposed',
      confidence: 'external_only',
      explanation: `The TLS handshake completed with ${protocol} and these profile issues: ${issues.join(', ')}.`,
      createsFinding: true,
      severity: 'medium',
    };
  }
  return null;
}

/** Open ports limited to 80/443 are the expected web service, not a firewall exposure. */
function correlateWebServicePortsOnly(metadata = {}) {
  if (!Array.isArray(metadata.open_ports)) return null;
  const open = metadata.open_ports.filter((port) => Number.isInteger(port));
  if (!open.length || open.some((port) => !WEB_SERVICE_PORTS.has(port))) return null;
  return {
    verdict: 'allowed_as_expected',
    confidence: 'external_only',
    explanation: `Only web service ports answered (${open.join(', ')}); no admin or data-service port in the bounded scan was reachable.`,
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
  probeMetadata = {},
}) {
  if (isObservationOnlyProbeKind(probeKind)) {
    return correlateObservationOnlyVerdict(probeKind);
  }

  const evidenceGap = correlateEvidenceGap(probeKind, probeMetadata);
  if (evidenceGap) return evidenceGap;

  const probeFailure = correlateProbeFailure(externalResult, probeKind, probeMetadata);
  if (probeFailure) return probeFailure;

  if (probeKind === 'dnssec_posture' && probeMetadata.assurance === 'authoritative_dnskey_presence_only') {
    const count = probeMetadata.dnskey_count;
    const configured = probeMetadata.dnssec_configured;
    if (probeIoObserved === true && Number.isSafeInteger(count) && count >= 0
      && configured === (count > 0) && externalResult === (configured ? 'blocked' : 'connected')) {
      return {
        verdict: configured ? 'protected' : 'exposed', confidence: 'external_only',
        explanation: configured
          ? 'An authoritative DNS response contained DNSKEY records. This confirms key presence only; delegation-chain validity and DDoS resilience were not tested.'
          : 'An authoritative DNS response contained no DNSKEY records for the declared zone. Delegation-chain validity and DDoS resilience were not tested.',
        createsFinding: !configured,
        ...(!configured ? { severity: 'medium' } : {}),
      };
    }
    return { verdict: 'inconclusive', confidence: 'external_only', explanation: 'DNSKEY presence metadata was incomplete or inconsistent with the attested query result.', createsFinding: false };
  }

  if (probeKind === 'tls_audit' && probeIoObserved === true) {
    const tlsVerdict = correlateTlsProfileVerdict(externalResult, probeMetadata);
    if (tlsVerdict) return tlsVerdict;
  }

  const blocked = externalResult === 'blocked' || externalResult === 'timeout';
  const connected = externalResult === 'connected' || externalResult === 'allowed';

  if (probeKind === 'port_scan_bounded' && connected && probeIoObserved === true) {
    const webOnly = correlateWebServicePortsOnly(probeMetadata);
    if (webOnly) return webOnly;
  }

  if (blocked && probeIoObserved !== true) {
    return {
      verdict: 'inconclusive',
      confidence: 'external_only',
      explanation: 'Blocked/timeout metadata had no attested probe I/O and cannot establish edge protection.',
      createsFinding: false,
    };
  }

  if (probeKind === 'host_sni_bypass' && expectedBehavior === 'must_block_before_origin') {
    return correlateDirectOriginVerdict({ blocked, connected, probeMetadata });
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
