import { maxProbeRequestsForKind } from '../contracts/checks.mjs';
import { minimumProbeRequestsForKind } from './capabilityProbes.mjs';
import {
  initialDestinationResolverAttemptsForJob,
  maxDestinationResolverAttemptsForJob,
} from './probeJobs.mjs';
import { redactObject } from './redact.mjs';

const DEFAULT_MAX_REQUESTS = 1;
const DEFAULT_TIMEOUT_CAP_MS = 5000;

// Hard-timeout callbacks can run late under scheduler/event-loop pressure. This bounded
// duration-only tolerance never raises a probe, resolver, or total-operation cap.
export const HARD_TIMEOUT_SCHEDULER_TOLERANCE_FIXED_MS = 5;
export const HARD_TIMEOUT_SCHEDULER_TOLERANCE_RATIO = 0.02;
export const HARD_TIMEOUT_SCHEDULER_TOLERANCE_MAX_MS = 50;

export function hardTimeoutSchedulerToleranceMs(timeoutMs) {
  const timeout = Number(timeoutMs);
  if (!Number.isSafeInteger(timeout) || timeout < 0) return 0;
  return Math.min(
    HARD_TIMEOUT_SCHEDULER_TOLERANCE_MAX_MS,
    Math.max(
      HARD_TIMEOUT_SCHEDULER_TOLERANCE_FIXED_MS,
      Math.ceil(timeout * HARD_TIMEOUT_SCHEDULER_TOLERANCE_RATIO),
    ),
  );
}

export const RAW_PACKET_FIELD_DENYLIST = new Set([
  'packet_payload',
  'raw_packet',
  'raw_packets',
  'packets',
  'packet_data',
  'raw_payload',
  'payload',
  'body',
  'headers',
  'request_body',
  'request_headers',
  'authorization',
  'cookie',
  'raw_log',
  'log_line',
]);
const RAW_PACKET_FIELD_COMPACT_DENYLIST = new Set(
  [...RAW_PACKET_FIELD_DENYLIST].map((key) => key.replace(/_/g, '')),
);

export const ALLOWED_EXTERNAL_RESULTS = new Set(['blocked', 'connected', 'timeout', 'error', 'not_run']);

const ALLOWED_ATTESTATION_META_KEYS = new Set(['worker_version', 'region', 'completed_at']);

export const PROBE_EVENT_RESERVED_METADATA_KEYS = new Set([
  'external_result',
  'probe_worker_id',
  'safety_attestation',
  'profile_kind',
  'probe_kind',
  'probe_profile_kind',
  'request_accounting',
  'request_counting_basis',
  'probe_logical_attempts',
  'probe_requests_sent',
  'destination_vetting_resolver_attempts',
  'destination_resolver_attempts',
  'total_operations',
]);

function objectContainsRawPacketFields(value) {
  const normalizeKey = (key) => String(key)
    .trim()
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
  const scan = (node) => {
    if (node == null) return false;
    if (Array.isArray(node)) {
      for (const item of node) {
        if (scan(item)) return true;
      }
      return false;
    }
    if (typeof node !== 'object') return false;
    for (const key of Object.keys(node)) {
      const normalized = normalizeKey(key);
      const compact = normalized.replace(/_/g, '');
      if (
        RAW_PACKET_FIELD_DENYLIST.has(normalized)
        || RAW_PACKET_FIELD_COMPACT_DENYLIST.has(compact)
        || normalized.startsWith('raw_')
        || compact.startsWith('raw')
      ) {
        return true;
      }
      if (scan(node[key])) return true;
    }
    return false;
  };
  return scan(value);
}

export function bodyContainsRawPacketFields(body) {
  if (!body || typeof body !== 'object') return false;
  return objectContainsRawPacketFields(body);
}

function sanitizeSafetyAttestation(attestation) {
  const out = {
    requests_sent: attestation.requests_sent,
    duration_ms: attestation.duration_ms,
  };
  for (const key of [
    'probe_requests_sent',
    'destination_resolver_attempts',
    'total_operations',
    ...ALLOWED_ATTESTATION_META_KEYS,
  ]) {
    if (attestation[key] != null) out[key] = attestation[key];
  }
  return out;
}

export function validateSafetyAttestation(
  body,
  constraints,
  { probeKind, probeProfile, target } = {},
) {
  const attestation = body?.safety_attestation ?? body?.execution_summary;
  if (attestation == null) {
    return {
      ok: false,
      error: 'missing_safety_attestation',
      status: 400,
      message: 'Probe results must include safety_attestation (or execution_summary).',
    };
  }
  if (typeof attestation !== 'object' || Array.isArray(attestation)) {
    return {
      ok: false,
      error: 'invalid_safety_attestation',
      status: 400,
      message: 'safety_attestation must be an object with exact operation counts and duration_ms.',
    };
  }
  if (bodyContainsRawPacketFields(attestation)) {
    return {
      ok: false,
      error: 'invalid_safety_attestation',
      status: 400,
      message: 'safety_attestation must not contain raw packet or payload fields.',
    };
  }
  const { requests_sent: requestsSent, duration_ms: durationMs } = attestation;
  if (!Number.isSafeInteger(requestsSent) || requestsSent < 0) {
    return {
      ok: false,
      error: 'invalid_safety_attestation',
      status: 400,
      message: 'safety_attestation.requests_sent must be a non-negative safe integer.',
    };
  }
  if (!Number.isSafeInteger(durationMs) || durationMs < 0) {
    return {
      ok: false,
      error: 'invalid_safety_attestation',
      status: 400,
      message: 'safety_attestation.duration_ms must be a non-negative safe integer.',
    };
  }

  const accountingFields = [
    'probe_requests_sent',
    'destination_resolver_attempts',
    'total_operations',
  ];
  const providedAccountingFields = accountingFields.filter((field) =>
    Object.prototype.hasOwnProperty.call(attestation, field));
  if (providedAccountingFields.length !== 0
    && providedAccountingFields.length !== accountingFields.length) {
    return {
      ok: false,
      error: 'invalid_safety_attestation',
      status: 400,
      message: 'safety_attestation operation accounting must include all split and total counts.',
    };
  }

  let probeRequestsSent = requestsSent;
  let destinationResolverAttempts = 0;
  let totalOperations = requestsSent;
  if (providedAccountingFields.length === accountingFields.length) {
    probeRequestsSent = attestation.probe_requests_sent;
    destinationResolverAttempts = attestation.destination_resolver_attempts;
    totalOperations = attestation.total_operations;
    if ([probeRequestsSent, destinationResolverAttempts, totalOperations]
      .some((value) => !Number.isSafeInteger(value) || value < 0)) {
      return {
        ok: false,
        error: 'invalid_safety_attestation',
        status: 400,
        message: 'safety_attestation operation counts must be non-negative safe integers.',
      };
    }
    if (
      requestsSent !== totalOperations
      || totalOperations !== probeRequestsSent + destinationResolverAttempts
    ) {
      return {
        ok: false,
        error: 'invalid_safety_attestation',
        status: 400,
        message: 'safety_attestation operation counts are not coherent.',
      };
    }
  }
  if (
    (totalOperations > 0 && durationMs === 0)
    || (durationMs === 0 && !['error', 'not_run'].includes(body?.external_result))
  ) {
    return {
      ok: false,
      error: 'invalid_safety_attestation',
      status: 400,
      message: 'duration_ms must be positive after I/O; zero is valid only for no-I/O error/not_run.',
    };
  }

  const signedCapFields = [
    'max_probe_requests',
    'min_destination_resolver_attempts',
    'max_destination_resolver_attempts',
    'max_total_operations',
  ];
  const providedCapFields = signedCapFields.filter((field) =>
    Object.prototype.hasOwnProperty.call(constraints, field));
  if (providedCapFields.length !== 0 && providedCapFields.length !== signedCapFields.length) {
    return {
      ok: false,
      error: 'invalid_signed_operation_caps',
      status: 422,
      message: 'Signed job operation caps are incomplete.',
    };
  }
  if (
    providedCapFields.length === signedCapFields.length
    && providedAccountingFields.length !== accountingFields.length
  ) {
    return {
      ok: false,
      error: 'invalid_safety_attestation',
      status: 400,
      message: 'safety_attestation must include exact split accounting for this signed job.',
    };
  }

  const signedMaxRequests = constraints.max_requests ?? DEFAULT_MAX_REQUESTS;
  let probeCap = signedMaxRequests;
  let destinationResolverFloor = 0;
  let destinationResolverCap = 0;
  let totalOperationCap = signedMaxRequests;
  if (providedCapFields.length === signedCapFields.length) {
    probeCap = constraints.max_probe_requests;
    destinationResolverFloor = constraints.min_destination_resolver_attempts;
    destinationResolverCap = constraints.max_destination_resolver_attempts;
    totalOperationCap = constraints.max_total_operations;
    if ([probeCap, destinationResolverFloor, destinationResolverCap, totalOperationCap]
      .some((value) => !Number.isSafeInteger(value) || value < 0)
      || destinationResolverFloor > destinationResolverCap
      || signedMaxRequests !== totalOperationCap
      || totalOperationCap !== probeCap + destinationResolverCap) {
      return {
        ok: false,
        error: 'invalid_signed_operation_caps',
        status: 422,
        message: 'Signed job operation caps are not coherent.',
      };
    }
  } else {
    if (!Number.isSafeInteger(signedMaxRequests) || signedMaxRequests < 0) {
      return {
        ok: false,
        error: 'invalid_signed_operation_caps',
        status: 422,
        message: 'Signed job max_requests must be a non-negative safe integer.',
      };
    }
    // Legacy results did not expose resolver/probe split accounting. If a new worker
    // supplies the split for an old job, enforce the bounded inferred resolver allowance;
    // otherwise validate only the historically observable legacy probe count.
    if (providedAccountingFields.length === accountingFields.length) {
      const legacyProfile = probeProfile ?? (probeKind ? { kind: probeKind } : null);
      destinationResolverFloor = initialDestinationResolverAttemptsForJob(
        legacyProfile,
        target,
      );
      destinationResolverCap = maxDestinationResolverAttemptsForJob(legacyProfile, target);
      totalOperationCap = signedMaxRequests + destinationResolverCap;
    }
  }

  const profileProbeCap = probeProfile?.max_requests;
  if (
    profileProbeCap != null
    && (
      !Number.isSafeInteger(profileProbeCap)
      || profileProbeCap < 0
      || probeCap > profileProbeCap
    )
  ) {
    return {
      ok: false,
      error: 'invalid_signed_operation_caps',
      status: 422,
      message: 'Signed job probe cap exceeds probe_profile.max_requests.',
    };
  }

  const kindCap = probeKind ? maxProbeRequestsForKind(probeKind) : probeCap;
  const maxProbeRequests = Math.min(probeCap, kindCap);
  const timeoutMs = constraints.timeout_ms ?? DEFAULT_TIMEOUT_CAP_MS;
  const hasExactSplitAccounting = providedAccountingFields.length === accountingFields.length;
  const resolverDeadlineError = body?.external_result === 'error'
    && hasExactSplitAccounting
    && probeRequestsSent === 0
    && destinationResolverAttempts > 0
    && ['probe_job_deadline_exceeded', 'probe_destination_dns_timeout']
      .includes(body?.metadata?.error_class);
  const timerDrivenResult = body?.external_result === 'timeout' || body?.external_result === 'blocked';
  const timeoutToleranceMs = timerDrivenResult || resolverDeadlineError
    ? hardTimeoutSchedulerToleranceMs(timeoutMs)
    : 0;
  const durationCap = Math.min(Number.MAX_SAFE_INTEGER, timeoutMs + timeoutToleranceMs);
  let minProbeRequests = 0;
  if (body?.external_result === 'connected') {
    minProbeRequests = minimumProbeRequestsForKind(probeKind);
  } else if (body?.external_result === 'blocked' || body?.external_result === 'timeout') {
    minProbeRequests = Math.min(1, minimumProbeRequestsForKind(probeKind));
  }
  const minDestinationResolverAttempts = ['error', 'not_run'].includes(body?.external_result)
    ? 0
    : destinationResolverFloor;
  if (
    probeRequestsSent < minProbeRequests
    || probeRequestsSent > maxProbeRequests
    || destinationResolverAttempts < minDestinationResolverAttempts
    || destinationResolverAttempts > destinationResolverCap
    || totalOperations > totalOperationCap
    || durationMs > durationCap
  ) {
    return {
      ok: false,
      error: 'safety_attestation_exceeded',
      status: 422,
      message: 'safety_attestation violates a signed probe, resolver, total-operation, or duration bound.',
    };
  }
  return { ok: true, sanitized: sanitizeSafetyAttestation(attestation) };
}

export function sanitizeWorkerProbeMetadata(metadata) {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    return {};
  }
  const stripped = {};
  for (const [key, val] of Object.entries(metadata)) {
    if (!PROBE_EVENT_RESERVED_METADATA_KEYS.has(key)) {
      stripped[key] = val;
    }
  }
  return redactObject(stripped);
}

export function validateProbeResultBody(
  body,
  constraints,
  { probeKind, probeProfile, target } = {},
) {
  if (bodyContainsRawPacketFields(body)) {
    return {
      error: 'raw_packet_rejected',
      status: 400,
      message: 'Raw packet or payload fields are not accepted.',
    };
  }

  const externalResult = body?.external_result;
  if (!externalResult || !ALLOWED_EXTERNAL_RESULTS.has(externalResult)) {
    return {
      error: 'invalid_external_result',
      status: 400,
      message: 'external_result must be one of: blocked, connected, timeout, error, not_run.',
    };
  }

  const resolvedProbeKind = probeKind ?? body?.metadata?.probe_kind ?? body?.metadata?.profile_kind ?? null;
  const attestationResult = validateSafetyAttestation(body, constraints ?? {}, {
    probeKind: resolvedProbeKind,
    probeProfile,
    target,
  });
  if (!attestationResult.ok) {
    return {
      error: attestationResult.error,
      status: attestationResult.status,
      message: attestationResult.message,
    };
  }

  return {
    ok: true,
    externalResult,
    safetyAttestation: attestationResult.sanitized,
    workerMetadata: sanitizeWorkerProbeMetadata(body.metadata),
  };
}
