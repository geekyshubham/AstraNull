// Shared outside-in observation semantics: status codes alone never establish enforcement; denial needs a control-specific signature.
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { classifyEdgeByAddress } from './edgeFingerprint.mjs';

export const EXTERNAL_OBSERVATION_SEMANTICS_VERSION = 'external-observation-v2';
export const LEGACY_EXTERNAL_OBSERVATION_SEMANTICS_VERSIONS = Object.freeze(['external-observation-v1']);

export const EXTERNAL_OBSERVATION_OUTCOMES = Object.freeze([
  'response_observed',
  'application_identity_confirmed',
  'explicit_denial_observed',
  'misdirected_request',
  'probe_path_error',
  'not_applicable',
  'no_response',
  'transport_error',
  'not_tested',
]);

/** Outcomes that carry no usable evidence: shown only as coverage gaps, never scored. */
export const EVIDENCE_GAP_OUTCOMES = Object.freeze([
  'misdirected_request',
  'probe_path_error',
  'not_applicable',
  'no_response',
  'transport_error',
  'not_tested',
]);

export const EXTERNAL_OBSERVATION_LABELS = Object.freeze({
  response_observed: 'Origin response observed',
  application_identity_confirmed: 'Origin response observed; application identity confirmed',
  explicit_denial_observed: 'Control-specific denial signature observed',
  misdirected_request: 'Misdirected request (HTTP 421); enforcement unverified',
  probe_path_error: 'Proxy error on the probe path (HTTP 407); not tested',
  not_applicable: 'CDN or WAF edge answered; not an origin observation',
  no_response: 'No response; enforcement unverified',
  transport_error: 'Transport error; enforcement unverified',
  not_tested: 'Not tested',
});

export const PATH_OBSERVATION_LABELS = Object.freeze({
  ...EXTERNAL_OBSERVATION_LABELS,
  response_observed: 'Response observed',
  application_identity_confirmed: 'Response observed; application identity confirmed',
  not_applicable: 'CDN or WAF edge answered; not a direct observation',
});

export const RESPONSE_REASONS = Object.freeze([
  'authentication_challenge',
  'unattributed_denial',
  'generic_error_response',
]);

export const CANARY_NONCE_REQUEST_HEADER = 'x-astranull-nonce';
export const CANARY_ECHO_RESPONSE_HEADER = 'x-astranull-canary-echo';
export const MARKER_ECHO_RESPONSE_HEADER = 'x-astranull-marker-echo';

const SUPPORTED_VERSIONS = new Set([EXTERNAL_OBSERVATION_SEMANTICS_VERSION, ...LEGACY_EXTERNAL_OBSERVATION_SEMANTICS_VERSIONS]);
const OUTCOME_SET = new Set(EXTERNAL_OBSERVATION_OUTCOMES);
const NO_RESPONSE_PATTERN = /abort|timeout|timedout|deadline/i;
const REFUSED_PATTERN = /ECONNREFUSED|ECONNRESET|connection_refused/i;
const MTLS_REJECTION_PATTERN = /certificate_required|ALERT_CERTIFICATE_REQUIRED|ALERT_HANDSHAKE_FAILURE|ALERT_BAD_CERTIFICATE|ALERT_UNKNOWN_CA/i;
const MAX_SIGNATURE_BODY = 8192;
const EDGE_ADDRESS_FAMILIES = new Set(['cdn', 'waf']);

/** Vendor block markers that name the control (G2); each needs more than a status code. */
const VENDOR_DENIAL_SIGNATURES = Object.freeze([
  {
    id: 'cloudflare_challenge',
    vendor: 'cloudflare',
    match: ({ header }) => (header('cf-mitigated') ?? '').toLowerCase() === 'challenge',
  },
  {
    id: 'cloudflare_block_page',
    vendor: 'cloudflare',
    match: ({ header, body }) => (/error code:?\s*(1020|100[6-9]|101[0-2])\b/i.test(body) || /attention required! \| cloudflare/i.test(body))
      && (Boolean(header('cf-ray')) || /cloudflare/i.test(body)),
  },
  {
    id: 'akamai_reference_18',
    vendor: 'akamai',
    match: ({ body }) => /access denied/i.test(body) && /reference\s*#18\.[0-9a-f]+/i.test(body),
  },
  {
    id: 'imperva_incident_id',
    vendor: 'imperva',
    match: ({ body }) => /incapsula incident id/i.test(body),
  },
  {
    id: 'aws_cloudfront_waf_block',
    vendor: 'aws',
    match: ({ status, header, body }) => status === 403 && Boolean(header('x-amz-cf-id')) && /request blocked/i.test(body),
  },
  {
    id: 'f5_asm_rejection',
    vendor: 'f5',
    match: ({ body }) => /the requested url was rejected/i.test(body) && /support id/i.test(body),
  },
]);

function headerGetter(source) {
  if (typeof source === 'function') return (name) => normalizeHeader(source(name));
  if (source?.headers?.get) return (name) => normalizeHeader(source.headers.get(name));
  return () => null;
}

function normalizeHeader(value) {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

function errorClassOf(error) {
  const value = String(error?.code ?? error?.name ?? '').trim();
  return value ? value.slice(0, 64) : 'transport_error';
}

function sha256Hex(text) {
  return createHash('sha256').update(String(text)).digest('hex');
}

/** A timeout or deadline is no response; every other failure is a transport error. */
export function classifyTransportFailure(error) {
  const signal = `${error?.name ?? ''} ${error?.code ?? ''}`;
  return NO_RESPONSE_PATTERN.test(signal) ? 'no_response' : 'transport_error';
}

/** `connection_refused` for RST/ECONNREFUSED; null for every other failure. */
export function transportFailureReason(error) {
  const signal = `${error?.name ?? ''} ${error?.code ?? ''}`;
  return REFUSED_PATTERN.test(signal) ? 'connection_refused' : null;
}

/** `healthy` only for a 2xx/3xx permitted-path response without a transport error or block signature. */
export function baselineHealth(baseline) {
  if (!baseline || typeof baseline !== 'object') return 'not_available';
  const status = Number(baseline.status_code);
  if (baseline.error_class || baseline.connection_dropped === true || !Number.isInteger(status)) return 'unhealthy';
  if (baseline.denial_signature) return 'unhealthy';
  return status >= 200 && status < 400 ? 'healthy' : 'unhealthy';
}

/** Customer-declared block or lockdown response: status plus body hash or header, matched exactly. */
export function matchDeclaredDenialSignature({ statusCode = null, headers = null, bodyText = null, declared = null } = {}) {
  if (!declared || typeof declared !== 'object') return null;
  const header = headerGetter(headers);
  if (Number.isInteger(declared.status_code) && declared.status_code !== statusCode) return null;
  const wantedHash = typeof declared.body_sha256 === 'string' ? declared.body_sha256.trim().toLowerCase() : '';
  const wantedHeader = declared.header && typeof declared.header.name === 'string' ? declared.header : null;
  if (!wantedHash && !wantedHeader) return null;
  if (wantedHash && (typeof bodyText !== 'string' || sha256Hex(bodyText) !== wantedHash)) return null;
  if (wantedHeader) {
    const observed = header(wantedHeader.name.toLowerCase());
    if (observed == null) return null;
    if (typeof wantedHeader.value === 'string' && observed !== wantedHeader.value.trim()) return null;
  }
  return { kind: 'declared', id: typeof declared.id === 'string' && declared.id ? declared.id.slice(0, 64) : 'declared_response', vendor: null };
}

/** Vendor block marker on one response, or null; a bare status code never matches. */
export function matchVendorDenialSignature({ statusCode = null, headers = null, bodyText = '' } = {}) {
  const header = headerGetter(headers);
  const body = String(bodyText ?? '').slice(0, MAX_SIGNATURE_BODY);
  for (const rule of VENDOR_DENIAL_SIGNATURES) {
    if (rule.match({ status: statusCode, header, body })) return { kind: 'vendor', id: rule.id, vendor: rule.vendor };
  }
  return null;
}

/** Declared signature first, then vendor markers. */
export function matchControlDenialSignature({ statusCode = null, headers = null, bodyText = '', declared = null } = {}) {
  return matchDeclaredDenialSignature({ statusCode, headers, bodyText, declared })
    ?? matchVendorDenialSignature({ statusCode, headers, bodyText });
}

/** CDN/WAF edge answered instead of the origin (G5): edge headers or a CDN/WAF address range. */
export function cdnEdgeSignal({ headers = null, directAddress = null } = {}) {
  const header = headerGetter(headers);
  const server = (header('server') ?? '').toLowerCase();
  if (server === 'cloudflare' && header('cf-ray')) return 'cloudflare_edge_headers';
  if (header('cf-mitigated')) return 'cloudflare_edge_headers';
  if (header('x-amz-cf-id')) return 'cloudfront_edge_headers';
  if (server.includes('akamaighost')) return 'akamai_edge_headers';
  if (header('x-iinfo')) return 'imperva_edge_headers';
  const address = String(directAddress ?? '').replace(/^\[|\]$/g, '').trim();
  if (address && isIP(address)) {
    const hit = classifyEdgeByAddress([address]).find((row) => EDGE_ADDRESS_FAMILIES.has(row.family));
    if (hit) return `${hit.family}_address_range:${hit.provider}`.slice(0, 64);
  }
  return null;
}

/** Outcome for an HTTP status with no control-specific signature. */
export function unsignedStatusOutcome(statusCode) {
  if (statusCode === 421) return { outcome: 'misdirected_request', response_reason: null };
  if (statusCode === 407) return { outcome: 'probe_path_error', response_reason: null };
  if (statusCode === 401) return { outcome: 'response_observed', response_reason: 'authentication_challenge' };
  if (statusCode >= 500) return { outcome: 'response_observed', response_reason: 'generic_error_response' };
  if (statusCode >= 400) return { outcome: 'response_observed', response_reason: 'unattributed_denial' };
  return { outcome: 'response_observed', response_reason: null };
}

function isDeclaredMtlsRejection({ error, statusCode, bodyText, declared }) {
  if (declared?.mtls !== true) return false;
  if (error) return MTLS_REJECTION_PATTERN.test(`${error?.code ?? ''} ${error?.name ?? ''} ${error?.message ?? ''}`);
  return statusCode === 400 && /no required ssl certificate was sent/i.test(String(bodyText ?? ''));
}

/** Classify one direct-origin request, scoped to the tested host/path/source/time. */
export function classifyDirectOriginObservation({
  attempted = true,
  response = null,
  error = null,
  bodyText = null,
  baseline = null,
  expectedNonce = null,
  expectedMarker = null,
  declaredLockdown = null,
  directAddress = null,
  scope = null,
  observedAt = null,
} = {}) {
  const baselineState = baselineHealth(baseline);
  const status = Number(response?.status);
  const statusCode = !error && Number.isInteger(status) && status >= 100 ? status : null;
  const limitations = ['scoped_to_tested_host_path_source_time', 'responsible_control_not_identified'];
  if (baselineState === 'not_available') limitations.push('baseline_not_available');
  if (baselineState === 'unhealthy') limitations.push('baseline_unhealthy');

  let outcome;
  let identityMethod = null;
  let denialSignature = null;
  let responseReason = null;
  let errorReason = null;
  let edgeSignal = null;
  const supportingSignals = [];
  if (attempted && !error && statusCode != null) edgeSignal = cdnEdgeSignal({ headers: response, directAddress });
  if (!attempted) outcome = 'not_tested';
  else if (error && isDeclaredMtlsRejection({ error, declared: declaredLockdown })) {
    outcome = 'explicit_denial_observed';
    denialSignature = { kind: 'declared', id: 'declared_mtls_rejection', vendor: null };
  } else if (error) {
    outcome = classifyTransportFailure(error);
    if (outcome === 'transport_error') errorReason = transportFailureReason(error);
  } else if (statusCode == null) outcome = 'transport_error';
  else if (edgeSignal) outcome = 'not_applicable';
  else {
    denialSignature = isDeclaredMtlsRejection({ statusCode, bodyText, declared: declaredLockdown })
      ? { kind: 'declared', id: 'declared_mtls_rejection', vendor: null }
      : matchControlDenialSignature({ statusCode, headers: response, bodyText, declared: declaredLockdown });
    if (denialSignature) outcome = 'explicit_denial_observed';
    else {
      const unsigned = unsignedStatusOutcome(statusCode);
      outcome = unsigned.outcome;
      responseReason = unsigned.response_reason;
    }
  }

  if (outcome === 'response_observed') {
    const success = statusCode >= 200 && statusCode < 400;
    const nonce = typeof expectedNonce === 'string' ? expectedNonce.trim() : '';
    const marker = typeof expectedMarker === 'string' ? expectedMarker.trim() : '';
    if (success && nonce && headerGetter(response)(CANARY_ECHO_RESPONSE_HEADER) === nonce) {
      identityMethod = 'nonce_canary';
    } else if (success && marker && headerGetter(response)(MARKER_ECHO_RESPONSE_HEADER) === marker) {
      identityMethod = 'marker_echo';
      limitations.push('marker_echo_not_nonce_bound');
    }
    const originServer = headerGetter(response)('server');
    const baselineServer = typeof baseline?.server_header === 'string' ? baseline.server_header.trim() : '';
    if (success && originServer && baselineServer && originServer === baselineServer) {
      supportingSignals.push('server_header_match');
    }
    if (responseReason) limitations.push(responseReason);
    if (identityMethod) outcome = 'application_identity_confirmed';
  }

  if (outcome === 'no_response' || outcome === 'transport_error') {
    limitations.push('silence_or_transport_failure_does_not_establish_enforcement');
  }
  if (outcome === 'misdirected_request') limitations.push('retry_with_matching_sni_required');
  if (outcome === 'probe_path_error') limitations.push('proxy_between_probe_and_target');
  if (outcome === 'not_applicable') limitations.push('cdn_edge_ip');
  if (supportingSignals.length > 0) limitations.push('header_similarity_is_supporting_only');

  const responseObserved = outcome === 'response_observed'
    || outcome === 'application_identity_confirmed'
    || outcome === 'explicit_denial_observed';
  const applicationBypassConfirmed = outcome === 'application_identity_confirmed'
    && identityMethod === 'nonce_canary'
    && baselineState === 'healthy';
  const success2xx3xx = statusCode != null && statusCode >= 200 && statusCode < 400;
  const applicationBypassSuspected = !applicationBypassConfirmed && success2xx3xx
    && (outcome === 'application_identity_confirmed' || (outcome === 'response_observed' && supportingSignals.length > 0));
  const originLockdownConfirmed = outcome === 'explicit_denial_observed'
    && denialSignature?.kind === 'declared'
    && baselineState === 'healthy';

  return {
    semantics_version: EXTERNAL_OBSERVATION_SEMANTICS_VERSION,
    outcome,
    label: EXTERNAL_OBSERVATION_LABELS[outcome],
    status_code: statusCode,
    ...(error ? { error_class: errorClassOf(error) } : {}),
    ...(errorReason ? { error_reason: errorReason } : {}),
    response_reason: responseReason,
    denial_signature: denialSignature,
    ...(outcome === 'not_applicable' ? { not_applicable_reason: 'cdn_edge_ip', edge_signal: edgeSignal } : {}),
    response_observed: responseObserved,
    explicit_denial_observed: outcome === 'explicit_denial_observed',
    baseline: baselineState,
    application_identity: { confirmed: identityMethod != null, method: identityMethod },
    supporting_signals: supportingSignals,
    application_bypass_confirmed: applicationBypassConfirmed,
    application_bypass_suspected: applicationBypassSuspected,
    origin_lockdown_confirmed: originLockdownConfirmed,
    control_identified: false,
    scope: {
      host: typeof scope?.host === 'string' ? scope.host.slice(0, 253) : null,
      path: typeof scope?.path === 'string' ? scope.path.slice(0, 256) : '/',
      port: Number.isInteger(scope?.port) ? scope.port : null,
    },
    observed_at: typeof observedAt === 'string' ? observedAt : null,
    limitations,
  };
}

/** Legacy v1 records denied on status alone; re-read them under current status semantics without editing the record. */
function reinterpretLegacy(value) {
  if (value.outcome !== 'explicit_denial_observed' && !(value.outcome === 'response_observed' && Number(value.status_code) >= 400)) {
    return { ...value, denial_signature: null, response_reason: value.response_reason ?? null, legacy_semantics: true };
  }
  const statusCode = Number.isInteger(value.status_code) ? value.status_code : null;
  const unsigned = statusCode == null ? { outcome: 'transport_error', response_reason: null } : unsignedStatusOutcome(statusCode);
  const limitations = [...(Array.isArray(value.limitations) ? value.limitations : [])];
  if (value.outcome === 'explicit_denial_observed') limitations.push('legacy_status_only_denial_reclassified');
  if (unsigned.response_reason && !limitations.includes(unsigned.response_reason)) limitations.push(unsigned.response_reason);
  return {
    ...value,
    outcome: unsigned.outcome,
    label: EXTERNAL_OBSERVATION_LABELS[unsigned.outcome],
    response_reason: unsigned.response_reason,
    denial_signature: null,
    response_observed: unsigned.outcome === 'response_observed',
    explicit_denial_observed: false,
    origin_lockdown_confirmed: false,
    legacy_semantics: true,
    limitations,
  };
}

/** The recorded origin observation on probe metadata under current semantics, or null. */
export function originObservationOf(metadata) {
  const value = metadata?.origin_observation;
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  if (!SUPPORTED_VERSIONS.has(value.semantics_version)) return null;
  if (!OUTCOME_SET.has(value.outcome)) return null;
  return value.semantics_version === EXTERNAL_OBSERVATION_SEMANTICS_VERSION ? value : reinterpretLegacy(value);
}

/** Origin lockdown only from a declared lockdown signature with a healthy baseline, never from a status code or silence. */
export function metadataConfirmsOriginLockdown(metadata) {
  const observation = originObservationOf(metadata);
  return Boolean(
    metadata?.origin_lockdown_confirmed === true
    && observation
    && observation.outcome === 'explicit_denial_observed'
    && observation.denial_signature?.kind === 'declared'
    && observation.baseline === 'healthy'
    && observation.origin_lockdown_confirmed === true,
  );
}

/** Application bypass only from confirmed application identity, never from header similarity. */
export function metadataConfirmsApplicationBypass(metadata) {
  const observation = originObservationOf(metadata);
  return Boolean(
    observation
    && observation.outcome === 'application_identity_confirmed'
    && observation.application_bypass_confirmed === true
    && observation.application_identity?.confirmed === true
    && observation.application_identity?.method === 'nonce_canary'
    && observation.baseline === 'healthy',
  );
}

/** Direct-origin status: a signed denial is denied; 2xx/3xx/401 is exposed; unattributed 4xx, 5xx, silence and errors stay inconclusive. */
export function directOriginStatusFor(observation) {
  if (!observation || observation.outcome === 'not_tested') return 'not_tested';
  if (observation.outcome === 'explicit_denial_observed') return observation.denial_signature ? 'denied' : 'inconclusive';
  if (observation.outcome === 'response_observed' || observation.outcome === 'application_identity_confirmed') {
    const reason = observation.response_reason ?? null;
    return reason === 'unattributed_denial' || reason === 'generic_error_response' ? 'inconclusive' : 'exposed';
  }
  return 'inconclusive';
}

export function externalObservationLabel(outcome, { originPath = true } = {}) {
  const labels = originPath ? EXTERNAL_OBSERVATION_LABELS : PATH_OBSERVATION_LABELS;
  return labels[outcome] ?? labels.not_tested;
}
