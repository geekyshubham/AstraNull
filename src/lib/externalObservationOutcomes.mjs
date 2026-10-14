// Shared outside-in observation semantics: status codes alone never establish enforcement; denial needs a control-specific signature.
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { classifyEdgeByAddress } from './edgeFingerprint.mjs';

export const EXTERNAL_OBSERVATION_SEMANTICS_VERSION = 'external-observation-v3';
export const LEGACY_EXTERNAL_OBSERVATION_SEMANTICS_VERSIONS = Object.freeze(['external-observation-v1', 'external-observation-v2']);

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

export const WAF_GRADING_VERSION = 'waf-grading.v2';
export const SIGNATURE_CORPUS_VERSION = 'waf-signatures.2026-10-13.2';
export const WAF_RESPONSE_OUTCOMES = Object.freeze([
  'blocked', 'challenged', 'allowed', 'redirected', 'inconclusive', 'error',
]);
export const WAF_CHALLENGED_OUTCOME = 'challenged';

const SUPPORTED_VERSIONS = new Set([EXTERNAL_OBSERVATION_SEMANTICS_VERSION, ...LEGACY_EXTERNAL_OBSERVATION_SEMANTICS_VERSIONS]);
const OUTCOME_SET = new Set(EXTERNAL_OBSERVATION_OUTCOMES);
const NO_RESPONSE_PATTERN = /abort|timeout|timedout|deadline/i;
const REFUSED_PATTERN = /ECONNREFUSED|ECONNRESET|connection_refused/i;
const MTLS_REJECTION_PATTERN = /certificate_required|ALERT_CERTIFICATE_REQUIRED|ALERT_HANDSHAKE_FAILURE|ALERT_BAD_CERTIFICATE|ALERT_UNKNOWN_CA/i;
const MAX_SIGNATURE_BODY = 8192;
const EDGE_ADDRESS_FAMILIES = new Set(['cdn', 'waf']);

/** Vendor block markers that name the control (G2); `match` needs a WAF-specific anchor, `suspect` is generic proxy/CDN evidence only. */
export const VENDOR_DENIAL_SIGNATURES = Object.freeze([
  {
    id: 'cloudflare_challenge',
    vendor: 'cloudflare',
    challenge: true,
    live_verified: true,
    match: ({ header }) => (header('cf-mitigated') ?? '').toLowerCase() === 'challenge',
  },
  {
    id: 'cloudflare_js_challenge',
    vendor: 'cloudflare',
    challenge: true,
    live_verified: true,
    match: ({ header, body }) => Boolean(header('cf-ray'))
      && /cdn-cgi\/challenge-platform|cf-browser-verification|_cf_chl_|just a moment[\s\S]{0,80}cloudflare|enable javascript and cookies to continue/i.test(body),
  },
  {
    id: 'cloudflare_block_page',
    vendor: 'cloudflare',
    live_verified: true,
    match: ({ header, body }) => (/error code:?\s*(1020|100[6-9]|101[0-2])\b/i.test(body) || /attention required! \| cloudflare/i.test(body))
      && (Boolean(header('cf-ray')) || /cloudflare/i.test(body)),
  },
  {
    id: 'captcha_interstitial',
    vendor: null,
    challenge: true,
    live_verified: false,
    match: ({ body }) => /verify (?:that )?you are human|complete the captcha to continue|checking your browser before/i.test(body)
      && /recaptcha|h-?captcha|g-recaptcha|cf-turnstile/i.test(body),
  },
  {
    id: 'akamai_reference_18',
    vendor: 'akamai',
    live_verified: true,
    match: ({ body }) => /access denied/i.test(body) && /reference\s*#18\.[0-9a-f]+/i.test(body),
  },
  {
    id: 'imperva_incident_id',
    vendor: 'imperva',
    live_verified: true,
    match: ({ body }) => /incapsula incident id/i.test(body),
  },
  {
    id: 'aws_cloudfront_waf_block',
    vendor: 'aws',
    live_verified: true,
    match: ({ status, header, body }) => status === 403 && Boolean(header('x-amz-cf-id')) && /request blocked/i.test(body),
  },
  {
    id: 'aws_alb_waf_block',
    vendor: 'aws',
    live_verified: false,
    match: ({ status, header, body }) => status === 403 && /awselb\/2\.0/i.test(header('server') ?? '')
      && /request blocked by aws waf/i.test(body),
    suspect: ({ status, header }) => status === 403 && /awselb\/2\.0/i.test(header('server') ?? ''),
  },
  {
    id: 'aws_apigateway_waf_block',
    vendor: 'aws',
    live_verified: false,
    match: ({ status, body }) => status === 403 && /request blocked by aws waf/i.test(body),
    suspect: ({ status, header, body }) => status === 403 && (
      /forbiddenexception/i.test(header('x-amzn-errortype') ?? '')
      || (Boolean(header('x-amzn-requestid')) && /forbidden/i.test(body))
    ),
  },
  {
    id: 'gcp_cloud_armor_block',
    vendor: 'google',
    live_verified: false,
    match: ({ status, header, body }) => status === 403 && /1\.1 google/i.test(header('via') ?? '')
      && /cloud armor/i.test(body),
    suspect: ({ status, header }) => status === 403 && /1\.1 google/i.test(header('via') ?? ''),
  },
  {
    id: 'azure_frontdoor_waf_block',
    vendor: 'azure',
    live_verified: false,
    match: ({ status, body }) => status === 403
      && /azure (?:front door|application gateway)[\s\S]{0,80}(blocked|denied|waf)/i.test(body),
    suspect: ({ status, header }) => status === 403 && (
      Boolean(header('x-azure-ref'))
      || /microsoft-azure-application-gateway/i.test(header('server') ?? '')
    ),
  },
  {
    id: 'fastly_ngwaf_block',
    vendor: 'fastly',
    live_verified: false,
    match: ({ status, body }) => status === 406 && /fastly next-gen waf|signal sciences|sigsci/i.test(body),
    suspect: ({ status, header }) => status === 406 && (
      Boolean(header('x-served-by')) || /fastly/i.test(header('server') ?? '') || Boolean(header('x-timer'))
    ),
  },
  {
    id: 'modsecurity_default_block',
    vendor: 'modsecurity',
    live_verified: false,
    match: ({ status, body }) => status === 403 && /this error was generated by mod_security|coraza waf/i.test(body),
    suspect: ({ status, header }) => status === 403 && /mod_?security|coraza/i.test(header('server') ?? ''),
  },
  {
    id: 'f5_asm_rejection',
    vendor: 'f5',
    live_verified: true,
    match: ({ body }) => /the requested url was rejected/i.test(body) && /support id/i.test(body),
  },
]);

export function headerGetter(source) {
  if (typeof source === 'function') return (name) => normalizeHeader(source(name));
  if (typeof source?.headers?.get === 'function') return (name) => normalizeHeader(source.headers.get(name));
  if (typeof source?.get === 'function') return (name) => normalizeHeader(source.get(name));
  if (source && typeof source === 'object') {
    const headersObj = source.headers && typeof source.headers === 'object' && !Array.isArray(source.headers)
      ? source.headers
      : source;
    const lowerMap = new Map();
    for (const [k, v] of Object.entries(headersObj)) {
      if (typeof k === 'string') lowerMap.set(k.toLowerCase(), v);
    }
    return (name) => {
      if (typeof name !== 'string') return null;
      return normalizeHeader(lowerMap.get(name.toLowerCase()));
    };
  }
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

function declaredHeaderSpec(declared) {
  if (typeof declared.header_name === 'string' && declared.header_name.trim()) {
    return { name: declared.header_name, value: declared.header_value };
  }
  if (declared.header && typeof declared.header.name === 'string') return declared.header;
  return null;
}

function declaredStatusMatches(declared, statusCode) {
  if (Array.isArray(declared.status_codes) && declared.status_codes.length > 0) {
    return declared.status_codes.some((code) => Number.isInteger(code) && code === statusCode);
  }
  if (Number.isInteger(declared.status_code)) return declared.status_code === statusCode;
  return true;
}

// Compute deterministic digest of customer-declared denial signature specification.
export function computeDeclaredSignatureDigest(declared) {
  if (!declared || typeof declared !== 'object') return null;
  const wantedHash = typeof declared.body_sha256 === 'string' ? declared.body_sha256.trim().toLowerCase() : '';
  const wantedHeader = declaredHeaderSpec(declared);
  if (!wantedHash && !wantedHeader) return null;
  const statusCodes = Array.isArray(declared.status_codes)
    ? [...declared.status_codes].filter((c) => Number.isInteger(c)).sort((a, b) => a - b)
    : (Number.isInteger(declared.status_code) ? [declared.status_code] : []);
  const payload = {
    header_name: wantedHeader ? String(wantedHeader.name).trim().toLowerCase() : '',
    header_value: wantedHeader ? String(wantedHeader.value ?? '').trim() : '',
    body_sha256: wantedHash,
    status_codes: statusCodes,
  };
  return sha256Hex(JSON.stringify(payload));
}

// Customer-declared block or lockdown response: status plus body hash or header, matched exactly.
export function matchDeclaredDenialSignature({ statusCode = null, headers = null, bodyText = null, declared = null, bodyComplete = false } = {}) {
  if (!declared || typeof declared !== 'object') return null;
  const header = headerGetter(headers);
  if (!declaredStatusMatches(declared, statusCode)) return null;
  const wantedHash = typeof declared.body_sha256 === 'string' ? declared.body_sha256.trim().toLowerCase() : '';
  const wantedHeader = declaredHeaderSpec(declared);
  if (!wantedHash && !wantedHeader) return null;
  if (wantedHash && (bodyComplete !== true || !/^[a-f0-9]{64}$/.test(wantedHash) || typeof bodyText !== 'string' || sha256Hex(bodyText) !== wantedHash)) return null;
  if (wantedHeader) {
    const observed = header(String(wantedHeader.name).toLowerCase());
    if (observed == null || typeof wantedHeader.value !== 'string' || !wantedHeader.value.trim()) return null;
    if (observed !== wantedHeader.value.trim()) return null;
  }
  const basis = wantedHeader ? 'declared_header' : 'declared_body';
  const declaration_digest = computeDeclaredSignatureDigest(declared);
  return {
    kind: 'declared',
    id: typeof declared.id === 'string' && declared.id ? declared.id.slice(0, 64) : 'declared_response',
    vendor: null,
    basis,
    declaration_digest,
  };
}

/** Vendor block marker on one response, or null; a bare status code or a generic proxy/CDN header never matches. */
export function matchVendorDenialSignature({ statusCode = null, headers = null, bodyText = '' } = {}) {
  const header = headerGetter(headers);
  const body = String(bodyText ?? '').slice(0, MAX_SIGNATURE_BODY);
  for (const rule of VENDOR_DENIAL_SIGNATURES) {
    if (rule.match({ status: statusCode, header, body })) {
      return {
        kind: 'vendor',
        id: rule.id,
        vendor: rule.vendor,
        ...(rule.challenge === true ? { challenge: true } : {}),
      };
    }
  }
  return null;
}

/** Unverified vendor rule matched only on generic proxy/CDN headers plus a denial status: a suspected block, never a block. */
export function matchSuspectedVendorSignature({ statusCode = null, headers = null, bodyText = '' } = {}) {
  if (matchVendorDenialSignature({ statusCode, headers, bodyText })) return null;
  const header = headerGetter(headers);
  const body = String(bodyText ?? '').slice(0, MAX_SIGNATURE_BODY);
  for (const rule of VENDOR_DENIAL_SIGNATURES) {
    if (rule.live_verified !== true && typeof rule.suspect === 'function' && rule.suspect({ status: statusCode, header, body })) {
      return { kind: 'vendor_suspected', id: rule.id, vendor: rule.vendor, live_verified: false };
    }
  }
  return null;
}

export const BLOCK_SUSPECTED_UNVERIFIED_SIGNATURE = 'block_suspected_unverified_signature';

/** Declared signature first, then vendor markers. */
export function matchControlDenialSignature({ statusCode = null, headers = null, bodyText = '', declared = null, bodyComplete = false } = {}) {
  return matchDeclaredDenialSignature({ statusCode, headers, bodyText, declared, bodyComplete })
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
    const hits = classifyEdgeByAddress([address]);
    if (!hits.some((row) => row.family === 'cloud')) {
      const hit = hits.find((row) => EDGE_ADDRESS_FAMILIES.has(row.family));
      if (hit) return `${hit.family}_address_range:${hit.provider}`.slice(0, 64);
    }
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

/** Independent permitted-path identity must match exact method, scope, source, scenario and freshness. */
export function originBaselineComparable({ baseline, scope, expectedNonce, observedAt } = {}) {
  if (baselineHealth(baseline) !== 'healthy' || typeof expectedNonce !== 'string' || !expectedNonce) return false;
  const prior = baseline?.scope;
  if (!prior || !scope || !['host', 'path', 'method', 'scenario_version', 'source_perspective', 'worker_id'].every(
    (key) => typeof scope[key] === 'string' && scope[key] && prior[key] === scope[key],
  )) return false;
  if (!Number.isInteger(scope.port) || prior.port !== scope.port) return false;
  const age = Date.parse(observedAt) - Date.parse(baseline.observed_at);
  return Number.isFinite(age) && age >= 0 && age <= 60000
    && baseline.application_identity?.confirmed === true
    && baseline.application_identity?.method === 'nonce_canary'
    && baseline.canary_echo === expectedNonce;
}

/** Classify one direct-origin request, scoped to the tested host/path/source/time. */
export function classifyDirectOriginObservation({
  attempted = true,
  response = null,
  error = null,
  bodyText = null,
  bodyComplete = false,
  baseline = null,
  expectedNonce = null,
  expectedMarker = null,
  declaredLockdown = null,
  directAddress = null,
  scope = null,
  observedAt = null,
} = {}) {
  const baselineState = baselineHealth(baseline);
  const baselineComparable = originBaselineComparable({ baseline, scope, expectedNonce, observedAt });
  const status = Number(response?.status);
  const statusCode = !error && Number.isInteger(status) && status >= 100 ? status : null;
  const limitations = ['scoped_to_tested_host_path_source_time', 'responsible_control_not_identified'];
  if (baselineState === 'not_available') limitations.push('baseline_not_available');
  if (baselineState === 'unhealthy') limitations.push('baseline_unhealthy');
  if (baselineState === 'healthy' && !baselineComparable) limitations.push('baseline_identity_scope_source_or_freshness_not_comparable');

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
      : matchControlDenialSignature({ statusCode, headers: response, bodyText, declared: declaredLockdown, bodyComplete });
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
    && baselineState === 'healthy' && baselineComparable;
  const success2xx3xx = statusCode != null && statusCode >= 200 && statusCode < 400;
  const applicationBypassSuspected = !applicationBypassConfirmed && success2xx3xx
    && (outcome === 'application_identity_confirmed' || (outcome === 'response_observed' && supportingSignals.length > 0));
  const originLockdownConfirmed = outcome === 'explicit_denial_observed'
    && denialSignature?.kind === 'declared'
    && baselineState === 'healthy' && baselineComparable;

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
    baseline_comparable: baselineComparable,
    readiness_conclusion: applicationBypassConfirmed || originLockdownConfirmed,
    observation_only: !applicationBypassConfirmed && !originLockdownConfirmed,
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
      method: typeof scope?.method === 'string' ? scope.method : null,
      scenario_version: typeof scope?.scenario_version === 'string' ? scope.scenario_version : null,
      source_perspective: typeof scope?.source_perspective === 'string' ? scope.source_perspective : null,
      worker_id: typeof scope?.worker_id === 'string' ? scope.worker_id : null,
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
  if (value.semantics_version === EXTERNAL_OBSERVATION_SEMANTICS_VERSION) return value;
  const legacy = value.semantics_version === 'external-observation-v1' ? reinterpretLegacy(value) : { ...value, legacy_semantics: true };
  return { ...legacy, application_bypass_confirmed: false, origin_lockdown_confirmed: false,
    baseline_comparable: false, observation_only: true, readiness_conclusion: false,
    limitations: [...(legacy.limitations ?? []), 'legacy_baseline_identity_or_completeness_unverified'] };
}

/** Origin lockdown only from a declared lockdown signature with a healthy baseline, never from a status code or silence. */
export function metadataConfirmsOriginLockdown(metadata) {
  const observation = originObservationOf(metadata);
  return Boolean(
    metadata?.origin_lockdown_confirmed === true
    && observation
    && observation.outcome === 'explicit_denial_observed'
    && observation.denial_signature?.kind === 'declared'
    && observation.baseline_comparable === true
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
    && observation.baseline_comparable === true
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
