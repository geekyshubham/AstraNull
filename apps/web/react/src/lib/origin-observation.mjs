// Mirrors src/lib/externalObservationOutcomes.mjs; a unit test keeps the labels in parity.
export const ORIGIN_OBSERVATION_LABELS = Object.freeze({
  response_observed: 'Origin response observed',
  application_identity_confirmed: 'Origin response observed; application identity confirmed',
  explicit_denial_observed: 'Control-specific denial signature observed',
  no_response: 'No response; enforcement unverified',
  transport_error: 'Transport error; enforcement unverified',
  not_tested: 'Not tested',
});

export const ORIGIN_OBSERVATION_GAP_LABELS = Object.freeze({
  misdirected_request: 'Misdirected request (HTTP 421); enforcement unverified',
  probe_path_error: 'Proxy error on the probe path (HTTP 407); not tested',
  not_applicable: 'CDN or WAF edge answered; not an origin observation',
});

const RESPONSE_REASON_LABELS = Object.freeze({
  authentication_challenge: 'Origin HTTP service reachable directly; authentication challenge observed',
  unattributed_denial: 'Origin HTTP service answered with a denial that matches no declared or vendor signature; lockdown unverified',
  generic_error_response: 'Origin answered with a server error; neither lockdown nor bypass',
});

const LEGACY_V1_VERSION = 'external-observation-v1';

const IDENTITY_METHOD_LABELS = Object.freeze({
  nonce_canary: 'Confirmed by nonce-bound canary echo',
  marker_echo: 'Confirmed by static marker echo',
});

const ALL_LABELS = Object.freeze({ ...ORIGIN_OBSERVATION_LABELS, ...ORIGIN_OBSERVATION_GAP_LABELS });

function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function knownOutcome(value) {
  return typeof value === 'string' && Object.hasOwn(ALL_LABELS, value) ? value : '';
}

export function originObservation(meta) {
  const value = record(record(meta)?.origin_observation);
  return value && knownOutcome(value.outcome) ? value : null;
}

function statusOnlyLegacyLabel(value) {
  const status = Number(value.status_code);
  if (status === 421) return ALL_LABELS.misdirected_request;
  if (status === 407) return ALL_LABELS.probe_path_error;
  if (status === 401) return RESPONSE_REASON_LABELS.authentication_challenge;
  if (status >= 500) return RESPONSE_REASON_LABELS.generic_error_response;
  if (status >= 400) return RESPONSE_REASON_LABELS.unattributed_denial;
  return '';
}

function currentLabel(value) {
  if (value.semantics_version === LEGACY_V1_VERSION && (value.outcome === 'explicit_denial_observed' || value.outcome === 'response_observed')) {
    const legacy = statusOnlyLegacyLabel(value);
    if (legacy) return legacy;
  }
  const reason = typeof value.response_reason === 'string' && Object.hasOwn(RESPONSE_REASON_LABELS, value.response_reason)
    ? value.response_reason
    : '';
  if (value.outcome === 'response_observed' && reason) return RESPONSE_REASON_LABELS[reason];
  return ALL_LABELS[value.outcome];
}

/** Customer label for a direct-origin leg; legacy results without the shared outcome stay unverified. */
export function originObservationLabel(meta, fallback = '—') {
  const value = originObservation(meta);
  if (value) return currentLabel(value);
  const direct = record(record(record(meta)?.network_firewall)?.direct_origin_reachability);
  const outcome = knownOutcome(direct?.outcome);
  if (outcome) return ALL_LABELS[outcome];
  if (record(meta) && ('bypass_signal' in meta || (meta.origin_bypass_status_code ?? null) !== null)) {
    return 'Recorded before current evidence semantics; retest required';
  }
  return fallback;
}

export function originIdentityLabel(meta) {
  const value = originObservation(meta);
  const identity = record(value?.application_identity);
  const method = typeof identity?.method === 'string' && Object.hasOwn(IDENTITY_METHOD_LABELS, identity.method)
    ? identity.method
    : '';
  if (identity?.confirmed === true && method) {
    if (value.application_bypass_confirmed === true) return IDENTITY_METHOD_LABELS[method];
    return value.baseline === 'unhealthy'
      ? `${IDENTITY_METHOD_LABELS[method]}; permitted-path baseline not healthy, bypass suspected`
      : `${IDENTITY_METHOD_LABELS[method]}; no permitted-path baseline captured, bypass suspected`;
  }
  if (value?.application_bypass_suspected === true) return 'Suspected from supporting signals only';
  return 'Not confirmed';
}
