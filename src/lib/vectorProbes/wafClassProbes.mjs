/**
 * WAF attack-class marker probes — bounded, outside-in, inert-marker-only.
 * Extends the outsideInWafScanner benign-marker pattern to additional WAF attack
 * families (SSRF, XXE, deserialization, request smuggling, NoSQL, JWT, SSTI,
 * open redirect, CRLF, prototype pollution, XPath, CSV/formula, LDAP/JNDI, file
 * upload, HTTP method policy). Every marker is an INERT detection string: a WAF
 * rule matches it, but it achieves nothing if it reaches the origin. No working
 * exploit, real SSRF target, functional gadget, or state-changing action exists
 * in this module. One probe kind, hard-bounded at 8 requests, no rate/count knob.
 */

import {
  BENIGN_CLASS_MARKERS,
  isBlockedOrChallenged,
  markerBaselineHealth,
  markerDenialSignature,
  markerResponseSnapshot,
  readSignatureBody,
} from '../outsideInWafScanner.mjs';
import { CANARY_ECHO_RESPONSE_HEADER, CANARY_NONCE_REQUEST_HEADER } from '../externalObservationOutcomes.mjs';
import { blockedBaselinePrerequisite } from './evasionProbes.mjs';

export const WAF_CLASS_MARKER_PROBE_KIND = 'waf_class_marker_probe';

/** Hard request ceiling for this probe kind. No rate/count/repeat parameter exists. */
export const WAF_CLASS_PROBE_MAX_REQUESTS = 8;

/** Every marker embeds this sentinel so a downstream reader can prove it is a probe. */
export const BENIGN_MARKER_SENTINEL = 'astranull';

function base64Url(value) {
  return Buffer.from(value, 'utf8').toString('base64')
    .replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

const INERT_JWT = (() => {
  const header = base64Url('{"alg":"none","astranull":"p"}');
  const payload = base64Url('{"astranull":"jwt-inert"}');
  return `${header}.${payload}.astranull-jwt-inert`;
})();

/**
 * Inert WAF-class markers. Each is a detection string a WAF rule flags; none is a
 * working exploit. URL-bearing markers point only at the RFC-6761 `.invalid` sink,
 * which never resolves. Operator/signature tokens (`$ne`, `${jndi:`, `<!DOCTYPE`,
 * `__proto__`) are carried as plain strings that match nothing and mutate nothing.
 */
export const WAF_CLASS_MARKERS = Object.freeze({
  ...BENIGN_CLASS_MARKERS,
  ssrf: 'http://astranull-ssrf-probe.invalid/marker',
  xxe: '<!DOCTYPE astranull [<!ENTITY astranullXxeProbe SYSTEM "http://astranull-xxe-probe.invalid/e">]>',
  deserialization: 'rO0ABQ-astranull-deser-probe-INERT',
  request_smuggling: 'astranull-smuggle-probe-CL0TE-inert',
  nosql: '$ne:astranull-nosql-probe-inert',
  jwt_tamper: INERT_JWT,
  ssti: '{{astranull-ssti-probe-inert}}',
  open_redirect: '//astranull-open-redirect-probe.invalid/',
  crlf: 'astranull-crlf-probe%0d%0aX-Astranull-Probe:inert',
  prototype_pollution: '__proto__.astranull_proto_probe_inert',
  xpath: "astranull-xpath-probe' and '1'='0",
  csv_injection: '=astranull_csv_probe_inert',
  ldap: '${jndi:ldap://astranull-jndi-probe.invalid/a}',
  file_upload_marker: 'astranull-upload-probe.php.txt',
  http_method_policy: 'astranull-method-policy-probe-TRACK-inert',
  session_marker: 'astranull-session-probe-inert',
  cors_marker: 'https://astranull-cors-probe.invalid',
});

/** Marker classes this probe kind understands. */
export const WAF_MARKER_CLASSES = Object.freeze(Object.keys(WAF_CLASS_MARKERS));

/** Subset that maps to gradeable outside-in E3 checks (see waf-class.manifest.mjs). */
export const WAF_E3_MARKER_CLASSES = Object.freeze([
  'http_method_policy',
  'request_smuggling',
  'crlf',
  'open_redirect',
  'nosql',
  'xpath',
  'ldap',
  'csv_injection',
  'prototype_pollution',
  'deserialization',
  'ssrf',
  'xxe',
  'file_upload_marker',
  'jwt_tamper',
]);

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_HEADERS = Object.freeze({
  accept: 'text/html,application/xhtml+xml',
  'accept-language': 'en-US,en;q=0.9',
});

/**
 * Substrings that would betray a working payload rather than an inert marker.
 * Used by the module's own guard and by the unit tests to assert inertness.
 */
export const FORBIDDEN_PAYLOAD_SIGNATURES = Object.freeze([
  '169.254.169.254',
  'metadata.google',
  'system(',
  'exec(',
  'passthru(',
  'sleep(',
  'file:///etc/passwd',
  'runtime.exec',
  'objectinputstream',
  'ping -c',
  ' && ',
  '| bash',
]);

/** True iff the marker embeds the benign sentinel and no working-payload signature. */
export function isInertMarker(marker) {
  const text = String(marker ?? '').toLowerCase();
  if (!text.includes(BENIGN_MARKER_SENTINEL)) return false;
  return !FORBIDDEN_PAYLOAD_SIGNATURES.some((sig) => text.includes(sig.toLowerCase()));
}

export function markerForClass(markerClass) {
  return WAF_CLASS_MARKERS[markerClass] ?? null;
}

/**
 * Build a bounded probe profile for one marker class. max_requests is clamped to
 * WAF_CLASS_PROBE_MAX_REQUESTS; there is no rate, concurrency, or repeat field.
 */
export function buildWafClassProbeProfile({ marker_class, max_requests, timeout_ms, entry_path_scenario } = {}) {
  if (!WAF_MARKER_CLASSES.includes(marker_class)) {
    throw new Error(`unknown waf marker_class: ${marker_class}`);
  }
  if (entry_path_scenario != null && !ENTRY_PATH_SCENARIOS.includes(entry_path_scenario)) {
    throw new Error(`unknown entry_path_scenario: ${entry_path_scenario}`);
  }
  const requested = Number.isInteger(max_requests) && max_requests > 0 ? max_requests : WAF_CLASS_PROBE_MAX_REQUESTS;
  const cappedTimeout = Number.isInteger(timeout_ms) && timeout_ms > 0
    ? Math.min(timeout_ms, DEFAULT_TIMEOUT_MS)
    : DEFAULT_TIMEOUT_MS;
  return Object.freeze({
    kind: WAF_CLASS_MARKER_PROBE_KIND,
    max_requests: Math.min(requested, WAF_CLASS_PROBE_MAX_REQUESTS),
    timeout_ms: cappedTimeout,
    marker_class,
    marker: String(WAF_CLASS_MARKERS[marker_class]).slice(0, 128),
    scenario_family: 'marker',
    expected_action: 'block',
    nonce_hash_only: true,
    collect: ['status_code', 'marker_probes', 'posture_status'],
    ...(entry_path_scenario ? { entry_path_scenario } : {}),
  });
}

function buildProbeUrl(baseUrl, markerClass, marker, placement) {
  const url = new URL(baseUrl);
  if (placement === 'path') {
    const joined = `${url.pathname.replace(/\/$/, '')}/${marker}`.replace(/\/+/g, '/');
    url.pathname = joined.startsWith('/') ? joined : `/${joined}`;
    return url.href;
  }
  url.searchParams.set(`astranull_${markerClass}_probe`, marker);
  return url.href;
}

/**
 * Run a bounded marker probe: one baseline request, then the marker placed in a
 * query parameter, path segment, and a benign header — capped at 8 requests total,
 * grading each with the shared isBlockedOrChallenged logic. Network access is fully
 * injectable via `fetchFn`; no real socket is opened in tests.
 */
export async function runWafClassMarkerProbe(options = {}) {
  if (options.entry_path_scenario != null) return runEntryPathMarkerProbe(options);
  const url = String(options.url ?? '').trim();
  const markerClass = options.marker_class;
  if (!url) return { error_class: 'unsupported_target', requests_sent: 0, phases: [] };
  if (!WAF_MARKER_CLASSES.includes(markerClass)) {
    return { error_class: 'unknown_marker_class', requests_sent: 0, phases: [] };
  }
  const marker = WAF_CLASS_MARKERS[markerClass];
  if (!isInertMarker(marker)) {
    return { error_class: 'non_inert_marker_blocked', requests_sent: 0, phases: [] };
  }

  const timeoutMs = Number.isInteger(options.timeout_ms) && options.timeout_ms > 0
    ? Math.min(options.timeout_ms, DEFAULT_TIMEOUT_MS)
    : DEFAULT_TIMEOUT_MS;
  const fetchFn = options.fetchFn;
  if (typeof fetchFn !== 'function') {
    return { error_class: 'no_transport', requests_sent: 0, phases: [] };
  }

  const maxRequests = Math.min(
    Number.isInteger(options.max_requests) && options.max_requests > 0
      ? options.max_requests
      : WAF_CLASS_PROBE_MAX_REQUESTS,
    WAF_CLASS_PROBE_MAX_REQUESTS,
  );
  const declared = options.declared_block_signature ?? null;
  const grade = (requestUrl, headers) => fetchGrade(fetchFn, requestUrl, headers, timeoutMs, 'GET', null, declared);
  const placements = [
    { phase: 'baseline', request: () => grade(url, { ...DEFAULT_HEADERS }) },
    { phase: 'query_marker', request: () => grade(buildProbeUrl(url, markerClass, marker, 'query'), { ...DEFAULT_HEADERS }) },
    { phase: 'path_marker', request: () => grade(buildProbeUrl(url, markerClass, marker, 'path'), { ...DEFAULT_HEADERS }) },
    { phase: 'header_marker', request: () => grade(url, { ...DEFAULT_HEADERS, 'x-astranull-marker': marker }) },
  ];

  const phases = [];
  const markerResults = [];
  let requestsSent = 0;
  let baseline = null;

  for (const step of placements) {
    if (requestsSent >= maxRequests) break;
    requestsSent += 1;
    const snapshot = await step.request();
    phases.push({ phase: step.phase, status_code: snapshot.status_code });
    if (snapshot.transport_error) break;
    if (step.phase === 'baseline') {
      baseline = snapshot;
      continue;
    }
    const verdict = isBlockedOrChallenged(snapshot, baseline);
    markerResults.push({ phase: step.phase, ...verdict, status_code: snapshot.status_code });
  }

  const anyAllowed = markerResults.some((r) => r.allowed === true);
  const anyBlocked = markerResults.some((r) => r.blocked === true);
  let posture = 'inconclusive';
  if (markerResults.length > 0) {
    if (anyAllowed) posture = 'exposed';
    else if (anyBlocked) posture = 'protected';
  }

  return {
    marker_class: markerClass,
    marker_inert: true,
    requests_sent: requestsSent,
    max_requests: maxRequests,
    posture,
    blocked_count: markerResults.filter((r) => r.blocked).length,
    allowed_count: markerResults.filter((r) => r.allowed).length,
    phases,
    marker_results: markerResults,
  };
}

function canaryEchoMatches(res, expectedNonce) {
  if (!expectedNonce || !res?.headers) return false;
  const value = typeof res.headers.get === 'function'
    ? res.headers.get(CANARY_ECHO_RESPONSE_HEADER)
    : res.headers[CANARY_ECHO_RESPONSE_HEADER];
  return typeof value === 'string' && value.trim() === expectedNonce;
}

async function fetchGrade(fetchFn, requestUrl, headers, timeoutMs, method = 'GET', expectedNonce = null, declared = null) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const safeMethod = ENTRY_PATH_SAFE_METHODS.includes(method) ? method : 'GET';
  try {
    const res = await fetchFn(requestUrl, {
      method: safeMethod,
      headers: expectedNonce ? { ...headers, [CANARY_NONCE_REQUEST_HEADER]: expectedNonce } : headers,
      redirect: 'manual',
      signal: controller.signal,
    });
    if (!res || !Number.isInteger(res.status)) return { ...markerResponseSnapshot(null), transport_error: true };
    const snapshot = markerResponseSnapshot(res, await readSignatureBody(res, safeMethod), declared);
    return expectedNonce ? { ...snapshot, canary_echo_matched: canaryEchoMatches(res, expectedNonce) } : snapshot;
  } catch {
    return { ...markerResponseSnapshot(null), transport_error: true };
  } finally {
    clearTimeout(timer);
  }
}

export const ENTRY_PATH_SCENARIOS = Object.freeze(['declared_login_path', 'declared_api_path']);

/** Only safe, non-state-changing methods; no request body is ever sent. */
export const ENTRY_PATH_SAFE_METHODS = Object.freeze(['GET', 'HEAD']);

export const ENTRY_PATH_QUERY_PADDING_BYTES = 2048;
export const ENTRY_PATH_HEADER_PADDING_BYTES = 4096;

const ENTRY_PATH_VARIATIONS = Object.freeze({
  declared_login_path: Object.freeze([
    Object.freeze({ variation: 'query_marker', method: 'GET', where: 'query', encoding: 'plain' }),
    Object.freeze({ variation: 'query_marker_percent_encoded', method: 'GET', where: 'query', encoding: 'percent', reference: 'query_marker' }),
    Object.freeze({ variation: 'header_marker', method: 'HEAD', where: 'header', encoding: 'plain' }),
    Object.freeze({ variation: 'query_marker_form_content_type', method: 'GET', where: 'query', encoding: 'plain', content_type: 'application/x-www-form-urlencoded', reference: 'query_marker' }),
    Object.freeze({ variation: 'query_marker_after_padding', method: 'GET', where: 'query', encoding: 'plain', padding_bytes: ENTRY_PATH_QUERY_PADDING_BYTES, reference: 'query_marker' }),
    Object.freeze({ variation: 'header_marker_after_padding', method: 'HEAD', where: 'header', encoding: 'plain', padding_bytes: ENTRY_PATH_HEADER_PADDING_BYTES, reference: 'header_marker' }),
  ]),
  declared_api_path: Object.freeze([
    Object.freeze({ variation: 'query_marker', method: 'GET', where: 'query', encoding: 'plain', accept: 'application/json' }),
    Object.freeze({ variation: 'query_marker_double_encoded', method: 'GET', where: 'query', encoding: 'double_percent', accept: 'application/json', reference: 'query_marker' }),
    Object.freeze({ variation: 'header_marker', method: 'HEAD', where: 'header', encoding: 'plain', accept: 'application/json' }),
    Object.freeze({ variation: 'query_marker_json_content_type', method: 'GET', where: 'query', encoding: 'plain', content_type: 'application/json', accept: 'application/json', reference: 'query_marker' }),
    Object.freeze({ variation: 'query_marker_after_padding', method: 'GET', where: 'query', encoding: 'plain', padding_bytes: ENTRY_PATH_QUERY_PADDING_BYTES, accept: 'application/json', reference: 'query_marker' }),
    Object.freeze({ variation: 'header_marker_after_padding', method: 'HEAD', where: 'header', encoding: 'plain', padding_bytes: ENTRY_PATH_HEADER_PADDING_BYTES, accept: 'application/json', reference: 'header_marker' }),
  ]),
});

/** Bounded variation plan for a declared login or API path; pure and network-free. */
export function entryPathVariations(scenario) {
  return ENTRY_PATH_VARIATIONS[scenario] ?? null;
}

function percentEncodeEveryByte(value) {
  return [...Buffer.from(value, 'utf8')].map((byte) => `%${byte.toString(16).toUpperCase().padStart(2, '0')}`).join('');
}

function encodeMarker(marker, encoding) {
  if (encoding === 'percent') return percentEncodeEveryByte(marker);
  if (encoding === 'double_percent') return encodeURIComponent(encodeURIComponent(marker));
  return marker;
}

/** Marker lands only in a query parameter or benign header; signed host, port, and path never change. */
export function buildEntryPathRequest(baseUrl, markerClass, variation) {
  if (!variation || !ENTRY_PATH_SAFE_METHODS.includes(variation.method)) {
    throw new Error('entry-path variations only use safe methods');
  }
  const marker = WAF_CLASS_MARKERS[markerClass];
  if (!isInertMarker(marker)) throw new Error(`non-inert or unknown marker class: ${markerClass}`);
  const url = new URL(baseUrl);
  const headers = {
    ...DEFAULT_HEADERS,
    ...(variation.accept ? { accept: variation.accept } : {}),
    ...(variation.content_type ? { 'content-type': variation.content_type } : {}),
  };
  const padding = Number.isInteger(variation.padding_bytes) ? 'a'.repeat(variation.padding_bytes) : null;
  const value = encodeMarker(marker, variation.encoding);
  if (variation.where === 'query') {
    const params = new URLSearchParams(url.search);
    if (padding) params.set('astranull_pad', padding);
    const encoded = variation.encoding === 'plain' ? encodeURIComponent(value) : value;
    const prefix = params.toString();
    url.search = `${prefix ? `${prefix}&` : ''}astranull_${markerClass}_probe=${encoded}`;
  } else {
    if (padding) headers['x-astranull-padding'] = padding;
    headers['x-astranull-marker'] = value;
  }
  return { url: url.href, method: variation.method, headers };
}

function enforcementFromResults(results) {
  const graded = results.filter((row) => !row.inconclusive && !row.error_class);
  const blocked = graded.filter((row) => row.blocked).length;
  const allowed = graded.filter((row) => row.allowed).length;
  if (blocked + allowed === 0) return 'unknown';
  if (allowed === 0) return 'enforced';
  if (blocked === 0) return 'not_enforced';
  return 'partial';
}

function referenceBlocked(row) {
  if (!row || row.inconclusive || row.error_class) return null;
  if (row.blocked === true) return true;
  return row.allowed === true ? false : null;
}

/** Evasion and inspection-limit variants grade only after their plain reference marker was blocked. */
export function gateEntryPathVariation(graded, variation, resultsByVariation) {
  if (!variation?.reference) return { ...graded };
  const prerequisite = blockedBaselinePrerequisite(referenceBlocked(resultsByVariation.get(variation.reference)));
  const gate = { reference_variation: variation.reference, blocked_baseline_prerequisite: prerequisite };
  if (prerequisite === 'met') return { ...graded, ...gate };
  return { ...graded, blocked: false, challenged: false, allowed: false, inconclusive: true, ...gate };
}

function baselineSignature(snapshot) {
  if (!snapshot || snapshot.transport_error) return null;
  const signature = markerDenialSignature(snapshot, null);
  if (!signature) return null;
  const { challenge: _challenge, ...denial } = signature;
  return denial;
}

/** Declared login/API scenario: permitted baseline then safe-method marker variations; no body, no redirects, max 8. */
export async function runEntryPathMarkerProbe(options = {}) {
  const url = String(options.url ?? '').trim();
  const scenario = options.entry_path_scenario;
  const markerClass = options.marker_class ?? 'sqli';
  const variations = entryPathVariations(scenario);
  if (!url) return { error_class: 'unsupported_target', requests_sent: 0, phases: [] };
  if (!variations) return { error_class: 'unknown_entry_path_scenario', requests_sent: 0, phases: [] };
  if (!WAF_MARKER_CLASSES.includes(markerClass)) return { error_class: 'unknown_marker_class', requests_sent: 0, phases: [] };
  if (!isInertMarker(WAF_CLASS_MARKERS[markerClass])) return { error_class: 'non_inert_marker_blocked', requests_sent: 0, phases: [] };
  const fetchFn = options.fetchFn;
  if (typeof fetchFn !== 'function') return { error_class: 'no_transport', requests_sent: 0, phases: [] };
  const timeoutMs = Number.isInteger(options.timeout_ms) && options.timeout_ms > 0
    ? Math.min(options.timeout_ms, DEFAULT_TIMEOUT_MS)
    : DEFAULT_TIMEOUT_MS;
  const maxRequests = Math.min(
    Number.isInteger(options.max_requests) && options.max_requests > 0 ? options.max_requests : WAF_CLASS_PROBE_MAX_REQUESTS,
    WAF_CLASS_PROBE_MAX_REQUESTS,
  );

  const phases = [];
  const markerResults = [];
  const resultsByVariation = new Map();
  const baselines = {};
  let requestsSent = 0;
  const declared = options.declared_block_signature ?? null;
  const expectedNonce = typeof options.expected_nonce === 'string' && options.expected_nonce.trim()
    ? options.expected_nonce.trim()
    : null;
  const baselineFor = async (method) => {
    if (!baselines[method]) {
      requestsSent += 1;
      baselines[method] = await fetchGrade(fetchFn, url, { ...DEFAULT_HEADERS }, timeoutMs, method, method === 'GET' ? expectedNonce : null, declared);
      phases.push({ phase: method === 'GET' ? 'baseline' : `baseline_${method.toLowerCase()}`, method, status_code: baselines[method].status_code });
    }
    return baselines[method];
  };
  const baseline = await baselineFor('GET');
  const health = baseline.transport_error ? 'unhealthy' : markerBaselineHealth(baseline);

  if (!baseline.transport_error) {
    for (const variation of variations) {
      const needsBaseline = !baselines[variation.method];
      if (requestsSent + (needsBaseline ? 2 : 1) > maxRequests) break;
      const methodBaseline = await baselineFor(variation.method);
      if (methodBaseline.transport_error) break;
      const request = buildEntryPathRequest(url, markerClass, variation);
      requestsSent += 1;
      const snapshot = await fetchGrade(fetchFn, request.url, request.headers, timeoutMs, request.method, null, declared);
      phases.push({ phase: variation.variation, method: request.method, status_code: snapshot.status_code });
      const graded = isBlockedOrChallenged(snapshot, methodBaseline);
      const row = {
        phase: variation.variation,
        method: request.method,
        ...gateEntryPathVariation(graded, variation, resultsByVariation),
        status_code: snapshot.status_code,
        ...(snapshot.transport_error ? { error_class: 'transport_error' } : {}),
      };
      resultsByVariation.set(variation.variation, row);
      markerResults.push(row);
      if (snapshot.transport_error) break;
    }
  }

  const enforcement = health === 'healthy' ? enforcementFromResults(markerResults) : 'unknown';
  const identityConfirmed = health === 'healthy' && baseline.canary_echo_matched === true;
  const posture = enforcement === 'enforced' ? 'protected'
    : enforcement === 'not_enforced' || enforcement === 'partial' ? 'exposed'
      : 'inconclusive';
  return {
    entry_path_scenario: scenario,
    marker_class: markerClass,
    marker_inert: true,
    requests_sent: requestsSent,
    max_requests: maxRequests,
    methods_used: [...new Set(phases.map((row) => row.method))],
    redirects_followed: false,
    permitted_baseline: {
      status_code: baseline.transport_error ? null : baseline.status_code,
      health,
      denial_signature: baselineSignature(baseline),
    },
    baseline_health: health,
    application_identity: {
      confirmed: identityConfirmed,
      method: identityConfirmed ? 'nonce_canary' : null,
      attempted: Boolean(expectedNonce),
    },
    enforcement,
    posture,
    blocked_count: markerResults.filter((row) => row.blocked).length,
    allowed_count: markerResults.filter((row) => row.allowed).length,
    inconclusive_count: markerResults.filter((row) => row.inconclusive).length,
    gated_variation_count: markerResults.filter((row) => row.blocked_baseline_prerequisite && row.blocked_baseline_prerequisite !== 'met').length,
    phases,
    marker_results: markerResults,
    ...(baseline.transport_error ? { error_class: 'baseline_transport_error' } : {}),
  };
}
