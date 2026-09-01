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
} from '../outsideInWafScanner.mjs';

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
export function buildWafClassProbeProfile({ marker_class, max_requests, timeout_ms } = {}) {
  if (!WAF_MARKER_CLASSES.includes(marker_class)) {
    throw new Error(`unknown waf marker_class: ${marker_class}`);
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
  });
}

function snapshotFromResponse(res) {
  if (!res) return { status_code: 0, header_names: [], server_header: null, block_page_signature_id: null, connection_dropped: true };
  const headerNames = [];
  if (res.headers && typeof res.headers.forEach === 'function') {
    res.headers.forEach((_v, k) => headerNames.push(String(k).toLowerCase()));
  } else if (res.headers && typeof res.headers === 'object') {
    for (const k of Object.keys(res.headers)) headerNames.push(String(k).toLowerCase());
  }
  const serverHeader = res.headers && typeof res.headers.get === 'function'
    ? res.headers.get('server')
    : res.headers?.server ?? null;
  return {
    status_code: res.status ?? 0,
    header_names: headerNames,
    server_header: serverHeader ?? null,
    block_page_signature_id: null,
    connection_dropped: false,
  };
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

  const placements = [
    { phase: 'baseline', request: () => fetchGrade(fetchFn, url, { ...DEFAULT_HEADERS }, timeoutMs) },
    { phase: 'query_marker', request: () => fetchGrade(fetchFn, buildProbeUrl(url, markerClass, marker, 'query'), { ...DEFAULT_HEADERS }, timeoutMs) },
    { phase: 'path_marker', request: () => fetchGrade(fetchFn, buildProbeUrl(url, markerClass, marker, 'path'), { ...DEFAULT_HEADERS }, timeoutMs) },
    { phase: 'header_marker', request: () => fetchGrade(fetchFn, url, { ...DEFAULT_HEADERS, 'x-astranull-marker': marker }, timeoutMs) },
  ];

  const phases = [];
  const markerResults = [];
  let requestsSent = 0;
  let baseline = null;

  for (const step of placements) {
    if (requestsSent >= WAF_CLASS_PROBE_MAX_REQUESTS) break;
    requestsSent += 1;
    const snapshot = await step.request();
    phases.push({ phase: step.phase, status_code: snapshot.status_code });
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
    max_requests: WAF_CLASS_PROBE_MAX_REQUESTS,
    posture,
    blocked_count: markerResults.filter((r) => r.blocked).length,
    allowed_count: markerResults.filter((r) => r.allowed).length,
    phases,
    marker_results: markerResults,
  };
}

async function fetchGrade(fetchFn, requestUrl, headers, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchFn(requestUrl, {
      method: 'GET',
      headers,
      redirect: 'manual',
      signal: controller.signal,
    });
    return snapshotFromResponse(res);
  } catch {
    return snapshotFromResponse(null);
  } finally {
    clearTimeout(timer);
  }
}
