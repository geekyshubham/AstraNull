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

import { BENIGN_CLASS_MARKERS } from '../inertWafMarkers.mjs';
import {
  markerBaselineHealth,
  markerDenialSignature,
  markerResponseSnapshot,
  readSignatureBody,
} from '../outsideInWafScanner.mjs';
import {
  CANARY_ECHO_RESPONSE_HEADER,
  CANARY_NONCE_REQUEST_HEADER,
  WAF_GRADING_VERSION,
  SIGNATURE_CORPUS_VERSION,
} from '../externalObservationOutcomes.mjs';
import { blockedBaselinePrerequisite } from './evasionProbes.mjs';
import {
  applyCacheBuster,
  deriveRunNonce,
  enforcementFromGraded,
  expectedWafActionOf,
  extractSignatureBasis,
  gradeMarkerSnapshot,
  gradingMeta,
  isGradedLeg,
  markerLegAccounting,
  postureFromEnforcement,
  redactedResponseFeature,
  resolveClassMarkerPaths,
  shuffleWithRng,
  suspectedVendorSummary,
  urlWithPath,
  withSuspectedSignature,
  worstEnforcement,
} from './wafProbeSupport.mjs';

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
 * working exploit. Lookup, external-entity, formula, template-evaluation and prototype
 * assignment forms are deliberately absent: even a non-resolving URL can trigger work.
 * These tokens test only explicitly configured marker-rule behavior, not exploit mitigation.
 */
export const WAF_CLASS_MARKERS = Object.freeze({
  ...BENIGN_CLASS_MARKERS,
  ssrf: 'astranull-ssrf-marker-inert',
  xxe: 'astranull-xxe-marker-inert',
  deserialization: 'rO0ABQ-astranull-deser-probe-INERT',
  request_smuggling: 'astranull-smuggle-probe-CL0TE-inert',
  nosql: '$ne:astranull-nosql-probe-inert',
  jwt_tamper: INERT_JWT,
  ssti: 'astranull-ssti-marker-inert',
  open_redirect: 'astranull-redirect-marker-inert',
  crlf: 'astranull-crlf-probe%0d%0aX-Astranull-Probe:inert',
  prototype_pollution: 'astranull-prototype-marker-inert',
  xpath: "astranull-xpath-probe' and '1'='0",
  csv_injection: 'astranull-csv-marker-inert',
  ldap: 'astranull-ldap-marker-inert',
  file_upload_marker: 'astranull-upload-probe.php.txt',
  http_method_policy: 'astranull-method-policy-probe-TRACK-inert',
  session_marker: 'astranull-session-probe-inert',
  cors_marker: 'astranull-cors-marker-inert',
  scanner_user_agent: 'sqlmap/1.8 (astranull-inert)',
});

/** Marker classes this probe kind understands. */
export const WAF_MARKER_CLASSES = Object.freeze(Object.keys(WAF_CLASS_MARKERS));

const MANAGED_RULE_MARKER_CLASSES = Object.freeze(['sqli', 'xss', 'path_traversal', 'scanner_user_agent']);
const MARKER_PLACEMENTS = Object.freeze(['query', 'path', 'header']);
const SCANNER_USER_AGENT_PLACEMENTS = Object.freeze(['user_agent']);

function placementsForClass(markerClass) {
  return markerClass === 'scanner_user_agent' ? SCANNER_USER_AGENT_PLACEMENTS : MARKER_PLACEMENTS;
}

export function assuranceScopeForMarkerClass(markerClass) {
  return MANAGED_RULE_MARKER_CLASSES.includes(markerClass) ? 'managed_rule_marker' : 'custom_canary_rule';
}

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
  '://', '//', '<!doctype', '<!entity', '${', '{{', '__proto__', 'constructor.prototype',
]);

/** True iff the marker embeds the benign sentinel and no working-payload signature. */
export function isInertMarker(marker) {
  const text = String(marker ?? '').toLowerCase();
  if (!text.includes(BENIGN_MARKER_SENTINEL) || /^[=+@]/.test(text)) return false;
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
    // Keep the marker in one segment: URL normalizes literal ../ before it reaches the WAF.
    url.pathname = `${url.pathname.replace(/\/$/, '')}/${encodeURIComponent(marker)}`;
    return url.href;
  }
  url.searchParams.set(`astranull_${markerClass}_probe`, marker);
  return url.href;
}

function placementRow(placement, snapshot, baseline) {
  const verdict = gradeMarkerSnapshot(snapshot, baseline);
  return {
    placement,
    phase: `${placement}_marker`,
    outcome: verdict.outcome,
    status_code: snapshot.status_code,
    signature_id: verdict.denial_signature?.id ?? null,
    cache_status: snapshot.cache_status ?? verdict.cache_status ?? null,
    location_changed: verdict.location_changed === true,
    ...verdict,
  };
}

function placementProjection(row) {
  return {
    placement: row.placement,
    outcome: row.outcome,
    status_code: row.status_code,
    signature_id: row.signature_id ?? null,
    cache_status: row.cache_status ?? null,
    location_changed: row.location_changed === true,
    ...(row.inconclusive_reason ? { inconclusive_reason: row.inconclusive_reason } : {}),
    ...(row.matched_vendor ? { matched_vendor: row.matched_vendor } : {}),
  };
}

function featureFromSnapshot(placement, snapshot, signatureId, path = null, graded = null) {
  const rowVerdict = graded ?? snapshot;
  const basis = extractSignatureBasis(snapshot, rowVerdict);
  return redactedResponseFeature({
    placement,
    status_code: snapshot?.status_code,
    signature_id: signatureId,
    headerGet: snapshot?._headerGet,
    body_bytes: snapshot?.body_bytes ?? 0,
    path,
    signature_basis: basis,
    location_changed: rowVerdict?.location_changed === true,
    redirected: rowVerdict?.redirected === true || rowVerdict?.outcome === 'redirected',
  });
}

async function runClassMarkerPath({
  pathUrl, markerClass, marker, fetchFn, timeoutMs, declared, maxRequests, requestsSent,
  rng, runNonce, seq,
}) {
  const phases = [];
  const features = [];
  const grade = async (requestUrl, headers, label) => {
    const busted = applyCacheBuster(requestUrl, runNonce, seq.value += 1);
    const snapshot = await fetchGrade(fetchFn, busted, headers, timeoutMs, 'GET', null, declared);
    phases.push({ phase: label, status_code: snapshot.status_code, path: new URL(pathUrl).pathname });
    return snapshot;
  };

  const baseline = await grade(pathUrl, { ...DEFAULT_HEADERS }, 'baseline');
  let used = 1;
  if (baseline.transport_error) {
    return { baseline, markerResults: [], trailingControl: null, sourcePenalized: false, legOrder: [],
      phases, features, used, declaredMatchesBaseline: false, transportError: true };
  }
  const declaredMatchesBaseline = Boolean(declared && baseline.denial_signature?.kind === 'declared');
  if (declaredMatchesBaseline) {
    return { baseline, markerResults: [], trailingControl: null, sourcePenalized: false, legOrder: [],
      phases, features: [featureFromSnapshot('baseline', baseline, baseline.denial_signature?.id, new URL(pathUrl).pathname)], used, declaredMatchesBaseline: true, transportError: false };
  }
  features.push(featureFromSnapshot('baseline', baseline, baseline?.denial_signature?.id, new URL(pathUrl).pathname));

  const remaining = maxRequests - requestsSent - used;
  const canCompleteSequence = remaining >= 2;
  const markerBudget = canCompleteSequence ? remaining - 1 : 0;
  const order = shuffleWithRng(placementsForClass(markerClass), rng).slice(0, markerBudget);
  const markerResults = [];
  for (const placement of order) {
    const headers = {
      ...DEFAULT_HEADERS,
      ...(placement === 'header' ? { 'x-astranull-marker': marker } : {}),
      ...(placement === 'user_agent' ? { 'user-agent': marker } : {}),
    };
    const requestUrl = placement === 'query' || placement === 'path'
      ? buildProbeUrl(pathUrl, markerClass, marker, placement)
      : pathUrl;
    const snapshot = await grade(requestUrl, headers, `${placement}_marker`);
    used += 1;
    const row = placementRow(placement, snapshot, baseline);
    markerResults.push(row);
    features.push(featureFromSnapshot(placement, snapshot, row.signature_id, new URL(pathUrl).pathname, row));
    if (snapshot.transport_error) {
      return { baseline, markerResults, trailingControl: null, sourcePenalized: false, legOrder: order,
        phases, features, used, declaredMatchesBaseline: false, transportError: true };
    }
  }

  let trailingControl = null;
  let sourcePenalized = false;
  if (order.length > 0 && requestsSent + used < maxRequests) {
    const snapshot = await grade(pathUrl, { ...DEFAULT_HEADERS }, 'trailing_control');
    used += 1;
    const graded = gradeMarkerSnapshot(snapshot, baseline);
    trailingControl = { outcome: graded.outcome, status_code: snapshot.status_code };
    sourcePenalized = graded.allowed !== true;
    features.push(featureFromSnapshot('trailing_control', snapshot, graded.denial_signature?.id ?? null, new URL(pathUrl).pathname, graded));
  }

  return {
    baseline, markerResults, trailingControl, sourcePenalized, legOrder: order,
    phases, features, used, declaredMatchesBaseline: false, transportError: false,
  };
}

/**
 * Run a bounded marker probe: one baseline request, then the marker placed in a
 * query parameter, path segment, and a benign header — capped at 8 requests total,
 * grading each with the shared gradeMarkerSnapshot logic. Network access is fully
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
  const expectedAction = expectedWafActionOf(options);
  const rng = typeof options.rng === 'function' ? options.rng : Math.random;
  const runNonce = deriveRunNonce(options.nonce ?? options.run_nonce);
  const seq = { value: 0 };
  const allPaths = resolveClassMarkerPaths(url, options);
  const minPerPath = 3;
  const affordable = Math.max(1, Math.floor(maxRequests / minPerPath));
  const paths = allPaths.slice(0, affordable);
  let pathsSkipped = Math.max(0, allPaths.length - paths.length);

  const phases = [];
  const pathResults = [];
  const responseFeatures = [];
  const combinedPlacements = [];
  // Fix the budget-selected plan before executing it; early failures cannot shrink its denominator.
  let plannedBudget = maxRequests;
  const plannedMarkerLegs = paths.reduce((total) => {
    const count = Math.min(placementsForClass(markerClass).length, Math.max(0, plannedBudget - 2));
    plannedBudget -= count + 2;
    return total + count;
  }, 0);
  let requestsSent = 0;
  let sourcePenalized = false;
  let declaredMatchesBaseline = false;
  let lastBaseline = null;
  const legOrder = [];

  for (const path of paths) {
    if (requestsSent >= maxRequests) {
      break;
    }
    const pathUrl = urlWithPath(url, path);
    const ran = await runClassMarkerPath({
      pathUrl, markerClass, marker, fetchFn, timeoutMs, declared,
      maxRequests, requestsSent, rng, runNonce, seq,
    });
    requestsSent += ran.used;
    phases.push(...ran.phases);
    responseFeatures.push(...ran.features);
    lastBaseline = ran.baseline;
    if (ran.declaredMatchesBaseline) declaredMatchesBaseline = true;
    if (ran.sourcePenalized) sourcePenalized = true;
    if (ran.legOrder.length) legOrder.push(...ran.legOrder);
    const graded = ran.markerResults.filter(isGradedLeg);
    const pathEnforcement = ran.sourcePenalized ? 'unknown' : enforcementFromGraded(graded, { expectedAction });
    const pathPosture = postureFromEnforcement(pathEnforcement, { sourcePenalized: ran.sourcePenalized });
    pathResults.push({
      path,
      ...pathPosture,
      placements: ran.markerResults.map(placementProjection),
      trailing_control: ran.trailingControl,
      source_penalized: ran.sourcePenalized,
      baseline: ran.baseline ? featureFromSnapshot('baseline', ran.baseline, ran.baseline?.denial_signature?.id ?? null, path) : null,
    });
    combinedPlacements.push(...ran.markerResults);
    if (ran.transportError || ran.declaredMatchesBaseline || ran.sourcePenalized) {
      pathsSkipped += Math.max(0, paths.length - pathResults.length);
      break;
    }
  }

  const graded = combinedPlacements.filter(isGradedLeg);
  let enforcement = sourcePenalized ? 'unknown' : (pathResults.length > 1
    ? worstEnforcement(pathResults.map((row) => row.enforcement))
    : enforcementFromGraded(graded, { expectedAction }));
  if (declaredMatchesBaseline) enforcement = 'unknown';
  const mapped = postureFromEnforcement(enforcement, { sourcePenalized });
  let posture = mapped.posture;
  let postureStatus = mapped.posture_status;
  let inconclusiveReason = null;
  let matchedVendor = null;
  if (declaredMatchesBaseline) {
    posture = 'inconclusive';
    postureStatus = 'inconclusive';
    inconclusiveReason = 'declared_signature_matches_baseline';
  } else if (graded.length === 0 && !sourcePenalized) {
    const suspected = suspectedVendorSummary(combinedPlacements);
    if (suspected) {
      inconclusiveReason = suspected.inconclusive_reason;
      matchedVendor = suspected.matched_vendor;
    }
  }
  const health = markerBaselineHealth(lastBaseline);
  const accounting = markerLegAccounting(combinedPlacements, plannedMarkerLegs);
  const comparisonComplete = health === 'healthy' && !sourcePenalized && !declaredMatchesBaseline
    && graded.length >= 1 && accounting.missing_marker_legs === 0
    && pathResults.every((row) => row.trailing_control?.outcome === 'allowed');
  const custom = assuranceScopeForMarkerClass(markerClass) === 'custom_canary_rule';
  if (!comparisonComplete || custom) {
    mapped.posture = posture = 'inconclusive';
    mapped.posture_status = postureStatus = sourcePenalized ? 'source_penalized' : 'inconclusive';
    mapped.enforcement = 'unknown';
  }
  if (custom) {
    inconclusiveReason = 'custom_canary_rule_setup_unavailable';
    for (const path of pathResults) {
      path.posture = 'inconclusive';
      path.posture_status = 'inconclusive';
      path.enforcement = 'unknown';
      path.setup_required = true;
      path.produces_verdict = false;
    }
  }

  return {
    classifier_version: 'marker-comparison-v5',
    assurance_scope: assuranceScopeForMarkerClass(markerClass),
    ...gradingMeta(),
    ...accounting,
    ...(custom ? { setup_required: true, produces_verdict: false } : { produces_verdict: true }),
    comparison_complete: comparisonComplete,
    baseline_health: health,
    observation_only: custom || !comparisonComplete,
    readiness_conclusion: !custom && comparisonComplete && mapped.posture !== 'inconclusive',
    marker_class: markerClass,
    marker_inert: true,
    requests_sent: requestsSent,
    max_requests: maxRequests,
    cache_buster: true,
    source_penalized: sourcePenalized,
    trailing_control: pathResults[0]?.trailing_control ?? null,
    leg_order: [...new Set(legOrder)],
    placements: combinedPlacements.map(placementProjection),
    paths: pathResults,
    paths_skipped: pathsSkipped,
    ...mapped,
    posture,
    posture_status: postureStatus,
    enforcement: mapped.enforcement,
    ...(inconclusiveReason ? { inconclusive_reason: inconclusiveReason } : {}),
    ...(matchedVendor ? { matched_vendor: matchedVendor } : {}),
    expected_action: expectedAction,
    blocked_count: combinedPlacements.filter((r) => r.blocked).length,
    allowed_count: combinedPlacements.filter((r) => r.allowed).length,
    phases,
    marker_results: combinedPlacements,
    response_features: responseFeatures,
    baseline: pathResults[0]?.baseline ?? (lastBaseline ? featureFromSnapshot('baseline', lastBaseline, lastBaseline?.denial_signature?.id ?? null, pathResults[0]?.path ?? '/') : null),
    grading_version: WAF_GRADING_VERSION,
    signature_corpus_version: SIGNATURE_CORPUS_VERSION,
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
  if (!ENTRY_PATH_SAFE_METHODS.includes(method)) return { ...markerResponseSnapshot(null), transport_error: true, error_class: 'unsupported_method' };
  const safeMethod = method;
  try {
    const res = await fetchFn(requestUrl, {
      method: safeMethod,
      headers: expectedNonce ? { ...headers, [CANARY_NONCE_REQUEST_HEADER]: expectedNonce } : headers,
      redirect: 'manual',
      signal: controller.signal,
    });
    if (!res || !Number.isInteger(res.status)) return { ...markerResponseSnapshot(null), transport_error: true };
    const bodyText = await readSignatureBody(res, safeMethod);
    const snapshot = withSuspectedSignature(markerResponseSnapshot(res, bodyText, declared), res, bodyText);
    const headerGet = (name) => {
      if (typeof res.headers?.get === 'function') return res.headers.get(name);
      if (res.headers && typeof res.headers === 'object') {
        const lower = Object.fromEntries(Object.entries(res.headers).map(([k, v]) => [String(k).toLowerCase(), v]));
        return lower[String(name).toLowerCase()] ?? null;
      }
      return null;
    };
    const decorated = { ...snapshot, _headerGet: headerGet };
    return expectedNonce ? { ...decorated, canary_echo_matched: canaryEchoMatches(res, expectedNonce) } : decorated;
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
    Object.freeze({ variation: 'header_marker', method: 'GET', where: 'header', encoding: 'plain' }),
    Object.freeze({ variation: 'query_marker_form_content_type', method: 'GET', where: 'query', encoding: 'plain', content_type: 'application/x-www-form-urlencoded', reference: 'query_marker' }),
    Object.freeze({ variation: 'query_marker_after_padding', method: 'GET', where: 'query', encoding: 'plain', padding_bytes: ENTRY_PATH_QUERY_PADDING_BYTES, reference: 'query_marker' }),
    Object.freeze({ variation: 'header_marker_after_padding', method: 'GET', where: 'header', encoding: 'plain', padding_bytes: ENTRY_PATH_HEADER_PADDING_BYTES, reference: 'header_marker' }),
  ]),
  declared_api_path: Object.freeze([
    Object.freeze({ variation: 'query_marker', method: 'GET', where: 'query', encoding: 'plain', accept: 'application/json' }),
    Object.freeze({ variation: 'query_marker_double_encoded', method: 'GET', where: 'query', encoding: 'double_percent', accept: 'application/json', reference: 'query_marker' }),
    Object.freeze({ variation: 'header_marker', method: 'GET', where: 'header', encoding: 'plain', accept: 'application/json' }),
    Object.freeze({ variation: 'query_marker_json_content_type', method: 'GET', where: 'query', encoding: 'plain', content_type: 'application/json', accept: 'application/json', reference: 'query_marker' }),
    Object.freeze({ variation: 'query_marker_after_padding', method: 'GET', where: 'query', encoding: 'plain', padding_bytes: ENTRY_PATH_QUERY_PADDING_BYTES, accept: 'application/json', reference: 'query_marker' }),
    Object.freeze({ variation: 'header_marker_after_padding', method: 'GET', where: 'header', encoding: 'plain', padding_bytes: ENTRY_PATH_HEADER_PADDING_BYTES, accept: 'application/json', reference: 'header_marker' }),
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

function enforcementFromResults(results, expectedAction = 'block') {
  return enforcementFromGraded((results ?? []).filter(isGradedLeg), { expectedAction });
}

function referenceBlocked(row) {
  if (!row || row.inconclusive || row.error_class) return null;
  if (row.blocked === true) return true;
  return row.allowed === true ? false : null;
}

/** Record the plain-reference prerequisite without voiding this leg's own grade. */
export function gateEntryPathVariation(graded, variation, resultsByVariation) {
  if (!variation?.reference) return { ...graded };
  const prerequisite = blockedBaselinePrerequisite(referenceBlocked(resultsByVariation.get(variation.reference)));
  return { ...graded, reference_variation: variation.reference, blocked_baseline_prerequisite: prerequisite };
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
  const rng = typeof options.rng === 'function' ? options.rng : Math.random;
  const runNonce = deriveRunNonce(options.nonce ?? options.run_nonce ?? options.expected_nonce);
  const seq = { value: 0 };
  const declared = options.declared_block_signature ?? null;
  const expectedNonce = typeof options.expected_nonce === 'string' && options.expected_nonce.trim()
    ? options.expected_nonce.trim()
    : null;

  const phases = [];
  const markerResults = [];
  const resultsByVariation = new Map();
  const responseFeatures = [];
  let requestsSent = 0;
  const busted = (href) => applyCacheBuster(href, runNonce, seq.value += 1);

  requestsSent += 1;
  const baseline = await fetchGrade(fetchFn, busted(url), { ...DEFAULT_HEADERS }, timeoutMs, 'GET', expectedNonce, declared);
  phases.push({ phase: 'baseline', method: 'GET', status_code: baseline.status_code });
  const health = baseline.transport_error ? 'unhealthy' : markerBaselineHealth(baseline);
  const declaredMatchesBaseline = Boolean(declared && baseline.denial_signature?.kind === 'declared');

  let sourcePenalized = false;
  let trailingControl = null;
  const independent = variations.filter((row) => !row.reference);
  const dependent = variations.filter((row) => row.reference);
  const ordered = [...shuffleWithRng(independent, rng), ...shuffleWithRng(dependent, rng)];
  if (!baseline.transport_error && !declaredMatchesBaseline) {
    for (const variation of ordered) {
      if (requestsSent + 2 > maxRequests) break;
      const request = buildEntryPathRequest(url, markerClass, variation);
      requestsSent += 1;
      const snapshot = await fetchGrade(fetchFn, busted(request.url), request.headers, timeoutMs, 'GET', null, declared);
      phases.push({ phase: variation.variation, method: 'GET', status_code: snapshot.status_code });
      const graded = gradeMarkerSnapshot(snapshot, baseline);
      const row = {
        phase: variation.variation,
        placement: variation.where,
        method: 'GET',
        ...gateEntryPathVariation(graded, variation, resultsByVariation),
        status_code: snapshot.status_code,
        signature_id: graded.denial_signature?.id ?? null,
        cache_status: snapshot.cache_status ?? graded.cache_status ?? null,
        location_changed: graded.location_changed === true,
        ...(snapshot.transport_error ? { error_class: 'transport_error' } : {}),
      };
      resultsByVariation.set(variation.variation, row);
      markerResults.push(row);
      responseFeatures.push(featureFromSnapshot(variation.variation, snapshot, row.signature_id));
      if (snapshot.transport_error) break;
    }
    if (markerResults.length > 0 && requestsSent < maxRequests) {
      requestsSent += 1;
      const snapshot = await fetchGrade(fetchFn, busted(url), { ...DEFAULT_HEADERS }, timeoutMs, 'GET', null, declared);
      const graded = gradeMarkerSnapshot(snapshot, baseline);
      trailingControl = { outcome: graded.outcome, status_code: snapshot.status_code };
      sourcePenalized = graded.allowed !== true;
      phases.push({ phase: 'trailing_control', method: 'GET', status_code: snapshot.status_code });
      responseFeatures.push(featureFromSnapshot('trailing_control', snapshot, graded.denial_signature?.id ?? null));
    }
  }

  const graded = markerResults.filter(isGradedLeg);
  const mapped = postureFromEnforcement(
    health === 'healthy' && !declaredMatchesBaseline ? enforcementFromResults(markerResults, expectedWafActionOf(options)) : 'unknown',
    { sourcePenalized },
  );
  if (declaredMatchesBaseline) {
    mapped.posture = 'inconclusive';
    mapped.posture_status = 'inconclusive';
    mapped.enforcement = 'unknown';
  }
  const identityConfirmed = health === 'healthy' && baseline.canary_echo_matched === true;
  const accounting = markerLegAccounting(markerResults, Math.min(variations.length, Math.max(0, maxRequests - 2)));
  const comparisonComplete = health === 'healthy' && !sourcePenalized && !declaredMatchesBaseline && graded.length >= 1
    && accounting.missing_marker_legs === 0 && trailingControl?.outcome === 'allowed';
  const custom = assuranceScopeForMarkerClass(markerClass) === 'custom_canary_rule';
  if (!comparisonComplete || custom) {
    mapped.posture = 'inconclusive';
    mapped.posture_status = sourcePenalized ? 'source_penalized' : 'inconclusive';
    mapped.enforcement = 'unknown';
  }
  return {
    entry_path_scenario: scenario,
    classifier_version: 'marker-comparison-v5',
    assurance_scope: assuranceScopeForMarkerClass(markerClass),
    ...gradingMeta(),
    ...accounting,
    ...(custom ? { setup_required: true, produces_verdict: false, inconclusive_reason: 'custom_canary_rule_setup_unavailable' } : { produces_verdict: true }),
    comparison_complete: comparisonComplete,
    observation_only: custom || !comparisonComplete,
    readiness_conclusion: !custom && comparisonComplete && mapped.posture !== 'inconclusive',
    marker_class: markerClass,
    marker_inert: true,
    requests_sent: requestsSent,
    max_requests: maxRequests,
    cache_buster: true,
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
    ...mapped,
    source_penalized: sourcePenalized,
    trailing_control: trailingControl,
    leg_order: markerResults.map((row) => row.phase),
    placements: markerResults.map((row) => placementProjection({ ...row, placement: row.placement ?? row.phase })),
    response_features: responseFeatures,
    baseline: !baseline.transport_error ? featureFromSnapshot('baseline', baseline, baseline?.denial_signature?.id ?? null, new URL(url).pathname) : null,
    ...(declaredMatchesBaseline ? { inconclusive_reason: 'declared_signature_matches_baseline' } : {}),
    blocked_count: markerResults.filter((row) => row.blocked).length,
    allowed_count: markerResults.filter((row) => row.allowed).length,
    inconclusive_count: markerResults.filter((row) => row.inconclusive).length,
    gated_variation_count: markerResults.filter((row) => row.blocked_baseline_prerequisite && row.blocked_baseline_prerequisite !== 'met').length,
    phases,
    marker_results: markerResults,
    ...(baseline.transport_error ? { error_class: 'baseline_transport_error' } : {}),
  };
}
