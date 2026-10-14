/**
 * WAF HTTP method-policy probe — baseline GET, then TRACE and ASTRANULLPROBE
 * with no body, then a trailing benign GET. Source-penalty follows T1 markers.
 */

import {
  markerBaselineHealth,
  markerResponseSnapshot,
  readSignatureBody,
} from '../outsideInWafScanner.mjs';
import { computeDeclaredSignatureDigest } from '../externalObservationOutcomes.mjs';
import {
  applyCacheBuster,
  deriveRunNonce,
  enforcementFromGraded,
  extractSignatureBasis,
  gradeMarkerSnapshot,
  gradingMeta,
  isGradedLeg,
  postureFromEnforcement,
  redactedResponseFeature,
  withSuspectedSignature,
} from './wafProbeSupport.mjs';

export const WAF_METHOD_POLICY_PROBE_KIND = 'waf_method_policy_probe';
export const WAF_METHOD_POLICY_MAX_REQUESTS = 8;
export const METHOD_POLICY_DISALLOWED_METHODS = Object.freeze(['TRACE', 'ASTRANULLPROBE']);
export const METHOD_POLICY_SAFE_METHODS = Object.freeze(['GET', 'HEAD', ...METHOD_POLICY_DISALLOWED_METHODS]);

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_HEADERS = Object.freeze({
  accept: 'text/html,application/xhtml+xml',
  'accept-language': 'en-US,en;q=0.9',
});

function featureFromSnapshot(placement, snapshot, signatureId, path = null, graded = null, declared = null) {
  const rowVerdict = graded ?? snapshot;
  const basis = extractSignatureBasis(snapshot, rowVerdict);
  const declaration_digest = basis?.declaration_digest
    ?? rowVerdict?.denial_signature?.declaration_digest
    ?? (basis && (basis.kind === 'declared_header' || basis.kind === 'declared_body') ? computeDeclaredSignatureDigest(declared) : null);
  return redactedResponseFeature({
    placement,
    status_code: snapshot?.status_code,
    signature_id: signatureId,
    headerGet: snapshot?._headerGet,
    body_bytes: snapshot?.body_bytes ?? 0,
    path,
    signature_basis: basis,
    declaration_digest,
    location_changed: rowVerdict?.location_changed === true,
    redirected: rowVerdict?.redirected === true || rowVerdict?.outcome === 'redirected',
  });
}

function decorateSnapshot(res, snapshot) {
  const headerGet = (name) => {
    if (typeof res?.headers?.get === 'function') return res.headers.get(name);
    if (res?.headers && typeof res.headers === 'object') {
      const lower = Object.fromEntries(Object.entries(res.headers).map(([k, v]) => [String(k).toLowerCase(), v]));
      return lower[String(name).toLowerCase()] ?? null;
    }
    return null;
  };
  return { ...snapshot, _headerGet: headerGet };
}

async function fetchGrade(fetchFn, requestUrl, headers, timeoutMs, method, declared = null) {
  if (!METHOD_POLICY_SAFE_METHODS.includes(method)) {
    return { ...markerResponseSnapshot(null), transport_error: true, error_class: 'unsupported_method' };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchFn(requestUrl, {
      method,
      headers,
      redirect: 'manual',
      signal: controller.signal,
      probeKind: WAF_METHOD_POLICY_PROBE_KIND,
    });
    if (!res || !Number.isInteger(res.status)) return { ...markerResponseSnapshot(null), transport_error: true };
    const bodyText = await readSignatureBody(res, method);
    const snapshot = withSuspectedSignature(markerResponseSnapshot(res, bodyText, declared), res, bodyText);
    return decorateSnapshot(res, snapshot);
  } catch {
    return { ...markerResponseSnapshot(null), transport_error: true };
  } finally {
    clearTimeout(timer);
  }
}

function gradeMethodLeg(method, snapshot, baseline) {
  const verdict = gradeMarkerSnapshot(snapshot, baseline);
  const status = snapshot?.status_code;
  const originReject = (status === 405 || status === 501)
    && verdict.blocked !== true
    && verdict.challenged !== true;
  if (originReject) {
    return {
      placement: method,
      method,
      phase: `${method.toLowerCase()}_method`,
      outcome: 'inconclusive',
      status_code: status,
      signature_id: verdict.denial_signature?.id ?? null,
      cache_status: snapshot.cache_status ?? verdict.cache_status ?? null,
      location_changed: verdict.location_changed === true,
      blocked: false,
      challenged: false,
      allowed: false,
      redirected: false,
      inconclusive: true,
      reason: 'not_enforced_by_waf_but_rejected_by_origin',
      origin_rejected: true,
    };
  }
  return {
    placement: method,
    method,
    phase: `${method.toLowerCase()}_method`,
    outcome: verdict.outcome,
    status_code: status,
    signature_id: verdict.denial_signature?.id ?? null,
    cache_status: snapshot.cache_status ?? verdict.cache_status ?? null,
    location_changed: verdict.location_changed === true,
    ...verdict,
  };
}

export function buildWafMethodPolicyProbeProfile({ max_requests, timeout_ms } = {}) {
  const requested = Number.isInteger(max_requests) && max_requests > 0 ? max_requests : WAF_METHOD_POLICY_MAX_REQUESTS;
  const cappedTimeout = Number.isInteger(timeout_ms) && timeout_ms > 0
    ? Math.min(timeout_ms, DEFAULT_TIMEOUT_MS)
    : DEFAULT_TIMEOUT_MS;
  return Object.freeze({
    kind: WAF_METHOD_POLICY_PROBE_KIND,
    max_requests: Math.min(requested, WAF_METHOD_POLICY_MAX_REQUESTS),
    timeout_ms: cappedTimeout,
    methods: [...METHOD_POLICY_DISALLOWED_METHODS],
    collect: ['status_code', 'method_results', 'posture_status'],
  });
}

export async function runWafMethodPolicyProbe(options = {}) {
  const url = String(options.url ?? '').trim();
  if (!url) return { error_class: 'unsupported_target', requests_sent: 0, phases: [] };
  const fetchFn = options.fetchFn;
  if (typeof fetchFn !== 'function') {
    return { error_class: 'no_transport', requests_sent: 0, phases: [] };
  }

  const timeoutMs = Number.isInteger(options.timeout_ms) && options.timeout_ms > 0
    ? Math.min(options.timeout_ms, DEFAULT_TIMEOUT_MS)
    : DEFAULT_TIMEOUT_MS;
  const maxRequests = Math.min(
    Number.isInteger(options.max_requests) && options.max_requests > 0
      ? options.max_requests
      : WAF_METHOD_POLICY_MAX_REQUESTS,
    WAF_METHOD_POLICY_MAX_REQUESTS,
  );
  const declared = options.declared_block_signature ?? null;
  const runNonce = deriveRunNonce(options.nonce ?? options.run_nonce);
  const seq = { value: 0 };
  const phases = [];
  const responseFeatures = [];
  let requestsSent = 0;

  const send = async (method, label) => {
    const busted = applyCacheBuster(url, runNonce, seq.value += 1);
    const snapshot = await fetchGrade(fetchFn, busted, { ...DEFAULT_HEADERS }, timeoutMs, method, declared);
    phases.push({ phase: label, method, status_code: snapshot.status_code });
    requestsSent += 1;
    return snapshot;
  };

  const baseline = await send('GET', 'baseline');
  if (baseline.transport_error) {
    return {
      error_class: 'baseline_transport_error',
      requests_sent: requestsSent,
      max_requests: maxRequests,
      phases,
      method_results: [],
      cache_buster: true,
      source_penalized: false,
      trailing_control: null,
      ...gradingMeta(),
    };
  }

  const declaredMatchesBaseline = Boolean(declared && baseline.denial_signature?.kind === 'declared');
  const methodResults = [];
  if (!declaredMatchesBaseline) {
    for (const method of METHOD_POLICY_DISALLOWED_METHODS) {
      if (requestsSent + 1 > maxRequests) break;
      const snapshot = await send(method, `${method.toLowerCase()}_method`);
      const row = gradeMethodLeg(method, snapshot, baseline);
      methodResults.push(row);
      responseFeatures.push(featureFromSnapshot(method, snapshot, row.signature_id, new URL(url).pathname, row, declared));
      if (snapshot.transport_error) break;
    }
  }

  let trailingControl = null;
  let sourcePenalized = false;
  if (!declaredMatchesBaseline && methodResults.length > 0 && requestsSent < maxRequests) {
    const snapshot = await send('GET', 'trailing_control');
    const graded = gradeMarkerSnapshot(snapshot, baseline);
    trailingControl = { outcome: graded.outcome, status_code: snapshot.status_code };
    sourcePenalized = graded.allowed !== true;
    responseFeatures.push(featureFromSnapshot('trailing_control', snapshot, graded.denial_signature?.id ?? null, new URL(url).pathname, graded, declared));
  }

  const originRejected = methodResults.filter((row) => row.origin_rejected === true);
  const graded = methodResults.filter(isGradedLeg);
  let enforcement = sourcePenalized ? 'unknown' : enforcementFromGraded(graded);
  if (declaredMatchesBaseline) enforcement = 'unknown';
  if (!sourcePenalized && !declaredMatchesBaseline && originRejected.length === methodResults.length && methodResults.length > 0 && graded.length === 0) {
    enforcement = 'unknown';
  }
  const mapped = postureFromEnforcement(enforcement, { sourcePenalized });
  let posture = mapped.posture;
  let postureStatus = mapped.posture_status;
  let inconclusiveReason = null;
  if (declaredMatchesBaseline) {
    posture = 'inconclusive';
    postureStatus = 'inconclusive';
    inconclusiveReason = 'declared_signature_matches_baseline';
  } else if (originRejected.length === methodResults.length && methodResults.length > 0 && graded.length === 0 && !sourcePenalized) {
    posture = 'inconclusive';
    postureStatus = 'inconclusive';
    inconclusiveReason = 'not_enforced_by_waf_but_rejected_by_origin';
  }
  const health = markerBaselineHealth(baseline);
  const comparisonComplete = health === 'healthy' && !sourcePenalized && !declaredMatchesBaseline
    && methodResults.length === METHOD_POLICY_DISALLOWED_METHODS.length
    && (graded.length >= 1 || originRejected.length === methodResults.length);

  return {
    classifier_version: 'marker-comparison-v4',
    assurance_scope: 'inert_marker_rule_action_only',
    ...gradingMeta(),
    planned_marker_legs: METHOD_POLICY_DISALLOWED_METHODS.length,
    completed_marker_legs: methodResults.length,
    comparison_complete: comparisonComplete,
    baseline_health: health,
    observation_only: !comparisonComplete,
    readiness_conclusion: comparisonComplete && mapped.posture !== 'inconclusive',
    requests_sent: requestsSent,
    max_requests: maxRequests,
    cache_buster: true,
    source_penalized: sourcePenalized,
    trailing_control: trailingControl,
    methods_used: [...new Set(phases.map((row) => row.method))],
    method_results: methodResults.map((row) => ({
      method: row.method,
      outcome: row.outcome,
      status_code: row.status_code,
      signature_id: row.signature_id ?? null,
      reason: row.reason ?? null,
      origin_rejected: row.origin_rejected === true,
    })),
    placements: methodResults.map((row) => ({
      placement: row.placement,
      outcome: row.outcome,
      status_code: row.status_code,
      signature_id: row.signature_id ?? null,
      cache_status: row.cache_status ?? null,
      location_changed: row.location_changed === true,
      ...(row.matched_vendor ? { inconclusive_reason: row.inconclusive_reason, matched_vendor: row.matched_vendor } : {}),
    })),
    ...mapped,
    posture,
    posture_status: postureStatus,
    enforcement: mapped.enforcement,
    ...(inconclusiveReason ? { inconclusive_reason: inconclusiveReason } : {}),
    blocked_count: methodResults.filter((row) => row.blocked).length,
    allowed_count: methodResults.filter((row) => row.allowed).length,
    phases,
    response_features: responseFeatures,
    baseline: !baseline.transport_error ? featureFromSnapshot('baseline', baseline, baseline?.denial_signature?.id ?? null, new URL(url).pathname, baseline, declared) : null,
  };
}
