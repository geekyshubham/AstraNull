/**
 * L7 resource-exhaustion POSTURE probes (Wave 4, ticket W4-L7).
 *
 * One bounded GET observes an actual ~1KB URI. It cannot establish a 64KB limit.
 * Compressed-body/parser scenarios are unsupported without a business-safe approved
 * endpoint; a declaration header or malformed encoding is never mitigation evidence.
 *
 * Hard-bounded by L7_RESOURCE_POSTURE_MAX_REQUESTS. No count, rate, concurrency, or
 * repeat parameter is exported. Response bodies are never retained.
 */

import { isLiveCapabilityProbeAuthorized } from '../capabilityProbeAuth.mjs';
import { normalizeProbeHttpPath } from '../../contracts/checks.mjs';
import { pinnedFetch } from '../pinnedHttpRequest.mjs';
import { resolveProbeRequestBudget } from '../probeRequestBudget.mjs';

export const L7_RESOURCE_POSTURE_PROBE_KIND = 'l7_resource_posture_probe';

// Single hard bound on the number of requests this probe kind may ever send.
export const L7_RESOURCE_POSTURE_MAX_REQUESTS = 3;

export const L7_POSTURE_MARKER_CLASSES = Object.freeze([
  'declared_content_encoding',
  'declared_oversize_uri',
]);

const DEFAULT_TIMEOUT_MS = 5000;
const MAX_TIMEOUT_MS = 5000;

// Exported compatibility token only; body delivery remains unsupported.
export const INERT_POSTURE_MARKER_BODY = 'astranull-inert-posture';

// Bounded benign URI marker used for the oversize-URI posture read. One small request.
const URI_MARKER_TOKEN = 'astranull-inert';
const URI_MARKER_LENGTH = 1024;

// DECLARED sizes are integers placed in a header string only — never materialised as bytes.
// No imaginary declared size is used as evidence.

// Absolute cap on the actual bytes any single request in this module may send.
export const MAX_ACTUAL_REQUEST_BYTES = 4096;

export function boundedPostureTimeoutMs(value) {
  const candidate = Number(value);
  if (!Number.isSafeInteger(candidate) || candidate <= 0) return DEFAULT_TIMEOUT_MS;
  return Math.min(Math.max(100, candidate), MAX_TIMEOUT_MS);
}

export function buildL7ResourcePostureProfile({
  marker_class,
  probe_path,
  max_requests = L7_RESOURCE_POSTURE_MAX_REQUESTS,
  timeout_ms = DEFAULT_TIMEOUT_MS,
} = {}) {
  if (!L7_POSTURE_MARKER_CLASSES.includes(marker_class)) {
    throw new Error(`invalid l7 posture marker_class: ${marker_class}`);
  }
  const profile = {
    kind: L7_RESOURCE_POSTURE_PROBE_KIND,
    max_requests: Math.min(Math.max(1, Number(max_requests) || 1), L7_RESOURCE_POSTURE_MAX_REQUESTS),
    timeout_ms: boundedPostureTimeoutMs(timeout_ms),
    marker_class,
  };
  if (!Number.isSafeInteger(max_requests) || max_requests < 1 || !Number.isSafeInteger(timeout_ms) || timeout_ms < 1) throw new Error('probe budget and timeout must be positive integers');
  const path = normalizeProbeHttpPath(probe_path);
  if (probe_path != null && !path) throw new Error('invalid bounded probe path');
  if (path) profile.probe_path = path;
  profile.observation_only = true;
  profile.readiness_conclusion = false;
  profile.delivery_supported = marker_class === 'declared_oversize_uri';
  return profile;
}

function resolveEndpoint(job) {
  const value = String(job?.target?.value ?? '').trim();
  if (!value) return null;
  let base;
  try {
    base = /^https?:\/\//i.test(value) ? new URL(value) : new URL(`https://${value}/`);
  } catch {
    return null;
  }
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.hash) return null;
  const configuredPath = normalizeProbeHttpPath(job?.probe_profile?.probe_path);
  if (job?.probe_profile?.probe_path != null && !configuredPath) return null;
  if (configuredPath) {
    base.pathname = configuredPath;
    base.search = '';
  }
  base.hash = '';
  return { url: base, path: base.pathname };
}

// Only an actual bounded URI is delivered. No declared compressed shape or POST.
function requestSpecsForMarkerClass(markerClass) {
  if (markerClass === 'declared_content_encoding') return [];
  return [
    {
      method: 'GET',
      query: `${URI_MARKER_TOKEN}=${'a'.repeat(URI_MARKER_LENGTH - URI_MARKER_TOKEN.length - 1)}`,
      headers: {
        'x-astranull-probe': 'l7-resource-posture',
      },
    },
  ];
}

function actualRequestBytes(spec) {
  const bodyLen = typeof spec.body === 'string' ? Buffer.byteLength(spec.body) : 0;
  const queryLen = typeof spec.query === 'string' ? Buffer.byteLength(spec.query) : 0;
  return bodyLen + queryLen;
}

async function defaultRequestFn(url, options, deps) {
  const resp = await pinnedFetch(url, options, deps);
  try {
    await resp.body?.cancel?.();
  } catch {
    // ignore: body is deliberately discarded, never retained
  }
  return { status: resp.status ?? 0 };
}

export async function probeL7ResourcePosture(job, deps = {}) {
  const kind = L7_RESOURCE_POSTURE_PROBE_KIND;
  const startedAt = Date.now();
  if (!isLiveCapabilityProbeAuthorized(job, deps)) {
    return {
      external_result: 'error',
      metadata: { probe_kind: kind, error_class: 'probe_not_authorized' },
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  const markerClass = job?.probe_profile?.marker_class;
  if (!L7_POSTURE_MARKER_CLASSES.includes(markerClass)) {
    return {
      external_result: 'error',
      metadata: { probe_kind: kind, error_class: 'unsupported_marker_class' },
      requests_sent: 0,
      duration_ms: Date.now() - startedAt,
    };
  }

  if (markerClass === 'declared_content_encoding') return { external_result: 'not_run', metadata: {
    probe_kind: kind, marker_class: markerClass, classifier_version: 'capability-observation-v3',
    observation_only: true, readiness_conclusion: false, delivery_supported: false,
    not_run_reason: 'approved_business_safe_body_endpoint_required', comparison_complete: false,
    request_counting_basis: 'logical_operations', body_retained: false,
  }, requests_sent: 0, duration_ms: 0 };

  const endpoint = resolveEndpoint(job);
  if (!endpoint) {
    return {
      external_result: 'error',
      metadata: { probe_kind: kind, error_class: 'unsupported_target', marker_class: markerClass },
      requests_sent: 0,
      duration_ms: Date.now() - startedAt,
    };
  }

  const timeoutMs = boundedPostureTimeoutMs(job?.probe_profile?.timeout_ms);
  const requestFn = deps.requestFn ?? defaultRequestFn;
  const profileBudget = Number(job?.probe_profile?.max_requests);
  const maxRequests = Math.min(
    Number.isInteger(profileBudget) && profileBudget > 0
      ? profileBudget
      : L7_RESOURCE_POSTURE_MAX_REQUESTS,
    resolveProbeRequestBudget(job),
    L7_RESOURCE_POSTURE_MAX_REQUESTS,
  );
  const specs = requestSpecsForMarkerClass(markerClass).slice(0, maxRequests);

  let requestsSent = 0;
  const observedStatuses = [];

  for (const spec of specs) {
    if (actualRequestBytes(spec) > MAX_ACTUAL_REQUEST_BYTES) {
      // Defensive guard: never emit an oversize actual payload.
      continue;
    }
    const requestUrl = new URL(endpoint.url.href);
    if (spec.query) {
      for (const [name, value] of new URLSearchParams(spec.query)) {
        requestUrl.searchParams.append(name, value);
      }
    }
    requestsSent += 1;
    try {
      const resp = await requestFn(requestUrl.href, {
        method: spec.method,
        headers: spec.headers,
        body: spec.body,
        timeoutMs,
      }, deps);
      const status = Number(resp?.status) || 0;
      observedStatuses.push(status);
    } catch {
      observedStatuses.push(0);
      break;
    }
  }

  let externalResult = 'error';
  if (observedStatuses.some((status) => status > 0)) externalResult = 'connected';

  return {
    external_result: externalResult,
    metadata: {
      probe_kind: kind,
      marker_class: markerClass,
      probe_path: endpoint.path,
      observed_statuses: observedStatuses,
      classifier_version: 'capability-observation-v3',
      observation_only: true, readiness_conclusion: false, evidence_tier: 'E2',
      actual_uri_query_bytes: URI_MARKER_LENGTH,
      parser_limit_confirmed: false,
      declared_only: false,
      body_retained: false,
      request_counting_basis: 'logical_operations',
    },
    requests_sent: requestsSent,
    duration_ms: Date.now() - startedAt,
  };
}

export const L7_RESOURCE_PROBE_HANDLERS = Object.freeze({
  [L7_RESOURCE_POSTURE_PROBE_KIND]: probeL7ResourcePosture,
});
