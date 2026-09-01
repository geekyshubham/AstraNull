/**
 * L7 resource-exhaustion POSTURE probes (Wave 4, ticket W4-L7).
 *
 * These probes read *acceptance posture* only. They DECLARE an oversize/compressed
 * request via headers and send a single tiny inert benign marker — they never send a
 * decompression bomb, hash-collision payload, or flood. A protected origin rejects the
 * declared shape before doing work (413/414/415/431/400); an exposed origin accepts it.
 *
 * Hard-bounded by L7_RESOURCE_POSTURE_MAX_REQUESTS. No count, rate, concurrency, or
 * repeat parameter is exported. Response bodies are never retained.
 */

import { isLiveCapabilityProbeAuthorized } from '../capabilityProbeAuth.mjs';
import { normalizeProbeHttpPath } from '../../contracts/checks.mjs';
import { pinnedFetch } from '../pinnedHttpRequest.mjs';
import { BENIGN_CLASS_MARKERS } from '../outsideInWafScanner.mjs';

export const L7_RESOURCE_POSTURE_PROBE_KIND = 'l7_resource_posture_probe';

// Single hard bound on the number of requests this probe kind may ever send.
export const L7_RESOURCE_POSTURE_MAX_REQUESTS = 3;

export const L7_POSTURE_MARKER_CLASSES = Object.freeze([
  'declared_content_encoding',
  'declared_oversize_uri',
]);

const DEFAULT_TIMEOUT_MS = 5000;
const MAX_TIMEOUT_MS = 5000;

// Inert benign marker body. ~30 bytes; compresses ~1:1. Not a bomb.
export const INERT_POSTURE_MARKER_BODY = `${BENIGN_CLASS_MARKERS.xss}astranull-inert-posture`;

// Bounded benign URI marker used for the oversize-URI posture read. One small request.
const URI_MARKER_TOKEN = 'astranull-inert';
const URI_MARKER_LENGTH = 1024;

// DECLARED sizes are integers placed in a header string only — never materialised as bytes.
const DECLARED_DECOMPRESSED_BYTES = 52428800;
const DECLARED_URI_LENGTH = 65536;

// Absolute cap on the actual bytes any single request in this module may send.
export const MAX_ACTUAL_REQUEST_BYTES = 4096;

const ENFORCED_STATUSES = new Set([400, 413, 414, 415, 431]);

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
  const path = normalizeProbeHttpPath(probe_path);
  if (path) profile.probe_path = path;
  return profile;
}

function resolveEndpoint(job) {
  const target = job?.target ?? {};
  const path = normalizeProbeHttpPath(job?.probe_profile?.probe_path) ?? '/';
  let base;
  try {
    if (typeof target.url === 'string' && target.url) base = new URL(target.url);
    else if (typeof target.fqdn === 'string' && target.fqdn) base = new URL(`https://${target.fqdn}`);
    else return null;
  } catch {
    return null;
  }
  return { origin: base.origin, path };
}

// Each spec declares an oversize/compressed shape via headers only. `body` and `query`
// are always inert and bounded; `declared_*` values live exclusively inside header strings.
function requestSpecsForMarkerClass(markerClass) {
  if (markerClass === 'declared_content_encoding') {
    return [
      {
        method: 'POST',
        headers: {
          'content-encoding': 'gzip',
          'content-type': 'application/octet-stream',
          'x-astranull-declared-decompressed-bytes': String(DECLARED_DECOMPRESSED_BYTES),
          'x-astranull-probe': 'l7-resource-posture',
        },
        body: INERT_POSTURE_MARKER_BODY,
      },
      {
        method: 'POST',
        headers: {
          'content-encoding': 'br',
          'content-type': 'application/octet-stream',
          'x-astranull-declared-decompressed-bytes': String(DECLARED_DECOMPRESSED_BYTES),
          'x-astranull-probe': 'l7-resource-posture',
        },
        body: INERT_POSTURE_MARKER_BODY,
      },
    ];
  }
  return [
    {
      method: 'GET',
      query: `${URI_MARKER_TOKEN}=${'a'.repeat(URI_MARKER_LENGTH - URI_MARKER_TOKEN.length - 1)}`,
      headers: {
        'x-astranull-declared-uri-length': String(DECLARED_URI_LENGTH),
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
  const specs = requestSpecsForMarkerClass(markerClass).slice(0, L7_RESOURCE_POSTURE_MAX_REQUESTS);

  let requestsSent = 0;
  let enforced = false;
  let accepted = false;
  const observedStatuses = [];

  for (const spec of specs) {
    if (actualRequestBytes(spec) > MAX_ACTUAL_REQUEST_BYTES) {
      // Defensive guard: never emit an oversize actual payload.
      continue;
    }
    const url = spec.query
      ? `${endpoint.origin}${endpoint.path}?${spec.query}`
      : `${endpoint.origin}${endpoint.path}`;
    requestsSent += 1;
    try {
      const resp = await requestFn(url, {
        method: spec.method,
        headers: spec.headers,
        body: spec.body,
        timeoutMs,
      }, deps);
      const status = Number(resp?.status) || 0;
      observedStatuses.push(status);
      if (ENFORCED_STATUSES.has(status)) enforced = true;
      else if (status >= 100 && status < 400) accepted = true;
    } catch (error) {
      observedStatuses.push(0);
      void error;
    }
    if (enforced) break;
  }

  let externalResult = 'error';
  if (enforced) externalResult = 'blocked';
  else if (accepted) externalResult = 'connected';

  return {
    external_result: externalResult,
    metadata: {
      probe_kind: kind,
      marker_class: markerClass,
      probe_path: endpoint.path,
      observed_statuses: observedStatuses,
      declared_only: true,
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
