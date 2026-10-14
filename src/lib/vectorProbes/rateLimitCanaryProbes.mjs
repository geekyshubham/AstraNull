/**
 * Declared low-threshold rate-limit canary. GET/HEAD only, no body, no cache-buster.
 * Caps at threshold + 2 and stops at the first limited response.
 */

import {
  markerBaselineHealth,
  markerResponseSnapshot,
  readSignatureBody,
} from '../outsideInWafScanner.mjs';
import { gradeMarkerSnapshot, sameHostPath, urlWithPath, withSuspectedSignature } from './wafProbeSupport.mjs';

export const RATE_LIMIT_CANARY_PROBE_KIND = 'rate_limit_canary_probe';
export const RATE_LIMIT_CANARY_MAX_REQUESTS = 8;
export const RATE_LIMIT_CANARY_HARD_CAP = 12;

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_HEADERS = Object.freeze({
  accept: 'text/html,application/xhtml+xml',
  'accept-language': 'en-US,en;q=0.9',
});

export function readRateLimitCanary(profile = {}) {
  const canary = profile?.declarations?.waf?.rate_limit_canary
    ?? profile?.rate_limit_canary
    ?? null;
  if (!canary || typeof canary !== 'object' || Array.isArray(canary)) return null;
  const path = String(canary.path ?? '').trim();
  const method = String(canary.method ?? 'GET').toUpperCase();
  const threshold = Number(canary.threshold);
  const windowSeconds = Number(canary.window_seconds);
  if (!path.startsWith('/') || path.startsWith('//')) return null;
  if (method !== 'GET' && method !== 'HEAD') return null;
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > 10) return null;
  if (!Number.isInteger(windowSeconds) || windowSeconds < 1 || windowSeconds > 60) return null;
  return { path, method, threshold, window_seconds: windowSeconds };
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

async function fetchOnce(fetchFn, requestUrl, method, timeoutMs, declared) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchFn(requestUrl, {
      method,
      headers: { ...DEFAULT_HEADERS },
      redirect: 'manual',
      signal: controller.signal,
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

function canaryLegOf(snapshot, baseline) {
  if (snapshot?.transport_error) return { limited: null, allowed: false };
  if (snapshot.status_code === 429) return { limited: 'rate_limited', allowed: false };
  const retryAfter = snapshot?._headerGet?.('retry-after') ?? snapshot?.headers?.get?.('retry-after') ?? snapshot?.headers?.['retry-after'] ?? null;
  if (snapshot.status_code === 503 && retryAfter != null) return { limited: 'rate_limited', allowed: false };
  const graded = gradeMarkerSnapshot(snapshot, baseline);
  if (graded.blocked === true) return { limited: 'blocked', allowed: false };
  if (graded.challenged === true) return { limited: 'challenged', allowed: false };
  return { limited: null, allowed: graded.allowed === true };
}

export function rateLimitCanaryCap(threshold, maxRequests = RATE_LIMIT_CANARY_MAX_REQUESTS) {
  const declared = Number.isInteger(threshold) && threshold > 0 ? threshold + 2 : 0;
  const budget = Number.isInteger(maxRequests) && maxRequests > 0 ? maxRequests : RATE_LIMIT_CANARY_MAX_REQUESTS;
  return Math.min(declared, budget, RATE_LIMIT_CANARY_HARD_CAP);
}

export async function runRateLimitCanaryProbe(options = {}) {
  const url = String(options.url ?? '').trim();
  const canary = readRateLimitCanary(options.probe_profile ?? options);
  if (!url) return { error_class: 'unsupported_target', requests_sent: 0, phases: [] };
  if (!canary) {
    return {
      error_class: 'unsupported_target',
      reason: 'no_rate_limit_canary_declared',
      requests_sent: 0,
      threshold: null,
      window_seconds: null,
      first_limited_at: null,
      limited_outcome: null,
      source_penalized: false,
      phases: [],
    };
  }
  const fetchFn = options.fetchFn;
  if (typeof fetchFn !== 'function') {
    return { error_class: 'no_transport', requests_sent: 0, phases: [] };
  }
  const path = sameHostPath(url, canary.path);
  if (!path) {
    return {
      error_class: 'unsupported_target',
      reason: 'canary_path_not_same_host',
      requests_sent: 0,
      threshold: canary.threshold,
      window_seconds: canary.window_seconds,
      first_limited_at: null,
      limited_outcome: null,
      source_penalized: false,
      phases: [],
    };
  }

  const timeoutMs = Number.isInteger(options.timeout_ms) && options.timeout_ms > 0
    ? Math.min(options.timeout_ms, DEFAULT_TIMEOUT_MS)
    : DEFAULT_TIMEOUT_MS;
  const maxRequests = rateLimitCanaryCap(
    canary.threshold,
    Number.isInteger(options.max_requests) && options.max_requests > 0
      ? options.max_requests
      : RATE_LIMIT_CANARY_MAX_REQUESTS,
  );
  const declared = options.declared_block_signature ?? null;
  const requestUrl = urlWithPath(url, path);
  const windowMs = canary.window_seconds * 1000;
  const started = Date.now();
  const phases = [];
  let requestsSent = 0;
  let firstLimitedAt = null;
  let limitedOutcome = null;
  let allowedBeforeLimit = 0;
  let baseline = null;

  for (let i = 0; i < maxRequests; i += 1) {
    if (Date.now() - started >= windowMs) break;
    const snapshot = await fetchOnce(fetchFn, requestUrl, canary.method, timeoutMs, declared);
    requestsSent += 1;
    phases.push({ phase: `canary_${requestsSent}`, method: canary.method, status_code: snapshot.status_code });
    if (snapshot.transport_error) {
      return {
        error_class: 'transport_error',
        requests_sent: requestsSent,
        threshold: canary.threshold,
        window_seconds: canary.window_seconds,
        first_limited_at: firstLimitedAt,
        limited_outcome: limitedOutcome,
        source_penalized: false,
        phases,
      };
    }
    if (baseline == null) baseline = snapshot;
    const leg = canaryLegOf(snapshot, markerBaselineHealth(baseline) === 'healthy' ? baseline : null);
    if (leg.limited) {
      firstLimitedAt = requestsSent;
      limitedOutcome = leg.limited;
      break;
    }
    if (leg.allowed) allowedBeforeLimit += 1;
  }

  return {
    threshold: canary.threshold,
    window_seconds: canary.window_seconds,
    requests_sent: requestsSent,
    first_limited_at: firstLimitedAt,
    limited_outcome: limitedOutcome,
    allowed_before_limit: allowedBeforeLimit,
    source_penalized: false,
    max_requests: maxRequests,
    canary_path: path,
    canary_method: canary.method,
    cache_buster: false,
    phases,
  };
}
