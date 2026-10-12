/**
 * Full P0/P1 capability probes — bounded, metadata-only results, no flooding.
 */

import dns, { Resolver } from 'node:dns/promises';
import {
  ALLOWED_PROBE_HTTP_METHODS,
  normalizeProbeHttpPath,
} from '../contracts/checks.mjs';
import https from 'node:https';
import http2 from 'node:http2';
import net from 'node:net';
import tls from 'node:tls';
import { isLiveCapabilityProbeAuthorized } from './capabilityProbeAuth.mjs';
import { pinnedFetch, pinnedHttp2Request, resolvePinnedDestination } from './pinnedHttpRequest.mjs';
import { startProbeIoAttempt } from './probeAttempt.mjs';
import {
  CANARY_NONCE_REQUEST_HEADER,
  classifyDirectOriginObservation,
  matchControlDenialSignature,
} from './externalObservationOutcomes.mjs';
import { OBSERVATION_ONLY_PROBE_KINDS } from './probeEvidenceTiers.mjs';
import { probeQuicReachability } from './safeNetworkProbes.mjs';
import {
  API_DOC_PATHS,
  RISKY_ADMIN_PORTS,
} from './probeEndpoint.mjs';
import {
  resolveBoundedSequenceBudget,
  resolveProbeRequestBudget,
} from './probeRequestBudget.mjs';
import { runDnsTcpAxfrQuery } from './dnsTcpAxfrSession.mjs';
import { probeDnsWireQuery } from './dnsWireQuery.mjs';
import {
  BENIGN_CLASS_MARKERS,
  OUTSIDE_IN_SCAN_DEFAULT_BUDGET,
  readBoundedResponseBody,
  readSignatureBody,
  signatureBodyComplete,
  runOutsideInWafScan,
} from './outsideInWafScanner.mjs';
import { enrichProbeMetadataWithWafCatalog } from './wafProductCatalog.mjs';
import { classifyEdgeFingerprint, EDGE_SIGNATURE_CORPUS_VERSION } from './edgeFingerprint.mjs';
import {
  WAF_CLASS_PROBE_MAX_REQUESTS,
  runWafClassMarkerProbe as runRawWafClassMarkerProbe,
} from './vectorProbes/wafClassProbes.mjs';
import {
  MAX_WAF_EVASION_MARKER_REQUESTS,
  isEvasionTransform,
  isSupportedEvasionTransform,
  runWafEvasionMarkerProbe as runRawWafEvasionMarkerProbe,
} from './vectorProbes/evasionProbes.mjs';
import {
  L7_RESOURCE_POSTURE_MAX_REQUESTS,
  probeL7ResourcePosture as runRawL7ResourcePostureProbe,
} from './vectorProbes/l7ResourceProbes.mjs';

export const BOUNDED_SUBDOMAIN_PREFIXES = Object.freeze([
  'www', 'api', 'admin', 'dev', 'staging', 'test', 'old', 'legacy', 'direct', 'origin', 'cdn', 'internal',
]);

// Declared in probeEndpoint.mjs (a leaf module) to keep the job-signing validators
// cycle-free; re-exported here so existing importers keep working. These must be
// imported (above) as well as re-exported — `export ... from` alone would leave the
// names unbound inside this module.
export { API_DOC_PATHS, RISKY_ADMIN_PORTS };

const WEAK_TLS_PROTOCOLS = new Set(['TLSv1', 'TLSv1.1', 'SSLv3']);
const DEFAULT_PROBE_TIMEOUT_MS = 5000;
const NANOSECONDS_PER_MILLISECOND = 1_000_000n;

// These profiles cannot produce their advertised result with fewer operations and their
// implementations may conditionally reach every operation listed here. Keep this in the
// leaf capability module so signing and worker execution share one floor.
export const MINIMUM_REQUESTS_BY_PROBE_KIND = Object.freeze({
  origin_leak_scan: 3, // apex A + apex AAAA + edge HEAD
  dns_axfr_leak: 2, // NS lookup + one TCP AXFR query
});

export function minimumProbeRequestsForKind(kind) {
  return MINIMUM_REQUESTS_BY_PROBE_KIND[kind] ?? 1;
}

function configuredProbeTimeoutMs(job) {
  const candidate = Number(job?.constraints?.timeout_ms ?? job?.probe_profile?.timeout_ms);
  return Number.isSafeInteger(candidate) && candidate > 0
    ? candidate
    : DEFAULT_PROBE_TIMEOUT_MS;
}

function ceilElapsedMilliseconds(startedNs) {
  const elapsedNs = process.hrtime.bigint() - startedNs;
  return Number((elapsedNs + NANOSECONDS_PER_MILLISECOND - 1n) / NANOSECONDS_PER_MILLISECOND);
}

function ensureProbeDeadline(job, deps = {}) {
  if (
    typeof deps.remainingJobTimeoutMs === 'function'
    && typeof deps.observedJobDurationMs === 'function'
  ) {
    return deps;
  }
  const startedNs = process.hrtime.bigint();
  const timeoutMs = configuredProbeTimeoutMs(job);
  const deadlineNs = startedNs + BigInt(timeoutMs) * NANOSECONDS_PER_MILLISECOND;
  return {
    ...deps,
    remainingJobTimeoutMs: () => {
      const remainingNs = deadlineNs - process.hrtime.bigint();
      return remainingNs > 0n
        ? Number(remainingNs / NANOSECONDS_PER_MILLISECOND)
        : 0;
    },
    observedJobDurationMs: () => ceilElapsedMilliseconds(startedNs),
  };
}

function remainingProbeTimeoutMs(job, deps = {}) {
  if (deps.jobDeadlineSignal?.aborted) return 0;
  const configured = configuredProbeTimeoutMs(job);
  if (typeof deps.remainingJobTimeoutMs !== 'function') return configured;
  const remaining = Number(deps.remainingJobTimeoutMs());
  if (!Number.isFinite(remaining) || remaining <= 0) return 0;
  return Math.min(configured, Math.floor(remaining));
}

function observedProbeDurationMs(deps, startedMs = Date.now()) {
  if (typeof deps.observedJobDurationMs === 'function') {
    return deps.observedJobDurationMs();
  }
  return Math.ceil(Date.now() - startedMs);
}

function probeDeadlineError() {
  const error = new Error('Signed probe job deadline elapsed.');
  error.name = 'AbortError';
  error.code = 'probe_job_deadline_exceeded';
  return error;
}

function isProbeDeadlineError(error, deps = {}) {
  return deps.jobDeadlineSignal?.aborted
    || error?.code === 'probe_job_deadline_exceeded'
    || error?.name === 'AbortError';
}

const AUTHORITATIVE_DNS_NEGATIVE_CODES = new Set(['ENODATA', 'ENOTFOUND']);
const EXECUTABLE_SAFE_HTTP_METHODS = new Set(ALLOWED_PROBE_HTTP_METHODS);

function dnsResolverErrorClass(error) {
  const explicit = String(error?.code ?? '').trim().toUpperCase();
  if (explicit) return explicit;
  const message = String(error?.message ?? '').toUpperCase();
  return message.match(/\bE[A-Z0-9_]+\b/)?.[0] ?? error?.name ?? 'dns_resolver_failure';
}

function isAuthoritativeDnsNegative(error) {
  return AUTHORITATIVE_DNS_NEGATIVE_CODES.has(dnsResolverErrorClass(error));
}

function isOperationBudgetError(error) {
  return error?.code === 'signed_operation_budget_exceeded';
}

function dnsResolverFailureOutcome(job, kind, deps, requestsSent, error, metadata = {}) {
  if (isOperationBudgetError(error)) throw error;
  if (isProbeDeadlineError(error, deps)) {
    return deadlineOutcome(job, kind, deps, requestsSent, metadata);
  }
  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: 'error',
    metadata: withKind(job, kind, {
      ...metadata,
      error_class: dnsResolverErrorClass(error),
      resolver_attempts: requestsSent,
      request_counting_basis: 'logical_operations',
      duration_ms: durationMs,
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

function recordProbeLogicalAttempt(deps, operation) {
  deps.recordProbeLogicalAttempt?.(operation);
}

async function withinRemainingProbeTime(promise, job, deps) {
  const observed = Promise.resolve(promise);
  const timeoutMs = remainingProbeTimeoutMs(job, deps);
  if (timeoutMs <= 0) {
    void observed.catch(() => {});
    throw probeDeadlineError();
  }
  let timer;
  return Promise.race([
    observed,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(probeDeadlineError()), timeoutMs);
    }),
  ]).finally(() => clearTimeout(timer));
}

function mandatoryBudgetFailure(job, kind) {
  const requiredRequests = minimumProbeRequestsForKind(kind);
  const effectiveBudget = resolveProbeRequestBudget(job);
  const profileBudget = job?.probe_profile?.max_requests;
  if (
    effectiveBudget >= requiredRequests
    && (!Number.isInteger(profileBudget) || profileBudget >= requiredRequests)
  ) {
    return null;
  }
  return {
    external_result: 'error',
    metadata: withKind(job, kind, {
      error_class: 'signed_request_budget_below_mandatory_floor',
      required_requests: requiredRequests,
      signed_max_requests: effectiveBudget,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: 0,
    duration_ms: 1,
  };
}

function deadlineOutcome(job, kind, deps, requestsSent, metadata = {}) {
  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: requestsSent > 0 ? 'timeout' : 'error',
    metadata: withKind(job, kind, {
      ...metadata,
      error_class: 'probe_job_deadline_exceeded',
      duration_ms: durationMs,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

export const CAPABILITY_OBSERVATION_VERSION = 'capability-observation-v3';
function withKind(job, kind, metadata) {
  const observationOnly = OBSERVATION_ONLY_PROBE_KINDS.includes(kind) || Boolean(metadata?.error_class);
  return { profile_kind: kind, probe_kind: kind, classifier_version: CAPABILITY_OBSERVATION_VERSION,
    ...metadata, ...(observationOnly ? {
      observation_only: true, readiness_conclusion: false, evidence_tier: 'E2',
      assurance_limits: 'Bounded external observations; no capacity, exploit mitigation or policy assurance.',
    } : {}) };
}


function apexDomain(job) {
  const value = String(job.target?.value ?? '').trim();
  if (!value) return null;
  if (/^https?:\/\//i.test(value)) {
    try {
      return new URL(value).hostname || null;
    } catch {
      return null;
    }
  }
  const withoutPath = value.split('/')[0];
  const bracketedIpv6 = withoutPath.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (bracketedIpv6) return bracketedIpv6[1];
  if (net.isIP(withoutPath)) return withoutPath;
  const hostPort = withoutPath.match(/^([^:]+):(\d+)$/);
  return (hostPort ? hostPort[1] : withoutPath) || null;
}

const BOUND_SCOPE_HOSTNAME_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function isBoundScopeHostname(value) {
  const hostname = value.endsWith('.') ? value.slice(0, -1) : value;
  if (
    !hostname
    || hostname.includes('://')
    || hostname.includes('@')
    || hostname.includes('/')
    || hostname.includes(':')
    || /\s/.test(hostname)
  ) {
    return false;
  }
  const labels = hostname.split('.');
  return labels.every((label) => label.length > 0 && BOUND_SCOPE_HOSTNAME_LABEL.test(label));
}

function isBoundScopePathValue(value) {
  return (
    typeof value !== 'string'
    || !value.startsWith('/')
    || value.startsWith('//')
    || value.includes('\\')
    || value.includes('@')
    || value.includes('?')
    || value.includes('#')
    || value.includes('://')
    || /[\u0000-\u0020\u007f]/.test(value)
    || value.length > 256
  );
}

/**
 * Exact approved origin scope of a signed bound probe job.
 *
 * The control plane signs `constraints.origin_scope` ({host, sni, port, path}) from the
 * server-validated binding derivation at run start — never from request or target metadata.
 * Only a shape-valid, self-consistent snapshot is consumed here. Authority-v2 or an
 * explicitly supplied malformed scope fails closed before I/O; no metadata fallback.
 *
 * @param {Record<string, unknown> | null | undefined} job
 * @returns {{ host: string, sni: string, port: number | null, path: string | null } | null}
 */
export function approvedSignedOriginScope(job) {
  if (job?.probe_profile?.kind !== 'host_sni_bypass') return null;
  const scope = job?.constraints?.origin_scope;
  if (!scope || typeof scope !== 'object' || Array.isArray(scope)) return null;
  const normalize = (value) => (typeof value === 'string' ? value.trim().toLowerCase() : null);
  const host = normalize(scope.host);
  const sni = normalize(scope.sni);
  if (!host || !sni || host !== sni || !isBoundScopeHostname(host)) return null;
  let port = null;
  if (scope.port != null) {
    if (typeof scope.port !== 'number') return null;
    port = scope.port;
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  }
  if (scope.path != null && isBoundScopePathValue(scope.path)) return null;
  const path = scope.path == null ? null : scope.path;
  return { host, sni, port, path };
}

function boundScopeRequestUrl(url, scope) {
  const rebuilt = new URL(url.toString());
  rebuilt.search = '';
  rebuilt.pathname = scope.path || '/';
  rebuilt.port = scope.port != null ? String(scope.port) : '';
  return rebuilt.toString();
}

function resolveHostSniTargets(job) {
  const targetValue = String(job.target?.value ?? '').trim();
  const approvedScope = approvedSignedOriginScope(job);
  let hostname = job.probe_profile?.protected_host ?? apexDomain(job);
  let hostHeader = hostname;
  let directIp = job.probe_profile?.direct_ip ?? job.target?.metadata?.direct_origin_ip ?? null;
  let requestUrl = null;
  let requestPort = null;
  let requestPath = '/';

  if (targetValue.startsWith('http')) {
    try {
      const url = new URL(targetValue);
      if (!job.probe_profile?.protected_host) {
        hostname = url.hostname;
        hostHeader = url.host;
      }
      requestPort = url.port ? Number(url.port) : null;
      requestPath = `${url.pathname || '/'}${url.search || ''}`;
      if (!directIp && /^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname)) {
        directIp = url.hostname;
        requestUrl = approvedScope ? boundScopeRequestUrl(url, approvedScope) : targetValue;
      }
    } catch {
      // ignore malformed URL targets
    }
  }
  if (!directIp && job.target?.kind === 'ip') {
    directIp = targetValue;
  }
  if (approvedScope) {
    // Bound run: the signed approved scope is the exact protected Host/SNI and port/path.
    // An untrusted probe profile or target URL cannot retarget the logical application
    // layer; the socket destination itself remains the independently verified,
    // target-bound origin address resolved below.
    hostname = approvedScope.host;
    const defaultPort = targetValue.startsWith('http://') ? 80 : 443;
    hostHeader = approvedScope.port != null && approvedScope.port !== defaultPort
      ? `${approvedScope.host}:${approvedScope.port}` : approvedScope.host;
    requestPort = approvedScope.port;
    requestPath = approvedScope.path ?? '/';
  }
  return { hostname, hostHeader, directIp, requestUrl, requestPort, requestPath };
}

function canonicalDnsHostname(value) {
  const candidate = String(value ?? '').trim().toLowerCase();
  if (!candidate) return null;
  return candidate.endsWith('.') ? candidate.slice(0, -1) : candidate;
}

function isExactDnsHostname(value, expected) {
  const candidate = canonicalDnsHostname(value);
  return candidate != null && candidate === canonicalDnsHostname(expected);
}

function baseUrlForHost(host, https = true) {
  const literal = String(host ?? '').replace(/^\[|\]$/g, '');
  const authority = net.isIP(literal) === 6 ? `[${literal}]` : host;
  return `${https ? 'https' : 'http'}://${authority}/`;
}

function httpsHeadWithSni(directIp, hostname, {
  hostHeader = hostname,
  headers = {},
  timeoutMs = 5000,
  port,
  path = '/',
} = {}, deps = {}, onReserved) {
  const requestFn = deps.httpsRequestFn ?? https.request;
  return new Promise((resolve, reject) => {
    let req;
    let settled = false;
    let timer;
    const signal = deps.jobDeadlineSignal;
    const finish = (result, destroy = false) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      req?.removeListener?.('timeout', onAbort);
      if (destroy) req?.destroy?.();
      resolve(result);
    };
    const onAbort = () => finish({ res: null, error: probeDeadlineError() }, true);
    const onError = (error) => finish({ res: null, error }, true);
    if (signal?.aborted || timeoutMs <= 0) return onAbort();
    try {
      req = startProbeIoAttempt(deps, 'https_head', () => requestFn({
        host: directIp, ...(port != null ? { port } : {}),
        servername: hostname, path, method: 'HEAD',
        headers: { Host: hostHeader, ...headers }, timeout: timeoutMs,
        rejectUnauthorized: false,
      }, (res) => {
        res.resume();
        finish({ res: { status: res.statusCode ?? 0,
          headers: { get: (name) => res.headers[String(name).toLowerCase()] ?? null },
        }, error: null });
      }), onReserved);
      req.on('error', onError);
      req.once?.('close', () => req.removeListener?.('error', onError));
      if (settled) { req.destroy?.(); return; }
      req.on('timeout', onAbort);
      signal?.addEventListener('abort', onAbort, { once: true });
      timer = setTimeout(onAbort, timeoutMs);
      if (signal?.aborted) return onAbort();
      req.end();
    } catch (error) {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      req?.destroy?.();
      reject(error);
    }
  });
}

function directHttpProbeUrl(directIp, port, path = '/') {
  const host = String(directIp).includes(':') && !String(directIp).startsWith('[')
    ? `[${directIp}]`
    : directIp;
  return `http://${host}${port != null ? `:${port}` : ''}${path || '/'}`;
}

async function boundedFetch(url, options = {}, deps = {}) {
  const fetchFn = deps.fetchFn ?? ((input, init) => pinnedFetch(input, init, deps));
  const requestedTimeoutMs = options.timeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS;
  const deadlineRemainingMs = typeof deps.remainingJobTimeoutMs === 'function'
    ? Number(deps.remainingJobTimeoutMs())
    : requestedTimeoutMs;
  const timeoutMs = Math.min(requestedTimeoutMs, Math.floor(deadlineRemainingMs));
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || deps.jobDeadlineSignal?.aborted) {
    return { res: null, error: probeDeadlineError(), attempted: false };
  }
  const controller = new AbortController();
  const upstreamSignal = deps.jobDeadlineSignal;
  const abortFromUpstream = () => controller.abort(probeDeadlineError());
  if (upstreamSignal) upstreamSignal.addEventListener('abort', abortFromUpstream, { once: true });
  const timer = setTimeout(() => controller.abort(probeDeadlineError()), timeoutMs);
  let rejectOnAbort;
  const aborted = new Promise((_, reject) => {
    rejectOnAbort = () => reject(
      controller.signal.reason instanceof Error
        ? controller.signal.reason
        : Object.assign(new Error('timeout'), { name: 'AbortError' }),
    );
    controller.signal.addEventListener('abort', rejectOnAbort, { once: true });
  });
  let attempted = false;
  try {
    const request = startProbeIoAttempt(
      deps,
      'http',
      () => fetchFn(url, {
        ...options.fetchOptions,
        signal: controller.signal,
      }),
      () => { attempted = true; },
    );
    const res = await Promise.race([Promise.resolve(request), aborted]);
    return { res, error: null, attempted };
  } catch (err) {
    if (!attempted && (isOperationBudgetError(err) || isProbeDeadlineError(err, deps))) throw err;
    return { res: null, error: err, attempted };
  } finally {
    clearTimeout(timer);
    controller.signal.removeEventListener('abort', rejectOnAbort);
    upstreamSignal?.removeEventListener('abort', abortFromUpstream);
  }
}

function classifyFetchError(err, { reachability = false } = {}) {
  const name = err?.name ?? '';
  const code = err?.code ?? '';
  if (name === 'AbortError' || code === 'probe_job_deadline_exceeded') return 'timeout';
  if (
    reachability
    && (code === 'ECONNREFUSED' || code === 'ENOTFOUND' || code === 'EHOSTUNREACH')
  ) {
    return 'error';
  }
  return 'error';
}

const ORIGIN_EDGE_HTTP_ERROR_CLASSES = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENOTFOUND',
  'EAI_AGAIN',
  'ETIMEDOUT',
  'UND_ERR_CONNECT_TIMEOUT',
]);

function boundedOriginEdgeHttpErrorClass(error) {
  const code = String(error?.code ?? '').trim().toUpperCase();
  return ORIGIN_EDGE_HTTP_ERROR_CLASSES.has(code) ? code : 'edge_http_transport_error';
}

async function resolve4(host, deps) {
  const fn = deps.resolve4Fn ?? dns.resolve4;
  if (typeof deps.remainingJobTimeoutMs === 'function' && deps.remainingJobTimeoutMs() <= 0) {
    throw probeDeadlineError();
  }
  try {
    return await withinRemainingProbeTime(
      startProbeIoAttempt(deps, 'dns_a', () => fn(host)),
      { constraints: { timeout_ms: DEFAULT_PROBE_TIMEOUT_MS } },
      deps,
    );
  } catch (error) {
    if (isProbeDeadlineError(error, deps) || isOperationBudgetError(error)) throw error;
    if (isAuthoritativeDnsNegative(error)) return [];
    throw error;
  }
}

export const OUTSIDE_IN_CNAME_HOPS_MAX = 3;

/**
 * cdncheck-style CNAME chain for the vetted host. Each hop is one counted logical operation;
 * ENODATA/ENOTFOUND ends the chain and any other resolver failure leaves the chain as observed.
 */
async function resolveCnameChain(host, deps, maxHops) {
  const fn = deps.resolveCnameFn ?? dns.resolveCname;
  const chain = [String(host ?? '').trim().toLowerCase().replace(/\.$/, '')];
  let lookups = 0;
  while (lookups < maxHops) {
    if (typeof deps.remainingJobTimeoutMs === 'function' && deps.remainingJobTimeoutMs() <= 0) break;
    lookups += 1;
    let next = null;
    try {
      const answers = await withinRemainingProbeTime(
        startProbeIoAttempt(deps, 'dns_cname', () => fn(chain[chain.length - 1])),
        { constraints: { timeout_ms: DEFAULT_PROBE_TIMEOUT_MS } },
        deps,
      );
      next = String(answers?.[0] ?? '').trim().toLowerCase().replace(/\.$/, '');
    } catch (error) {
      if (isOperationBudgetError(error)) throw error;
      break;
    }
    if (!next || chain.includes(next)) break;
    chain.push(next);
    deps.onCnameObservation?.(chain);
  }
  return { chain, lookups };
}

async function resolve6(host, deps) {
  const fn = deps.resolve6Fn ?? dns.resolve6;
  if (typeof deps.remainingJobTimeoutMs === 'function' && deps.remainingJobTimeoutMs() <= 0) {
    throw probeDeadlineError();
  }
  try {
    return await withinRemainingProbeTime(
      startProbeIoAttempt(deps, 'dns_aaaa', () => fn(host)),
      { constraints: { timeout_ms: DEFAULT_PROBE_TIMEOUT_MS } },
      deps,
    );
  } catch (error) {
    if (isProbeDeadlineError(error, deps) || isOperationBudgetError(error)) throw error;
    if (isAuthoritativeDnsNegative(error)) return [];
    throw error;
  }
}

async function resolveNs(zone, deps) {
  const fn = deps.resolveNsFn ?? dns.resolveNs;
  if (typeof deps.remainingJobTimeoutMs === 'function' && deps.remainingJobTimeoutMs() <= 0) {
    throw probeDeadlineError();
  }
  try {
    return await withinRemainingProbeTime(
      startProbeIoAttempt(deps, 'dns_ns', () => fn(zone)),
      { constraints: { timeout_ms: DEFAULT_PROBE_TIMEOUT_MS } },
      deps,
    );
  } catch (error) {
    if (isProbeDeadlineError(error, deps) || isOperationBudgetError(error)) throw error;
    if (isAuthoritativeDnsNegative(error)) return [];
    throw error;
  }
}

/**
 * Per-destination guard for probes that egress to a host the worker chokepoint cannot
 * vet (a nameserver discovered mid-probe, or a profile-declared resolver).
 *
 * IP literals are classified directly. Hostnames are resolved first and every resulting
 * address must pass; zero A/AAAA answers fail closed. `requireIpLiteral` is for destinations
 * that must be a literal by construction (dns.Resolver#setServers).
 *
 * @param {string} host
 * @param {Record<string, unknown>} deps
 * @param {{ requireIpLiteral?: boolean }} [options]
 */
async function vetProbeDestinationHost(host, deps = {}, options = {}) {
  const candidate = typeof host === 'string' ? host.trim() : '';
  if (!candidate) return { ok: false, reason: 'missing_host', addresses: [] };
  if (options.requireIpLiteral === true && net.isIP(candidate) === 0) {
    return { ok: false, reason: 'not_an_ip_literal', addresses: [] };
  }

  try {
    const pinned = await withinRemainingProbeTime(
      resolvePinnedDestination(candidate, deps),
      { constraints: { timeout_ms: DEFAULT_PROBE_TIMEOUT_MS } },
      deps,
    );
    return { ok: true, host: pinned.host, addresses: pinned.addresses };
  } catch (error) {
    if (isProbeDeadlineError(error, deps) || error?.code === 'signed_operation_budget_exceeded') {
      throw error;
    }
    const errorClass = dnsResolverErrorClass(error);
    return {
      ok: false,
      host: candidate,
      addresses: [],
      error_class: errorClass,
      reason: errorClass === 'ENOTFOUND'
        ? 'no_resolved_addresses'
        : 'destination_resolution_failed',
      blocked_address: error?.blockedAddress ?? null,
    };
  }
}

function tcpConnectProbe(host, port, timeoutMs, connectFn = net.connect, deps = {}, onReserved) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = startProbeIoAttempt(
      deps,
      'tcp_connect',
      () => connectFn({ host, port, timeout: timeoutMs }),
      onReserved,
    );
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve('timeout');
    }, timeoutMs);
    socket.once('connect', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.end();
      resolve('open');
    });
    socket.once('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const code = err?.code ?? '';
      if (code === 'ECONNREFUSED') resolve('closed');
      else if (code === 'ETIMEOUT') resolve('timeout');
      else resolve('filtered');
    });
  });
}

/**
 * P0 — Origin leak: DNS A/AAAA, bounded subdomains, IPv6 vs edge path signals.
 */
export async function probeOriginLeakScan(job, deps = {}) {
  const kind = 'origin_leak_scan';
  const domain = apexDomain(job);
  if (!domain) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  deps = ensureProbeDeadline(job, deps);
  const budgetFailure = mandatoryBudgetFailure(job, kind);
  if (budgetFailure) return budgetFailure;

  const budget = resolveProbeRequestBudget(job);
  let requestsSent = 0;
  let resolverAttempts = 0;
  let httpAttempts = 0;
  const leak_signals = [];
  const corroborated_leak_signals = [];
  const subdomain_divergences = [];
  const subdomains_scanned = [];
  const origin_ips = new Set();
  const ipv6_addrs = new Set();
  let apex4 = [];
  let edgeProbe = { res: null, error: null, attempted: false };

  const timeout = () => deadlineOutcome(job, kind, deps, requestsSent, {
    apex_domain: domain,
    origin_ips: [...origin_ips].slice(0, 8),
    ipv6_addrs: [...ipv6_addrs].slice(0, 8),
    subdomains_scanned,
    leak_signals,
    leak_count: corroborated_leak_signals.length,
    corroborated_leak_signals,
    observed_signal_count: leak_signals.length,
    resolver_attempts: resolverAttempts,
    http_attempts: httpAttempts,
  });

  if (remainingProbeTimeoutMs(job, deps) <= 0) return timeout();
  requestsSent += 1;
  resolverAttempts += 1;
  try {
    apex4 = await resolve4(domain, deps);
  } catch (error) {
    return dnsResolverFailureOutcome(job, kind, deps, requestsSent, error, {
      apex_domain: domain,
      resolver_attempts: resolverAttempts,
      http_attempts: httpAttempts,
      subdomains_scanned,
      leak_signals,
    });
  }
  apex4.forEach((ip) => origin_ips.add(ip));
  if (remainingProbeTimeoutMs(job, deps) <= 0) return timeout();

  let apex6;
  requestsSent += 1;
  resolverAttempts += 1;
  try {
    apex6 = await resolve6(domain, deps);
  } catch (error) {
    return dnsResolverFailureOutcome(job, kind, deps, requestsSent, error, {
      apex_domain: domain,
      origin_ips: [...origin_ips].slice(0, 8),
      resolver_attempts: resolverAttempts,
      http_attempts: httpAttempts,
      subdomains_scanned,
      leak_signals,
    });
  }
  apex6.forEach((ip) => ipv6_addrs.add(ip));
  // Observation only: an IPv6-only apex is common, legitimate dual-stack/CDN behavior on its
  // own. It becomes a leak signal only once corroborated against the edge_ip below.
  const ipv6OnlyDns = apex6.length > 0 && apex4.length === 0;
  if (remainingProbeTimeoutMs(job, deps) <= 0) return timeout();

  edgeProbe = await boundedFetch(baseUrlForHost(domain), {
    timeoutMs: remainingProbeTimeoutMs(job, deps),
    fetchOptions: { method: 'HEAD', redirect: 'manual' },
  }, deps);
  if (edgeProbe.attempted) {
    requestsSent += 1;
    httpAttempts += 1;
  }
  if (!edgeProbe.attempted || isProbeDeadlineError(edgeProbe.error, deps)) return timeout();
  if (edgeProbe.error) {
    const durationMs = observedProbeDurationMs(deps);
    return {
      external_result: 'error',
      metadata: withKind(job, kind, {
        error_class: boundedOriginEdgeHttpErrorClass(edgeProbe.error),
        duration_ms: durationMs,
        apex_domain: domain,
        origin_ips: [...origin_ips].slice(0, 8),
        ipv6_addrs: [...ipv6_addrs].slice(0, 8),
        subdomains_scanned: [],
        leak_signals: [],
        leak_count: 0,
        resolver_attempts: resolverAttempts,
        http_attempts: httpAttempts,
        request_counting_basis: 'logical_operations',
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  }

  let edge_ip = null;
  if (edgeProbe.res) {
    edge_ip = edgeProbe.res.headers.get('x-backend-ip') ?? null;
  }

  for (const prefix of BOUNDED_SUBDOMAIN_PREFIXES) {
    if (requestsSent >= budget) break;
    if (remainingProbeTimeoutMs(job, deps) <= 0) return timeout();
    const host = `${prefix}.${domain}`;
    subdomains_scanned.push(host);
    requestsSent += 1;
    resolverAttempts += 1;
    let ips;
    try {
      ips = await resolve4(host, deps);
    } catch (error) {
      return dnsResolverFailureOutcome(job, kind, deps, requestsSent, error, {
        apex_domain: domain,
        origin_ips: [...origin_ips].slice(0, 8),
        ipv6_addrs: [...ipv6_addrs].slice(0, 8),
        resolver_attempts: resolverAttempts,
        http_attempts: httpAttempts,
        subdomains_scanned,
        leak_signals,
      });
    }
    if (ips.length > 0) {
      ips.forEach((ip) => origin_ips.add(ip));
      const unique = [...new Set(ips)];
      if (apex4.length && unique.some((ip) => !apex4.includes(ip))) {
        // Observation only here too: an alternate hostname resolving to a different address
        // than the apex can be legitimate CDN/load-balancer routing. It is corroborated below
        // only when that address is distinct from the apex's own observed edge_ip.
        subdomain_divergences.push({ prefix, ips: unique });
      }
    }
    if (remainingProbeTimeoutMs(job, deps) <= 0) return timeout();
  }

  const directIps = [...origin_ips];
  const edgeMismatch = Boolean(directIps.length && edge_ip && directIps.includes(edge_ip) === false);
  if (edgeMismatch) {
    leak_signals.push('dns_points_not_edge');
  }
  if (directIps.length && !edgeProbe.res) {
    leak_signals.push('dns_only_no_edge_http');
  }

  // Corroboration: an IPv6-only apex or a divergent subdomain address is treated as a leak
  // signal only when there is an independent indication the address is not the CDN edge —
  // i.e. we observed an edge_ip and the divergent/IPv6 address does not match it. Without an
  // edge_ip to compare against, these remain recorded observations, not leak claims.
  if (ipv6OnlyDns) {
    leak_signals.push('ipv6_only_dns');
    if (edge_ip && ![...ipv6_addrs].includes(edge_ip)) {
      corroborated_leak_signals.push('ipv6_only_dns');
    }
  }
  for (const { prefix, ips } of subdomain_divergences) {
    const signal = `subdomain_origin_divergence:${prefix}`;
    leak_signals.push(signal);
    if (edge_ip && ips.every((ip) => ip !== edge_ip)) {
      corroborated_leak_signals.push(signal);
    }
  }
  if (edgeMismatch) corroborated_leak_signals.push('dns_points_not_edge');

  const durationMs = observedProbeDurationMs(deps);
  const external = corroborated_leak_signals.length > 0 ? 'connected' : 'blocked';
  return {
    external_result: external,
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      apex_domain: domain,
      origin_ips: directIps.slice(0, 8),
      ipv6_addrs: [...ipv6_addrs].slice(0, 8),
      subdomains_scanned,
      leak_signals,
      leak_count: corroborated_leak_signals.length,
      corroborated_leak_signals,
      observed_signal_count: leak_signals.length,
      resolver_attempts: resolverAttempts,
      http_attempts: httpAttempts,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

/**
 * P0 — CDN/WAF bypass: HTTPS to direct IP with TLS SNI + Host of protected hostname.
 * Injectable deps.fetchFn uses HTTP+Host for bounded test/verification consumers.
 */
export async function probeHostSniBypass(job, deps = {}) {
  const kind = 'host_sni_bypass';
  if ((job?.constraints?.origin_scope != null || job?.constraints?.authority_version === 'probe-authority-v2') && !approvedSignedOriginScope(job)) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'invalid_signed_origin_scope', readiness_conclusion: false, observation_only: true }), requests_sent: 0, duration_ms: 0 };
  }
  const { hostname, hostHeader, directIp, requestUrl, requestPort, requestPath } = resolveHostSniTargets(job);
  if (!hostname || !directIp) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'missing_direct_ip_or_host' }), requests_sent: 0, duration_ms: 0 };
  }

  deps = ensureProbeDeadline(job, deps);
  const directDestination = await vetProbeDestinationHost(directIp, deps);
  if (remainingProbeTimeoutMs(job, deps) <= 0) {
    return deadlineOutcome(job, kind, deps, 0, { protected_host: hostname, direct_ip: directIp });
  }
  if (!directDestination.ok || directDestination.addresses.length === 0) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, {
        error_class: 'direct_destination_not_routable',
        protected_host: hostname,
        direct_ip: directIp,
        blocked_address: directDestination.blocked_address ?? null,
        reason: directDestination.reason ?? 'no_resolved_addresses',
      }),
      requests_sent: 0,
      duration_ms: observedProbeDurationMs(deps),
    };
  }
  const pinnedDirectIp = directDestination.addresses[0];
  const headers = {
    Host: hostHeader,
    ...(job.nonce ? { 'x-astranull-nonce': job.nonce } : {}),
    ...(job.probe_profile?.marker ? { 'x-astranull-marker': String(job.probe_profile.marker) } : {}),
  };
  const hasInjectedFetch = typeof deps.fetchFn === 'function';
  const useHttps = !hasInjectedFetch && job.probe_profile?.use_https !== false && !requestUrl;
  const timeoutMs = remainingProbeTimeoutMs(job, deps);
  let attempted = false;
  let res;
  let error;
  if (useHttps) {
    ({ res, error } = await httpsHeadWithSni(pinnedDirectIp, hostname, {
      headers,
      hostHeader,
      timeoutMs,
      port: requestPort,
      path: requestPath,
    }, deps, () => { attempted = true; }));
  } else {
    const outcome = await boundedFetch(
      requestUrl ?? directHttpProbeUrl(pinnedDirectIp, requestPort, requestPath),
      {
        timeoutMs,
        fetchOptions: { method: 'HEAD', headers, redirect: 'manual' },
      },
      // Injected fetch tests retain the declared URL; production connects to the
      // independently classified direct-origin literal with the protected Host header.
      hasInjectedFetch
        ? deps
        : {
            ...deps,
            vettedHost: directDestination.host ?? pinnedDirectIp,
            vettedAddresses: directDestination.addresses,
          },
    );
    ({ res, error, attempted } = outcome);
  }

  if (!attempted || isProbeDeadlineError(error, deps)) {
    return deadlineOutcome(job, kind, deps, attempted ? 1 : 0, {
      protected_host: hostname,
      direct_ip: directIp,
    });
  }
  const durationMs = observedProbeDurationMs(deps);
  const expectedMarker = job.probe_profile?.marker ? String(job.probe_profile.marker) : null;
  const observation = classifyDirectOriginObservation({
    attempted: true,
    response: error ? null : res,
    error: error ?? null,
    baseline: null,
    expectedNonce: job.nonce ?? null,
    expectedMarker,
    declaredLockdown: job.probe_profile?.declared_origin_lockdown ?? null,
    directAddress: pinnedDirectIp,
    scope: { host: hostname, path: String(requestPath || '/'), port: requestPort ?? (job.target?.value?.startsWith('http://') ? 80 : 443),
      method: 'HEAD', scenario_version: job.probe_profile?.scenario_version ?? 'probe-observation-v3',
      source_perspective: deps.sourcePerspective ?? 'astranull-signed-public-worker', worker_id: deps.workerId ?? job.worker_id ?? null },
    observedAt: new Date().toISOString(),
  });
  const external = observation.outcome === 'explicit_denial_observed'
    ? 'blocked'
    : observation.response_observed
      ? 'connected'
      : observation.outcome === 'no_response' ? 'timeout' : 'error';
  return {
    external_result: external,
    metadata: withKind(job, kind, {
      ...(observation.status_code != null ? { status_code: observation.status_code } : {}),
      ...(observation.error_class ? { error_class: observation.error_class } : {}),
      protected_host: hostname,
      direct_ip: directIp,
      observation_outcome: observation.outcome,
      network_reachable: observation.response_observed,
      explicit_denial_observed: observation.explicit_denial_observed,
      denial_signature: observation.denial_signature,
      response_reason: observation.response_reason,
      application_bypass_confirmed: observation.application_bypass_confirmed,
      application_bypass_suspected: observation.application_bypass_suspected,
      // Deprecated alias: network response observed, never an application bypass or protection claim.
      bypass_signal: observation.response_observed,
      origin_observation: observation,
      observation_complete: true,
      target_port: requestPort ?? (job.target?.value?.startsWith('http://') ? 80 : 443),
      observation_only: true, readiness_conclusion: false, comparison_complete: false,
      duration_ms: durationMs,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: 1,
    duration_ms: durationMs,
  };
}

const PORT_CONNECT_TIMEOUT_MAX_MS = 3000;
const PORT_SCAN_DEADLINE_MARGIN_MS = 50;

/** Splits what is left of the job deadline across the ports still to sample, so one filtered port cannot starve the rest. */
export function portConnectTimeoutMs(remainingJobMs, portsLeft) {
  const usable = Math.floor(Number(remainingJobMs)) - PORT_SCAN_DEADLINE_MARGIN_MS;
  if (!Number.isFinite(usable) || usable <= 0) return 0;
  return Math.min(PORT_CONNECT_TIMEOUT_MAX_MS, Math.floor(usable / Math.max(1, portsLeft)));
}

/**
 * P0 — Firewall exposure: bounded risky-port scan (one connect per port).
 */
export async function probePortScanBounded(job, deps = {}) {
  const kind = 'port_scan_bounded';
  // Scan host is derived from the declared target only. A profile-supplied scan_host used
  // to let a signed job point the port scan at an address unrelated to the declared target.
  const targetHost = job.target?.kind === 'ip'
    ? String(job.target.value ?? '').trim()
    : apexDomain(job);
  const host = targetHost ?? job.target?.value;
  if (!host) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  deps = ensureProbeDeadline(job, deps);
  const budget = resolveProbeRequestBudget(job);
  const ports = (job.probe_profile?.ports ?? RISKY_ADMIN_PORTS).slice(0, budget);
  const open_ports = [];
  const filtered_ports = [];
  const closed_ports = [];
  let requestsSent = 0;

  const destination = await vetProbeDestinationHost(host, deps);
  if (remainingProbeTimeoutMs(job, deps) <= 0) {
    return deadlineOutcome(job, kind, deps, requestsSent, {
      scan_host: host,
      open_ports,
      filtered_ports,
    });
  }
  if (!destination.ok || destination.addresses.length === 0) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, {
        error_class: 'destination_not_routable',
        scan_host: host,
        blocked_address: destination.blocked_address ?? null,
        reason: destination.reason ?? 'no_resolved_addresses',
      }),
      requests_sent: 0,
      duration_ms: observedProbeDurationMs(deps),
    };
  }
  const resolvedHost = destination.addresses[0];

  for (const [index, port] of ports.entries()) {
    if (requestsSent >= budget) break;
    const remainingMs = portConnectTimeoutMs(remainingProbeTimeoutMs(job, deps), Math.min(ports.length, budget) - index);
    if (remainingMs <= 0) {
      return deadlineOutcome(job, kind, deps, requestsSent, {
        scan_host: resolvedHost,
        open_ports,
        filtered_ports,
      });
    }
    const state = await tcpConnectProbe(
      resolvedHost,
      port,
      remainingMs,
      deps.connectFn,
      deps,
      () => { requestsSent += 1; },
    );
    if (state === 'open') open_ports.push(port);
    else if (state === 'filtered' || state === 'timeout') filtered_ports.push(port);
    else if (state === 'closed') closed_ports.push(port);
    if (remainingProbeTimeoutMs(job, deps) <= 0 && requestsSent < ports.length) {
      return deadlineOutcome(job, kind, deps, requestsSent, {
        scan_host: resolvedHost,
        open_ports,
        filtered_ports,
      });
    }
  }

  const durationMs = observedProbeDurationMs(deps);
  const risky_open = open_ports.filter((p) => [22, 23, 3389, 5432, 6379, 445].includes(p));
  return {
    external_result: open_ports.length ? 'connected' : 'blocked',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      scan_host: resolvedHost,
      open_ports,
      filtered_ports,
      closed_ports,
      risky_admin_ports_open: risky_open,
      exposure_count: open_ports.length,
      observation_complete: ports.length > 0 && requestsSent === ports.length
        && open_ports.length + filtered_ports.length + closed_ports.length === ports.length,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

function capabilityProbeAuthorizationFailure(job, kind, deps) {
  if (isLiveCapabilityProbeAuthorized(job, deps)) return null;
  return {
    external_result: 'error',
    metadata: withKind(job, kind, {
      error_class: 'live_probe_requires_signed_worker',
      simulation: 'SAFE_PROBE_SIMULATION',
      note: 'Live capability probes require a signed-worker job or injectable test deps.',
    }),
    requests_sent: 0,
    duration_ms: 0,
  };
}

function httpProbeEndpoint(job, configuredPath) {
  if (configuredPath != null && !normalizeProbeHttpPath(configuredPath)) return null;
  const configured = normalizeProbeHttpPath(configuredPath);
  const targetValue = String(job.target?.value ?? '').trim();
  try {
    const origin = /^https?:\/\//i.test(targetValue)
      ? new URL(targetValue).origin
      : baseUrlForHost(apexDomain(job) ?? '').replace(/\/$/, '');
    const url = configured ? new URL(configured, `${origin}/`) : new URL(/^https?:\/\//i.test(targetValue) ? targetValue : `${origin}/`);
    if (url.username || url.password || !['http:', 'https:'].includes(url.protocol)) return null;
    url.hash = '';
    return origin ? { url: url.href, probePath: `${url.pathname}${url.search}` } : null;
  } catch {
    return null;
  }
}

function inertProbeMarker(job) {
  return String(job.nonce_hash ?? job.probe_profile?.marker ?? 'astranull-safe-marker').slice(0, 128);
}

/** Bounded body prefix for signature matching, raced against the remaining job time; '' when unavailable. */
async function signatureBodyOf(res, method, job, deps) {
  const remaining = Math.max(0, Math.min(1_000, remainingProbeTimeoutMs(job, deps)));
  if (!res || remaining <= 0) return '';
  return readSignatureBody(res, method, { timeoutMs: remaining, signal: deps.jobDeadlineSignal });
}

function blockedHttpStatus(status) {
  return [400, 401, 403, 405, 406, 409, 413, 414, 429, 431, 501, 503].includes(status);
}

const MARKER_SIGNATURE_HEADERS = Object.freeze(['x-waf-block', 'x-bot-challenge', 'x-sucuri-block']);
const UNSIGNED_MARKER_STATUS_REASONS = Object.freeze({
  401: 'authentication_gate_precedes_inspection',
  407: 'probe_path_error',
  421: 'misdirected_request',
});

/** Benign-marker response class: blocked only with a control-specific signature; unsigned 4xx is at most block_suspected. */
export function classifyMarkerResponse(res, { baselineStatus = null, declared = null, bodyText = '' } = {}) {
  const status = Number(res?.status);
  const out = (fields) => ({ blocked: false, allowed: false, inconclusive: false, block_suspected: false, denial_signature: null, reason: null, ...fields });
  if (!Number.isInteger(status)) return out({ inconclusive: true, reason: 'rst_or_drop_unattributed' });
  const header = MARKER_SIGNATURE_HEADERS.find((name) => res.headers?.get?.(name) != null);
  const signature = matchControlDenialSignature({ statusCode: status, headers: res, bodyText, declared, bodyComplete: signatureBodyComplete(res) })
    ?? (header ? { kind: 'vendor', id: `challenge_header:${header}`, vendor: null } : null);
  if (signature) return out({ blocked: true, denial_signature: signature });
  if (UNSIGNED_MARKER_STATUS_REASONS[status]) return out({ inconclusive: true, reason: UNSIGNED_MARKER_STATUS_REASONS[status] });
  if (status >= 500) return out({ inconclusive: true, reason: 'error_not_attributable' });
  if (status >= 200 && status < 400) return out({ allowed: true });
  const differs = Number.isInteger(baselineStatus) && baselineStatus >= 200 && baselineStatus < 400 && baselineStatus !== status;
  return out({ inconclusive: true, block_suspected: differs, reason: differs ? 'unattributed_denial' : 'baseline_not_available' });
}

/**
 * P0 — Rate-limit: rapid bounded sequence on the declared abuse-sensitive path.
 */
export async function probeRateLimitSequence(job, deps = {}) {
  const kind = 'rate_limit_sequence';
  const endpoint = httpProbeEndpoint(job, job.probe_profile?.probe_path);
  if (!endpoint) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }
  const method = typeof job.probe_profile?.http_method === 'string'
    ? job.probe_profile.http_method
    : 'HEAD';
  if (!EXECUTABLE_SAFE_HTTP_METHODS.has(method)) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, {
        error_class: 'unsafe_http_method',
        probe_path: endpoint.probePath,
        http_method: method,
        request_counting_basis: 'logical_operations',
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }
  if (method === 'POST') {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, {
        error_class: 'unsafe_post_profile',
        probe_path: endpoint.probePath,
        http_method: method,
        request_counting_basis: 'logical_operations',
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  deps = ensureProbeDeadline(job, deps);
  const maxSeq = resolveBoundedSequenceBudget(job, { ceiling: 5 });
  const statuses = [];
  let throttled = false;
  let transportError = null;
  let requestsSent = 0;

  for (let i = 0; i < maxSeq; i += 1) {
    if (remainingProbeTimeoutMs(job, deps) <= 0) {
      return deadlineOutcome(job, kind, deps, requestsSent, {
        status_sequence: statuses,
        throttled,
        probe_path: endpoint.probePath,
        http_method: method,
      });
    }
    const marker = inertProbeMarker(job);
    const { res, error, attempted } = await boundedFetch(endpoint.url, {
      timeoutMs: remainingProbeTimeoutMs(job, deps),
      fetchOptions: {
        method,
        redirect: 'manual',
        headers: {
          'x-astranull-marker': marker,
          ...(method === 'POST' ? { 'Content-Type': 'text/plain' } : {}),
        },
        ...(method === 'POST' ? { body: marker } : {}),
      },
    }, deps);
    if (attempted) requestsSent += 1;
    if (!attempted || isProbeDeadlineError(error, deps)) {
      return deadlineOutcome(job, kind, deps, requestsSent, {
        status_sequence: statuses,
        throttled,
        probe_path: endpoint.probePath,
        http_method: method,
      });
    }
    if (error) {
      transportError = error.code ?? error.name ?? 'probe_transport_error';
      statuses.push(transportError);
      break;
    }
    statuses.push(res.status);
    // Status is a response observation, not attribution to a rate-limiting control.
    if (res.status === 429) throttled = true;
    await res.body?.cancel?.().catch?.(() => {});
  }

  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: transportError ? 'error' : 'connected',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      status_sequence: statuses,
      throttled,
      ...(transportError ? { error_class: transportError } : {}),
      rate_limit_enforced: null,
      throttle_status_observed: throttled,
      control_attribution: 'unknown',
      probe_path: endpoint.probePath,
      http_method: method,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

export async function probeHttpMethodMatrix(job, deps = {}) {
  const kind = 'http_method_matrix';
  const unauthorized = capabilityProbeAuthorizationFailure(job, kind, deps);
  if (unauthorized) return unauthorized;
  const endpoint = httpProbeEndpoint(job, job.probe_profile?.probe_path);
  if (!endpoint) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  deps = ensureProbeDeadline(job, deps);
  const marker = inertProbeMarker(job);
  const methods = ['HEAD', 'OPTIONS']
    .slice(0, resolveBoundedSequenceBudget(job, { ceiling: 2 }));
  const method_statuses = [];
  const methods_allowed = [];
  const methods_blocked = [];
  const method_errors = [];
  let allowHeader = null;
  let requestsSent = 0;

  for (const method of methods) {
    if (remainingProbeTimeoutMs(job, deps) <= 0) {
      return deadlineOutcome(job, kind, deps, requestsSent, {
        probe_path: endpoint.probePath,
        method_statuses,
        methods_allowed,
        methods_blocked,
        method_errors,
      });
    }
    const { res, error, attempted } = await boundedFetch(endpoint.url, {
      timeoutMs: remainingProbeTimeoutMs(job, deps),
      fetchOptions: {
        method,
        redirect: 'manual',
        headers: { 'x-astranull-marker': marker },
      },
    }, deps);
    if (attempted) requestsSent += 1;
    if (!attempted || isProbeDeadlineError(error, deps)) {
      return deadlineOutcome(job, kind, deps, requestsSent, {
        probe_path: endpoint.probePath,
        method_statuses,
        methods_allowed,
        methods_blocked,
        method_errors,
      });
    }
    if (error) {
      const errorClass = error.code ?? error.name ?? 'probe_failed';
      method_statuses.push({ method, status_code: 0, error_class: errorClass });
      method_errors.push({ method, error_class: errorClass });
      continue;
    }
    const statusCode = res.status;
    const rejected = statusCode === 405;
    const blocked = false;
    const observedAllow = res.headers?.get?.('allow') ?? null;
    if (observedAllow && allowHeader == null) allowHeader = observedAllow;
    if (statusCode >= 200 && statusCode < 300) methods_allowed.push(method);
    method_statuses.push({ method, status_code: statusCode, rejected_status: rejected, blocked: false });
    await res.body?.cancel?.().catch?.(() => {});
  }

  const advertisedMethods = allowHeader
    ? [...new Set(allowHeader.split(',').map((method) => method.trim().toUpperCase()).filter(Boolean))]
    : [];
  const safeSemanticMethods = new Set(['GET', 'HEAD', 'OPTIONS']);
  const unsafeMethodsAdvertised = advertisedMethods
    .filter((method) => !safeSemanticMethods.has(method));
  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: method_errors.length === method_statuses.length ? 'error' : 'connected',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      probe_path: endpoint.probePath,
      method_statuses,
      methods_allowed,
      methods_blocked,
      method_errors,
      allow_header: allowHeader,
      advertised_methods: advertisedMethods,
      unsafe_methods_advertised: unsafeMethodsAdvertised,
      unsafe_methods_executed: false,
      trace_advertised: advertisedMethods.includes('TRACE'),
      trace_enabled: null,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

export async function probeHeaderSizeBoundary(job, deps = {}) {
  const kind = 'header_size_probe';
  const unauthorized = capabilityProbeAuthorizationFailure(job, kind, deps);
  if (unauthorized) return unauthorized;
  const endpoint = httpProbeEndpoint(job, job.probe_profile?.probe_path);
  if (!endpoint) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  deps = ensureProbeDeadline(job, deps);
  const oversizeBytes = Math.min(
    16_384,
    Math.max(1_024, Number(job.probe_profile?.oversize_header_bytes) || 8_192),
  );
  const budget = resolveBoundedSequenceBudget(job, { ceiling: 2 });
  let baselineStatus = null;
  let oversizeStatus = null;
  let transportError = null;
  let requestsSent = 0;

  for (let index = 0; index < budget; index += 1) {
    if (remainingProbeTimeoutMs(job, deps) <= 0) {
      return deadlineOutcome(job, kind, deps, requestsSent, {
        probe_path: endpoint.probePath,
        baseline_status: baselineStatus,
        oversize_status: oversizeStatus,
        oversize_bytes: oversizeBytes,
      });
    }
    const oversize = index === 1;
    const { res, error, attempted } = await boundedFetch(endpoint.url, {
      timeoutMs: remainingProbeTimeoutMs(job, deps),
      fetchOptions: {
        method: 'HEAD',
        redirect: 'manual',
        headers: oversize ? { 'x-astranull-boundary': 'a'.repeat(oversizeBytes) } : {},
      },
    }, deps);
    if (attempted) requestsSent += 1;
    if (!attempted || isProbeDeadlineError(error, deps)) {
      return deadlineOutcome(job, kind, deps, requestsSent, {
        probe_path: endpoint.probePath,
        baseline_status: baselineStatus,
        oversize_status: oversizeStatus,
        oversize_bytes: oversizeBytes,
      });
    }
    if (error) {
      transportError = error.code ?? error.name ?? 'probe_transport_error';
      break;
    }
    if (oversize) oversizeStatus = res.status;
    else baselineStatus = res.status;
  }

  const comparisonComplete = baselineStatus !== null && oversizeStatus !== null;
  const boundaryEnforced = comparisonComplete
    && [400, 413, 414, 431].includes(oversizeStatus);
  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: transportError
      ? 'error'
      : (comparisonComplete ? 'connected' : 'not_run'),
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      probe_path: endpoint.probePath,
      baseline_status: baselineStatus,
      oversize_status: oversizeStatus,
      oversize_bytes: oversizeBytes,
      boundary_enforced: null,
      boundary_rejection_status_observed: boundaryEnforced,
      comparison_complete: comparisonComplete,
      ...(transportError ? { error_class: transportError } : {}),
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

export async function probeSlowHeaderTimeout(job, deps = {}) {
  const kind = 'slow_header_probe';
  const unauthorized = capabilityProbeAuthorizationFailure(job, kind, deps);
  if (unauthorized) return unauthorized;
  const endpoint = httpProbeEndpoint(job, job.probe_profile?.probe_path);
  if (!endpoint) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  deps = ensureProbeDeadline(job, deps);
  if (remainingProbeTimeoutMs(job, deps) <= 0) return deadlineOutcome(job, kind, deps, 0);
  const parsed = new URL(endpoint.url);
  let destination;
  try {
    destination = await vetProbeDestinationHost(parsed.hostname, deps);
  } catch (error) {
    if (isOperationBudgetError(error)) throw error;
    if (isProbeDeadlineError(error, deps)) return deadlineOutcome(job, kind, deps, 0);
    throw error;
  }
  if (!destination.ok || destination.addresses.length === 0) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, { error_class: 'destination_not_routable', probe_path: endpoint.probePath }),
      requests_sent: 0,
      duration_ms: observedProbeDurationMs(deps),
    };
  }

  const timeoutMs = remainingProbeTimeoutMs(job, deps);
  if (timeoutMs <= 0 || deps.jobDeadlineSignal?.aborted) return deadlineOutcome(job, kind, deps, 0);
  const connectFn = deps.connectFn ?? (parsed.protocol === 'https:' ? tls.connect : net.connect);
  const connectOptions = {
    host: destination.addresses[0],
    port: Number(parsed.port) || (parsed.protocol === 'https:' ? 443 : 80),
    timeout: timeoutMs,
    ...(parsed.protocol === 'https:' ? { servername: parsed.hostname, ALPNProtocols: ['http/1.1'] } : {}),
  };
  const started = Date.now();
  let socket = null;
  let connectionClosedByServer = false;
  let requestsSent = 0;

  try {
    socket = startProbeIoAttempt(
      deps,
      'slow_header_connection',
      () => connectFn(connectOptions),
      () => { requestsSent = 1; },
    );
    await new Promise((resolve, reject) => {
      let settled = false;
      let timer;
      const signal = deps.jobDeadlineSignal;
      const connectedEvent = parsed.protocol === 'https:' ? 'secureConnect' : 'connect';
      const finish = (closedByServer, error = null) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
        for (const [event, listener] of [[connectedEvent, onConnect], ['end', onEnd], ['close', onEnd]]) {
          socket.removeListener?.(event, listener);
        }
        connectionClosedByServer = closedByServer;
        if (error) reject(error);
        else resolve();
      };
      const onAbort = () => finish(false, probeDeadlineError());
      const onError = (error) => finish(false, error);
      const onEnd = () => finish(true);
      const onConnect = () => {
        if (settled || signal?.aborted) return;
        try {
          socket.write(`HEAD ${endpoint.probePath} HTTP/1.1\r\nHost: ${parsed.host}\r\nX-AstraNull-Marker: `);
        } catch (error) { finish(false, error); }
      };
      timer = setTimeout(() => finish(false), timeoutMs);
      signal?.addEventListener('abort', onAbort, { once: true });
      if (signal?.aborted) return onAbort();
      socket.once(connectedEvent, onConnect);
      if (settled) return;
      socket.once('end', onEnd);
      socket.once('close', onEnd);
      socket.once('error', onError);
    });
  } catch (error) {
    const durationMs = observedProbeDurationMs(deps, started);
    return {
      external_result: classifyFetchError(error),
      metadata: withKind(job, kind, {
        error_class: error.code ?? error.name ?? 'slow_header_probe_failed',
        probe_path: endpoint.probePath,
        header_timeout_ms: durationMs,
        connection_closed_by_server: connectionClosedByServer,
        timeout_enforced: null,
        request_counting_basis: 'logical_operations',
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  } finally {
    socket?.destroy?.();
  }

  const durationMs = observedProbeDurationMs(deps, started);
  return {
    external_result: 'connected',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      probe_path: endpoint.probePath,
      header_timeout_ms: durationMs,
      connection_closed_by_server: connectionClosedByServer,
      timeout_enforced: null,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

function waitForHttp2Settings(session, job, deps) {
  return withinRemainingProbeTime(new Promise((resolve, reject) => {
    const cleanup = () => {
      session.removeListener?.('remoteSettings', onSettings);
      session.removeListener?.('connect', onConnect);
      session.removeListener?.('error', onError);
    };
    const onSettings = (settings) => {
      cleanup();
      resolve(settings ?? session.remoteSettings ?? {});
    };
    const onConnect = () => {
      const protocol = session.alpnProtocol;
      if (protocol && protocol !== 'h2') {
        cleanup();
        reject(Object.assign(new Error('HTTP/2 was not negotiated.'), { code: 'http2_not_negotiated' }));
      }
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    session.once('remoteSettings', onSettings);
    session.once('connect', onConnect);
    session.once('error', onError);
  }), job, deps);
}

export async function probeHttp2FrameBehavior(job, deps = {}) {
  const kind = 'http2_frame_probe';
  const unauthorized = capabilityProbeAuthorizationFailure(job, kind, deps);
  if (unauthorized) return unauthorized;
  const endpoint = httpProbeEndpoint(job, job.probe_profile?.probe_path);
  if (!endpoint) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  deps = ensureProbeDeadline(job, deps);
  const parsed = new URL(endpoint.url);
  const budget = resolveBoundedSequenceBudget(job, { ceiling: 4 });
  const destination = await vetProbeDestinationHost(parsed.hostname, deps);
  if (!destination.ok || destination.addresses.length === 0) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, { error_class: 'destination_not_routable', probe_path: endpoint.probePath }),
      requests_sent: 0,
      duration_ms: observedProbeDurationMs(deps),
    };
  }

  let session = null;
  let requestsSent = 0;
  let settings = {};
  let pingRttMs = null;
  let resetAccepted = null;
  let continuationBoundAdvertised = null;
  try {
    const connectFn = deps.http2ConnectFn ?? http2.connect;
    const connectOptions = deps.http2ConnectFn ? {} : {
      createConnection: () => tls.connect({
        host: destination.addresses[0],
        port: Number(parsed.port) || 443,
        servername: parsed.hostname,
        ALPNProtocols: ['h2'],
      }),
    };
    session = startProbeIoAttempt(
      deps,
      'http2_settings',
      () => connectFn(parsed.origin, connectOptions),
      () => { requestsSent += 1; },
    );
    settings = await waitForHttp2Settings(session, job, deps);

    let resetStream = null;
    if (budget >= 3) {
      // The existing PING settles after this stream is queued; keep its request side open
      // until the single CANCEL instead of destroying an unsent, already-ended HEAD stream.
      resetStream = startProbeIoAttempt(
        deps,
        'http2_single_reset',
        () => session.request({ ':method': 'HEAD', ':path': endpoint.probePath }, { endStream: false }),
        () => { requestsSent += 1; },
      );
      resetStream.once?.('error', () => {});
    }
    if (budget >= 2) {
      pingRttMs = await withinRemainingProbeTime(new Promise((resolve, reject) => {
        startProbeIoAttempt(deps, 'http2_ping', () => session.ping(Buffer.alloc(8), (error, duration) => {
          if (error) reject(error);
          else resolve(Math.max(0, Math.ceil(Number(duration) || 0)));
        }), () => { requestsSent += 1; });
      }), job, deps);
    }

    if (budget >= 3) {
      const stream = resetStream;
      let onReady;
      let onError;
      const signal = deps.jobDeadlineSignal;
      let onAbort;
      try {
        if (stream.closed || stream.destroyed) throw new Error('HTTP/2 stream closed before reset.');
        resetAccepted = await withinRemainingProbeTime(new Promise((resolve, reject) => {
          onReady = () => {
            try {
              if (remainingProbeTimeoutMs(job, deps) <= 0) throw probeDeadlineError();
              // Await the opened stream's close before destroying its session. An immediate
              // reset/destroy can discard both HEADERS and RST_STREAM before they reach the peer.
              stream.close(http2.constants.NGHTTP2_CANCEL, () => resolve(true));
            } catch (error) { reject(error); }
          };
          onError = reject;
          onAbort = () => reject(probeDeadlineError());
          stream.once?.('error', onError);
          signal?.addEventListener('abort', onAbort, { once: true });
          if (signal?.aborted) onAbort();
          else if (stream.pending) stream.once('ready', onReady);
          else onReady();
        }), job, deps);
      } catch (error) {
        if (isProbeDeadlineError(error, deps) || isOperationBudgetError(error)) throw error;
        resetAccepted = false;
      } finally {
        if (onReady) stream?.removeListener?.('ready', onReady);
        if (onError) stream?.removeListener?.('error', onError);
        if (onAbort) signal?.removeEventListener('abort', onAbort);
      }
    }

    // The peer's SETTINGS frame already arrived with the connection handshake, so reading the
    // advertised header-list bound performs no network I/O. It must therefore neither reserve
    // budget nor be attested as an operation: doing so over-reported one operation per probe
    // and broke exact worker attestation against real initializer counts.
    continuationBoundAdvertised = Number.isSafeInteger(settings.maxHeaderListSize)
      && settings.maxHeaderListSize > 0;
  } catch (error) {
    const durationMs = observedProbeDurationMs(deps);
    const errorClass = error.code === 'http2_not_negotiated'
      ? 'http2_not_negotiated'
      : (error.code ?? error.name ?? 'http2_probe_failed');
    return {
      external_result: 'error',
      metadata: withKind(job, kind, {
        error_class: errorClass,
        probe_path: endpoint.probePath,
        max_concurrent_streams: settings.maxConcurrentStreams ?? null,
        header_table_size: settings.headerTableSize ?? null,
        max_header_list_size: settings.maxHeaderListSize ?? null,
        settings_assertion: job.probe_profile?.settings_assertion ?? null,
        ping_rtt_ms: pingRttMs,
        reset_accepted: resetAccepted,
        rapid_reset_mitigation_hint: false,
        continuation_bound_advertised: continuationBoundAdvertised,
        request_counting_basis: 'logical_operations',
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  } finally {
    session?.close?.();
    session?.destroy?.();
  }

  const maxConcurrentStreams = settings.maxConcurrentStreams ?? null;
  const headerTableSize = settings.headerTableSize ?? null;
  const maxHeaderListSize = settings.maxHeaderListSize ?? null;
  const mitigationHint = null;
  const hpackLimitsAdvertised = Number.isSafeInteger(headerTableSize)
    && headerTableSize >= 0
    && Number.isSafeInteger(maxHeaderListSize)
    && maxHeaderListSize > 0
    && maxHeaderListSize < 0xffff_ffff;
  const settingsAssertion = job.probe_profile?.settings_assertion ?? null;
  const semanticResult = 'connected';
  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: semanticResult,
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      probe_path: endpoint.probePath,
      max_concurrent_streams: maxConcurrentStreams,
      header_table_size: headerTableSize,
      max_header_list_size: maxHeaderListSize,
      enable_push: settings.enablePush ?? null,
      settings_assertion: settingsAssertion,
      hpack_limits_advertised: hpackLimitsAdvertised,
      ping_rtt_ms: pingRttMs,
      reset_accepted: resetAccepted,
      rapid_reset_mitigation_hint: mitigationHint,
      continuation_bound_advertised: continuationBoundAdvertised,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

export async function probeHttp3ControlStream(job, deps = {}) {
  const kind = 'http3_control_probe';
  const unauthorized = capabilityProbeAuthorizationFailure(job, kind, deps);
  if (unauthorized) return unauthorized;

  const outcome = await probeQuicReachability(job, deps);
  return {
    ...outcome,
    metadata: withKind(job, kind, {
      ...outcome.metadata,
      profile_kind: kind,
      probe_kind: kind,
      capability_scope: 'http3_alt_svc_observation_only',
      request_counting_basis: 'logical_operations',
    }),
  };
}

export async function probeWafInspectionLimit(job, deps = {}) {
  const kind = 'waf_inspection_limit_probe';
  const unauthorized = capabilityProbeAuthorizationFailure(job, kind, deps);
  if (unauthorized) return unauthorized;
  // Body/form/JSON parser limits require an explicitly approved business-safe sink.
  // A nonce or a small body does not authorize POST into a login/API/business route.
  // No sink contract exists for this catalog scenario: do not substitute header/query delivery.
  return { external_result: 'not_run', metadata: withKind(job, kind, {
    not_run_reason: 'approved_business_safe_body_endpoint_required',
    delivery_supported: false, comparison_complete: false,
    planned_marker_legs: 4, completed_marker_legs: 0, variants: [],
    baseline_blocked: null, inspection_limit_bypass_suspected: null, fail_open_signal: null,
    observation_only: true, readiness_conclusion: false,
    request_counting_basis: 'logical_operations',
  }), requests_sent: 0, duration_ms: 0 };
}

/**
 * Outside-in WAF scanner: fingerprint, benign class markers, optional origin bypass, posture report.
 */
export async function probeOutsideInWafScan(job, deps = {}) {
  const fingerprintOnly = job.probe_profile?.kind === 'waf_fingerprint_observation';
  const kind = fingerprintOnly ? 'waf_fingerprint_observation' : 'outside_in_waf_scan';
  const budgetFailure = mandatoryBudgetFailure(job, kind);
  if (budgetFailure) return budgetFailure;
  const targetValue = String(job.target?.value ?? '').trim();
  const url = targetValue.startsWith('http') ? targetValue : baseUrlForHost(apexDomain(job) ?? '');
  if (!url) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, { error_class: 'unsupported_target' }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  deps = ensureProbeDeadline(job, deps);
  const primaryHost = apexDomain(job);
  const primaryDestination = await vetProbeDestinationHost(primaryHost, deps);
  if (remainingProbeTimeoutMs(job, deps) <= 0) {
    return deadlineOutcome(job, kind, deps, 0);
  }
  if (!primaryDestination.ok || primaryDestination.addresses.length === 0) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, {
        error_class: 'destination_not_routable',
        blocked_address: primaryDestination.blocked_address ?? null,
        reason: primaryDestination.reason ?? 'no_resolved_addresses',
      }),
      requests_sent: 0,
      duration_ms: observedProbeDurationMs(deps),
    };
  }
  const primaryDeps = {
    ...deps,
    vettedHost: primaryDestination.host,
    vettedAddresses: primaryDestination.addresses,
  };

  const { hostname, directIp: declaredDirectIp } = resolveHostSniTargets(job);
  const directIp = fingerprintOnly ? null : declaredDirectIp;
  let pinnedDirectIp = null;
  if (directIp) {
    const directDestination = await vetProbeDestinationHost(directIp, primaryDeps);
    if (remainingProbeTimeoutMs(job, deps) <= 0) {
      return deadlineOutcome(job, kind, deps, 0);
    }
    if (!directDestination.ok || directDestination.addresses.length === 0) {
      return {
        external_result: 'error',
        metadata: withKind(job, kind, {
          error_class: 'direct_destination_not_routable',
          blocked_address: directDestination.blocked_address ?? null,
          reason: directDestination.reason ?? 'no_resolved_addresses',
        }),
        requests_sent: 0,
        duration_ms: observedProbeDurationMs(deps),
      };
    }
    pinnedDirectIp = directDestination.addresses[0];
  }
  const totalBudget = resolveProbeRequestBudget(job);
  const reportProviderObservation = (chain = []) => {
    if (!fingerprintOnly || typeof deps.onProviderObservation !== 'function') return;
    const edge = classifyEdgeFingerprint({ resolvedIps: primaryDestination.addresses, cnameChain: chain, dnsObserved: true });
    deps.onProviderObservation(enrichProbeMetadataWithWafCatalog(withKind(job, kind, {
      edge_signature: { ...edge, waf_present: null, waf_providers: [], layers: edge.layers.filter((layer) => layer.family !== 'waf') },
      edge_signature_corpus_version: EDGE_SIGNATURE_CORPUS_VERSION,
      dns_resolved_ips: primaryDestination.addresses,
      dns_cname_chain: chain,
      baseline_status_code: 0,
      waf_detected: null,
      waf_fingerprint_detected: null,
      detected_vendor: null,
    }), job.check_id));
  };
  reportProviderObservation();
  const cnameHopBudget = Math.max(0, Math.min(OUTSIDE_IN_CNAME_HOPS_MAX, totalBudget - (fingerprintOnly ? 1 : OUTSIDE_IN_SCAN_DEFAULT_BUDGET)));
  const cnameResult = net.isIP(primaryHost ?? '') === 0 && cnameHopBudget > 0
    ? await resolveCnameChain(primaryHost, { ...primaryDeps,
      ...(fingerprintOnly ? { onCnameObservation: reportProviderObservation } : {}),
    }, cnameHopBudget)
    : { chain: [], lookups: 0 };
  reportProviderObservation(cnameResult.chain);
  const budget = fingerprintOnly ? 1 : totalBudget - cnameResult.lookups;
  const rawFetch = deps.fetchFn ?? ((input, init) => pinnedFetch(input, init, primaryDeps));
  const deadlineFetch = async (input, init = {}) => {
    const { res, error } = await boundedFetch(input, {
      timeoutMs: remainingProbeTimeoutMs(job, deps),
      fetchOptions: init,
    }, { ...primaryDeps, fetchFn: rawFetch });
    if (error) throw error;
    return res;
  };
  const scan = await runOutsideInWafScan({
    url,
    hostname,
    directIp: pinnedDirectIp,
    resolvedIps: primaryDestination.addresses,
    cnameChain: cnameResult.chain,
    budget,
    fingerprintOnly,
    timeoutMs: remainingProbeTimeoutMs(job, deps),
    // Signed outside-in jobs authorize only the statically planned, pre-reserved HTTP probes.
    // Legacy profiles may still carry hint/redirect fields, but raw CNAME/A/AAAA/TLS collectors
    // and redirect expansion remain disabled until each operation has its own signed accounting.
    followRedirects: false,
    collectNetworkHints: false,
    wafRequired: fingerprintOnly ? false : job.probe_profile?.waf_required !== false,
    customerVendorHint: job.probe_profile?.expected_vendor_hint ?? job.target?.metadata?.expected_vendor_hint,
    fetchFn: deadlineFetch,
    jobDeadlineSignal: deps.jobDeadlineSignal,
    onPhase: (entry) => deps.onProbeActivity?.({ stage: 'phase_completed', operation: entry.phase,
      ...(Number.isInteger(entry.status_code) && entry.status_code >= 100 ? { status_code: entry.status_code } : {}),
      ...(entry.error_class ? { error_class: entry.error_class } : {}) }),
    canaryNonce: job.nonce ?? null,
    originScope: { host: hostname, path: new URL(url).pathname + new URL(url).search,
      port: Number(new URL(url).port) || (new URL(url).protocol === 'https:' ? 443 : 80),
      method: 'GET', scenario_version: job.probe_profile?.scenario_version ?? 'marker-comparison-v4',
      source_perspective: deps.sourcePerspective ?? 'astranull-signed-public-worker',
      worker_id: deps.workerId ?? job.worker_id ?? null },
    declaredBlockSignature: job.probe_profile?.declared_block_signature ?? null,
    declaredOriginLockdown: job.probe_profile?.declared_origin_lockdown ?? null,
    originBypassFn: directIp && hostname && job.constraints?.authority_version !== 'probe-authority-v2'
      ? async ({ directIp: ip, hostname: host, canaryNonce }) => {
        try {
          const targetUrl = new URL(url);
          const res = await deadlineFetch(directHttpProbeUrl(ip, Number(targetUrl.port) || (targetUrl.protocol === 'https:' ? 443 : 80), targetUrl.pathname + targetUrl.search), {
            method: 'GET',
            redirect: 'manual',
            headers: { Host: host, ...(canaryNonce ? { [CANARY_NONCE_REQUEST_HEADER]: canaryNonce } : {}) },
          });
          return { res, error: null };
        } catch (error) {
          return { res: null, error };
        }
      }
      : undefined,
  });

  if (remainingProbeTimeoutMs(job, deps) <= 0) {
    return deadlineOutcome(job, kind, deps, (scan.requests_sent ?? 0) + cnameResult.lookups, {
      phases_completed: Array.isArray(scan.phases) ? scan.phases.length : 0,
    });
  }
  const durationMs = observedProbeDurationMs(deps);
  if (scan.error_class && !scan.posture_status) {
    return {
      external_result: 'error',
      metadata: enrichProbeMetadataWithWafCatalog(
        withKind(job, kind, { ...scan, duration_ms: durationMs }),
        job.check_id,
      ),
      requests_sent: (scan.requests_sent ?? 0) + cnameResult.lookups,
      duration_ms: durationMs,
    };
  }

  const external = fingerprintOnly && !scan.error_class && Number(scan.baseline_status_code) >= 100
    ? 'connected'
    : ['blocked', 'connected', 'timeout', 'error', 'not_run']
    .includes(scan.external_result)
    ? scan.external_result
    : scan.error_class ? 'error' : 'not_run';

  const enrichedScan = withKind(job, kind, {
    duration_ms: durationMs,
    scenario_family: 'fingerprint',
    ...scan,
    dns_cname_lookups: cnameResult.lookups,
  });

  return {
    external_result: external,
    metadata: enrichProbeMetadataWithWafCatalog(enrichedScan, job.check_id),
    requests_sent: (scan.requests_sent ?? 0) + cnameResult.lookups,
    duration_ms: durationMs,
  };
}

/**
 * P0 — WAF enforcement: marker must be blocked or challenged.
 */
export async function probeWafEnforcement(job, deps = {}) {
  const kind = 'waf_enforcement_probe';
  const url = job.target?.value?.startsWith('http') ? job.target.value : baseUrlForHost(apexDomain(job) ?? '');
  if (!url) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  const marker = job.probe_profile?.marker ?? 'astranull-waf-marker';
  const started = Date.now();
  const { res, error } = await boundedFetch(url, {
    timeoutMs: job.constraints?.timeout_ms ?? 5000,
    fetchOptions: {
      method: 'GET',
      redirect: 'manual',
      headers: {
        'x-astranull-marker': marker,
        ...(job.nonce ? { 'x-astranull-nonce': job.nonce } : {}),
      },
    },
  }, deps);

  const durationMs = Date.now() - started;
  if (error) {
    return {
      external_result: classifyFetchError(error),
      metadata: withKind(job, kind, { error_class: error.code ?? error.name, duration_ms: durationMs }),
      requests_sent: 1,
      duration_ms: durationMs,
    };
  }

  const bodyText = await signatureBodyOf(res, 'GET', job, deps);
  const graded = classifyMarkerResponse(res, { declared: job.probe_profile?.declared_block_signature ?? null, bodyText });
  const enforced = graded.blocked;
  const monitor_only = res.status >= 200 && res.status < 300 && graded.allowed;

  return {
    external_result: 'not_run',
    metadata: withKind(job, kind, {
      status_code: res.status,
      waf_enforced: null,
      control_action_observed: enforced,
      monitor_only_leak: null,
      comparison_complete: false,
      observation_only: true, readiness_conclusion: false,
      not_run_reason: 'independent_permitted_baseline_not_available',
      denial_signature: graded.denial_signature,
      ...(graded.denial_signature?.vendor ? { waf_product_hint: graded.denial_signature.vendor } : {}),
      ...(graded.inconclusive ? { inconclusive_reason: graded.reason, block_suspected: graded.block_suspected } : {}),
      duration_ms: durationMs,
    }),
    requests_sent: 1,
    duration_ms: durationMs,
  };
}

/**
 * P1 — DNSSEC posture via authoritative DNSKEY presence (no chain validation).
 */
export async function probeDnssecPosture(job, deps = {}) {
  const kind = 'dnssec_posture';
  const zone = apexDomain(job);
  if (!zone) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  deps = ensureProbeDeadline(job, deps);
  const budget = resolveBoundedSequenceBudget(job, { ceiling: 1 });
  if (budget < 1) return mandatoryBudgetFailure(job, kind);
  const wire = await (deps.dnssecWireQueryFn ?? probeDnsWireQuery)({
    ...job,
    target: { ...job.target, value: zone },
    constraints: { ...job.constraints, timeout_ms: remainingProbeTimeoutMs(job, deps), max_requests: 1 },
    probe_profile: { ...job.probe_profile, dns_qtype: 'DNSKEY', dns_transport: 'udp', strict_dns_answer: true },
  }, deps);
  if (wire.external_result !== 'connected' || !Number.isSafeInteger(wire.metadata?.matching_answer_count) || wire.metadata.matching_answer_count < 0) {
    return {
      ...wire,
      external_result: wire.external_result === 'timeout' ? 'timeout' : 'error',
      metadata: withKind(job, kind, {
        ...wire.metadata,
        probe_kind: kind,
        error_class: wire.metadata?.error_class ?? 'non_definitive_dns_response',
      }),
    };
  }
  const dnskey_count = wire.metadata.matching_answer_count;
  const durationMs = observedProbeDurationMs(deps);
  const dnssec_configured = dnskey_count > 0;
  return {
    external_result: 'connected',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      query_name: zone,
      qtype: 'DNSKEY',
      rcode: wire.metadata.rcode ?? null,
      response_bytes: wire.metadata.response_bytes ?? null,
      dnskey_count,
      ds_count: null,
      dnssec_chain_validated: false,
      assurance: 'authoritative_dnskey_presence_only',
      dnssec_configured: null,
      dnskey_present: dnssec_configured,
      dnssec_missing: null,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: wire.requests_sent,
    duration_ms: durationMs,
  };
}

/**
 * P1 — AXFR leak: single TCP-53 AXFR attempt against first NS.
 */
export async function probeAxfrLeak(job, deps = {}) {
  const kind = 'dns_axfr_leak';
  // Never trust profile.zone here, even after signature verification. A stale, maliciously
  // pre-signed, or corrupt job must not turn an owned target A into an NS lookup and TCP/53
  // connection for victim B.
  const zone = canonicalDnsHostname(apexDomain(job));
  if (!zone) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  deps = ensureProbeDeadline(job, deps);
  const budgetFailure = mandatoryBudgetFailure(job, kind);
  if (budgetFailure) return budgetFailure;

  let requestsSent = 0;
  let resolverAttempts = 0;
  let transportAttempts = 0;
  if (remainingProbeTimeoutMs(job, deps) <= 0) {
    return deadlineOutcome(job, kind, deps, requestsSent, { zone, resolver_attempts: 0 });
  }
  requestsSent += 1;
  resolverAttempts += 1;
  let nameservers;
  try {
    nameservers = await resolveNs(zone, deps);
  } catch (error) {
    return dnsResolverFailureOutcome(job, kind, deps, requestsSent, error, {
      zone,
      resolver_attempts: resolverAttempts,
      transport_attempts: transportAttempts,
    });
  }
  if (remainingProbeTimeoutMs(job, deps) <= 0) {
    return deadlineOutcome(job, kind, deps, requestsSent, { zone, resolver_attempts: resolverAttempts });
  }
  if (!nameservers.length) {
    const durationMs = observedProbeDurationMs(deps);
    return {
      external_result: 'not_run',
      metadata: withKind(job, kind, {
        axfr_refused: false,
        observation_only: true, readiness_conclusion: false,
        reason: 'no_nameservers',
        zone,
        resolver_attempts: resolverAttempts,
        transport_attempts: transportAttempts,
        request_counting_basis: 'logical_operations',
        duration_ms: durationMs,
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  }

  const nsHost = nameservers[0];

  // The nameserver is discovered mid-probe, so the worker chokepoint never saw it.
  const nsVerdict = await vetProbeDestinationHost(nsHost, deps);
  if (remainingProbeTimeoutMs(job, deps) <= 0) {
    return deadlineOutcome(job, kind, deps, requestsSent, {
      zone,
      nameserver: nsHost,
      resolver_attempts: resolverAttempts,
    });
  }
  if (!nsVerdict.ok || nsVerdict.addresses.length === 0) {
    const durationMs = observedProbeDurationMs(deps);
    return {
      external_result: 'error',
      metadata: withKind(job, kind, {
        error_class: nsVerdict.error_class ?? 'resolver_not_routable',
        zone,
        nameserver: nsHost,
        blocked_address: nsVerdict.blocked_address ?? null,
        reason: nsVerdict.reason ?? 'no_resolved_addresses',
        resolver_attempts: resolverAttempts,
        destination_vetting_resolver_attempts: net.isIP(nsHost) === 0 ? 2 : 0,
        transport_attempts: transportAttempts,
        request_counting_basis: 'logical_operations',
        duration_ms: durationMs,
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  }

  const outcome = await runDnsTcpAxfrQuery({
    nsHost: nsVerdict.addresses[0],
    zone,
    timeoutMs: remainingProbeTimeoutMs(job, deps),
    connectFn: deps.connectFn,
    transactionId: deps.axfrTransactionId,
    transactionIdFn: deps.axfrTransactionIdFn,
    beforeProbeIoAttempt: deps.beforeProbeIoAttempt,
    recordProbeLogicalAttempt: deps.recordProbeLogicalAttempt,
    signal: deps.jobDeadlineSignal,
    onAttempt: () => {
      requestsSent += 1;
      transportAttempts += 1;
    },
  });

  const durationMs = observedProbeDurationMs(deps);
  const leaked = outcome.axfr_leak === true;
  return {
    external_result: leaked ? 'connected' : outcome.axfr_refused === true ? 'blocked' : outcome.error_class === 'timeout' ? 'timeout' : 'not_run',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      zone,
      nameserver: nsHost,
      ...outcome,
      observation_only: !leaked && outcome.axfr_refused !== true,
      readiness_conclusion: leaked || outcome.axfr_refused === true,
      resolver_attempts: resolverAttempts,
      destination_vetting_resolver_attempts: net.isIP(nsHost) === 0 ? 2 : 0,
      transport_attempts: transportAttempts,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

/**
 * P1 — TLS audit: protocol, cipher, cert expiry, authorization.
 */
export async function probeTlsAudit(job, deps = {}) {
  const kind = 'tls_audit';
  const host = apexDomain(job);
  if (!host) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  deps = ensureProbeDeadline(job, deps);
  const connectFn = deps.connectFn ?? tls.connect;
  const hostVerdict = await vetProbeDestinationHost(host, deps);
  if (remainingProbeTimeoutMs(job, deps) <= 0) {
    return deadlineOutcome(job, kind, deps, 0, { audit_host: host });
  }
  if (!hostVerdict.ok || hostVerdict.addresses.length === 0) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, {
        error_class: 'resolver_not_routable',
        audit_host: host,
        blocked_address: hostVerdict.blocked_address ?? null,
        reason: hostVerdict.reason ?? 'no_resolved_addresses',
      }),
      requests_sent: 0,
      duration_ms: observedProbeDurationMs(deps),
    };
  }

  let requestsSent = 0;
  try {
    const session = await new Promise((resolve, reject) => {
      let settled = false;
      const socket = startProbeIoAttempt(
        deps,
        'tls_connect',
        () => connectFn({
        host: hostVerdict.addresses[0],
        port: Number(job.target?.port) || Number(httpProbeEndpoint(job)?.url ? new URL(httpProbeEndpoint(job).url).port : '') || 443,
        ...(net.isIP(host) === 0 ? { servername: host } : {}),
          rejectUnauthorized: false,
        }),
        () => { requestsSent = 1; },
      );
      const signal = deps.jobDeadlineSignal;
      const timer = setTimeout(() => settle(Object.assign(new Error('timeout'), { code: 'ETIMEOUT', name: 'AbortError' })), remainingProbeTimeoutMs(job, deps));
      const onAbort = () => settle(probeDeadlineError());
      const settle = (err, result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
        socket.removeListener('secureConnect', onSecureConnect);
        if (err) {
          socket.destroy();
          reject(err);
          return;
        }
        socket.end();
        resolve(result);
      };
      const onSecureConnect = () => {
        const cert = socket.getPeerCertificate();
        settle(null, {
          tls_protocol: socket.getProtocol(),
          cipher: socket.getCipher()?.name ?? null,
          authorized: socket.authorized,
          certificate_hostname_match: cert && Object.keys(cert).length > 0 ? !tls.checkServerIdentity(host, cert) : null,
          certificate_not_yet_valid: cert?.valid_from ? new Date(cert.valid_from).getTime() > Date.now() : null,
          valid_to: cert?.valid_to ?? null,
          issuer: cert?.issuer?.O ?? null,
          subject: cert?.subject?.CN ?? null,
          days_to_expiry: cert?.valid_to ? Math.floor((new Date(cert.valid_to) - Date.now()) / 86400000) : null,
        });
      };
      socket.once('secureConnect', onSecureConnect);
      socket.once('error', (err) => settle(err));
      if (signal?.aborted) onAbort();
      else signal?.addEventListener('abort', onAbort, { once: true });
    });

    const durationMs = observedProbeDurationMs(deps);
    const weak_tls = WEAK_TLS_PROTOCOLS.has(session.tls_protocol);
    const cert_expired = session.days_to_expiry != null && session.days_to_expiry < 0;
    const issues = [];
    if (weak_tls) issues.push('weak_tls_protocol');
    if (cert_expired) issues.push('cert_expired');
    if (!session.authorized) issues.push('unauthorized_chain');
    if (session.certificate_hostname_match === false) issues.push('certificate_hostname_mismatch');
    if (session.certificate_not_yet_valid === true) issues.push('certificate_not_yet_valid');

    return {
      external_result: 'connected',
      metadata: withKind(job, kind, { duration_ms: durationMs, ...session, tls_issues: issues,
        complete: true, target_port: Number(job.target?.port) || Number(httpProbeEndpoint(job)?.url ? new URL(httpProbeEndpoint(job).url).port : '') || 443,
        pinned_address: hostVerdict.addresses[0] }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  } catch (err) {
    const durationMs = observedProbeDurationMs(deps);
    return {
      external_result: classifyFetchError(err),
      metadata: withKind(job, kind, { error_class: err.code ?? err.name, duration_ms: durationMs,
        complete: requestsSent === 1,
        target_port: Number(job.target?.port) || Number(httpProbeEndpoint(job)?.url ? new URL(httpProbeEndpoint(job).url).port : '') || 443,
        pinned_address: hostVerdict.addresses[0] }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  }
}

/**
 * P1 — Cache/CDN abuse: cache-bust + vary probe.
 */
export async function probeCacheAbuse(job, deps = {}) {
  const kind = 'cache_abuse_probe';
  const base = job.target?.value?.startsWith('http') ? job.target.value : baseUrlForHost(apexDomain(job) ?? '');
  if (!base) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  deps = ensureProbeDeadline(job, deps);
  const observations = [];
  let transportError = null;
  let requestsSent = 0;
  const maxObservations = resolveBoundedSequenceBudget(job, { ceiling: 3 });
  const urls = [
    base,
    `${base}${base.includes('?') ? '&' : '?'}cb=${Date.now()}`,
    base,
  ].slice(0, maxObservations);

  for (const url of urls) {
    if (remainingProbeTimeoutMs(job, deps) <= 0) {
      return deadlineOutcome(job, kind, deps, requestsSent, { observations });
    }
    const { res, error, attempted } = await boundedFetch(url, {
      timeoutMs: remainingProbeTimeoutMs(job, deps),
      fetchOptions: {
        method: 'HEAD',
        redirect: 'manual',
        headers: { 'x-astranull-cache-probe': '1' },
      },
    }, deps);
    if (attempted) requestsSent += 1;
    if (!attempted || isProbeDeadlineError(error, deps)) {
      return deadlineOutcome(job, kind, deps, requestsSent, { observations });
    }
    if (error) {
      transportError = error.code ?? error.name ?? 'probe_transport_error';
      break;
    }
    observations.push({
      cache_control: res.headers.get('cache-control'),
      age: res.headers.get('age'),
      x_cache: res.headers.get('x-cache') ?? res.headers.get('cf-cache-status'),
      status: res.status,
    });
  }

  const durationMs = observedProbeDurationMs(deps);
  const sensitive_cached = null;
  const cache_key_weakness = null;
  const comparisonComplete = observations.length === 3;
  return {
    external_result: transportError ? 'error' : observations.length ? 'connected' : 'not_run',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      observations,
      sensitive_cached,
      cache_key_weakness,
      comparison_complete: comparisonComplete,
      ...(transportError ? { error_class: transportError } : {}),
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

/**
 * P1 — API surface scan: common doc paths.
 */
export async function probeApiSurfaceScan(job, deps = {}) {
  const kind = 'api_surface_scan';
  const endpoint = httpProbeEndpoint(job);
  const origin = endpoint ? new URL(endpoint.url).origin : null;

  if (!origin) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  deps = ensureProbeDeadline(job, deps);
  const budget = resolveProbeRequestBudget(job);
  const configuredPaths = job.probe_profile?.paths ?? API_DOC_PATHS;
  if (!Array.isArray(configuredPaths) || configuredPaths.some((path) => !normalizeProbeHttpPath(path))) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsafe_api_probe_path' }), requests_sent: 0, duration_ms: 0 };
  }
  const paths = configuredPaths.slice(0, budget);
  const path_observations = [];
  const exposed_paths = [];
  const path_errors = [];
  let requestsSent = 0;

  for (const path of paths) {
    if (remainingProbeTimeoutMs(job, deps) <= 0) {
      return deadlineOutcome(job, kind, deps, requestsSent, { exposed_paths });
    }
    const { res, error, attempted } = await boundedFetch(`${origin}${path}`, {
      timeoutMs: remainingProbeTimeoutMs(job, deps),
      fetchOptions: { method: 'HEAD', redirect: 'manual' },
    }, deps);
    if (attempted) requestsSent += 1;
    if (!attempted || isProbeDeadlineError(error, deps)) {
      return deadlineOutcome(job, kind, deps, requestsSent, { exposed_paths });
    }
    if (error) {
      path_errors.push({ path, error_class: error.code ?? error.name ?? 'probe_transport_error' });
      continue;
    }
    path_observations.push({ path, status: res.status, content_type: res.headers?.get?.('content-type') ?? null, redirect_observed: res.status >= 300 && res.status < 400 });
  }

  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: path_observations.length ? 'connected' : path_errors.length ? 'error' : 'not_run',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      exposed_paths,
      path_observations,
      api_identity_confirmed: false,
      exposure_count: null,
      path_errors,
      ...(exposed_paths.length === 0 && path_errors.length > 0
        ? { error_class: path_errors[0].error_class }
        : {}),
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

/**
 * P1 — CORS posture: OPTIONS preflight with foreign Origin.
 */
export async function probeCorsPosture(job, deps = {}) {
  const kind = 'cors_posture_probe';
  const url = job.target?.value?.startsWith('http') ? job.target.value : baseUrlForHost(apexDomain(job) ?? '');
  if (!url) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  const started = Date.now();
  const { res, error } = await boundedFetch(url, {
    timeoutMs: job.constraints?.timeout_ms ?? 5000,
    fetchOptions: {
      method: 'OPTIONS',
      redirect: 'manual',
      headers: {
        Origin: 'https://probe.invalid.astranull',
        'Access-Control-Request-Method': 'GET',
      },
    },
  }, deps);

  const durationMs = Date.now() - started;
  if (error) {
    return {
      external_result: classifyFetchError(error),
      metadata: withKind(job, kind, { error_class: error.code ?? error.name, duration_ms: durationMs }),
      requests_sent: 1,
      duration_ms: durationMs,
    };
  }

  const acao = res.headers.get('access-control-allow-origin');
  const weak_cors = null;
  const origin_permission_advertised = acao === '*' || acao === 'https://probe.invalid.astranull';
  return {
    external_result: 'connected',
    metadata: withKind(job, kind, {
      status_code: res.status,
      access_control_allow_origin: acao,
      weak_cors,
      origin_permission_advertised,
      credentials_advertised: res.headers.get('access-control-allow-credentials') === 'true',
      sensitive_exposure_confirmed: false,
      duration_ms: durationMs,
    }),
    requests_sent: 1,
    duration_ms: durationMs,
  };
}

/**
 * P1 — Bot/challenge: cookie-less scripted client.
 */
export async function probeBotChallenge(job, deps = {}) {
  const kind = 'bot_challenge_probe';
  const url = job.target?.value?.startsWith('http') ? job.target.value : baseUrlForHost(apexDomain(job) ?? '');
  if (!url) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  const started = Date.now();
  const { res, error } = await boundedFetch(url, {
    timeoutMs: job.constraints?.timeout_ms ?? 5000,
    fetchOptions: {
      method: 'HEAD',
      redirect: 'manual',
      headers: {
        'User-Agent': 'AstraNullBotProbe/1.0 (+https://astranull.invalid/bot-probe)',
        Accept: '*/*',
      },
    },
  }, deps);

  const durationMs = Date.now() - started;
  if (error) {
    return {
      external_result: classifyFetchError(error),
      metadata: withKind(job, kind, { error_class: error.code ?? error.name, duration_ms: durationMs }),
      requests_sent: 1,
      duration_ms: durationMs,
    };
  }

  const actionSignature = matchControlDenialSignature({ statusCode: res.status, headers: res, declared: job.probe_profile?.declared_block_signature ?? null });
  const challenged = Boolean(actionSignature);
  const challenge_header = res.headers.get('cf-mitigated') ?? res.headers.get('x-bot-challenge') ?? null;
  const no_challenge = res.status >= 200 && res.status < 300 && !challenge_header;

  return {
    external_result: 'connected',
    metadata: withKind(job, kind, {
      status_code: res.status,
      challenge_header,
      bot_challenge_missing: null,
      challenge_observed: challenged,
      denial_signature: actionSignature,
      challenge_not_observed: no_challenge,
      duration_ms: durationMs,
    }),
    requests_sent: 1,
    duration_ms: durationMs,
  };
}

/**
 * P1 — GraphQL posture: endpoint reachability + complexity signal headers.
 */
export async function probeGraphqlPosture(job, deps = {}) {
  const kind = 'graphql_posture_probe';
  const endpoint = httpProbeEndpoint(job, job.probe_profile?.graphql_path ?? (/^https?:\/\//i.test(job.target?.value ?? '') ? null : '/graphql'));
  const path = endpoint?.probePath;
  const origin = endpoint ? new URL(endpoint.url).origin : null;

  if (!origin) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  const started = Date.now();
  const { res, error } = await boundedFetch(endpoint?.url ?? `${origin}${path}`, {
    timeoutMs: job.constraints?.timeout_ms ?? 5000,
    fetchOptions: {
      method: 'HEAD',
      redirect: 'manual',
      headers: { Accept: 'application/json' },
    },
  }, deps);

  const durationMs = Date.now() - started;
  if (error) {
    return {
      external_result: classifyFetchError(error),
      metadata: withKind(job, kind, { error_class: error.code ?? error.name, duration_ms: durationMs }),
      requests_sent: 1,
      duration_ms: durationMs,
    };
  }

  const exposed = res.status >= 200 && res.status < 400;
  const complexity_limits_advertised = Boolean(
    res.headers.get('x-graphql-complexity-limit'),
  );

  return {
    external_result: 'connected',
    metadata: withKind(job, kind, {
      status_code: res.status,
      graphql_exposed: null,
      route_response_observed: exposed,
      graphql_identity_confirmed: false,
      complexity_enforcement_confirmed: false,
      complexity_limits_advertised,
      duration_ms: durationMs,
    }),
    requests_sent: 1,
    duration_ms: durationMs,
  };
}

/**
 * P1 — Open resolver: single external lookup via declared resolver.
 */
export async function probeOpenRecursion(job, deps = {}) {
  const kind = 'dns_open_recursion';
  // resolver_host and recursion_test_name are accepted only as exact-target metadata at the
  // signing boundary. Derive them again here so a corrupt/pre-signed job cannot select a sibling
  // resolver or induce a lookup for an unrelated declared domain.
  const targetHost = canonicalDnsHostname(apexDomain(job));
  const resolverHost = targetHost;
  if (!resolverHost) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, { error_class: 'unsupported_target' }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  deps = ensureProbeDeadline(job, deps);
  const queryName = targetHost;
  const resolverVerdict = await vetProbeDestinationHost(resolverHost, deps);
  if (remainingProbeTimeoutMs(job, deps) <= 0) {
    return deadlineOutcome(job, kind, deps, 0, { resolver_host: resolverHost });
  }
  if (!resolverVerdict.ok) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, {
        error_class: resolverVerdict.blocked_address ? 'resolver_not_routable' : (resolverVerdict.error_class ?? 'resolver_not_routable'),
        resolver_host: resolverHost,
        blocked_address: resolverVerdict.blocked_address ?? null,
        reason: resolverVerdict.reason,
      }),
      requests_sent: 0,
      duration_ms: observedProbeDurationMs(deps),
    };
  }

  const resolveExternal = deps.resolve4ExternalFn ?? (async (resolver, name) => {
    const resolverClient = new Resolver();
    resolverClient.setServers([resolver]);
    return resolverClient.resolve4(name);
  });

  const resolverAddress = resolverVerdict.addresses?.[0] ?? resolverHost;

  let open_recursion = false;
  let requestsSent = 0;
  try {
    await withinRemainingProbeTime(
      startProbeIoAttempt(
        deps,
        'dns_external_lookup',
        () => resolveExternal(resolverAddress, queryName),
        () => { requestsSent = 1; },
      ),
      job,
      deps,
    );
    open_recursion = true;
  } catch (error) {
    if (!isAuthoritativeDnsNegative(error)) {
      return dnsResolverFailureOutcome(job, kind, deps, requestsSent, error, {
        resolver_host: resolverHost,
        resolver_address: resolverAddress,
        recursion_test_name: queryName,
      });
    }
  }

  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: 'connected',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      resolver_host: resolverHost,
      resolver_address: resolverAddress,
      recursion_test_name: queryName,
      open_recursion_detected: null,
      same_target_answer_observed: open_recursion,
      recursion_proof_available: false,
      resolver_attempts: requestsSent,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

/**
 * P1 — Secondary DNS failover posture: NS count and declared secondary reachability.
 */
export async function probeDnsFailoverPosture(job, deps = {}) {
  const kind = 'dns_failover_posture';
  const zone = apexDomain(job);
  if (!zone) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, { error_class: 'unsupported_target' }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  deps = ensureProbeDeadline(job, deps);
  if (remainingProbeTimeoutMs(job, deps) <= 0) {
    return deadlineOutcome(job, kind, deps, 0, { zone });
  }
  let nameservers;
  try {
    nameservers = await resolveNs(zone, deps);
  } catch (error) {
    return dnsResolverFailureOutcome(job, kind, deps, 1, error, { zone });
  }
  let requestsSent = 1;
  if (remainingProbeTimeoutMs(job, deps) <= 0) {
    return deadlineOutcome(job, kind, deps, requestsSent, { zone, nameservers: nameservers.slice(0, 4) });
  }
  const budget = resolveProbeRequestBudget(job);
  const remainingBudget = Math.max(0, budget - requestsSent);
  const declaredSecondary = (job.probe_profile?.secondary_nameservers ?? [])
    .filter((nameserver) => isExactDnsHostname(nameserver, zone))
    .map(() => canonicalDnsHostname(zone))
    .filter(Boolean)
    .slice(0, remainingBudget);
  const secondary_results = [];

  for (const ns of declaredSecondary) {
    if (requestsSent >= budget) break;
    if (remainingProbeTimeoutMs(job, deps) <= 0) {
      return deadlineOutcome(job, kind, deps, requestsSent, {
        zone,
        nameservers: nameservers.slice(0, 4),
        secondary_results,
      });
    }
    requestsSent += 1;
    let addrs;
    try {
      addrs = await resolve4(ns, deps);
    } catch (error) {
      return dnsResolverFailureOutcome(job, kind, deps, requestsSent, error, {
        zone,
        nameservers: nameservers.slice(0, 4),
        secondary_results,
      });
    }
    secondary_results.push({ nameserver: ns, hostname_resolved: addrs.length > 0, reachable: null, addresses: addrs.slice(0, 2) });
  }

  const weak_failover = nameservers.length < 2
    || (declaredSecondary.length > 0 && secondary_results.some((r) => !r.reachable));
  const durationMs = observedProbeDurationMs(deps);

  return {
    external_result: 'connected',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      zone,
      nameserver_count: nameservers.length,
      nameservers: nameservers.slice(0, 4),
      secondary_results,
      weak_failover: null,
      nameserver_count_below_two: nameservers.length < 2,
      failover_exercised: false,
      resolver_attempts: requestsSent,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

const DELEGATED_SAFE_HTTP_METHODS = new Set(['GET', 'HEAD']);
const DELEGATED_MAX_ACTUAL_BODY_BYTES = 4096;
const DELEGATED_FORBIDDEN_HEADERS = new Set([
  'connection',
  'content-length',
  'transfer-encoding',
  'upgrade',
  'x-http-method-override',
  'x-method-override',
]);

function delegatedTargetUrl(job) {
  const value = String(job?.target?.value ?? '').trim();
  if (!value) return null;
  try {
    const url = /^https?:\/\//i.test(value) ? new URL(value) : new URL(`https://${value}/`);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    return url.href;
  } catch {
    return null;
  }
}

function delegatedHeaderNames(headers) {
  if (!headers) return [];
  if (typeof headers.keys === 'function') return [...headers.keys()].map((key) => String(key).toLowerCase());
  return Object.keys(headers).map((key) => String(key).toLowerCase());
}

function delegatedBodyBytes(body) {
  if (body == null) return 0;
  if (typeof body === 'string' || Buffer.isBuffer(body) || body instanceof Uint8Array) {
    return Buffer.byteLength(body);
  }
  return Number.POSITIVE_INFINITY;
}

function createDelegatedHttpTransport(job, deps, state) {
  const targetUrl = delegatedTargetUrl(job);
  if (!targetUrl) return { targetUrl: null, request: null };
  const targetOrigin = new URL(targetUrl).origin;
  const request = async (input, init = {}) => {
    let requestUrl;
    try {
      requestUrl = new URL(String(input));
    } catch {
      state.error = Object.assign(new Error('Invalid delegated probe URL.'), {
        code: 'delegated_target_mismatch',
      });
      throw state.error;
    }
    if (requestUrl.origin !== targetOrigin || requestUrl.username || requestUrl.password) {
      state.error = Object.assign(new Error('Delegated probe attempted to retarget.'), {
        code: 'delegated_target_mismatch',
      });
      throw state.error;
    }

    const method = String(init.method ?? 'GET').toUpperCase();
    const bodyBytes = delegatedBodyBytes(init.body);
    const hasForbiddenHeader = delegatedHeaderNames(init.headers)
      .some((name) => DELEGATED_FORBIDDEN_HEADERS.has(name));
    if (
      !DELEGATED_SAFE_HTTP_METHODS.has(method)
      || (['GET', 'HEAD'].includes(method) && init.body != null)
      || bodyBytes > DELEGATED_MAX_ACTUAL_BODY_BYTES
      || hasForbiddenHeader
    ) {
      state.error = Object.assign(new Error('Unsafe delegated HTTP request refused.'), {
        code: 'unsafe_delegated_http_request',
      });
      throw state.error;
    }

    const outcome = await boundedFetch(requestUrl.href, {
      timeoutMs: remainingProbeTimeoutMs(job, deps),
      fetchOptions: {
        ...init,
        method,
        redirect: 'manual',
      },
    }, deps);
    if (outcome.attempted) state.requestsSent += 1;
    if (outcome.error) {
      state.error = outcome.error;
      throw outcome.error;
    }
    const bodyText = await signatureBodyOf(outcome.res, method, job, deps);
    if (method === 'HEAD') await outcome.res?.body?.cancel?.().catch?.(() => {});
    // Preserve the bounded transient prefix for downstream signature grading.
    return { status: outcome.res.status, headers: outcome.res.headers,
      bodyText, body_complete: signatureBodyComplete(outcome.res),
      body: new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(bodyText)); controller.close(); } }),
    };
  };
  return { targetUrl, request };
}

function delegatedFailureOutcome(job, kind, deps, state, rawMetadata = {}) {
  const error = state.error;
  if (!error) return null;
  if (isOperationBudgetError(error)) throw error;
  if (isProbeDeadlineError(error, deps)) {
    return deadlineOutcome(job, kind, deps, state.requestsSent, rawMetadata);
  }
  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: 'error',
    metadata: withKind(job, kind, {
      ...rawMetadata,
      error_class: error?.code ?? error?.name ?? 'delegated_probe_failed',
      duration_ms: durationMs,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: state.requestsSent,
    duration_ms: durationMs,
  };
}

export async function probeWafClassMarker(job, deps = {}) {
  const kind = 'waf_class_marker_probe';
  const authorizationFailure = capabilityProbeAuthorizationFailure(job, kind, deps);
  if (authorizationFailure) return authorizationFailure;
  deps = ensureProbeDeadline(job, deps);
  const state = { requestsSent: 0, error: null };
  const transport = createDelegatedHttpTransport(job, deps, state);
  if (!transport.request) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, { error_class: 'unsupported_target' }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }
  const budget = Math.min(resolveProbeRequestBudget(job), WAF_CLASS_PROBE_MAX_REQUESTS);
  const raw = await (deps.wafClassProbeFn ?? runRawWafClassMarkerProbe)({
    url: transport.targetUrl,
    marker_class: job.probe_profile?.marker_class,
    max_requests: budget,
    timeout_ms: remainingProbeTimeoutMs(job, deps),
    fetchFn: transport.request,
    declared_block_signature: job.probe_profile?.declared_block_signature ?? null,
    ...(job.probe_profile?.entry_path_scenario ? {
      entry_path_scenario: job.probe_profile.entry_path_scenario,
      expected_nonce: job.nonce ?? null,
    } : {}),
  });
  const failure = delegatedFailureOutcome(job, kind, deps, state, {
    marker_class: raw?.marker_class ?? job.probe_profile?.marker_class ?? null,
  });
  if (failure) return failure;

  const rawMetadata = { ...(raw ?? {}) };
  delete rawMetadata.requests_sent;
  const hasMarkerEvidence = Array.isArray(raw?.marker_results) && raw.marker_results.length > 0
    && raw.comparison_complete === true && raw.classifier_version === 'marker-comparison-v4'
    && Number.isSafeInteger(raw.planned_marker_legs) && raw.planned_marker_legs > 0
    && raw.completed_marker_legs === raw.planned_marker_legs
    && (raw.baseline_health ?? raw.permitted_baseline?.health) === 'healthy';
  const externalResult = raw?.error_class
    ? 'error'
    : hasMarkerEvidence && raw.posture === 'protected'
      ? 'blocked'
      : hasMarkerEvidence && raw.posture === 'exposed'
        ? 'connected'
        : 'not_run';
  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: externalResult,
    metadata: withKind(job, kind, {
      ...rawMetadata,
      max_requests: budget,
      observation_only: externalResult === 'not_run',
      readiness_conclusion: ['blocked', 'connected'].includes(externalResult),
      ...(externalResult === 'not_run'
        ? { not_run_reason: 'insufficient_marker_comparison' }
        : {}),
      duration_ms: durationMs,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: state.requestsSent,
    duration_ms: durationMs,
  };
}

export async function probeWafEvasionMarker(job, deps = {}) {
  const kind = 'waf_evasion_marker_probe';
  const authorizationFailure = capabilityProbeAuthorizationFailure(job, kind, deps);
  if (authorizationFailure) return authorizationFailure;
  deps = ensureProbeDeadline(job, deps);
  const state = { requestsSent: 0, error: null };
  const transport = createDelegatedHttpTransport(job, deps, state);
  if (!transport.request) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, { error_class: 'unsupported_target' }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }
  const budget = Math.min(resolveProbeRequestBudget(job), MAX_WAF_EVASION_MARKER_REQUESTS);
  const raw = await (deps.wafEvasionProbeFn ?? runRawWafEvasionMarkerProbe)({
    ...job,
    target: { ...job.target, value: transport.targetUrl },
    constraints: { ...job.constraints, max_requests: budget },
    probe_profile: { ...job.probe_profile, max_requests: budget },
  }, {
    ...deps,
    fetchFn: transport.request,
    signal: deps.jobDeadlineSignal,
  });
  const failure = delegatedFailureOutcome(job, kind, deps, state, raw?.metadata);
  if (failure) return failure;

  const comparisonComplete = raw?.metadata?.comparison_complete === true
    && raw.metadata.classifier_version === 'marker-comparison-v4'
    && raw.metadata.permitted_baseline_health === 'healthy'
    && raw.metadata.planned_marker_legs === 2 && raw.metadata.completed_marker_legs === 2;
  const externalResult = raw?.external_result === 'error' ? 'error' : !comparisonComplete ? 'not_run' : raw?.external_result === 'external_blocked'
    ? 'blocked'
    : raw?.external_result === 'external_allowed'
      ? 'connected'
      : raw?.external_result === 'error'
        ? 'error'
        : 'not_run';
  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: externalResult,
    metadata: withKind(job, kind, {
      ...(raw?.metadata ?? {}),
      observation_only: externalResult === 'not_run',
      readiness_conclusion: ['blocked', 'connected'].includes(externalResult),
      ...(externalResult === 'not_run'
        ? { not_run_reason: 'insufficient_evasion_comparison', comparison_reason: raw?.metadata?.inconclusive_reason ?? (raw?.metadata?.baseline_blocked === false ? 'baseline_marker_not_blocked' : 'comparison_incomplete') }
        : {}),
      duration_ms: durationMs,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: state.requestsSent,
    duration_ms: durationMs,
  };
}

export async function probeDelegatedL7ResourcePosture(job, deps = {}) {
  const kind = 'l7_resource_posture_probe';
  const authorizationFailure = capabilityProbeAuthorizationFailure(job, kind, deps);
  if (authorizationFailure) return authorizationFailure;
  deps = ensureProbeDeadline(job, deps);
  const state = { requestsSent: 0, error: null };
  const transport = createDelegatedHttpTransport(job, deps, state);
  if (!transport.request) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, { error_class: 'unsupported_target' }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }
  const budget = Math.min(resolveProbeRequestBudget(job), L7_RESOURCE_POSTURE_MAX_REQUESTS);
  const raw = await (deps.l7ResourceProbeFn ?? runRawL7ResourcePostureProbe)({
    ...job,
    target: { ...job.target, value: transport.targetUrl },
    constraints: { ...job.constraints, max_requests: budget },
    probe_profile: { ...job.probe_profile, max_requests: budget },
  }, {
    ...deps,
    requestFn: (url, options) => transport.request(url, options),
  });
  const failure = delegatedFailureOutcome(job, kind, deps, state, raw?.metadata);
  if (failure) return failure;

  const externalResult = ['blocked', 'connected', 'error', 'timeout', 'not_run']
    .includes(raw?.external_result)
    ? raw.external_result
    : 'error';
  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: externalResult,
    metadata: withKind(job, kind, {
      ...(raw?.metadata ?? {}),
      duration_ms: durationMs,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: state.requestsSent,
    duration_ms: durationMs,
  };
}

/** Existing metadata-only refusals must precede destination resolution. Never run an injected producer here. */
export async function capabilityProbeNoDeliveryOutcome(job, deps = {}) {
  const profile = job.probe_profile ?? {};
  if (profile.kind === 'waf_inspection_limit_probe') return probeWafInspectionLimit(job, deps);
  if (profile.kind === 'waf_evasion_marker_probe'
    && isEvasionTransform(profile.evasion_transform)
    && !isSupportedEvasionTransform(profile.evasion_transform)) {
    return probeWafEvasionMarker(job, { ...deps, wafEvasionProbeFn: runRawWafEvasionMarkerProbe });
  }
  if (profile.kind === 'l7_resource_posture_probe' && profile.marker_class === 'declared_content_encoding') {
    return probeDelegatedL7ResourcePosture(job, { ...deps, l7ResourceProbeFn: runRawL7ResourcePostureProbe });
  }
  return null;
}

export const CAPABILITY_PROBE_DISPATCH = Object.freeze({
  waf_fingerprint_observation: probeOutsideInWafScan,
  outside_in_waf_scan: probeOutsideInWafScan,
  origin_leak_scan: probeOriginLeakScan,
  host_sni_bypass: probeHostSniBypass,
  port_scan_bounded: probePortScanBounded,
  rate_limit_sequence: probeRateLimitSequence,
  http_method_matrix: probeHttpMethodMatrix,
  header_size_probe: probeHeaderSizeBoundary,
  slow_header_probe: probeSlowHeaderTimeout,
  http2_frame_probe: probeHttp2FrameBehavior,
  http3_control_probe: probeHttp3ControlStream,
  waf_inspection_limit_probe: probeWafInspectionLimit,
  waf_enforcement_probe: probeWafEnforcement,
  dnssec_posture: probeDnssecPosture,
  dns_open_recursion: probeOpenRecursion,
  dns_failover_posture: probeDnsFailoverPosture,
  dns_axfr_leak: probeAxfrLeak,
  tls_audit: probeTlsAudit,
  cache_abuse_probe: probeCacheAbuse,
  api_surface_scan: probeApiSurfaceScan,
  cors_posture_probe: probeCorsPosture,
  bot_challenge_probe: probeBotChallenge,
  graphql_posture_probe: probeGraphqlPosture,
  grpc_reflection_probe: probeGrpcReflection,
  waf_evasion_marker_probe: probeWafEvasionMarker,
  l7_resource_posture_probe: probeDelegatedL7ResourcePosture,
  waf_class_marker_probe: probeWafClassMarker,
});

const GRPC_HEALTH_PATH = '/grpc.health.v1.Health/Check';
const GRPC_REFLECTION_PATHS = new Set([
  '/grpc.reflection.v1.ServerReflection/ServerReflectionInfo',
  '/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo',
]);
const DEFAULT_GRPC_REFLECTION_PATH = '/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo';

function grpcRequestSpec(configuredPath) {
  const path = configuredPath == null ? DEFAULT_GRPC_REFLECTION_PATH : normalizeProbeHttpPath(configuredPath);
  if (!path) return null;
  if (GRPC_REFLECTION_PATHS.has(path)) {
    // ServerReflectionRequest.list_services = "" (field 7, length-delimited),
    // wrapped in one uncompressed gRPC frame.
    return {
      path,
      service: 'reflection',
      body: Buffer.from([0, 0, 0, 0, 2, 0x3a, 0]),
    };
  }
  if (path === GRPC_HEALTH_PATH) {
    // HealthCheckRequest with an omitted service field is a valid empty message.
    return { path, service: 'health', body: Buffer.from([0, 0, 0, 0, 0]) };
  }
  return null;
}

/** Strict bounded protobuf framing for the two fixed, read-only gRPC requests. */
function protobufFields(bytes) {
  let offset = 0;
  const fields = [];
  const varint = () => {
    let value = 0;
    for (let count = 0; count < 5; count += 1) {
      if (offset >= bytes.length) throw new RangeError('truncated protobuf');
      const byte = bytes[offset++];
      value += (byte & 127) * (2 ** (count * 7));
      if ((byte & 128) === 0) {
        if (!Number.isSafeInteger(value) || value > 0xffffffff) throw new RangeError('protobuf value too large');
        return value;
      }
    }
    throw new RangeError('protobuf varint too large');
  };
  while (offset < bytes.length) {
    if (fields.length >= 256) throw new RangeError('too many protobuf fields');
    const key = varint();
    const number = Math.floor(key / 8);
    const wire = key & 7;
    if (number < 1 || ![0, 1, 2, 5].includes(wire)) throw new RangeError('invalid protobuf field');
    let value;
    if (wire === 0) value = varint();
    else {
      const size = wire === 2 ? varint() : wire === 1 ? 8 : 4;
      if (offset + size > bytes.length) throw new RangeError('truncated protobuf field');
      value = bytes.subarray(offset, offset + size);
      offset += size;
    }
    fields.push({ number, wire, value });
  }
  return fields;
}

export function validateGrpcResponseBody(body, service) {
  if (!Buffer.isBuffer(body) || body.length < 5 || body.length > 65536 || body[0] !== 0
    || body.readUInt32BE(1) !== body.length - 5) return false;
  try {
    const fields = protobufFields(body.subarray(5));
    if (service === 'health') {
      return fields.length === 1 && fields[0].number === 1 && fields[0].wire === 0
        && fields[0].value >= 0 && fields[0].value <= 3;
    }
    if (service !== 'reflection') return false;
    const original = fields.filter((field) => field.number === 2);
    const lists = fields.filter((field) => field.number === 6);
    if (original.length !== 1 || lists.length !== 1 || original[0].wire !== 2 || lists[0].wire !== 2
      || fields.some((field) => ![1, 2, 6].includes(field.number))) return false;
    const request = protobufFields(original[0].value);
    if (request.length !== 1 || request[0].number !== 7 || request[0].wire !== 2 || request[0].value.length !== 0) return false;
    const services = protobufFields(lists[0].value);
    return services.every((field) => {
      if (field.number !== 1 || field.wire !== 2) return false;
      const name = protobufFields(field.value);
      return name.length === 1 && name[0].number === 1 && name[0].wire === 2
        && /^[A-Za-z_][A-Za-z0-9_.]{0,252}$/.test(name[0].value.toString('utf8'));
    });
  } catch {
    return false;
  }
}

/**
 * DET-021 — exactly one bounded gRPC reflection or health request over TLS
 * HTTP/2. Only the two standard reflection methods and the standard health
 * method are encoded; unknown protobuf methods fail unsupported rather than
 * pretending an empty HTTP/1.1 POST proves reflection routing.
 */
export async function probeGrpcReflection(job, deps = {}) {
  const kind = 'grpc_reflection_probe';
  const requestSpec = grpcRequestSpec(job.probe_profile?.grpc_path);
  if (!requestSpec) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, {
        error_class: 'unsupported_grpc_method',
        reflection_service_routed: null,
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  let endpoint;
  try {
    const value = String(job.target?.value ?? '').trim();
    if (value) endpoint = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`);
  } catch {
    endpoint = null;
  }
  if (!endpoint?.hostname) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, { error_class: 'unsupported_target' }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }
  if (endpoint.protocol !== 'https:') {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, {
        error_class: 'grpc_http2_tls_required',
        grpc_transport: 'unsupported',
        reflection_service_routed: null,
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  deps = ensureProbeDeadline(job, deps);
  const boundedTimeout = remainingProbeTimeoutMs(job, deps);
  if (boundedTimeout <= 0) {
    return deadlineOutcome(job, kind, deps, 0, {
      grpc_transport: 'h2_tls',
      grpc_probe_service: requestSpec.service,
      reflection_service_routed: null,
    });
  }
  const controller = new AbortController();
  const abortForDeadline = () => controller.abort(probeDeadlineError());
  deps.jobDeadlineSignal?.addEventListener('abort', abortForDeadline, { once: true });
  const timer = setTimeout(abortForDeadline, boundedTimeout);
  const requestFn = deps.http2RequestFn
    ?? ((input, init) => pinnedHttp2Request(input, init, deps));

  let res;
  let requestsSent = 0;
  try {
    const request = startProbeIoAttempt(
      deps,
      'grpc_reflection_request',
      () => requestFn(`${endpoint.origin}${requestSpec.path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/grpc',
          TE: 'trailers',
          'grpc-accept-encoding': 'identity',
        },
        body: requestSpec.body,
        signal: controller.signal,
        timeoutMs: boundedTimeout,
        maxResponseBytes: 64 * 1024,
        captureResponseBody: true,
      }),
      () => { requestsSent = 1; },
    );
    res = await withinRemainingProbeTime(Promise.resolve(request), job, deps);
  } catch (error) {
    const deadlineFailed = isProbeDeadlineError(error, deps) || controller.signal.aborted;
    const durationMs = observedProbeDurationMs(deps);
    return {
      external_result: deadlineFailed
        ? (requestsSent > 0 ? 'timeout' : 'error')
        : classifyFetchError(error, { reachability: true }),
      metadata: withKind(job, kind, {
        error_class: deadlineFailed
          ? 'probe_job_deadline_exceeded'
          : (error?.code ?? error?.name ?? 'grpc_transport_failed'),
        grpc_transport: 'h2_tls',
        grpc_probe_service: requestSpec.service,
        reflection_service_routed: null,
        duration_ms: durationMs,
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  } finally {
    clearTimeout(timer);
    deps.jobDeadlineSignal?.removeEventListener('abort', abortForDeadline);
  }

  const durationMs = observedProbeDurationMs(deps);
  if (res.httpVersion !== '2.0') {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, {
        error_class: 'grpc_http2_required',
        grpc_transport: 'unsupported',
        grpc_probe_service: requestSpec.service,
        reflection_service_routed: null,
        duration_ms: durationMs,
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  }

  const trailerStatus = res.trailers?.get('grpc-status') ?? null;
  const headerStatus = res.headers.get('grpc-status');
  const grpcStatus = trailerStatus ?? headerStatus;
  const grpcStatusSource = trailerStatus !== null
    ? 'trailers'
    : (headerStatus !== null ? 'headers' : null);
  const grpcMessage = res.trailers?.get('grpc-message')
    ?? res.headers.get('grpc-message');
  const contentType = res.headers.get('content-type') ?? '';
  const contentTypeIsGrpc = contentType.toLowerCase().startsWith('application/grpc');
  const grpcEndpointReachable = res.status >= 200
    && res.status < 300
    && contentTypeIsGrpc
    && grpcStatus !== null;
  const protocolIdentityConfirmed = grpcEndpointReachable && grpcStatus === '0'
    && validateGrpcResponseBody(res.responseBody, requestSpec.service);
  const requestSucceeded = protocolIdentityConfirmed;
  const isReflection = requestSpec.service === 'reflection';
  const reflectionServiceRouted = isReflection && protocolIdentityConfirmed ? true : null;

  return {
    external_result: requestSucceeded ? 'connected' : 'not_run',
    metadata: withKind(job, kind, {
      status_code: res.status,
      grpc_status: grpcStatus,
      grpc_status_source: grpcStatusSource,
      grpc_message_present: Boolean(grpcMessage),
      content_type_is_grpc: contentTypeIsGrpc,
      grpc_endpoint_reachable: protocolIdentityConfirmed,
      route_response_observed: grpcEndpointReachable,
      protocol_identity_confirmed: protocolIdentityConfirmed,
      response_bytes: res.responseBytes ?? null,
      grpc_request_succeeded: requestSucceeded,
      grpc_probe_service: requestSpec.service,
      grpc_transport: 'h2_tls',
      pinned_address: res.pinnedAddress ?? null,
      reflection_service_routed: reflectionServiceRouted,
      reflection_service_exposed: isReflection && requestSucceeded,
      requests_sent: requestsSent,
      duration_ms: durationMs,
      response_body_retained: false,
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

export async function executeCapabilityProbe(job, deps = {}) {
  const kind = job.probe_profile?.kind;
  const fn = CAPABILITY_PROBE_DISPATCH[kind];
  if (!fn) return null;
  if (!isLiveCapabilityProbeAuthorized(job, deps)) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, {
        error_class: 'live_probe_requires_signed_worker',
        simulation: 'SAFE_PROBE_SIMULATION',
        note: 'Live capability probes require a signed-worker job or injectable test deps.',
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }
  return fn(job, deps);
}
