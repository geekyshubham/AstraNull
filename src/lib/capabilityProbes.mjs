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
import {
  enrichOutsideInWafProbeMetadata,
  resolveDomXssValidation,
} from './outsideInWafAgentEvidence.mjs';
import {
  BENIGN_CLASS_MARKERS,
  OUTSIDE_IN_SCAN_DEFAULT_BUDGET,
  readBoundedResponseBody,
  runOutsideInWafScan,
} from './outsideInWafScanner.mjs';
import { enrichProbeMetadataWithWafCatalog } from './wafProductCatalog.mjs';
import {
  WAF_CLASS_PROBE_MAX_REQUESTS,
  runWafClassMarkerProbe as runRawWafClassMarkerProbe,
} from './vectorProbes/wafClassProbes.mjs';
import {
  MAX_WAF_EVASION_MARKER_REQUESTS,
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
  const timeoutMs = remainingProbeTimeoutMs(job, deps);
  if (timeoutMs <= 0) throw probeDeadlineError();
  let timer;
  return Promise.race([
    Promise.resolve(promise),
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

function withKind(job, kind, metadata) {
  return { profile_kind: kind, probe_kind: kind, ...metadata };
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

function resolveHostSniTargets(job) {
  const targetValue = String(job.target?.value ?? '').trim();
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
        requestUrl = targetValue;
      }
    } catch {
      // ignore malformed URL targets
    }
  }
  if (!directIp && job.target?.kind === 'ip') {
    directIp = targetValue;
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
  return `${https ? 'https' : 'http'}://${host}/`;
}

function httpsHeadWithSni(directIp, hostname, {
  hostHeader = hostname,
  headers = {},
  timeoutMs = 5000,
  port,
  path = '/',
} = {}, deps = {}, onReserved) {
  const requestFn = deps.httpsRequestFn ?? https.request;
  return new Promise((resolve) => {
    const req = startProbeIoAttempt(
      deps,
      'https_head',
      () => requestFn(
        {
          host: directIp,
          ...(port != null ? { port } : {}),
          servername: hostname,
          path,
          method: 'HEAD',
          headers: { Host: hostHeader, ...headers },
          timeout: timeoutMs,
          rejectUnauthorized: false,
        },
        (res) => {
          res.resume();
          resolve({
            res: {
              status: res.statusCode ?? 0,
              headers: { get: (name) => res.headers[String(name).toLowerCase()] ?? null },
            },
            error: null,
          });
        },
      ),
      onReserved,
    );
    req.on('timeout', () => {
      req.destroy();
      resolve({ res: null, error: Object.assign(new Error('timeout'), { name: 'AbortError' }) });
    });
    req.on('error', (err) => resolve({ res: null, error: err }));
    req.end();
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

function classifyFetchError(err) {
  const name = err?.name ?? '';
  const code = err?.code ?? '';
  if (name === 'AbortError' || code === 'probe_job_deadline_exceeded') return 'timeout';
  if (code === 'ECONNREFUSED' || code === 'ENOTFOUND' || code === 'EHOSTUNREACH') return 'blocked';
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
    leak_count: leak_signals.length,
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
  if (apex6.length > 0 && apex4.length === 0) {
    leak_signals.push('ipv6_only_dns');
  }
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
        leak_signals.push(`subdomain_origin_divergence:${prefix}`);
      }
    }
    if (remainingProbeTimeoutMs(job, deps) <= 0) return timeout();
  }

  const directIps = [...origin_ips];
  if (directIps.length && edge_ip && directIps.includes(edge_ip) === false) {
    leak_signals.push('dns_points_not_edge');
  }
  if (directIps.length && !edgeProbe.res) {
    leak_signals.push('dns_only_no_edge_http');
  }

  const durationMs = observedProbeDurationMs(deps);
  const external = leak_signals.length > 0 ? 'connected' : 'blocked';
  return {
    external_result: external,
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      apex_domain: domain,
      origin_ips: directIps.slice(0, 8),
      ipv6_addrs: [...ipv6_addrs].slice(0, 8),
      subdomains_scanned,
      leak_signals,
      leak_count: leak_signals.length,
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
  if (error) {
    return {
      external_result: classifyFetchError(error),
      metadata: withKind(job, kind, { error_class: error.code ?? error.name, protected_host: hostname, direct_ip: directIp, duration_ms: durationMs }),
      requests_sent: 1,
      duration_ms: durationMs,
    };
  }
  const bypassed = res.status >= 200 && res.status < 500;
  return {
    external_result: bypassed ? 'connected' : 'blocked',
    metadata: withKind(job, kind, {
      status_code: res.status,
      protected_host: hostname,
      direct_ip: directIp,
      bypass_signal: bypassed,
      duration_ms: durationMs,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: 1,
    duration_ms: durationMs,
  };
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

  for (const port of ports) {
    if (requestsSent >= budget) break;
    const remainingMs = Math.min(3000, remainingProbeTimeoutMs(job, deps));
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
      risky_admin_ports_open: risky_open,
      exposure_count: open_ports.length,
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
  const probePath = normalizeProbeHttpPath(configuredPath) ?? '/';
  const targetValue = String(job.target?.value ?? '').trim();
  try {
    const origin = /^https?:\/\//i.test(targetValue)
      ? new URL(targetValue).origin
      : baseUrlForHost(apexDomain(job) ?? '').replace(/\/$/, '');
    return origin ? { url: new URL(probePath, `${origin}/`).href, probePath } : null;
  } catch {
    return null;
  }
}

function inertProbeMarker(job) {
  return String(job.nonce_hash ?? job.probe_profile?.marker ?? 'astranull-safe-marker').slice(0, 128);
}

function blockedHttpStatus(status) {
  return [400, 401, 403, 405, 406, 409, 413, 414, 429, 431, 501, 503].includes(status);
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
  if (method === 'POST' && job.probe_profile?.nonce_hash_only !== true) {
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
      statuses.push(classifyFetchError(error));
      continue;
    }
    statuses.push(res.status);
    if (res.status === 429 || res.status === 403 || res.status === 503) throttled = true;
  }

  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: throttled ? 'blocked' : 'connected',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      status_sequence: statuses,
      throttled,
      rate_limit_enforced: throttled,
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
    const blocked = blockedHttpStatus(statusCode);
    const observedAllow = res.headers?.get?.('allow') ?? null;
    if (observedAllow && allowHeader == null) allowHeader = observedAllow;
    if (blocked) methods_blocked.push(method);
    else methods_allowed.push(method);
    method_statuses.push({ method, status_code: statusCode, blocked });
  }

  const advertisedMethods = allowHeader
    ? [...new Set(allowHeader.split(',').map((method) => method.trim().toUpperCase()).filter(Boolean))]
    : [];
  const safeSemanticMethods = new Set(['GET', 'HEAD', 'OPTIONS']);
  const unsafeMethodsAdvertised = advertisedMethods
    .filter((method) => !safeSemanticMethods.has(method));
  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: allowHeader == null
      ? 'error'
      : (unsafeMethodsAdvertised.length > 0 ? 'connected' : 'blocked'),
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
    const status = error ? 0 : res.status;
    if (oversize) oversizeStatus = status;
    else baselineStatus = status;
  }

  const boundaryEnforced = [400, 413, 414, 431].includes(oversizeStatus);
  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: boundaryEnforced ? 'blocked' : 'connected',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      probe_path: endpoint.probePath,
      baseline_status: baselineStatus,
      oversize_status: oversizeStatus,
      oversize_bytes: oversizeBytes,
      boundary_enforced: boundaryEnforced,
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
  const destination = await vetProbeDestinationHost(parsed.hostname, deps);
  if (!destination.ok || destination.addresses.length === 0) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, { error_class: 'destination_not_routable', probe_path: endpoint.probePath }),
      requests_sent: 0,
      duration_ms: observedProbeDurationMs(deps),
    };
  }

  const timeoutMs = remainingProbeTimeoutMs(job, deps);
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
      const finish = (closedByServer, error = null) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        connectionClosedByServer = closedByServer;
        if (error) reject(error);
        else resolve();
      };
      const timer = setTimeout(() => finish(false), timeoutMs);
      const connectedEvent = parsed.protocol === 'https:' ? 'secureConnect' : 'connect';
      socket.once(connectedEvent, () => {
        try {
          socket.write(`HEAD ${endpoint.probePath} HTTP/1.1\r\nHost: ${parsed.host}\r\nX-AstraNull-Marker: `);
        } catch (error) {
          finish(false, error);
        }
      });
      socket.once('end', () => finish(true));
      socket.once('close', () => finish(true));
      socket.once('error', (error) => finish(true, error));
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
        timeout_enforced: false,
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
    external_result: connectionClosedByServer ? 'blocked' : 'connected',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      probe_path: endpoint.probePath,
      header_timeout_ms: durationMs,
      connection_closed_by_server: connectionClosedByServer,
      timeout_enforced: connectionClosedByServer,
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

    if (budget >= 2) {
      pingRttMs = await withinRemainingProbeTime(new Promise((resolve, reject) => {
        startProbeIoAttempt(deps, 'http2_ping', () => session.ping(Buffer.alloc(8), (error, duration) => {
          if (error) reject(error);
          else resolve(Math.max(0, Math.ceil(Number(duration) || 0)));
        }), () => { requestsSent += 1; });
      }), job, deps);
    }

    if (budget >= 3) {
      try {
        const stream = startProbeIoAttempt(
          deps,
          'http2_single_reset',
          () => session.request({ ':method': 'HEAD', ':path': endpoint.probePath }),
          () => { requestsSent += 1; },
        );
        stream.once?.('error', () => {});
        stream.close(http2.constants.NGHTTP2_CANCEL);
        resetAccepted = true;
      } catch {
        resetAccepted = false;
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
        max_header_list_size: settings.maxHeaderListSize ?? null,
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
  const maxHeaderListSize = settings.maxHeaderListSize ?? null;
  const mitigationHint = Number.isSafeInteger(maxConcurrentStreams) && maxConcurrentStreams > 0;
  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: mitigationHint && continuationBoundAdvertised !== false ? 'blocked' : 'connected',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      probe_path: endpoint.probePath,
      max_concurrent_streams: maxConcurrentStreams,
      max_header_list_size: maxHeaderListSize,
      enable_push: settings.enablePush ?? null,
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
  const endpoint = httpProbeEndpoint(job, job.probe_profile?.probe_path);
  if (!endpoint) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  deps = ensureProbeDeadline(job, deps);
  const marker = BENIGN_CLASS_MARKERS.sqli;
  const bodyBytes = 8_192;
  const formFieldCount = 64;
  const jsonDepth = 8;
  const headerBlockBytes = 8_192;
  let nestedJson = marker;
  for (let depth = 0; depth < jsonDepth; depth += 1) nestedJson = { a: nestedJson };
  const formFields = Array.from({ length: formFieldCount - 1 }, (_, index) => `f${index}=a`);
  formFields.push(`marker=${encodeURIComponent(marker)}`);
  const variants = [
    {
      variant: 'marker_past_large_body',
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: `${'a'.repeat(bodyBytes)}${marker}`,
    },
    {
      variant: 'marker_after_high_field_count',
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formFields.join('&'),
    },
    {
      variant: 'marker_in_deep_json',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(nestedJson),
    },
    {
      variant: 'marker_after_large_header_block',
      method: 'HEAD',
      headers: {
        'x-astranull-padding': 'a'.repeat(headerBlockBytes),
        'x-astranull-marker': marker,
      },
    },
  ];
  const budget = resolveBoundedSequenceBudget(job, { ceiling: 6 });
  let requestsSent = 0;
  let baselineStatus = null;
  let baselineBlocked = false;
  const variantResults = [];

  if (budget > 0) {
    const baseline = await boundedFetch(endpoint.url, {
      timeoutMs: remainingProbeTimeoutMs(job, deps),
      fetchOptions: {
        method: 'HEAD',
        redirect: 'manual',
        headers: { 'x-astranull-marker': marker },
      },
    }, deps);
    if (baseline.attempted) requestsSent += 1;
    if (!baseline.attempted || isProbeDeadlineError(baseline.error, deps)) {
      return deadlineOutcome(job, kind, deps, requestsSent, { probe_path: endpoint.probePath, variants: variantResults });
    }
    baselineStatus = baseline.error ? 0 : baseline.res.status;
    baselineBlocked = blockedHttpStatus(baselineStatus);
  }

  for (const variant of variants.slice(0, Math.max(0, budget - requestsSent))) {
    if (remainingProbeTimeoutMs(job, deps) <= 0) {
      return deadlineOutcome(job, kind, deps, requestsSent, {
        probe_path: endpoint.probePath,
        baseline_status: baselineStatus,
        variants: variantResults,
      });
    }
    const { res, error, attempted } = await boundedFetch(endpoint.url, {
      timeoutMs: remainingProbeTimeoutMs(job, deps),
      fetchOptions: {
        method: variant.method,
        redirect: 'manual',
        headers: variant.headers,
        ...(variant.body != null ? { body: variant.body } : {}),
      },
    }, deps);
    if (attempted) requestsSent += 1;
    if (!attempted || isProbeDeadlineError(error, deps)) {
      return deadlineOutcome(job, kind, deps, requestsSent, {
        probe_path: endpoint.probePath,
        baseline_status: baselineStatus,
        variants: variantResults,
      });
    }
    const statusCode = error ? 0 : res.status;
    variantResults.push({
      variant: variant.variant,
      status_code: statusCode,
      blocked: blockedHttpStatus(statusCode),
    });
  }

  const inspectionLimitBypassSuspected = baselineBlocked
    && variantResults.some((variant) => !variant.blocked && variant.status_code >= 200 && variant.status_code < 400);
  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: inspectionLimitBypassSuspected ? 'connected' : 'blocked',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      probe_path: endpoint.probePath,
      baseline_status: baselineStatus,
      baseline_blocked: baselineBlocked,
      inspection_limit_bypass_suspected: inspectionLimitBypassSuspected,
      fail_open_signal: inspectionLimitBypassSuspected,
      variants: variantResults,
      body_bytes: bodyBytes,
      form_field_count: formFieldCount,
      json_depth: jsonDepth,
      header_block_bytes: headerBlockBytes,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

/**
 * Outside-in WAF scanner: fingerprint, benign class markers, optional origin bypass, posture report.
 */
export async function probeOutsideInWafScan(job, deps = {}) {
  const kind = 'outside_in_waf_scan';
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

  const { hostname, directIp } = resolveHostSniTargets(job);
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
  const cnameHopBudget = Math.max(0, Math.min(OUTSIDE_IN_CNAME_HOPS_MAX, totalBudget - OUTSIDE_IN_SCAN_DEFAULT_BUDGET));
  const cnameResult = net.isIP(primaryHost ?? '') === 0 && cnameHopBudget > 0
    ? await resolveCnameChain(primaryHost, primaryDeps, cnameHopBudget)
    : { chain: [], lookups: 0 };
  const budget = totalBudget - cnameResult.lookups;
  const agentObservations = Array.isArray(deps.agentObservations) ? deps.agentObservations : [];
  const nonceHash = job.nonce_hash ?? null;
  const domXssValidation = resolveDomXssValidation({ agents: agentObservations, nonceHash });
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
    timeoutMs: remainingProbeTimeoutMs(job, deps),
    // Signed outside-in jobs authorize only the statically planned, pre-reserved HTTP probes.
    // Legacy profiles may still carry hint/redirect fields, but raw CNAME/A/AAAA/TLS collectors
    // and redirect expansion remain disabled until each operation has its own signed accounting.
    followRedirects: false,
    collectNetworkHints: false,
    wafRequired: job.probe_profile?.waf_required !== false,
    customerVendorHint: job.probe_profile?.expected_vendor_hint ?? job.target?.metadata?.expected_vendor_hint,
    agentCorroborated: job.probe_profile?.agent_corroborated === true
      || job.target?.metadata?.agent_corroborated === true,
    requireAgentForProtected: job.probe_profile?.require_agent_for_protected !== false,
    domXssValidation,
    fetchFn: deadlineFetch,
    originBypassFn: directIp && hostname
      ? async ({ directIp: ip, hostname: host }) => {
        try {
          const res = await deadlineFetch(`http://${ip}/`, {
            method: 'HEAD',
            redirect: 'manual',
            headers: { Host: host },
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

  const external = scan.origin_bypass_confirmed
    ? 'connected'
    : scan.validation_failed
      ? 'connected'
      : scan.waf_detected
        ? 'blocked'
        : 'connected';

  const enrichedScan = enrichOutsideInWafProbeMetadata(
    withKind(job, kind, {
      duration_ms: durationMs,
      scenario_family: 'fingerprint',
      ...scan,
      dns_cname_lookups: cnameResult.lookups,
    }),
    { agents: agentObservations, nonceHash },
  );

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
      method: 'HEAD',
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

  const challenged = res.status === 403 || res.status === 401 || res.status === 429;
  const mitigated = Boolean(res.headers.get('cf-mitigated') ?? res.headers.get('x-waf-block'));
  const enforced = challenged || mitigated;
  const monitor_only = res.status >= 200 && res.status < 300 && !enforced;

  return {
    external_result: enforced ? 'blocked' : 'connected',
    metadata: withKind(job, kind, {
      status_code: res.status,
      waf_enforced: enforced,
      monitor_only_leak: monitor_only,
      duration_ms: durationMs,
    }),
    requests_sent: 1,
    duration_ms: durationMs,
  };
}

/**
 * P1 — DNSSEC posture via DNSKEY/DS presence.
 */
export async function probeDnssecPosture(job, deps = {}) {
  const kind = 'dnssec_posture';
  const zone = apexDomain(job);
  if (!zone) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  deps = ensureProbeDeadline(job, deps);
  const resolveFn = deps.resolveFn ?? dns.resolve;
  let dnskey_count = 0;
  let ds_count = 0;
  let requestsSent = 0;
  const queryBudget = resolveBoundedSequenceBudget(job, { ceiling: 2 });
  const queries = ['DNSKEY', 'DS'].slice(0, queryBudget);

  for (const recordType of queries) {
    if (remainingProbeTimeoutMs(job, deps) <= 0) {
      return deadlineOutcome(job, kind, deps, requestsSent, { dnskey_count, ds_count });
    }
    try {
      const records = await withinRemainingProbeTime(
        startProbeIoAttempt(
          deps,
          `dns_${recordType.toLowerCase()}`,
          () => resolveFn(zone, recordType),
          () => { requestsSent += 1; },
        ),
        job,
        deps,
      );
      if (recordType === 'DNSKEY') dnskey_count = records?.length ?? 0;
      if (recordType === 'DS') ds_count = records?.length ?? 0;
    } catch (error) {
      if (isAuthoritativeDnsNegative(error)) continue;
      return dnsResolverFailureOutcome(job, kind, deps, requestsSent, error, {
        dnskey_count,
        ds_count,
      });
    }
  }

  const durationMs = observedProbeDurationMs(deps);
  const dnssec_configured = dnskey_count > 0 || ds_count > 0;
  return {
    external_result: dnssec_configured ? 'blocked' : 'connected',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      dnskey_count,
      ds_count,
      dnssec_configured,
      dnssec_missing: !dnssec_configured,
      resolver_attempts: requestsSent,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: requestsSent,
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
      external_result: 'blocked',
      metadata: withKind(job, kind, {
        axfr_refused: true,
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
    onAttempt: () => {
      requestsSent += 1;
      transportAttempts += 1;
    },
  });

  const durationMs = observedProbeDurationMs(deps);
  const leaked = outcome.axfr_leak === true;
  return {
    external_result: leaked ? 'connected' : 'blocked',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      zone,
      nameserver: nsHost,
      ...outcome,
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
        port: 443,
        servername: host,
          rejectUnauthorized: false,
        }),
        () => { requestsSent = 1; },
      );
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        socket.destroy();
        reject(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' }));
      }, remainingProbeTimeoutMs(job, deps));
      socket.once('secureConnect', () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        const cert = socket.getPeerCertificate();
        resolve({
          tls_protocol: socket.getProtocol(),
          cipher: socket.getCipher()?.name ?? null,
          authorized: socket.authorized,
          valid_to: cert?.valid_to ?? null,
          issuer: cert?.issuer?.O ?? null,
          subject: cert?.subject?.CN ?? null,
          days_to_expiry: cert?.valid_to ? Math.floor((new Date(cert.valid_to) - Date.now()) / 86400000) : null,
        });
        socket.end();
      });
      socket.once('error', (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(err);
      });
    });

    const durationMs = observedProbeDurationMs(deps);
    const weak_tls = WEAK_TLS_PROTOCOLS.has(session.tls_protocol);
    const cert_expired = session.days_to_expiry != null && session.days_to_expiry < 0;
    const issues = [];
    if (weak_tls) issues.push('weak_tls_protocol');
    if (cert_expired) issues.push('cert_expired');
    if (!session.authorized) issues.push('unauthorized_chain');

    return {
      external_result: issues.length ? 'connected' : 'blocked',
      metadata: withKind(job, kind, { duration_ms: durationMs, ...session, tls_issues: issues }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  } catch (err) {
    const durationMs = observedProbeDurationMs(deps);
    return {
      external_result: classifyFetchError(err),
      metadata: withKind(job, kind, { error_class: err.code ?? err.name, duration_ms: durationMs }),
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
    if (res) {
      observations.push({
        cache_control: res.headers.get('cache-control'),
        age: res.headers.get('age'),
        x_cache: res.headers.get('x-cache') ?? res.headers.get('cf-cache-status'),
        status: res.status,
      });
    }
  }

  const durationMs = observedProbeDurationMs(deps);
  const sensitive_cached = observations.some((o) => o.cache_control?.includes('public') && !o.cache_control?.includes('no-store'));
  const cache_key_weakness = observations.length >= 3
    && observations[0].x_cache != null
    && observations[0].x_cache === observations[1].x_cache
    && observations[0].x_cache === observations[2].x_cache;

  return {
    external_result: sensitive_cached || cache_key_weakness ? 'connected' : 'blocked',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      observations,
      sensitive_cached,
      cache_key_weakness,
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
  const origin = job.target?.value?.startsWith('http')
    ? new URL(job.target.value).origin
    : baseUrlForHost(apexDomain(job) ?? '').replace(/\/$/, '');

  if (!origin) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  deps = ensureProbeDeadline(job, deps);
  const budget = resolveProbeRequestBudget(job);
  const paths = (job.probe_profile?.paths ?? API_DOC_PATHS).slice(0, budget);
  const exposed_paths = [];
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
    if (res && res.status >= 200 && res.status < 400) {
      exposed_paths.push({ path, status: res.status });
    }
  }

  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: exposed_paths.length ? 'connected' : 'blocked',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      exposed_paths,
      exposure_count: exposed_paths.length,
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
  const weak_cors = acao === '*' || acao === 'https://probe.invalid.astranull';
  return {
    external_result: weak_cors ? 'connected' : 'blocked',
    metadata: withKind(job, kind, {
      status_code: res.status,
      access_control_allow_origin: acao,
      weak_cors,
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

  const challenged = res.status === 403 || res.status === 401 || res.status === 429 || res.status === 302;
  const challenge_header = res.headers.get('cf-mitigated') ?? res.headers.get('x-bot-challenge') ?? null;
  const no_challenge = res.status >= 200 && res.status < 300 && !challenge_header;

  return {
    external_result: challenged ? 'blocked' : 'connected',
    metadata: withKind(job, kind, {
      status_code: res.status,
      challenge_header,
      bot_challenge_missing: no_challenge,
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
  const path = normalizeProbeHttpPath(job.probe_profile?.graphql_path) ?? '/graphql';
  const origin = job.target?.value?.startsWith('http')
    ? new URL(job.target.value).origin
    : baseUrlForHost(apexDomain(job) ?? '').replace(/\/$/, '');

  if (!origin) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  const started = Date.now();
  const { res, error } = await boundedFetch(`${origin}${path}`, {
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
    res.headers.get('x-graphql-complexity-limit') ?? res.headers.get('x-rate-limit-limit'),
  );

  return {
    external_result: exposed && !complexity_limits_advertised ? 'connected' : 'blocked',
    metadata: withKind(job, kind, {
      status_code: res.status,
      graphql_exposed: exposed,
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
  const resolverVerdict = await vetProbeDestinationHost(resolverHost, deps, {
    requireIpLiteral: true,
  });
  if (remainingProbeTimeoutMs(job, deps) <= 0) {
    return deadlineOutcome(job, kind, deps, 0, { resolver_host: resolverHost });
  }
  if (!resolverVerdict.ok) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, {
        error_class: 'resolver_not_routable',
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

  let open_recursion = false;
  let requestsSent = 0;
  try {
    await withinRemainingProbeTime(
      startProbeIoAttempt(
        deps,
        'dns_external_lookup',
        () => resolveExternal(resolverHost, queryName),
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
        recursion_test_name: queryName,
      });
    }
  }

  const durationMs = observedProbeDurationMs(deps);
  return {
    external_result: open_recursion ? 'connected' : 'blocked',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      resolver_host: resolverHost,
      recursion_test_name: queryName,
      open_recursion_detected: open_recursion,
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
    secondary_results.push({ nameserver: ns, reachable: addrs.length > 0, addresses: addrs.slice(0, 2) });
  }

  const weak_failover = nameservers.length < 2
    || (declaredSecondary.length > 0 && secondary_results.some((r) => !r.reachable));
  const durationMs = observedProbeDurationMs(deps);

  return {
    external_result: weak_failover ? 'connected' : 'blocked',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      zone,
      nameserver_count: nameservers.length,
      nameservers: nameservers.slice(0, 4),
      secondary_results,
      weak_failover,
      resolver_attempts: requestsSent,
      request_counting_basis: 'logical_operations',
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

const DELEGATED_SAFE_HTTP_METHODS = new Set(['GET', 'POST']);
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
      || (method === 'GET' && init.body != null)
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
    try {
      await outcome.res?.body?.cancel?.();
    } catch {
      // Headers/status are the complete delegated evidence; body disposal is best effort.
    }
    return outcome.res;
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
  });
  const failure = delegatedFailureOutcome(job, kind, deps, state, {
    marker_class: raw?.marker_class ?? job.probe_profile?.marker_class ?? null,
  });
  if (failure) return failure;

  const rawMetadata = { ...(raw ?? {}) };
  delete rawMetadata.requests_sent;
  const hasMarkerEvidence = Array.isArray(raw?.marker_results) && raw.marker_results.length > 0;
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

  const externalResult = raw?.external_result === 'external_blocked'
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
        ? { not_run_reason: 'insufficient_evasion_comparison' }
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

export const CAPABILITY_PROBE_DISPATCH = Object.freeze({
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
  const path = normalizeProbeHttpPath(configuredPath) ?? DEFAULT_GRPC_REFLECTION_PATH;
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
        : classifyFetchError(error),
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
  const requestSucceeded = grpcEndpointReachable && grpcStatus === '0';
  const isReflection = requestSpec.service === 'reflection';
  const reflectionServiceRouted = isReflection && grpcEndpointReachable
    ? grpcStatus !== '12'
    : null;

  return {
    external_result: requestSucceeded ? 'connected' : 'blocked',
    metadata: withKind(job, kind, {
      status_code: res.status,
      grpc_status: grpcStatus,
      grpc_status_source: grpcStatusSource,
      grpc_message_present: Boolean(grpcMessage),
      content_type_is_grpc: contentTypeIsGrpc,
      grpc_endpoint_reachable: grpcEndpointReachable,
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
