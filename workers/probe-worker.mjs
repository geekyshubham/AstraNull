#!/usr/bin/env node
/**
 * AstraNull signed probe worker — metadata-only, bounded probes for assigned jobs.
 * Not customer traffic tooling; no amplification, flooding, or arbitrary target scanning.
 */

import dns from 'node:dns/promises';
import { hostname } from 'node:os';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { executeCapabilityProbe } from '../src/lib/capabilityProbes.mjs';
import {
  probeAlertWebhookPing,
  probeHttp2Settings,
  probeQuicReachability,
  probeTlsSession,
  probeUdpDatagram,
  probeWebsocketUpgradePosture,
} from '../src/lib/safeNetworkProbes.mjs';
import { resolveDeploymentProfile } from '../src/lib/deploymentProfile.mjs';
import { assertProbeDestinationAllowed } from '../src/lib/probeEndpoint.mjs';
import { enrichProbeMetadataWithWafCatalog } from '../src/lib/wafProductCatalog.mjs';
import {
  probeWorkerAuthHeaders,
  verifyProbeJobSignature,
} from '../src/services/probeCoordinator.mjs';

export const WORKER_VERSION = '0.1.0';
const POLL_INTERVAL_MIN_MS = 1000;
const POLL_INTERVAL_MAX_MS = 60_000;
const DEFAULT_POLL_INTERVAL_MS = 5000;
const DEFAULT_API_URL = 'http://localhost:3000';
const MIN_SECRET_LENGTH = 32;

const DNS_VECTOR_FAMILIES = new Set(['dns']);
const TCP_VECTOR_FAMILIES = new Set(['l3_l4']);
const HTTP_VECTOR_FAMILIES = new Set(['origin', 'l7', 'path', 'tls', 'protocol']);

export function redactSecrets(text, secret) {
  if (!text || !secret) return text;
  return String(text).split(secret).join('[redacted]');
}

function parseFlag(argv, name) {
  const idx = argv.indexOf(name);
  if (idx === -1) return undefined;
  return argv[idx + 1];
}

function parseBoolEnv(value) {
  if (value == null || value === '') return false;
  return value === '1' || value.toLowerCase() === 'true' || value.toLowerCase() === 'yes';
}

/**
 * Production-like deployments never get the private-destination escape hatch.
 * NODE_ENV=production alone is enough — a hosted-staging profile does not soften this,
 * and an unparseable profile fails closed.
 *
 * @param {NodeJS.ProcessEnv} [env]
 */
export function isProductionLikeDeployment(env = process.env) {
  if (String(env.NODE_ENV ?? '').trim() === 'production') return true;
  try {
    return resolveDeploymentProfile(env) === 'production';
  } catch {
    return true;
  }
}

/**
 * Opt-in relaxation for legitimate on-prem RFC1918 probing. Refused outright when the
 * deployment is production-like; cloud metadata and link-local stay blocked regardless.
 *
 * @param {NodeJS.ProcessEnv} [env]
 */
export function resolveProbeDestinationPolicy(env = process.env) {
  const productionLike = isProductionLikeDeployment(env);
  const requested = parseBoolEnv(env.ASTRANULL_PROBE_ALLOW_PRIVATE_DESTINATIONS);

  // Loopback is where the local harness lives (dev servers, local-staging smoke targets),
  // and an operator probing their own box gains nothing an attacker could not already do.
  // In a production-like deployment it is a genuine SSRF sink (the prober's own admin
  // surface), so it is refused there. Cloud metadata and link-local are never allowed by
  // either branch — assertProbeDestinationAllowed refuses those unconditionally.
  const allowLoopback = !productionLike;

  return {
    allowPrivate: requested && !productionLike,
    allowLoopback,
    optInRefused: requested && productionLike,
  };
}

export function parseWorkerConfig(argv = process.argv.slice(2), env = process.env) {
  const apiUrl = parseFlag(argv, '--api') ?? env.ASTRANULL_API_URL ?? DEFAULT_API_URL;
  const workerId =
    parseFlag(argv, '--worker-id') ?? env.ASTRANULL_PROBE_WORKER_ID ?? hostname();
  const secret = parseFlag(argv, '--secret') ?? env.ASTRANULL_PROBE_WORKER_SECRET;
  const once = argv.includes('--once') || parseBoolEnv(env.ASTRANULL_PROBE_ONCE);
  const pollRaw =
    parseFlag(argv, '--poll-interval-ms') ?? env.ASTRANULL_PROBE_POLL_INTERVAL_MS;
  let pollIntervalMs = pollRaw != null ? Number(pollRaw) : DEFAULT_POLL_INTERVAL_MS;
  if (!Number.isFinite(pollIntervalMs)) pollIntervalMs = DEFAULT_POLL_INTERVAL_MS;
  pollIntervalMs = Math.min(POLL_INTERVAL_MAX_MS, Math.max(POLL_INTERVAL_MIN_MS, pollIntervalMs));
  const tenantId =
    parseFlag(argv, '--tenant-id') ?? env.ASTRANULL_PROBE_TENANT_ID ?? undefined;
  const tenantIdStr =
    tenantId != null && String(tenantId).trim() !== '' ? String(tenantId).trim() : undefined;

  if (!secret || String(secret).length < MIN_SECRET_LENGTH) {
    throw new Error(
      'Probe worker secret is required (≥32 chars). Set --secret or ASTRANULL_PROBE_WORKER_SECRET.',
    );
  }

  if (!tenantIdStr) {
    throw new Error(
      'Probe worker tenant id is required. Set --tenant-id or ASTRANULL_PROBE_TENANT_ID.',
    );
  }

  return {
    apiUrl: apiUrl.replace(/\/$/, ''),
    workerId: String(workerId),
    secret: String(secret),
    once,
    pollIntervalMs,
    tenantId: tenantIdStr,
  };
}

/** HMAC path must match control-plane route paths (root-mounted, no API URL pathname prefix). */
export function workerSigningPath(_apiUrl, routePath) {
  return routePath;
}

async function signedFetch(config, method, path, body) {
  const bodyText = body == null ? '' : JSON.stringify(body);
  const fullPath = workerSigningPath(config.apiUrl, path);
  const headers = {
    ...probeWorkerAuthHeaders(
      config.workerId,
      { method, path: fullPath, bodyText, tenantId: config.tenantId },
      config.secret,
    ),
    accept: 'application/json',
  };
  if (body != null) headers['content-type'] = 'application/json';

  const url = `${config.apiUrl}${path}`;
  const res = await fetch(url, { method, headers, body: body == null ? undefined : bodyText });
  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: res.status, json, text };
}

function clampAttestation(job, requestsSent, durationMs) {
  const maxRequests = job.constraints?.max_requests ?? 1;
  const timeoutMs = job.constraints?.timeout_ms ?? 5000;
  return {
    requests_sent: Math.min(Math.max(0, requestsSent), maxRequests),
    duration_ms: Math.min(Math.max(0, durationMs), timeoutMs),
  };
}

const METADATA_DENY_KEYS = new Set([
  'headers',
  'header',
  'body',
  'payload',
  'raw_packet',
  'packet_payload',
  'raw_packets',
  'log_line',
]);

export function sanitizeProbeMetadata(metadata) {
  if (metadata == null || typeof metadata !== 'object' || Array.isArray(metadata)) {
    return {};
  }
  function walk(value) {
    if (value == null || typeof value !== 'object' || Array.isArray(value)) {
      return value;
    }
    const out = {};
    for (const [key, child] of Object.entries(value)) {
      if (METADATA_DENY_KEYS.has(key)) continue;
      if (child != null && typeof child === 'object') {
        if (Array.isArray(child)) continue;
        const nested = walk(child);
        if (nested != null && typeof nested === 'object' && Object.keys(nested).length > 0) {
          out[key] = nested;
        }
      } else {
        out[key] = child;
      }
    }
    return out;
  }
  return walk(metadata);
}

function profileKindForJob(job, metadata = {}) {
  return job.probe_profile?.kind ?? metadata.profile_kind ?? metadata.probe_kind ?? null;
}

function withProfileKind(job, metadata) {
  return { profile_kind: profileKindForJob(job), ...metadata };
}

function buildResultBody(job, externalResult, metadata, attestationBase) {
  const att = clampAttestation(job, attestationBase.requests_sent, attestationBase.duration_ms);
  const safeMetadata = sanitizeProbeMetadata(metadata);
  const profileKind = profileKindForJob(job, safeMetadata);
  const enrichedMetadata = enrichProbeMetadataWithWafCatalog(
    {
      probe_kind: safeMetadata.probe_kind ?? 'unknown',
      profile_kind: profileKind,
      target_kind: job.target?.kind ?? null,
      vector_family: job.vector_family ?? null,
      ...safeMetadata,
    },
    job.check_id,
  );

  return {
    external_result: externalResult,
    metadata: enrichedMetadata,
    safety_attestation: {
      ...att,
      worker_version: WORKER_VERSION,
      completed_at: new Date().toISOString(),
    },
  };
}

function isUrlValue(value) {
  return /^https?:\/\//i.test(String(value ?? ''));
}

function resolveHttpUrl(job) {
  const { target, vector_family: vectorFamily } = job;
  const value = target?.value;
  if (!value) return null;
  if (target.kind === 'url' || isUrlValue(value)) return String(value);
  if (HTTP_VECTOR_FAMILIES.has(vectorFamily) || target.kind === 'fqdn') {
    return `https://${String(value).replace(/^\/+/, '')}/`;
  }
  return null;
}

function parseTcpEndpoint(job) {
  const target = job.target ?? {};
  const value = String(target.value ?? '');
  const portFromTarget = target.port != null ? Number(target.port) : null;

  if (value.includes(':')) {
    const lastColon = value.lastIndexOf(':');
    const host = value.slice(0, lastColon);
    const port = Number(value.slice(lastColon + 1));
    if (host && Number.isInteger(port) && port > 0 && port <= 65535) {
      return { host, port };
    }
  }
  if (portFromTarget && Number.isInteger(portFromTarget) && value) {
    return { host: value, port: portFromTarget };
  }
  return null;
}

function dnsQueryName(job) {
  const value = String(job.target?.value ?? '').trim();
  if (!value) return null;
  const checkId = String(job.check_id ?? '');
  const nonce = String(job.nonce ?? '').trim();
  if (checkId.includes('random_prefix') && nonce) {
    const label = nonce.replace(/[^a-zA-Z0-9-]/g, '').slice(0, 32) || 'probe';
    const base = value.replace(/^\./, '');
    return `${label}.${base}`;
  }
  return value;
}

/**
 * Extract the single host this job will egress to, mirroring how the probe helpers
 * derive their destination (bare host, host:port, [v6]:port, or URL).
 *
 * @param {Record<string, unknown>} job
 * @returns {string | null}
 */
export function probeDestinationHost(job) {
  const value = String(job?.target?.value ?? '').trim();
  if (!value) return null;
  if (/^https?:\/\//i.test(value)) {
    try {
      const { hostname } = new URL(value);
      return hostname.replace(/^\[/, '').replace(/\]$/, '') || null;
    } catch {
      return null;
    }
  }
  const withoutPath = value.split('/')[0];
  const bracketed = withoutPath.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (bracketed) return bracketed[1];
  if (net.isIP(withoutPath) !== 0) return withoutPath;
  const hostPort = withoutPath.match(/^([^:]+):(\d+)$/);
  return (hostPort ? hostPort[1] : withoutPath) || null;
}

async function resolveOrEmpty(fn, host) {
  try {
    const out = await fn(host);
    return Array.isArray(out) ? out.filter((ip) => typeof ip === 'string') : [];
  } catch {
    return [];
  }
}

/**
 * Single destination-classification chokepoint for probe egress.
 *
 * Resolves the target host's A/AAAA set exactly once and refuses the job when ANY
 * resolved address is non-routable. Resolving once (rather than letting each probe
 * re-resolve) also closes the DNS-rebinding/TOCTOU window between check and connect.
 *
 * Hosts that resolve to nothing are allowed through: there is no address to probe, so
 * the underlying probe reports its own ENOTFOUND/blocked outcome.
 *
 * @param {Record<string, unknown>} job
 * @param {{ resolve4Fn?: Function, resolve6Fn?: Function, destinationPolicy?: object, env?: NodeJS.ProcessEnv }} deps
 */
export async function vetProbeDestination(job, deps = {}) {
  const policy = deps.destinationPolicy ?? resolveProbeDestinationPolicy(deps.env ?? process.env);
  const host = probeDestinationHost(job);
  if (!host) {
    return { ok: true, host: null, addresses: [], policy };
  }

  if (net.isIP(host) !== 0) {
    const verdict = assertProbeDestinationAllowed(host, policy);
    return verdict.ok
      ? { ok: true, host, addresses: [host], policy }
      : { ok: false, host, addresses: [host], blocked_address: host, reason: verdict.message, policy };
  }

  const resolve4Fn = deps.resolve4Fn ?? dns.resolve4;
  const resolve6Fn = deps.resolve6Fn ?? dns.resolve6;
  const [v4, v6] = await Promise.all([
    resolveOrEmpty(resolve4Fn, host),
    resolveOrEmpty(resolve6Fn, host),
  ]);
  const addresses = [...new Set([...v4, ...v6])];
  if (addresses.length === 0) {
    return { ok: true, host, addresses: [], unresolved: true, policy };
  }

  for (const ip of addresses) {
    const verdict = assertProbeDestinationAllowed(ip, policy);
    if (!verdict.ok) {
      return { ok: false, host, addresses, blocked_address: ip, reason: verdict.message, policy };
    }
  }
  return { ok: true, host, addresses, policy };
}

function destinationBlockedOutcome(job, vetted) {
  return {
    external_result: 'blocked',
    metadata: withProfileKind(job, {
      probe_kind: 'destination_gate',
      error_class: 'destination_not_routable',
      destination_host: vetted.host,
      blocked_address: vetted.blocked_address ?? null,
      reason: vetted.reason ?? 'not_routable',
      ...(vetted.policy?.optInRefused
        ? { private_destination_opt_in_refused: true }
        : {}),
    }),
    requests_sent: 0,
    duration_ms: 0,
  };
}

const MAX_SAFE_HTTP_REDIRECTS = 3;

/**
 * Follow redirects manually without leaking nonce/marker headers to third-party hosts.
 *
 * @param {string} startUrl
 * @param {Record<string, string>} sensitiveHeaders
 * @param {{ signal?: AbortSignal, maxRequests?: number }} options
 * @param {{ fetchFn?: typeof fetch }} deps
 */
export async function fetchHttpHeadWithSafeRedirects(startUrl, sensitiveHeaders, options = {}, deps = {}) {
  const fetchFn = deps.fetchFn ?? fetch;
  const originalHost = new URL(startUrl).host;
  const maxRequests = Number.isFinite(Number(options.maxRequests)) && Number(options.maxRequests) > 0
    ? Math.floor(Number(options.maxRequests))
    : Number.POSITIVE_INFINITY;
  let currentUrl = startUrl;
  let redirectCount = 0;
  let requestsSent = 0;
  let res;

  while (redirectCount <= MAX_SAFE_HTTP_REDIRECTS) {
    if (requestsSent >= maxRequests) {
      return {
        res,
        redirectBlocked: true,
        redirectReason: 'request_cap_exhausted',
        requestsSent,
      };
    }
    const headers = redirectCount === 0 ? sensitiveHeaders : {};
    requestsSent += 1;
    res = await fetchFn(currentUrl, {
      method: 'HEAD',
      headers,
      signal: options.signal,
      redirect: 'manual',
    });

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location');
      if (!location) {
        return {
          res,
          redirectBlocked: true,
          redirectReason: 'missing_location',
          requestsSent,
        };
      }
      const nextUrl = new URL(location, currentUrl);
      if (nextUrl.host !== originalHost) {
        return {
          res,
          redirectBlocked: true,
          redirectReason: 'host_mismatch',
          finalHost: nextUrl.host,
          requestsSent,
        };
      }
      if (requestsSent >= maxRequests) {
        return {
          res,
          redirectBlocked: true,
          redirectReason: 'request_cap_exhausted',
          requestsSent,
        };
      }
      currentUrl = nextUrl.href;
      redirectCount += 1;
      continue;
    }

    return {
      res,
      redirectBlocked: false,
      redirectCount,
      finalUrl: currentUrl,
      requestsSent,
    };
  }

  return {
    res,
    redirectBlocked: true,
    redirectReason: 'redirect_limit_exceeded',
    requestsSent,
  };
}

export async function probeHttpHead(job, deps = {}) {
  const fetchFn = deps.fetchFn ?? fetch;
  const url = resolveHttpUrl(job);
  if (!url) {
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'http_head',
        error_class: 'unsupported_target',
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  const timeoutMs = job.constraints?.timeout_ms ?? 5000;
  const maxRequests = Math.min(1, job.constraints?.max_requests ?? 1);
  if (maxRequests < 1) {
    return {
      external_result: 'error',
      metadata: withProfileKind(job, { probe_kind: 'http_head', error_class: 'zero_request_cap' }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let requestsSent = 0;
  try {
    const sensitiveHeaders = {};
    if (job.nonce) sensitiveHeaders['x-astranull-nonce'] = job.nonce;
    const marker = job.probe_profile?.marker;
    if (marker) sensitiveHeaders['x-astranull-marker'] = String(marker);

    const outcome = await fetchHttpHeadWithSafeRedirects(
      url,
      sensitiveHeaders,
      { signal: controller.signal, maxRequests },
      { fetchFn },
    );
    requestsSent = outcome.requestsSent ?? 1;
    const durationMs = Date.now() - started;

    if (requestsSent > maxRequests) {
      return {
        external_result: 'error',
        metadata: withProfileKind(job, {
          probe_kind: 'http_head',
          error_class: 'request_cap_exceeded',
          requests_sent: requestsSent,
          max_requests: maxRequests,
          duration_ms: durationMs,
        }),
        requests_sent: requestsSent,
        duration_ms: durationMs,
      };
    }

    if (outcome.redirectBlocked) {
      return {
        external_result: 'error',
        metadata: withProfileKind(job, {
          probe_kind: 'http_head',
          error_class: 'unsafe_redirect',
          redirect_reason: outcome.redirectReason ?? 'redirect_blocked',
          redirect_host: outcome.finalHost ?? null,
          duration_ms: durationMs,
        }),
        requests_sent: requestsSent,
        duration_ms: durationMs,
      };
    }

    const res = outcome.res;
    let finalHost = null;
    let finalScheme = null;
    try {
      const finalUrl = new URL(outcome.finalUrl || res.url || url);
      finalHost = finalUrl.host;
      finalScheme = finalUrl.protocol.replace(/:$/, '');
    } catch {
      /* metadata only — ignore parse errors */
    }
    return {
      external_result: 'connected',
      metadata: withProfileKind(job, {
        probe_kind: 'http_head',
        status_code: res.status,
        duration_ms: durationMs,
        final_scheme: finalScheme,
        final_host: finalHost,
        redirect_count: outcome.redirectCount ?? 0,
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  } catch (err) {
    const durationMs = Date.now() - started;
    if (requestsSent === 0) requestsSent = 1;
    const name = err?.name ?? '';
    const code = err?.code ?? '';
    if (name === 'AbortError') {
      return {
        external_result: 'timeout',
        metadata: withProfileKind(job, {
          probe_kind: 'http_head',
          error_class: 'timeout',
          duration_ms: durationMs,
        }),
        requests_sent: 1,
        duration_ms: durationMs,
      };
    }
    if (code === 'ECONNREFUSED' || code === 'ENOTFOUND' || code === 'EHOSTUNREACH') {
      return {
        external_result: 'blocked',
        metadata: withProfileKind(job, {
          probe_kind: 'http_head',
          error_class: code,
          duration_ms: durationMs,
        }),
        requests_sent: 1,
        duration_ms: durationMs,
      };
    }
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'http_head',
        error_class: 'probe_failed',
        duration_ms: durationMs,
      }),
      requests_sent: 1,
      duration_ms: durationMs,
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function probeDns(job, deps = {}) {
  const lookupFn = deps.lookupFn ?? dns.lookup;
  const name = dnsQueryName(job);
  if (!name) {
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'dns_resolve',
        error_class: 'unsupported_target',
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  const timeoutMs = job.constraints?.timeout_ms ?? 5000;
  const started = Date.now();
  let timeoutTimer;
  try {
    await Promise.race([
      lookupFn(name),
      new Promise((_, reject) => {
        timeoutTimer = setTimeout(
          () => reject(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' })),
          timeoutMs,
        );
      }),
    ]);
    const durationMs = Date.now() - started;
    return {
      external_result: 'connected',
      metadata: withProfileKind(job, {
        probe_kind: 'dns_resolve',
        duration_ms: durationMs,
        query_name: name,
      }),
      requests_sent: 1,
      duration_ms: durationMs,
    };
  } catch (err) {
    const durationMs = Date.now() - started;
    const code = err?.code ?? '';
    if (code === 'ETIMEOUT') {
      return {
        external_result: 'timeout',
        metadata: withProfileKind(job, {
          probe_kind: 'dns_resolve',
          error_class: 'timeout',
          duration_ms: durationMs,
        }),
        requests_sent: 1,
        duration_ms: durationMs,
      };
    }
    if (code === 'ENOTFOUND' || code === 'ENODATA') {
      return {
        external_result: 'blocked',
        metadata: withProfileKind(job, {
          probe_kind: 'dns_resolve',
          error_class: code,
          duration_ms: durationMs,
        }),
        requests_sent: 1,
        duration_ms: durationMs,
      };
    }
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'dns_resolve',
        error_class: 'probe_failed',
        duration_ms: durationMs,
      }),
      requests_sent: 1,
      duration_ms: durationMs,
    };
  } finally {
    if (timeoutTimer != null) clearTimeout(timeoutTimer);
  }
}

export function probeTcpConnect(job, deps = {}) {
  const connectFn = deps.connectFn ?? net.connect;
  const endpoint = parseTcpEndpoint(job);
  if (!endpoint) {
    return Promise.resolve({
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'tcp_connect',
        error_class: 'unsupported_target',
      }),
      requests_sent: 0,
      duration_ms: 0,
    });
  }

  const timeoutMs = job.constraints?.timeout_ms ?? 5000;
  const started = Date.now();

  return new Promise((resolve) => {
    let settled = false;
    let requestsSent = 0;
    const socket = connectFn(
      { host: endpoint.host, port: endpoint.port },
      () => {
        if (settled) return;
        settled = true;
        requestsSent = 1;
        const durationMs = Date.now() - started;
        socket.destroy();
        resolve({
          external_result: 'connected',
          metadata: withProfileKind(job, {
            probe_kind: 'tcp_connect',
            duration_ms: durationMs,
            target_port: endpoint.port,
          }),
          requests_sent: requestsSent,
          duration_ms: durationMs,
        });
      },
    );

    socket.setTimeout(timeoutMs);
    socket.on('timeout', () => {
      if (settled) return;
      settled = true;
      requestsSent = 1;
      const durationMs = Date.now() - started;
      socket.destroy();
      resolve({
        external_result: 'timeout',
        metadata: withProfileKind(job, {
          probe_kind: 'tcp_connect',
          error_class: 'timeout',
          duration_ms: durationMs,
        }),
        requests_sent: requestsSent,
        duration_ms: durationMs,
      });
    });
    socket.on('error', (err) => {
      if (settled) return;
      settled = true;
      requestsSent = 1;
      const durationMs = Date.now() - started;
      const code = err?.code ?? '';
      const external =
        code === 'ECONNREFUSED' || code === 'EHOSTUNREACH' || code === 'ENETUNREACH'
          ? 'blocked'
          : 'error';
      resolve({
        external_result: external,
        metadata: withProfileKind(job, {
          probe_kind: 'tcp_connect',
          error_class: code || 'connect_failed',
          duration_ms: durationMs,
        }),
        requests_sent: requestsSent,
        duration_ms: durationMs,
      });
    });
  });
}

export function probeMetadataMarker(job) {
  const marker = job.probe_profile?.marker ?? 'astranull-safe-marker';
  return {
    external_result: 'blocked',
    metadata: withProfileKind(job, {
      probe_kind: 'metadata_marker',
      marker,
      simulation: 'SAFE_PROBE_SIMULATION',
    }),
    requests_sent: 0,
    duration_ms: 0,
  };
}

export async function executeProbeForJob(job, deps = {}) {
  const profileKind = job.probe_profile?.kind;

  // Destination chokepoint. metadata_marker sends no packets, so it is exempt; every
  // other kind egresses and must clear the classifier before any probe helper — and
  // therefore before any connectFn/fetchFn — is touched.
  let destinationPolicy = deps.destinationPolicy;
  let vettedAddresses = [];
  if (profileKind !== 'metadata_marker') {
    const vetted = await vetProbeDestination(job, deps);
    if (!vetted.ok) {
      return destinationBlockedOutcome(job, vetted);
    }
    destinationPolicy = vetted.policy;
    vettedAddresses = vetted.addresses ?? [];
  }
  // Reuse the vetted policy for destinations discovered mid-probe (NS hosts, resolvers),
  // and hand down the already-vetted IP literals so probes need not re-resolve.
  const probeDeps = { ...deps, destinationPolicy };
  if (vettedAddresses.length > 0 && deps.vettedAddresses == null) {
    probeDeps.vettedAddresses = vettedAddresses;
  }

  const capabilityOutcome = await executeCapabilityProbe(job, probeDeps);
  if (capabilityOutcome) {
    return capabilityOutcome;
  }
  if (profileKind === 'metadata_marker') {
    return probeMetadataMarker(job);
  }
  if (profileKind === 'udp_probe') {
    return probeUdpDatagram(job);
  }
  if (profileKind === 'quic_reachability') {
    return probeQuicReachability(job);
  }
  if (profileKind === 'alert_webhook_ping') {
    return probeAlertWebhookPing(job, { destinationPolicy });
  }
  if (profileKind === 'ownership_challenge') {
    const res = await probeHttpHead(job);
    res.metadata = { ...res.metadata, probe_kind: 'ownership_challenge' };
    return res;
  }
  if (profileKind === 'tls_session') return probeTlsSession(job);
  if (profileKind === 'http2_settings') return probeHttp2Settings(job);
  if (profileKind === 'websocket_upgrade_posture') return probeWebsocketUpgradePosture(job);
  const vectorFamily = job.vector_family;
  if (DNS_VECTOR_FAMILIES.has(vectorFamily)) return probeDns(job);
  if (TCP_VECTOR_FAMILIES.has(vectorFamily)) return probeTcpConnect(job);
  if (HTTP_VECTOR_FAMILIES.has(vectorFamily) || resolveHttpUrl(job)) return probeHttpHead(job);
  return {
    external_result: 'error',
    metadata: withProfileKind(job, { probe_kind: 'none', error_class: 'unsupported_check' }),
    requests_sent: 0,
    duration_ms: 0,
  };
}

export async function processJob(config, job) {
  if (!verifyProbeJobSignature(job, config.secret)) {
    return buildResultBody(
      job,
      'error',
      { probe_kind: 'signature', error_class: 'invalid_job_signature' },
      { requests_sent: 0, duration_ms: 0 },
    );
  }

  const outcome = await executeProbeForJob(job, {
    probeWorkerSecret: config.secret,
    signedJobVerified: true,
  });
  return buildResultBody(job, outcome.external_result, outcome.metadata, {
    requests_sent: outcome.requests_sent,
    duration_ms: outcome.duration_ms,
  });
}

export async function pollAndProcessOnce(config) {
  const listed = await signedFetch(config, 'GET', '/internal/probe/jobs');
  if (listed.status !== 200) {
    throw new Error(
      `Probe job poll failed (${listed.status}): ${redactSecrets(listed.text?.slice(0, 200), config.secret)}`,
    );
  }
  const jobs = listed.json?.jobs ?? [];
  const results = [];
  for (const job of jobs) {
    const body = await processJob(config, job);
    const resultPath = `/internal/probe/jobs/${job.id}/result`;
    const posted = await signedFetch(config, 'POST', resultPath, body);
    if (posted.status !== 201) {
      throw new Error(
        `Probe result post failed (${posted.status}) for ${job.id}: ${redactSecrets(
          posted.text?.slice(0, 200),
          config.secret,
        )}`,
      );
    }
    results.push({ job_id: job.id, external_result: body.external_result });
  }
  return results;
}

export async function runProbeWorker(config) {
  do {
    await pollAndProcessOnce(config);
    if (config.once) break;
    await new Promise((r) => setTimeout(r, config.pollIntervalMs));
  } while (!config.once);
}

const workerEntry = fileURLToPath(import.meta.url);
const invokedAsMain =
  process.argv[1] != null && path.resolve(process.argv[1]) === workerEntry;

if (invokedAsMain) {
  try {
    const config = parseWorkerConfig();
    await runProbeWorker(config);
  } catch (err) {
    const secret = process.env.ASTRANULL_PROBE_WORKER_SECRET;
    console.error(redactSecrets(err?.message ?? String(err), secret));
    process.exit(1);
  }
}
