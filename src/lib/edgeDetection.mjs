/**
 * Hostname → edge detection: one governed passive path for "is this host behind a
 * WAF/CDN?".
 *
 * Composition:
 *   - bounded DNS metadata (CNAME chain, A/AAAA) via injectable resolvers,
 *   - exactly ONE bounded passive GET (no redirects followed, bounded body read),
 *   - `classifyEdgeFingerprint` for the wafw00f/cdncheck corpus classification.
 *
 * Safety contract (mirrors the outside-in scanner, stricter budget):
 *   - passive tier only: block-page signatures are never evaluated here because this
 *     path never sends anything a WAF would reject — no markers, no evasion variants.
 *   - no attack traffic, no payload generation, no automatic discovery: the caller
 *     supplies a customer-declared hostname.
 *   - metadata-only result: header values and body text stay in memory and are never
 *     returned.
 */

import { resolve4 as defaultResolve4, resolve6 as defaultResolve6, resolveCname as defaultResolveCname } from 'node:dns/promises';
import { isIP } from 'node:net';
import {
  EDGE_SIGNATURE_CORPUS_VERSION,
  classifyEdgeFingerprint,
  extractFingerprintHeaderEntries,
} from './edgeFingerprint.mjs';

const MAX_BODY_READ_BYTES = 8192;
const MAX_CNAME_HOPS = 4;
const DEFAULT_TIMEOUT_MS = 4000;
const MAX_TIMEOUT_MS = 10_000;

const HOSTNAME_PATTERN = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.?$/;
const LOOPBACK_HOSTNAMES = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

/**
 * Normalize and validate a customer-supplied hostname.
 * Accepts a bare hostname or IP literal; rejects URLs, credentials, paths, ports.
 * @param {unknown} input
 * @returns {{ hostname: string } | { error: string }}
 */
export function normalizeDetectionHostname(input) {
  let value = String(input ?? '').trim().toLowerCase();
  if (!value) return { error: 'invalid_hostname' };
  value = value.replace(/\.$/, '');
  if (value.length > 253) return { error: 'invalid_hostname' };
  if (/[/?#@\\\s]/.test(value)) return { error: 'invalid_hostname' };
  // Reject a scheme or port outright — callers pass hostnames, not URLs.
  if (value.includes('://') || /:\d+$/.test(value)) return { error: 'invalid_hostname' };

  const bracketedV6 = value.startsWith('[') && value.endsWith(']');
  if (bracketedV6) {
    const inner = value.slice(1, -1);
    if (isIP(inner) !== 6) return { error: 'invalid_hostname' };
    return { hostname: inner };
  }
  if (isIP(value)) return { hostname: value };
  if (!HOSTNAME_PATTERN.test(value)) return { error: 'invalid_hostname' };
  return { hostname: value };
}

function isLoopback(hostname) {
  return LOOPBACK_HOSTNAMES.has(hostname) || hostname === '[::1]' || hostname.startsWith('127.');
}

function cookieNamesFromHeaders(res) {
  const raw = res?.headers?.get?.('set-cookie');
  if (!raw) return [];
  return [...new Set(
    String(raw)
      .split(/,(?=[^;]+?=)/)
      .map((part) => part.split('=')[0]?.trim().toLowerCase())
      .filter(Boolean),
  )].sort();
}

/**
 * Bounded CNAME chain resolution. Returns hostnames (no IPs) in resolution order.
 */
async function resolveCnameChain(hostname, { resolveCname, timeoutMs }) {
  const chain = [];
  let current = hostname;
  for (let hop = 0; hop < MAX_CNAME_HOPS; hop += 1) {
    let cnames = [];
    try {
      cnames = await withDnsTimeout(Promise.resolve(resolveCname(current)), timeoutMs);
    } catch {
      break;
    }
    const next = String((Array.isArray(cnames) ? cnames[0] : '') ?? '').trim().toLowerCase().replace(/\.$/, '');
    if (!next || next === current || chain.includes(next)) break;
    chain.push(next);
    current = next;
  }
  return chain;
}

async function withDnsTimeout(promise, timeoutMs) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error('dns_timeout')), Math.min(timeoutMs, 2000));
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function resolveAddresses(hostname, { resolve4, resolve6, timeoutMs }) {
  const lookup = async (fn) => {
    if (typeof fn !== 'function') return [];
    try {
      const rows = await withDnsTimeout(Promise.resolve(fn(hostname)), timeoutMs);
      return (Array.isArray(rows) ? rows : [])
        .map((row) => String(row).trim())
        .filter((row) => isIP(row))
        .slice(0, 2);
    } catch {
      return [];
    }
  };
  const [v4, v6] = await Promise.all([lookup(resolve4), lookup(resolve6)]);
  return { v4, v6 };
}

/**
 * One bounded passive GET. Never follows redirects; reads at most 8KB.
 */
async function passiveGet(url, { fetchFn, timeoutMs }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchFn(url, {
      method: 'GET',
      headers: {
        Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
        'User-Agent': 'Mozilla/5.0 (compatible; AstraNullEdgeDetect/1.0; +https://astranull.invalid/probe)',
      },
      redirect: 'manual',
      signal: controller.signal,
    });
    let bodyText = '';
    if (res && typeof res.text === 'function') {
      bodyText = String(await res.text()).slice(0, MAX_BODY_READ_BYTES);
    }
    return { res, bodyText, error: null };
  } catch (err) {
    return { res: null, bodyText: '', error: err };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Detect WAF/CDN edge presence for a hostname. Metadata-only, passive-only.
 * @param {{
 *   hostname: string,
 *   timeoutMs?: number,
 *   fetchFn?: typeof fetch,
 *   resolveCname?: typeof resolveCname,
 *   resolve4?: typeof resolve4,
 *   resolve6?: typeof resolve6,
 * }} input
 */
export async function detectEdgeForHostname(input = {}) {
  const normalized = normalizeDetectionHostname(input.hostname);
  if (normalized.error) {
    return { error: normalized.error, status: 400 };
  }
  const hostname = normalized.hostname;
  const timeoutMs = Math.min(
    Math.max(Number(input.timeoutMs) || DEFAULT_TIMEOUT_MS, 250),
    MAX_TIMEOUT_MS,
  );
  const deps = {
    fetchFn: input.fetchFn ?? fetch,
    resolveCname: input.resolveCname ?? defaultResolveCname,
    resolve4: input.resolve4 ?? defaultResolve4,
    resolve6: input.resolve6 ?? defaultResolve6,
  };

  const started = Date.now();
  const isIpLiteral = isIP(hostname) !== 0;

  const dnsDeps = {
    resolveCname: deps.resolveCname,
    resolve4: deps.resolve4,
    resolve6: deps.resolve6,
    timeoutMs,
  };
  const cnameChain = isIpLiteral ? [] : await resolveCnameChain(hostname, dnsDeps);
  const lookupHost = cnameChain[cnameChain.length - 1] ?? hostname;
  const addresses = isIpLiteral
    ? { v4: isIP(hostname) === 4 ? [hostname] : [], v6: isIP(hostname) === 6 ? [hostname] : [] }
    : await resolveAddresses(lookupHost, dnsDeps);
  const resolvedIps = [...addresses.v4, ...addresses.v6];

  const scheme = isLoopback(hostname) ? 'http' : 'https';
  const requestHost = isIP(hostname) === 6 ? `[${hostname}]` : hostname;
  const { res, bodyText, error } = await passiveGet(`${scheme}://${requestHost}/`, {
    fetchFn: deps.fetchFn,
    timeoutMs,
  });

  const requestErrorClass = error
    ? (error.name === 'AbortError' ? 'probe_timeout' : (error.code ?? error.name ?? 'probe_failed'))
    : null;

  const headerEntries = res ? extractFingerprintHeaderEntries(res) : [];
  const classification = classifyEdgeFingerprint({
    headerEntries,
    cookieNames: res ? cookieNamesFromHeaders(res) : [],
    bodyText: '',
    statusCode: res?.status ?? null,
    blockResponse: false,
    resolvedIps,
    cnameChain,
  });

  return {
    detection: 'host_edge_detection',
    tier: 'passive_only',
    corpus_version: EDGE_SIGNATURE_CORPUS_VERSION,
    hostname,
    dns_chain: [...cnameChain, ...resolvedIps],
    resolved_ips: resolvedIps,
    waf_present: classification.waf_present,
    cdn_detected: classification.cdn_detected,
    best_vendor: classification.best_vendor,
    vendor_matches: classification.vendor_matches,
    address_matches: classification.address_matches,
    cname_matches: classification.cname_matches,
    conflicting_vendor_signals: classification.conflicting_vendor_signals,
    baseline_status_code: res?.status ?? 0,
    redirect_status: res && res.status >= 300 && res.status < 400 ? res.status : null,
    request_error_class: requestErrorClass,
    requests_sent: 1,
    duration_ms: Date.now() - started,
  };
}
