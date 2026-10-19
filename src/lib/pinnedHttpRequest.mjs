import dns from 'node:dns/promises';
import http from 'node:http';
import http2 from 'node:http2';
import https from 'node:https';
import net from 'node:net';
import { Readable } from 'node:stream';
import tls from 'node:tls';
import { randomUUID } from 'node:crypto';
import { captureHttpHeaders, captureUrl, HTTP_CAPTURE_VERSION } from './probeHttpCapture.mjs';
import { assertProbeDestinationAllowed } from './probeEndpoint.mjs';
import { emitProbeActivity } from './probeActivity.mjs';
import { previewRequest, previewContentType, captureResponsePayload, emitPayloadChunks, PROBE_PREVIEW_BYTES, MAX_CAPTURE_BODY_BYTES } from './probePayloadPreview.mjs';

export const ASTRANULL_PROBE_USER_AGENT = 'AstraNull-Probe/1.0 (+https://astranull.io/probe)';

export const PINNED_HTTP_METHODS = Object.freeze(['GET', 'HEAD', 'OPTIONS', 'POST']);
export const METHOD_POLICY_ONLY_HTTP_METHODS = Object.freeze(['TRACE', 'ASTRANULLPROBE']);
export const METHOD_POLICY_PROBE_KIND = 'waf_method_policy_probe';

export function assertPinnedHttpMethod(method, { probeKind = null, body = null } = {}) {
  const normalized = String(method ?? 'GET').toUpperCase();
  const hasBody = body != null;
  if (METHOD_POLICY_ONLY_HTTP_METHODS.includes(normalized)) {
    if (probeKind !== METHOD_POLICY_PROBE_KIND || hasBody) {
      throw Object.assign(new Error('HTTP method not permitted for this probe'), { code: 'EHTTP_METHOD' });
    }
    return normalized;
  }
  if (!PINNED_HTTP_METHODS.includes(normalized)) {
    throw Object.assign(new Error('HTTP method not permitted'), { code: 'EHTTP_METHOD' });
  }
  return normalized;
}

const DEFAULT_TRANSPORT_TIMEOUT_MS = 5000;
const MAX_TRANSPORT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_REQUEST_BYTES = 64 * 1024;
const AUTHORITATIVE_DNS_NEGATIVE_CODES = new Set(['ENODATA', 'ENOTFOUND']);

function dnsResolverErrorCode(error) {
  return String(error?.code ?? '').trim().toUpperCase();
}

async function resolveOrEmpty(fn, host) {
  try {
    const values = await fn(host);
    return Array.isArray(values) ? values.filter((value) => net.isIP(value) !== 0) : [];
  } catch (error) {
    if (AUTHORITATIVE_DNS_NEGATIVE_CODES.has(dnsResolverErrorCode(error))) return [];
    throw error;
  }
}

function destinationError(message, details = {}) {
  return Object.assign(new Error(message), { code: 'EDESTINATION', ...details });
}

function canonicalHost(value) {
  const candidate = String(value ?? '').trim().replace(/^\[|\]$/g, '');
  if (!candidate) return '';
  return (net.isIP(candidate) !== 0 ? candidate : candidate.replace(/\.$/, '')).toLowerCase();
}

function assertAllowedAddresses(addresses, policy) {
  for (const address of addresses) {
    const verdict = assertProbeDestinationAllowed(address, policy);
    if (!verdict.ok) {
      throw destinationError(verdict.message, { blockedAddress: address });
    }
  }
}

/**
 * Validate the worker-preflight handoff. Both fields are required together so an
 * address set can never be reused for a different logical host. A complete set is
 * policy-checked again here, at the actual transport boundary.
 */
function readInjectedDestination(deps, policy) {
  const hasHost = Object.prototype.hasOwnProperty.call(deps, 'vettedHost');
  const hasAddresses = Object.prototype.hasOwnProperty.call(deps, 'vettedAddresses');
  if (!hasHost && !hasAddresses) return null;
  if (!hasHost || !hasAddresses) {
    throw destinationError('incomplete vetted destination');
  }

  if (typeof deps.vettedHost !== 'string' || deps.vettedHost !== deps.vettedHost.trim()) {
    throw destinationError('invalid vetted destination host');
  }
  const host = canonicalHost(deps.vettedHost);
  if (!host || host.includes('/') || host.includes('@')) {
    throw destinationError('invalid vetted destination host');
  }
  if (!Array.isArray(deps.vettedAddresses) || deps.vettedAddresses.length === 0) {
    throw destinationError('vetted destination addresses must be a nonempty array');
  }

  const addresses = [];
  const seen = new Set();
  for (const value of deps.vettedAddresses) {
    if (typeof value !== 'string' || value !== value.trim() || net.isIP(value) === 0 || seen.has(value)) {
      throw destinationError('invalid vetted destination address set');
    }
    seen.add(value);
    addresses.push(value);
  }
  if (net.isIP(host) !== 0 && (addresses.length !== 1 || canonicalHost(addresses[0]) !== host)) {
    throw destinationError('vetted literal host does not match its address set');
  }
  assertAllowedAddresses(addresses, policy);
  return { host, addresses };
}

export async function resolvePinnedDestination(host, deps = {}) {
  const candidate = String(host ?? '').trim().replace(/^\[|\]$/g, '');
  if (!candidate) throw destinationError('missing destination host');
  const policy = deps.destinationPolicy ?? { allowPrivate: false, allowLoopback: false };
  const injected = readInjectedDestination(deps, policy);

  const familyPref = deps.addressFamily === 'ipv4' || deps.addressFamily === 'ipv6'
    ? deps.addressFamily
    : 'both';
  const byFamily = (list) => {
    const ipv4 = list.filter((value) => net.isIP(value) === 4);
    const ipv6 = list.filter((value) => net.isIP(value) === 6);
    return { ipv4, ipv6 };
  };
  const pickAddresses = (ipv4, ipv6) => (
    familyPref === 'ipv4' ? ipv4 : familyPref === 'ipv6' ? ipv6 : [...ipv4, ...ipv6]
  );

  // Same logical host: consume the exact preflight set and do not touch DNS. A
  // genuinely different redirect/discovered host is resolved and classified below.
  if (injected && canonicalHost(candidate) === injected.host) {
    const split = byFamily(injected.addresses);
    const addresses = pickAddresses(split.ipv4, split.ipv6);
    if (addresses.length === 0) {
      throw Object.assign(new Error('destination did not resolve'), { code: 'ENOTFOUND' });
    }
    return {
      host: candidate,
      address: addresses[0],
      addresses: [...addresses],
      families: split,
    };
  }

  let ipv4 = [];
  let ipv6 = [];
  if (net.isIP(candidate) === 4) ipv4 = [candidate];
  else if (net.isIP(candidate) === 6) ipv6 = [candidate];
  else {
    const v4Task = familyPref === 'ipv6'
      ? Promise.resolve([])
      : resolveOrEmpty(deps.resolve4Fn ?? dns.resolve4, candidate);
    const v6Task = familyPref === 'ipv4'
      ? Promise.resolve([])
      : resolveOrEmpty(deps.resolve6Fn ?? dns.resolve6, candidate);
    [ipv4, ipv6] = await Promise.all([v4Task, v6Task]);
  }
  const addresses = [...new Set(pickAddresses(ipv4, ipv6))];
  if (addresses.length === 0) {
    throw Object.assign(new Error('destination did not resolve'), { code: 'ENOTFOUND' });
  }
  assertAllowedAddresses(addresses, policy);
  return { host: candidate, address: addresses[0], addresses, families: { ipv4, ipv6 } };
}

function responseHeaders(headers) {
  const source = headers ?? {};
  const get = (name) => {
    const value = source[String(name).toLowerCase()];
    return Array.isArray(value) ? value.join(', ') : (value == null ? null : String(value));
  };
  const names = () => Object.keys(source).map((name) => name.toLowerCase()).sort();
  return {
    get,
    has: (name) => get(name) !== null,
    keys: () => names()[Symbol.iterator](),
    forEach(callback) {
      for (const name of names()) callback(get(name), name, this);
    },
    getSetCookie() {
      const value = source['set-cookie'];
      if (value == null) return [];
      return Array.isArray(value) ? value.map(String) : [String(value)];
    },
  };
}

function abortError(message = 'aborted', code) {
  return Object.assign(new Error(message), { name: 'AbortError', ...(code ? { code } : {}) });
}

function timeoutMs(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_TRANSPORT_TIMEOUT_MS;
  return Math.min(Math.floor(parsed), MAX_TRANSPORT_TIMEOUT_MS);
}

function maxResponseBytes(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_MAX_RESPONSE_BYTES;
  return Math.min(Math.floor(parsed), MAX_RESPONSE_BYTES);
}

function logicalHostname(url) {
  return url.hostname.replace(/^\[|\]$/g, '');
}

function assertHttpUrl(urlValue, protocols) {
  let url;
  try {
    url = new URL(urlValue);
  } catch {
    throw Object.assign(new Error('invalid destination URL'), { code: 'EDESTINATION' });
  }
  if (!protocols.includes(url.protocol)) {
    throw Object.assign(new Error('unsupported destination scheme'), { code: 'EDESTINATION' });
  }
  return url;
}

async function resolvePinnedWithinBounds(host, deps, { signal, timeout } = {}) {
  if (signal?.aborted) throw abortError();

  let timer = null;
  let onAbort = null;
  const blockers = [];
  if (signal) {
    blockers.push(new Promise((_, reject) => {
      onAbort = () => reject(abortError());
      signal.addEventListener('abort', onAbort, { once: true });
    }));
  }
  if (timeout != null) {
    blockers.push(new Promise((_, reject) => {
      timer = setTimeout(
        () => reject(abortError('timeout', 'ETIMEOUT')),
        timeout,
      );
    }));
  }

  try {
    return await Promise.race([resolvePinnedDestination(host, deps), ...blockers]);
  } finally {
    if (timer) clearTimeout(timer);
    if (onAbort) signal.removeEventListener('abort', onAbort);
  }
}

function http1RequestOptions(url, pinned, headers, options) {
  const hostname = logicalHostname(url);
  return {
    protocol: url.protocol,
    hostname: pinned.address,
    port: url.port || undefined,
    path: `${url.pathname}${url.search}`,
    method: options.method ?? 'GET',
    headers,
    ...(url.protocol === 'https:'
      ? {
          ...(net.isIP(hostname) === 0 ? { servername: hostname } : {}),
          rejectUnauthorized: true,
        }
      : {}),
  };
}

function headersWithHost(url, input = {}) {
  const headers = { ...input };
  if (!Object.keys(headers).some((name) => name.toLowerCase() === 'host')) headers.Host = url.host;
  if (!Object.keys(headers).some((name) => name.toLowerCase() === 'user-agent')) {
    headers['User-Agent'] = ASTRANULL_PROBE_USER_AGENT;
  }
  return headers;
}

function exchangeActivity(url, options, deps, operation) {
  const id = randomUUID();
  return { capture_version: HTTP_CAPTURE_VERSION, exchange_id: id, attempt_id: id, operation_id: id,
    operation, method: options.method ?? 'GET', url: captureUrl(url.href),
    protocol: url.protocol.replace(':', ''), ...(options.activity_phase ? { phase: options.activity_phase } : {}) };
}

function requestCapture(url, options, deps, headers, common) {
  const preview = previewRequest(url.href, options);
  const body = options.body == null ? Buffer.alloc(0) : Buffer.from(options.body);
  const captured = { ...preview, request_headers: captureHttpHeaders(headers) };
  if (body.length > PROBE_PREVIEW_BYTES || Buffer.byteLength(JSON.stringify({ ...common, ...captured })) > 20 * 1024) {
    try { emitPayloadChunks(deps, common, 'request', body.subarray(0, MAX_CAPTURE_BODY_BYTES)); } catch { /* Capture cannot change transport. */ }
  }
  return captured;
}

/**
 * Minimal fetch-compatible response for metadata-only probes. Redirects are
 * intentionally never followed here; callers must explicitly vet every hop.
 */
export async function pinnedFetch(urlValue, options = {}, deps = {}) {
  const startedAt = Date.now();
  const method = assertPinnedHttpMethod(options.method ?? 'GET', {
    probeKind: options.probeKind ?? options.probe_kind ?? null,
    body: options.body,
  });
  const url = assertHttpUrl(urlValue, ['http:', 'https:']);

  const pinned = await resolvePinnedWithinBounds(logicalHostname(url), deps, {
    signal: options.signal,
    ...(options.timeoutMs == null ? {} : { timeout: timeoutMs(options.timeoutMs) }),
  });
  if (options.signal?.aborted) throw abortError();
  const requestFn = url.protocol === 'https:'
    ? (deps.httpsRequestFn ?? https.request)
    : (deps.httpRequestFn ?? http.request);
  const headers = headersWithHost(url, options.headers);
  const requestOptions = { ...options, method };
  const commonActivity = exchangeActivity(url, requestOptions, deps, 'http_request');

  return new Promise((resolve, reject) => {
    let settled = false;
    const finishReject = (error) => {
      if (settled) return;
      settled = true;
      emitProbeActivity(deps, { stage: 'attempt_failed', ...commonActivity, error_class: String(error?.code ?? error?.name ?? 'request_failed'), duration_ms: Date.now() - startedAt });
      reject(error);
    };
    const req = requestFn(http1RequestOptions(url, pinned, headers, requestOptions), (res) => {
      if (settled) {
        res.destroy();
        return;
      }
      settled = true;
      const contentType = previewContentType(res.headers?.['content-type']);
      const responseActivity = { ...commonActivity, ...(Number.isInteger(res.statusCode) ? { status_code: res.statusCode } : {}),
        ...(['1.0', '1.1'].includes(res.httpVersion) ? { http_version: res.httpVersion } : {}),
        response_headers: captureHttpHeaders(res.rawHeaders ?? res.headers),
        ...(contentType ? { response_content_type: contentType } : {}) };
      emitProbeActivity(deps, { stage: 'response_received', ...responseActivity,
        response_payload_available: false, reason: 'response_not_consumed', duration_ms: Date.now() - startedAt });
      let body = Readable.toWeb(res);
      if (typeof deps.onProbeActivity === 'function') {
        const capture = captureResponsePayload(deps, responseActivity, contentType);
        if (commonActivity.method === 'HEAD' || [204, 304].includes(res.statusCode)) capture.complete();
        else {
          const reader = body.getReader();
          let cancelled = false;
          body = new ReadableStream({
            async pull(controller) {
              try {
                const next = await reader.read();
                if (cancelled) return;
                if (next.done) { capture.complete(); controller.close(); reader.releaseLock(); return; }
                try { capture.chunk(next.value); } catch { /* Bounded observation only. */ }
                controller.enqueue(next.value);
              } catch (error) { capture.cancelled(); controller.error(error); }
            },
            async cancel(reason) { cancelled = true; capture.cancelled(); try { await reader.cancel(reason); } finally { reader.releaseLock(); } },
          }, { highWaterMark: 0 });
        }
      }
      resolve({
        status: res.statusCode ?? 0,
        statusText: res.statusMessage ?? '',
        ok: (res.statusCode ?? 0) >= 200 && (res.statusCode ?? 0) < 300,
        headers: responseHeaders(res.headers),
        url: url.href,
        body,
        pinnedAddress: pinned.address,
        ...(url.protocol === 'https:' ? { tls: (() => {
          const socket = res.socket;
          const certificate = socket?.getPeerCertificate?.();
          const hasCertificate = certificate && Object.keys(certificate).length > 0;
          return { verification_enabled: true, trust_valid: socket?.authorized === true,
            name_valid: hasCertificate ? !tls.checkServerIdentity(logicalHostname(url), certificate) : null,
            authorization_error: socket?.authorizationError ? String(socket.authorizationError).slice(0, 128) : null,
            certificate_sha256: hasCertificate ? certificate.fingerprint256 ?? null : null };
        })() } : { tls: { verification_enabled: false, trust_valid: null, name_valid: null } }),
      });
    });
    req.once('error', finishReject);
    const abort = () => req.destroy(abortError());
    if (options.signal) {
      if (options.signal.aborted) abort();
      else options.signal.addEventListener('abort', abort, { once: true });
      req.once('close', () => options.signal?.removeEventListener('abort', abort));
    }
    if (options.body != null) req.write(options.body);
    req.end();
    if (!req.destroyed && !options.signal?.aborted) emitProbeActivity(deps, { stage: 'request_started', ...commonActivity,
      http_version: '1.1', body_bytes: options.body == null ? 0 : Buffer.byteLength(options.body), header_names: Object.keys(headers).slice(0, 16),
      ...requestCapture(url, options, deps, req.getHeaders?.() ?? headers, commonActivity) });
  });
}

/**
 * Perform one HTTP/1.1 WebSocket upgrade handshake against an independently
 * resolved and classified IP literal. A 101 settles from ClientRequest's
 * `upgrade` event, and the upgraded socket is immediately destroyed so the
 * readiness probe never holds a connection open. Redirects are returned but
 * never followed, preventing marker/nonce headers from crossing origins.
 */
export async function pinnedWebSocketUpgrade(urlValue, options = {}, deps = {}) {
  const url = assertHttpUrl(urlValue, ['http:', 'https:']);

  const boundedTimeout = timeoutMs(options.timeoutMs);
  const deadline = Date.now() + boundedTimeout;
  const pinned = await resolvePinnedWithinBounds(logicalHostname(url), deps, {
    signal: options.signal,
    timeout: boundedTimeout,
  });
  const requestFn = url.protocol === 'https:'
    ? (deps.httpsRequestFn ?? https.request)
    : (deps.httpRequestFn ?? http.request);
  const headers = headersWithHost(url, options.headers);
  const startedAt = Date.now();
  const commonActivity = exchangeActivity(url, options, deps, 'websocket_upgrade');

  return new Promise((resolve, reject) => {
    let settled = false;
    let timer = null;
    let req;

    const cleanup = () => {
      if (timer) clearTimeout(timer);
      options.signal?.removeEventListener('abort', abort);
    };
    const finishReject = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      emitProbeActivity(deps, { stage: 'attempt_failed', ...commonActivity,
        error_class: String(error?.code ?? error?.name ?? 'request_failed'), duration_ms: Date.now() - startedAt });
      reject(error);
    };
    const finishResponse = (res) => {
      if (settled) return;
      settled = true;
      cleanup();
      emitProbeActivity(deps, { stage: 'response_received', ...commonActivity,
        ...(Number.isInteger(res.statusCode) ? { status_code: res.statusCode } : {}),
        ...(['1.0', '1.1'].includes(res.httpVersion) ? { http_version: res.httpVersion } : {}),
        response_headers: captureHttpHeaders(res.rawHeaders ?? res.headers),
        response_payload_available: false, reason: 'response_not_consumed', duration_ms: Date.now() - startedAt });
      resolve({
        status: res.statusCode ?? 0,
        headers: responseHeaders(res.headers),
        url: url.href,
        pinnedAddress: pinned.address,
      });
    };
    const terminate = (error) => {
      req?.destroy(error);
      finishReject(error);
    };
    const abort = () => terminate(abortError());

    try {
      req = requestFn(http1RequestOptions(url, pinned, headers, options), (res) => {
        finishResponse(res);
        res.destroy();
      });
      req.once('upgrade', (res, socket) => {
        finishResponse(res);
        socket.destroy();
      });
      req.once('error', finishReject);
      if (options.signal?.aborted) {
        abort();
        return;
      }
      options.signal?.addEventListener('abort', abort, { once: true });
      timer = setTimeout(
        () => terminate(abortError('timeout', 'ETIMEOUT')),
        Math.max(1, deadline - Date.now()),
      );
      if (options.body != null) req.write(options.body);
      req.end();
      if (!req.destroyed) emitProbeActivity(deps, { stage: 'request_started', ...commonActivity, http_version: '1.1',
        body_bytes: options.body == null ? 0 : Buffer.byteLength(options.body),
        ...requestCapture(url, options, deps, req.getHeaders?.() ?? headers, commonActivity) });
    } catch (error) {
      finishReject(error);
    }
  });
}

function http2RequestHeaders(url, options) {
  const headers = {
    ':method': options.method ?? 'GET',
    ':path': `${url.pathname}${url.search}`,
    ':scheme': 'https',
    ':authority': url.host,
  };
  if (!Object.keys(options.headers ?? {}).some((name) => name.toLowerCase() === 'user-agent')) {
    headers['user-agent'] = ASTRANULL_PROBE_USER_AGENT;
  }

  for (const [name, rawValue] of Object.entries(options.headers ?? {})) {
    const lower = name.toLowerCase();
    if (lower === 'host') {
      headers[':authority'] = String(rawValue);
      continue;
    }
    if (lower.startsWith(':') || ['connection', 'upgrade', 'transfer-encoding'].includes(lower)) {
      throw Object.assign(new Error(`unsupported HTTP/2 request header: ${name}`), { code: 'EHTTP2HEADER' });
    }
    if (lower === 'te' && String(rawValue).toLowerCase() !== 'trailers') {
      throw Object.assign(new Error('HTTP/2 TE header must be trailers'), { code: 'EHTTP2HEADER' });
    }
    headers[lower] = rawValue;
  }
  return headers;
}

/**
 * Send one bounded metadata-only request over TLS HTTP/2. The TLS socket is
 * connected to the independently classified IP literal while `:authority` and
 * TLS SNI retain the declared hostname. Response data is drained under a byte
 * cap so gRPC trailers can be observed. Optional activity retains only a redacted bounded preview.
 */
export async function pinnedHttp2Request(urlValue, options = {}, deps = {}) {
  const url = assertHttpUrl(urlValue, ['https:']);

  const boundedTimeout = timeoutMs(options.timeoutMs);
  const deadline = Date.now() + boundedTimeout;
  const pinned = await resolvePinnedWithinBounds(logicalHostname(url), deps, {
    signal: options.signal,
    timeout: boundedTimeout,
  });
  const body = options.body == null ? Buffer.alloc(0) : Buffer.from(options.body);
  if (body.length > MAX_REQUEST_BYTES) {
    throw Object.assign(new Error('HTTP/2 request body exceeds bounded limit'), { code: 'EREQUESTTOOLARGE' });
  }
  const requestHeaders = http2RequestHeaders(url, options);
  const responseByteLimit = maxResponseBytes(options.maxResponseBytes);
  const connectFn = deps.http2ConnectFn ?? http2.connect;
  const tlsConnectFn = deps.tlsConnectFn ?? tls.connect;
  const hostname = logicalHostname(url);
  const startedAt = Date.now();
  const commonActivity = { ...exchangeActivity(url, options, deps, 'http2_request'), http_version: '2.0' };

  return new Promise((resolve, reject) => {
    let settled = false;
    let session = null;
    let stream = null;
    let timer = null;
    let response = null;
    let trailers = {};
    let receivedBytes = 0;
    let responseCapture = null;
    const transientChunks = options.captureResponseBody === true ? [] : null;

    const cleanup = () => {
      if (timer) clearTimeout(timer);
      options.signal?.removeEventListener('abort', abort);
    };
    const closeTransport = () => {
      stream?.close?.(http2.constants.NGHTTP2_CANCEL);
      session?.destroy?.();
    };
    const finishReject = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      closeTransport();
      emitProbeActivity(deps, { stage: 'attempt_failed', ...commonActivity, error_class: String(error?.code ?? error?.name ?? 'request_failed'), duration_ms: Date.now() - startedAt });
      reject(error);
    };
    const finishResolve = () => {
      if (settled) return;
      if (!response) {
        finishReject(Object.assign(new Error('HTTP/2 stream ended without response headers'), { code: 'EPROTO' }));
        return;
      }
      settled = true;
      cleanup();
      responseCapture?.complete();
      const result = {
        status: Number(response[':status'] ?? 0),
        headers: responseHeaders(response),
        trailers: responseHeaders(trailers),
        url: url.href,
        pinnedAddress: pinned.address,
        httpVersion: '2.0',
        responseBytes: receivedBytes,
        ...(transientChunks ? { responseBody: Buffer.concat(transientChunks, receivedBytes) } : {}),
      };
      closeTransport();
      resolve(result);
    };
    const abort = () => finishReject(abortError());

    try {
      session = connectFn(url.origin, {
        createConnection: () => tlsConnectFn({
          host: pinned.address,
          port: url.port ? Number(url.port) : 443,
          ...(net.isIP(hostname) === 0 ? { servername: hostname } : {}),
          ALPNProtocols: ['h2'],
          rejectUnauthorized: true,
          ...(deps.tlsCa == null ? {} : { ca: deps.tlsCa }),
        }),
      });
      session.once('error', finishReject);
      stream = session.request(requestHeaders);
      stream.once('response', (headers) => {
        response = headers;
          const contentType = previewContentType(headers['content-type']);
        const activity = { ...commonActivity, ...(Number(headers[':status']) >= 100 ? { status_code: Number(headers[':status']) } : {}) };
        emitProbeActivity(deps, { stage: 'response_received', ...activity,
          response_headers: captureHttpHeaders(headers),
          response_payload_available: false, reason: 'response_not_consumed',
          ...(contentType ? { response_content_type: contentType } : {}), duration_ms: Date.now() - startedAt });
        if (typeof deps.onProbeActivity === 'function') responseCapture = captureResponsePayload(deps, activity, contentType);
      });
      stream.once('trailers', (headers) => {
        trailers = headers;
      });
      stream.on('data', (chunk) => {
        receivedBytes += chunk.length;
        if (receivedBytes > responseByteLimit) {
          finishReject(Object.assign(new Error('HTTP/2 response exceeds bounded limit'), { code: 'ERESPONSETOOLARGE' }));
          return;
        }
        transientChunks?.push(Buffer.from(chunk));
        responseCapture?.chunk(chunk);
      });
      stream.once('aborted', () => {
        finishReject(Object.assign(new Error('HTTP/2 stream aborted'), { code: 'EHTTP2ABORTED' }));
      });
      stream.once('error', finishReject);
      stream.once('end', finishResolve);
      stream.once('close', () => {
        if (!settled && !stream.readableEnded) {
          finishReject(Object.assign(new Error('HTTP/2 stream closed before completion'), { code: 'EHTTP2CLOSED' }));
        }
      });
      if (options.signal?.aborted) {
        abort();
        return;
      }
      options.signal?.addEventListener('abort', abort, { once: true });
      timer = setTimeout(
        () => finishReject(abortError('timeout', 'ETIMEOUT')),
        Math.max(1, deadline - Date.now()),
      );
      stream.end(body);
      emitProbeActivity(deps, { stage: 'request_started', ...commonActivity, body_bytes: body.length,
        header_names: Object.keys(requestHeaders).filter((name) => !name.startsWith(':')).slice(0, 16),
        ...requestCapture(url, options, deps, requestHeaders, commonActivity) });
    } catch (error) {
      finishReject(error);
    }
  });
}
