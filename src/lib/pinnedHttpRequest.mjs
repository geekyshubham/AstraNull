import dns from 'node:dns/promises';
import http from 'node:http';
import http2 from 'node:http2';
import https from 'node:https';
import net from 'node:net';
import { Readable } from 'node:stream';
import tls from 'node:tls';
import { assertProbeDestinationAllowed } from './probeEndpoint.mjs';

const DEFAULT_TRANSPORT_TIMEOUT_MS = 5000;
const MAX_TRANSPORT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_REQUEST_BYTES = 64 * 1024;

async function resolveOrEmpty(fn, host) {
  try {
    const values = await fn(host);
    return Array.isArray(values) ? values.filter((value) => net.isIP(value) !== 0) : [];
  } catch {
    return [];
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

  // Same logical host: consume the exact preflight set and do not touch DNS. A
  // genuinely different redirect/discovered host is resolved and classified below.
  if (injected && canonicalHost(candidate) === injected.host) {
    return {
      host: candidate,
      address: injected.addresses[0],
      addresses: [...injected.addresses],
    };
  }

  const addresses = net.isIP(candidate) !== 0
    ? [candidate]
    : [...new Set((await Promise.all([
      resolveOrEmpty(deps.resolve4Fn ?? dns.resolve4, candidate),
      resolveOrEmpty(deps.resolve6Fn ?? dns.resolve6, candidate),
    ])).flat())];
  if (addresses.length === 0) {
    throw Object.assign(new Error('destination did not resolve'), { code: 'ENOTFOUND' });
  }
  assertAllowedAddresses(addresses, policy);
  return { host: candidate, address: addresses[0], addresses };
}

function responseHeaders(headers) {
  return {
    get(name) {
      const value = headers?.[String(name).toLowerCase()];
      return Array.isArray(value) ? value.join(', ') : (value == null ? null : String(value));
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
  return headers;
}

/**
 * Minimal fetch-compatible response for metadata-only probes. Redirects are
 * intentionally never followed here; callers must explicitly vet every hop.
 */
export async function pinnedFetch(urlValue, options = {}, deps = {}) {
  const url = assertHttpUrl(urlValue, ['http:', 'https:']);
  const pinned = await resolvePinnedWithinBounds(logicalHostname(url), deps, {
    signal: options.signal,
    ...(options.timeoutMs == null ? {} : { timeout: timeoutMs(options.timeoutMs) }),
  });
  const requestFn = url.protocol === 'https:'
    ? (deps.httpsRequestFn ?? https.request)
    : (deps.httpRequestFn ?? http.request);
  const headers = headersWithHost(url, options.headers);

  return new Promise((resolve, reject) => {
    let settled = false;
    const finishReject = (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    const req = requestFn(http1RequestOptions(url, pinned, headers, options), (res) => {
      if (settled) {
        res.destroy();
        return;
      }
      settled = true;
      resolve({
        status: res.statusCode ?? 0,
        headers: responseHeaders(res.headers),
        url: url.href,
        body: Readable.toWeb(res),
        pinnedAddress: pinned.address,
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
      reject(error);
    };
    const finishResponse = (res) => {
      if (settled) return;
      settled = true;
      cleanup();
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
 * cap solely so gRPC trailers can be observed; no body is retained.
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

  return new Promise((resolve, reject) => {
    let settled = false;
    let session = null;
    let stream = null;
    let timer = null;
    let response = null;
    let trailers = {};
    let receivedBytes = 0;

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
      const result = {
        status: Number(response[':status'] ?? 0),
        headers: responseHeaders(response),
        trailers: responseHeaders(trailers),
        url: url.href,
        pinnedAddress: pinned.address,
        httpVersion: '2.0',
        responseBytes: receivedBytes,
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
      });
      stream.once('trailers', (headers) => {
        trailers = headers;
      });
      stream.on('data', (chunk) => {
        receivedBytes += chunk.length;
        if (receivedBytes > responseByteLimit) {
          finishReject(Object.assign(new Error('HTTP/2 response exceeds bounded limit'), { code: 'ERESPONSETOOLARGE' }));
        }
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
    } catch (error) {
      finishReject(error);
    }
  });
}
