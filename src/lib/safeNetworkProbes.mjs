/**
 * Bounded safe network probes — single datagram/request caps, no amplification or flooding.
 */

import { randomBytes } from 'node:crypto';
import dgram from 'node:dgram';
import http2 from 'node:http2';
import net from 'node:net';
import tls from 'node:tls';
import { pinnedFetch, pinnedWebSocketUpgrade, resolvePinnedDestination } from './pinnedHttpRequest.mjs';
import { startProbeIoAttempt } from './probeAttempt.mjs';
import { reflectorPayloadForProfile } from './reflectorPayloads.mjs';

const SAFE_UDP_PAYLOAD_PREFIX = 'ASTRANULL:udp:';
const SAFE_ALERT_PAYLOAD_TYPE = 'astranull_alert_workflow_ping';

/**
 * @param {{ target?: { value?: string, port?: number } }} job
 */
export function parseNetworkEndpoint(job) {
  const target = job.target ?? {};
  const value = String(target.value ?? '').trim();
  const portFromTarget = validNetworkPort(target.port != null ? Number(target.port) : null);
  if (!value) return null;

  const bracketed = value.match(/^\[([^\]]+)\](?::(\d{1,5}))?$/);
  if (bracketed) {
    if (net.isIP(bracketed[1]) !== 6) return null;
    const port = bracketed[2] != null ? validNetworkPort(Number(bracketed[2])) : portFromTarget;
    return port ? { host: bracketed[1], port } : null;
  }
  // An unbracketed IPv6 literal never carries a port; splitting at its last colon would dial a different address.
  if (net.isIP(value) === 6) return portFromTarget ? { host: value, port: portFromTarget } : null;
  const hostPort = value.match(/^([^:\s]+):(\d{1,5})$/);
  if (hostPort) {
    const port = validNetworkPort(Number(hostPort[2]));
    return port ? { host: hostPort[1], port } : null;
  }
  if (value.includes(':')) return null;
  return portFromTarget ? { host: value, port: portFromTarget } : null;
}

function resolveHostForJob(job) {
  const value = String(job.target?.value ?? '').trim();
  if (!value) return null;
  if (/^https?:\/\//i.test(value)) {
    try {
      return new URL(value).hostname.replace(/^\[/, '').replace(/\]$/, '') || null;
    } catch {
      return null;
    }
  }
  const endpoint = parseNetworkEndpoint(job);
  if (endpoint?.host) return endpoint.host;
  return value.replace(/^\/+/, '') || null;
}

function resolvePortForJob(job, fallback = 443) {
  const value = String(job.target?.value ?? '').trim();
  if (/^https?:\/\//i.test(value)) {
    try {
      const port = Number(new URL(value).port);
      if (Number.isInteger(port) && port > 0 && port <= 65535) return port;
    } catch {
      return fallback;
    }
  }
  return parseNetworkEndpoint(job)?.port ?? fallback;
}

function withProfileKind(job, metadata) {
  const profileKind = job.probe_profile?.kind ?? metadata.probe_kind ?? null;
  return { profile_kind: profileKind, ...metadata };
}

function safeUdpPayload(job) {
  const noncePart = String(job.nonce_hash ?? job.nonce ?? 'probe').slice(0, 16);
  return Buffer.from(`${SAFE_UDP_PAYLOAD_PREFIX}${noncePart}`, 'utf8');
}

function udpResponseSizeClass(byteCount) {
  if (byteCount === 0) return 'none';
  if (byteCount <= 64) return 'tiny';
  if (byteCount <= 512) return 'small';
  if (byteCount <= 1200) return 'medium';
  return 'large';
}

function canonicalIpAddress(value) {
  const candidate = String(value ?? '').trim();
  if (net.isIP(candidate) !== 6) return candidate;
  try {
    return new URL(`http://[${candidate}]/`).hostname.slice(1, -1).toLowerCase();
  } catch {
    return candidate.toLowerCase();
  }
}

export function isExpectedUdpPeer(rinfo, host, port) {
  return rinfo != null
    && canonicalIpAddress(rinfo.address) === canonicalIpAddress(host)
    && Number(rinfo.port) === port;
}

/**
 * Send exactly one datagram and wait for at most one response from the pinned peer.
 * The response payload is never returned or retained.
 *
 * @param {import('node:dgram').Socket} socket
 * @param {Buffer} payload
 * @param {number} port
 * @param {string} host
 * @param {number} timeoutMs
 */
function sendUdpDatagram(socket, payload, port, host, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer;

    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener?.('message', onMessage);
      socket.removeListener?.('error', onError);
      try {
        socket.close();
      } catch {
        // A synchronous send failure can leave the socket unopened; it is still settled.
      }
    };
    const settle = (value, error) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) reject(error);
      else resolve(value);
    };
    const onMessage = (message, rinfo) => {
      if (!isExpectedUdpPeer(rinfo, host, port)) return;
      const responseBytes = Buffer.isBuffer(message)
        ? message.length
        : Buffer.byteLength(message ?? '');
      settle({
        response_received: true,
        response_bytes: responseBytes,
        response_size_class: udpResponseSizeClass(responseBytes),
      });
    };
    const onError = (error) => settle(null, error);

    socket.on('message', onMessage);
    socket.once('error', onError);
    timer = setTimeout(() => settle({
      response_received: false,
      response_bytes: 0,
      response_size_class: 'none',
    }), Math.max(1, Number(timeoutMs) || 5000));

    try {
      socket.send(payload, port, host, (error) => {
        if (error) settle(null, error);
      });
    } catch (error) {
      settle(null, error);
    }
  });
}

function validNetworkPort(value) {
  const port = Number(value);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : null;
}

function reflectionEndpoint(job, payloadProfile) {
  const host = resolveHostForJob(job);
  if (!host) return null;
  const customerPort = validNetworkPort(job.target?.port)
    ?? validNetworkPort(parseNetworkEndpoint(job)?.port);
  const port = customerPort
    ?? validNetworkPort(job.probe_profile?.service_port)
    ?? validNetworkPort(payloadProfile.default_port);
  return port == null ? null : { host, port };
}

function sendTcpPayload(connectFn, payload, endpoint, timeoutMs, deps, onReserved) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer;
    const settle = (value, error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socket.destroy();
      } catch {
        // The injected socket can fail synchronously before it is fully initialized.
      }
      if (error) reject(error);
      else resolve(value);
    };
    const socket = startProbeIoAttempt(
      deps,
      'reflection_tcp',
      () => connectFn({ host: endpoint.host, port: endpoint.port }, () => {
        try {
          socket.write(payload, (error) => {
            if (error) settle(null, error);
          });
        } catch (error) {
          settle(null, error);
        }
      }),
      onReserved,
    );
    socket.once('data', (chunk) => settle({
      response_received: true,
      response_bytes: Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(chunk ?? ''),
    }));
    socket.once('end', () => settle({ response_received: false, response_bytes: 0 }));
    socket.once('close', () => settle({ response_received: false, response_bytes: 0 }));
    socket.once('error', (error) => settle(null, error));
    socket.setTimeout?.(Math.max(1, timeoutMs), () => settle({
      response_received: false,
      response_bytes: 0,
    }));
    timer = setTimeout(() => settle({
      response_received: false,
      response_bytes: 0,
    }), Math.max(1, timeoutMs));
  });
}

function reflectionFailure(job, metadata, externalResult, requestsSent, started) {
  const durationMs = Date.now() - started;
  return {
    external_result: externalResult,
    metadata: {
      probe_kind: 'reflection_service_probe',
      ...metadata,
      duration_ms: durationMs,
    },
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

export async function probeReflectionService(job, deps = {}) {
  const profileName = job.probe_profile?.payload_profile ?? 'generic_probe';
  const payloadProfile = reflectorPayloadForProfile(profileName);
  const endpoint = reflectionEndpoint(job, payloadProfile);
  const started = Date.now();
  if (!endpoint) {
    return reflectionFailure(job, {
      target_port: null,
      payload_profile: payloadProfile.id,
      request_bytes: 0,
      response_received: false,
      response_bytes: 0,
      response_size_class: 'none',
      amplification_ratio: null,
      reflector_confirmed: false,
      error_class: 'unsupported_target',
    }, 'error', 0, started);
  }

  const timeoutMs = Math.max(1, Number(job.constraints?.timeout_ms) || 5000);
  const maxRequests = Math.min(2, Math.max(1, Number(job.constraints?.max_requests) || 1));
  const payload = payloadProfile.build({
    nonceHash: job.nonce_hash ?? job.nonce,
    queryName: job.target?.metadata?.query_name,
  });
  let requestsSent = 0;
  const baseMetadata = {
    target_port: endpoint.port,
    payload_profile: payloadProfile.id,
    request_bytes: payload.length,
  };

  try {
    const pinned = await resolvePinnedDestination(endpoint.host, deps);
    let response = { response_received: false, response_bytes: 0 };
    if (payloadProfile.transport === 'tcp') {
      response = await sendTcpPayload(
        deps.connectFn ?? net.connect,
        payload,
        { host: pinned.address, port: endpoint.port },
        timeoutMs,
        deps,
        () => { requestsSent = 1; },
      );
    } else {
      const createSocket = deps.createSocket ?? dgram.createSocket.bind(dgram);
      for (let attempt = 0; attempt < maxRequests; attempt += 1) {
        const remainingMs = timeoutMs - (Date.now() - started);
        if (remainingMs <= 0) break;
        const attemptsRemaining = maxRequests - attempt;
        const attemptTimeoutMs = Math.max(1, Math.floor(remainingMs / attemptsRemaining));
        const socket = startProbeIoAttempt(
          deps,
          'reflection_udp',
          () => createSocket(net.isIP(pinned.address) === 6 ? 'udp6' : 'udp4'),
          () => { requestsSent += 1; },
        );
        response = await sendUdpDatagram(
          socket,
          payload,
          endpoint.port,
          pinned.address,
          attemptTimeoutMs,
        );
        if (response.response_received) break;
      }
    }

    const classification = payloadProfile.classify(
      payload,
      response.response_bytes,
      response.response_received,
    );
    if (!response.response_received) {
      return reflectionFailure(job, {
        ...baseMetadata,
        response_received: false,
        response_bytes: 0,
        ...classification,
        error_class: 'no_reflection_response',
      }, 'timeout', requestsSent, started);
    }
    return reflectionFailure(job, {
      ...baseMetadata,
      response_received: true,
      response_bytes: response.response_bytes,
      ...classification,
    }, 'connected', requestsSent, started);
  } catch (error) {
    const code = error?.code ?? '';
    const externalResult = requestsSent === 0
      ? 'error'
      : (code === 'ETIMEOUT'
        ? 'timeout'
        : (['EACCES', 'EPERM', 'ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'ENOTFOUND', 'EDESTINATION'].includes(code)
          ? 'blocked'
          : 'error'));
    return reflectionFailure(job, {
      ...baseMetadata,
      response_received: false,
      response_bytes: 0,
      response_size_class: 'none',
      amplification_ratio: null,
      reflector_confirmed: false,
      error_class: code || 'reflection_probe_failed',
    }, externalResult, requestsSent, started);
  }
}

/**
 * @param {Record<string, unknown>} job
 * @param {{ createSocket?: typeof dgram.createSocket }} deps
 */
export async function probeUdpDatagram(job, deps = {}) {
  const createSocket = deps.createSocket ?? dgram.createSocket.bind(dgram);
  const endpoint = parseNetworkEndpoint(job);
  if (!endpoint) {
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'udp_probe',
        error_class: 'unsupported_target',
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  const timeoutMs = job.constraints?.timeout_ms ?? 5000;
  const started = Date.now();
  let requestsSent = 0;
  try {
    const pinned = await resolvePinnedDestination(endpoint.host, deps);
    const payload = safeUdpPayload(job);
    const socket = startProbeIoAttempt(
      deps,
      'udp_datagram',
      () => createSocket(net.isIP(pinned.address) === 6 ? 'udp6' : 'udp4'),
      () => { requestsSent = 1; },
    );
    const response = await sendUdpDatagram(
      socket,
      payload,
      endpoint.port,
      pinned.address,
      timeoutMs,
    );
    const durationMs = Date.now() - started;
    return {
      external_result: response.response_received ? 'connected' : 'timeout',
      metadata: withProfileKind(job, {
        probe_kind: 'udp_probe',
        ...(!response.response_received ? { error_class: 'no_udp_response' } : {}),
        duration_ms: durationMs,
        target_port: endpoint.port,
        datagram_bytes: payload.length,
        response_received: response.response_received,
        response_bytes: response.response_bytes,
        response_size_class: response.response_size_class,
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  } catch (err) {
    const durationMs = Date.now() - started;
    const code = err?.code ?? '';
    if (code === 'ETIMEOUT') {
      return {
        external_result: requestsSent > 0 ? 'timeout' : 'error',
        metadata: withProfileKind(job, {
          probe_kind: 'udp_probe',
          error_class: 'timeout',
          duration_ms: durationMs,
          target_port: endpoint.port,
        }),
        requests_sent: requestsSent,
        duration_ms: durationMs,
      };
    }
    if (
      code === 'EACCES'
      || code === 'EPERM'
      || code === 'EHOSTUNREACH'
      || code === 'ENETUNREACH'
      || code === 'ENOTFOUND'
      || code === 'EDESTINATION'
    ) {
      return {
        external_result: requestsSent > 0 ? 'blocked' : 'error',
        metadata: withProfileKind(job, {
          probe_kind: 'udp_probe',
          error_class: code,
          duration_ms: durationMs,
          target_port: endpoint.port,
        }),
        requests_sent: requestsSent,
        duration_ms: durationMs,
      };
    }
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'udp_probe',
        error_class: code || 'udp_send_failed',
        duration_ms: durationMs,
        target_port: endpoint.port,
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  }
}

export function parseHttp3AltSvc(headerValue) {
  if (typeof headerValue !== 'string' || headerValue.trim() === '') {
    return {
      alt_svc_present: false,
      http3_advertised: false,
      advertised_h3_port: null,
      alt_svc_h3_valid: false,
    };
  }
  for (const entry of headerValue.split(',')) {
    const match = entry.match(/^\s*h3\s*=\s*"([^"]+)"(?:\s*;|\s*$)/i);
    if (!match) continue;
    const portMatch = match[1].match(/:(\d{1,5})$/);
    const port = portMatch ? Number(portMatch[1]) : null;
    if (!Number.isInteger(port) || port < 1 || port > 65535) continue;
    return {
      alt_svc_present: true,
      http3_advertised: true,
      advertised_h3_port: port,
      alt_svc_h3_valid: true,
    };
  }
  return {
    alt_svc_present: true,
    http3_advertised: false,
    advertised_h3_port: null,
    alt_svc_h3_valid: false,
  };
}

function resolveHttpUrl(job) {
  const value = String(job.target?.value ?? '');
  if (!value) return null;
  if (/^https?:\/\//i.test(value)) return value;
  if (job.target?.kind === 'url') return value;
  return `https://${value.replace(/^\/+/, '')}/`;
}

const TLS_BLOCKED_CODES = new Set(['ECONNREFUSED', 'EHOSTUNREACH', 'ENOTFOUND', 'ENETUNREACH']);

function classifyNetworkProbeError(err, durationMs, job, probeKind, requestsSent = 1) {
  const code = err?.code ?? '';
  if (code === 'ETIMEOUT') {
    return {
      external_result: requestsSent > 0 ? 'timeout' : 'error',
      metadata: withProfileKind(job, {
        probe_kind: probeKind,
        error_class: 'timeout',
        duration_ms: durationMs,
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  }
  if (TLS_BLOCKED_CODES.has(code) || code === 'EDESTINATION') {
    return {
      external_result: requestsSent > 0 ? 'blocked' : 'error',
      metadata: withProfileKind(job, {
        probe_kind: probeKind,
        error_class: code,
        duration_ms: durationMs,
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  }
  return {
    external_result: 'error',
    metadata: withProfileKind(job, {
      probe_kind: probeKind,
      error_class: code || 'probe_failed',
      duration_ms: durationMs,
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

/**
 * @param {typeof tls.connect} connectFn
 * @param {{ host: string, port: number }} endpoint
 * @param {number} timeoutMs
 */
function openTlsSession(connectFn, endpoint, timeoutMs, deps, onReserved) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = startProbeIoAttempt(
      deps,
      'tls_connect',
      () => connectFn({
        host: endpoint.host,
        port: endpoint.port,
        ...(net.isIP(endpoint.servername ?? endpoint.host) === 0
          ? { servername: endpoint.servername ?? endpoint.host }
          : {}),
        rejectUnauthorized: false,
      }),
      onReserved,
    );

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' }));
    }, timeoutMs);

    const settle = (err, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) {
        socket.destroy();
        reject(err);
        return;
      }
      socket.end();
      resolve(result);
    };

    socket.once('secureConnect', () => {
      settle(null, {
        tls_protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name ?? null,
        authorized: socket.authorized,
      });
    });
    socket.once('error', (err) => settle(err));
  });
}

/**
 * @param {typeof http2.connect} connectFn
 * @param {string} url
 * @param {number} timeoutMs
 */
function readHttp2RemoteSettings(connectFn, tlsConnectFn, url, timeoutMs, connectHost, deps, onReserved) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const parsed = new URL(url);
    const logicalHost = parsed.hostname.replace(/^\[/, '').replace(/\]$/, '');
    const session = startProbeIoAttempt(
      deps,
      'http2_settings',
      () => connectFn(parsed.origin, {
        createConnection: () => tlsConnectFn({
          host: connectHost,
          port: parsed.port ? Number(parsed.port) : 443,
          ...(net.isIP(logicalHost) === 0 ? { servername: logicalHost } : {}),
          rejectUnauthorized: false,
        }),
      }),
      onReserved,
    );

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      session.close();
      session.destroy();
      reject(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' }));
    }, timeoutMs);

    const settle = (err, settings) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      session.close();
      if (err) {
        session.destroy();
        reject(err);
        return;
      }
      resolve(settings);
    };

    const captureSettings = (settings) => {
      settle(null, {
        max_concurrent_streams: settings.maxConcurrentStreams ?? null,
        enable_push: settings.enablePush ?? null,
      });
    };

    session.once('remoteSettings', captureSettings);
    session.once('connect', () => {
      if (settled) return;
      const remote = session.remoteSettings;
      if (remote && Object.keys(remote).length > 0) captureSettings(remote);
    });
    session.once('error', (err) => settle(err));
  });
}

/**
 * @param {Record<string, unknown>} job
 * @param {{ connectFn?: typeof tls.connect }} deps
 */
export async function probeTlsSession(job, deps = {}) {
  const connectFn = deps.connectFn ?? tls.connect;
  const host = resolveHostForJob(job);
  if (!host) {
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'tls_session',
        error_class: 'unsupported_target',
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  const port = resolvePortForJob(job);
  const timeoutMs = job.constraints?.timeout_ms ?? 5000;
  const started = Date.now();
  let requestsSent = 0;

  try {
    const pinned = await resolvePinnedDestination(host, deps);
    const sessionInfo = await openTlsSession(connectFn, {
      host: pinned.address,
      ...(net.isIP(host) === 0 ? { servername: host } : {}),
      port,
    }, timeoutMs, deps, () => { requestsSent = 1; });
    const durationMs = Date.now() - started;
    return {
      external_result: 'connected',
      metadata: withProfileKind(job, {
        probe_kind: 'tls_session',
        tls_protocol: sessionInfo.tls_protocol,
        cipher: sessionInfo.cipher,
        authorized: sessionInfo.authorized,
        duration_ms: durationMs,
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  } catch (err) {
    return classifyNetworkProbeError(
      err,
      Date.now() - started,
      job,
      'tls_session',
      requestsSent,
    );
  }
}

/**
 * @param {Record<string, unknown>} job
 * @param {{ connectFn?: typeof http2.connect }} deps
 */
export async function probeHttp2Settings(job, deps = {}) {
  const connectFn = deps.connectFn ?? http2.connect;
  const tlsConnectFn = deps.tlsConnectFn ?? tls.connect;
  const httpUrl = resolveHttpUrl(job);
  const host = resolveHostForJob(job);
  if (!httpUrl || !host) {
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'http2_settings',
        error_class: 'unsupported_target',
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  const timeoutMs = job.constraints?.timeout_ms ?? 5000;
  const started = Date.now();
  let requestsSent = 0;

  try {
    const pinned = await resolvePinnedDestination(host, deps);
    const settings = await readHttp2RemoteSettings(
      connectFn,
      tlsConnectFn,
      httpUrl,
      timeoutMs,
      pinned.address,
      deps,
      () => { requestsSent = 1; },
    );
    const durationMs = Date.now() - started;
    return {
      external_result: 'connected',
      metadata: withProfileKind(job, {
        probe_kind: 'http2_settings',
        max_concurrent_streams: settings.max_concurrent_streams,
        enable_push: settings.enable_push,
        duration_ms: durationMs,
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  } catch (err) {
    return classifyNetworkProbeError(
      err,
      Date.now() - started,
      job,
      'http2_settings',
      requestsSent,
    );
  }
}

/**
 * Legacy compatibility kind: one HEAD observes a modern h3 Alt-Svc advertisement only.
 * It performs no UDP, QUIC handshake, control-stream, or SETTINGS validation.
 * @param {Record<string, unknown>} job
 * @param {{ fetchFn?: typeof fetch }} deps
 */
export async function probeQuicReachability(job, deps = {}) {
  const host = resolveHostForJob(job);
  const httpUrl = resolveHttpUrl(job);
  if (!host || !httpUrl) {
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'quic_reachability',
        error_class: 'unsupported_target',
        capability_scope: 'http3_alt_svc_observation_only',
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  const signedBudget = Number(job.constraints?.max_requests ?? job.probe_profile?.max_requests ?? 1);
  if (!Number.isSafeInteger(signedBudget) || signedBudget < 1) {
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'quic_reachability',
        error_class: 'zero_request_cap',
        capability_scope: 'http3_alt_svc_observation_only',
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  const timeoutMs = job.constraints?.timeout_ms ?? 5000;
  const started = Date.now();
  let requestsSent = 0;
  let altSvc = parseHttp3AltSvc(null);
  try {
    const pinned = await resolvePinnedDestination(host, deps);
    const pinnedDeps = {
      ...deps,
      vettedHost: pinned.host,
      vettedAddresses: pinned.addresses,
    };
    const fetchFn = deps.fetchFn ?? ((input, init) => pinnedFetch(input, init, pinnedDeps));
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await startProbeIoAttempt(
        deps,
        'http',
        () => fetchFn(httpUrl, {
          method: 'HEAD',
          redirect: 'manual',
          signal: controller.signal,
        }),
        () => { requestsSent = 1; },
      );
      altSvc = parseHttp3AltSvc(res.headers.get('alt-svc'));
      const durationMs = Date.now() - started;
      return {
        external_result: 'connected',
        metadata: withProfileKind(job, {
          probe_kind: 'quic_reachability',
          capability_scope: 'http3_alt_svc_observation_only',
          http_method: 'HEAD',
          status_code: res.status,
          ...altSvc,
          duration_ms: durationMs,
        }),
        requests_sent: requestsSent,
        duration_ms: durationMs,
      };
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    const durationMs = Date.now() - started;
    const normalized = err?.name === 'AbortError'
      ? Object.assign(new Error('timeout'), { code: 'ETIMEOUT' })
      : err;
    const outcome = classifyNetworkProbeError(
      normalized,
      durationMs,
      job,
      'quic_reachability',
      requestsSent,
    );
    return {
      ...outcome,
      metadata: {
        ...outcome.metadata,
        capability_scope: 'http3_alt_svc_observation_only',
        http_method: 'HEAD',
        ...altSvc,
      },
    };
  }
}

/**
 * @param {Record<string, unknown>} job
 */
export function resolveAlertWebhookUrl(job) {
  const meta = job.target?.metadata ?? {};
  const fromMeta = meta.alert_webhook_url ?? meta.webhook_url;
  if (typeof fromMeta === 'string' && fromMeta.trim()) return fromMeta.trim();
  return null;
}

/**
 * @param {Record<string, unknown>} job
 * @param {{
 *   fetchFn?: typeof fetch,
 *   resolve4Fn?: Function,
 *   resolve6Fn?: Function,
 *   destinationPolicy?: { allowPrivate?: boolean, allowLoopback?: boolean },
 * }} deps
 */
export async function probeAlertWebhookPing(job, deps = {}) {
  const webhookUrl = resolveAlertWebhookUrl(job);
  if (!webhookUrl) {
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'alert_webhook_ping',
        error_class: 'missing_webhook_url',
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(webhookUrl);
  } catch {
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'alert_webhook_ping',
        error_class: 'invalid_webhook_url',
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  // Cleartext webhooks would leak the marker/nonce and are trivially redirectable.
  if (parsedUrl.protocol !== 'https:') {
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'alert_webhook_ping',
        error_class: 'webhook_scheme_not_allowed',
        webhook_host: parsedUrl.hostname,
        webhook_scheme: parsedUrl.protocol.replace(/:$/, ''),
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  const webhookHostname = parsedUrl.hostname.replace(/^\[/, '').replace(/\]$/, '');
  let pinned;
  try {
    pinned = await resolvePinnedDestination(webhookHostname, deps);
  } catch (error) {
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'alert_webhook_ping',
        error_class: 'webhook_host_not_routable',
        webhook_host: webhookHostname,
        blocked_address: error?.blockedAddress ?? null,
        reason: error?.code === 'ENOTFOUND' ? 'no_resolved_addresses' : error?.message,
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }
  const pinnedAddress = pinned.address;
  const pinnedDeps = {
    ...deps,
    vettedHost: pinned.host,
    vettedAddresses: pinned.addresses,
  };
  const fetchFn = deps.fetchFn ?? ((input, init) => pinnedFetch(input, init, pinnedDeps));

  const timeoutMs = job.constraints?.timeout_ms ?? 5000;
  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let requestsSent = 0;

  try {
    const marker = job.probe_profile?.marker ?? 'astranull-safe-marker';
    const body = {
      type: SAFE_ALERT_PAYLOAD_TYPE,
      marker,
      nonce_hash: job.nonce_hash ?? null,
      check_id: job.check_id ?? null,
      test_run_id: job.test_run_id ?? null,
    };
    const res = await startProbeIoAttempt(
      deps,
      'alert_webhook_post',
      () => fetchFn(parsedUrl.href, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-astranull-marker': String(marker),
          ...(job.nonce ? { 'x-astranull-nonce': String(job.nonce) } : {}),
        },
        body: JSON.stringify(body),
        redirect: 'manual',
        signal: controller.signal,
      }),
      () => { requestsSent = 1; },
    );
    const durationMs = Date.now() - started;

    // A 3xx is terminal. Following it would re-resolve an attacker-chosen host and
    // bypass the classification above, so record where it pointed and stop.
    if (res.status >= 300 && res.status < 400) {
      let redirectHost = null;
      const location = res.headers?.get?.('location') ?? null;
      if (location) {
        try {
          redirectHost = new URL(location, parsedUrl.href).hostname;
        } catch {
          redirectHost = null;
        }
      }
      return {
        external_result: 'blocked',
        metadata: withProfileKind(job, {
          probe_kind: 'alert_webhook_ping',
          error_class: 'redirect_declined',
          duration_ms: durationMs,
          webhook_host: webhookHostname,
          pinned_address: pinnedAddress,
          redirect_declined: true,
          redirect_host: redirectHost,
          response_status: res.status,
          alert_delivery_ok: false,
        }),
        requests_sent: requestsSent,
        duration_ms: durationMs,
      };
    }

    const ok = res.status >= 200 && res.status < 300;
    return {
      external_result: ok ? 'connected' : 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'alert_webhook_ping',
        duration_ms: durationMs,
        webhook_host: webhookHostname,
        pinned_address: pinnedAddress,
        response_status: res.status,
        alert_delivery_ok: ok,
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  } catch (err) {
    const durationMs = Date.now() - started;
    const code = err?.name === 'AbortError' ? 'ETIMEOUT' : (err?.code ?? 'probe_failed');
    const external = code === 'ETIMEOUT' ? 'timeout' : 'error';
    return {
      external_result: external,
      metadata: withProfileKind(job, {
        probe_kind: 'alert_webhook_ping',
        error_class: code,
        duration_ms: durationMs,
        webhook_host: webhookHostname,
        pinned_address: pinnedAddress,
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  } finally {
    clearTimeout(timer);
  }
}

const WEBSOCKET_UPGRADE_DENIED_STATUSES = new Set([401, 403, 405, 429]);

function safeWebsocketKey() {
  return randomBytes(16).toString('base64');
}

function classifyWebsocketUpgradeStatus(status) {
  if (status === 101) {
    return {
      external_result: 'connected',
      upgrade_accepted: true,
      upgrade_denied: false,
      upgrade_required: false,
    };
  }
  if (WEBSOCKET_UPGRADE_DENIED_STATUSES.has(status)) {
    return {
      external_result: 'blocked',
      upgrade_accepted: false,
      upgrade_denied: true,
      upgrade_required: false,
    };
  }
  if (status === 426) {
    return {
      external_result: 'blocked',
      upgrade_accepted: false,
      upgrade_denied: false,
      upgrade_required: true,
    };
  }
  return {
    external_result: 'error',
    upgrade_accepted: false,
    upgrade_denied: false,
    upgrade_required: false,
  };
}

/**
 * @param {Record<string, unknown>} job
 * @param {{ websocketUpgradeFn?: Function, fetchFn?: typeof fetch }} deps
 */
export async function probeWebsocketUpgradePosture(job, deps = {}) {
  const upgradeFn = deps.websocketUpgradeFn
    ?? deps.fetchFn
    ?? ((input, init) => pinnedWebSocketUpgrade(input, init, deps));
  const resolvedUrl = resolveHttpUrl(job);
  const httpUrl = resolvedUrl
    ?.replace(/^wss:/i, 'https:')
    .replace(/^ws:/i, 'http:');
  if (!httpUrl) {
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'websocket_upgrade_posture',
        error_class: 'unsupported_target',
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  const maxRequests = Math.min(1, job.constraints?.max_requests ?? 1);
  if (maxRequests < 1) {
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'websocket_upgrade_posture',
        error_class: 'zero_request_cap',
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  const timeoutMs = job.constraints?.timeout_ms ?? 5000;
  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let requestsSent = 0;

  const headers = {
    Connection: 'Upgrade',
    Upgrade: 'websocket',
    'Sec-WebSocket-Version': '13',
    'Sec-WebSocket-Key': safeWebsocketKey(),
  };
  const marker = job.probe_profile?.marker;
  if (marker) headers['x-astranull-marker'] = String(marker);
  if (job.nonce) headers['x-astranull-nonce'] = String(job.nonce);

  try {
    const res = await startProbeIoAttempt(
      deps,
      'websocket_upgrade',
      () => upgradeFn(httpUrl, {
        method: 'GET',
        headers,
        redirect: 'manual',
        signal: controller.signal,
        timeoutMs,
      }),
      () => { requestsSent = 1; },
    );
    const durationMs = Date.now() - started;
    const classification = classifyWebsocketUpgradeStatus(res.status);
    return {
      external_result: classification.external_result,
      metadata: withProfileKind(job, {
        probe_kind: 'websocket_upgrade_posture',
        status_code: res.status,
        upgrade_accepted: classification.upgrade_accepted,
        upgrade_denied: classification.upgrade_denied,
        upgrade_required: classification.upgrade_required,
        response_upgrade_header: res.headers.get('upgrade'),
        response_connection_header: res.headers.get('connection'),
        duration_ms: durationMs,
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  } catch (err) {
    const durationMs = Date.now() - started;
    const code = err?.name === 'AbortError' ? 'ETIMEOUT' : (err?.code ?? '');
    if (code === 'ETIMEOUT') {
      return {
        external_result: 'timeout',
        metadata: withProfileKind(job, {
          probe_kind: 'websocket_upgrade_posture',
          error_class: 'timeout',
          duration_ms: durationMs,
        }),
        requests_sent: requestsSent,
        duration_ms: durationMs,
      };
    }
    if (TLS_BLOCKED_CODES.has(code)) {
      return {
        external_result: 'blocked',
        metadata: withProfileKind(job, {
          probe_kind: 'websocket_upgrade_posture',
          error_class: code,
          duration_ms: durationMs,
        }),
        requests_sent: requestsSent,
        duration_ms: durationMs,
      };
    }
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'websocket_upgrade_posture',
        error_class: code || 'probe_failed',
        duration_ms: durationMs,
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  } finally {
    clearTimeout(timer);
  }
}
