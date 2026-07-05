/**
 * Bounded safe network probes — single datagram/request caps, no amplification or flooding.
 */

import dgram from 'node:dgram';
import dns from 'node:dns/promises';

const SAFE_UDP_PAYLOAD_PREFIX = 'ASTRANULL:udp:';
const SAFE_ALERT_PAYLOAD_TYPE = 'astranull_alert_workflow_ping';

/**
 * @param {{ target?: { value?: string, port?: number } }} job
 */
export function parseNetworkEndpoint(job) {
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

function resolveHostForJob(job) {
  const endpoint = parseNetworkEndpoint(job);
  if (endpoint?.host) return endpoint.host;
  const value = String(job.target?.value ?? '').trim();
  if (!value || /^https?:\/\//i.test(value)) return null;
  try {
    if (/^https?:\/\//i.test(value)) return new URL(value).hostname;
  } catch {
    /* ignore */
  }
  return value.replace(/^\/+/, '') || null;
}

function withProfileKind(job, metadata) {
  const profileKind = job.probe_profile?.kind ?? metadata.probe_kind ?? null;
  return { profile_kind: profileKind, ...metadata };
}

function safeUdpPayload(job) {
  const noncePart = String(job.nonce_hash ?? job.nonce ?? 'probe').slice(0, 16);
  return Buffer.from(`${SAFE_UDP_PAYLOAD_PREFIX}${noncePart}`, 'utf8');
}

/**
 * @param {import('node:dgram').Socket} socket
 * @param {Buffer} payload
 * @param {number} port
 * @param {string} host
 * @param {number} timeoutMs
 */
function sendUdpDatagram(socket, payload, port, host, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.close();
      reject(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' }));
    }, timeoutMs);

    socket.send(payload, port, host, (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.close();
      if (err) reject(err);
      else resolve();
    });
  });
}

/**
 * @param {Record<string, unknown>} job
 * @param {{ createSocket?: typeof dgram.createSocket, lookupFn?: typeof dns.lookup }} deps
 */
export async function probeUdpDatagram(job, deps = {}) {
  const createSocket = deps.createSocket ?? dgram.createSocket.bind(dgram);
  const lookupFn = deps.lookupFn ?? dns.lookup;
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
  try {
    await lookupFn(endpoint.host);
    const socket = createSocket('udp4');
    const payload = safeUdpPayload(job);
    await sendUdpDatagram(socket, payload, endpoint.port, endpoint.host, timeoutMs);
    const durationMs = Date.now() - started;
    return {
      external_result: 'connected',
      metadata: withProfileKind(job, {
        probe_kind: 'udp_probe',
        duration_ms: durationMs,
        target_port: endpoint.port,
        datagram_bytes: payload.length,
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
          probe_kind: 'udp_probe',
          error_class: 'timeout',
          duration_ms: durationMs,
          target_port: endpoint.port,
        }),
        requests_sent: 1,
        duration_ms: durationMs,
      };
    }
    if (
      code === 'EACCES'
      || code === 'EPERM'
      || code === 'EHOSTUNREACH'
      || code === 'ENETUNREACH'
      || code === 'ENOTFOUND'
    ) {
      return {
        external_result: 'blocked',
        metadata: withProfileKind(job, {
          probe_kind: 'udp_probe',
          error_class: code,
          duration_ms: durationMs,
          target_port: endpoint.port,
        }),
        requests_sent: 1,
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
      requests_sent: 1,
      duration_ms: durationMs,
    };
  }
}

function parseAltSvcHint(headerValue) {
  if (!headerValue || typeof headerValue !== 'string') {
    return { alt_svc_present: false, quic_port: null };
  }
  const match = headerValue.match(/quic="[^"]+":(\d+)/i);
  return {
    alt_svc_present: true,
    quic_port: match ? Number(match[1]) : 443,
  };
}

function resolveHttpUrl(job) {
  const value = String(job.target?.value ?? '');
  if (!value) return null;
  if (/^https?:\/\//i.test(value)) return value;
  if (job.target?.kind === 'url') return value;
  return `https://${value.replace(/^\/+/, '')}/`;
}

/**
 * @param {Record<string, unknown>} job
 * @param {{ fetchFn?: typeof fetch, createSocket?: typeof dgram.createSocket, lookupFn?: typeof dns.lookup }} deps
 */
export async function probeQuicReachability(job, deps = {}) {
  const fetchFn = deps.fetchFn ?? fetch;
  const createSocket = deps.createSocket ?? dgram.createSocket.bind(dgram);
  const lookupFn = deps.lookupFn ?? dns.lookup;
  const host = resolveHostForJob(job);
  const httpUrl = resolveHttpUrl(job);

  if (!host || !httpUrl) {
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'quic_reachability',
        error_class: 'unsupported_target',
      }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  const timeoutMs = job.constraints?.timeout_ms ?? 5000;
  const started = Date.now();
  let requestsSent = 0;
  let altSvc = { alt_svc_present: false, quic_port: null };

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      requestsSent += 1;
      const res = await fetchFn(httpUrl, {
        method: 'HEAD',
        redirect: 'manual',
        signal: controller.signal,
      });
      altSvc = parseAltSvcHint(res.headers.get('alt-svc'));
    } finally {
      clearTimeout(timer);
    }

    const quicPort = altSvc.quic_port ?? 443;
    await lookupFn(host);
    const socket = createSocket('udp4');
    const payload = safeUdpPayload(job);
    await sendUdpDatagram(socket, payload, quicPort, host, timeoutMs);
    requestsSent += 1;

    const durationMs = Date.now() - started;
    return {
      external_result: 'connected',
      metadata: withProfileKind(job, {
        probe_kind: 'quic_reachability',
        duration_ms: durationMs,
        alt_svc_present: altSvc.alt_svc_present,
        quic_port: quicPort,
        udp_datagram_bytes: payload.length,
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
          probe_kind: 'quic_reachability',
          error_class: 'timeout',
          duration_ms: durationMs,
          alt_svc_present: altSvc.alt_svc_present,
          quic_port: altSvc.quic_port,
        }),
        requests_sent: Math.max(requestsSent, 1),
        duration_ms: durationMs,
      };
    }
    if (code === 'ENOTFOUND' || code === 'ECONNREFUSED' || code === 'EHOSTUNREACH') {
      return {
        external_result: 'blocked',
        metadata: withProfileKind(job, {
          probe_kind: 'quic_reachability',
          error_class: code,
          duration_ms: durationMs,
          alt_svc_present: altSvc.alt_svc_present,
          quic_port: altSvc.quic_port,
        }),
        requests_sent: Math.max(requestsSent, 1),
        duration_ms: durationMs,
      };
    }
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'quic_reachability',
        error_class: code || 'quic_probe_failed',
        duration_ms: durationMs,
        alt_svc_present: altSvc.alt_svc_present,
        quic_port: altSvc.quic_port,
      }),
      requests_sent: Math.max(requestsSent, 1),
      duration_ms: durationMs,
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
 * @param {{ fetchFn?: typeof fetch }} deps
 */
export async function probeAlertWebhookPing(job, deps = {}) {
  const fetchFn = deps.fetchFn ?? fetch;
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
    if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
      throw new Error('invalid_protocol');
    }
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

  const timeoutMs = job.constraints?.timeout_ms ?? 5000;
  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const marker = job.probe_profile?.marker ?? 'astranull-safe-marker';
    const body = {
      type: SAFE_ALERT_PAYLOAD_TYPE,
      marker,
      nonce_hash: job.nonce_hash ?? null,
      check_id: job.check_id ?? null,
      test_run_id: job.test_run_id ?? null,
    };
    const res = await fetchFn(parsedUrl.href, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-astranull-marker': String(marker),
        ...(job.nonce ? { 'x-astranull-nonce': String(job.nonce) } : {}),
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const durationMs = Date.now() - started;
    const ok = res.status >= 200 && res.status < 300;
    return {
      external_result: ok ? 'connected' : 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'alert_webhook_ping',
        duration_ms: durationMs,
        webhook_host: parsedUrl.hostname,
        response_status: res.status,
        alert_delivery_ok: ok,
      }),
      requests_sent: 1,
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
        webhook_host: parsedUrl.hostname,
      }),
      requests_sent: 1,
      duration_ms: durationMs,
    };
  } finally {
    clearTimeout(timer);
  }
}