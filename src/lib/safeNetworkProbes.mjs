/**
 * Bounded safe network probes — single datagram/request caps, no amplification or flooding.
 */

import { randomBytes, createHash } from 'node:crypto';
import dgram from 'node:dgram';
import http2 from 'node:http2';
import net from 'node:net';
import tls from 'node:tls';
import { pinnedFetch, pinnedWebSocketUpgrade, resolvePinnedDestination } from './pinnedHttpRequest.mjs';
import { startProbeIoAttempt } from './probeAttempt.mjs';
import { payloadProfilesForJob, reflectorPayloadForProfile } from './reflectorPayloads.mjs';
import {
  addressFamilyNumber,
  classifyTcpErrno,
  classifyUdpErrno,
  declaredDenyPortPlan,
  declaredDenyPorts,
  familyParity,
  MAX_TCP_UDP_SAMPLES,
  noPortDeclaredResult,
  peerIsCdn,
  requestedAddressFamily,
  resolveDeclaredNetworkPort,
  SAMPLE_GAP_MS,
  sampleAgreement,
  selectFamilyAddresses,
  sleepMs,
  stampSourcePerspective,
  validNetworkPort,
} from './networkProbeOutcomes.mjs';

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

function withProfileKind(job, metadata, deps = {}) {
  const profileKind = job.probe_profile?.kind ?? metadata.probe_kind ?? null;
  return stampSourcePerspective({
    profile_kind: profileKind, ...metadata, classifier_version: 'protocol-identity-v3',
    observation_only: true, readiness_conclusion: false, evidence_tier: 'E2',
  }, deps);
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
function sendUdpDatagram(socket, payload, port, host, timeoutMs, { captureResponse = false, signal } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer;

    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener?.('message', onMessage);
      socket.removeListener?.('error', onError);
      signal?.removeEventListener('abort', onAbort);
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
        ...(captureResponse ? { response_payload: Buffer.from(message).subarray(0, 65536), response_complete: responseBytes <= 65536 } : {}),
      });
    };
    const onError = (error) => settle(null, error);
    const onAbort = () => settle(null, Object.assign(new Error('probe canceled'), { code: 'ETIMEOUT' }));
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) { onAbort(); return; }

    socket.on('message', onMessage);
    socket.once('error', onError);
    timer = setTimeout(() => settle({
      response_received: false,
      response_bytes: 0,
      response_size_class: 'none',
    }), Math.max(1, Number(timeoutMs) || 5000));

    const onSendError = (error) => { if (error) settle(null, error); };
    const sendUnconnected = () => {
      try {
        socket.send(payload, port, host, onSendError);
      } catch (error) {
        settle(null, error);
      }
    };
    const sendConnected = () => {
      try {
        socket.send(payload, onSendError);
      } catch (error) {
        settle(null, error);
      }
    };

    // Native dgram: connect so ICMP port-unreachable surfaces (F19), then 1-arg send.
    // Delivery fixtures wrap send as (packet, port, host, cb); 1-arg send never reaches the peer.
    // Unit fakes implement their own connect. Wrapped native sockets keep 4-arg unconnected send.
    const nativeConnect = socket.connect === dgram.Socket.prototype.connect;
    const nativeSend = socket.send === dgram.Socket.prototype.send;
    const fakeConnect = typeof socket.connect === 'function' && !nativeConnect;
    if ((nativeConnect && nativeSend) || fakeConnect) {
      try {
        socket.connect(port, host, sendConnected);
      } catch (error) {
        settle(null, error);
      }
    } else {
      sendUnconnected();
    }
  });
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
    let socket;
    const onAbort = () => settle(null, Object.assign(new Error('probe canceled'), { code: 'ETIMEOUT' }));
    if (deps.jobDeadlineSignal?.aborted) { reject(Object.assign(new Error('probe canceled'), { code: 'ETIMEOUT' })); return; }
    const settle = (value, error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      deps.jobDeadlineSignal?.removeEventListener('abort', onAbort);
      try {
        socket.destroy();
      } catch {
        // The injected socket can fail synchronously before it is fully initialized.
      }
      if (error) reject(error);
      else resolve(value);
    };
    socket = startProbeIoAttempt(
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
    let responsePayload = Buffer.alloc(0);
    let responseTruncated = false;
    deps.jobDeadlineSignal?.addEventListener('abort', onAbort, { once: true });
    if (deps.jobDeadlineSignal?.aborted) { onAbort(); return; }
    socket.on('data', (chunk) => {
      const received = Buffer.concat([responsePayload, Buffer.from(chunk ?? [])]);
      responseTruncated ||= received.length > 65536;
      responsePayload = received.subarray(0, 65536);
      if (responsePayload.length < 4) return;
      const frameLength = (responsePayload.readUInt32BE(0) & 0x7fffffff) + 4;
      if (frameLength > 65536) { settle({ response_received: true, response_bytes: responsePayload.length, response_payload: responsePayload, response_complete: false }); return; }
      if (responsePayload.length >= frameLength) settle({ response_received: true, response_bytes: responsePayload.length, response_payload: responsePayload, response_complete: !responseTruncated && responsePayload.length === frameLength });
    });
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

function reflectionFailure(job, metadata, externalResult, requestsSent, started, deps = {}) {
  const durationMs = Date.now() - started;
  return {
    external_result: externalResult,
    metadata: stampSourcePerspective({
      probe_kind: 'reflection_service_probe',
      profile_kind: 'reflection_service_probe',
      ...metadata,
      classifier_version: 'protocol-identity-v3', observation_only: true, readiness_conclusion: false, evidence_tier: 'E2',
      duration_ms: durationMs,
    }, deps),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

/** Select only authoritative no-delivery branches; no resolver or transport is initialized. */
export async function networkProbeNoDeliveryOutcome(job, deps = {}) {
  const profile = job.probe_profile ?? {};
  if (profile.kind === 'reflection_service_probe') {
    const payload = reflectorPayloadForProfile(profile.payload_profile ?? 'generic_probe');
    if (!payload || payload.execution_supported === false) return probeReflectionService(job, deps);
  }
  if (profile.kind === 'alert_webhook_ping') {
    const approved = job.constraints?.alert_webhook_url;
    if (typeof approved !== 'string' || !approved || resolveAlertWebhookUrl(job) !== approved) {
      return probeAlertWebhookPing(job, deps);
    }
  }
  return null;
}

function classifyReflectionReply(payloadProfile, payload, response) {
  const classification = payloadProfile.classify(
    payload,
    response.response_complete === true ? response.response_payload ?? null : null,
    response.response_received,
  );
  if (!response.response_received) {
    return { ...classification, udp_outcome: 'silent', service_validated: false };
  }
  if (classification.protocol_identity_confirmed) {
    return { ...classification, udp_outcome: 'validated_reply', service_validated: true };
  }
  return { ...classification, udp_outcome: 'unvalidated_reply', service_validated: false, unvalidated_reply: true };
}

async function sendOneReflection(job, deps, payloadProfile, endpoint, pinned, timeoutMs, onAttempt) {
  const payload = payloadProfile.build({
    nonceHash: job.nonce_hash ?? job.nonce,
    queryName: job.target?.metadata?.query_name,
  });
  if (payloadProfile.transport === 'tcp') {
    const response = await sendTcpPayload(
      deps.connectFn ?? net.connect,
      payload,
      { host: pinned.address, port: endpoint.port },
      timeoutMs,
      deps,
      onAttempt,
    );
    return { payload, response, port: endpoint.port };
  }
  const createSocket = deps.createSocket ?? dgram.createSocket.bind(dgram);
  const socket = startProbeIoAttempt(
    deps,
    'reflection_udp',
    () => createSocket(net.isIP(pinned.address) === 6 ? 'udp6' : 'udp4'),
    onAttempt,
  );
  const response = await sendUdpDatagram(
    socket,
    payload,
    endpoint.port,
    pinned.address,
    timeoutMs,
    { captureResponse: true, signal: deps.jobDeadlineSignal },
  );
  return { payload, response, port: endpoint.port };
}

export async function probeReflectionService(job, deps = {}) {
  const profileNames = payloadProfilesForJob(job);
  const primaryName = profileNames[0] ?? job.probe_profile?.payload_profile ?? 'generic_probe';
  const primaryProfile = reflectorPayloadForProfile(primaryName);
  if (!primaryProfile || primaryProfile.execution_supported === false) {
    return reflectionFailure(job, { payload_profile: primaryName, delivery_supported: false, not_run_reason: 'unsupported_or_unapproved_protocol_request', reflector_confirmed: false }, 'not_run', 0, Date.now(), deps);
  }
  const endpoint = reflectionEndpoint(job, primaryProfile);
  const started = Date.now();
  if (!endpoint) {
    return reflectionFailure(job, {
      target_port: null,
      payload_profile: primaryProfile.id,
      request_bytes: 0,
      response_received: false,
      response_bytes: 0,
      response_size_class: 'none',
      amplification_ratio: null,
      reflector_confirmed: false,
      error_class: 'unsupported_target',
    }, 'error', 0, started, deps);
  }

  const timeoutMs = Math.max(1, Number(job.constraints?.timeout_ms) || 5000);
  const requested = requestBudget(job, 1);
  const isComposite = profileNames.length > 1;
  const hardCap = isComposite ? 4 : 2;
  const maxRequests = Math.min(hardCap, requested);
  const sendList = isComposite ? profileNames.slice(0, maxRequests) : [primaryName];
  const perProfileTimeout = isComposite
    ? Math.max(1, Math.floor(timeoutMs / sendList.length))
    : timeoutMs;
  let requestsSent = 0;
  const baseMetadata = {
    target_port: endpoint.port,
    payload_profile: primaryProfile.id,
    payload_profiles_declared: sendList,
  };

  try {
    const familyPref = requestedAddressFamily(job);
    const pinned = await resolvePinnedDestination(endpoint.host, { ...deps, addressFamily: familyPref === 'both' ? undefined : familyPref });
    const protocolResults = [];
    let last = null;
    for (const name of sendList) {
      const spec = reflectorPayloadForProfile(name);
      if (!spec || spec.execution_supported === false) continue;
      const remainingMs = timeoutMs - (Date.now() - started);
      if (remainingMs <= 0 || requestsSent >= maxRequests) break;
      const customerPort = validNetworkPort(job.target?.port)
        ?? validNetworkPort(parseNetworkEndpoint(job)?.port)
        ?? validNetworkPort(job.probe_profile?.service_port);
      const port = customerPort ?? validNetworkPort(spec.default_port) ?? endpoint.port;
      try {
        last = await sendOneReflection(
          job,
          deps,
          spec,
          { host: endpoint.host, port },
          pinned,
          Math.max(1, Math.min(perProfileTimeout, remainingMs)),
          () => { requestsSent += 1; },
        );
        const classified = classifyReflectionReply(spec, last.payload, last.response);
        protocolResults.push({
          payload_profile: spec.id,
          protocol: spec.transport,
          port,
          udp_outcome: classified.udp_outcome,
          service_validated: classified.service_validated,
          response_received: last.response.response_received === true,
          protocol_identity_confirmed: classified.protocol_identity_confirmed === true,
        });
        if (sendList.length === 1 && !last.response.response_received && requestsSent < maxRequests) {
          const retryRemaining = timeoutMs - (Date.now() - started);
          if (retryRemaining > 0) {
            last = await sendOneReflection(job, deps, spec, { host: endpoint.host, port }, pinned, retryRemaining, () => { requestsSent += 1; });
            const retried = classifyReflectionReply(spec, last.payload, last.response);
            protocolResults[0] = {
              payload_profile: spec.id,
              protocol: spec.transport,
              port,
              udp_outcome: retried.udp_outcome,
              service_validated: retried.service_validated,
              response_received: last.response.response_received === true,
              protocol_identity_confirmed: retried.protocol_identity_confirmed === true,
            };
          }
        }
      } catch (error) {
        const classified = classifyUdpErrno(error?.code ?? '');
        protocolResults.push({
          payload_profile: spec.id,
          protocol: spec.transport,
          port,
          udp_outcome: classified.udp_outcome,
          icmp: classified.icmp,
          service_validated: false,
          response_received: false,
          error_class: error?.code ?? 'reflection_probe_failed',
        });
        last = { payload: spec.build({ nonceHash: job.nonce_hash ?? job.nonce }), response: { response_received: false, response_bytes: 0 }, error };
      }
    }

    const primaryResult = protocolResults[0] ?? null;
    const lastResponse = last?.response ?? { response_received: false, response_bytes: 0 };
    const lastPayload = last?.payload ?? Buffer.alloc(0);
    const lastSpec = reflectorPayloadForProfile(primaryResult?.payload_profile ?? primaryName) ?? primaryProfile;
    const classification = last?.error
      ? { amplification_ratio: null, response_size_class: 'none', protocol_identity_confirmed: false, reflector_confirmed: false }
      : classifyReflectionReply(lastSpec, lastPayload, lastResponse);
    const anyValidated = protocolResults.some((row) => row.service_validated);
    const anyReply = protocolResults.some((row) => row.response_received);
    const icmp = primaryResult?.icmp ?? (last?.error ? classifyUdpErrno(last.error.code).icmp : null);
    const udpOutcome = anyValidated
      ? 'validated_reply'
      : anyReply
        ? 'unvalidated_reply'
        : (primaryResult?.udp_outcome ?? classification.udp_outcome ?? 'silent');
    const externalResult = anyValidated
      ? 'connected'
      : anyReply
        ? 'not_run'
        : udpOutcome === 'rejected_icmp'
          ? 'blocked'
          : udpOutcome === 'port_unreachable' || udpOutcome === 'silent'
            ? 'timeout'
            : last?.error && requestsSent === 0
              ? 'error'
              : 'timeout';
    return reflectionFailure(job, {
      ...baseMetadata,
      request_bytes: lastPayload.length,
      response_received: anyReply,
      response_bytes: lastResponse.response_bytes ?? 0,
      ...classification,
      udp_outcome: udpOutcome,
      service_validated: anyValidated,
      protocol_identity_confirmed: anyValidated,
      reflector_confirmed: anyValidated,
      icmp,
      peer_is_cdn: peerIsCdn(pinned.address),
      address: pinned.address,
      address_family: addressFamilyNumber(pinned.address),
      protocol: lastSpec.transport,
      port: endpoint.port,
      protocol_results: protocolResults,
      payload_profiles_sent: protocolResults.map((row) => row.payload_profile),
      response_complete: lastResponse.response_complete === true,
      identity_supported: lastSpec.identity_supported === true || anyValidated,
      response_body_retained: false,
      ...(externalResult === 'timeout' ? { error_class: 'no_reflection_response' } : {}),
    }, externalResult, requestsSent, started, deps);
  } catch (error) {
    const code = error?.code ?? '';
    const classified = classifyUdpErrno(code);
    const externalResult = requestsSent === 0
      ? 'error'
      : (code === 'ETIMEOUT' ? 'timeout' : classified.udp_outcome === 'rejected_icmp' ? 'blocked' : classified.udp_outcome === 'port_unreachable' ? 'timeout' : 'error');
    return reflectionFailure(job, {
      ...baseMetadata,
      request_bytes: 0,
      response_received: false,
      response_bytes: 0,
      response_size_class: 'none',
      amplification_ratio: null,
      reflector_confirmed: false,
      udp_outcome: classified.udp_outcome,
      icmp: classified.icmp,
      service_validated: false,
      error_class: code || 'reflection_probe_failed',
    }, externalResult, requestsSent, started, deps);
  }
}

function requestBudget(job, fallback = 1) {
  const n = Number(job.constraints?.max_requests ?? job.probe_profile?.max_requests ?? fallback);
  return Number.isSafeInteger(n) && n > 0 ? n : fallback;
}

function udpExternalResult(outcome) {
  if (outcome === 'validated_reply' || outcome === 'unvalidated_reply') return 'connected';
  if (outcome === 'rejected_icmp') return 'blocked';
  if (outcome === 'port_unreachable' || outcome === 'silent') return 'timeout';
  return 'error';
}

function tcpExternalResult(outcome) {
  if (outcome === 'handshake') return 'connected';
  if (outcome === 'refused_rst' || outcome === 'rejected_icmp') return 'blocked';
  if (outcome === 'timeout') return 'timeout';
  return 'error';
}

async function sendOneUdp(job, deps, address, port, timeoutMs, onAttempt) {
  const createSocket = deps.createSocket ?? dgram.createSocket.bind(dgram);
  const payload = safeUdpPayload(job);
  // The first address classification can initialize a large local index. Keep
  // that work inside the pre-I/O budget, not after a deadline has closed the socket.
  const peerCdn = peerIsCdn(address);
  const socket = startProbeIoAttempt(
    deps,
    'udp_datagram',
    () => createSocket(net.isIP(address) === 6 ? 'udp6' : 'udp4'),
    onAttempt,
  );
  const attemptStarted = Date.now();
  try {
    const response = await sendUdpDatagram(socket, payload, port, address, timeoutMs, {
      signal: deps.jobDeadlineSignal,
    });
    const durationMs = Math.max(0, Date.now() - attemptStarted);
    const udp_outcome = response.response_received ? 'unvalidated_reply' : 'silent';
    return {
      udp_outcome,
      icmp: null,
      service_validated: false,
      response_received: response.response_received === true,
      response_bytes: response.response_bytes ?? 0,
      response_size_class: response.response_size_class,
      datagram_bytes: payload.length,
      address,
      address_family: addressFamilyNumber(address),
      peer_is_cdn: peerCdn,
      duration_ms: durationMs,
      elapsed_ms: durationMs,
    };
  } catch (err) {
    const durationMs = Math.max(0, Date.now() - attemptStarted);
    const classified = classifyUdpErrno(err?.code ?? '');
    return {
      ...classified,
      service_validated: false,
      response_received: false,
      response_bytes: 0,
      response_size_class: 'none',
      datagram_bytes: payload.length,
      address,
      address_family: addressFamilyNumber(address),
      peer_is_cdn: peerCdn,
      duration_ms: durationMs,
      elapsed_ms: durationMs,
      error_class: err?.code || 'udp_send_failed',
    };
  }
}

async function probeDeclaredDenyPorts(job, deps, { protocol, ports, selected, familyKeys, pinned, budget, timeoutMs, started, sampleOnce, onRequest }) {
  let requestsSent = 0;
  const onReserved = () => { requestsSent += 1; onRequest?.(); };
  const outcomeKey = protocol === 'udp' ? 'udp_outcome' : 'tcp_outcome';
  const portResults = [];
  const plannedTotalAttempts = Math.max(1, Math.min(budget, ports.length * familyKeys.length * MAX_TCP_UDP_SAMPLES));
  const perAttemptTimeout = Math.max(1, Math.floor(timeoutMs / plannedTotalAttempts));
  for (let index = 0; index < ports.length; index += 1) {
    if (requestsSent >= budget || deps.jobDeadlineSignal?.aborted) break;
    const timeLeft = timeoutMs - (Date.now() - started);
    if (timeLeft <= 0) break;
    const port = ports[index];
    const portBudget = Math.max(1, Math.floor((budget - requestsSent) / (ports.length - index)));
    const portDeadline = Date.now() + Math.max(1, Math.floor(timeLeft / (ports.length - index)));
    const samplesPerFamily = familyKeys.length === 1 && portBudget >= MAX_TCP_UDP_SAMPLES ? MAX_TCP_UDP_SAMPLES : 1;
    const plannedSamples = Math.min(portBudget, samplesPerFamily * familyKeys.length);
    let portRequests = 0;
    const families = {};
    const portSamples = [];
    for (const key of familyKeys) {
      const samples = [];
      for (let i = 0; i < samplesPerFamily && portRequests < portBudget && requestsSent < budget; i += 1) {
        if (i > 0) {
          const gap = deps.sampleGapMs ?? SAMPLE_GAP_MS;
          if (gap > 0) await sleepMs(gap, deps.jobDeadlineSignal);
        }
        const overallTimeLeft = timeoutMs - (Date.now() - started);
        const portTimeLeft = portDeadline - Date.now();
        if (overallTimeLeft <= 0 || portTimeLeft <= 0) break;
        const samplesLeft = Math.max(1, plannedSamples - portRequests);
        const portSlice = Math.max(1, Math.floor(portTimeLeft / samplesLeft));
        const remaining = Math.min(perAttemptTimeout, portSlice, overallTimeLeft);
        if (remaining <= 0) break;
        const before = requestsSent;
        const sample = await sampleOnce(selected[key], port, remaining, onReserved);
        portRequests += requestsSent - before;
        samples.push(sample);
        portSamples.push(sample);
      }
      if (samples.length) families[key] = { ...samples[0], samples, sample_agreement: sampleAgreement(samples) };
    }
    if (!portSamples.length) break;
    const violating = protocol === 'udp' ? 'validated_reply' : 'handshake';
    const first = portSamples.find((sample) => sample[outcomeKey] === violating) ?? portSamples[0];
    portResults.push({
      protocol,
      port,
      address: first.address,
      address_family: first.address_family,
      [outcomeKey]: first[outcomeKey],
      icmp: first.icmp ?? null,
      service_validated: first.service_validated === true,
      peer_is_cdn: first.peer_is_cdn ?? null,
      families,
      parity: familyParity(families),
      samples: portSamples,
      sample_agreement: sampleAgreement(portSamples),
    });
  }
  const violating = protocol === 'udp' ? 'validated_reply' : 'handshake';
  const primary = portResults.find((row) => row[outcomeKey] === violating) ?? portResults[0] ?? {};
  const probed = portResults.map((row) => row.port);
  const declared = declaredDenyPorts(job, { protocol });
  const durationMs = Date.now() - started;
  const outcome = primary[outcomeKey] ?? 'error';
  return {
    external_result: protocol === 'udp' ? udpExternalResult(outcome) : tcpExternalResult(outcome),
    metadata: withProfileKind(job, {
      probe_kind: protocol === 'udp' ? 'udp_probe' : 'tcp_connect',
      protocol,
      port: primary.port ?? ports[0],
      address: primary.address ?? pinned.address,
      address_family: primary.address_family ?? addressFamilyNumber(pinned.address),
      [outcomeKey]: outcome,
      icmp: primary.icmp ?? null,
      service_validated: primary.service_validated === true,
      peer_is_cdn: primary.peer_is_cdn ?? peerIsCdn(pinned.address),
      families: primary.families ?? {},
      parity: primary.parity ?? 'single_family',
      samples: primary.samples ?? [],
      sample_agreement: primary.sample_agreement ?? 'single',
      port_results: portResults,
      declared_deny_ports: declared,
      ports_probed: probed,
      unprobed_deny_ports: declared.filter((port) => !probed.includes(port)),
      duration_ms: durationMs,
      target_port: primary.port ?? ports[0],
      observation_complete: requestsSent >= 1,
      pinned_address: primary.address ?? pinned.address,
      ...(outcome !== violating && primary.error_class ? { error_class: primary.error_class } : {}),
    }, deps),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

/**
 * @param {Record<string, unknown>} job
 * @param {{ createSocket?: typeof dgram.createSocket }} deps
 */
export async function probeUdpDatagram(job, deps = {}) {
  const host = resolveHostForJob(job);
  const port = resolveDeclaredNetworkPort(job, { protocol: 'udp' })
    ?? parseNetworkEndpoint(job)?.port
    ?? null;
  if (!host || !port) {
    return {
      ...noPortDeclaredResult('udp_probe'),
      metadata: withProfileKind(job, {
        probe_kind: 'udp_probe',
        error_class: 'unsupported_target',
        reason: 'no_port_declared',
      }, deps),
    };
  }

  const timeoutMs = job.constraints?.timeout_ms ?? 5000;
  const started = Date.now();
  const budget = requestBudget(job);
  let requestsSent = 0;
  try {
    const familyPref = requestedAddressFamily(job);
    const pinned = await resolvePinnedDestination(host, {
      ...deps,
      addressFamily: familyPref === 'both' ? undefined : familyPref,
    });
    const selected = selectFamilyAddresses(pinned, familyPref);
    const familyKeys = Object.entries(selected).filter(([, address]) => address).map(([key]) => key);
    if (familyKeys.length === 0) {
      return {
        external_result: 'error',
        metadata: withProfileKind(job, {
          probe_kind: 'udp_probe',
          error_class: 'unsupported_target',
          reason: 'no_port_declared',
          target_port: port,
        }, deps),
        requests_sent: 0,
        duration_ms: Date.now() - started,
      };
    }
    const denyPorts = declaredDenyPortPlan(job, { protocol: 'udp', budget });
    if (denyPorts) {
      return await probeDeclaredDenyPorts(job, deps, {
        protocol: 'udp', ports: denyPorts, selected, familyKeys, pinned, budget, timeoutMs, started, onRequest: () => { requestsSent += 1; },
        sampleOnce: (address, samplePort, remaining, onReserved) => sendOneUdp(job, deps, address, samplePort, remaining, onReserved),
      });
    }
    const samplesPerFamily = familyKeys.length === 1 && budget >= MAX_TCP_UDP_SAMPLES
      ? MAX_TCP_UDP_SAMPLES
      : 1;
    const plannedAttempts = Math.max(1, Math.min(budget, familyKeys.length * samplesPerFamily));
    const perAttemptTimeout = Math.max(1, Math.floor(timeoutMs / plannedAttempts));
    const families = {};
    const allSamples = [];
    for (const key of familyKeys) {
      if (requestsSent >= budget) break;
      const address = selected[key];
      const samples = [];
      for (let i = 0; i < samplesPerFamily && requestsSent < budget; i += 1) {
        if (i > 0) {
          const gap = deps.sampleGapMs ?? SAMPLE_GAP_MS;
          if (gap > 0) await sleepMs(gap, deps.jobDeadlineSignal);
        }
        const timeLeft = timeoutMs - (Date.now() - started);
        if (timeLeft <= 0) break;
        const remaining = Math.min(perAttemptTimeout, timeLeft);
        if (remaining <= 0) break;
        const sample = await sendOneUdp(job, deps, address, port, remaining, () => { requestsSent += 1; });
        samples.push(sample);
        allSamples.push(sample);
      }
      if (samples.length) {
        families[key] = {
          ...samples[0],
          samples,
          sample_agreement: sampleAgreement(samples),
        };
      }
    }
    const primary = allSamples.find((sample) => sample.udp_outcome === 'validated_reply') ?? allSamples[0] ?? {};
    const durationMs = Date.now() - started;
    const udp_outcome = primary.udp_outcome ?? 'error';
    return {
      external_result: udpExternalResult(udp_outcome),
      metadata: withProfileKind(job, {
        probe_kind: 'udp_probe',
        protocol: 'udp',
        port,
        address: primary.address ?? pinned.address,
        address_family: primary.address_family ?? addressFamilyNumber(pinned.address),
        udp_outcome,
        icmp: primary.icmp ?? null,
        service_validated: primary.service_validated === true,
        peer_is_cdn: primary.peer_is_cdn ?? peerIsCdn(pinned.address),
        families,
        parity: familyParity(families),
        samples: allSamples,
        sample_agreement: sampleAgreement(allSamples),
        ...(!primary.response_received && udp_outcome === 'silent' ? { error_class: 'no_udp_response' } : {}),
        ...(primary.error_class && udp_outcome === 'error' ? { error_class: primary.error_class } : {}),
        duration_ms: durationMs,
        target_port: port,
        datagram_bytes: primary.datagram_bytes,
        observation_complete: requestsSent >= 1,
        pinned_address: primary.address ?? pinned.address,
        response_received: primary.response_received === true,
        response_bytes: primary.response_bytes ?? 0,
        response_size_class: primary.response_size_class ?? 'none',
      }, deps),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  } catch (err) {
    const durationMs = Date.now() - started;
    const code = err?.code ?? '';
    const classified = classifyUdpErrno(code);
    const external = code === 'ETIMEOUT'
      ? (requestsSent > 0 ? 'timeout' : 'error')
      : udpExternalResult(classified.udp_outcome);
    return {
      external_result: external,
      metadata: withProfileKind(job, {
        probe_kind: 'udp_probe',
        protocol: 'udp',
        port,
        udp_outcome: classified.udp_outcome,
        icmp: classified.icmp,
        service_validated: false,
        error_class: code === 'ETIMEOUT' ? 'timeout' : (code || 'udp_send_failed'),
        duration_ms: durationMs,
        target_port: port,
        observation_complete: requestsSent === 1,
      }, deps),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  }
}

function openTcpOnce(connectFn, address, port, timeoutMs, deps, onReserved) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = startProbeIoAttempt(
      deps,
      'tcp_connect',
      () => connectFn({ host: address, port }),
      onReserved,
    );
    const attemptStarted = Date.now();
    const finish = (result) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch { /* already closed */ }
      const durationMs = result.duration_ms ?? Math.max(0, Date.now() - attemptStarted);
      const elapsedMs = result.elapsed_ms ?? durationMs;
      resolve({ ...result, duration_ms: durationMs, elapsed_ms: elapsedMs });
    };
    const timer = setTimeout(() => finish({
      tcp_outcome: 'timeout',
      icmp: null,
      error_class: 'timeout',
    }), Math.max(1, timeoutMs));
    socket.once?.('connect', () => {
      clearTimeout(timer);
      finish({ tcp_outcome: 'handshake', icmp: null });
    });
    socket.setTimeout?.(Math.max(1, timeoutMs), () => {
      clearTimeout(timer);
      finish({ tcp_outcome: 'timeout', icmp: null, error_class: 'timeout' });
    });
    socket.on?.('timeout', () => {
      clearTimeout(timer);
      finish({ tcp_outcome: 'timeout', icmp: null, error_class: 'timeout' });
    });
    socket.on?.('error', (err) => {
      clearTimeout(timer);
      const elapsedMs = Math.max(0, Date.now() - attemptStarted);
      const classified = classifyTcpErrno(err?.code ?? '');
      finish({ ...classified, duration_ms: elapsedMs, elapsed_ms: elapsedMs, error_class: err?.code || 'connect_failed' });
    });
  });
}

export async function probeTcpConnect(job, deps = {}) {
  const host = resolveHostForJob(job);
  const port = resolveDeclaredNetworkPort(job, { protocol: 'tcp' })
    ?? parseNetworkEndpoint(job)?.port
    ?? null;
  if (!host || !port) {
    return {
      ...noPortDeclaredResult('tcp_connect'),
      metadata: withProfileKind(job, {
        probe_kind: 'tcp_connect',
        error_class: 'unsupported_target',
        reason: 'no_port_declared',
      }, deps),
    };
  }

  const timeoutMs = job.constraints?.timeout_ms ?? 5000;
  const started = Date.now();
  const budget = requestBudget(job);
  const connectFn = deps.connectFn ?? net.connect;
  let requestsSent = 0;
  try {
    const familyPref = requestedAddressFamily(job);
    const pinned = await resolvePinnedDestination(host, {
      ...deps,
      addressFamily: familyPref === 'both' ? undefined : familyPref,
    });
    const selected = selectFamilyAddresses(pinned, familyPref);
    const familyKeys = Object.entries(selected).filter(([, address]) => address).map(([key]) => key);
    if (familyKeys.length === 0) {
      return {
        external_result: 'error',
        metadata: withProfileKind(job, {
          probe_kind: 'tcp_connect',
          error_class: 'destination_unresolved',
          target_port: port,
        }, deps),
        requests_sent: 0,
        duration_ms: Date.now() - started,
      };
    }
    const denyPorts = declaredDenyPortPlan(job, { protocol: 'tcp', budget });
    if (denyPorts) {
      return await probeDeclaredDenyPorts(job, deps, {
        protocol: 'tcp', ports: denyPorts, selected, familyKeys, pinned, budget, timeoutMs, started, onRequest: () => { requestsSent += 1; },
        sampleOnce: async (address, samplePort, remaining, onReserved) => {
          const sample = await openTcpOnce(connectFn, address, samplePort, remaining, deps, onReserved);
          return {
            ...sample,
            protocol: 'tcp',
            port: samplePort,
            address,
            address_family: addressFamilyNumber(address),
            peer_is_cdn: peerIsCdn(address),
            service_validated: sample.tcp_outcome === 'handshake',
          };
        },
      });
    }
    const samplesPerFamily = familyKeys.length === 1 && budget >= MAX_TCP_UDP_SAMPLES
      ? MAX_TCP_UDP_SAMPLES
      : 1;
    const plannedAttempts = Math.max(1, Math.min(budget, familyKeys.length * samplesPerFamily));
    const perAttemptTimeout = Math.max(1, Math.floor(timeoutMs / plannedAttempts));
    const families = {};
    const allSamples = [];
    for (const key of familyKeys) {
      if (requestsSent >= budget) break;
      const address = selected[key];
      const samples = [];
      for (let i = 0; i < samplesPerFamily && requestsSent < budget; i += 1) {
        if (i > 0) {
          const gap = deps.sampleGapMs ?? SAMPLE_GAP_MS;
          if (gap > 0) await sleepMs(gap, deps.jobDeadlineSignal);
        }
        const timeLeft = timeoutMs - (Date.now() - started);
        if (timeLeft <= 0) break;
        const remaining = Math.min(perAttemptTimeout, timeLeft);
        if (remaining <= 0) break;
        const sample = await openTcpOnce(
          connectFn,
          address,
          port,
          remaining,
          deps,
          () => { requestsSent += 1; },
        );
        const row = {
          ...sample,
          protocol: 'tcp',
          port,
          address,
          address_family: addressFamilyNumber(address),
          peer_is_cdn: peerIsCdn(address),
          service_validated: sample.tcp_outcome === 'handshake',
        };
        samples.push(row);
        allSamples.push(row);
      }
      if (samples.length) {
        families[key] = {
          ...samples[0],
          samples,
          sample_agreement: sampleAgreement(samples),
        };
      }
    }
    const primary = allSamples.find((sample) => sample.tcp_outcome === 'handshake') ?? allSamples[0] ?? {};
    const durationMs = Date.now() - started;
    return {
      external_result: tcpExternalResult(primary.tcp_outcome),
      metadata: withProfileKind(job, {
        probe_kind: 'tcp_connect',
        protocol: 'tcp',
        port,
        address: primary.address ?? pinned.address,
        address_family: primary.address_family ?? addressFamilyNumber(pinned.address),
        tcp_outcome: primary.tcp_outcome,
        icmp: primary.icmp ?? null,
        service_validated: primary.service_validated === true,
        peer_is_cdn: primary.peer_is_cdn ?? peerIsCdn(pinned.address),
        families,
        parity: familyParity(families),
        samples: allSamples,
        sample_agreement: sampleAgreement(allSamples),
        duration_ms: durationMs,
        target_port: port,
        observation_complete: requestsSent >= 1,
        pinned_address: primary.address ?? pinned.address,
        ...(primary.tcp_outcome !== 'handshake' ? { error_class: primary.error_class ?? primary.tcp_outcome } : {}),
      }, deps),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  } catch (error) {
    const durationMs = Date.now() - started;
    const code = error?.code ?? '';
    return {
      external_result: 'error',
      metadata: withProfileKind(job, {
        probe_kind: 'tcp_connect',
        error_class: code === 'ENOTFOUND' ? 'destination_unresolved' : 'destination_not_routable',
        target_port: port,
        duration_ms: durationMs,
      }, deps),
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
      external_result: 'error',
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
function openTlsSession(connectFn, endpoint, timeoutMs, deps, onReserved, { attemptRenegotiation = false } = {}) {
  return new Promise((resolve, reject) => {
    const signal = deps.jobDeadlineSignal;
    const stopped = () => Object.assign(new Error('Probe stopped.'), { code: 'ETIMEOUT', name: 'AbortError' });
    if (signal?.aborted) { reject(stopped()); return; }
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

    const timer = setTimeout(() => settle(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' })), timeoutMs);
    const onAbort = () => settle(stopped());
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

    let renegotiation = null;
    const onSecureConnect = () => {
      const session = {
        tls_protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name ?? null,
        authorized: socket.authorized,
      };
      if (!attemptRenegotiation) {
        settle(null, session);
        return;
      }
      if (session.tls_protocol !== 'TLSv1.2' || typeof socket.renegotiate !== 'function') {
        settle(null, { ...session, client_renegotiation_attempted: false, client_renegotiation_accepted: false });
        return;
      }
      renegotiation = (accepted) => {
        renegotiation = null;
        socket.removeListener('close', onRenegotiationClose);
        settle(null, { ...session, client_renegotiation_attempted: true, client_renegotiation_accepted: accepted });
      };
      socket.once('close', onRenegotiationClose);
      try {
        const started = socket.renegotiate({ rejectUnauthorized: false }, (err) => renegotiation?.(!err));
        if (started === false) renegotiation?.(false);
      } catch {
        renegotiation?.(false);
      }
    };
    const onRenegotiationClose = () => renegotiation?.(false);
    socket.once('secureConnect', onSecureConnect);
    const onError = (err) => {
      if (renegotiation) renegotiation(false);
      else settle(err);
    };
    if (attemptRenegotiation && typeof socket.on === 'function') socket.on('error', onError);
    else socket.once('error', onError);
    if (signal?.aborted) onAbort();
    else signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * @param {typeof http2.connect} connectFn
 * @param {string} url
 * @param {number} timeoutMs
 */
function readHttp2RemoteSettings(connectFn, tlsConnectFn, url, timeoutMs, connectHost, deps, onReserved) {
  return new Promise((resolve, reject) => {
    const signal = deps.jobDeadlineSignal ?? deps.signal;
    const stopped = () => Object.assign(new Error('Probe stopped.'), { code: 'ETIMEOUT', name: 'AbortError' });
    if (signal?.aborted) { reject(stopped()); return; }
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
          ALPNProtocols: ['h2'],
          rejectUnauthorized: false,
        }),
      }),
      onReserved,
    );

    const timer = setTimeout(() => settle(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' })), timeoutMs);
    const onAbort = () => settle(stopped());
    const onClose = () => settle(Object.assign(new Error('HTTP/2 closed before peer SETTINGS.'), { code: 'ECONNRESET' }));
    const settle = (err, settings) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      session.removeListener('remoteSettings', captureSettings);
      session.removeListener('close', onClose);
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

    // Node exposes protocol defaults at connect; only this event proves peer SETTINGS arrived.
    session.once('remoteSettings', captureSettings);
    session.once('close', onClose);
    session.once('error', (err) => settle(err));
    if (signal?.aborted) onAbort();
    else signal?.addEventListener('abort', onAbort, { once: true });
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
    }, timeoutMs, deps, () => { requestsSent = 1; }, { attemptRenegotiation: job.check_id === 'tls.renegotiation.readiness' });
    const durationMs = Date.now() - started;
    return {
      external_result: 'connected',
      metadata: withProfileKind(job, {
        probe_kind: 'tls_session',
        tls_protocol: sessionInfo.tls_protocol,
        cipher: sessionInfo.cipher,
        authorized: sessionInfo.authorized,
        ...('client_renegotiation_accepted' in sessionInfo ? {
          client_renegotiation_attempted: sessionInfo.client_renegotiation_attempted,
          client_renegotiation_accepted: sessionInfo.client_renegotiation_accepted,
        } : {}),
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
  const controller = new AbortController();
  const upstreamSignal = deps.jobDeadlineSignal;
  const onAbort = () => controller.abort();
  if (upstreamSignal?.aborted) onAbort();
  else upstreamSignal?.addEventListener('abort', onAbort, { once: true });
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    controller.signal.throwIfAborted();
    const pinned = await resolvePinnedDestination(host, deps);
    const pinnedDeps = {
      ...deps,
      vettedHost: pinned.host,
      vettedAddresses: pinned.addresses,
    };
    const fetchFn = deps.fetchFn ?? ((input, init) => pinnedFetch(input, init, pinnedDeps));
    controller.signal.throwIfAborted();
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
  } finally {
    clearTimeout(timer);
    upstreamSignal?.removeEventListener('abort', onAbort);
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
  const declared = resolveAlertWebhookUrl(job);
  const approved = job.constraints?.alert_webhook_url;
  if (typeof approved !== 'string' || !approved || declared !== approved) {
    return { external_result: 'not_run', metadata: withProfileKind(job, {
      probe_kind: 'alert_webhook_ping', not_run_reason: 'approved_signed_callback_scope_required',
      delivery_supported: false, observation_only: true, readiness_conclusion: false,
    }), requests_sent: 0, duration_ms: 0 };
  }
  const webhookUrl = approved;
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
  if (parsedUrl.protocol !== 'https:' || parsedUrl.username || parsedUrl.password || parsedUrl.hash) {
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

function classifyWebsocketUpgradeStatus(status, identityConfirmed) {
  if (status === 101 && identityConfirmed) {
    return {
      external_result: 'connected',
      upgrade_accepted: true,
      upgrade_denied: false,
      upgrade_required: false,
    };
  }
  if (WEBSOCKET_UPGRADE_DENIED_STATUSES.has(status)) {
    return {
      external_result: 'not_run',
      upgrade_accepted: false,
      upgrade_denied: false,
      upgrade_required: false,
    };
  }
  if (status === 426) {
    return {
      external_result: 'not_run',
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
  const upstreamSignal = deps.jobDeadlineSignal;
  const onAbort = () => controller.abort();
  if (upstreamSignal?.aborted) onAbort();
  else upstreamSignal?.addEventListener('abort', onAbort, { once: true });
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
    controller.signal.throwIfAborted();
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
    const expectedAccept = createHash('sha1').update(headers['Sec-WebSocket-Key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    const identityConfirmed = res.status === 101 && res.headers.get('sec-websocket-accept') === expectedAccept && String(res.headers.get('upgrade')).toLowerCase() === 'websocket' && String(res.headers.get('connection')).toLowerCase().split(/\s*,\s*/).includes('upgrade');
    const classification = classifyWebsocketUpgradeStatus(res.status, identityConfirmed);
    return {
      external_result: classification.external_result,
      metadata: withProfileKind(job, {
        probe_kind: 'websocket_upgrade_posture',
        status_code: res.status,
        upgrade_accepted: classification.upgrade_accepted,
        handshake_identity_confirmed: identityConfirmed,
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
        external_result: 'error',
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
    upstreamSignal?.removeEventListener('abort', onAbort);
  }
}
