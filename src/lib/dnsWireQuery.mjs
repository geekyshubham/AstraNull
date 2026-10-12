import { createHash } from 'node:crypto';
import dgram from 'node:dgram';
import dns from 'node:dns/promises';
import net from 'node:net';
import {
  accumulateDnsTcpResponse,
  buildDnsQueryMessage,
  frameDnsTcpMessage,
  parseDnsResponseHeader,
  parseDnsResponseStructure,
  DNS_QTYPE_CODES,
} from './dnsTcpWire.mjs';
import { resolvePinnedDestination } from './pinnedHttpRequest.mjs';
import { startProbeIoAttempt } from './probeAttempt.mjs';
import { isExpectedUdpPeer } from './safeNetworkProbes.mjs';

function queryIdForJob(job) {
  return createHash('sha256')
    .update(String(job.nonce_hash ?? job.nonce ?? 'astranull-dns'))
    .digest()
    .readUInt16BE(0);
}

function normalizedDnsName(value) {
  return String(value ?? '').trim().replace(/^\./, '').replace(/\.$/, '');
}

export function dnsQueryNameForJob(job) {
  const value = normalizedDnsName(job.target?.value);
  if (!value) return null;
  const checkId = String(job.check_id ?? '');
  const nonce = String(job.nonce ?? '').trim();
  if (checkId.includes('random_prefix') && nonce) {
    const label = nonce.replace(/[^a-zA-Z0-9-]/g, '').slice(0, 32) || 'probe';
    return `${label}.${value}`;
  }
  return value;
}

function remainingTimeoutMs(started, timeoutMs) {
  return Math.max(0, timeoutMs - (Date.now() - started));
}

function withTimeout(promise, timeoutMs, signal, cancel = () => {}) {
  if (timeoutMs <= 0) {
    return Promise.reject(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' }));
  }
  let timer;
  let onAbort;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      onAbort = () => { cancel(); reject(Object.assign(new Error('probe canceled'), { code: 'ETIMEOUT' })); };
      signal?.addEventListener('abort', onAbort, { once: true });
      if (signal?.aborted) onAbort();
    }),
    new Promise((_, reject) => {
      timer = setTimeout(
        () => { cancel(); reject(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' })); },
        timeoutMs,
      );
    }),
  ]).finally(() => { clearTimeout(timer); signal?.removeEventListener('abort', onAbort); });
}

async function resolveDnsDestination(job, deps, queryName, started, timeoutMs) {
  const targetValue = normalizedDnsName(job.target?.value);
  const directHost = net.isIP(targetValue) !== 0 ? targetValue : null;
  if (directHost) {
    return withTimeout(
      resolvePinnedDestination(directHost, deps),
      remainingTimeoutMs(started, timeoutMs), deps.jobDeadlineSignal,
    );
  }

  const zone = targetValue || queryName;
  deps.recordDestinationResolverAttempt?.('ns');
  const resolver = deps.resolveNsFn ? null : new dns.Resolver();
  const resolveNsFn = deps.resolveNsFn ?? resolver.resolveNs.bind(resolver);
  const nameservers = await withTimeout(
    resolveNsFn(zone),
    remainingTimeoutMs(started, timeoutMs), deps.jobDeadlineSignal, () => resolver?.cancel(),
  );
  const nameserver = Array.isArray(nameservers)
    ? nameservers.find((value) => typeof value === 'string' && value.trim())
    : null;
  if (!nameserver) throw Object.assign(new Error('authoritative nameserver not found'), { code: 'ENOTFOUND' });
  const { vettedHost: _vettedHost, vettedAddresses: _vettedAddresses, ...unpinnedDeps } = deps;
  return withTimeout(
    resolvePinnedDestination(nameserver.replace(/\.$/, ''), {
      ...unpinnedDeps,
    }),
    remainingTimeoutMs(started, timeoutMs),
  );
}

function sendDnsUdp(createSocket, query, endpoint, timeoutMs, transactionId, deps, operation, onAttempt) {
  return new Promise((resolve, reject) => {
    if (deps.jobDeadlineSignal?.aborted) { reject(Object.assign(new Error('probe canceled'), { code: 'ETIMEOUT' })); return; }
    const socket = startProbeIoAttempt(
      deps,
      operation,
      () => createSocket(net.isIP(endpoint.host) === 6 ? 'udp6' : 'udp4'),
      onAttempt,
    );
    let settled = false;
    let timer;
    const settle = (value, error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeListener?.('message', onMessage);
      socket.removeListener?.('error', onError);
      deps.jobDeadlineSignal?.removeEventListener('abort', onAbort);
      try {
        socket.close();
      } catch {
        // A synchronous datagram failure can leave the socket unopened.
      }
      if (error) reject(error);
      else resolve(value);
    };
    const onMessage = (message, rinfo) => {
      if (!isExpectedUdpPeer(rinfo, endpoint.host, endpoint.port)) return;
      const response = Buffer.isBuffer(message) ? message : Buffer.from(message ?? []);
      const parsed = parseDnsResponseHeader(response, { transport: 'udp' });
      if (parsed.incomplete || parsed.transaction_id !== transactionId) return;
      settle({
        received: true,
        response_bytes: response.length,
        parsed,
      });
    };
    const onError = (error) => settle(null, error);
    const onAbort = () => settle(null, Object.assign(new Error('probe canceled'), { code: 'ETIMEOUT' }));
    deps.jobDeadlineSignal?.addEventListener('abort', onAbort, { once: true });
    socket.on('message', onMessage);
    socket.once('error', onError);
    timer = setTimeout(
      () => settle({ received: false, response_bytes: 0, parsed: null }),
      Math.max(1, timeoutMs),
    );
    try {
      socket.send(query, endpoint.port, endpoint.host, (error) => {
        if (error) settle(null, error);
      });
    } catch (error) {
      settle(null, error);
    }
  });
}

function sendDnsTcp(connectFn, query, endpoint, timeoutMs, transactionId, deps, operation, onAttempt) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let responseBuffer = Buffer.alloc(0);
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
        // The injected socket can fail before initialization completes.
      }
      if (error) reject(error);
      else resolve(value);
    };
    deps.jobDeadlineSignal?.addEventListener('abort', onAbort, { once: true });
    socket = startProbeIoAttempt(
      deps,
      operation,
      () => connectFn({ host: endpoint.host, port: endpoint.port }, () => {
        try {
          socket.write(frameDnsTcpMessage(query), (error) => {
            if (error) settle(null, error);
          });
        } catch (error) {
          settle(null, error);
        }
      }),
      onAttempt,
    );
    const onData = (chunk) => {
      if (settled) return;
      const accumulated = accumulateDnsTcpResponse(responseBuffer, chunk, { transport: 'tcp' });
      responseBuffer = accumulated.buffer;
      if (!accumulated.complete) return;
      if (accumulated.parsed.transaction_id !== transactionId) {
        const frameBytes = responseBuffer.length >= 2
          ? Math.min(responseBuffer.length, responseBuffer.readUInt16BE(0) + 2)
          : responseBuffer.length;
        responseBuffer = responseBuffer.subarray(frameBytes);
        if (responseBuffer.length > 0) onData(Buffer.alloc(0));
        return;
      }
      const responseBytes = accumulated.parsed.dns_message?.length ?? Math.max(0, responseBuffer.length - 2);
      settle({
        received: accumulated.parsed.rcode != null,
        response_bytes: responseBytes,
        parsed: accumulated.parsed,
      });
    };
    socket.on('data', onData);
    socket.once('error', (error) => settle(null, error));
    socket.once('end', () => settle({ received: false, response_bytes: 0, parsed: null }));
    socket.setTimeout?.(Math.max(1, timeoutMs), () => settle({
      received: false,
      response_bytes: 0,
      parsed: null,
    }));
    timer = setTimeout(() => settle({
      received: false,
      response_bytes: 0,
      parsed: null,
    }), Math.max(1, timeoutMs));
  });
}

function amplificationRatio(responseBytes, requestBytes) {
  return responseBytes > 0 && requestBytes > 0
    ? Math.round((responseBytes / requestBytes) * 100) / 100
    : null;
}

function dnsOutcome(job, fields, externalResult, requestsSent, started) {
  const durationMs = Date.now() - started;
  return {
    external_result: externalResult,
    metadata: {
      probe_kind: 'dns_wire_query',
      ...fields,
      classifier_version: 'dns-message-identity-v3', observation_only: true, readiness_conclusion: false, evidence_tier: 'E2',
      duration_ms: durationMs,
    },
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

export async function probeDnsWireQuery(job, deps = {}) {
  const started = Date.now();
  const queryName = dnsQueryNameForJob(job);
  const qtype = String(job.probe_profile?.dns_qtype ?? 'A').toUpperCase();
  const requestedTransport = job.probe_profile?.dns_transport ?? 'udp';
  const timeoutMs = Math.max(1, Number(job.constraints?.timeout_ms) || 5000);
  const maxRequests = Math.min(3, Math.max(0, Number(job.constraints?.max_requests) || 0));
  const base = {
    query_name: queryName,
    qtype,
    transport: requestedTransport,
    rcode: null,
    answer_count: 0,
    response_bytes: 0,
    amplification_ratio: null,
    truncated: false,
    tcp_fallback_used: false,
    wildcard_response_detected: null,
    random_prefix_answer_observed: false,
    protocol_identity_confirmed: false,
    authoritative: false,
  };
  const targetName = normalizedDnsName(job.target?.value).toLowerCase();
  const declaredZone = normalizedDnsName(job.target?.metadata?.zone).toLowerCase();
  const declaredResolver = normalizedDnsName(job.target?.metadata?.resolver_host).toLowerCase();
  if ((declaredZone && declaredZone !== targetName) || (declaredResolver && declaredResolver !== targetName)) {
    return dnsOutcome(job, { ...base, error_class: 'dns_scope_not_target_bound', not_run_reason: 'dns_scope_not_target_bound' }, 'not_run', 0, started);
  }
  if (!queryName || !['udp', 'tcp', 'auto'].includes(requestedTransport) || maxRequests < 1) {
    return dnsOutcome(job, { ...base, error_class: 'unsupported_dns_query' }, 'error', 0, started);
  }

  let query;
  try {
    query = buildDnsQueryMessage(queryName, {
      qtype,
      id: queryIdForJob(job),
      recursionDesired: false,
    });
  } catch {
    return dnsOutcome(job, { ...base, error_class: 'unsupported_dns_query' }, 'error', 0, started);
  }

  let requestsSent = 0;
  try {
    const pinned = await resolveDnsDestination(job, deps, queryName, started, timeoutMs);
    const endpoint = { host: pinned.address, port: 53 };
    const transactionId = query.readUInt16BE(0);
    let transport = requestedTransport === 'tcp' ? 'tcp' : 'udp';
    const recordAttempt = () => { requestsSent += 1; };
    let response = transport === 'tcp'
      ? await sendDnsTcp(
          deps.connectFn ?? net.connect,
          query,
          endpoint,
          remainingTimeoutMs(started, timeoutMs),
          transactionId,
          deps,
          `dns_${transport}`,
          recordAttempt,
        )
      : await sendDnsUdp(
          deps.createSocket ?? dgram.createSocket.bind(dgram),
          query,
          endpoint,
          remainingTimeoutMs(started, timeoutMs),
          transactionId,
          deps,
          `dns_${transport}`,
          recordAttempt,
        );

    const truncated = Boolean(response.parsed?.truncated);
    let tcpFallbackUsed = false;
    if (requestedTransport === 'auto' && truncated && maxRequests >= 2) {
      transport = 'tcp';
      tcpFallbackUsed = true;
      response = await sendDnsTcp(
        deps.connectFn ?? net.connect,
        query,
        endpoint,
        remainingTimeoutMs(started, timeoutMs),
        transactionId,
        deps,
        'dns_tcp_fallback',
        recordAttempt,
      );
    }

    if (!response.received) {
      return dnsOutcome(job, {
        ...base,
        transport,
        truncated,
        tcp_fallback_used: tcpFallbackUsed,
        error_class: 'no_dns_response',
      }, 'timeout', requestsSent, started);
    }

    const rcode = response.parsed?.rcode ?? null;
    const answerCount = response.parsed?.answer_count ?? 0;
    const message = response.parsed.dns_message;
    const structure = parseDnsResponseStructure(message, {
      expectedQuestion: { name: queryName, qtype: DNS_QTYPE_CODES[qtype], qclass: 1 },
    });
    if (!structure.structure_valid || (message[2] & 0x80) === 0 || (message[2] & 0x78) !== 0) {
      return dnsOutcome(job, { ...base, rcode, response_bytes: response.response_bytes,
        error_class: structure.reason ?? 'not_dns_response' }, 'not_run', requestsSent, started);
    }
    let strictMetadata = { question_matches: true, protocol_identity_confirmed: true,
      message_complete: !response.parsed.truncated };
    if (job.probe_profile?.strict_dns_answer === true) {
      if (!structure.structure_valid || !response.parsed.authoritative || response.parsed.truncated || rcode !== 0
        || (answerCount > 0 && structure.matching_answer_count === 0)) {
        return dnsOutcome(job, { ...base, rcode, error_class: structure.reason ?? 'non_definitive_dns_response' }, 'error', requestsSent, started);
      }
      strictMetadata = { ...strictMetadata, matching_answer_count: structure.matching_answer_count };
    }
    const randomPrefix = String(job.check_id ?? '').includes('random_prefix');
    const wildcardResponseDetected = randomPrefix && rcode === 0 && answerCount > 0;
    return dnsOutcome(job, {
      ...base,
      transport,
      rcode,
      answer_count: answerCount,
      response_bytes: response.response_bytes,
      amplification_ratio: amplificationRatio(response.response_bytes, query.length),
      truncated,
      tcp_fallback_used: tcpFallbackUsed,
      wildcard_response_detected: null,
      random_prefix_answer_observed: wildcardResponseDetected,
      authoritative: Boolean(response.parsed?.authoritative),
      ...strictMetadata,
    }, 'connected', requestsSent, started);
  } catch (error) {
    const code = error?.code ?? '';
    if (['signed_operation_budget_exceeded', 'probe_job_deadline_exceeded'].includes(code)) {
      throw error;
    }
    const externalResult = requestsSent === 0
      ? 'error'
      : (code === 'ETIMEOUT'
        ? 'timeout'
        : 'error');
    return dnsOutcome(job, {
      ...base,
      error_class: code || 'dns_wire_query_failed',
    }, externalResult, requestsSent, started);
  }
}
