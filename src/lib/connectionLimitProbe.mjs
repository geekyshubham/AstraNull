import net from 'node:net';
import { targetHostFromRecord } from '../contracts/controlDeclarations.mjs';
import { resolvePinnedDestination } from './pinnedHttpRequest.mjs';
import { startProbeIoAttempt } from './probeAttempt.mjs';
import {
  CONNECTION_HOLD_MS,
  CONNECTION_LIMIT_HARD_CAP,
  noPortDeclaredResult,
  peerIsCdn,
  requestedAddressFamily,
  stampSourcePerspective,
  validNetworkPort,
} from './networkProbeOutcomes.mjs';

function declaredTcpLimit(job) {
  const rows = job?.probe_profile?.declarations?.connection_limits;
  if (!Array.isArray(rows)) return null;
  const tcp = rows.find((row) => row && row.protocol === 'tcp' && validNetworkPort(row.port)
    && Number.isInteger(row.max_connections_per_source)
    && row.max_connections_per_source >= 1
    && row.max_connections_per_source <= 10);
  return tcp ?? null;
}

function holdThenClose(socket, holdMs, signal) {
  return new Promise((resolve) => {
    const finish = () => {
      try { socket.destroy(); } catch { /* already closed */ }
      resolve();
    };
    if (signal?.aborted) { finish(); return; }
    const timer = setTimeout(finish, holdMs);
    const onAbort = () => { clearTimeout(timer); finish(); };
    signal?.addEventListener('abort', onAbort, { once: true });
    socket.once?.('error', () => { clearTimeout(timer); finish(); });
  });
}

function tryConnect(connectFn, address, port, timeoutMs, deps, onReserved) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = startProbeIoAttempt(
      deps,
      'tcp_connect',
      () => connectFn({ host: address, port }),
      onReserved,
    );
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    const timer = setTimeout(() => {
      try { socket.destroy(); } catch { /* ignore */ }
      finish({ accepted: false, socket: null, reason: 'timeout' });
    }, Math.max(1, timeoutMs));
    socket.once?.('connect', () => {
      clearTimeout(timer);
      finish({ accepted: true, socket, reason: null });
    });
    socket.on?.('error', (err) => {
      clearTimeout(timer);
      try { socket.destroy(); } catch { /* ignore */ }
      finish({ accepted: false, socket: null, reason: err?.code || 'connect_failed' });
    });
  });
}

export async function probeConnectionLimit(job, deps = {}) {
  const kind = 'connection_limit_probe';
  const stamp = (metadata) => stampSourcePerspective(metadata, deps);
  const declared = declaredTcpLimit(job);
  if (!declared) {
    return {
      ...noPortDeclaredResult(kind, { reason: 'no_connection_limit_declared' }),
      reason: 'no_connection_limit_declared',
      metadata: stamp({
        probe_kind: kind,
        profile_kind: kind,
        error_class: 'unsupported_target',
        reason: 'no_connection_limit_declared',
      }),
    };
  }

  const host = targetHostFromRecord(job.target);
  const port = validNetworkPort(declared.port);
  if (!host || !port) {
    return {
      ...noPortDeclaredResult(kind),
      metadata: stamp({
        probe_kind: kind,
        profile_kind: kind,
        error_class: 'unsupported_target',
        reason: 'no_port_declared',
      }),
    };
  }

  const declaredLimit = declared.max_connections_per_source;
  const attempted = Math.min(declaredLimit + 2, CONNECTION_LIMIT_HARD_CAP);
  const timeoutMs = Math.max(1, Number(job.constraints?.timeout_ms) || 2000);
  const holdMs = Math.min(CONNECTION_HOLD_MS, timeoutMs);
  const started = Date.now();
  const connectFn = deps.connectFn ?? net.connect;
  const sockets = [];
  let requestsSent = 0;
  let acceptedCount = 0;
  let refusedAfter = null;

  try {
    const familyPref = requestedAddressFamily(job);
    const pinned = await resolvePinnedDestination(host, {
      ...deps,
      addressFamily: familyPref === 'both' ? undefined : familyPref,
    });
    for (let i = 0; i < attempted; i += 1) {
      const result = await tryConnect(
        connectFn,
        pinned.address,
        port,
        timeoutMs,
        deps,
        () => { requestsSent += 1; },
      );
      if (result.accepted) {
        acceptedCount += 1;
        sockets.push(result.socket);
      } else if (refusedAfter == null && result.reason === 'ECONNREFUSED') {
        refusedAfter = acceptedCount;
      }
    }
    await Promise.all(sockets.map((socket) => holdThenClose(socket, holdMs, deps.jobDeadlineSignal)));
    const durationMs = Date.now() - started;
    return {
      external_result: acceptedCount > 0 ? 'connected' : 'blocked',
      metadata: stamp({
        probe_kind: kind,
        profile_kind: kind,
        port,
        attempted,
        accepted_count: acceptedCount,
        refused_after: refusedAfter,
        declared_limit: declaredLimit,
        peer_is_cdn: peerIsCdn(pinned.address),
        address: pinned.address,
        duration_ms: durationMs,
      }),
      requests_sent: requestsSent,
      duration_ms: durationMs,
    };
  } catch (error) {
    for (const socket of sockets) {
      try { socket.destroy(); } catch { /* ignore */ }
    }
    return {
      external_result: 'error',
      metadata: stamp({
        probe_kind: kind,
        profile_kind: kind,
        port,
        attempted,
        accepted_count: acceptedCount,
        refused_after: refusedAfter,
        declared_limit: declaredLimit,
        error_class: error?.code || 'connection_limit_probe_failed',
        duration_ms: Date.now() - started,
      }),
      requests_sent: requestsSent,
      duration_ms: Date.now() - started,
    };
  }
}
