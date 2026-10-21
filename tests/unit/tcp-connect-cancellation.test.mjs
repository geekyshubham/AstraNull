import assert from 'node:assert/strict';
import { EventEmitter, once } from 'node:events';
import net from 'node:net';
import test from 'node:test';
import { probePortScanBounded } from '../../src/lib/capabilityProbes.mjs';
import { probeConnectionLimit } from '../../src/lib/connectionLimitProbe.mjs';
import { probeTcpConnect } from '../../src/lib/safeNetworkProbes.mjs';

const constraints = { max_requests: 4, timeout_ms: 2000 };
const destinationPolicy = { allowPrivate: true, allowLoopback: true };
const jobs = [
  ['TCP reachability', probeTcpConnect, {
    target: { kind: 'ip', value: '127.0.0.1', port: 8083 },
    probe_profile: { kind: 'tcp_connect', max_requests: 1 },
    constraints: { ...constraints, max_requests: 1 },
  }],
  ['bounded port scan', probePortScanBounded, {
    target: { kind: 'ip', value: '127.0.0.1' },
    probe_profile: { kind: 'port_scan_bounded', ports: [443], max_requests: 1 },
    constraints: { ...constraints, max_requests: 1 },
  }],
  ['connection limit', probeConnectionLimit, {
    target: { kind: 'ip', value: '127.0.0.1' },
    probe_profile: { declarations: { connection_limits: [{ protocol: 'tcp', port: 8083, max_connections_per_source: 1 }] } },
    constraints,
  }],
];

// A controlled transport tests net.connect's signal contract, not native SYN-timeout evidence.
function pendingSocket(options) {
  const socket = new EventEmitter();
  socket.destroyed = false;
  socket.fallbackFired = false;
  socket.setTimeout = () => socket;
  socket.end = () => socket.destroy();
  const fail = (code) => {
    socket.destroy();
    socket.emit('error', Object.assign(new Error(code), { code }));
  };
  const onAbort = () => queueMicrotask(() => fail('ABORT_ERR'));
  const timer = setTimeout(() => {
    socket.fallbackFired = true;
    fail('ETIMEDOUT');
  }, 250);
  socket.destroy = () => {
    socket.destroyed = true;
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', onAbort);
  };
  options.signal?.addEventListener('abort', onAbort, { once: true });
  if (options.signal?.aborted) onAbort();
  return socket;
}

for (const [name, probe, job] of jobs) {
  test(`${name} forwards Stop to a pending connection before its timeout`, async () => {
    const controller = new AbortController();
    const options = [];
    const sockets = [];
    await probe(job, {
      destinationPolicy,
      jobDeadlineSignal: controller.signal,
      beforeProbeIoAttempt: () => controller.signal.throwIfAborted(),
      connectFn: (value) => {
        options.push(value);
        const socket = pendingSocket(value);
        sockets.push(socket);
        queueMicrotask(() => controller.abort());
        return socket;
      },
    });
    assert.equal(options.length, 1, 'Stop must not start another attempt');
    assert.equal(options[0].signal, controller.signal);
    assert.equal(sockets[0].destroyed, true);
    assert.equal(sockets[0].fallbackFired, false, 'Stop must settle before the transport timeout');
  });
}

test('connection-limit Stop closes an earlier owned native connection while the next attempt is pending', async (t) => {
  const peers = new Set();
  let peerClosed;
  const closed = new Promise((resolve) => { peerClosed = resolve; });
  const server = net.createServer((socket) => {
    peers.add(socket);
    socket.resume();
    socket.on('close', () => { peers.delete(socket); peerClosed(); });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    for (const peer of peers) peer.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  const controller = new AbortController();
  let connections = 0;
  let nativeSocket;
  let pending;
  const result = await probeConnectionLimit({
    target: { kind: 'ip', value: '127.0.0.1' },
    probe_profile: { declarations: { connection_limits: [{ protocol: 'tcp', port: server.address().port, max_connections_per_source: 1 }] } },
    constraints,
  }, {
    destinationPolicy,
    jobDeadlineSignal: controller.signal,
    beforeProbeIoAttempt: () => controller.signal.throwIfAborted(),
    connectFn: (options) => {
      connections += 1;
      if (connections === 1) {
        nativeSocket = net.connect(options);
        return nativeSocket;
      }
      pending = pendingSocket(options);
      queueMicrotask(() => controller.abort());
      return pending;
    },
  });
  if (!nativeSocket.closed) await once(nativeSocket, 'close');
  await closed;
  assert.equal(connections, 2);
  assert.equal(result.requests_sent, 2);
  assert.equal(pending.fallbackFired, false);
  assert.equal(nativeSocket.destroyed, true);
  assert.equal(peers.size, 0, 'the actual loopback peer must observe closure');
});
