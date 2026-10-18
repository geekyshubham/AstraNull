import assert from 'node:assert/strict';
import net from 'node:net';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { executeMemoryDelivery } from './check-delivery-fixtures.mjs';
import { RISKY_ADMIN_PORTS } from '../../src/lib/capabilityProbes.mjs';

export const CONNECT_FAULT_KINDS = Object.freeze(['tcp_connect', 'port_scan_bounded', 'connection_limit_probe']);

/** Observe real native sockets; never emit errors, delay events or modify signed jobs. */
export async function createConnectFaultFixture(fixtures, check, branch) {
  assert.ok(CONNECT_FAULT_KINDS.includes(check.probe_profile.kind));
  assert.ok(['peer_refused', 'cancel'].includes(branch), 'SYN timeout requires the separately preflighted kernel fault lab');
  const fixture = fixtures.forCheck(check);
  const attempts = []; const evidence = []; const wire = []; const routes = [];
  const sockets = new Set(); const peers = new Set();
  const cancellation = new AbortController();
  const server = net.createServer((socket) => {
    peers.add(socket);
    wire.push({ transport: 'tcp_connect', fixture_host: '127.0.0.1', fixture_port: serverPort,
      remote_port: socket.remotePort, accepted_at: new Date().toISOString() });
    socket.on('error', () => {});
    socket.once('close', () => { peers.delete(socket); });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, resolve);
  });
  const serverPort = server.address().port;
  if (branch === 'peer_refused') await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  fixture.target.port = serverPort;
  if (check.probe_profile.kind === 'connection_limit_probe') {
    fixture.target.metadata_json.control_declarations.connection_limits[0].port = serverPort;
  }
  fixture.deps.cancellationSignal = cancellation.signal;
  fixture.deps.connectFn = (options) => {
    assert.equal(options.host, '127.0.0.1');
    if (check.probe_profile.kind !== 'port_scan_bounded') assert.equal(Number(options.port), serverPort);
    else assert.ok((check.probe_profile.ports ?? RISKY_ADMIN_PORTS).includes(Number(options.port)), 'only catalog-declared scan ports may be mapped to the owned peer');
    const route = { transport: 'tcp', requested_host: options.host, requested_port: Number(options.port),
      fixture_host: '127.0.0.1', fixture_port: serverPort,
      mapping: Number(options.port) === serverPort ? 'unchanged' : 'owned_transport_pin_not_production_port_proof' };
    routes.push(route);
    const attempt = { ...route, transport: 'tcp_connect', attempt_id: randomUUID(), phase: 'connect',
      started_at: new Date().toISOString(), accepted: false, source: 'native_node_net_socket' };
    attempts.push(attempt);
    const socket = net.connect({ ...options, port: serverPort });
    sockets.add(socket);
    socket.once('connect', () => {
      attempt.accepted = true;
      attempt.connected_at = new Date().toISOString();
      attempt.local_port = socket.localPort;
      if (branch === 'cancel' && !cancellation.signal.aborted) {
        evidence.push({ event: 'cancel_requested', transport: 'tcp', attempt_id: attempt.attempt_id,
          phase: 'established_connection_before_next_attempt', source: 'native_connect_event', client_local_port: socket.localPort,
          fixture_host: '127.0.0.1', fixture_port: serverPort, at: new Date().toISOString() });
        cancellation.abort();
      }
    });
    socket.once('error', (error) => {
      attempt.error_code = error.code;
      attempt.error_at = new Date().toISOString();
      if (error.code === 'ECONNREFUSED') evidence.push({ event: 'connection_refused', transport: 'tcp',
        attempt_id: attempt.attempt_id, phase: 'connect', fixture_host: '127.0.0.1', fixture_port: serverPort,
        error_code: error.code, at: attempt.error_at });
    });
    socket.once('close', () => {
      sockets.delete(socket);
      attempt.closed_at = new Date().toISOString();
      evidence.push({ event: 'owned_client_socket_closed', transport: 'tcp', attempt_id: attempt.attempt_id,
        phase: 'connect', fixture_host: '127.0.0.1', fixture_port: serverPort, at: attempt.closed_at });
    });
    return socket;
  };
  fixture.wire = () => structuredClone(wire);
  fixture.routes = () => structuredClone(routes);
  fixture.peerEvidence = () => structuredClone(evidence);
  fixture.waitForWire = async () => {
    // Wait only for native terminal events; never manufacture them during cleanup.
    const deadline = Date.now() + 1000;
    while (sockets.size || peers.size) {
      assert.ok(Date.now() < deadline, 'producer must terminate all client and peer work before fixture teardown');
      await delay(5);
    }
    if (branch === 'cancel') assert.ok(wire.length > 0, 'actual accepted handshake required for this native cancellation phase');
  };
  fixture.close = async () => {
    for (const socket of sockets) socket.destroy();
    for (const socket of peers) socket.destroy();
    if (server.listening) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  };
  fixture.attempts = () => structuredClone(attempts);
  return fixture;
}

export async function executeConnectFaultDelivery(check, fixture) {
  const result = await executeMemoryDelivery(check, fixture);
  assert.ok(result.job, 'actual signed worker lifecycle required');
  result.networkAttempts = fixture.attempts().map((attempt) => ({ ...attempt,
    job_id: result.job.id, invocation_id: result.receipt.invocation_id, target_id: result.job.target_id }));
  // Only refusal attempts substitute for absent accepted wire. Cancellation already
  // has a real accepted handshake and uses its separately bound causal events.
  if (result.networkAttempts.every((attempt) => attempt.error_code === 'ECONNREFUSED')) {
    result.receipt.actual_network_attempts = structuredClone(result.networkAttempts);
  }
  result.receipt.branch_peer_evidence = fixture.peerEvidence();
  result.receipt.runtime_provenance = { platform: process.platform, node: process.version, scope: 'owned_loopback' };
  return result;
}
