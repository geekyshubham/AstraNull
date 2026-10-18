import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import dns from 'node:dns/promises';
import net from 'node:net';
import { buildDnsQueryMessage, encodeDnsQName, frameDnsTcpMessage } from '../../src/lib/dnsTcpWire.mjs';
import { deliverySocketIdentity, deliveryDatagramIdentity } from './check-delivery-peer-identity.mjs';

export function dnsQuestion(message) {
  let offset = 12;
  const labels = [];
  while (message[offset]) {
    const length = message[offset++];
    assert.ok(length <= 63 && offset + length < message.length);
    labels.push(message.subarray(offset, offset + length).toString('ascii'));
    offset += length;
  }
  offset += 1;
  return { name: labels.join('.'), qtype: message.readUInt16BE(offset), qclass: message.readUInt16BE(offset + 2), end: offset + 4 };
}
function record(type, data) {
  const fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(type, 0); fixed.writeUInt16BE(1, 2);
  fixed.writeUInt32BE(30, 4); fixed.writeUInt16BE(data.length, 8);
  return Buffer.concat([Buffer.from([0xc0, 0x0c]), fixed, data]);
}
export function dnsResponse(query, { truncated = false, axfrRefused = false, nxdomain = false, axfrTransfer = false } = {}) {
  const question = dnsQuestion(query);
  let data = null;
  if (question.qtype === 1) data = Buffer.from([127, 0, 0, 1]);
  if (question.qtype === 2) data = encodeDnsQName('ns.grpc.test');
  if (question.qtype === 16) data = Buffer.from([7, ...Buffer.from('fixture')]);
  if (question.qtype === 48) data = Buffer.from([1, 0, 3, 8, 1, 2, 3, 4]);
  if (question.qtype === 6 || axfrTransfer) {
    const integers = Buffer.alloc(20);
    [1, 3600, 600, 86400, 60].forEach((value, i) => integers.writeUInt32BE(value, i * 4));
    data = Buffer.concat([encodeDnsQName('ns.grpc.test'), encodeDnsQName('hostmaster.grpc.test'), integers]);
  }
  const rcode = nxdomain ? 3 : axfrRefused ? 5 : 0;
  const header = Buffer.alloc(12);
  query.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8400 | (query.readUInt16BE(2) & 0x0100) | (truncated ? 0x0200 : 0) | rcode, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(!truncated && !rcode && data ? axfrTransfer ? 2 : 1 : 0, 6);
  return Buffer.concat([header, query.subarray(12, question.end), ...(!truncated && !rcode && data ? axfrTransfer ? [record(6, data), record(6, data)] : [record(question.qtype, data)] : [])]);
}

export async function createDeliveryDnsFixture() {
  const rows = []; const peerEvidence = [];
  const clients = new Set(); const probePorts = new Set();
  let truncateProbe = false; let scenario = 'success'; let onCancel; let epoch = 0; let probeKind;
  const resolverClients = new Set(); const observedDatagrams = new Map();
  const udp = dgram.createSocket('udp4');
  const wrongPeer = dgram.createSocket('udp4');
  const responseForProbe = (query, transport, observed) => {
    const question = dnsQuestion(query);
    const reply = dnsResponse(query, { axfrRefused: question.qtype === 252 && scenario !== 'axfr_transfer', axfrTransfer: question.qtype === 252 && scenario === 'axfr_transfer', nxdomain: ['nxdomain', 'negative_dns'].includes(scenario), truncated: transport === 'dns_udp' && truncateProbe && ![1, 28, 2].includes(question.qtype) });
    if (scenario === 'malformed_response') reply.writeUInt16BE(1, 6); // Claims an answer whose bytes are absent.
    const response = scenario === 'malformed_response' ? reply.subarray(0, question.end) : reply;
    peerEvidence.push({ event: 'dns_response_constructed', transport, ...observed, qtype: question.qtype, rcode: reply.readUInt16BE(2) & 15, request_hex: query.toString('hex'), response_hex: response.toString('hex') });
    return response;
  };
  const tcp = net.createServer((socket) => {
    const ownerEpoch = epoch;
    const identity = { ...deliverySocketIdentity(socket), phase: 'dns_query' };
    clients.add(socket); socket.once('close', () => {
      clients.delete(socket);
      if (ownerEpoch === epoch) peerEvidence.push({ event: 'owned_peer_socket_closed', transport: 'dns_tcp', ...identity, observed_at_ms: Date.now() });
    });
    socket.on('error', () => {});
    let pending = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      pending = Buffer.concat([pending, chunk]);
      if (pending.length < 2 || pending.length < pending.readUInt16BE(0) + 2) return;
      const query = pending.subarray(2, pending.readUInt16BE(0) + 2);
      const question = dnsQuestion(query);
      const observed = { ...identity, request_hex: query.toString('hex') };
      rows.push({ transport: 'dns_tcp', ...observed, ...question, transaction_id: query.readUInt16BE(0), bytes: query.length });
      peerEvidence.push({ event: 'dns_request_received', transport: 'dns_tcp', ...observed, question: question.name, qtype: question.qtype });
      if (scenario === 'timeout' || scenario === 'cancel') {
        peerEvidence.push({ event: 'response_withheld', transport: 'dns_tcp', ...observed });
        if (scenario === 'cancel') onCancel?.({ transport: 'dns_tcp', ...observed });
        pending = Buffer.alloc(0);
        return;
      }
      const reply = frameDnsTcpMessage(responseForProbe(query, 'dns_tcp', observed));
      // Exercise TCP message accumulation, not just a single chunk/header.
      socket.write(reply.subarray(0, 4), () => socket.end(reply.subarray(4)));
      pending = Buffer.alloc(0);
    });
  });
  udp.on('message', (query, peer) => {
    assert.equal(peer.address, '127.0.0.1');
    const question = dnsQuestion(query);
    const observed = { ...deliveryDatagramIdentity(udp, peer), phase: 'dns_query', request_hex: query.toString('hex') };
    observedDatagrams.set(peer.port, observed);
    rows.push({ transport: 'dns_udp', ...observed, ...question, transaction_id: query.readUInt16BE(0), bytes: query.length });
    if (!probePorts.has(peer.port)) { udp.send(dnsResponse(query), peer.port, peer.address); return; }
    peerEvidence.push({ event: 'dns_request_received', transport: 'dns_udp', ...observed, question: question.name, qtype: question.qtype });
    if (scenario === 'timeout' || scenario === 'cancel') {
      peerEvidence.push({ event: 'response_withheld', transport: 'dns_udp', ...observed });
      if (scenario === 'cancel') onCancel?.({ transport: 'dns_udp', ...observed });
      return;
    }
    const reply = responseForProbe(query, 'dns_udp', observed);
    if (scenario === 'wrong_peer') {
      peerEvidence.push({ event: 'wrong_peer_response_sent', transport: 'dns_udp', ...observed, expected_port: udp.address().port, actual_port: wrongPeer.address().port,
        response_sender: deliveryDatagramIdentity(wrongPeer, peer), response_hex: reply.toString('hex') });
      wrongPeer.send(reply, peer.port, peer.address);
    } else udp.send(reply, peer.port, peer.address);
  });
  await new Promise((resolve) => udp.bind(0, '127.0.0.1', resolve));
  await new Promise((resolve) => wrongPeer.bind(0, '127.0.0.1', resolve));
  await new Promise((resolve) => tcp.listen(0, '127.0.0.1', resolve));
  const resolver = new dns.Resolver({ timeout: 500, tries: 1 });
  resolver.setServers([`127.0.0.1:${udp.address().port}`]);
  const resolutionCalls = [];
  const resolveLocal = (method) => async (name) => {
    assert.ok(name === 'grpc.test' || name.endsWith('.grpc.test'), `fixture refused public DNS: ${name}`);
    resolutionCalls.push({ method, name });
    try { return await resolver[method](name); }
    catch (error) { if (error.code === 'ENODATA') return []; throw error; }
  };
  // Fault-only adapter owns its actual UDP socket and obeys the operation signal.
  // Closure evidence is emitted only by that socket's close event, with the exact
  // received query/tuple. Independent expiry remains distinct from cancellation.
  // Positive/default resolution remains the native c-ares implementation above.
  const resolveProbe = (name, qtype, { signal } = {}) => new Promise((resolve, reject) => {
    assert.ok(name === 'grpc.test' || name.endsWith('.grpc.test'));
    if (signal?.aborted) { reject(signal.reason); return; }
    const socket = dgram.createSocket('udp4');
    const query = buildDnsQueryMessage(name, { qtype, recursionDesired: true });
    resolverClients.add(socket);
    const ownerEpoch = epoch;
    let closureCause = null; let clientPort;
    const expiresAt = Date.now() + 500;
    const close = (cause) => {
      if (closureCause !== null) return;
      closureCause = cause;
      socket.close();
    };
    const cancel = () => close('worker_cancel');
    const timer = setTimeout(() => { close('resolver_timeout'); reject(Object.assign(new Error('owned DNS resolver timeout'), { code: 'ETIMEOUT' })); }, 500);
    signal?.addEventListener('abort', cancel, { once: true });
    socket.once('close', () => {
      clearTimeout(timer); signal?.removeEventListener('abort', cancel); resolverClients.delete(socket);
      const observed = observedDatagrams.get(clientPort);
      if (ownerEpoch === epoch && observed) peerEvidence.push({ event: 'owned_client_socket_closed', transport: 'dns_udp', ...observed, closure_cause: closureCause, observed_at_ms: Date.now(), resolver_expires_at_ms: expiresAt });
      reject(Object.assign(new Error('owned DNS resolver closed'), { code: 'ECANCELLED' }));
    });
    socket.once('error', (error) => { close('resolver_error'); reject(error); });
    socket.once('message', (packet, peer) => {
      assert.equal(peer.address, '127.0.0.1'); assert.equal(peer.port, udp.address().port);
      assert.equal(packet.readUInt16BE(0), query.readUInt16BE(0));
      assert.deepEqual(dnsQuestion(packet), dnsQuestion(query));
      assert.ok(packet.readUInt16BE(2) & 0x8000);
      const rcode = packet.readUInt16BE(2) & 15;
      close('resolver_response');
      if (rcode === 3) reject(Object.assign(new Error('owned DNS NXDOMAIN'), { code: 'ENOTFOUND' }));
      else reject(Object.assign(new Error('fault-only resolver received unexpected non-negative response'), { code: 'EBADRESP' }));
    });
    socket.bind(0, '127.0.0.1', () => {
      clientPort = socket.address().port; probePorts.add(clientPort);
      socket.send(query, udp.address().port, '127.0.0.1');
    });
  });
  return {
    rows, resolutionCalls, peerEvidence,
    setScenario(value, cancel, kind) { epoch += 1; scenario = value; onCancel = cancel; probeKind = kind; peerEvidence.length = 0; probePorts.clear(); observedDatagrams.clear(); },
    port: udp.address().port,
    setTruncated(value) { truncateProbe = value; },
    deps: {
      resolve4Fn: resolveLocal('resolve4'), resolve6Fn: resolveLocal('resolve6'),
      resolveNsFn: (name, options) => probeKind === 'dns_failover_posture' && ['negative_dns', 'timeout', 'cancel'].includes(scenario) ? resolveProbe(name, 'NS', options) : resolveLocal('resolveNs')(name), resolveCnameFn: resolveLocal('resolveCname'),
      resolve4ExternalFn: async (address, name, options) => { assert.equal(address, '127.0.0.1'); return ['negative_dns', 'timeout', 'cancel'].includes(scenario) ? resolveProbe(name, 'A', options) : resolveLocal('resolve4')(name); },
      // Only the owned transport port changes; the signed query, expected peer, and
      // packet identity remain under the real worker/helper's control.
      createSocket(type) {
        assert.equal(type, 'udp4');
        const socket = dgram.createSocket(type);
        let clientPort;
        socket.once('listening', () => { clientPort = socket.address().port; probePorts.add(clientPort); });
        const ownerEpoch = epoch;
        socket.once('close', () => {
          const observed = observedDatagrams.get(clientPort);
          if (ownerEpoch === epoch && observed) peerEvidence.push({ event: 'owned_client_socket_closed', transport: 'dns_udp', ...observed, observed_at_ms: Date.now() });
        });
        const send = socket.send.bind(socket);
        socket.send = (packet, port, host, callback) => {
          assert.equal(host, '127.0.0.1');
          // dgram's implicit-bind queue re-enters socket.send with the already pinned port.
          assert.ok(port === 53 || port === udp.address().port);
          return send(packet, port === 53 ? udp.address().port : port, host, callback);
        };
        const on = socket.on.bind(socket);
        socket.on = (event, callback) => on(event, event === 'message' ? (packet, peer) => {
          assert.equal(peer.address, '127.0.0.1');
          assert.ok([udp.address().port, wrongPeer.address().port].includes(peer.port));
          // Preserve wrong-owned-peer identity; never rewrite it into an expected reply.
          callback(packet, { ...peer, port: peer.port === udp.address().port ? 53 : peer.port });
        } : callback);
        return socket;
      },
      connectFn(options, callback) {
        assert.equal(options.host, '127.0.0.1'); assert.equal(options.port, 53);
        return net.connect({ ...options, port: tcp.address().port }, callback);
      },
    },
    async close() {
      resolver.cancel(); for (const socket of clients) socket.destroy();
      for (const socket of resolverClients) socket.close();
      await Promise.all([new Promise((resolve) => udp.close(resolve)), new Promise((resolve) => wrongPeer.close(resolve)), new Promise((resolve) => tcp.close(resolve))]);
    },
  };
}
