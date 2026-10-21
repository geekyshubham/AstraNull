import './dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { randomBytes, createHash } from 'node:crypto';
import dgram from 'node:dgram';
import http from 'node:http';
import https from 'node:https';
import http2 from 'node:http2';
import net from 'node:net';
import tls from 'node:tls';
import { rmSync } from 'node:fs';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { buildSignedProbeJobRecord, verifyProbeJobSignature } from '../../src/lib/probeJobs.mjs';
import { deriveRunEvidenceStamp } from '../../src/lib/checkDefinitionVersion.mjs';
import { probeExecutionEvidenceReceipt } from '../../src/lib/probeExecution.mjs';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { getStore } from '../../src/store.mjs';
import { startTestRun, finalizeTestRun, maybeFinalizeRunAfterProbeIngest } from '../../src/services/testRuns.mjs';
import { listPendingProbeJobsForWorker, reserveProbeExecution, ingestProbeResult } from '../../src/services/probeCoordinator.mjs';
import { computeReadiness } from '../../src/services/readiness.mjs';
import { createOriginBinding } from '../../src/services/originBindings.mjs';
import { RISKY_ADMIN_PORTS } from '../../src/lib/capabilityProbes.mjs';
import { BENIGN_CLASS_MARKERS } from '../../src/lib/inertWafMarkers.mjs';
import { executeProbeForJob, buildResultBody } from '../../workers/probe-worker.mjs';
import { CHECK_DELIVERY_INVENTORY, deliveryFingerprint, OWNED_INVALID_TLS_REPLY_HEX } from '../fixtures/check-delivery-coverage.mjs';
import { createTlsFixture } from '../unit/protocol-transport-socket.fixture.mjs';
import { freshStore } from './reset.mjs';
import { createDeliveryDnsFixture, dnsQuestion, dnsResponse } from './check-delivery-dns-fixture.mjs';
import { deliverySocketIdentity, deliveryDatagramIdentity } from './check-delivery-peer-identity.mjs';

export const DELIVERY_WORKER_SECRET = randomBytes(32).toString('base64url');
export const DELIVERY_CTX = Object.freeze({ tenantId: 'ten_demo', userId: 'delivery-test', role: 'admin' });
export const DELIVERY_WORKER_CTX = Object.freeze({ tenantId: 'ten_demo', workerId: 'delivery-local-worker' });
export const DELIVERY_RUNTIME = loadRuntimeConfig({ NODE_ENV: 'test', ASTRANULL_NO_PERSIST: '1', ASTRANULL_PROBE_MODE: 'signed-worker', ASTRANULL_PROBE_WORKER_SECRET: DELIVERY_WORKER_SECRET });
const byCheck = new Map(CHECK_DELIVERY_INVENTORY.rows.map((row) => [row.check_id, row]));
let invocation = 0;
const listen = (server) => new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => resolve(server.address().port)); });
const close = (server) => new Promise((resolve) => server.close(resolve));
function serializedProbePart(marker) {
  const url = new URL('http://x.invalid/');
  url.search = `probe=${encodeURIComponent(marker)}`;
  return url.search.replace(/^\?/, '').split('&')[0];
}
const REFERENCE_PROBE_PARTS = new Set(Object.values(BENIGN_CLASS_MARKERS).map(serializedProbePart));

function stripCacheBuster(url) {
  const [path, qs] = String(url ?? '').split('?');
  if (qs == null) return String(url ?? '');
  const kept = qs.split('&').filter((part) => part && !part.startsWith('an_cb=')).join('&');
  return kept ? `${path}?${kept}` : path;
}

function requestCarriesMarker(request) {
  if (request.headers['x-astranull-marker']) return true;
  const ua = request.headers['user-agent'] ?? '';
  if (/sqlmap/i.test(ua) || /astranull-inert/i.test(ua)) return true;
  if (request.headers.cookie && /astranull/i.test(request.headers.cookie)) return true;
  const stripped = stripCacheBuster(request.url || '');
  const qIndex = stripped.indexOf('?');
  const path = qIndex === -1 ? stripped : stripped.slice(0, qIndex);
  const query = qIndex === -1 ? '' : stripped.slice(qIndex + 1);
  if (/(?:^|&)probe=/.test(query)) return true;
  if (/astranull_/i.test(query) || /astranull/i.test(path)) return true;
  return false;
}

function requestIsEvasionTransform(request) {
  if (!requestCarriesMarker(request)) return false;
  if (request.headers.cookie) return true;
  const query = stripCacheBuster(request.url || '').split('?')[1] || '';
  const parts = query.split('&').filter(Boolean);
  if (parts.includes('probe=astranull-permitted')) return true;
  if (parts.some((part) => part.startsWith('probe=') && !REFERENCE_PROBE_PARTS.has(part))) return true;
  return false;
}

export function catalogSignedJob(check, target = { id: 'tgt_delivery', kind: 'fqdn', value: 'grpc.test' }, override = null) {
  const now = new Date(); const id = ++invocation;
  const stamp = deriveRunEvidenceStamp(check, {}, { probeMode: 'signed-worker' });
  return buildSignedProbeJobRecord({
    run: { id: `run_delivery_${id}`, tenant_id: DELIVERY_CTX.tenantId, created_at: now.toISOString(), safety_constraints: { ...check.safety_constraints, check_version: stamp.check_version, scenario_version: stamp.scenario_version }, provenance_json: stamp },
    check, target, probeProfile: override, probeWorkerSecret: DELIVERY_WORKER_SECRET, now, newId: () => `pj_delivery_${id}`,
  });
}

function reflectionReply(profile, request) {
  if (profile === 'memcached_udp_stats') {
    const header = Buffer.alloc(8); request.copy(header, 0, 0, 2); header.writeUInt16BE(1, 4);
    return Buffer.concat([header, Buffer.from('STAT fixture local-owned-response\r\nEND\r\n')]);
  }
  if (profile === 'stun_binding_request') { const reply = Buffer.from(request); reply.writeUInt16BE(0x0101, 0); return reply; }
  if (profile === 'ntp_mode6_readvar') { const reply = Buffer.from(request.subarray(0, 12)); reply[1] |= 0x80; reply.writeUInt16BE(0, 10); return reply; }
  if (profile === 'coap_get_wellknown') { const reply = Buffer.from(request.subarray(0, 4)); reply[0] = 0x60; reply[1] = 0x45; return reply; }
  if (profile === 'ssdp_msearch') return Buffer.from('HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nUSN: uuid:12345678-1234-1234-1234-123456789012::upnp:rootdevice\r\n\r\n');
  if (profile === 'snmp_v2c_get_sysdescr') {
    const reply = Buffer.from(request); const pdu = reply.indexOf(0xa0); assert.ok(pdu > 0); reply[pdu] = 0xa2;
    assert.equal(reply[reply.length - 2], 5); reply[reply.length - 2] = 4; return reply;
  }
  if (['mdns_ptr_query', 'netbios_nbstat'].includes(profile)) {
    try {
      const q = dnsQuestion(request); const fixed = Buffer.alloc(10); fixed.writeUInt16BE(q.qtype, 0); fixed.writeUInt16BE(1, 2); fixed.writeUInt16BE(1, 8);
      const header = Buffer.from(request.subarray(0, 12)); header.writeUInt16BE(0x8000, 2); header.writeUInt16BE(1, 6);
      return Buffer.concat([header, request.subarray(12, q.end), Buffer.from([0xc0, 0x0c]), fixed, Buffer.from([0])]);
    } catch {
      return Buffer.from('owned fixture response; identity deliberately not established');
    }
  }
  if (profile === 'portmap_dump') {
    const reply = Buffer.alloc(32); reply.writeUInt32BE(0x8000001c, 0); request.copy(reply, 4, 4, 8); reply.writeUInt32BE(1, 8); return reply;
  }
  // These shipped transports intentionally have no supported message-identity
  // classifier. A real received packet must remain not_run, never byte-count proof.
  return Buffer.from('owned fixture response; identity deliberately not established');
}

export async function createCheckDeliveryFixtures() {
  const cert = createTlsFixture({ includeLoopbackIp: true });
  const dnsFixture = await createDeliveryDnsFixture();
  const rows = []; const routes = []; const peerEvidence = [];
  const sockets = new Set(); const sessions = new Set();
  let activeCheck = null; let ordinal = 0; let mode = 'success'; let cancellation; let epoch = 0;
  const connectionPhases = new Map(); const observedDatagrams = new Map();
  const socketEvidence = (socket, phase = 'request') => {
    const identity = deliverySocketIdentity(socket);
    connectionPhases.set(identity.connection_id, phase);
    return { ...identity, phase };
  };
  const cancelFromPeer = (evidence) => {
    peerEvidence.push({ event: 'cancel_requested', ...evidence, observed_at_ms: Date.now(), source: 'owned_peer_after_actual_request' });
    cancellation.abort();
  };
  const track = (socket) => {
    const ownerEpoch = epoch;
    const identity = deliverySocketIdentity(socket); // Snapshot while the endpoint is observable.
    sockets.add(socket);
    socket.once('close', () => {
      sockets.delete(socket);
      if (ownerEpoch === epoch) peerEvidence.push({ event: 'owned_peer_socket_closed', transport: 'tcp', ...identity, phase: connectionPhases.get(identity.connection_id), observed_at_ms: Date.now() });
    });
    socket.on('error', () => {});
  };
  function respond(request, response) {
    ordinal += 1;
    const identity = socketEvidence(request.socket);
    rows.push({ transport: request.socket.encrypted ? 'https' : 'http', ...identity, method: request.method, url: request.url, host: request.headers.host, servername: request.socket.servername ?? null, peer_address: request.socket.remoteAddress, peer_port: request.socket.remotePort, nonce: request.headers['x-astranull-nonce'], nonce_hash: request.headers['x-astranull-nonce-hash'], marker: request.headers['x-astranull-marker'], cookie: request.headers.cookie, bytes: 0, request_headers: { ...request.headers } });
    const endpointEvidence = { transport: request.socket.encrypted ? 'https' : 'http', ...identity, method: request.method, path: request.url };
    peerEvidence.push({ event: 'request_received', ...endpointEvidence });
    if (mode === 'timeout') { peerEvidence.push({ event: 'response_withheld', ...endpointEvidence }); return; }
    if (mode === 'cancel') { cancelFromPeer(endpointEvidence); return; }
    if (mode === 'error' || mode === 'peer_error') { peerEvidence.push({ event: 'peer_reset', ...endpointEvidence }); request.socket.destroy(); return; }
    const semantic = ['waf_class_marker_probe', 'waf_evasion_marker_probe'].includes(activeCheck?.probe_profile?.kind);
    const entryPermittedHead = activeCheck?.probe_profile?.entry_path_scenario && request.method === 'HEAD'
      && !request.headers['x-astranull-marker'] && !request.url.includes('_probe=');
    const marker = requestCarriesMarker(request);
    const transformed = activeCheck?.probe_profile?.kind === 'waf_evasion_marker_probe' && requestIsEvasionTransform(request);
    const deny = semantic && !entryPermittedHead && (mode === 'permitted_unhealthy' || (marker && !(mode === 'variant_allowed' && transformed)));
    if (mode === 'challenged' && marker) {
      response.statusCode = 403;
      response.setHeader('cf-mitigated', 'challenge');
    } else if (mode === 'partial' && transformed) {
      response.statusCode = 503;
    } else if (deny) {
      response.statusCode = 403;
      if (!['variant_unsigned', 'unsigned_denial'].includes(mode)) response.setHeader('x-waf-block', '1');
    } else {
      response.statusCode = 200;
    }
    response.setHeader('Alt-Svc', 'h3=":443"; ma=60');
    response.setHeader('Access-Control-Allow-Origin', '*');
    response.setHeader('X-RateLimit-Limit', '10');
    peerEvidence.push({ event: 'response_sent', ...endpointEvidence,
      request_ordinal: ordinal, request_phase: transformed ? 'transform' : marker ? 'reference' : ordinal === 1 ? 'permitted' : 'clean_control',
      status: response.statusCode, headers: { ...response.getHeaders() }, local_address: request.socket.localAddress, local_port: request.socket.localPort });
    response.end(request.method === 'HEAD' ? undefined : '{"data":{"fixture":true}}');
  }
  const httpServer = http.createServer({ maxHeaderSize: 16384 }, respond);
  const httpsServer = https.createServer({ key: cert.key, cert: cert.cert, maxHeaderSize: 16384 }, respond);
  for (const server of [httpServer, httpsServer]) {
    server.on('clientError', (err, socket) => {
      if (err.code === 'HPE_INVALID_METHOD' && err.rawPacket) {
        const line = String(err.rawPacket).split('\r\n')[0] ?? '';
        const [method, urlPath] = line.split(' ');
        const transport = socket.encrypted ? 'https' : 'http';
        rows.push({
          transport, ...socketEvidence(socket), method, url: urlPath, host: null, servername: socket.servername ?? null,
          peer_address: socket.remoteAddress, peer_port: socket.remotePort,
          nonce: null, nonce_hash: null, marker: null, cookie: null, bytes: 0, request_headers: {},
        });
        peerEvidence.push({ event: 'request_received', transport, ...socketEvidence(socket), method, path: urlPath });
        socket.end('HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n');
        return;
      }
      socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    });
    server.on('connection', (socket) => {
      track(socket);
      if (activeCheck?.probe_profile?.kind === 'slow_header_probe') {
        socket.once('data', (packet) => {
          const observed = { ...socketEvidence(socket), request_hex: packet.toString('hex') };
          rows.push({ transport: 'slow_header_connection', ...observed });
          peerEvidence.push({ event: 'request_received', transport: 'slow_header', ...observed });
          if (mode === 'cancel') cancelFromPeer({ transport: 'slow_header', ...observed });
          else if (mode === 'timeout') peerEvidence.push({ event: 'response_withheld', transport: 'slow_header', ...observed });
          else if (mode === 'peer_error') {
            peerEvidence.push({ event: 'peer_reset', transport: 'slow_header', ...observed });
            socket.resetAndDestroy();
          } else {
            const timer = setTimeout(() => socket.destroy(), 40);
            socket.once('close', () => clearTimeout(timer));
          }
        });
      }
    });
    server.on('clientError', (err, socket) => {
      if (err?.code === 'HPE_INVALID_METHOD' && activeCheck?.probe_profile?.kind === 'waf_method_policy_probe') {
        const raw = String(err.rawPacket ?? '');
        const [start, ...headerLines] = raw.split('\r\n');
        const [method, url] = start.split(' ');
        const request_headers = {};
        for (const line of headerLines) {
          const idx = line.indexOf(':');
          if (idx > 0) request_headers[line.slice(0, idx).toLowerCase()] = line.slice(idx + 1).trim();
        }
        rows.push({
          transport: socket?.encrypted ? 'https' : 'http',
          method,
          url: url || '/',
          host: request_headers.host,
          request_headers,
        });
      }
      if (socket?.writable && !socket.writableEnded) {
        socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      }
    });
    server.on('upgrade', (request, socket) => {
      const observed = { ...socketEvidence(socket), method: request.method, path: request.url };
      rows.push({ transport: 'websocket_upgrade', ...observed, url: request.url, host: request.headers.host, nonce_hash: request.headers['x-astranull-nonce-hash'], request_headers: { ...request.headers } });
      peerEvidence.push({ event: 'upgrade_received', transport: 'websocket', ...observed });
      if (mode === 'timeout') { peerEvidence.push({ event: 'response_withheld', transport: 'websocket', ...observed }); return; }
      if (mode === 'cancel') {
        // Upgraded sockets are half-open and unmanaged; observe the client's FIN before closing our side.
        socket.once('end', () => socket.destroy());
        socket.resume();
        cancelFromPeer({ transport: 'websocket', ...observed });
        return;
      }
      const accept = mode === 'invalid_upgrade' ? 'invalid-owned-peer-accept' : createHash('sha1').update(`${request.headers['sec-websocket-key']}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');
      peerEvidence.push({ event: mode === 'invalid_upgrade' ? 'invalid_upgrade_sent' : 'valid_upgrade_sent', transport: 'websocket', ...observed, accept });
      socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`); socket.resume();
    });
  }
  const h2Server = http2.createSecureServer({ key: cert.key, cert: cert.cert, settings: { maxConcurrentStreams: 7, headerTableSize: 1024, maxHeaderListSize: 8192, enablePush: false } });
  h2Server.on('session', (session) => {
    sessions.add(session); session.once('close', () => sessions.delete(session)); session.on('error', () => {});
    session.on('ping', (payload) => rows.push({ transport: 'h2_ping', payload_hex: payload.toString('hex') }));
  });
  h2Server.on('secureConnection', (socket) => { track(socket); rows.push({ transport: 'h2_tls_session', servername: socket.servername, alpn: socket.alpnProtocol }); });
  h2Server.on('stream', (stream, headers) => {
    const identity = socketEvidence(stream.session.socket);
    rows.push({ transport: 'h2_stream_open', ...identity, method: headers[':method'], path: headers[':path'], authority: headers[':authority'] });
    stream.once('close', () => rows.push({ transport: 'h2_stream_close', rst_code: stream.rstCode }));
    stream.on('error', () => {});
    const chunks = [];
    stream.on('data', (chunk) => chunks.push(chunk));
    stream.on('end', () => {
      const observed = { ...identity, request_hex: Buffer.concat(chunks).toString('hex') };
      rows.push({ transport: 'h2_stream', ...identity, method: headers[':method'], path: headers[':path'], authority: headers[':authority'], content_type: headers['content-type'], request_body_hex: observed.request_hex });
      if (stream.destroyed || stream.closed) return;
      // The existing bounded reset probe needs an open real peer stream to cancel,
      // not a completed 204 response that races its single permitted CANCEL.
      if (activeCheck?.probe_profile?.kind === 'http2_frame_probe') return;
      if (headers['content-type'] === 'application/grpc') {
        peerEvidence.push({ event: 'grpc_request_received', transport: 'h2', ...observed });
        if (mode === 'timeout') { peerEvidence.push({ event: 'response_withheld', transport: 'grpc', ...observed }); return; }
        if (mode === 'cancel') { cancelFromPeer({ transport: 'grpc', ...observed }); return; }
        stream.respond({ ':status': 200, 'content-type': 'application/grpc' }, { waitForTrailers: true });
        stream.once('wantTrailers', () => stream.sendTrailers({ 'grpc-status': mode === 'unimplemented' ? '12' : '0', 'grpc-message': 'fixture-owned' }));
        const response = mode === 'malformed_response' ? Buffer.from([0, 0, 0, 0, 99, 0]) : mode === 'unimplemented' ? Buffer.alloc(0) : Buffer.from([0, 0, 0, 0, 6, 0x12, 2, 0x3a, 0, 0x32, 0]);
        peerEvidence.push({ event: 'grpc_response_sent', transport: 'h2', ...observed, response_hex: response.toString('hex'), grpc_status: mode === 'unimplemented' ? '12' : '0' });
        stream.end(response);
      } else { stream.respond({ ':status': 204 }); stream.end(); }
    });
  });
  // A genuine TLS handshake and h2 ALPN precede this invalid SETTINGS frame.
  // An invalid TLS record cannot stand in for a post-TLS HTTP/2 protocol fault.
  const invalidH2Server = tls.createServer({ key: cert.key, cert: cert.cert, ALPNProtocols: ['h2'] }, (socket) => {
    const identity = socketEvidence(socket);
    rows.push({ transport: 'h2_tls_session', ...identity, servername: socket.servername, alpn: socket.alpnProtocol });
    let pending = Buffer.alloc(0); let handled = false;
    socket.on('data', (chunk) => {
      pending = Buffer.concat([pending, chunk]);
      if (pending.length < 24 || socket.writableEnded || handled) return;
      assert.equal(socket.alpnProtocol, 'h2');
      assert.equal(pending.subarray(0, 24).toString(), 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
      handled = true;
      const observed = { ...identity, alpn: socket.alpnProtocol, tls_protocol: socket.getProtocol(), request_hex: pending.toString('hex') };
      rows.push({ transport: 'h2_client_preface', ...observed });
      if (mode === 'timeout' || mode === 'cancel') {
        peerEvidence.push({ event: 'response_withheld', transport: 'h2', ...observed });
        if (mode === 'cancel') cancelFromPeer({ transport: 'h2', ...observed });
        return; // Actual TLS+ALPN and preface succeeded; withhold server SETTINGS.
      }
      const frame = Buffer.from([0, 0, 1, 4, 0, 0, 0, 0, 0, 0]); // SETTINGS length must be a multiple of six.
      peerEvidence.push({ event: 'malformed_h2_sent', transport: 'h2', ...observed, response_hex: frame.toString('hex') });
      socket.end(frame);
    });
  });
  invalidH2Server.on('connection', track);
  invalidH2Server.on('tlsClientError', () => {});
  const tlsServer = tls.createServer({ key: cert.key, cert: cert.cert }, (socket) => { rows.push({ transport: 'tls_session', servername: socket.servername, protocol: socket.getProtocol() }); socket.end(); });
  tlsServer.on('connection', track);
  const tcpServer = net.createServer((socket) => {
    track(socket); rows.push({ transport: 'tcp_connect' });
    peerEvidence.push({ event: 'connection_received', transport: 'tcp' });
    if (mode === 'timeout' || mode === 'cancel') {
      socket.once('data', (request) => {
        const reflection = activeCheck?.probe_profile?.kind === 'reflection_service_probe';
        const observed = { ...socketEvidence(socket, reflection ? 'request' : 'tls_handshake'), request_hex: request.toString('hex') };
        rows.push(reflection
          ? { transport: 'reflection_tcp', payload_profile: activeCheck.probe_profile.payload_profile, ...observed }
          : { transport: 'raw_protocol_input', ...observed });
        peerEvidence.push({ event: 'response_withheld', transport: reflection ? 'reflection_tcp' : 'tcp', ...observed });
        if (mode === 'cancel') cancelFromPeer({ transport: reflection ? 'reflection_tcp' : 'tcp', ...observed });
      });
      return;
    }
    if (mode === 'invalid_tls') {
      socket.once('data', (request) => {
        const observed = { ...socketEvidence(socket, 'tls_handshake'), request_hex: request.toString('hex') };
        rows.push({ transport: 'raw_protocol_input', ...observed });
        const reply = Buffer.from(OWNED_INVALID_TLS_REPLY_HEX, 'hex');
        peerEvidence.push({ event: 'malformed_tls_sent', transport: 'tcp', ...observed, response_hex: reply.toString('hex') });
        socket.end(reply);
      });
      return;
    }
    if (activeCheck?.probe_profile?.kind === 'reflection_service_probe') socket.once('data', (request) => {
      const observed = { ...socketEvidence(socket), request_hex: request.toString('hex') };
      rows.push({ transport: 'reflection_tcp', payload_profile: activeCheck.probe_profile.payload_profile, ...observed });
      peerEvidence.push({ event: 'request_received', transport: 'reflection_tcp', ...observed });
      socket.end(mode === 'unconfirmed_response' ? Buffer.from('owned invalid identity') : reflectionReply(activeCheck.probe_profile.payload_profile, request));
    }); else socket.end();
  });
  const udpServer = dgram.createSocket('udp4');
  udpServer.on('message', (request, peer) => {
    assert.equal(peer.address, '127.0.0.1');
    const observed = { ...deliveryDatagramIdentity(udpServer, peer), phase: 'datagram', request_hex: request.toString('hex') };
    observedDatagrams.set(peer.port, observed);
    rows.push({ transport: 'udp', payload_profile: activeCheck?.probe_profile?.payload_profile ?? null, ...observed });
    peerEvidence.push({ event: 'request_received', transport: 'udp', ...observed });
    if (mode === 'timeout') { peerEvidence.push({ event: 'response_withheld', transport: 'udp', ...observed }); return; }
    if (mode === 'cancel') { cancelFromPeer({ transport: 'udp', ...observed }); return; }
    udpServer.send(mode === 'unconfirmed_response' ? Buffer.from('owned invalid identity') : activeCheck?.probe_profile?.kind === 'reflection_service_probe' ? reflectionReply(activeCheck.probe_profile.payload_profile, request) : Buffer.from('ASTRANULL:owned-udp-fixture'), peer.port, peer.address);
  });
  const [httpPort, httpsPort, h2Port, tlsPort, tcpPort, invalidH2Port] = await Promise.all([httpServer, httpsServer, h2Server, tlsServer, tcpServer, invalidH2Server].map(listen));
  await new Promise((resolve) => udpServer.bind(0, '127.0.0.1', resolve));
  const udpPort = udpServer.address().port;
  const ports = { http: httpPort, https: httpsPort, h2: h2Port, tls: tlsPort, tcp: tcpPort, udp: udpPort };

  function forCheck(check, { targetKind, scenario = 'success', timeoutMs } = {}) {
    epoch += 1;
    activeCheck = check; ordinal = 0; mode = scenario; cancellation = new AbortController();
    rows.length = 0; routes.length = 0; peerEvidence.length = 0; dnsFixture.rows.length = 0; dnsFixture.resolutionCalls.length = 0;
    connectionPhases.clear(); observedDatagrams.clear();
    dnsFixture.setScenario?.(scenario, cancelFromPeer, check.probe_profile?.kind);
    const kind = check.probe_profile?.kind;
    const dnsKind = ['dns_wire_query', 'dnssec_posture', 'dns_axfr_leak', 'dns_open_recursion', 'dns_failover_posture', 'dns_resolve'].includes(kind);
    const tlsKind = ['tls_session', 'tls_audit'].includes(kind);
    const h2Kind = ['http2_settings', 'http2_frame_probe', 'grpc_reflection_probe'].includes(kind);
    const udpKind = ['udp_probe', 'reflection_service_probe'].includes(kind) && check.probe_profile?.payload_profile !== 'portmap_dump';
    const tcpKind = kind === 'tcp_connect' || kind === 'port_scan_bounded' || kind === 'connection_limit_probe' || (kind === 'reflection_service_probe' && !udpKind);
    const primary = targetKind ?? (check.supported_targets.includes('url') ? 'url' : check.supported_targets.includes('fqdn') ? 'fqdn' : check.supported_targets[0]);
    const rawTlsFault = tlsKind && ['timeout', 'cancel', 'invalid_tls'].includes(scenario);
    const h2Fault = h2Kind && kind !== 'grpc_reflection_probe' && ['invalid_h2', 'timeout', 'cancel'].includes(scenario);
    const protocolPort = h2Fault ? invalidH2Port : rawTlsFault ? tcpPort : tlsKind ? tlsPort : h2Kind ? h2Port : udpKind ? udpPort : tcpKind ? tcpPort : httpsPort;
    const urlProtocol = ['http3_control_probe', 'quic_reachability', 'tls_session', 'tls_audit', 'http2_settings', 'http2_frame_probe', 'grpc_reflection_probe'].includes(kind) ? 'https' : 'http';
    const target = {
      id: 'tgt_1', tenant_id: DELIVERY_CTX.tenantId, target_group_id: 'tg_1', kind: primary,
      value: primary === 'url' || primary === 'canary' ? `${urlProtocol}://grpc.test:${urlProtocol === 'http' ? httpPort : protocolPort}/signed/path?keep=1` : primary === 'ip' ? '127.0.0.1' : 'grpc.test',
      expected_behavior: check.default_expected_behavior ?? 'must_block_before_origin',
      ...(!dnsKind && (tlsKind || h2Kind || udpKind || tcpKind || primary === 'url') ? { port: primary === 'url' && urlProtocol === 'http' ? httpPort : protocolPort } : {}),
    };
    const logicalHost = () => ['url', 'canary'].includes(target.kind) ? new URL(target.value).hostname : target.value;
    const endpointPort = (secure) => kind === 'origin_leak_scan' ? secure ? 443 : 80 : ['url', 'canary'].includes(target.kind) ? Number(new URL(target.value).port) || (secure ? 443 : 80) : secure ? 443 : 80;
    const route = (transport, options, fixturePort) => routes.push({ transport, requested_host: options.host ?? options.hostname, requested_port: Number(options.port), requested_servername: options.servername ?? null, fixture_host: '127.0.0.1', fixture_port: fixturePort, mapping: Number(options.port) === fixturePort ? 'unchanged' : 'owned_transport_pin_not_production_port_proof' });
    const deps = { ...dnsFixture.deps, destinationPolicy: { allowLoopback: true }, tlsCa: cert.cert, cancellationSignal: cancellation.signal };
    deps.httpsRequestFn = (options, callback) => {
      assert.equal(options.hostname, '127.0.0.1');
      assert.equal(Number(options.port || 443), endpointPort(true));
      if (options.servername != null) assert.equal(options.servername, deps.expectedOriginScope?.host ?? (logicalHost() === '127.0.0.1' ? undefined : logicalHost()));
      const mapped = Number(options.port || 443) === 443 ? httpsPort : Number(options.port);
      route('https', { ...options, port: Number(options.port || 443) }, mapped);
      // Each scenario owns its sockets; keep-alive reuse would retain a prior epoch.
      return https.request({ ...options, port: mapped, ca: cert.cert, agent: false }, callback);
    };
    deps.httpRequestFn = (options, callback) => {
      assert.equal(options.hostname, '127.0.0.1');
      assert.equal(Number(options.port || 80), endpointPort(false));
      const mapped = Number(options.port || 80) === 80 ? httpPort : Number(options.port);
      route('http', { ...options, port: Number(options.port || 80) }, mapped);
      return http.request({ ...options, port: mapped, agent: false }, callback);
    };
    if (!dnsKind) {
      deps.createSocket = (type) => {
        assert.equal(type, 'udp4');
        const socket = dgram.createSocket(type);
        const send = socket.send.bind(socket);
        const connect = socket.connect.bind(socket);
        const ownerEpoch = epoch;
        let connected = null; let clientPort;
        socket.once('listening', () => { clientPort = socket.address().port; });
        socket.once('close', () => {
          const observed = observedDatagrams.get(clientPort);
          if (ownerEpoch === epoch && observed) peerEvidence.push({ event: 'owned_client_socket_closed', transport: 'udp', ...observed, observed_at_ms: Date.now() });
        });
        socket.connect = (port, host, callback) => {
          assert.equal(host, '127.0.0.1');
          assert.equal(Number(port), target.port);
          connected = { host, port: Number(port) };
          return connect(port, host, callback);
        };
        socket.send = (packet, port, host, callback) => {
          if (typeof port === 'function' || (connected && host == null && typeof port !== 'number')) {
            callback = typeof port === 'function' ? port : callback;
            assert.equal(connected?.host, '127.0.0.1');
            assert.equal(Number(connected?.port), target.port);
            route('udp', connected, connected.port);
            return send(packet, callback);
          }
          assert.equal(host, '127.0.0.1'); assert.equal(Number(port), target.port);
          route('udp', { host, port }, Number(port));
          return send(packet, port, host, callback);
        };
        return socket;
      };
      deps.connectFn = (options, callback) => {
        assert.equal(options.host, '127.0.0.1');
        if (tlsKind) {
          assert.equal(Number(options.port), target.port);
          assert.equal(options.servername ?? null, logicalHost() === '127.0.0.1' ? null : logicalHost());
          route('tls', options, Number(options.port));
          return tls.connect({ ...options, ca: cert.cert }, callback);
        }
        if (kind === 'slow_header_probe') {
          const secure = !(primary === 'url' && urlProtocol === 'http');
          assert.equal(Number(options.port), endpointPort(secure));
          if (secure) assert.equal(options.servername, logicalHost());
          const mapped = Number(options.port) === (secure ? 443 : 80) ? secure ? httpsPort : httpPort : Number(options.port);
          route('slow_header', options, mapped);
          return (secure ? tls.connect : net.connect)({ ...options, port: mapped, ca: cert.cert }, callback);
        }
        if (kind === 'port_scan_bounded') {
          assert.ok((check.probe_profile.ports ?? RISKY_ADMIN_PORTS).includes(Number(options.port)), `unapproved scanned port ${options.port}`);
          route('bounded_port_scan', options, tcpPort);
          return net.connect({ ...options, port: tcpPort }, callback);
        }
        assert.equal(Number(options.port), target.port);
        route('tcp', options, Number(options.port));
        return net.connect(options, callback);
      };
    }
    if (h2Kind) {
      const connectTls = (options) => {
        assert.equal(options.host, '127.0.0.1');
        assert.equal(Number(options.port), endpointPort(true));
        assert.equal(options.servername ?? null, logicalHost() === '127.0.0.1' ? null : logicalHost());
        const mapped = Number(options.port) === 443 ? h2Port : Number(options.port);
        route('h2_tls', options, mapped);
        return tls.connect({ ...options, port: mapped, ca: cert.cert, ALPNProtocols: ['h2'] });
      };
      deps.tlsConnectFn = connectTls;
      deps.http2ConnectFn = (authority, options) => {
        const parsed = new URL(authority);
        assert.equal(parsed.hostname, logicalHost());
        assert.equal(Number(parsed.port || 443), endpointPort(true));
        return http2.connect(authority, { ...options, createConnection: () => connectTls({ host: '127.0.0.1', port: Number(parsed.port || 443), ...(parsed.hostname === '127.0.0.1' ? {} : { servername: parsed.hostname }) }) });
      };
      // http2_settings calls connectFn rather than http2ConnectFn.
      if (kind === 'http2_settings') deps.connectFn = (authority, options) => http2.connect(authority, options);
    }
    if (kind === 'dns_failover_posture') target.metadata_json = { secondary_nameservers: ['grpc.test'] };
    if (kind === 'connection_limit_probe') {
      target.metadata_json = {
        ...(target.metadata_json ?? {}),
        control_declarations: {
          version: 1,
          connection_limits: [{ protocol: 'tcp', port: tcpPort, max_connections_per_source: 1 }],
        },
      };
    }
    if (kind === 'rate_limit_canary_probe') {
      const canaryPath = ['url', 'canary'].includes(target.kind) ? (new URL(target.value).pathname || '/') : '/signed/path';
      target.metadata_json = {
        ...(target.metadata_json ?? {}),
        control_declarations: {
          version: 1,
          waf: { rate_limit_canary: { path: canaryPath, method: 'GET', threshold: 3, window_seconds: 10 } },
        },
      };
    }
    return {
      target, deps, timeoutMs,
      wire: () => [...rows, ...dnsFixture.rows], routes: () => structuredClone(routes),
      peerEvidence: () => structuredClone([...peerEvidence, ...(dnsFixture.peerEvidence ?? [])]),
      async waitForCancelledSocketClose({ closureCause, timeoutMs = 500 } = {}) {
        assert.ok(Number.isInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 1000, 'owned closure wait must remain bounded');
        const deadline = Date.now() + timeoutMs;
        const observedClose = () => {
          const evidence = [...peerEvidence, ...(dnsFixture.peerEvidence ?? [])];
          return evidence.some((row) => ['owned_peer_socket_closed', 'owned_client_socket_closed'].includes(row.event)
            && (closureCause === undefined || (row.closure_cause === closureCause && evidence.some((requested) => requested.event === 'cancel_requested'
              && requested.connection_id === row.connection_id && requested.phase === row.phase))));
        };
        while (!observedClose()) {
          assert.ok(Date.now() < deadline, `${check.check_id}: cancellation settled without actual ${closureCause ?? 'owned'} socket close`);
          await new Promise((resolve) => setTimeout(resolve, 5));
        }
      },
      resolverCalls: () => [...dnsFixture.resolutionCalls], ports, dnsFixture,
      async waitForWire(outcome) {
        if (dnsKind || (outcome.probe_requests_sent ?? outcome.requests_sent ?? 0) === 0) return;
        const expected = tlsKind ? 'tls_session' : h2Kind ? 'h2_tls_session' : tcpKind ? 'tcp_connect' : kind === 'slow_header_probe' ? 'slow_header_connection' : null;
        if (!expected || !['connected', 'blocked', 'not_run'].includes(outcome.external_result)) return;
        const required = [(row) => row.transport === expected];
        if (kind === 'http2_frame_probe' && outcome.metadata?.ping_rtt_ms != null) required.push((row) => row.transport === 'h2_ping');
        if (kind === 'http2_frame_probe' && outcome.metadata?.reset_accepted === true) required.push((row) => row.transport === 'h2_stream_close' && row.rst_code === http2.constants.NGHTTP2_CANCEL);
        const deadline = Date.now() + 1000;
        while (!required.every((matches) => rows.some(matches))) {
          assert.ok(Date.now() < deadline, `${check.check_id}: owned peer never recorded ${expected} and claimed frame actions`);
          await new Promise((resolve) => setTimeout(resolve, 5));
        }
      },
    };
  }
  return {
    forCheck, ports, rows, dnsFixture,
    async close() {
      for (const session of sessions) session.destroy(); for (const socket of sockets) socket.destroy();
      await Promise.all([httpServer, httpsServer, h2Server, tlsServer, tcpServer, invalidH2Server].map(close));
      await new Promise((resolve) => udpServer.close(resolve)); await dnsFixture.close();
      rmSync(cert.dir, { recursive: true, force: true });
    },
  };
}

export function prepareMemoryDelivery(check, target, profileOverride = null, originScope = null) {
  freshStore(); const store = getStore();
  store.targets[0] = { ...target, tenant_id: DELIVERY_CTX.tenantId, target_group_id: 'tg_1' };
  store.targetGroups[0].safety_policy = { min_seconds_between_runs: 0, max_runs_per_hour: 100 };
  store.targetVerifications = [{ id: 'tv_delivery_owned', tenant_id: DELIVERY_CTX.tenantId, target_id: target.id, state: 'dns_verified', source_kind: 'dns_txt', source_ref: { dns_challenge_id: 'owned-local-fixture' }, transitioned_at: new Date().toISOString(), transitioned_by: 'system' }];
  let bindingId = null;
  if (originScope) {
    store.targets.push({ id: 'tgt_delivery_protected', tenant_id: DELIVERY_CTX.tenantId, target_group_id: 'tg_1', kind: 'fqdn', value: originScope.host,
      declaration_json: { allowed_scope: { ports: [originScope.port], paths: [originScope.path] } } });
    store.targetVerifications.push({ ...store.targetVerifications[0], id: 'tv_delivery_protected', target_id: 'tgt_delivery_protected' });
    const binding = createOriginBinding(DELIVERY_CTX, { protected_target_id: 'tgt_delivery_protected', origin_target_id: target.id });
    assert.equal(binding.error, undefined, JSON.stringify(binding));
    bindingId = binding.id;
  }
  return startTestRun(DELIVERY_CTX, { check_id: check.check_id, target_group_id: 'tg_1', target_id: target.id, ...(profileOverride ? { probe_profile: profileOverride } : {}), ...(bindingId ? { origin_binding_id: bindingId } : {}) }, DELIVERY_RUNTIME);
}

export function actualDeliveryReceipt(check, { run, job, outcome, body, event, verdict, readiness, wire, reservation, invocationId, reason }) {
  const row = byCheck.get(check.check_id);
  return {
    invocation_id: invocationId ?? job?.id ?? run?.id ?? `admission_${++invocation}`,
    tenant_id: run?.tenant_id ?? job?.tenant_id ?? DELIVERY_CTX.tenantId,
    check_id: check.check_id, check_version: row.check_version, definition_digest: row.definition_digest,
    delivery_fingerprint: deliveryFingerprint(check), disposition: row.disposition,
    execution: row.execution, reason: reason ?? row.reason,
    run_id: run?.id ?? job?.test_run_id ?? null, target_id: job?.target_id ?? run?.target_id ?? null,
    job_id: job?.id ?? null, nonce_hash: job?.nonce_hash ?? null, job_signature: job?.job_signature ?? null,
    signed_target: job?.target ?? null, signed_profile: job?.probe_profile ?? null, signed_caps: job?.constraints ?? null,
    reservation_id: reservation?.reservation_id ?? null,
    outcome: outcome ? structuredClone(outcome) : null, result_body: body ? structuredClone(body) : null,
    execution_receipt: event?.metadata?.execution_receipt ?? event?.metadata_json?.execution_receipt ?? null,
    event_id: event?.id ?? null, verdict_id: verdict?.id ?? null, verdict: verdict?.verdict ?? null,
    confidence: verdict?.confidence ?? null, readiness: readiness ? structuredClone(readiness) : null,
    actual_wire: wire ? structuredClone(wire) : [],
    signed_job: job ? structuredClone(job) : null,
    run_evidence_stamp: run ? { check_version: run.check_version, scenario_version: run.scenario_version, provenance: structuredClone(run.provenance_json), nonce_hash: run.correlation?.nonce_hash } : null,
    accepted_event: event ? structuredClone(event) : null,
    published_verdict: verdict ? structuredClone(verdict) : null,
    prerequisites: structuredClone(check.prerequisites ?? []),
    required_customer_setup: structuredClone(check.required_customer_setup ?? []),
  };
}

export async function executeMemoryDelivery(check, fixture) {
  if (fixture.originScope) fixture.deps.expectedOriginScope = fixture.originScope;
  const started = prepareMemoryDelivery(check, fixture.target, fixture.profileOverride, fixture.originScope);
  if (started.error) {
    const receipt = actualDeliveryReceipt(check, { reason: started.error });
    receipt.admission = structuredClone(started);
    receipt.audits = structuredClone(getStore().auditLog);
    receipt.declared_target = structuredClone(fixture.target);
    return { started, receipt };
  }
  if (!started.probe_job) {
    const run = getStore().testRuns.find((row) => row.id === started.run.id);
    const verdict = getStore().verdicts.find((row) => row.test_run_id === run.id);
    const event = getStore().events.find((row) => row.test_run_id === run.id);
    const receipt = actualDeliveryReceipt(check, { run, verdict, event, wire: fixture.wire() });
    receipt.audits = structuredClone(getStore().auditLog);
    receipt.declared_target = structuredClone(fixture.target);
    return { started, run, event, verdict, receipt };
  }
  const [job] = listPendingProbeJobsForWorker(DELIVERY_WORKER_CTX, DELIVERY_RUNTIME);
  assert.equal(job.id, started.probe_job.id);
  assert.equal(verifyProbeJobSignature(job, DELIVERY_WORKER_SECRET), true);
  const reservation = reserveProbeExecution(DELIVERY_WORKER_CTX, job.id, { leased_at: job.leased_at });
  assert.equal(reservation.authorized, true, JSON.stringify(reservation));
  const outcome = await executeProbeForJob(job, fixture.deps);
  const body = buildResultBody(job, outcome.external_result, outcome.metadata, outcome);
  const ingested = ingestProbeResult(DELIVERY_WORKER_CTX, job.id, body, DELIVERY_RUNTIME);
  assert.equal(ingested.error, undefined, `${check.check_id}: ${JSON.stringify(ingested)}; ${JSON.stringify(outcome)}`);
  // Match the API route's post-ingest publication hook, including max-events=1.
  maybeFinalizeRunAfterProbeIngest(DELIVERY_CTX, job.test_run_id);
  if (!getStore().verdicts.some((row) => row.test_run_id === job.test_run_id)) {
    const finalized = finalizeTestRun(DELIVERY_CTX, job.test_run_id, { force: true });
    assert.equal(finalized.error, undefined, JSON.stringify(finalized));
  }
  // Positive connection-only paths finish on a client event before the peer callback.
  // Wait for that actual owned peer record, not an arbitrary elapsed warm-up interval.
  await fixture.waitForWire?.(outcome);
  const store = getStore();
  const run = store.testRuns.find((row) => row.id === job.test_run_id);
  const event = store.events.find((row) => row.test_run_id === run.id && row.signal_type === 'probe_result');
  const verdict = store.verdicts.find((row) => row.test_run_id === run.id);
  const storedJob = store.probeJobs.find((row) => row.id === job.id);
  assert.equal(event.metadata.execution_receipt.digest, probeExecutionEvidenceReceipt(storedJob, DELIVERY_WORKER_CTX.workerId, body.safety_attestation, outcome.external_result).digest);
  const readiness = computeReadiness(DELIVERY_CTX.tenantId, { catalog: [check] });
  const receipt = actualDeliveryReceipt(check, { run, job: storedJob, outcome, body, event, verdict, readiness, wire: fixture.wire(), reservation });
  receipt.transport_routes = fixture.routes?.() ?? [];
  receipt.audits = structuredClone(store.auditLog.filter((row) => [run.id, job.id].includes(row.resource_id)));
  receipt.declared_target = structuredClone(fixture.target);
  return { started, run, job, outcome, body, event, verdict, readiness, receipt, events: store.events.filter((row) => row.test_run_id === run.id), findings: store.findings.filter((row) => row.test_run_id === run.id), audits: store.auditLog.filter((row) => [run.id, job.id].includes(row.resource_id)) };
}

export const SUPPORTED_DELIVERY_CHECKS = CHECK_CATALOG.filter((check) => byCheck.get(check.check_id).execution === 'socket');

/** Validate measured protocol details, not merely the existence of any socket. */
export function assertOwnedProtocolReceipt(check, receipt) {
  const kind = check.probe_profile?.kind;
  const wire = receipt.actual_wire;
  const target = receipt.signed_target;
  if (!target) return;
  const parsed = ['url', 'canary'].includes(target.kind) ? new URL(target.value) : null;
  const host = parsed?.hostname ?? target.value;
  const httpRows = wire.filter((row) => ['http', 'https'].includes(row.transport));
  if (kind === 'http_head') {
    assert.ok(httpRows.length > 0);
    for (const row of httpRows) {
      assert.equal(row.method, receipt.signed_profile.method ?? 'HEAD');
      assert.equal(row.url, receipt.signed_profile.path ?? (parsed ? `${parsed.pathname}${parsed.search}` : '/'));
    }
  }
  if (kind === 'waf_method_policy_probe') {
    assert.ok(httpRows.some((row) => row.method === 'GET'));
    assert.ok(httpRows.some((row) => row.method === 'TRACE'));
    assert.ok(httpRows.some((row) => row.method === 'ASTRANULLPROBE'));
    assert.equal(httpRows.some((row) => row.request_headers && Number(row.request_headers['content-length']) > 0), false);
  }
  if (kind === 'rate_limit_canary_probe') {
    const gets = httpRows.filter((row) => row.method === 'GET');
    assert.ok(gets.length > 0);
    const cap = Number(receipt.outcome?.metadata?.threshold) + 2;
    if (Number.isInteger(cap)) {
      const phases = receipt.outcome?.metadata?.phases;
      assert.ok(Array.isArray(phases) && phases.length <= cap);
    }
  }
  if (kind === 'connection_limit_probe') {
    assert.ok(wire.some((row) => row.transport === 'tcp_connect'));
  }
  if (['tls_session', 'tls_audit', 'http2_settings', 'http2_frame_probe', 'grpc_reflection_probe'].includes(kind)) {
    const peer = wire.find((row) => row.transport === (['tls_session', 'tls_audit'].includes(kind) ? 'tls_session' : 'h2_tls_session'));
    assert.ok(peer, `${check.check_id}: actual peer TLS record required`);
    assert.equal(peer.servername || null, host === '127.0.0.1' ? null : host);
    if (!['tls_session', 'tls_audit'].includes(kind)) assert.equal(peer.alpn, 'h2');
  }
  if (kind === 'http2_frame_probe') {
    if (receipt.outcome.metadata.ping_rtt_ms != null) assert.equal(wire.filter((row) => row.transport === 'h2_ping').length, 1);
    if (receipt.outcome.metadata.reset_accepted === true) {
      const stream = wire.find((row) => row.transport === 'h2_stream_open');
      assert.ok(stream);
      // This existing bounded producer uses fixed HEAD, not buildProfile's GET fallback.
      assert.equal(stream.method, 'HEAD');
      assert.equal(stream.path, parsed ? `${parsed.pathname}${parsed.search}` : '/');
      assert.ok(wire.some((row) => row.transport === 'h2_stream_close' && row.rst_code === http2.constants.NGHTTP2_CANCEL));
    }
  }
  if (kind === 'grpc_reflection_probe') {
    const stream = wire.find((row) => row.transport === 'h2_stream');
    assert.ok(stream);
    assert.equal(stream.method, 'POST');
    assert.equal(stream.path, receipt.signed_profile.grpc_path ?? '/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo');
    assert.equal(stream.content_type, 'application/grpc');
    assert.equal(new URL(`https://${stream.authority}`).hostname, host);
    const frame = Buffer.from(stream.request_body_hex, 'hex');
    assert.equal(frame[0], 0);
    assert.equal(frame.readUInt32BE(1), frame.length - 5);
  }
  if (['dns_wire_query', 'dnssec_posture', 'dns_axfr_leak'].includes(kind)) {
    const type = kind === 'dnssec_posture' ? 48 : kind === 'dns_axfr_leak' ? 252 : { A: 1, NS: 2, SOA: 6, TXT: 16, AAAA: 28, ANY: 255 }[receipt.signed_profile.dns_qtype ?? 'A'];
    const question = check.check_id.includes('random_prefix')
      ? `${String(receipt.signed_job.nonce).replace(/[^a-zA-Z0-9-]/g, '').slice(0, 32) || 'probe'}.${host}`
      : host;
    const transport = kind === 'dns_axfr_leak' || receipt.signed_profile.dns_transport === 'tcp' ? 'dns_tcp' : 'dns_udp';
    // Resolver NS vetting can share the probe qtype; it is not TCP delivery proof.
    const query = wire.find((row) => row.qtype === type && row.name === question && row.transport === transport);
    assert.ok(query, `${check.check_id}: exact signed DNS question and transport required`);
    assert.equal(query.qclass, 1);
    assert.ok(Number.isInteger(query.transaction_id));
  }
}

/** Run actual catalog invocations for consumers that need receipts, not names.
 * This never fabricates a successful receipt or changes an unsupported selector.
 * Production publication/admission defects reject the collector with their real error.
 */
export async function collectCheckDeliveryReceipts({ catalog = CHECK_CATALOG, onInvocation } = {}) {
  const fixtures = await createCheckDeliveryFixtures();
  const receipts = [];
  try {
    for (const check of catalog) {
      const result = await executeMemoryDelivery(check, fixtures.forCheck(check));
      if (onInvocation) await onInvocation(check, result);
      receipts.push(result.receipt);
    }
    return receipts;
  } finally { await fixtures.close(); }
}
