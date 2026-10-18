import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import tls from 'node:tls';
import http2 from 'node:http2';
import { rmSync } from 'node:fs';
import { CHECK_CATALOG, getCheckById } from '../../src/contracts/checks.mjs';
import { probeHttp2Settings } from '../../src/lib/safeNetworkProbes.mjs';
import { probeWafEvasionMarker } from '../../src/lib/capabilityProbes.mjs';
import { probeDnsWireQuery } from '../../src/lib/dnsWireQuery.mjs';
import { signProbeJob, verifyProbeJobSignature } from '../../src/lib/probeJobs.mjs';
import { DELIVERY_WORKER_SECRET } from '../helpers/check-delivery-fixtures.mjs';
import { catalogSignedJob, createCheckDeliveryFixtures, executeMemoryDelivery, assertOwnedProtocolReceipt } from '../helpers/check-delivery-fixtures.mjs';
import { createTlsFixture } from './protocol-transport-socket.fixture.mjs';

function withoutCacheBuster(url) {
  const [path, qs] = String(url ?? '').split('?');
  if (qs == null) return String(url ?? '');
  const kept = qs.split('&').filter((part) => part && !part.startsWith('an_cb=')).join('&');
  return kept ? `${path}?${kept}` : path;
}

function assertEvasionWire(wire, { referenceUrl, transformUrl, cookie } = {}) {
  assert.equal(wire.length, 4);
  for (const row of wire) assert.ok(row.url.includes('an_cb='), row.url);
  const dump = wire.map((row) => row.url).join('\n');
  const controls = wire.filter((row) => withoutCacheBuster(row.url) === '/signed/path?keep=1' && !row.cookie && !row.marker);
  assert.equal(controls.length, 2, dump);
  if (referenceUrl) assert.ok(wire.some((row) => withoutCacheBuster(row.url) === referenceUrl), dump);
  if (transformUrl) {
    const hit = wire.find((row) => withoutCacheBuster(row.url) === transformUrl && (cookie ? row.cookie === cookie : true));
    assert.ok(hit, dump);
    if (cookie) assert.equal(hit.cookie, cookie);
  }
}

describe('actual owned wire boundaries of shipped profile selectors', { concurrency: false }, () => {
  let fixtures;
  before(async () => { fixtures = await createCheckDeliveryFixtures(); });
  after(async () => { await fixtures?.close(); });
  for (const check of CHECK_CATALOG.filter((row) => row.probe_profile?.kind === 'host_sni_bypass')) {
    it(`${check.check_id}: separately labelled verified direct-address + approved binding variant`, async () => {
      const fixture = fixtures.forCheck(check, { targetKind: 'url' });
      fixture.target.value = `https://127.0.0.1:${fixture.ports.https}/caller/ignored`;
      fixture.originScope = { host: 'grpc.test', port: fixture.ports.https, path: '/bound/health' };
      if (check.check_id === 'nfw.origin_lockdown.safe') {
        fixture.target.metadata_json = {
          ...(fixture.target.metadata_json ?? {}),
          control_declarations: { version: 1, origin: { lockdown_expected: true } },
        };
      }
      const result = await executeMemoryDelivery(check, fixture);
      assert.equal(result.started.error, undefined);
      assert.deepEqual(result.job.constraints.origin_scope, { host: 'grpc.test', sni: 'grpc.test', port: fixture.ports.https, path: '/bound/health' });
      assert.equal(result.job.probe_profile.protected_host, 'grpc.test');
      assert.notEqual(result.job.probe_profile.direct_ip, '192.0.2.99');
      const [wire] = result.receipt.actual_wire;
      assert.equal(result.receipt.actual_wire.length, 1);
      assert.equal(wire.transport, 'https');
      assert.equal(wire.peer_address, '127.0.0.1');
      assert.equal(wire.servername, 'grpc.test');
      assert.equal(wire.host, `grpc.test:${fixture.ports.https}`);
      assert.equal(wire.url, '/bound/health');
      assert.equal(wire.method, 'HEAD');
      assert.equal(wire.nonce, result.job.nonce);
      assert.equal(result.outcome.destination_resolver_attempts, 0);
      assert.equal(fixture.resolverCalls().length, 0);
      assert.equal(result.outcome.metadata.application_bypass_confirmed, false);
      assert.equal(result.outcome.metadata.readiness_conclusion, false);
      assert.equal(result.verdict.verdict, 'inconclusive');
      assert.equal(result.readiness.coverage.passed_count, 0);
    });
  }
  for (const transform of ['double_url', 'mixed_url']) {
    it(`${transform}: existing helper-only real socket selector, NOT an admitted catalog-definition receipt`, async () => {
      const check = getCheckById('waf.evasion_overlong_utf8.safe');
      const fixture = fixtures.forCheck(check);
      const base = catalogSignedJob(check, fixture.target);
      const outcome = await probeWafEvasionMarker({ target: fixture.target, constraints: base.constraints, probe_profile: { ...check.probe_profile, evasion_transform: transform } }, fixture.deps);
      const wire = fixture.wire().filter((row) => row.transport === 'http');
      assert.equal(outcome.external_result, 'blocked');
      assert.equal(outcome.metadata.evasion_transform, transform);
      assertEvasionWire(wire, {
        referenceUrl: '/signed/path?keep=1&probe=astranull%27%20OR%20%271%27%3D%270',
        transformUrl: transform === 'double_url'
          ? '/signed/path?keep=1&probe=astranull%2527%2520OR%2520%25271%2527%253D%25270'
          : '/signed/path?keep=1&probe=astranull%27%20OR%20%271%27=%270',
      });
      assert.equal(outcome.metadata.comparison_complete, true);
      // No fabricated admission, execution receipt, event, verdict or aggregate credit.
    });
  }
  it('DNS auto fallback: helper-only exact UDP TC -> split TCP question/transaction identity', async () => {
    const check = getCheckById('amp.dns_any_txt_exposure.safe');
    const fixture = fixtures.forCheck(check);
    const base = catalogSignedJob(check, fixture.target);
    fixture.dnsFixture.setTruncated(true);
    try {
      const outcome = await probeDnsWireQuery({ target: fixture.target, constraints: base.constraints, probe_profile: { ...check.probe_profile, dns_transport: 'auto' } }, fixture.deps);
      assert.equal(outcome.external_result, 'connected');
      assert.equal(outcome.metadata.tcp_fallback_used, true);
      assert.equal(outcome.metadata.message_complete, true);
      assert.equal(outcome.metadata.protocol_identity_confirmed, true);
      const questions = fixture.wire().filter((row) => row.qtype === 16);
      assert.deepEqual(questions.map((row) => row.transport), ['dns_udp', 'dns_tcp']);
      assert.equal(questions[0].transaction_id, questions[1].transaction_id);
      assert.equal(questions[0].name, questions[1].name);
      assert.equal(questions[0].qclass, questions[1].qclass);
      assert.equal(outcome.metadata.readiness_conclusion, false);
    } finally { fixture.dnsFixture.setTruncated(false); }
  });
  it('transport pins reject wrong port, logical H2 authority and TLS SNI before any I/O', () => {
    const check = getCheckById('protocol.http2_readiness.safe');
    const fixture = fixtures.forCheck(check);
    assert.throws(() => fixture.deps.tlsConnectFn({ host: '127.0.0.1', port: fixture.ports.h2 + 1, servername: 'grpc.test' }), assert.AssertionError);
    assert.throws(() => fixture.deps.tlsConnectFn({ host: '127.0.0.1', port: fixture.ports.h2, servername: 'wrong.test' }), assert.AssertionError);
    assert.throws(() => fixture.deps.http2ConnectFn(`https://wrong.test:${fixture.ports.h2}`, {}), assert.AssertionError);
    assert.throws(() => fixture.deps.httpsRequestFn({ hostname: '127.0.0.1', port: fixture.ports.h2 + 1 }), assert.AssertionError);
    assert.equal(fixture.wire().length, 0);
    assert.equal(fixture.routes().length, 0);
  });
  for (const mutation of [
    { id: 'l7.expensive_endpoint.safe', transport: 'http', field: 'method', value: 'POST' },
    { id: 'l7.expensive_endpoint.safe', transport: 'http', field: 'url', value: '/different' },
    { id: 'dns.authoritative_response.safe', transport: 'dns_udp', field: 'qtype', value: 16, onlyType: 6 },
    { id: 'tls.full_audit.safe', transport: 'tls_session', field: 'servername', value: 'wrong.test' },
    { id: 'protocol.grpc_reflection_stream.safe', transport: 'h2_stream', field: 'request_body_hex', value: '0000000063' },
  ]) {
    it(`${mutation.id}: measured ${mutation.field} mutation invalidates wire proof`, async () => {
      const check = getCheckById(mutation.id), result = await executeMemoryDelivery(check, fixtures.forCheck(check));
      assertOwnedProtocolReceipt(check, result.receipt);
      const changed = structuredClone(result.receipt);
      const row = changed.actual_wire.find((wire) => wire.transport === mutation.transport && (!mutation.onlyType || wire.qtype === mutation.onlyType));
      assert.ok(row);
      row[mutation.field] = mutation.value;
      assert.throws(() => assertOwnedProtocolReceipt(check, changed), assert.AssertionError);
    });
  }
  const expected = {
    parameter_location: { url: '/signed/path?keep=1', cookie: "astranull_probe=astranull'%20OR%20'1'%3D'0" },
    parser_hpp: { url: '/signed/path?keep=1&probe=astranull-permitted&probe=astranull%27%20OR%20%271%27%3D%270' },
    overlong_utf8: { url: '/signed/path?keep=1&probe=astranull%C0%A7%20OR%20%C0%A71%C0%A7%3D%C0%A70' },
    whitespace: { url: '/signed/path?keep=1&probe=astranull%27%09OR%09%271%27%3D%270' },
  };
  for (const [transform, exact] of Object.entries(expected)) {
    it(`${transform}: real raw path, duplicate query or Cookie bytes survive transport`, async () => {
      const check = getCheckById(`waf.evasion_${transform}.safe`);
      const result = await executeMemoryDelivery(check, fixtures.forCheck(check));
      const wire = result.receipt.actual_wire.filter((row) => row.transport === 'http');
      assertEvasionWire(wire, {
        referenceUrl: '/signed/path?keep=1&probe=astranull%27%20OR%20%271%27%3D%270',
        transformUrl: exact.url,
        cookie: exact.cookie,
      });
      assert.equal(result.outcome.metadata.comparison_complete, true);
      assert.equal(result.outcome.metadata.enforcement, 'enforced');
      assert.equal(result.readiness.coverage.passed_count, 1);
      assert.equal(result.findings.length, 0);
    });
  }
  it('challenged fixture response grades challenged and is never enforced', async () => {
    const check = getCheckById('waf.evasion_overlong_utf8.safe');
    const result = await executeMemoryDelivery(check, fixtures.forCheck(check, { scenario: 'challenged' }));
    assert.equal(result.outcome.metadata.enforcement, 'challenged');
    assert.notEqual(result.outcome.metadata.enforcement, 'enforced');
    assert.equal(result.outcome.metadata.reference_outcome, 'challenged');
    assert.equal(result.outcome.metadata.transform_outcome, 'challenged');
    assert.notEqual(result.verdict.verdict, 'edge_protected');
    assert.equal(result.readiness.coverage.passed_count, 0);
  });
  for (const check of CHECK_CATALOG.filter((row) => ['http3_control_probe', 'quic_reachability'].includes(row.probe_profile?.kind))) {
    it(`${check.check_id}: HTTP3 remains HEAD Alt-Svc only, never QUIC packets or assurance`, async () => {
      const result = await executeMemoryDelivery(check, fixtures.forCheck(check));
      assert.equal(result.outcome.metadata.http3_advertised, true);
      assert.equal(result.outcome.metadata.readiness_conclusion, false);
      assert.ok(result.receipt.actual_wire.some((row) => row.method === 'HEAD'));
      assert.equal(result.receipt.actual_wire.some((row) => row.transport === 'udp'), false);
      assert.equal(result.readiness.coverage.passed_count, 0);
    });
  }
  it('gRPC reflection sends a real framed stream with logical authority and decodes identity conservatively', async () => {
    const check = getCheckById('protocol.grpc_reflection_stream.safe');
    const result = await executeMemoryDelivery(check, fixtures.forCheck(check));
    const stream = result.receipt.actual_wire.find((row) => row.transport === 'h2_stream');
    assert.equal(stream.method, 'POST');
    assert.ok(stream.path.endsWith('/ServerReflectionInfo'));
    assert.equal(stream.content_type, 'application/grpc');
    assert.ok(stream.authority.startsWith('grpc.test:'));
    const body = Buffer.from(stream.request_body_hex, 'hex');
    assert.equal(body[0], 0);
    assert.equal(body.readUInt32BE(1), body.length - 5);
    assert.equal(result.outcome.external_result, 'connected');
    assert.equal(result.outcome.metadata.protocol_identity_confirmed, true);
    assert.equal(result.readiness.coverage.passed_count, 0);
  });
  for (const id of ['tls.full_audit.safe', 'tls.idle_connection_timeout.safe']) {
    it(`${id}: distinct actual TLS audit/session handler, exact signed SNI and port`, async () => {
      const check = getCheckById(id), result = await executeMemoryDelivery(check, fixtures.forCheck(check));
      assert.equal(result.outcome.external_result, 'connected');
      const peer = result.receipt.actual_wire.find((row) => row.transport === 'tls_session');
      assert.equal(peer.servername, 'grpc.test');
      assert.equal(peer.protocol, result.outcome.metadata.tls_protocol);
      const [route] = result.receipt.transport_routes;
      assert.equal(route.requested_port, result.job.target.port);
      assert.equal(route.fixture_port, route.requested_port);
      assert.equal(route.mapping, 'unchanged');
      if (check.probe_profile.kind === 'tls_audit') assert.equal(result.outcome.metadata.certificate_hostname_match, true);
      assert.equal(result.readiness.coverage.passed_count, 0);
    });
  }
  for (const check of CHECK_CATALOG.filter((row) => row.probe_profile?.kind === 'http2_frame_probe' && row.probe_profile.max_requests > 1)) {
    it(`${check.check_id}: bounded PING and single CANCEL are actually observed by the H2 peer`, async () => {
      const fixture = fixtures.forCheck(check), result = await executeMemoryDelivery(check, fixture);
      const deadline = Date.now() + 500;
      while (!fixture.wire().some((row) => row.transport === 'h2_stream_close' && row.rst_code === http2.constants.NGHTTP2_CANCEL) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 5));
      const peer = fixture.wire();
      assert.equal(peer.filter((row) => row.transport === 'h2_ping').length, 1);
      const streams = peer.filter((row) => row.transport === 'h2_stream_open');
      assert.equal(streams.length, 1, 'client-local reset flag is not actual HEADERS/RST_STREAM delivery');
      assert.equal(streams[0].method, 'HEAD');
      assert.equal(streams[0].path, '/signed/path?keep=1');
      assert.ok(peer.some((row) => row.transport === 'h2_stream_close' && row.rst_code === http2.constants.NGHTTP2_CANCEL));
      assert.equal(result.outcome.metadata.reset_accepted, true);
      assert.equal(result.readiness.coverage.passed_count, 0);
      assert.equal(result.outcome.metadata.rapid_reset_mitigation_hint, null);
    });
  }
  for (const id of ['dns.authoritative_response.safe', 'dns.tcp_fallback.readiness', 'dns.zone_transfer_exposure.safe']) {
    it(`${id}: exact real DNS question, framing, protocol identity and conservative coverage`, async () => {
      const check = getCheckById(id);
      const result = await executeMemoryDelivery(check, fixtures.forCheck(check));
      const expectedType = id === 'dns.zone_transfer_exposure.safe' ? 252 : id === 'dns.tcp_fallback.readiness' ? 255 : 6;
      const queries = result.receipt.actual_wire.filter((row) => row.qtype === expectedType);
      assert.equal(queries.length, 1);
      assert.equal(queries[0].name, 'grpc.test');
      assert.equal(queries[0].qclass, 1);
      assert.ok(Number.isInteger(queries[0].transaction_id));
      assert.equal(queries[0].transport, id === 'dns.authoritative_response.safe' ? 'dns_udp' : 'dns_tcp');
      assert.equal(result.outcome.metadata.protocol_identity_confirmed, true);
      assert.equal(result.readiness.coverage.passed_count, id === 'dns.zone_transfer_exposure.safe' ? 1 : 0);
    });
  }
  it('waf.http_method_policy_enforced.safe: TRACE and ASTRANULLPROBE leave the fixture with no body', async () => {
    const check = getCheckById('waf.http_method_policy_enforced.safe');
    const result = await executeMemoryDelivery(check, fixtures.forCheck(check));
    assert.equal(result.started.error, undefined);
    const methods = result.receipt.actual_wire.map((row) => row.method);
    assert.ok(methods.includes('GET'));
    assert.ok(methods.includes('TRACE'));
    assert.ok(methods.includes('ASTRANULLPROBE'));
    assert.ok(result.outcome.requests_sent <= 8);
  });
  it('waf.rate_limit_canary.validation: declared canary path is hit and capped', async () => {
    const check = getCheckById('waf.rate_limit_canary.validation');
    const result = await executeMemoryDelivery(check, fixtures.forCheck(check));
    assert.equal(result.started.error, undefined);
    const httpRows = result.receipt.actual_wire.filter((row) => ['http', 'https'].includes(row.transport) && row.method === 'GET');
    assert.ok(httpRows.length > 0);
    assert.equal(result.outcome.metadata.threshold, 3);
    assert.ok(result.outcome.metadata.phases.length <= result.outcome.metadata.threshold + 2);
    assert.equal(result.outcome.metadata.source_penalized, false);
  });
  it('nfw.connection_limit.safe: declared TCP cap produces actual connect attempts', async () => {
    const check = getCheckById('nfw.connection_limit.safe');
    const result = await executeMemoryDelivery(check, fixtures.forCheck(check));
    assert.equal(result.started.error, undefined);
    assert.ok(result.receipt.actual_wire.some((row) => row.transport === 'tcp_connect'));
    assert.ok(result.outcome.metadata.attempted <= 12);
  });
  for (const targetKind of ['url', 'fqdn', 'ip']) {
    it(`waf.fingerprint.safe: actual declared ${targetKind} target class remains observation only`, async () => {
      const check = getCheckById('waf.fingerprint.safe');
      const result = await executeMemoryDelivery(check, fixtures.forCheck(check, { targetKind }));
      assert.equal(result.job.target.kind, targetKind);
      assert.ok(result.receipt.actual_wire.some((row) => ['http', 'https'].includes(row.transport)));
      assert.equal(result.outcome.metadata.observation_only, true);
      assert.equal(result.readiness.coverage.passed_count, 0);
      assert.equal(result.verdict.verdict, 'inconclusive');
    });
  }
});

for (const terminal of ['cancel', 'timeout', 'peer_close']) {
  it(`HTTP2 ${terminal} before peer SETTINGS destroys the actual session without reading default settings`, { timeout: 5000 }, async () => {
    const cert = createTlsFixture();
    const peers = new Set();
    let session;
    const controller = new AbortController();
    const server = tls.createServer({ key: cert.key, cert: cert.cert, ALPNProtocols: ['h2'] }, (socket) => {
      peers.add(socket); socket.on('error', () => {}); socket.once('close', () => peers.delete(socket));
      // Own peer deliberately sends no H2 SETTINGS, but accepts the actual client preface.
      socket.once('data', (chunk) => {
        assert.ok(chunk.includes(Buffer.from('PRI * HTTP/2.0')));
        if (terminal === 'cancel') controller.abort();
        if (terminal === 'peer_close') socket.destroy();
      });
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    const fixtures = await createCheckDeliveryFixtures();
    try {
      const check = getCheckById('protocol.http2_readiness.safe');
      const fixture = fixtures.forCheck(check);
      const job = catalogSignedJob(check, { id: 'tgt_h2_cleanup', kind: 'url', value: `https://grpc.test:${port}/` });
      // Explicitly labelled helper-only reduced-cap signed fixture; never raises authority.
      job.constraints.timeout_ms = 200;
      job.job_signature = signProbeJob(job, DELIVERY_WORKER_SECRET);
      assert.equal(verifyProbeJobSignature(job, DELIVERY_WORKER_SECRET), true);
      const outcome = await probeHttp2Settings(job, { ...fixture.deps, signal: controller.signal,
        connectFn: (authority, options) => { session = http2.connect(authority, options); return session; },
        tlsConnectFn: (options) => { assert.equal(options.host, '127.0.0.1'); return tls.connect({ ...options, port, ca: cert.cert, ALPNProtocols: ['h2'] }); },
      });
      assert.equal(outcome.external_result, terminal === 'peer_close' ? 'error' : 'timeout');
      assert.equal(outcome.metadata.error_class, terminal === 'peer_close' ? 'ECONNRESET' : 'timeout');
      assert.equal(outcome.requests_sent, 1);
      assert.equal(outcome.metadata.max_concurrent_streams, undefined);
      assert.equal(outcome.metadata.enable_push, undefined);
      assert.equal(session.destroyed, true);
      assert.equal(session.listenerCount('remoteSettings'), 0);
      assert.equal(session.listenerCount('close'), 0);
    } finally {
      session?.destroy(); for (const socket of peers) socket.destroy();
      await new Promise((resolve) => server.close(resolve));
      await fixtures.close(); rmSync(cert.dir, { recursive: true, force: true });
    }
  });
}
