import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { after, before, describe, it } from 'node:test';
import { probeReflectionService } from '../../src/lib/safeNetworkProbes.mjs';

// Live loopback verification of the reflector/vulnerable-service probe. A real UDP socket is used;
// only the local echo server is contacted, and the probe still caps itself at <= 2 packets. This
// proves the end-to-end path: build payload -> pin destination -> send datagram -> receive
// response -> classify amplification, without any third-party traffic.
describe('reflector service probe (live loopback UDP)', () => {
  /** @type {import('node:dgram').Socket} */
  let server;
  let port = 0;
  let received = 0;
  // The reflector answers with a payload larger than the request to model amplification.
  const REPLY = Buffer.alloc(200, 0x41);

  before(async () => {
    server = dgram.createSocket('udp4');
    server.on('message', (msg, rinfo) => {
      received += 1;
      server.send(REPLY, rinfo.port, rinfo.address);
    });
    await new Promise((resolve) => server.bind(0, '127.0.0.1', resolve));
    port = server.address().port;
  });

  after(() => {
    try { server.close(); } catch { /* already closed */ }
  });

  const deps = {
    // Allow the loopback destination for this controlled test; production policy blocks it.
    destinationPolicy: { allowPrivate: true, allowLoopback: true },
    createSocket: (type) => dgram.createSocket(type),
  };

  it('confirms a reflector and computes an amplification ratio > 1', async () => {
    const job = {
      nonce_hash: 'abc123',
      target: { value: `127.0.0.1:${port}` },
      probe_profile: { kind: 'reflection_service_probe', payload_profile: 'memcached_udp_stats' },
      constraints: { timeout_ms: 2000, max_requests: 2 },
    };
    const result = await probeReflectionService(job, deps);

    assert.equal(result.external_result, 'connected', JSON.stringify(result.metadata));
    assert.equal(result.metadata.reflector_confirmed, true);
    assert.equal(result.metadata.response_received, true);
    assert.equal(result.metadata.target_port, port);
    assert.ok(result.metadata.request_bytes > 0);
    assert.ok(result.metadata.amplification_ratio > 1, `ratio=${result.metadata.amplification_ratio}`);
    assert.equal(result.metadata.response_size_class, 'small');
    // Never sends attack-scale traffic.
    assert.ok(result.requests_sent >= 1 && result.requests_sent <= 2, `requests_sent=${result.requests_sent}`);
    // The server actually received our probe (real datagram, not a stub).
    assert.ok(received >= 1);
  });

  it('reports a timeout (no reflector) when nothing answers on the port', async () => {
    // A closed loopback port: the OS will not answer, so the probe times out with no response.
    const job = {
      nonce_hash: 'def456',
      target: { value: '127.0.0.1:1' },
      probe_profile: { kind: 'reflection_service_probe', payload_profile: 'ntp_mode6_readvar' },
      constraints: { timeout_ms: 400, max_requests: 2 },
    };
    const result = await probeReflectionService(job, deps);
    // Either timeout (no response) or blocked (ICMP port-unreachable surfaced as ECONNREFUSED).
    assert.ok(['timeout', 'blocked'].includes(result.external_result), JSON.stringify(result));
    assert.equal(result.metadata.reflector_confirmed, false);
    assert.equal(result.metadata.amplification_ratio, null);
  });
});
