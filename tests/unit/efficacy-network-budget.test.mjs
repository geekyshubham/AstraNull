import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { probeTcpConnect } from '../../src/lib/safeNetworkProbes.mjs';

class FakeSocket extends EventEmitter {
  constructor(endpoint) {
    super();
    this.endpoint = endpoint;
    this.timeoutMs = null;
  }
  setTimeout(ms, cb) {
    this.timeoutMs = ms;
    if (cb) this.once('timeout', cb);
    return this;
  }
  destroy() { return this; }
  end() { return this; }
}

describe('efficacy network budget', () => {
  it('surfaces ipv6 handshake when ipv4 drops within budgeted attempt slice', async () => {
    const sockets = [];
    const connectFn = (endpoint) => {
      const socket = new FakeSocket(endpoint);
      sockets.push(socket);
      if (endpoint.host === '2001:db8::10') {
        queueMicrotask(() => socket.emit('connect'));
      } else {
        // Deterministically drive the budgeted timeout instead of waiting out real wall-clock,
        // which is flaky on loaded CI runners; the probe honours the socket 'timeout' event.
        queueMicrotask(() => socket.emit('timeout'));
      }
      return socket;
    };

    const job = {
      check_id: 'nfw.declared_deny_tcp.safe',
      target: { value: 'owned.example.test', port: 8080 },
      probe_profile: {
        kind: 'tcp_connect',
        max_requests: 2,
        address_family: 'both',
        declarations: { network_policy: [{ protocol: 'tcp', port: 8080, action: 'deny', address_family: 'any' }] },
      },
      declarations: { network_policy: [{ protocol: 'tcp', port: 8080, action: 'deny', address_family: 'any' }] },
      constraints: { timeout_ms: 200, max_requests: 2 },
    };

    const deps = {
      vettedHost: 'owned.example.test',
      vettedAddresses: ['203.0.113.10', '2001:db8::10'],
      resolve4Fn: async () => ['203.0.113.10'],
      resolve6Fn: async () => ['2001:db8::10'],
      sampleGapMs: 0,
      connectFn,
    };

    const res = await probeTcpConnect(job, deps);
    assert.equal(res.requests_sent, 2);
    assert.equal(res.external_result, 'connected');
    assert.notEqual(res.external_result, 'protected');
    assert.equal(res.metadata.readiness_conclusion, false);
    assert.equal(res.metadata.families.ipv4.tcp_outcome, 'timeout');
    assert.equal(res.metadata.families.ipv6.tcp_outcome, 'handshake');
    assert.ok(sockets[0].timeoutMs <= 100, `v4 timeout was ${sockets[0].timeoutMs}`);
  });

  it('multiport 22 handshake and 8081 silence connects before deadline without stealing entire timeout', async () => {
    const sockets = [];
    const connectFn = (endpoint) => {
      const socket = new FakeSocket(endpoint);
      sockets.push(socket);
      if (endpoint.port === 22) {
        queueMicrotask(() => socket.emit('connect'));
      } else {
        // Deterministically drive the budgeted timeout instead of waiting out real wall-clock,
        // which is flaky on loaded CI runners; the probe honours the socket 'timeout' event.
        queueMicrotask(() => socket.emit('timeout'));
      }
      return socket;
    };

    const job = {
      check_id: 'nfw.declared_deny_tcp.safe',
      target: { kind: 'fqdn', value: 'owned.example.test' },
      probe_profile: {
        kind: 'tcp_connect',
        max_requests: 2,
        address_family: 'ipv4',
        declarations: { network_policy: [{ protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' }, { protocol: 'tcp', port: 8081, action: 'deny', address_family: 'any' }] },
      },
      declarations: { network_policy: [{ protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' }, { protocol: 'tcp', port: 8081, action: 'deny', address_family: 'any' }] },
      constraints: { timeout_ms: 200, max_requests: 2 },
    };

    const deps = {
      vettedHost: 'owned.example.test',
      vettedAddresses: ['203.0.113.10'],
      resolve4Fn: async () => ['203.0.113.10'],
      sampleGapMs: 0,
      connectFn,
    };

    const res = await probeTcpConnect(job, deps);
    assert.equal(res.requests_sent, 2);
    assert.equal(res.external_result, 'connected');
    assert.equal(sockets.length, 2);
    const silentSocket = sockets.find((s) => s.endpoint.port === 8081);
    assert.ok(silentSocket, 'port 8081 socket opened');
    assert.ok(silentSocket.timeoutMs <= 100, `silent port timeout was ${silentSocket.timeoutMs}`);
    assert.ok(res.duration_ms < 350, `duration ${res.duration_ms} exceeded robust bound`);
  });
});
