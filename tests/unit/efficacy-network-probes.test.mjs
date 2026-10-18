import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { probeHttp2Settings } from '../../src/lib/safeNetworkProbes.mjs';

function createMockDeps({ vettedHost, onSession }) {
  let capturedTlsOpts;
  return {
    vettedHost,
    vettedAddresses: ['203.0.113.10'],
    getCapturedTlsOpts: () => capturedTlsOpts,
    tlsConnectFn: (opts) => {
      capturedTlsOpts = opts;
      return new EventEmitter();
    },
    connectFn: (authority, options) => {
      options?.createConnection?.(authority, options);
      const session = new EventEmitter();
      session.remoteSettings = { maxConcurrentStreams: 100 };
      session.close = (cb) => { session.emit('close'); cb?.(); };
      session.destroy = () => { session.emit('close'); };
      session.unref = () => session;
      onSession(session);
      return session;
    }
  };
}

test('probeHttp2Settings enforces ALPN h2, pinned host, SNI, and captures remoteSettings', async () => {
  const deps = createMockDeps({
    vettedHost: 'owned.example.test',
    onSession: (session) => {
      queueMicrotask(() => {
        session.emit('remoteSettings', { maxConcurrentStreams: 4294967295, enablePush: false });
      });
    }
  });
  const job = {
    target: { kind: 'url', value: 'https://owned.example.test:8443/' },
    probe_profile: { kind: 'http2_settings', max_requests: 1, timeout_ms: 1000 },
    constraints: { timeout_ms: 1000, max_requests: 1 }
  };

  const res = await probeHttp2Settings(job, deps);
  const tls = deps.getCapturedTlsOpts();

  assert.deepStrictEqual(tls.ALPNProtocols, ['h2']);
  assert.strictEqual(tls.host, '203.0.113.10');
  assert.strictEqual(Number(tls.port), 8443);
  assert.strictEqual(tls.rejectUnauthorized, false);
  assert.strictEqual(tls.servername, 'owned.example.test');
  assert.strictEqual(res.external_result, 'connected');
  assert.strictEqual(res.requests_sent, 1);
  assert.strictEqual(res.metadata?.max_concurrent_streams, 4294967295);
});

test('probeHttp2Settings omits SNI for IP target, requires ALPN h2, close yields error', async () => {
  const deps = createMockDeps({
    vettedHost: '203.0.113.10',
    onSession: (session) => {
      queueMicrotask(() => {
        session.emit('close');
      });
    }
  });
  const job = {
    target: { kind: 'url', value: 'https://203.0.113.10/' },
    probe_profile: { kind: 'http2_settings', max_requests: 1, timeout_ms: 1000 },
    constraints: { timeout_ms: 1000, max_requests: 1 }
  };

  const res = await probeHttp2Settings(job, deps);
  const tls = deps.getCapturedTlsOpts();

  assert.deepStrictEqual(tls.ALPNProtocols, ['h2']);
  assert.strictEqual(tls.host, '203.0.113.10');
  assert.strictEqual(Number(tls.port), 443);
  assert.strictEqual(tls.rejectUnauthorized, false);
  assert.strictEqual(tls.servername, undefined);
  assert.strictEqual(res.external_result, 'error');
  assert.strictEqual(res.requests_sent, 1);
  assert.strictEqual(res.metadata?.max_concurrent_streams, undefined);
});
