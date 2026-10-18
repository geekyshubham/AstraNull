import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { EventEmitter, getEventListeners } from 'node:events';
import { it } from 'node:test';
import { probeHttp2Settings, probeQuicReachability } from '../../src/lib/safeNetworkProbes.mjs';
import { probeDnsFailoverPosture, probeHttp2FrameBehavior, probeHttpMethodMatrix, probeOpenRecursion, probeSlowHeaderTimeout } from '../../src/lib/capabilityProbes.mjs';

const target = { kind: 'url', value: 'https://owned.example.test/health' };
const destination = { vettedHost: 'owned.example.test', vettedAddresses: ['203.0.113.10'] };
const job = (kind) => ({ target, probe_profile: { kind }, constraints: { timeout_ms: 100, max_requests: 1 } });

for (const [kind, probe, resolverKey] of [
  ['dns_open_recursion', probeOpenRecursion, 'resolve4ExternalFn'],
  ['dns_failover_posture', probeDnsFailoverPosture, 'resolveNsFn'],
]) {
  for (const code of ['ETIMEOUT', 'ETIMEDOUT', 'EAI_AGAIN']) {
    it(`${kind} preserves native ${code} without inventing a job deadline or DNS conclusion`, async () => {
      const outcome = await probe(job(kind), {
        ...destination,
        [resolverKey]: async () => { throw Object.assign(new Error(code), { code }); },
      });
      assert.equal(outcome.external_result, code === 'EAI_AGAIN' ? 'error' : 'timeout');
      assert.equal(outcome.metadata.error_class, code);
      assert.equal(outcome.requests_sent, 1);
      assert.equal(outcome.metadata.resolver_attempts, 1);
      assert.equal(outcome.metadata.readiness_conclusion, false);
      assert.notEqual(outcome.metadata.open_recursion_detected, true);
      assert.notEqual(outcome.metadata.weak_failover, true);
    });
  }
}

it('slow-header local deadline is a timeout, not an observed server close', async () => {
  const socket = new EventEmitter();
  let writes = 0;
  let destroys = 0;
  socket.write = () => { writes += 1; };
  socket.destroy = () => { destroys += 1; };
  const cancellation = new AbortController();
  const outcome = await probeSlowHeaderTimeout(job('slow_header_probe'), {
    ...destination,
    signedJobVerified: true,
    jobDeadlineSignal: cancellation.signal,
    connectFn: () => { queueMicrotask(() => socket.emit('secureConnect')); return socket; },
  });
  assert.equal(outcome.external_result, 'timeout');
  assert.equal(outcome.metadata.error_class, 'probe_job_deadline_exceeded');
  assert.equal(outcome.metadata.connection_closed_by_server, false);
  assert.equal(outcome.metadata.timeout_enforced, null);
  assert.equal(outcome.metadata.readiness_conclusion, false);
  assert.equal(outcome.requests_sent, 1);
  assert.equal(writes, 1);
  assert.equal(destroys, 1);
  for (const event of ['secureConnect', 'end', 'close']) assert.equal(socket.listenerCount(event), 0);
  assert.equal(getEventListeners(cancellation.signal, 'abort').length, 0);
  socket.emit('error', new Error('late teardown'));
  socket.emit('close');
  assert.equal(outcome.metadata.connection_closed_by_server, false);
});

for (const mixed of [false, true]) {
  it(`HTTP method observation retains ${mixed ? 'partial success and per-method errors' : 'an aggregate transport error when all methods fail'}`, async () => {
    const outcome = await probeHttpMethodMatrix({ ...job('http_method_matrix'), constraints: { timeout_ms: 100, max_requests: 2 } }, {
      ...destination,
      signedJobVerified: true,
      fetchFn: async (_url, options) => {
        if (mixed && options.method === 'OPTIONS') return { status: 204, headers: new Headers() };
        throw Object.assign(new Error('peer reset'), { code: 'ECONNRESET' });
      },
    });
    assert.equal(outcome.external_result, mixed ? 'connected' : 'error');
    assert.equal(outcome.metadata.error_class, mixed ? undefined : 'ECONNRESET');
    assert.deepEqual(outcome.metadata.method_errors, mixed
      ? [{ method: 'HEAD', error_class: 'ECONNRESET' }]
      : [{ method: 'HEAD', error_class: 'ECONNRESET' }, { method: 'OPTIONS', error_class: 'ECONNRESET' }]);
    assert.equal(outcome.requests_sent, 2);
    assert.equal(outcome.metadata.trace_enabled, null);
    assert.deepEqual(outcome.metadata.methods_blocked, []);
    assert.equal(outcome.metadata.readiness_conclusion, false);
  });
}

it('HTTP/2 frame observation classifies a stopped SETTINGS wait without claiming frames or protection', async () => {
  const cancellation = new AbortController();
  const session = new EventEmitter();
  let destroys = 0;
  let observeAbortTurn;
  const abortTurn = new Promise((resolve) => { observeAbortTurn = resolve; });
  session.close = () => {};
  session.destroy = () => { destroys += 1; };
  const outcome = await probeHttp2FrameBehavior(job('http2_frame_probe'), {
    ...destination,
    signedJobVerified: true,
    jobDeadlineSignal: cancellation.signal,
    http2ConnectFn: () => {
      queueMicrotask(() => {
        cancellation.abort();
        setImmediate(() => observeAbortTurn(destroys));
      });
      return session;
    },
  });
  assert.equal(await abortTurn, 1, 'session teardown must follow cancellation, not the separate timeout');
  assert.equal(session.listenerCount('remoteSettings'), 0);
  assert.equal(session.listenerCount('connect'), 0);
  assert.equal(session.listenerCount('close'), 0);
  session.emit('error', new Error('late session teardown'));
  assert.equal(outcome.external_result, 'timeout');
  assert.equal(outcome.metadata.error_class, 'probe_job_deadline_exceeded');
  assert.equal(outcome.requests_sent, 1);
  assert.equal(outcome.metadata.max_concurrent_streams, null);
  assert.equal(outcome.metadata.ping_rtt_ms, null);
  assert.equal(outcome.metadata.reset_accepted, null);
  assert.equal(outcome.metadata.rapid_reset_mitigation_hint, false);
  assert.equal(destroys, 1);
  assert.equal(getEventListeners(cancellation.signal, 'abort').length, 0);
});

it('HTTP/2 frame observation cannot open a session after cancellation', async () => {
  const cancellation = new AbortController();
  cancellation.abort();
  let connects = 0;
  const session = new EventEmitter();
  session.close = () => {};
  session.destroy = () => {};
  await assert.rejects(probeHttp2FrameBehavior(job('http2_frame_probe'), {
    ...destination,
    signedJobVerified: true,
    jobDeadlineSignal: cancellation.signal,
    http2ConnectFn: () => { connects += 1; return session; },
  }), (error) => error.code === 'probe_job_deadline_exceeded');
  assert.equal(connects, 0);
});

it('HTTP/2 frame budget refusal still propagates before any session initializer', async () => {
  const budgetError = Object.assign(new Error('budget exhausted'), { code: 'signed_operation_budget_exceeded' });
  let connects = 0;
  await assert.rejects(probeHttp2FrameBehavior(job('http2_frame_probe'), {
    ...destination,
    signedJobVerified: true,
    beforeProbeIoAttempt: () => { throw budgetError; },
    http2ConnectFn: () => { connects += 1; },
  }), (error) => error === budgetError);
  assert.equal(connects, 0);
});

for (const terminal of ['close', 'deadline', 'invalid_alpn', 'settings']) {
  it(`HTTP/2 frame SETTINGS ${terminal} cleans pending listeners without inventing frame delivery`, async () => {
    const cancellation = new AbortController();
    const session = new EventEmitter();
    let destroys = 0;
    session.close = () => {};
    session.destroy = () => { destroys += 1; };
    const outcome = await probeHttp2FrameBehavior(job('http2_frame_probe'), {
      ...destination,
      signedJobVerified: true,
      jobDeadlineSignal: cancellation.signal,
      http2ConnectFn: () => {
        queueMicrotask(() => {
          if (terminal === 'close') session.emit('close');
          if (terminal === 'invalid_alpn') { session.alpnProtocol = 'http/1.1'; session.emit('connect'); }
          if (terminal === 'settings') session.emit('remoteSettings', { maxConcurrentStreams: 7 });
        });
        return session;
      },
    });
    assert.equal(outcome.external_result, terminal === 'settings' ? 'connected' : terminal === 'deadline' ? 'timeout' : 'error');
    if (terminal !== 'settings') {
      assert.equal(outcome.metadata.error_class, terminal === 'deadline' ? 'probe_job_deadline_exceeded' : terminal === 'close' ? 'ECONNRESET' : 'http2_not_negotiated');
      assert.equal(outcome.metadata.max_concurrent_streams, null);
    } else assert.equal(outcome.metadata.max_concurrent_streams, 7);
    assert.equal(outcome.requests_sent, 1);
    assert.equal(outcome.metadata.reset_accepted, null);
    assert.equal(outcome.metadata.ping_rtt_ms, null);
    assert.equal(destroys, 1);
    for (const event of ['remoteSettings', 'connect', 'close']) assert.equal(session.listenerCount(event), 0);
    assert.equal(getEventListeners(cancellation.signal, 'abort').length, 0);
    session.emit('remoteSettings', { maxConcurrentStreams: 999 });
    session.emit('error', new Error('late session error'));
    assert.equal(destroys, 1);
  });
}

it('HTTP/2 frame cancellation during PING settles immediately and ignores a late acknowledgement', async () => {
  const cancellation = new AbortController();
  const session = new EventEmitter();
  let acknowledge;
  let destroys = 0;
  let observeAbortTurn;
  const abortTurn = new Promise((resolve) => { observeAbortTurn = resolve; });
  session.close = () => {};
  session.destroy = () => { destroys += 1; };
  session.ping = (_payload, callback) => {
    acknowledge = callback;
    queueMicrotask(() => {
      cancellation.abort();
      setImmediate(() => observeAbortTurn(destroys));
    });
  };
  const outcome = await probeHttp2FrameBehavior({ ...job('http2_frame_probe'), constraints: { timeout_ms: 100, max_requests: 2 } }, {
    ...destination,
    signedJobVerified: true,
    jobDeadlineSignal: cancellation.signal,
    http2ConnectFn: () => {
      queueMicrotask(() => session.emit('remoteSettings', { maxConcurrentStreams: 7 }));
      return session;
    },
  });
  assert.equal(await abortTurn, 1, 'PING cancellation must not wait for the separate timer');
  assert.equal(outcome.external_result, 'timeout');
  assert.equal(outcome.requests_sent, 2);
  assert.equal(outcome.metadata.ping_rtt_ms, null);
  assert.equal(outcome.metadata.reset_accepted, null);
  assert.equal(getEventListeners(cancellation.signal, 'abort').length, 0);
  acknowledge(null, 2);
  assert.equal(outcome.metadata.ping_rtt_ms, null);
  assert.equal(destroys, 1);
});

// Helper regressions only. Catalog branch receipts require the unchanged signed
// service lifecycle and actual owned protocol peers in check-delivery-branches.
it('Alt-Svc observation relays cancellation immediately and removes its upstream listener', async () => {
  const cancellation = new AbortController();
  let relayed = false;
  let requestSignal;
  const outcome = await probeQuicReachability(job('quic_reachability'), {
    ...destination,
    jobDeadlineSignal: cancellation.signal,
    fetchFn: (_url, options) => {
      requestSignal = options.signal;
      queueMicrotask(() => { cancellation.abort(); relayed = requestSignal.aborted; });
      return new Promise((_resolve, reject) => {
        options.signal.addEventListener('abort', () => reject(Object.assign(new Error('stopped'), { name: 'AbortError' })), { once: true });
      });
    },
  });
  assert.equal(relayed, true, 'the request must stop on cancellation, not its separate timeout');
  assert.equal(outcome.external_result, 'timeout');
  assert.equal(outcome.requests_sent, 1);
  assert.equal(getEventListeners(cancellation.signal, 'abort').length, 0);
});

it('Alt-Svc observation cannot start a request when already stopped', async () => {
  const cancellation = new AbortController();
  cancellation.abort();
  let requests = 0;
  const outcome = await probeQuicReachability(job('quic_reachability'), {
    ...destination,
    jobDeadlineSignal: cancellation.signal,
    fetchFn: async () => { requests += 1; return { status: 200, headers: new Headers() }; },
  });
  assert.equal(requests, 0);
  assert.equal(outcome.requests_sent, 0);
  assert.notEqual(outcome.external_result, 'connected');
  assert.equal(getEventListeners(cancellation.signal, 'abort').length, 0);
});

it('Alt-Svc observation removes cancellation listeners after success without inventing QUIC proof', async () => {
  const cancellation = new AbortController();
  let requestSignal;
  const outcome = await probeQuicReachability(job('quic_reachability'), {
    ...destination,
    jobDeadlineSignal: cancellation.signal,
    fetchFn: async (_url, options) => {
      requestSignal = options.signal;
      return { status: 200, headers: new Headers({ 'alt-svc': 'h3=":443"; ma=60' }) };
    },
  });
  assert.equal(outcome.external_result, 'connected');
  assert.equal(outcome.metadata.capability_scope, 'http3_alt_svc_observation_only');
  assert.equal(outcome.requests_sent, 1);
  assert.equal(getEventListeners(cancellation.signal, 'abort').length, 0);
  cancellation.abort();
  assert.equal(requestSignal.aborted, false);
});

it('HTTP/2 abort before peer SETTINGS is a timeout outcome, not a late ordinary error', async () => {
  const cancellation = new AbortController();
  const session = new EventEmitter();
  let closes = 0;
  let destroys = 0;
  session.close = () => { closes += 1; };
  session.destroy = () => { destroys += 1; };
  const outcome = await probeHttp2Settings(job('http2_settings'), {
    ...destination,
    jobDeadlineSignal: cancellation.signal,
    connectFn: () => { queueMicrotask(() => cancellation.abort()); return session; },
  });
  assert.equal(outcome.external_result, 'timeout');
  assert.equal(outcome.metadata.error_class, 'timeout');
  assert.equal(outcome.metadata.max_concurrent_streams, undefined);
  assert.equal(outcome.requests_sent, 1);
  assert.equal(closes, 1);
  assert.equal(destroys, 1);
  assert.equal(session.listenerCount('remoteSettings'), 0);
  assert.equal(session.listenerCount('close'), 0);
  assert.equal(getEventListeners(cancellation.signal, 'abort').length, 0);
  session.emit('error', new Error('late transport teardown'));
  assert.equal(destroys, 1);
});
