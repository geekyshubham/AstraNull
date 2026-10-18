import assert from 'node:assert/strict';
import dns from 'node:dns/promises';
import dgram from 'node:dgram';
import { getEventListeners } from 'node:events';
import { describe, it } from 'node:test';
import { probeDnsFailoverPosture, probeOpenRecursion } from '../../src/lib/capabilityProbes.mjs';
import { resolveOwnedDns } from '../../src/lib/ownedDnsResolver.mjs';

const deadlineError = () => Object.assign(new Error('signed deadline'), { code: 'probe_job_deadline_exceeded' });
const job = (kind, timeout = 1000) => ({
  constraints: { timeout_ms: timeout, max_requests: 1 },
  probe_profile: { kind, max_requests: 1 },
  target: { kind: 'fqdn', value: 'grpc.test' },
});
const probes = [
  ['NS failover', probeDnsFailoverPosture, 'dns_failover_posture', 'resolveNsFn'],
  ['external A', probeOpenRecursion, 'dns_open_recursion', 'resolve4ExternalFn'],
];
const pin = { resolve4Fn: async () => ['127.0.0.1'], resolve6Fn: async () => [], destinationPolicy: { allowLoopback: true } };

// These helper regressions do not issue public DNS and never constitute catalog receipts.
describe('operation-owned DNS resolver cancellation', { concurrency: false }, () => {
  for (const [label, probe, kind, injection] of probes) {
    for (const source of ['Stop', 'signed deadline', 'local fallback']) {
      it(`${label}: injected resolver receives real cancellation for ${source}`, async () => {
        const controller = new AbortController();
        let signal; let aborted = 0; let attempts = 0;
        const outcome = await probe(job(kind, source === 'local fallback' ? 30 : 1000), {
          ...pin,
          ...(source === 'Stop' ? { cancellationSignal: controller.signal } : { jobDeadlineSignal: controller.signal }),
          beforeProbeIoAttempt: () => { attempts += 1; },
          [injection]: (...args) => {
            signal = args.at(-1)?.signal;
            // Keep the red test bounded even before production propagates a signal.
            if (source !== 'local fallback') queueMicrotask(() => controller.abort(source === 'Stop' ? new Error('Stop') : deadlineError()));
            return new Promise((_, reject) => signal?.addEventListener('abort', () => {
              aborted += 1;
              reject(signal.reason);
            }, { once: true }));
          },
        });
        assert.ok(signal instanceof AbortSignal, 'resolver adapter must receive the operation AbortSignal');
        assert.equal(signal.aborted, true);
        assert.equal(aborted, 1);
        assert.equal(attempts, 1);
        assert.equal(outcome.requests_sent, 1);
        assert.equal(outcome.external_result, 'timeout');
        assert.equal(outcome.metadata.error_class, 'probe_job_deadline_exceeded');
        assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
      });
    }
    for (const source of ['Stop', 'signed deadline', 'local fallback']) {
      it(`${label}: production default owns and cancels its Resolver once for ${source}`, async (t) => {
        const controller = new AbortController();
        const instances = [];
        t.mock.method(dns, 'resolveNs', () => assert.fail('global resolver must never be used'));
        t.mock.method(dns, 'Resolver', function OwnedResolver() {
          const instance = { servers: null, cancelled: 0, resolve4: query, resolveNs: query,
            setServers(servers) { this.servers = servers; }, cancel() { this.cancelled += 1; } };
          function query(name) {
            assert.equal(name, 'grpc.test');
            if (source !== 'local fallback') queueMicrotask(() => controller.abort(source === 'Stop' ? new Error('Stop') : deadlineError()));
            return new Promise(() => {});
          }
          instances.push(instance);
          return instance;
        });
        // Pinning is separate from the actual external lookup and uses no system DNS.
        const outcome = await probe(job(kind, 40), {
          ...pin, ...(source === 'Stop' ? { cancellationSignal: controller.signal } : { jobDeadlineSignal: controller.signal }),
        });
        assert.equal(outcome.external_result, 'timeout');
        assert.equal(instances.length, 1, 'default creates an operation-owned Resolver');
        assert.equal(instances[0].cancelled, 1);
        assert.deepEqual(instances[0].servers, kind === 'dns_open_recursion' ? ['127.0.0.1'] : null);
        assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
        controller.abort(deadlineError());
        assert.equal(instances[0].cancelled, 1, 'late/duplicate upstream cancellation must be detached');
      });
    }
    for (const terminal of ['success', 'error']) {
      it(`${label}: ${terminal} detaches cancellation without aborting a completed operation`, async () => {
        const controller = new AbortController();
        let signal;
        const outcome = await probe(job(kind), {
          ...pin, jobDeadlineSignal: controller.signal,
          [injection]: (...args) => {
            signal = args.at(-1).signal;
            if (terminal === 'error') throw Object.assign(new Error('real refusal'), { code: 'ECONNREFUSED' });
            return [];
          },
        });
        assert.equal(outcome.external_result, terminal === 'success' ? 'connected' : 'error');
        assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
        controller.abort();
        assert.equal(signal.aborted, false, 'settled DNS operation must not retain upstream ownership');
      });
    }
    it(`${label}: signed operation refusal creates no resolver and starts no DNS adapter`, async (t) => {
      t.mock.method(dns, 'Resolver', () => assert.fail('no resolver before budget reservation'));
      const refused = Object.assign(new Error('signed budget'), { code: 'signed_operation_budget_exceeded' });
      await assert.rejects(probe(job(kind), {
        ...pin, beforeProbeIoAttempt: () => { throw refused; },
        [injection]: () => assert.fail('no query before budget reservation'),
      }), (error) => error === refused);
    });
  }

  it('cancelling one operation-owned Resolver does not cancel a concurrent resolver', async (t) => {
    const instances = [];
    t.mock.method(dns, 'Resolver', function OwnedResolver() {
      let complete; let fail;
      const pending = new Promise((resolve, reject) => { complete = resolve; fail = reject; });
      const instance = { complete, cancelled: 0, resolveNs: () => pending,
        cancel() { this.cancelled += 1; fail(Object.assign(new Error('native cancel'), { code: 'ECANCELLED' })); } };
      instances.push(instance);
      return instance;
    });
    const controller = new AbortController();
    const first = probeDnsFailoverPosture(job('dns_failover_posture'), { jobDeadlineSignal: controller.signal });
    const second = probeDnsFailoverPosture(job('dns_failover_posture'));
    assert.equal(instances.length, 2);
    controller.abort();
    assert.equal((await first).external_result, 'timeout');
    assert.equal(instances[0].cancelled, 1);
    assert.equal(instances[1].cancelled, 0);
    instances[1].complete(['ns.grpc.test']);
    assert.equal((await second).external_result, 'connected');
    assert.equal(instances[1].cancelled, 0);
  });

  it('preaborted or locally expired operations create no Resolver and invoke no adapter', async (t) => {
    const controller = new AbortController();
    controller.abort();
    t.mock.method(dns, 'Resolver', () => assert.fail('preaborted operations cannot allocate a Resolver'));
    for (const options of [{ timeoutMs: 100, signals: [controller.signal] }, { timeoutMs: 0 }]) {
      for (const injected of [false, true]) {
        await assert.rejects(resolveOwnedDns({
          method: 'resolveNs', name: 'grpc.test', ...options,
          ...(injected ? { resolveFn: () => assert.fail('preaborted operations cannot start DNS I/O') } : {}),
        }), (error) => error.code === 'probe_job_deadline_exceeded');
      }
    }
  });

  it('synchronous adapter abort followed by throw leaves no listener or unhandled rejection', async () => {
    const controller = new AbortController();
    await assert.rejects(resolveOwnedDns({
      method: 'resolveNs', name: 'grpc.test', timeoutMs: 100, signals: [controller.signal],
      resolveFn: (_name, { signal }) => {
        controller.abort();
        assert.equal(signal.aborted, true);
        throw signal.reason;
      },
    }), (error) => error.code === 'probe_job_deadline_exceeded');
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
    await new Promise((resolve) => setImmediate(resolve));
  });

  it('late adapter completion cannot turn a cancelled lookup into an answer or next operation', async () => {
    const controller = new AbortController();
    let complete; let calls = 0;
    const pending = new Promise((resolve) => { complete = resolve; });
    const operation = probeDnsFailoverPosture(job('dns_failover_posture'), {
      jobDeadlineSignal: controller.signal,
      resolveNsFn: () => { calls += 1; return pending; },
    });
    controller.abort();
    const outcome = await operation;
    complete(['ns.grpc.test']);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(outcome.external_result, 'timeout');
    assert.equal(outcome.metadata.nameserver_count, undefined);
    assert.equal(calls, 1);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  });

  for (const [label, probe, kind] of probes) {
    for (const source of ['Stop', 'signed deadline', 'local fallback']) {
      it(`${label}: native Resolver cancels a withheld owned query for ${source} before native expiry`, async (t) => {
        const server = dgram.createSocket('udp4');
        await new Promise((resolve, reject) => {
          server.once('error', reject);
          server.bind(0, '127.0.0.1', resolve);
        });
        const controller = new AbortController();
        const NativeResolver = dns.Resolver;
        t.mock.method(dns, 'resolveNs', () => assert.fail('global resolver must never be used'));
        let received = 0; let actualError; let nativeCancelled = 0;
        server.on('message', (_packet, peer) => {
          assert.equal(peer.address, '127.0.0.1');
          received += 1;
          if (source !== 'local fallback') controller.abort(source === 'Stop' ? new Error('Stop after real query') : deadlineError());
        });
        t.mock.method(dns, 'Resolver', function OwnedNativeResolver() {
          const resolver = new NativeResolver({ timeout: 2000, tries: 1 });
          const setServers = resolver.setServers.bind(resolver);
          setServers([`127.0.0.1:${server.address().port}`]);
          resolver.setServers = (servers) => {
            assert.deepEqual(servers, ['127.0.0.1']);
            setServers([`127.0.0.1:${server.address().port}`]);
          };
          const method = kind === 'dns_open_recursion' ? 'resolve4' : 'resolveNs';
          const query = resolver[method].bind(resolver);
          const cancel = resolver.cancel.bind(resolver);
          resolver.cancel = () => { nativeCancelled += 1; cancel(); };
          resolver[method] = (name) => query(name).catch((error) => { actualError = error; throw error; });
          return resolver;
        });
        try {
          const started = Date.now();
          const outcome = await probe(job(kind, 100), {
            ...pin, ...(source === 'Stop' ? { cancellationSignal: controller.signal } : { jobDeadlineSignal: controller.signal }),
          });
          await new Promise((resolve) => setImmediate(resolve));
          assert.equal(received, 1);
          assert.equal(nativeCancelled, 1);
          assert.equal(actualError?.code, 'ECANCELLED', 'native c-ares request actually cancelled, not merely raced');
          assert.ok(Date.now() - started < 500, 'must precede independent 2000ms native expiry');
          assert.equal(outcome.external_result, 'timeout');
        } finally {
          await new Promise((resolve) => server.close(resolve));
        }
      });
    }
  }
});
