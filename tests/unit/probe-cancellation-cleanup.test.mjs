import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { EventEmitter, getEventListeners } from 'node:events';
import { describe, it } from 'node:test';
import { probeHttpHead } from '../../workers/probe-worker.mjs';
import { probeTlsSession, probeWebsocketUpgradePosture } from '../../src/lib/safeNetworkProbes.mjs';
import { probeTlsAudit } from '../../src/lib/capabilityProbes.mjs';

function job(kind) {
  return {
    constraints: { timeout_ms: 100, max_requests: 1 },
    probe_profile: { kind, max_requests: 1 },
    target: { kind: 'url', value: 'https://owned.example.test/health' },
  };
}

const deps = {
  resolve4Fn: async () => ['203.0.113.10'],
  resolve6Fn: async () => [],
};

function pendingSocket() {
  const socket = new EventEmitter();
  socket.destroyCount = 0;
  socket.endCount = 0;
  socket.destroy = () => { socket.destroyCount += 1; };
  socket.end = () => { socket.endCount += 1; };
  socket.getProtocol = () => 'TLSv1.3';
  socket.getCipher = () => ({ name: 'TLS_AES_128_GCM_SHA256' });
  socket.authorized = true;
  socket.getPeerCertificate = () => ({});
  return socket;
}

for (const [kind, probe] of [['http_head', probeHttpHead], ['websocket_upgrade_posture', probeWebsocketUpgradePosture]]) {
  describe(`${kind} cancellation signal cleanup`, () => {
    it('propagates cancellation to the request and removes the upstream listener', async () => {
      const controller = new AbortController();
      let signal;
      let abortedOnCancellation = false;
      const outcome = await probe(job(kind), {
        ...deps,
        jobDeadlineSignal: controller.signal,
        fetchFn: async (_url, options) => {
          signal = options.signal;
          queueMicrotask(() => {
            controller.abort();
            abortedOnCancellation = signal.aborted;
          });
          return new Promise((resolve, reject) => {
            signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })), { once: true });
          });
        },
      });
      assert.equal(abortedOnCancellation, true);
      assert.equal(signal.aborted, true);
      assert.equal(outcome.external_result, 'timeout');
      assert.equal(outcome.requests_sent, 1);
      assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
    });

    it('does not invoke a request factory when already cancelled', async () => {
      const controller = new AbortController();
      controller.abort();
      let calls = 0;
      const outcome = await probe(job(kind), {
        ...deps, jobDeadlineSignal: controller.signal,
        fetchFn: async () => { calls += 1; throw new Error('must not send'); },
      });
      assert.equal(calls, 0);
      assert.equal(outcome.requests_sent, 0);
    });
  });
}

for (const [kind, probe] of [['tls_session', probeTlsSession], ['tls_audit', probeTlsAudit]]) {
  describe(`${kind} socket cancellation cleanup`, () => {
    it('destroys once on cancellation, removes handshake/abort listeners and ignores late secureConnect', async () => {
      const controller = new AbortController();
      const socket = pendingSocket();
      let destroyedOnCancellation = false;
      const outcome = await probe(job(kind), {
        ...deps, jobDeadlineSignal: controller.signal,
        connectFn: () => {
          queueMicrotask(() => {
            controller.abort();
            destroyedOnCancellation = socket.destroyCount === 1;
          });
          return socket;
        },
      });
      assert.equal(destroyedOnCancellation, true);
      assert.equal(socket.destroyCount, 1);
      assert.equal(outcome.requests_sent, 1);
      assert.equal(outcome.external_result, 'timeout');
      assert.equal(socket.listenerCount('secureConnect'), 0);
      assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
      socket.emit('secureConnect');
      socket.emit('error', new Error('late socket teardown'));
      assert.equal(socket.endCount, 0);
      assert.equal(socket.destroyCount, 1);
    });

    it('removes abort listener after success, and later cancellation cannot destroy the settled socket', async () => {
      const controller = new AbortController();
      const socket = pendingSocket();
      const outcome = await probe(job(kind), {
        ...deps, jobDeadlineSignal: controller.signal,
        connectFn: () => { queueMicrotask(() => socket.emit('secureConnect')); return socket; },
      });
      assert.equal(outcome.external_result, 'connected');
      assert.equal(socket.endCount, 1);
      assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
      controller.abort();
      assert.equal(socket.destroyCount, 0);
    });

    it('does not connect when already cancelled', async () => {
      const controller = new AbortController();
      controller.abort();
      let calls = 0;
      const pending = probe(job(kind), {
        ...deps, jobDeadlineSignal: controller.signal,
        connectFn: () => { calls += 1; return pendingSocket(); },
      });
      if (kind === 'tls_audit') {
        await assert.rejects(pending, (error) => error.code === 'probe_job_deadline_exceeded');
      } else {
        const outcome = await pending;
        assert.equal(outcome.requests_sent, 0);
      }
      assert.equal(calls, 0);
    });
  });
}

it('TLS audit idle timeout is timer-driven evidence, not an ordinary error outside duration tolerance', async () => {
  const socket = pendingSocket();
  const outcome = await probeTlsAudit(job('tls_audit'), { ...deps, connectFn: () => socket });
  assert.equal(outcome.external_result, 'timeout');
  assert.equal(outcome.metadata.error_class, 'ETIMEOUT');
  assert.equal(socket.destroyCount, 1);
  assert.equal(socket.listenerCount('secureConnect'), 0);
});
