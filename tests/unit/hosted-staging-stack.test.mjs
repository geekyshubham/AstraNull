import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import {
  discoverRailwayBaseUrl,
  normalizeHostedBaseUrl,
  parseHostedStagingStackArgs,
} from '../../scripts/hosted-staging-stack.mjs';
import {
  LOCAL_ONLY_STAGING_PROBE_WORKER_SECRET_HEX,
  resolveStagingProbeWorkerSecret,
} from '../../scripts/lib/hostedStaging.mjs';

test('normalizeHostedBaseUrl strips quotes and trailing slashes', () => {
  assert.equal(
    normalizeHostedBaseUrl('https://control-plane-production-3404.up.railway.app"'),
    'https://control-plane-production-3404.up.railway.app',
  );
  assert.equal(
    normalizeHostedBaseUrl('control-plane-production-3404.up.railway.app/'),
    'https://control-plane-production-3404.up.railway.app',
  );
});

test('parseHostedStagingStackArgs honors --base-url', () => {
  const opts = parseHostedStagingStackArgs(['smoke', '--base-url', 'https://staging.example.test/']);
  assert.equal(opts.command, 'smoke');
  assert.equal(opts.baseUrl, 'https://staging.example.test/');
});

test('discoverRailwayBaseUrl uses only the injected runner in unit tests', () => {
  const calls = [];
  const discovered = discoverRailwayBaseUrl({
    runner(command) {
      calls.push(command);
      return JSON.stringify({ domain: 'control-plane-test.up.railway.app' });
    },
  });
  assert.deepEqual(calls, [
    'railway domain --json 2>/dev/null || railway domain 2>/dev/null',
  ]);
  assert.equal(discovered, 'https://control-plane-test.up.railway.app');
});


test('remote hosted staging requires an explicit probe-worker secret', () => {
  assert.throws(
    () => resolveStagingProbeWorkerSecret('https://staging.example.test', {}),
    /ASTRANULL_PROBE_WORKER_SECRET is required/,
  );
});

test('remote hosted staging validates entropy without echoing the rejected secret', () => {
  const weakSecret = 'z'.repeat(64);
  assert.throws(
    () => resolveStagingProbeWorkerSecret('https://staging.example.test', {
      ASTRANULL_PROBE_WORKER_SECRET: weakSecret,
    }),
    (error) => /entropy validation/.test(error.message) && !error.message.includes(weakSecret),
  );
});

test('hosted resolver rejects sequential, repeated, and explicitly supplied local fallback material', () => {
  for (const secret of [
    Buffer.from(Array.from({ length: 32 }, (_, index) => index)).toString('hex'),
    'z'.repeat(64),
    LOCAL_ONLY_STAGING_PROBE_WORKER_SECRET_HEX,
  ]) {
    assert.throws(
      () => resolveStagingProbeWorkerSecret('https://staging.example.test', {
        ASTRANULL_PROBE_WORKER_SECRET: secret,
      }),
      (error) => /entropy validation/.test(error.message) && !error.message.includes(secret),
    );
  }
  assert.throws(
    () => resolveStagingProbeWorkerSecret('http://127.0.0.1:3000', {
      ASTRANULL_PROBE_WORKER_SECRET: LOCAL_ONLY_STAGING_PROBE_WORKER_SECRET_HEX,
    }),
    /hmac_secret_known_public/,
  );
});

test('remote hosted staging accepts an explicit runtime-generated high-entropy secret', () => {
  const secret = randomBytes(32).toString('hex');
  assert.equal(resolveStagingProbeWorkerSecret('https://staging.example.test', {
    ASTRANULL_PROBE_WORKER_SECRET: secret,
  }), secret);
});

test('loopback staging alone may use the named local-only deterministic secret', () => {
  assert.equal(
    resolveStagingProbeWorkerSecret('http://127.0.0.1:3000', {}),
    LOCAL_ONLY_STAGING_PROBE_WORKER_SECRET_HEX,
  );
  assert.throws(
    () => resolveStagingProbeWorkerSecret('https://127.0.0.1.example.test', {}),
    /ASTRANULL_PROBE_WORKER_SECRET is required/,
  );
});
