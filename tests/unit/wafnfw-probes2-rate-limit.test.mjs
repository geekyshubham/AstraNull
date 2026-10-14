import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  RATE_LIMIT_CANARY_HARD_CAP,
  rateLimitCanaryCap,
  runRateLimitCanaryProbe,
} from '../../src/lib/vectorProbes/rateLimitCanaryProbes.mjs';
import { CAPABILITY_PROBE_DISPATCH, probeRateLimitCanary } from '../../src/lib/capabilityProbes.mjs';

function okResponse(status, headers = {}) {
  return { status, headers: new Map(Object.entries(headers)) };
}

function profile(canary) {
  return { kind: 'rate_limit_canary_probe', max_requests: 8, declarations: { waf: { rate_limit_canary: canary } } };
}

describe('rate-limit canary probe', () => {
  it('registers the named executor', () => {
    assert.equal(CAPABILITY_PROBE_DISPATCH.rate_limit_canary_probe.name, 'probeRateLimitCanary');
  });

  it('sends nothing without a declaration', async () => {
    let calls = 0;
    const result = await runRateLimitCanaryProbe({
      url: 'https://edge.example.test/app',
      probe_profile: { kind: 'rate_limit_canary_probe' },
      fetchFn: async () => { calls += 1; return okResponse(200); },
    });
    assert.equal(result.error_class, 'unsupported_target');
    assert.equal(result.requests_sent, 0);
    assert.equal(calls, 0);
  });

  it('stops at the first 429 and never exceeds threshold + 2', async () => {
    let calls = 0;
    const result = await runRateLimitCanaryProbe({
      url: 'https://edge.example.test/app',
      probe_profile: profile({ path: '/rl', method: 'GET', threshold: 3, window_seconds: 10 }),
      fetchFn: async () => {
        calls += 1;
        return calls >= 3 ? okResponse(429) : okResponse(200);
      },
    });
    assert.equal(result.requests_sent, 3);
    assert.ok(result.requests_sent <= 5);
    assert.equal(result.first_limited_at, 3);
    assert.equal(result.limited_outcome, 'rate_limited');
    assert.equal(result.threshold, 3);
    assert.equal(result.window_seconds, 10);
    assert.equal(result.source_penalized, false);
    assert.equal(result.cache_buster, false);
  });

  it('stops at a blocked grade before sending the remainder', async () => {
    let calls = 0;
    const result = await runRateLimitCanaryProbe({
      url: 'https://edge.example.test/app',
      probe_profile: profile({ path: '/rl', method: 'HEAD', threshold: 4, window_seconds: 5 }),
      fetchFn: async () => {
        calls += 1;
        return calls === 2 ? okResponse(403, { 'x-waf-block': '1' }) : okResponse(200);
      },
    });
    assert.equal(calls, 2);
    assert.equal(result.first_limited_at, 2);
    assert.equal(result.limited_outcome, 'blocked');
  });

  it('caps at threshold + 2 even when never limited', async () => {
    let calls = 0;
    const result = await runRateLimitCanaryProbe({
      url: 'https://edge.example.test/app',
      probe_profile: profile({ path: '/rl', method: 'GET', threshold: 2, window_seconds: 10 }),
      fetchFn: async () => { calls += 1; return okResponse(200); },
    });
    assert.equal(calls, 4);
    assert.equal(result.requests_sent, 4);
    assert.equal(result.first_limited_at, null);
    assert.equal(result.limited_outcome, null);
    assert.equal(rateLimitCanaryCap(10, 8), 8);
    assert.ok(rateLimitCanaryCap(10, 99) <= RATE_LIMIT_CANARY_HARD_CAP);
  });

  it('rejects a canary path on another host', async () => {
    const result = await runRateLimitCanaryProbe({
      url: 'https://edge.example.test/app',
      probe_profile: profile({ path: 'https://other.example/rl', method: 'GET', threshold: 1, window_seconds: 1 }),
      fetchFn: async () => okResponse(200),
    });
    assert.equal(result.error_class, 'unsupported_target');
    assert.equal(result.requests_sent, 0);
  });

  it('delegated executor reports blocked when limited', async () => {
    const outcome = await probeRateLimitCanary({
      constraints: { timeout_ms: 1000, max_requests: 8 },
      probe_profile: profile({ path: '/rl', method: 'GET', threshold: 1, window_seconds: 10 }),
      target: { kind: 'url', value: 'https://edge.example.test/app' },
    }, {
      signedJobVerified: true,
      fetchFn: async () => okResponse(429),
    });
    assert.equal(outcome.external_result, 'blocked');
    assert.equal(outcome.metadata.first_limited_at, 1);
    assert.equal(outcome.metadata.limited_outcome, 'rate_limited');
    assert.equal(outcome.requests_sent, 1);
  });
});
