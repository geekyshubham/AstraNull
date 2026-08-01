import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createFixedWindowRateLimiter, deriveClientKey } from '../../src/lib/rateLimit.mjs';

describe('deriveClientKey', () => {
  it('ignores spoofed X-Forwarded-For by default and uses socket remoteAddress', () => {
    const key = deriveClientKey({
      headers: { 'x-forwarded-for': '203.0.113.1, 198.51.100.2' },
      socket: { remoteAddress: '127.0.0.1' },
    });
    assert.equal(key, 'ip:127.0.0.1');
  });

  it('ignores X-Real-IP by default', () => {
    const key = deriveClientKey({
      headers: { 'x-real-ip': '203.0.113.9' },
      socket: { remoteAddress: '10.0.0.5' },
    });
    assert.equal(key, 'ip:10.0.0.5');
  });

  it('uses the first X-Forwarded-For hop when trustProxyHeaders is true', () => {
    const key = deriveClientKey(
      {
        headers: { 'x-forwarded-for': '203.0.113.1, 198.51.100.2' },
        socket: { remoteAddress: '127.0.0.1' },
      },
      { trustProxyHeaders: true },
    );
    assert.equal(key, 'ip:203.0.113.1');
  });

  it('falls back to socket remoteAddress when trustProxyHeaders is true but headers absent', () => {
    const key = deriveClientKey(
      {
        headers: {},
        socket: { remoteAddress: '::1' },
      },
      { trustProxyHeaders: true },
    );
    assert.equal(key, 'ip:::1');
  });
});

describe('fixed-window rate limiter', () => {
  it('allows requests up to max then blocks until window resets', () => {
    let clock = 1_000_000;
    const limiter = createFixedWindowRateLimiter({
      windowMs: 10_000,
      maxRequests: 2,
      now: () => clock,
    });

    assert.equal(limiter.check('client-a').allowed, true);
    assert.equal(limiter.check('client-a').allowed, true);
    const blocked = limiter.check('client-a');
    assert.equal(blocked.allowed, false);
    assert.ok(blocked.retryAfterSeconds >= 1);

    clock += 10_000;
    assert.equal(limiter.check('client-a').allowed, true);
  });

  it('tracks separate keys independently', () => {
    const limiter = createFixedWindowRateLimiter({
      windowMs: 60_000,
      maxRequests: 1,
      now: () => 0,
    });
    assert.equal(limiter.check('client-a').allowed, true);
    assert.equal(limiter.check('client-a').allowed, false);
    assert.equal(limiter.check('client-b').allowed, true);
  });

  it('prunes stale buckets when the window advances', () => {
    let clock = 0;
    const limiter = createFixedWindowRateLimiter({
      windowMs: 1_000,
      maxRequests: 1,
      now: () => clock,
    });

    for (let i = 0; i < 25; i++) {
      limiter.check(`client-${i}`);
    }
    assert.equal(limiter.bucketCount(), 25);

    clock = 1_000;
    limiter.check('client-new');
    assert.equal(limiter.bucketCount(), 1);
  });

  it('resets counts when the clock skips several windows', () => {
    let clock = 0;
    const limiter = createFixedWindowRateLimiter({
      windowMs: 1_000,
      maxRequests: 1,
      now: () => clock,
    });
    assert.equal(limiter.check('a').allowed, true);
    assert.equal(limiter.check('a').allowed, false);
    clock = 10_000; // gap of ten windows
    assert.equal(limiter.check('a').allowed, true);
  });
});

describe('rate limiter cost under flood', () => {
  it('stays O(1) per call across 100k distinct keys', () => {
    // The old implementation swept the entire bucket Map on every check, so cost
    // grew with the number of live keys — quadratic exactly when a flood makes
    // the map large. Compare early-window cost against late-window cost: a
    // per-call sweep would make the last batch dramatically slower.
    const limiter = createFixedWindowRateLimiter({
      windowMs: 60_000,
      maxRequests: 1_000_000,
      maxKeys: 200_000, // above the key count, so eviction is not what we measure
      now: () => 1_000,
    });

    const BATCH = 5_000;
    const TOTAL = 100_000;

    const firstStart = process.hrtime.bigint();
    for (let i = 0; i < BATCH; i++) limiter.check(`k${i}`);
    const firstNs = Number(process.hrtime.bigint() - firstStart);

    for (let i = BATCH; i < TOTAL - BATCH; i++) limiter.check(`k${i}`);

    const lastStart = process.hrtime.bigint();
    for (let i = TOTAL - BATCH; i < TOTAL; i++) limiter.check(`k${i}`);
    const lastNs = Number(process.hrtime.bigint() - lastStart);

    assert.equal(limiter.bucketCount(), TOTAL);

    // With a per-request sweep, the final batch would be several orders of
    // magnitude slower (it would scan ~95k entries per call). Allow a generous
    // factor so this is not flaky on a loaded machine while still failing hard if
    // linear-scan behaviour returns.
    const ratio = lastNs / Math.max(firstNs, 1);
    assert.ok(
      ratio < 20,
      `late-batch cost ratio ${ratio.toFixed(2)} suggests per-call scanning returned`,
    );
  });

  it('caps distinct keys and evicts least-recently-used entries', () => {
    const limiter = createFixedWindowRateLimiter({
      windowMs: 60_000,
      maxRequests: 5,
      maxKeys: 100,
      now: () => 0,
    });

    for (let i = 0; i < 1_000; i++) limiter.check(`flood-${i}`);

    // Hard ceiling holds regardless of how many distinct sources appear.
    assert.equal(limiter.bucketCount(), 100);
    assert.equal(limiter.evictedCount(), 900);
  });

  it('keeps an actively-used key while idle keys are evicted', () => {
    const limiter = createFixedWindowRateLimiter({
      windowMs: 60_000,
      maxRequests: 3,
      maxKeys: 10,
      now: () => 0,
    });

    limiter.check('steady'); // count 1
    limiter.check('steady'); // count 2

    // Push enough distinct keys to overflow the ceiling repeatedly, touching
    // 'steady' each round so it stays recently used.
    for (let round = 0; round < 5; round++) {
      for (let i = 0; i < 8; i++) limiter.check(`noise-${round}-${i}`);
      limiter.check('steady');
    }

    assert.equal(limiter.bucketCount(), 10);
    // 'steady' was never evicted, so its count kept climbing past the limit of 3
    // rather than being reset to a fresh allowance by the flood.
    assert.equal(limiter.check('steady').allowed, false);
  });

  it('rejects a non-positive maxKeys', () => {
    assert.throws(
      () => createFixedWindowRateLimiter({ windowMs: 1_000, maxRequests: 1, maxKeys: 0 }),
      /positive integer maxKeys/,
    );
  });
});