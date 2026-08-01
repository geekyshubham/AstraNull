import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { afterEach, describe, it } from 'node:test';
import { assertStrongSecretEncryptionKey, loadSecretEncryptionKey } from '../../src/lib/secrets.mjs';

// The fixture key that was committed to ops/railway/staging.env.example and
// ops/docker/local-staging.env in a PUBLIC repository. Present here only so the
// denylist can be proven to reject it.
const PUBLISHED_FIXTURE_KEY_HEX =
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

afterEach(() => {
  restoreEnv();
});

/** Capture console.warn so warning-vs-throw behaviour can be asserted. */
function withCapturedWarnings(fn) {
  const original = console.warn;
  const warnings = [];
  console.warn = (...args) => warnings.push(args.join(' '));
  try {
    return { result: fn(), warnings };
  } finally {
    console.warn = original;
  }
}

const PRODUCTION = { ASTRANULL_DEPLOYMENT_PROFILE: 'production' };

describe('secret encryption key strength — decoded entropy', () => {
  it('accepts a freshly generated random key', () => {
    const key = randomBytes(32);
    assert.doesNotThrow(() => assertStrongSecretEncryptionKey(key, PRODUCTION));
  });

  it('rejects the published fixture key under the production profile', () => {
    const key = Buffer.from(PUBLISHED_FIXTURE_KEY_HEX, 'hex');
    assert.throws(() => assertStrongSecretEncryptionKey(key, PRODUCTION), (err) => {
      assert.match(err.message, /Refusing to start/);
      assert.match(err.message, /compromised/i);
      // Diagnostics must never echo the key itself.
      assert.doesNotMatch(err.message, new RegExp(PUBLISHED_FIXTURE_KEY_HEX));
      return true;
    });
  });

  it('rejects an all-zero key and a single-repeated-character key', () => {
    assert.throws(
      () => assertStrongSecretEncryptionKey(Buffer.alloc(32, 0), PRODUCTION),
      /Refusing to start/,
    );
    assert.throws(
      () => assertStrongSecretEncryptionKey(Buffer.alloc(32, 0x61), PRODUCTION),
      /Refusing to start/,
    );
  });

  it('rejects a key that is 32 CHARACTERS but low entropy once decoded', () => {
    // 'abababab...' is 64 hex chars -> 32 bytes, so any character-count check
    // passes. Decoded it is two distinct bytes on a 2-byte cycle.
    const key = Buffer.from('ab'.repeat(32), 'hex');
    assert.equal(key.length, 32);
    assert.throws(() => assertStrongSecretEncryptionKey(key, PRODUCTION), (err) => {
      assert.match(err.message, /distinct byte values|repeat/);
      return true;
    });
  });

  it('rejects a 32-byte key whose bytes repeat on a short period', () => {
    // 16 distinct bytes, but only an 16-byte cycle repeated twice: half the
    // claimed key material is redundant.
    const half = Buffer.from(Array.from({ length: 16 }, (_, i) => i * 7 + 3));
    const key = Buffer.concat([half, half]);
    assert.equal(key.length, 32);
    assert.throws(() => assertStrongSecretEncryptionKey(key, PRODUCTION), /repeat every 16 byte/);
  });

  it('rejects a truncated repeat that does not divide the key length', () => {
    // Period 5 over 32 bytes: the cycle does not divide evenly, so a check that
    // required period | length would miss it.
    const cycle = [1, 2, 3, 4, 5];
    const key = Buffer.from(Array.from({ length: 32 }, (_, i) => cycle[i % cycle.length]));
    assert.throws(() => assertStrongSecretEncryptionKey(key, PRODUCTION), /repeat every 5 byte/);
  });

  it('reports the offending property without echoing key material', () => {
    const key = Buffer.alloc(32, 0x41);
    assert.throws(() => assertStrongSecretEncryptionKey(key, PRODUCTION), (err) => {
      assert.doesNotMatch(err.message, /AAAA/);
      assert.match(err.message, /openssl rand -hex 32/);
      return true;
    });
  });
});

describe('secret encryption key strength — deployment profile gating', () => {
  it('warns but does not throw under hosted-staging even when NODE_ENV=production', () => {
    // Mirrors the live astranull.site configuration. Gating must key off the
    // deployment profile, never NODE_ENV, or this deployment stops booting.
    const key = Buffer.from(PUBLISHED_FIXTURE_KEY_HEX, 'hex');
    const { warnings } = withCapturedWarnings(() =>
      assertStrongSecretEncryptionKey(key, {
        NODE_ENV: 'production',
        ASTRANULL_DEPLOYMENT_PROFILE: 'hosted-staging',
      }),
    );
    assert.ok(
      warnings.some((w) => /WARNING/.test(w) && /weak/i.test(w)),
      `expected a loud warning, got: ${JSON.stringify(warnings)}`,
    );
  });

  it('warns but does not throw when NODE_ENV=production with no profile set', () => {
    const key = Buffer.from(PUBLISHED_FIXTURE_KEY_HEX, 'hex');
    const { warnings } = withCapturedWarnings(() =>
      assertStrongSecretEncryptionKey(key, { NODE_ENV: 'production' }),
    );
    assert.equal(warnings.length, 1);
  });

  it('throws only for the production profile', () => {
    const key = Buffer.from(PUBLISHED_FIXTURE_KEY_HEX, 'hex');
    assert.throws(
      () => assertStrongSecretEncryptionKey(key, { ASTRANULL_DEPLOYMENT_PROFILE: 'production' }),
      /Refusing to start/,
    );
    assert.doesNotThrow(() =>
      withCapturedWarnings(() =>
        assertStrongSecretEncryptionKey(key, { ASTRANULL_DEPLOYMENT_PROFILE: 'local-staging' }),
      ),
    );
  });
});

describe('loadSecretEncryptionKey enforces strength', () => {
  it('rejects the published fixture key via the loader under production', () => {
    assert.throws(
      () =>
        loadSecretEncryptionKey({
          ASTRANULL_DEPLOYMENT_PROFILE: 'production',
          ASTRANULL_SECRET_ENCRYPTION_KEY: PUBLISHED_FIXTURE_KEY_HEX,
        }),
      /Refusing to start/,
    );
  });

  it('rejects a low-entropy base64 key via the loader under production', () => {
    const b64 = Buffer.alloc(32, 0x2a).toString('base64');
    assert.throws(
      () =>
        loadSecretEncryptionKey({
          ASTRANULL_DEPLOYMENT_PROFILE: 'production',
          ASTRANULL_SECRET_ENCRYPTION_KEY: b64,
        }),
      /Refusing to start/,
    );
  });

  it('accepts a strong random key via the loader under production', () => {
    const key = loadSecretEncryptionKey({
      ASTRANULL_DEPLOYMENT_PROFILE: 'production',
      ASTRANULL_SECRET_ENCRYPTION_KEY: randomBytes(32).toString('hex'),
    });
    assert.equal(key.length, 32);
  });

  it('still boots hosted-staging with the compromised key, with a warning', () => {
    const { result: key, warnings } = withCapturedWarnings(() =>
      loadSecretEncryptionKey({
        NODE_ENV: 'production',
        ASTRANULL_DEPLOYMENT_PROFILE: 'hosted-staging',
        ASTRANULL_SECRET_ENCRYPTION_KEY: PUBLISHED_FIXTURE_KEY_HEX,
      }),
    );
    assert.equal(key.length, 32);
    assert.ok(warnings.some((w) => /weak/i.test(w)));
  });
});
