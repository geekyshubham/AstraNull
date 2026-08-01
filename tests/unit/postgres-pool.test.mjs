import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { closePgPool, createPgPool, pingPostgres, resolvePgPoolConfig } from '../../src/persistence/postgres/pool.mjs';

// Not a real certificate — only needs to be non-empty PEM-shaped text, since
// resolvePgPoolConfig passes it through to pg rather than parsing it.
const FAKE_CA_PEM = '-----BEGIN CERTIFICATE-----\nZmFrZS10ZXN0LWNh\n-----END CERTIFICATE-----';

/** Capture console.warn output so warning-vs-throw behaviour can be asserted. */
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

describe('postgres pool', () => {
  it('resolvePgPoolConfig uses bounded env overrides', () => {
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb';
    process.env.ASTRANULL_PG_POOL_MAX = '5';
    process.env.ASTRANULL_PG_IDLE_TIMEOUT_MS = '2000';
    process.env.ASTRANULL_PG_CONNECTION_TIMEOUT_MS = '3000';
    const config = resolvePgPoolConfig();
    assert.equal(config.max, 5);
    assert.equal(config.idleTimeoutMillis, 2000);
    assert.equal(config.connectionTimeoutMillis, 3000);
    assert.equal(config.connectionString, 'postgresql://localhost/testdb');
  });

  it('rejects invalid pool max without exposing database URL', () => {
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://secret:secret@host/db';
    process.env.ASTRANULL_PG_POOL_MAX = '9999';
    assert.throws(() => resolvePgPoolConfig(), (err) => {
      assert.match(err.message, /ASTRANULL_PG_POOL_MAX must be an integer/);
      assert.doesNotMatch(err.message, /secret@host/);
      return true;
    });
  });

  it('requires database URL', () => {
    delete process.env.ASTRANULL_DATABASE_URL;
    assert.throws(() => resolvePgPoolConfig(), /ASTRANULL_DATABASE_URL must be set/);
  });

  it('allows managed Postgres TLS when ssl rejection is disabled', () => {
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb?sslmode=require';
    process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED = '0';
    const config = withCapturedWarnings(() => resolvePgPoolConfig()).result;
    assert.match(config.connectionString, /sslmode=no-verify/);
  });
});

describe('postgres pool TLS verification', () => {
  it('keeps verification enabled and does not rewrite sslmode when a CA is provided', () => {
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb?sslmode=require';
    process.env.ASTRANULL_PG_SSL_CA = FAKE_CA_PEM;
    delete process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED;

    const config = resolvePgPoolConfig();
    assert.doesNotMatch(config.connectionString, /no-verify/);
    assert.equal(config.connectionString, 'postgresql://localhost/testdb?sslmode=require');
    assert.equal(config.ssl.rejectUnauthorized, true);
    assert.equal(config.ssl.ca, FAKE_CA_PEM);
  });

  it('a configured CA overrides the relaxed flag instead of downgrading to no-verify', () => {
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb?sslmode=require';
    process.env.ASTRANULL_PG_SSL_CA = FAKE_CA_PEM;
    process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED = '0';

    const { result: config, warnings } = withCapturedWarnings(() => resolvePgPoolConfig());
    assert.doesNotMatch(config.connectionString, /no-verify/);
    assert.equal(config.ssl.rejectUnauthorized, true);
    assert.ok(warnings.some((w) => /ignored/i.test(w)));
  });

  it('reads the CA from a mounted file', () => {
    const caPath = path.join(mkdtempSync(path.join(tmpdir(), 'astranull-ca-')), 'ca.crt');
    writeFileSync(caPath, `${FAKE_CA_PEM}\n`);
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb';
    process.env.ASTRANULL_PG_SSL_CA_FILE = caPath;

    const config = resolvePgPoolConfig();
    assert.equal(config.ssl.ca, FAKE_CA_PEM);
    assert.equal(config.ssl.rejectUnauthorized, true);
  });

  it('reports an unreadable CA file by path without leaking contents', () => {
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb';
    process.env.ASTRANULL_PG_SSL_CA_FILE = '/nonexistent/astranull-ca.crt';
    assert.throws(() => resolvePgPoolConfig(), /ASTRANULL_PG_SSL_CA_FILE.*ENOENT/s);
  });

  it('rejects setting both inline CA and CA file', () => {
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb';
    process.env.ASTRANULL_PG_SSL_CA = FAKE_CA_PEM;
    process.env.ASTRANULL_PG_SSL_CA_FILE = '/tmp/ca.crt';
    assert.throws(() => resolvePgPoolConfig(), /only one of/i);
  });

  it('refuses to boot with verification disabled under the production profile', () => {
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://user:pass@db.example/astranull';
    process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED = '0';
    process.env.ASTRANULL_DEPLOYMENT_PROFILE = 'production';
    delete process.env.ASTRANULL_PG_SSL_CA;

    assert.throws(() => resolvePgPoolConfig(), (err) => {
      assert.match(err.message, /Refusing to start/);
      assert.match(err.message, /ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED=0/);
      // Never echo credentials in a startup failure.
      assert.doesNotMatch(err.message, /user:pass/);
      return true;
    });
  });

  it('warns but still boots with verification disabled under hosted-staging, even when NODE_ENV=production', () => {
    // Mirrors the live astranull.site configuration: the hard failure must be
    // gated on the deployment profile, never on NODE_ENV.
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb';
    process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED = '0';
    process.env.ASTRANULL_DEPLOYMENT_PROFILE = 'hosted-staging';
    process.env.NODE_ENV = 'production';
    delete process.env.ASTRANULL_PG_SSL_CA;

    const { result: config, warnings } = withCapturedWarnings(() => resolvePgPoolConfig());
    assert.match(config.connectionString, /sslmode=no-verify/);
    assert.ok(
      warnings.some((w) => /WARNING/.test(w) && /man-in-the-middle/i.test(w)),
      `expected a loud TLS warning, got: ${JSON.stringify(warnings)}`,
    );
  });

  it('does not throw for relaxed TLS when NODE_ENV=production but no profile is set', () => {
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb';
    process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED = '0';
    process.env.NODE_ENV = 'production';
    delete process.env.ASTRANULL_DEPLOYMENT_PROFILE;
    delete process.env.ASTRANULL_PG_SSL_CA;

    const { warnings } = withCapturedWarnings(() => resolvePgPoolConfig());
    assert.ok(warnings.length >= 1);
  });
});

describe('postgres pool lifecycle', () => {
  it('pingPostgres uses SELECT 1 and releases client', async () => {
    const released = [];
    const pool = {
      async connect() {
        return {
          async query(text) {
            assert.equal(text, 'SELECT 1 AS ok');
            return { rows: [{ ok: 1 }] };
          },
          release() {
            released.push(true);
          },
        };
      },
    };
    const result = await pingPostgres(pool);
    assert.deepEqual(result, { ok: true });
    assert.equal(released.length, 1);
  });

  it('closePgPool ends pool when present', async () => {
    let ended = false;
    await closePgPool({ end: async () => { ended = true; } });
    assert.equal(ended, true);
    await closePgPool(null);
  });

  it('createPgPool accepts explicit config object', () => {
    const pool = createPgPool({ connectionString: 'postgresql://localhost/x' });
    assert.ok(pool);
    assert.equal(typeof pool.end, 'function');
    pool.end().catch(() => {});
  });
});