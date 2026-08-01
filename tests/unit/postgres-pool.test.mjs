import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import pg from 'pg';
import {
  checkRoleRlsPosture,
  closePgPool,
  createPgPool,
  describeRoleRlsPosture,
  pingPostgres,
  resolvePgPoolConfig,
} from '../../src/persistence/postgres/pool.mjs';

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
  it('keeps verification enabled and strips URL sslmode when a CA is provided', () => {
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb?sslmode=require';
    process.env.ASTRANULL_PG_SSL_CA = FAKE_CA_PEM;
    delete process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED;

    const config = resolvePgPoolConfig();
    assert.doesNotMatch(config.connectionString, /no-verify/);
    // sslmode must NOT survive: pg merges the parsed URL over the caller config,
    // so any sslmode replaces our ssl object with {} and drops the CA entirely.
    // See the client.ssl assertions below for the behaviour that actually matters.
    assert.equal(config.connectionString, 'postgresql://localhost/testdb');
    assert.equal(config.ssl.rejectUnauthorized, true);
    assert.equal(config.ssl.ca, FAKE_CA_PEM);
  });

  it('delivers the CA to a real pg client for a managed-Postgres sslmode URL', () => {
    // Regression guard for a silently-discarded CA. Asserting resolvePgPoolConfig's
    // own return value is not enough — it looked correct the whole time the CA was
    // being thrown away downstream. This drives pg's real config pipeline
    // (ConnectionParameters via the Client constructor, which does not connect).
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb?sslmode=require';
    process.env.ASTRANULL_PG_SSL_CA = FAKE_CA_PEM;
    delete process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED;

    const client = new pg.Client(resolvePgPoolConfig());
    assert.equal(typeof client.ssl, 'object', `expected a TLS config object, got ${JSON.stringify(client.ssl)}`);
    assert.equal(client.ssl.ca, FAKE_CA_PEM, 'the configured CA must reach pg, not be replaced by {}');
    assert.equal(client.ssl.rejectUnauthorized, true);
  });

  it('delivers the CA to a real pg client when the URL carries sslnegotiation', () => {
    // sslnegotiation=direct makes pg-connection-string set ssl = true (not {}),
    // which discards the CA just as thoroughly as sslmode does.
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb?sslnegotiation=direct';
    process.env.ASTRANULL_PG_SSL_CA = FAKE_CA_PEM;
    delete process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED;

    const client = new pg.Client(resolvePgPoolConfig());
    assert.equal(client.ssl?.ca, FAKE_CA_PEM);
    assert.equal(client.ssl?.rejectUnauthorized, true);
  });

  /**
   * `ssl=` is a THIRD clobber path, independent of both sslmode and sslnegotiation.
   * pg-connection-string:69-75 maps ssl=true / ssl=1 to `config.ssl = true` before it
   * ever looks at sslmode, so a bare `ssl=true` discarded the CA with no warning at all.
   */
  for (const query of ['ssl=true', 'ssl=1']) {
    it(`delivers the CA to a real pg client when the URL carries ${query}`, () => {
      process.env.ASTRANULL_DATABASE_URL = `postgresql://localhost/testdb?${query}`;
      process.env.ASTRANULL_PG_SSL_CA = FAKE_CA_PEM;
      delete process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED;

      const client = new pg.Client(resolvePgPoolConfig());
      assert.equal(
        client.ssl?.ca,
        FAKE_CA_PEM,
        `${query} must not replace the CA with a bare boolean`,
      );
      assert.equal(client.ssl?.rejectUnauthorized, true);
    });
  }

  it('leaves ssl=0 alone and warns that the CA is not in effect', () => {
    // ssl=0 is pg's other spelling of "no TLS at all" (pg-connection-string:73-75), so it
    // gets the sslmode=disable treatment: stripping it would upgrade a plaintext link to
    // TLS behind the operator's back and could fail against a server with no TLS listener.
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb?ssl=0';
    process.env.ASTRANULL_PG_SSL_CA = FAKE_CA_PEM;
    delete process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED;

    const { result: config, warnings } = withCapturedWarnings(() => resolvePgPoolConfig());
    assert.match(config.connectionString, /ssl=0/);
    assert.equal(new pg.Client(config).ssl, false, 'TLS must stay off, not be silently enabled');
    assert.ok(
      warnings.some((w) => /NOT in effect/i.test(w) && /ssl=0/.test(w)),
      `expected a CA-ignored warning naming ssl=0, got: ${JSON.stringify(warnings)}`,
    );
  });

  it('treats only the exact value 0 as TLS-off, so ssl=false still gets the CA', () => {
    // pg leaves 'false' as a truthy string, so that connection already attempts TLS.
    // Stripping it changes no connectivity; it only adds the verification we were asked for.
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb?ssl=false';
    process.env.ASTRANULL_PG_SSL_CA = FAKE_CA_PEM;
    delete process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED;

    assert.equal(new pg.Client(resolvePgPoolConfig()).ssl?.ca, FAKE_CA_PEM);
  });

  it('preserves non-TLS query parameters and credentials while stripping sslmode', () => {
    process.env.ASTRANULL_DATABASE_URL =
      'postgresql://user:p%40ss@db.example:5432/astranull?sslmode=require&application_name=astranull';
    process.env.ASTRANULL_PG_SSL_CA = FAKE_CA_PEM;
    delete process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED;

    const config = resolvePgPoolConfig();
    assert.doesNotMatch(config.connectionString, /sslmode/);
    assert.match(config.connectionString, /application_name=astranull/);
    const client = new pg.Client(config);
    assert.equal(client.ssl?.ca, FAKE_CA_PEM);
    assert.equal(client.connectionParameters.host, 'db.example');
    assert.equal(client.connectionParameters.port, 5432);
    assert.equal(client.connectionParameters.database, 'astranull');
  });

  it('passes a libpq key=value DSN through untouched instead of throwing when a CA is set', () => {
    // A DSN is not a URL. Widening the URL rewrite to every CA path must not turn
    // a previously-working boot into a startup crash.
    process.env.ASTRANULL_DATABASE_URL = 'host=localhost dbname=testdb sslmode=require';
    process.env.ASTRANULL_PG_SSL_CA = FAKE_CA_PEM;
    delete process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED;

    const config = resolvePgPoolConfig();
    assert.equal(config.connectionString, 'host=localhost dbname=testdb sslmode=require');
    // pg does not parse a DSN into config.ssl, so the caller's CA already survives.
    assert.equal(new pg.Client(config).ssl?.ca, FAKE_CA_PEM);
  });

  it('leaves sslmode=disable alone and warns that the CA is not in effect', () => {
    // Deliberate: stripping sslmode=disable would upgrade a plaintext link to TLS
    // behind the operator's back and could fail against a server with no TLS
    // listener. The contradiction is surfaced instead of silently resolved.
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb?sslmode=disable';
    process.env.ASTRANULL_PG_SSL_CA = FAKE_CA_PEM;
    delete process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED;

    const { result: config, warnings } = withCapturedWarnings(() => resolvePgPoolConfig());
    assert.match(config.connectionString, /sslmode=disable/);
    assert.ok(
      warnings.some((w) => /NOT in effect/i.test(w) && /sslmode=disable/.test(w)),
      `expected a CA-ignored warning, got: ${JSON.stringify(warnings)}`,
    );
  });

  it('does not strip sslrootcert/sslcert and warns the CA is not in effect', () => {
    // Those parameters name files pg reads into config.ssl; removing them would
    // silently drop client-certificate auth.
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb?sslmode=verify-full&sslrootcert=/tmp/root.crt';
    process.env.ASTRANULL_PG_SSL_CA = FAKE_CA_PEM;
    delete process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED;

    const { result: config, warnings } = withCapturedWarnings(() => resolvePgPoolConfig());
    assert.match(config.connectionString, /sslrootcert=/);
    assert.ok(
      warnings.some((w) => /NOT in effect/i.test(w) && /sslrootcert/.test(w)),
      `expected an sslrootcert conflict warning, got: ${JSON.stringify(warnings)}`,
    );
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

  it('refuses to boot for relaxed TLS when NODE_ENV=production and no profile is set', () => {
    // Fail closed on an undeclared production boot. The hosted-staging carve-out
    // keys on a positive self-declaration (see the test above), so the absence of
    // any profile can no longer be a route to booting with sslmode=no-verify.
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb';
    process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED = '0';
    process.env.NODE_ENV = 'production';
    delete process.env.ASTRANULL_DEPLOYMENT_PROFILE;
    delete process.env.ASTRANULL_BUNDLED_STAGING_OIDC;
    delete process.env.ASTRANULL_PG_SSL_CA;

    assert.throws(() => resolvePgPoolConfig(), /Refusing to start/);
  });

  it('still boots for relaxed TLS when NODE_ENV is not production', () => {
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb';
    process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED = '0';
    process.env.NODE_ENV = 'development';
    delete process.env.ASTRANULL_DEPLOYMENT_PROFILE;
    delete process.env.ASTRANULL_PG_SSL_CA;

    const { result: config, warnings } = withCapturedWarnings(() => resolvePgPoolConfig());
    assert.match(config.connectionString, /sslmode=no-verify/);
    assert.ok(warnings.length >= 1);
  });

  it('honours the bundled-staging flag as a hosted-staging self-declaration', () => {
    // ASTRANULL_BUNDLED_STAGING_OIDC=1 resolves to the hosted-staging profile, so
    // the live deployment keeps booting even if the explicit profile var is dropped.
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb';
    process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED = '0';
    process.env.NODE_ENV = 'production';
    delete process.env.ASTRANULL_DEPLOYMENT_PROFILE;
    process.env.ASTRANULL_BUNDLED_STAGING_OIDC = '1';
    delete process.env.ASTRANULL_PG_SSL_CA;

    const { result: config } = withCapturedWarnings(() => resolvePgPoolConfig());
    assert.match(config.connectionString, /sslmode=no-verify/);
  });
});

describe('postgres role RLS posture', () => {
  const CLEAN_ROW = Object.freeze({
    role_name: 'astranull_app',
    is_superuser: false,
    can_bypass_rls: false,
    owned_table_count: 0,
  });

  it('reports no warnings for a non-owner NOBYPASSRLS role', () => {
    const posture = describeRoleRlsPosture(CLEAN_ROW);
    assert.deepEqual(posture.warnings, []);
    assert.equal(posture.bypassesRls, false);
    assert.equal(posture.ownsTables, false);
    assert.equal(posture.role, 'astranull_app');
  });

  it('flags a superuser as bypassing RLS', () => {
    const posture = describeRoleRlsPosture({ ...CLEAN_ROW, role_name: 'doadmin', is_superuser: true });
    assert.equal(posture.bypassesRls, true);
    assert.ok(posture.warnings.some((w) => /SUPERUSER/.test(w) && /doadmin/.test(w)));
  });

  it('flags an explicit BYPASSRLS role', () => {
    const posture = describeRoleRlsPosture({ ...CLEAN_ROW, can_bypass_rls: true });
    assert.equal(posture.bypassesRls, true);
    assert.ok(posture.warnings.some((w) => /BYPASSRLS/.test(w)));
  });

  it('warns about table ownership without calling it an isolation bypass', () => {
    // FORCE ROW LEVEL SECURITY still applies policies to owners, so ownership is
    // excess authority rather than a hole. This must stay a warning: on managed
    // Postgres the migration runner and the app commonly share one role.
    const posture = describeRoleRlsPosture({ ...CLEAN_ROW, owned_table_count: 42 });
    assert.equal(posture.bypassesRls, false);
    assert.equal(posture.ownsTables, true);
    assert.ok(posture.warnings.some((w) => /owns 42 table/.test(w)));
  });

  it('checkRoleRlsPosture queries the catalog and emits warnings without throwing', async () => {
    const queries = [];
    const warnings = [];
    const client = {
      async query(sql) {
        queries.push(sql);
        return { rows: [{ ...CLEAN_ROW, role_name: 'doadmin', can_bypass_rls: true }] };
      },
    };

    const posture = await checkRoleRlsPosture(client, { warn: (m) => warnings.push(m) });
    assert.equal(posture.bypassesRls, true);
    assert.equal(queries.length, 1);
    // Observe the shipped SQL, not a copy of it.
    assert.match(queries[0], /rolbypassrls/);
    assert.match(queries[0], /current_user/);
    assert.ok(warnings.some((w) => /WARNING/.test(w) && /BYPASSRLS/.test(w)));
  });

  it('checkRoleRlsPosture never throws when the catalog query fails', async () => {
    const warnings = [];
    const client = {
      async query() {
        const err = new Error('permission denied for table pg_roles');
        err.code = '42501';
        throw err;
      },
    };

    const posture = await checkRoleRlsPosture(client, { warn: (m) => warnings.push(m) });
    assert.equal(posture.role, 'unknown');
    assert.equal(posture.bypassesRls, null);
    assert.ok(warnings.some((w) => /Unable to verify/.test(w)));
  });

  it('checkRoleRlsPosture reports an unknown posture when the role is missing', async () => {
    const warnings = [];
    const client = { async query() { return { rows: [] }; } };
    const posture = await checkRoleRlsPosture(client, { warn: (m) => warnings.push(m) });
    assert.equal(posture.role, 'unknown');
    assert.ok(warnings.some((w) => /not found in pg_roles/.test(w)));
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