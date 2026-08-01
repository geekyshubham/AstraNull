import { readFileSync } from 'node:fs';
import pg from 'pg';
import { isHostedStagingDeployment, resolveDeploymentProfile } from '../../lib/deploymentProfile.mjs';

const DEFAULT_POOL_MAX = 10;
const MIN_POOL_MAX = 1;
const MAX_POOL_MAX = 50;

const DEFAULT_IDLE_TIMEOUT_MS = 30_000;
const MIN_IDLE_TIMEOUT_MS = 1_000;
const MAX_IDLE_TIMEOUT_MS = 600_000;

const DEFAULT_CONNECTION_TIMEOUT_MS = 10_000;
const MIN_CONNECTION_TIMEOUT_MS = 1_000;
const MAX_CONNECTION_TIMEOUT_MS = 120_000;

function parseBoundedInt(raw, name, { min, max, fallback }) {
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return fallback;
  }
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}.`);
  }
  return n;
}

// URL query parameters that make `pg` build its own TLS config and therefore
// discard the `ssl` object we pass alongside `connectionString`.
// pg-connection-string sets `config.ssl = {}` whenever any of sslmode / sslcert
// / sslkey / sslrootcert is present, and `config.ssl = true` for
// sslnegotiation=direct; pg's ConnectionParameters then merges the PARSED url
// OVER the caller config, so our `{ ca, rejectUnauthorized: true }` is
// overwritten wholesale before it ever reaches client.ssl.
//
// `ssl` is a THIRD, independent clobber path: pg-connection-string:69-75 maps
// ssl=true / ssl=1 to `config.ssl = true` and ssl=0 to `config.ssl = false`,
// before and entirely separately from the sslmode/sslcert check below. A bare
// `ssl=true` therefore discarded the CA just as thoroughly as sslmode did, and
// `ssl=0` disabled TLS outright.
//
// None of these name a file on disk, so removing them cannot drop TLS material —
// the CA we supply is strictly more specific than what the URL was asking for.
//
// One is not purely cosmetic, stated precisely: dropping `sslnegotiation=direct`
// reverts the handshake from direct TLS to the standard postgres negotiation
// (pg reads it as a first-class connection parameter, not just an ssl-object
// hint). That is a wire-level change, but a safe-direction one — it falls back to
// the universally supported default, so it cannot fail anywhere direct worked. It
// costs one round trip and buys actual certificate verification.
const URL_SSL_MODE_PARAMS = Object.freeze(['sslmode', 'sslnegotiation', 'ssl']);
// These name key/cert files that pg reads from disk into config.ssl. Stripping
// them would silently drop client-certificate auth, so we never touch them.
const URL_SSL_MATERIAL_PARAMS = Object.freeze(['sslcert', 'sslkey', 'sslrootcert']);

/**
 * Remove the URL-level TLS parameters that would otherwise clobber a
 * caller-supplied `ssl: { ca, rejectUnauthorized: true }`.
 *
 * Returns the original string untouched (plus a reason) whenever rewriting
 * would be lossy or ambiguous, so a configured CA never turns a working boot
 * into a crash.
 *
 * @param {string} connectionString
 * @returns {{ connectionString: string, ignoredCaReason: string | null }}
 */
function stripUrlSslParamsForCa(connectionString) {
  let url;
  try {
    url = new URL(connectionString.replace(/^postgresql:/i, 'postgres:'));
  } catch {
    // libpq key=value DSNs ("host=... dbname=...") are not URLs. pg parses
    // those without setting config.ssl at all, so our ssl object already
    // survives and there is nothing to strip. Never throw here: this path used
    // to pass straight through and a boot-time parse error would be a
    // regression, not a fix.
    return { connectionString, ignoredCaReason: null };
  }

  const present = URL_SSL_MODE_PARAMS.filter((p) => url.searchParams.has(p));
  const material = URL_SSL_MATERIAL_PARAMS.filter((p) => url.searchParams.has(p));

  if (material.length) {
    // The URL already supplies its own TLS material (including possibly its own
    // root CA via sslrootcert). Two CAs are configured and we cannot merge them
    // without risking the loss of a client certificate, so leave the URL as the
    // single source of truth and say so out loud.
    return {
      connectionString,
      ignoredCaReason: `the database URL sets ${material.join(', ')}`,
    };
  }

  const sslmode = (url.searchParams.get('sslmode') ?? '').trim().toLowerCase();
  if (sslmode === 'disable') {
    // Deliberate: `sslmode=disable` means "no TLS at all", so removing it would
    // upgrade a plaintext connection to TLS and could fail against a server
    // that has no TLS listener. We refuse to change connectivity behind the
    // operator's back. The CA stays inert and the contradiction is warned
    // about — one of the two settings has to go.
    return { connectionString, ignoredCaReason: 'the database URL sets sslmode=disable' };
  }

  // `ssl=0` is pg's other spelling of "no TLS at all", and gets the same treatment
  // as sslmode=disable for the same reason: stripping it would upgrade a plaintext
  // connection to TLS behind the operator's back and could hard-fail against a
  // server with no TLS listener.
  //
  // Only the exact value '0' is carved out, because only '0' actually disables TLS
  // (pg-connection-string:73-75). pg leaves other falsy-looking spellings such as
  // `ssl=false` as truthy strings, so those already attempt TLS — stripping them
  // changes no connectivity, it only adds the CA we were asked to use.
  if ((url.searchParams.get('ssl') ?? '').trim() === '0') {
    return { connectionString, ignoredCaReason: 'the database URL sets ssl=0' };
  }

  if (!present.length) {
    return { connectionString, ignoredCaReason: null };
  }

  for (const param of present) {
    url.searchParams.delete(param);
  }
  return {
    connectionString: url.toString().replace(/^postgres:/i, 'postgresql:'),
    ignoredCaReason: null,
  };
}

/**
 * Resolve the PostgreSQL TLS CA (inline PEM or mounted file) and the
 * relaxed-verification flag. A CA makes certificate verification possible,
 * which is what the `sslmode=no-verify` rewrite otherwise gives up.
 * @param {NodeJS.ProcessEnv} env
 */
function resolvePgTlsCa(env) {
  const rawFlag = String(env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED ?? '1').trim();
  const verificationDisabled = rawFlag === '0' || rawFlag.toLowerCase() === 'false';

  const inline = (env.ASTRANULL_PG_SSL_CA ?? '').trim();
  const caFile = (env.ASTRANULL_PG_SSL_CA_FILE ?? '').trim();

  if (inline && caFile) {
    throw new Error('Set only one of ASTRANULL_PG_SSL_CA or ASTRANULL_PG_SSL_CA_FILE, not both.');
  }

  if (inline) {
    return { ca: inline, verificationDisabled };
  }

  if (caFile) {
    let contents;
    try {
      contents = readFileSync(caFile, 'utf8');
    } catch (err) {
      // Surface only the path and error code — never the file body.
      throw new Error(
        `Unable to read ASTRANULL_PG_SSL_CA_FILE at "${caFile}": ${err.code ?? 'read failed'}.`,
      );
    }
    if (!contents.trim()) {
      throw new Error(`ASTRANULL_PG_SSL_CA_FILE at "${caFile}" is empty.`);
    }
    return { ca: contents.trim(), verificationDisabled };
  }

  return { ca: null, verificationDisabled };
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function resolvePgPoolConfig(env = process.env) {
  const connectionString = (env.ASTRANULL_DATABASE_URL ?? '').trim();
  if (!connectionString) {
    throw new Error('ASTRANULL_DATABASE_URL must be set for PostgreSQL.');
  }

  const { ca, verificationDisabled } = resolvePgTlsCa(env);

  // A configured CA always wins: verification is the safe state, so the relaxed
  // flag is ignored rather than allowed to downgrade an otherwise-verified link.
  const relaxedTls = verificationDisabled && !ca;

  if (verificationDisabled && ca) {
    console.warn(
      '[astranull] WARNING: ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED=0 is ignored because a PostgreSQL TLS CA is configured; certificate verification stays enabled. Remove the flag.',
    );
  }

  if (relaxedTls) {
    const message =
      'ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED=0 disables PostgreSQL TLS certificate '
      + 'verification, exposing the database connection to man-in-the-middle attacks. '
      + 'Provide the managed-database CA via ASTRANULL_PG_SSL_CA or '
      + 'ASTRANULL_PG_SSL_CA_FILE and remove the flag.';
    // The explicit production profile always refuses. NODE_ENV=production also
    // refuses, EXCEPT for hosted-staging: that deployment runs NODE_ENV=production
    // today and must keep booting with a loud warning, but it declares itself
    // explicitly (ASTRANULL_DEPLOYMENT_PROFILE=hosted-staging, and independently
    // ASTRANULL_BUNDLED_STAGING_OIDC=1), so the carve-out keys on a positive
    // declaration rather than on the absence of one. Before this change an
    // undeclared NODE_ENV=production boot fell through to a warning and came up
    // with sslmode=no-verify, which made TLS the only production gate in the
    // codebase that trusted an easily-omitted variable — every gate in
    // src/config.mjs (persistence mode, auth mode, probe mode, rate limiting)
    // keys on NODE_ENV and refuses to start.
    const nodeEnv = String(env.NODE_ENV ?? 'development').trim();
    const refuses =
      resolveDeploymentProfile(env) === 'production'
      || (nodeEnv === 'production' && !isHostedStagingDeployment(env));
    if (refuses) {
      throw new Error(`Refusing to start: ${message}`);
    }
    console.warn(`[astranull] WARNING: ${message}`);
  }

  let resolvedConnectionString = connectionString;
  if (relaxedTls) {
    const url = new URL(connectionString.replace(/^postgresql:/i, 'postgres:'));
    url.searchParams.set('sslmode', 'no-verify');
    resolvedConnectionString = url.toString().replace(/^postgres:/i, 'postgresql:');
  } else if (ca) {
    // Without this, a configured CA is silently discarded. pg merges the parsed
    // connectionString over the caller config, so any sslmode in the URL
    // replaces our { ca, rejectUnauthorized: true } with a bare {} — the CA
    // never reaches client.ssl and the documented remediation for the
    // no-CA gap (docs/release-checklist.md) is a no-op. Managed-Postgres URLs
    // (including DigitalOcean's) carry sslmode=require, so this was the norm,
    // not an edge case.
    const stripped = stripUrlSslParamsForCa(connectionString);
    resolvedConnectionString = stripped.connectionString;
    if (stripped.ignoredCaReason) {
      console.warn(
        `[astranull] WARNING: the configured PostgreSQL TLS CA is NOT in effect because ${stripped.ignoredCaReason}. `
        + 'Remove that parameter from ASTRANULL_DATABASE_URL, or drop ASTRANULL_PG_SSL_CA / '
        + 'ASTRANULL_PG_SSL_CA_FILE, so there is a single source of truth for database TLS.',
      );
    }
  }

  return {
    connectionString: resolvedConnectionString,
    ...(ca ? { ssl: { ca, rejectUnauthorized: true } } : {}),
    max: parseBoundedInt(env.ASTRANULL_PG_POOL_MAX, 'ASTRANULL_PG_POOL_MAX', {
      min: MIN_POOL_MAX,
      max: MAX_POOL_MAX,
      fallback: DEFAULT_POOL_MAX,
    }),
    idleTimeoutMillis: parseBoundedInt(
      env.ASTRANULL_PG_IDLE_TIMEOUT_MS,
      'ASTRANULL_PG_IDLE_TIMEOUT_MS',
      {
        min: MIN_IDLE_TIMEOUT_MS,
        max: MAX_IDLE_TIMEOUT_MS,
        fallback: DEFAULT_IDLE_TIMEOUT_MS,
      },
    ),
    connectionTimeoutMillis: parseBoundedInt(
      env.ASTRANULL_PG_CONNECTION_TIMEOUT_MS,
      'ASTRANULL_PG_CONNECTION_TIMEOUT_MS',
      {
        min: MIN_CONNECTION_TIMEOUT_MS,
        max: MAX_CONNECTION_TIMEOUT_MS,
        fallback: DEFAULT_CONNECTION_TIMEOUT_MS,
      },
    ),
  };
}

/**
 * @param {import('pg').PoolConfig | NodeJS.ProcessEnv} configOrEnv
 * @returns {import('pg').Pool}
 */
export function createPgPool(configOrEnv = process.env) {
  const config =
    configOrEnv != null &&
    typeof configOrEnv === 'object' &&
    'connectionString' in configOrEnv &&
    configOrEnv.connectionString
      ? configOrEnv
      : resolvePgPoolConfig(configOrEnv);
  return new pg.Pool(config);
}

/**
 * @param {import('pg').Pool | null | undefined} pool
 */
export async function closePgPool(pool) {
  if (pool) {
    await pool.end();
  }
}

// Every tenant_isolation_* policy in db/schema.sql is silently inert if the
// connected role can bypass RLS. FORCE ROW LEVEL SECURITY closes the
// table-owner hole but does NOT constrain a superuser or a BYPASSRLS role, and
// nothing outside local Docker (db/docker/01-app-role.sql) had ever asserted
// which role the runtime actually connects as. /health and /ready pass either
// way, so this failure mode is invisible without an explicit check.
/**
 * The single source of truth for the posture query's column aliases.
 *
 * The SQL below is built from these names and describeRoleRlsPosture reads the row
 * through them, so an alias can never drift away from its reader. That drift would be
 * SILENT and total: every field would read `undefined`, `undefined === true` is false,
 * and the check would report a clean posture forever against a live database — the exact
 * false reassurance this code exists to prevent.
 *
 * Exported for assertions, but note what the test should NOT do: building a stub row from
 * this constant would make the test tautological — it would pass under any names at all.
 * tests/unit/postgres-pool.test.mjs deliberately spells the column names as literals, so
 * this constant is checked against an independent statement of the expected contract.
 */
export const ROLE_POSTURE_COLUMNS = Object.freeze({
  role: 'role_name',
  superuser: 'is_superuser',
  bypassRls: 'can_bypass_rls',
  ownedTables: 'owned_table_count',
});

const ROLE_RLS_POSTURE_SQL = `
  SELECT current_user AS ${ROLE_POSTURE_COLUMNS.role},
         r.rolsuper AS ${ROLE_POSTURE_COLUMNS.superuser},
         r.rolbypassrls AS ${ROLE_POSTURE_COLUMNS.bypassRls},
         (
           SELECT count(*)
           FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE c.relkind = 'r'
             AND n.nspname = 'public'
             AND c.relowner = r.oid
         ) AS ${ROLE_POSTURE_COLUMNS.ownedTables}
  FROM pg_roles r
  WHERE r.rolname = current_user
`;

/**
 * Classify the connected role's ability to bypass row level security.
 *
 * WARNINGS ONLY, deliberately — see the note on ownership below. Nobody has yet
 * verified which role the live ASTRANULL_DATABASE_URL authenticates as, and
 * promotion to production is a manual workflow_dispatch with no automatic
 * rollback, so a throw here could brick a deploy on an unverified assumption.
 *
 * OPERATOR ACTION before this can become a hard failure: confirm the runtime
 * role on the live database is (a) not a superuser, (b) NOBYPASSRLS, and (c) not
 * the owner of the public tenant tables — i.e. that the app role is distinct
 * from the migration/owner role. Once (a) and (b) are confirmed in a real
 * deploy, promote those two to a throw and leave (c) as a warning.
 *
 * @param {{ role_name?: string, is_superuser?: unknown, can_bypass_rls?: unknown, owned_table_count?: unknown }} row
 * @returns {{ role: string, bypassesRls: boolean, ownsTables: boolean, warnings: string[] }}
 */
export function describeRoleRlsPosture(row) {
  // Read through ROLE_POSTURE_COLUMNS, not literals: the SQL aliases are generated from the
  // same constant, so the query and this reader cannot drift apart into a silent all-undefined
  // "clean posture" result.
  const role = String(row?.[ROLE_POSTURE_COLUMNS.role] ?? 'unknown');
  const isSuperuser = row?.[ROLE_POSTURE_COLUMNS.superuser] === true;
  const canBypassRls = row?.[ROLE_POSTURE_COLUMNS.bypassRls] === true;
  const ownedTableCount = Number(row?.[ROLE_POSTURE_COLUMNS.ownedTables] ?? 0) || 0;

  /** @type {string[]} */
  const warnings = [];

  if (isSuperuser) {
    warnings.push(
      `PostgreSQL role "${role}" is a SUPERUSER. Superusers bypass row level security, so every `
      + 'tenant_isolation_* policy is inert and cross-tenant reads are possible. Connect as a '
      + 'dedicated NOSUPERUSER NOBYPASSRLS application role.',
    );
  }

  if (canBypassRls) {
    warnings.push(
      `PostgreSQL role "${role}" has BYPASSRLS. Row level security does not constrain it, so `
      + 'tenant isolation is not enforced. Run ALTER ROLE ... NOBYPASSRLS, or connect as a '
      + 'dedicated application role.',
    );
  }

  if (ownedTableCount > 0) {
    // Intent-only, not load-bearing: FORCE ROW LEVEL SECURITY already applies
    // policies to table owners, so ownership alone does not defeat isolation.
    // It is warned about because owning the tables means the role can ALTER
    // them (including disabling RLS), which is more authority than the runtime
    // needs. On managed Postgres the migration runner and the app commonly
    // share one role, so a non-zero count is the likely current state and must
    // never be escalated to a throw without an operator migrating the roles apart.
    warnings.push(
      `PostgreSQL role "${role}" owns ${ownedTableCount} table(s) in schema public. FORCE ROW LEVEL `
      + 'SECURITY still applies policies to owners, so isolation holds, but an owner can ALTER or '
      + 'disable RLS. Prefer a separate non-owner runtime role from the migration role.',
    );
  }

  return { role, bypassesRls: isSuperuser || canBypassRls, ownsTables: ownedTableCount > 0, warnings };
}

/**
 * Query the connected role's RLS posture and emit loud warnings.
 *
 * Never throws on query failure: this runs at startup next to the connectivity
 * probe, and a catalog permission quirk must not be able to take the control
 * plane down. An unreadable catalog is reported as an unknown posture.
 *
 * @param {{ query: (sql: string) => Promise<{ rows: Array<Record<string, unknown>> }> }} client
 * @param {{ warn?: (message: string) => void }} [options]
 */
export async function checkRoleRlsPosture(client, { warn = console.warn } = {}) {
  let rows;
  try {
    ({ rows } = await client.query(ROLE_RLS_POSTURE_SQL));
  } catch (err) {
    const detail = err instanceof Error ? (err.code ?? err.message) : String(err);
    const message = `Unable to verify the PostgreSQL role's row-level-security posture: ${detail}. `
      + 'Tenant isolation depends on the runtime role being NOBYPASSRLS and non-superuser; verify it manually.';
    warn(`[astranull] WARNING: ${message}`);
    return { role: 'unknown', bypassesRls: null, ownsTables: null, warnings: [message] };
  }

  if (!rows?.length) {
    const message = 'The connected PostgreSQL role was not found in pg_roles, so its row-level-security '
      + 'posture could not be verified. Tenant isolation requires a non-superuser NOBYPASSRLS role.';
    warn(`[astranull] WARNING: ${message}`);
    return { role: 'unknown', bypassesRls: null, ownsTables: null, warnings: [message] };
  }

  const posture = describeRoleRlsPosture(rows[0]);
  for (const message of posture.warnings) {
    warn(`[astranull] WARNING: ${message}`);
  }
  return posture;
}

/**
 * Lightweight connectivity probe (no secrets logged).
 * @param {import('pg').Pool} pool
 */
export async function pingPostgres(pool) {
  const client = await pool.connect();
  try {
    await client.query('SELECT 1 AS ok');
    return { ok: true };
  } finally {
    client.release();
  }
}