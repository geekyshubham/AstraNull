import { readFileSync } from 'node:fs';
import pg from 'pg';
import { resolveDeploymentProfile } from '../../lib/deploymentProfile.mjs';

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
    // Gated on the deployment profile only (never NODE_ENV): hosted-staging runs
    // with NODE_ENV=production today and must keep booting with a loud warning.
    if (resolveDeploymentProfile(env) === 'production') {
      throw new Error(`Refusing to start: ${message}`);
    }
    console.warn(`[astranull] WARNING: ${message}`);
  }

  let resolvedConnectionString = connectionString;
  if (relaxedTls) {
    const url = new URL(connectionString.replace(/^postgresql:/i, 'postgres:'));
    url.searchParams.set('sslmode', 'no-verify');
    resolvedConnectionString = url.toString().replace(/^postgres:/i, 'postgresql:');
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