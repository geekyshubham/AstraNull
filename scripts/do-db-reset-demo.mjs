#!/usr/bin/env node
/**
 * DigitalOcean hosted-staging Postgres reset: wipe tenant data, re-seed demo tenant.
 *
 * Dev Postgres is only reachable from the App Platform container. This script runs
 * the reset inside the live web instance via doctl console when no local URL works.
 *
 * Demo login after reset: https://astranull.site/login
 *   tenant_id: ten_demo
 *   user_id:   usr_admin
 *   role:      admin
 */
import { closePgPool, createPgPool } from '../src/persistence/postgres/pool.mjs';
import { LOCAL_STAGING_DEMO_IDS } from './lib/localStaging.mjs';
import {
  countDemoSnapshot,
  resetAndSeedDemoTenant,
} from './lib/demoTenantReset.mjs';
import {
  redactDatabaseUrl,
  resolveDigitalOceanAppId,
  resolveDigitalOceanDatabaseUrl,
} from './lib/doAppDatabase.mjs';
import { runDigitalOceanConsoleCommands } from './lib/runDigitalOceanConsoleCommand.mjs';

const LOGIN = Object.freeze({
  url: 'https://astranull.site/login',
  tenant_id: LOCAL_STAGING_DEMO_IDS.tenantId,
  user_id: LOCAL_STAGING_DEMO_IDS.adminUserId,
  role: 'admin',
});

/**
 * @param {string} databaseUrl
 */
function buildPoolEnv(databaseUrl) {
  return {
    ...process.env,
    ASTRANULL_DATABASE_URL: databaseUrl,
    ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED: process.env.ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED ?? '0',
  };
}

/**
 * @param {string} databaseUrl
 */
async function runLocalReset(databaseUrl) {
  const pool = createPgPool(buildPoolEnv(databaseUrl));
  try {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const reset = await resetAndSeedDemoTenant(client);
      await client.query('COMMIT');
      return {
        mode: 'local',
        database: redactDatabaseUrl(databaseUrl),
        ...reset,
        counts_after: await countDemoSnapshot(pool),
        login: LOGIN,
      };
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } finally {
    await closePgPool(pool);
  }
}

const REMOTE_TRUNCATE_COMMAND = `cd /app && node --input-type=module <<'NODE'
import { createPgPool, closePgPool } from './src/persistence/postgres/pool.mjs';
const pool = createPgPool({ ...process.env, ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED: '0' });
const client = await pool.connect();
const tables = (await client.query("SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename NOT IN ('schema_migrations','waf_products')")).rows.map((row) => row.tablename);
if (tables.length) {
  const quoted = tables.map((table) => '"' + table + '"').join(', ');
  await client.query('TRUNCATE TABLE ' + quoted + ' RESTART IDENTITY CASCADE');
}
await client.release();
await closePgPool(pool);
console.log('truncated', tables.length);
NODE`;

/**
 * Run reset inside the App Platform web container (dev DB is VPC-only).
 */
function runRemoteReset() {
  const output = runDigitalOceanConsoleCommands(
    [REMOTE_TRUNCATE_COMMAND, 'cd /app && node scripts/seed-local-staging-tenant.mjs'],
    { timeoutSec: 180 },
  );

  const normalized = String(output).replace(/\r/g, '');
  const truncatedMatches = [...normalized.matchAll(/truncated (\d+)/g)];
  const truncatedTables = Number(truncatedMatches.at(-1)?.[1] ?? '0');
  const seeded =
    normalized.includes('seed-local-staging-tenant:') &&
    (normalized.includes('seeded tenant=ten_demo') || normalized.includes('already_present tenant=ten_demo'));
  if (truncatedTables <= 0 || !seeded) {
    throw new Error(`Remote reset did not complete successfully.${output ? ` Output: ${output.slice(-500)}` : ''}`);
  }

  return {
    mode: 'remote',
    truncated_tables: truncatedTables,
    seed_status: normalized.includes('seeded tenant=ten_demo')
      ? 'seeded tenant=ten_demo'
      : 'already_present tenant=ten_demo',
    tenant_id: LOCAL_STAGING_DEMO_IDS.tenantId,
    login: LOGIN,
  };
}

async function main() {
  const explicitUrl = String(process.env.ASTRANULL_DATABASE_URL ?? '').trim();
  const forceRemote = process.env.ASTRANULL_DO_RESET_REMOTE === '1';

  let report;
  if (!forceRemote && explicitUrl) {
    try {
      report = await runLocalReset(explicitUrl);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (!/timeout|ECONNREFUSED|ENOTFOUND/i.test(message)) throw err;
      report = runRemoteReset();
    }
  } else if (!forceRemote) {
    try {
      const databaseUrl = resolveDigitalOceanDatabaseUrl();
      report = await runLocalReset(databaseUrl);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (!/timeout|ECONNREFUSED|ENOTFOUND/i.test(message)) throw err;
      report = runRemoteReset();
    }
  } else {
    report = runRemoteReset();
  }

  console.log(JSON.stringify(report, null, 2));

  if (report.mode === 'local') {
    if (report.counts_after?.tenants !== 1 || report.counts_after?.target_groups !== 1) {
      process.exitCode = 1;
    }
  } else if (report.mode === 'remote') {
    if (!String(report.seed_status ?? '').startsWith('seeded')) {
      process.exitCode = 1;
    }
  }
}

main().catch((err) => {
  console.error(err?.message ?? err);
  process.exit(1);
});