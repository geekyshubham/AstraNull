import { LOCAL_STAGING_DEMO_IDS } from './localStaging.mjs';
import { seedLocalStagingTenant } from '../seed-local-staging-tenant.mjs';

export const DEMO_RESET_PRESERVED_TABLES = Object.freeze(['schema_migrations', 'waf_products']);

/**
 * @param {import('pg').PoolClient} client
 */
export async function listPublicTables(client) {
  const { rows } = await client.query(
    `SELECT tablename
     FROM pg_tables
     WHERE schemaname = 'public'
     ORDER BY tablename`,
  );
  return rows.map((row) => String(row.tablename));
}

/**
 * @param {import('pg').PoolClient} client
 * @param {readonly string[]} [preservedTables]
 */
export async function truncateHostedStagingData(client, preservedTables = DEMO_RESET_PRESERVED_TABLES) {
  const preserved = new Set(preservedTables);
  const tables = await listPublicTables(client);
  const targets = tables.filter((table) => !preserved.has(table));
  if (targets.length === 0) {
    return { truncated_tables: [], preserved_tables: [...preservedTables] };
  }

  const quoted = targets.map((table) => `"${table.replace(/"/g, '""')}"`).join(', ');
  await client.query(`TRUNCATE TABLE ${quoted} RESTART IDENTITY CASCADE`);
  return { truncated_tables: targets, preserved_tables: [...preservedTables] };
}

/**
 * @param {import('pg').PoolClient} client
 * @param {typeof LOCAL_STAGING_DEMO_IDS} [ids]
 */
export async function resetAndSeedDemoTenant(client, ids = LOCAL_STAGING_DEMO_IDS) {
  const truncated = await truncateHostedStagingData(client);
  const seedResult = await seedLocalStagingTenant(client, ids);
  return {
    truncated,
    seeded: seedResult.seeded,
    tenant_id: seedResult.tenantId,
  };
}

/**
 * @param {import('pg').Pool} pool
 */
export async function countDemoSnapshot(pool) {
  const tables = [
    'tenants',
    'users',
    'environments',
    'target_groups',
    'targets',
    'agents',
    'test_runs',
    'findings',
    'waf_validation_plans',
  ];
  const counts = {};
  const client = await pool.connect();
  try {
    for (const table of tables) {
      const { rows } = await client.query(`SELECT COUNT(*)::int AS count FROM ${table}`);
      counts[table] = Number(rows[0]?.count ?? 0);
    }
  } finally {
    client.release();
  }
  return counts;
}