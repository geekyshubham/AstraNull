#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DEMO_AUTO_VERIFY_ENV,
  DEMO_AUTO_VERIFY_SOURCE_KIND,
  DEMO_AUTO_VERIFY_STATE,
  demoAutoVerifyAuditEntry,
  demoAutoVerifySourceRef,
  isDemoAutoVerifyTenant,
} from '../src/lib/demoAutoVerify.mjs';
import { newId } from '../src/lib/ids.mjs';

const USAGE = `Usage: node scripts/demo-auto-verify-backfill.mjs --tenant-id <tenant>

Marks existing targets of an allowlisted demo tenant as verified (ADR-0016).
The tenant must be listed in ${DEMO_AUTO_VERIFY_ENV}. Uses Postgres when
ASTRANULL_DATABASE_URL is set, otherwise the dev JSON store.`;

const SYSTEM_CTX_ROLE = 'system';

function parseTenantId(argv) {
  const index = argv.indexOf('--tenant-id');
  return index >= 0 ? String(argv[index + 1] ?? '').trim() : '';
}

async function backfillPostgres(tenantId, env) {
  const { closePgPool, createPgPool } = await import('../src/persistence/postgres/pool.mjs');
  const { withTenantContext } = await import('../src/persistence/postgres/tenantContext.mjs');
  const { createAuditRepository } = await import('../src/persistence/postgres/auditRepository.mjs');
  const pool = createPgPool(env);
  const auditRepository = createAuditRepository(pool);
  const ctx = { tenantId, userId: 'system:demo-auto-verify', role: SYSTEM_CTX_ROLE };
  try {
    return await withTenantContext(pool, tenantId, async (client) => {
      const { rows } = await client.query(
        `SELECT t.id, t.target_group_id
         FROM targets t
         LEFT JOIN target_verification_current v
           ON v.tenant_id = t.tenant_id AND v.target_id = t.id
         WHERE t.tenant_id = $1
           AND t.deleted_at IS NULL
           AND (v.state IS NULL OR v.state NOT IN ('dns_verified', 'provider_verified', 'user_confirmed'))
         ORDER BY t.id`,
        [tenantId],
      );
      for (const row of rows) {
        const now = new Date();
        const auditEntry = await auditRepository.appendAuditEvent(
          demoAutoVerifyAuditEntry(ctx, { targetId: row.id, targetGroupId: row.target_group_id }),
          { client, now },
        );
        await client.query(
          `INSERT INTO target_verifications (
             id, tenant_id, target_id, state, source_kind, source_ref,
             transitioned_at, transitioned_by, audit_entry_id
           ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::timestamptz, $8, $9)`,
          [newId('tv'), tenantId, row.id, DEMO_AUTO_VERIFY_STATE, DEMO_AUTO_VERIFY_SOURCE_KIND,
            JSON.stringify(demoAutoVerifySourceRef()), now.toISOString(), ctx.userId, auditEntry.id],
        );
      }
      return { verified_count: rows.length, target_ids: rows.map((row) => row.id) };
    });
  } finally {
    await closePgPool(pool);
  }
}

async function backfillDevStore(tenantId) {
  const { backfillDemoAutoVerifications } = await import('../src/services/targetGroups.mjs');
  return backfillDemoAutoVerifications({ tenantId, userId: 'system:demo-auto-verify', role: SYSTEM_CTX_ROLE });
}

export async function runDemoAutoVerifyBackfill(argv = process.argv.slice(2), env = process.env) {
  const tenantId = parseTenantId(argv) || 'Astra-D1TrtI4HMTSrwKRW-9';
  if (!isDemoAutoVerifyTenant(tenantId, env)) {
    throw new Error(`Tenant ${tenantId} is not an authorized demo tenant.`);
  }
  return String(env.ASTRANULL_DATABASE_URL ?? '').trim()
    ? backfillPostgres(tenantId, env)
    : backfillDevStore(tenantId);
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  runDemoAutoVerifyBackfill()
    .then((result) => {
      if (result?.error) throw new Error(result.error);
      console.log(`demo-auto-verify-backfill: verified ${result.verified_count} target(s)`);
    })
    .catch((err) => {
      console.error(`demo-auto-verify-backfill: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
    });
}
