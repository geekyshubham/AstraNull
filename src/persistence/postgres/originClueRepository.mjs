import { withTenantContext } from './tenantContext.mjs';

const COLUMNS = `id, tenant_id, target_id, batch_id, fingerprint, clue_json`;
function clueRow(row) {
  return row ? { ...row.clue_json, id: row.id, tenant_id: row.tenant_id, target_id: row.target_id, batch_id: row.batch_id, fingerprint: row.fingerprint } : null;
}
const TARGET_SQL = `SELECT t.* FROM targets t
  JOIN target_groups g ON g.tenant_id = t.tenant_id AND g.id = t.target_group_id
  WHERE t.tenant_id = $1 AND t.id = $2 AND t.deleted_at IS NULL
    AND g.deleted_at IS NULL AND g.archived_at IS NULL`;

/** Tenant RLS, append-only provenance, replay ledger and chained audit share one transaction. */
export function createPostgresOriginClueRepository(pool, audit) {
  if (typeof audit?.appendAuditEvent !== 'function') throw new Error('origin clue audit repository required');
  return {
    getTarget: (ctx, id) => withTenantContext(pool, ctx.tenantId, async (client) =>
      (await client.query(TARGET_SQL, [ctx.tenantId, id])).rows[0] ?? null),
    latestCoverage: (ctx, targetId) => withTenantContext(pool, ctx.tenantId, async (client) =>
      (await client.query(`SELECT response_json->'coverage' AS coverage FROM origin_clue_batches
        WHERE tenant_id = $1 AND target_id = $2 ORDER BY recorded_sequence DESC LIMIT 1`, [ctx.tenantId, targetId])).rows[0]?.coverage ?? null),
    list: (ctx, targetId, { limit, after }) => withTenantContext(pool, ctx.tenantId, async (client) => {
      const { rows } = await client.query(`SELECT ${COLUMNS} FROM origin_clues
        WHERE tenant_id = $1 AND target_id = $2
          AND ($3::timestamptz IS NULL OR (retrieved_at, id COLLATE "C") > ($3::timestamptz, $4::text COLLATE "C"))
        ORDER BY retrieved_at ASC, id COLLATE "C" ASC LIMIT $5`,
      [ctx.tenantId, targetId, after?.at ?? null, after?.id ?? null, limit]);
      return rows.map(clueRow);
    }),
    withBatch: (ctx, targetId, fn) => withTenantContext(pool, ctx.tenantId, async (client) => {
      // Match catalog/audit lock order. This also prevents concurrent replay collection.
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [ctx.tenantId]);
      // Shared lifecycle order: tenant advisory lock, then authoritative tenant row, then target rows.
      await client.query('SELECT id FROM tenants WHERE id = $1 FOR SHARE', [ctx.tenantId]);
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))', [ctx.tenantId, `origin_clues:${targetId}`]);
      return fn({
        getTarget: async (id) => (await client.query(`${TARGET_SQL} FOR SHARE OF t, g`, [ctx.tenantId, id])).rows[0] ?? null,
        getBatch: async (key) => {
          const row = (await client.query(`SELECT request_digest, response_json FROM origin_clue_batches
            WHERE tenant_id = $1 AND target_id = $2 AND idempotency_key = $3`, [ctx.tenantId, targetId, key])).rows[0];
          return row ? { request_digest: row.request_digest, response: row.response_json } : null;
        },
        async insertClue(row) {
          const { id, tenant_id: _tenant, target_id: _target, batch_id, fingerprint, ...clue } = row;
          const inserted = await client.query(`INSERT INTO origin_clues
            (id, tenant_id, target_id, batch_id, fingerprint, retrieved_at, clue_json)
            VALUES ($1, $2, $3, $4, $5, $6::timestamptz, $7::jsonb)
            ON CONFLICT (tenant_id, target_id, fingerprint) DO NOTHING RETURNING ${COLUMNS}`,
          [id, ctx.tenantId, targetId, batch_id, fingerprint, clue.retrieved_at, JSON.stringify(clue)]);
          if (inserted.rows[0]) return { row: clueRow(inserted.rows[0]), created: true };
          const existing = await client.query(`SELECT ${COLUMNS} FROM origin_clues
            WHERE tenant_id = $1 AND target_id = $2 AND fingerprint = $3`, [ctx.tenantId, targetId, fingerprint]);
          return { row: clueRow(existing.rows[0]), created: false };
        },
        async finish(batch, entry) {
          await client.query(`INSERT INTO origin_clue_batches
            (id, tenant_id, target_id, idempotency_key, request_digest, action, created_at, response_json)
            VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, $8::jsonb)`,
          [batch.id, ctx.tenantId, targetId, batch.idempotency_key, batch.request_digest, batch.action, batch.created_at, JSON.stringify(batch.response)]);
          await audit.appendAuditEvent(entry, { client, auditLockHeld: true });
        },
      });
    }),
  };
}
