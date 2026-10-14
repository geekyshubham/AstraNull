import { randomUUID } from 'node:crypto';
import { withTenantContext } from './tenantContext.mjs';

function map(row) {
  if (!row) return null;
  return { ...row, requested_at: new Date(row.requested_at).toISOString(),
    next_attempt_at: new Date(row.next_attempt_at).toISOString() };
}

export function createInitialEdgeDetectionRepository(pool) {
  return {
    getTarget: (ctx, id) => withTenantContext(pool, ctx.tenantId, async (client) => {
      const { rows } = await client.query(`SELECT target.*, verification.state AS verification_state
        FROM targets target JOIN target_groups policy ON policy.tenant_id = target.tenant_id AND policy.id = target.target_group_id
        LEFT JOIN target_verification_current verification ON verification.tenant_id = target.tenant_id AND verification.target_id = target.id
        WHERE target.tenant_id = $1 AND target.id = $2 AND target.deleted_at IS NULL
          AND policy.deleted_at IS NULL AND policy.archived_at IS NULL`, [ctx.tenantId, id]);
      return rows[0] ?? null;
    }),
    read: (ctx, id) => withTenantContext(pool, ctx.tenantId, async (client) => {
      const { rows } = await client.query('SELECT * FROM target_initial_edge_detections WHERE tenant_id = $1 AND target_id = $2', [ctx.tenantId, id]);
      return map(rows[0]);
    }),
    claim: (ctx, { limit, now }) => withTenantContext(pool, ctx.tenantId, async (client) => {
      const { rows } = await client.query(`WITH due AS MATERIALIZED (
        SELECT tenant_id, target_id FROM target_initial_edge_detections
        WHERE tenant_id = $1 AND next_attempt_at <= GREATEST($2::timestamptz, clock_timestamp())
          AND (status = 'queued' OR (status = 'leased' AND lease_expires_at <= GREATEST($2::timestamptz, clock_timestamp())))
        ORDER BY next_attempt_at, target_id LIMIT $3 FOR UPDATE SKIP LOCKED
      ) UPDATE target_initial_edge_detections request SET status = 'leased', lease_token = $4,
        lease_expires_at = $2::timestamptz + interval '60 seconds', attempts = request.attempts + 1
        FROM due WHERE request.tenant_id = due.tenant_id AND request.target_id = due.target_id RETURNING request.*`,
      [ctx.tenantId, now.toISOString(), limit, randomUUID()]);
      return rows.map(map);
    }),
    finish: (ctx, request, outcome) => withTenantContext(pool, ctx.tenantId, async (client) => {
      const { rows } = await client.query(`UPDATE target_initial_edge_detections SET status = $4, blocked_reason = $5,
        test_run_id = $6, next_attempt_at = $7::timestamptz, lease_token = NULL, lease_expires_at = NULL
        WHERE tenant_id = $1 AND target_id = $2 AND lease_token = $3 RETURNING *`,
      [ctx.tenantId, request.target_id, request.lease_token, outcome.status, outcome.blocked_reason,
        outcome.test_run_id ?? null, outcome.next_attempt_at]);
      return map(rows[0]);
    }),
  };
}
