import { withManagedTenantClient, withTenantContext } from './tenantContext.mjs';
import { effectiveTargetVerifications } from '../../lib/effectiveTargetVerification.mjs';
import { ownershipProofFromStates } from '../../lib/ownershipPolicy.mjs';
import { dnsOwnershipProofMatchesTarget } from '../../lib/dnsOwnershipTarget.mjs';

const exact = (column) => `to_char(${column} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const COLUMNS = `id, tenant_id, target_id, plan_json AS plan, plan_digest, approved_by, approved_role,
  ${exact('approved_at')} AS approved_at, ${exact('revoked_at')} AS revoked_at, revoked_by`;
// Keep canonical milliseconds for current reviews, but never round legacy review
// authority into a different instant before the strict binding validator sees it.
const reviewTime = (value) => value == null ? null : value.replace(/(\.\d{3})000Z$/, '$1Z');
function mapRow(row) {
  return row ? { ...row, approved_at: reviewTime(row.approved_at), revoked_at: reviewTime(row.revoked_at) } : null;
}

/** Review, target lifecycle and its direct ownership are locked in one tenant transaction. No dispatch. */
export function createReviewedOperationRepository(pool, audit) {
  if (typeof audit?.appendAuditEvent !== 'function') throw new Error('reviewed operation audit repository required');
  return {
    /** Current authority reads and its consumer share the exact held tenant transaction. */
    withAuthorityRows: (ctx, targetId, reviewId, fn, options = {}) => withManagedTenantClient(pool, ctx.tenantId, options.client, async (client) => {
      // New verification INSERTs do not conflict with existing-row FOR SHARE locks.
      // Current audited catalog/ownership writers use this same canonical tenant lock.
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [ctx.tenantId]);
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))', [ctx.tenantId, `reviewed_operation:${targetId}`]);
      const targetGroup = (await client.query(`SELECT tg.* FROM target_groups tg
        WHERE tg.tenant_id = $1 AND tg.deleted_at IS NULL AND tg.archived_at IS NULL
          AND tg.id = (SELECT target_group_id FROM targets WHERE tenant_id = $1 AND id = $2)
        FOR SHARE OF tg`, [ctx.tenantId, targetId])).rows[0] ?? null;
      const target = (await client.query(`SELECT * FROM targets
        WHERE tenant_id = $1 AND id = $2 FOR SHARE`, [ctx.tenantId, targetId])).rows[0] ?? null;
      // No LIMIT, state/provenance filter or premature JS Date conversion: chronology
      // must see the latest unverified row, ambiguous ties and exact microseconds.
      const ownershipHistory = (await client.query(`SELECT *, ${exact('transitioned_at')} AS transitioned_at
        FROM target_verifications WHERE tenant_id = $1 AND target_id = $2 FOR SHARE`, [ctx.tenantId, targetId])).rows;
      const review = mapRow((await client.query(`SELECT ${COLUMNS} FROM reviewed_operations
        WHERE tenant_id = $1 AND id = $2 FOR SHARE`, [ctx.tenantId, reviewId])).rows[0]);
      // Transaction start time (now()) could have expired while any lock waited.
      // Bindings use millisecond clocks; this fresh DB instant is sampled AFTER waits.
      const checkedAt = (await client.query('SELECT clock_timestamp() AS checked_at')).rows[0].checked_at.toISOString();
      return fn({ targetGroup, target, ownershipHistory, review, checkedAt });
    }),
    get: (ctx, id) => withTenantContext(pool, ctx.tenantId, async (client) => mapRow((await client.query(
      `SELECT ${COLUMNS} FROM reviewed_operations WHERE tenant_id = $1 AND id = $2`, [ctx.tenantId, id],
    )).rows[0])),
    withTarget: (ctx, targetId, fn) => withTenantContext(pool, ctx.tenantId, async (client) => {
      // Catalog mutations acquire audit before target locks; keep the same order.
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [ctx.tenantId]);
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))', [ctx.tenantId, `reviewed_operation:${targetId}`]);
      const target = (await client.query(`SELECT id, tenant_id, target_group_id, kind, value, protocol, port,
        expected_behavior, declaration_json, metadata_json, deleted_at, created_at FROM targets
        WHERE tenant_id = $1 AND id = $2 FOR SHARE`, [ctx.tenantId, targetId])).rows[0] ?? null;
      const verifications = (await client.query(`SELECT *, ${exact('transitioned_at')} AS transitioned_at
        FROM target_verifications WHERE tenant_id = $1 AND target_id = $2 FOR SHARE`, [ctx.tenantId, targetId])).rows;
      const verification = effectiveTargetVerifications({ targets: target ? [target] : [], targetVerifications: verifications },
        ctx.tenantId, [targetId]).get(targetId);
      const verified = target?.kind === 'url'
        ? verification?.state === 'dns_verified' && verification.source_kind === 'dns_txt'
          && dnsOwnershipProofMatchesTarget(target, verification)
        : ownershipProofFromStates({ targetState: verification?.state }).verified === true;
      const context = { target, ownershipVerified: !target?.deleted_at && verified };
      return fn({
        context: () => context,
        get: async (id) => mapRow((await client.query(`SELECT ${COLUMNS} FROM reviewed_operations
          WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, [ctx.tenantId, id])).rows[0]),
        findByDigest: async (digest) => mapRow((await client.query(`SELECT ${COLUMNS} FROM reviewed_operations
          WHERE tenant_id = $1 AND plan_digest = $2`, [ctx.tenantId, digest])).rows[0]),
        async insert(row, entry) {
          await client.query(`INSERT INTO reviewed_operations (id, tenant_id, target_id, plan_json, plan_digest,
            approved_by, approved_role, approved_at) VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8)`,
          [row.id, ctx.tenantId, row.target_id, JSON.stringify(row.plan), row.plan_digest, row.approved_by, row.approved_role, row.approved_at]);
          await audit.appendAuditEvent(entry, { client });
        },
        async revoke(row, entry) {
          await client.query(`UPDATE reviewed_operations SET revoked_at = $3, revoked_by = $4
            WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`, [ctx.tenantId, row.id, row.revoked_at, row.revoked_by]);
          await audit.appendAuditEvent(entry, { client });
        },
      });
    }),
  };
}
