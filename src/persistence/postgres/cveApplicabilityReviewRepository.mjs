import { withTenantContext } from './tenantContext.mjs';
import { mapCvePipelineItemRow, mapCveAssetMatchRow } from './cvePipelineRepository.mjs';
import { mapWafAssetRow } from './wafPostureRepository.mjs';
import { CveApplicabilityReviewError } from '../../contracts/cveApplicabilityReviews.mjs';

const COLUMNS = `id, tenant_id, cve_pipeline_item_id, cve_id, cve_asset_match_id, waf_asset_id,
  plan_json AS plan, plan_digest, approved_by, approved_role, approved_at, revoked_at, revoked_by`;
function mapRow(row) {
  return row ? { ...row, approved_at: new Date(row.approved_at).toISOString(),
    revoked_at: row.revoked_at == null ? null : new Date(row.revoked_at).toISOString() } : null;
}

/** Locked current definitions and review/audit writes share one tenant transaction. No dispatch. */
export function createCveApplicabilityReviewRepository(pool, audit) {
  if (typeof audit?.appendAuditEvent !== 'function') throw new Error('CVE applicability audit repository required');
  return {
    get: (ctx, id) => withTenantContext(pool, ctx.tenantId, async (client) => mapRow((await client.query(
      `SELECT ${COLUMNS} FROM cve_applicability_reviews WHERE tenant_id = $1 AND id = $2`, [ctx.tenantId, id],
    )).rows[0])),
    withMatch: (ctx, matchId, fn) => withTenantContext(pool, ctx.tenantId, async (client) => {
      // Match catalog/admission/audit lock order before taking definition locks.
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [ctx.tenantId]);
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))', [ctx.tenantId, `cve_applicability:${matchId}`]);
      const rawMatch = (await client.query(`SELECT * FROM cve_asset_matches
        WHERE tenant_id = $1 AND id = $2 FOR SHARE`, [ctx.tenantId, matchId])).rows[0] ?? null;
      const match = mapCveAssetMatchRow(rawMatch);
      const item = mapCvePipelineItemRow((await client.query(`SELECT * FROM cve_pipeline_items
        WHERE tenant_id = $1 AND id = $2 FOR SHARE`, [ctx.tenantId, match?.cve_pipeline_item_id ?? null])).rows[0]);
      const asset = mapWafAssetRow((await client.query(`SELECT * FROM waf_assets
        WHERE tenant_id = $1 AND id = $2 FOR SHARE`, [ctx.tenantId, match?.waf_asset_id ?? null])).rows[0]);
      const target = asset?.target_id ? (await client.query(`SELECT * FROM targets
        WHERE tenant_id = $1 AND id = $2 FOR SHARE`, [ctx.tenantId, asset.target_id])).rows[0] ?? null : null;
      const context = { tenantId: ctx.tenantId, match, item, asset, target };
      return fn({
        context: () => context,
        get: async (id) => mapRow((await client.query(`SELECT ${COLUMNS} FROM cve_applicability_reviews
          WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, [ctx.tenantId, id])).rows[0]),
        findByDigest: async (digest) => mapRow((await client.query(`SELECT ${COLUMNS} FROM cve_applicability_reviews
          WHERE tenant_id = $1 AND plan_digest = $2`, [ctx.tenantId, digest])).rows[0]),
        async insert(row, entry) {
          await client.query(`INSERT INTO cve_applicability_reviews (id, tenant_id, cve_pipeline_item_id, cve_id,
            cve_asset_match_id, waf_asset_id, plan_json, plan_digest, approved_by, approved_role, approved_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11)`,
          [row.id, ctx.tenantId, row.cve_pipeline_item_id, row.cve_id, row.cve_asset_match_id, row.waf_asset_id,
            JSON.stringify(row.plan), row.plan_digest, row.approved_by, row.approved_role, row.approved_at]);
          await audit.appendAuditEvent(entry, { client });
        },
        async revoke(row, entry) {
          if (Date.parse(row.revoked_at) < Date.parse(row.approved_at)) throw new CveApplicabilityReviewError('cve_review_clock_invalid', 409);
          const updated = await client.query(`UPDATE cve_applicability_reviews SET revoked_at = $3, revoked_by = $4
            WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL RETURNING id`,
          [ctx.tenantId, row.id, row.revoked_at, row.revoked_by]);
          if (!updated.rowCount) throw new CveApplicabilityReviewError('cve_review_revoked', 409);
          await audit.appendAuditEvent(entry, { client });
        },
      });
    }),
  };
}
