import { newId } from '../lib/ids.mjs';
import { roleHasPermission } from '../contracts/roles.mjs';
import { buildCveApplicabilityReviewPlan, cveApplicabilityReviewGap, CveApplicabilityReviewError,
  CVE_APPLICABILITY_NO_EXECUTION } from '../contracts/cveApplicabilityReviews.mjs';

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const fail = (error, status) => ({ error, status, ...CVE_APPLICABILITY_NO_EXECUTION });
function gate(ctx, write = false) {
  const permission = write ? 'waf:write' : 'waf:read';
  if (!ctx?.tenantId || typeof ctx.userId !== 'string' || !ID.test(ctx.userId) || ctx.serviceAccountId
    || !roleHasPermission(ctx.role, permission)
    || (ctx.scopes != null && (!Array.isArray(ctx.scopes) || (!ctx.scopes.includes('*') && !ctx.scopes.includes(permission))))
    || (write && !['owner', 'admin'].includes(ctx.role))) return fail('forbidden', 403);
  return null;
}
const publicRow = (row, context, at) => ({ ...structuredClone(row),
  current_review_gap: cveApplicabilityReviewGap(row, context, at),
  evidence_classification: 'customer_declaration', external_applicability_verified: false,
  exposure_claim_allowed: false, observed_enforcement: false, ...CVE_APPLICABILITY_NO_EXECUTION });
const auditEntry = (ctx, action, row) => ({ tenant_id: ctx.tenantId, actor_user_id: ctx.userId,
  actor_role: ctx.role, action, resource_type: 'cve_applicability_review', resource_id: row.id,
  metadata: { cve_pipeline_item_id: row.cve_pipeline_item_id, cve_id: row.cve_id,
    cve_asset_match_id: row.cve_asset_match_id, waf_asset_id: row.waf_asset_id,
    plan_digest: row.plan_digest, evidence_classification: 'customer_declaration', ...CVE_APPLICABILITY_NO_EXECUTION } });

/** Isolated passive foundation. It never writes legacy component_applicability or calls execution services. */
export function createCveApplicabilityReviewService({ backend, now = () => new Date() }) {
  async function attempt(fn) {
    try { return await fn(); } catch (error) {
      if (error instanceof CveApplicabilityReviewError) return fail(error.code, error.status);
      throw error;
    }
  }
  const contextFor = async (ctx, tx) => ({ ...await tx.context(), tenantId: ctx.tenantId });
  return {
    async preview(ctx, body) {
      const denied = gate(ctx); if (denied) return denied;
      return attempt(() => backend.withMatch(ctx, body?.cve_asset_match_id, async (tx) =>
        buildCveApplicabilityReviewPlan(body, await contextFor(ctx, tx))));
    },
    async approve(ctx, body) {
      const denied = gate(ctx, true); if (denied) return denied;
      return attempt(() => backend.withMatch(ctx, body?.cve_asset_match_id, async (tx) => {
        const context = await contextFor(ctx, tx), at = new Date(now()).toISOString();
        const proposal = buildCveApplicabilityReviewPlan(body, context);
        if (body.reviewed_plan_digest !== proposal.plan_digest) return fail('reviewed_plan_digest_mismatch', 409);
        const existing = await tx.findByDigest(proposal.plan_digest);
        if (existing) {
          if (existing.revoked_at) return fail('cve_review_revoked', 409);
          return { ...publicRow(existing, context, at), replayed: true };
        }
        const row = { id: newId('cveApplicabilityReview'), tenant_id: ctx.tenantId,
          cve_pipeline_item_id: proposal.plan.cve_pipeline_item_id, cve_id: proposal.plan.cve_id,
          cve_asset_match_id: proposal.plan.cve_asset_match_id, waf_asset_id: proposal.plan.waf_asset_id,
          ...proposal, approved_by: ctx.userId, approved_role: ctx.role, approved_at: at,
          revoked_at: null, revoked_by: null };
        await tx.insert(row, auditEntry(ctx, 'cve_applicability_review.approved', row));
        return { ...publicRow(row, context, at), replayed: false };
      }));
    },
    async get(ctx, id) {
      const denied = gate(ctx); if (denied) return denied;
      return attempt(async () => {
        const locator = await backend.get(ctx, id);
        if (!locator) return fail('cve_review_not_found', 404);
        return backend.withMatch(ctx, locator.cve_asset_match_id, async (tx) => {
          const current = await tx.get(id);
          if (!current) return fail('cve_review_not_found', 404);
          return publicRow(current, await contextFor(ctx, tx), now());
        });
      });
    },
    async revoke(ctx, id) {
      const denied = gate(ctx, true); if (denied) return denied;
      return attempt(async () => {
        const locator = await backend.get(ctx, id);
        if (!locator) return fail('cve_review_not_found', 404);
        return backend.withMatch(ctx, locator.cve_asset_match_id, async (tx) => {
          const current = await tx.get(id);
          if (!current) return fail('cve_review_not_found', 404);
          if (current.revoked_at) return fail('cve_review_revoked', 409);
          const revoked = { ...current, revoked_at: new Date(now()).toISOString(), revoked_by: ctx.userId };
          await tx.revoke(revoked, auditEntry(ctx, 'cve_applicability_review.revoked', revoked));
          return publicRow(revoked, await contextFor(ctx, tx), now());
        });
      });
    },
  };
}
