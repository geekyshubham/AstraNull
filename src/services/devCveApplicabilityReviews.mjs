import { getStore } from '../store.mjs';
import { audit } from '../audit.mjs';
import { cveApplicabilityReviewGap, CveApplicabilityReviewError } from '../contracts/cveApplicabilityReviews.mjs';
import { createCveApplicabilityReviewService } from './cveApplicabilityReviews.mjs';

let devMutation = Promise.resolve();
/** Isolated dev-json backend. Add cveApplicabilityReviews: [] to emptyStore's upgrade baseline. */
export function createDevCveApplicabilityReviewBackend() {
  const records = () => getStore().cveApplicabilityReviews ?? [];
  const find = (ctx, id) => records().find((row) => row.tenant_id === ctx.tenantId && row.id === id) ?? null;
  function mutate(fn, entry) {
    const store = getStore(), previous = structuredClone(store.cveApplicabilityReviews ?? []);
    const auditLength = store.auditLog.length;
    try { fn(); audit(entry); }
    catch (error) {
      store.cveApplicabilityReviews = previous;
      store.auditLog.splice(auditLength);
      throw error;
    }
  }
  return {
    get: (ctx, id) => structuredClone(find(ctx, id)),
    withMatch(ctx, matchId, fn) {
      const work = devMutation.then(() => {
        const context = () => {
          const store = getStore();
          const match = store.cveAssetMatches.find((row) => row.tenant_id === ctx.tenantId && row.id === matchId) ?? null;
          const item = store.cvePipelineItems.find((row) => row.tenant_id === ctx.tenantId && row.id === match?.cve_pipeline_item_id) ?? null;
          const asset = store.wafAssets.find((row) => row.tenant_id === ctx.tenantId && row.id === match?.waf_asset_id) ?? null;
          const target = store.targets.find((row) => row.tenant_id === ctx.tenantId && row.id === asset?.target_id) ?? null;
          return { tenantId: ctx.tenantId, match, item, asset, target };
        };
        return fn({ context,
          get: (id) => structuredClone(find(ctx, id)),
          findByDigest: (digest) => structuredClone(records().find((row) => row.tenant_id === ctx.tenantId && row.plan_digest === digest) ?? null),
          insert(row, entry) {
            const gap = cveApplicabilityReviewGap(row, context(), row.approved_at);
            if (gap) throw new CveApplicabilityReviewError(gap, 409);
            mutate(() => { (getStore().cveApplicabilityReviews ??= []).push(structuredClone(row)); }, entry);
          },
          revoke(row, entry) {
            const current = find(ctx, row.id);
            if (!current) throw new CveApplicabilityReviewError('cve_review_not_found', 404);
            if (current.revoked_at) throw new CveApplicabilityReviewError('cve_review_revoked', 409);
            if (Date.parse(row.revoked_at) < Date.parse(current.approved_at)) throw new CveApplicabilityReviewError('cve_review_clock_invalid', 409);
            mutate(() => Object.assign(current, { revoked_at: row.revoked_at, revoked_by: row.revoked_by }), entry);
          },
        });
      });
      devMutation = work.catch(() => {});
      return work;
    },
  };
}
export const devCveApplicabilityReviews = createCveApplicabilityReviewService({ backend: createDevCveApplicabilityReviewBackend() });
