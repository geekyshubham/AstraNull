import { getCheckById } from '../contracts/checks.mjs';
import { reviewedOperationGap, ReviewedOperationError } from '../contracts/reviewedOperations.mjs';
import { effectiveTargetVerifications } from '../lib/effectiveTargetVerification.mjs';
import { ownershipProofFromStates } from '../lib/ownershipPolicy.mjs';
import { dnsOwnershipProofMatchesTarget } from '../lib/dnsOwnershipTarget.mjs';
import { createReviewedOperationService } from './reviewedOperations.mjs';
import { createReviewedOperationAuthority } from './reviewedOperationAuthority.mjs';
import { getStore } from '../store.mjs';
import { audit } from '../audit.mjs';

let devMutation = Promise.resolve();
export function createDevReviewedOperationBackend({ now = () => new Date() } = {}) {
  const records = () => getStore().reviewedOperations ?? [];
  const find = (ctx, id) => records().find((row) => row.tenant_id === ctx.tenantId && row.id === id) ?? null;
  function mutate(fn, entry) {
    const store = getStore();
    const previous = structuredClone(store.reviewedOperations ?? []);
    const auditLength = store.auditLog.length;
    try { fn(); audit(entry); }
    catch (error) {
      store.reviewedOperations = previous;
      store.auditLog.splice(auditLength);
      throw error;
    }
  }
  return {
    synchronousAuthority: true,
    withAuthorityRows(ctx, targetId, reviewId, fn) {
      // This synchronous read is deliberately NOT devMutation: that queue only
      // serializes review mutations, not every catalog or ownership writer.
      const store = getStore();
      const target = store.targets.find((row) => row.tenant_id === ctx.tenantId && row.id === targetId) ?? null;
      const targetGroup = store.targetGroups.find((row) => row.tenant_id === ctx.tenantId && row.id === target?.target_group_id) ?? null;
      const ownershipHistory = (store.targetVerifications ?? []).filter((row) => row.tenant_id === ctx.tenantId && row.target_id === targetId);
      const rows = structuredClone({ target, targetGroup, ownershipHistory, review: find(ctx, reviewId) });
      rows.checkedAt = now().toISOString();
      const result = fn(rows);
      if (result && typeof result.then === 'function') {
        // No asynchronous signing/current-state guarantee exists in the dev store.
        if (typeof result.catch === 'function') result.catch(() => {});
        throw Object.assign(new Error('reviewed_operation_authority_async_callback_unavailable'), {
          code: 'reviewed_operation_authority_async_callback_unavailable', status: 409,
          grants_execution: false, execution_available: false,
        });
      }
      return result;
    },
    get: (ctx, id) => structuredClone(find(ctx, id)),
    withTarget(ctx, targetId, fn) {
      const work = devMutation.then(() => {
        const context = () => {
          const store = getStore();
          const target = store.targets.find((row) => row.tenant_id === ctx.tenantId && row.id === targetId) ?? null;
          const verification = effectiveTargetVerifications(store, ctx.tenantId, [targetId]).get(targetId);
          const verified = target?.kind === 'url'
            ? verification?.state === 'dns_verified' && verification.source_kind === 'dns_txt'
              && dnsOwnershipProofMatchesTarget(target, verification)
            : ownershipProofFromStates({ targetState: verification?.state }).verified === true;
          return { target, ownershipVerified: !target?.deleted_at && verified };
        };
        return fn({ context,
          get: (id) => structuredClone(find(ctx, id)),
          findByDigest: (digest) => structuredClone(records().find((row) => row.tenant_id === ctx.tenantId && row.plan_digest === digest) ?? null),
          insert(row, entry) {
            const current = context();
            if (!current.ownershipVerified || reviewedOperationGap(row, { tenantId: ctx.tenantId, target: current.target,
              check: getCheckById(row.plan.check_id), now: row.approved_at })) throw new ReviewedOperationError('operation_target_changed', 409);
            mutate(() => { (getStore().reviewedOperations ??= []).push(structuredClone(row)); }, entry);
          },
          revoke(row, entry) {
            const current = find(ctx, row.id);
            if (!current) throw new ReviewedOperationError('operation_not_found', 404);
            if (current.revoked_at) throw new ReviewedOperationError('operation_revoked', 409);
            mutate(() => Object.assign(current, { revoked_at: row.revoked_at, revoked_by: row.revoked_by }), entry);
          },
        });
      });
      devMutation = work.catch(() => {});
      return work;
    },
  };
}
const devReviewedOperationBackend = createDevReviewedOperationBackend();
export const devReviewedOperations = createReviewedOperationService({ backend: devReviewedOperationBackend });
export const devReviewedOperationAuthority = createReviewedOperationAuthority({ backend: devReviewedOperationBackend });
