import { newId } from '../lib/ids.mjs';
import { getCheckById } from '../contracts/checks.mjs';
import { roleHasPermission } from '../contracts/roles.mjs';
import { buildReviewedOperationPlan, reviewedOperationGap, ReviewedOperationError } from '../contracts/reviewedOperations.mjs';

const fail = (error, status) => ({ error, status });
function gate(ctx, review = false) {
  const permission = review ? 'test_run:start' : 'test_run:read';
  if (!ctx?.tenantId || !ctx?.userId || !roleHasPermission(ctx.role, permission)
    || (Array.isArray(ctx.scopes) && !ctx.scopes.includes('*') && !ctx.scopes.includes(permission))
    || (review && (!['owner', 'admin'].includes(ctx.role) || ctx.serviceAccountId))) return fail('forbidden', 403);
  return null;
}
const auditEntry = (ctx, action, row) => ({ tenant_id: ctx.tenantId, actor_user_id: ctx.userId,
  actor_role: ctx.role, action, resource_type: 'reviewed_operation', resource_id: row.id,
  metadata: { target_id: row.target_id, plan_digest: row.plan_digest } });
function publicRow(row, context, now) {
  return { ...structuredClone(row), current_review_gap: reviewedOperationGap(row, {
    tenantId: row.tenant_id, target: context.target, check: getCheckById(row.plan.check_id), now,
  }) ?? (context.ownershipVerified ? null : 'ownership_not_verified'), grants_execution: false, execution_available: false };
}

/** Persistent preflight review only. Dispatch remains unavailable until its independent execution gates are implemented. */
export function createReviewedOperationService({ backend, now = () => new Date() }) {
  function projected(ctx, row, context, at) {
    const result = publicRow(row, context, at);
    return { ...result, reviewed_execution: { available: false, check_id: 'waf.evasion_base64_wrap.safe',
      reason: result.current_review_gap ?? 'reviewed_operation_execution_unavailable' } };
  }
  async function attempt(fn) {
    try { return await fn(); }
    catch (error) {
      if (error instanceof ReviewedOperationError) return fail(error.code, error.status);
      throw error;
    }
  }
  return {
    async preview(ctx, body) {
      const denied = gate(ctx); if (denied) return denied;
      return attempt(() => backend.withTarget(ctx, body?.target_id, async (tx) => {
        const context = await tx.context();
        if (!context.ownershipVerified) return fail(context.target ? 'ownership_not_verified' : 'target_not_found', context.target ? 409 : 404);
        return buildReviewedOperationPlan(body, { tenantId: ctx.tenantId, target: context.target, check: getCheckById(body?.check_id), now: now() });
      }));
    },
    async approve(ctx, body) {
      const denied = gate(ctx, true); if (denied) return denied;
      return attempt(() => backend.withTarget(ctx, body?.target_id, async (tx) => {
        const context = await tx.context();
        if (!context.ownershipVerified) return fail(context.target ? 'ownership_not_verified' : 'target_not_found', context.target ? 409 : 404);
        const at = now();
        const proposal = buildReviewedOperationPlan(body, { tenantId: ctx.tenantId, target: context.target, check: getCheckById(body?.check_id), now: at });
        if (body.reviewed_plan_digest !== proposal.plan_digest) return fail('reviewed_plan_digest_mismatch', 409);
        const existing = await tx.findByDigest(proposal.plan_digest);
        if (existing) {
          if (existing.revoked_at) return fail('operation_revoked', 409);
          return { ...await projected(ctx,existing,context,at), replayed: true };
        }
        const row = { id: newId('reviewedOperation'), tenant_id: ctx.tenantId, target_id: context.target.id,
          plan: proposal.plan, plan_digest: proposal.plan_digest, approved_by: ctx.userId,
          approved_role: ctx.role, approved_at: new Date(at).toISOString(), revoked_at: null, revoked_by: null };
        await tx.insert(row, auditEntry(ctx, 'reviewed_operation.approved', row));
        return { ...await projected(ctx,row,context,at), replayed: false };
      }));
    },
    async get(ctx, id) {
      const denied = gate(ctx); if (denied) return denied;
      const row = await backend.get(ctx, id);
      if (!row) return fail('operation_not_found', 404);
      return backend.withTarget(ctx, row.target_id, async (tx) => {
        const current = await tx.get(id);
        if (!current) return fail('operation_not_found', 404);
        return projected(ctx,current,await tx.context(),now());
      });
    },
    async revoke(ctx, id) {
      const denied = gate(ctx, true); if (denied) return denied;
      const row = await backend.get(ctx, id);
      if (!row) return fail('operation_not_found', 404);
      return backend.withTarget(ctx, row.target_id, async (tx) => {
        const current = await tx.get(id);
        if (!current) return fail('operation_not_found', 404);
        if (current.revoked_at) return fail('operation_revoked', 409);
        const revoked = { ...current, revoked_at: new Date(now()).toISOString(), revoked_by: ctx.userId };
        await tx.revoke(revoked, auditEntry(ctx, 'reviewed_operation.revoked', revoked));
        return projected(ctx,revoked,await tx.context(),now());
      });
    },
  };
}

