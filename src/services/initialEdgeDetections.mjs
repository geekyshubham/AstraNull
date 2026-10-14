import { randomUUID } from 'node:crypto';
import { getStore, persistStore } from '../store.mjs';
import { INITIAL_EDGE_CHECK_ID, presentInitialEdgeDetection } from '../lib/initialEdgeDetection.mjs';
import { scanIncludesTarget } from '../lib/targetExecutionScope.mjs';
import { isArchivedTarget } from './targetGroups.mjs';
import { targetOwnershipProof } from './ownershipVerification.mjs';
import * as testRuns from './testRuns.mjs';
import { wafPostureEnabledFor } from '../lib/tenantFeatureAccess.mjs';

/** Initial observations share the normal run path and all its execution gates. */
export function createInitialEdgeDetectionService(deps) {
  return {
    getInitialDetection: async (ctx, id) => presentInitialEdgeDetection(await deps.read(ctx, id)),
    async dispatchPending(ctx, { runtimeConfig, limit = 25, now = new Date() } = {}) {
      const claimed = await deps.claim(ctx, { limit: Math.max(1, Math.min(100, Number(limit) || 25)), now });
      const results = [];
      for (const request of claimed) {
        const actor = { tenantId: ctx.tenantId, userId: 'automatic-edge-detection', role: 'system' };
        let outcome;
        try {
          const target = await deps.getTarget(actor, request.target_id);
          if (!target || target.deleted_at || target.archived_at) outcome = { status: 'cancelled', blocked_reason: 'target_unavailable' };
          else {
            // Reconcile an accepted run before retrying a lease after a process failure.
            const latest = await deps.latestRun(actor, target.id);
            if (latest && ['running', 'collecting', 'planned', 'verdicted', 'completed'].includes(latest.status)
              && Date.parse(latest.created_at) >= Date.parse(request.requested_at)) {
              outcome = { status: 'dispatched', test_run_id: latest.id, blocked_reason: null };
            } else if (!wafPostureEnabledFor(runtimeConfig, ctx.tenantId)) outcome = { status: 'queued', blocked_reason: 'waf_feature_disabled' };
            else if (await deps.activeScan(actor, target)) outcome = { status: 'queued', blocked_reason: 'target_validation_active' };
            else if (deps.ownership && !(await deps.ownership(actor, target))) outcome = { status: 'queued', blocked_reason: 'ownership_not_verified' };
            else {
              const result = await deps.startTestRun(actor, { target_group_id: target.target_group_id,
                target_id: target.id, check_id: INITIAL_EDGE_CHECK_ID }, runtimeConfig);
              outcome = result?.run?.id ? { status: 'dispatched', test_run_id: result.run.id, blocked_reason: null }
                : { status: 'queued', blocked_reason: result?.error ?? 'detection_dispatch_unavailable' };
            }
          }
        } catch { outcome = { status: 'queued', blocked_reason: 'detection_dispatch_unavailable' }; }
        outcome.next_attempt_at = new Date(now.getTime() + 30_000).toISOString();
        const stored = await deps.finish(actor, request, outcome);
        results.push({ target_id: request.target_id, ...outcome, recorded: Boolean(stored) });
      }
      return results;
    },
  };
}

export const devInitialEdgeDetections = createInitialEdgeDetectionService({
  read: (ctx, id) => (getStore().initialEdgeDetections ?? []).find((row) => row.tenant_id === ctx.tenantId && row.target_id === id),
  claim: (ctx, { limit, now }) => {
    const rows = (getStore().initialEdgeDetections ?? []).filter((row) => row.tenant_id === ctx.tenantId
      && (row.status === 'queued' || (row.status === 'leased' && Date.parse(row.lease_expires_at) <= now.getTime()))
      && Date.parse(row.next_attempt_at) <= now.getTime()).sort((a, b) => String(a.next_attempt_at).localeCompare(String(b.next_attempt_at))).slice(0, limit);
    for (const row of rows) { row.status = 'leased'; row.lease_token = randomUUID(); row.lease_expires_at = new Date(now.getTime() + 60_000).toISOString(); row.attempts += 1; }
    persistStore();
    return rows.map((row) => ({ ...row }));
  },
  finish: (ctx, request, outcome) => {
    const row = (getStore().initialEdgeDetections ?? []).find((item) => item.tenant_id === ctx.tenantId
      && item.target_id === request.target_id && item.lease_token === request.lease_token);
    if (!row) return null;
    Object.assign(row, outcome, { lease_token: null, lease_expires_at: null }); persistStore(); return row;
  },
  getTarget: (ctx, id) => getStore().targets.find((target) => target.tenant_id === ctx.tenantId && target.id === id && !isArchivedTarget(target)),
  latestRun: (ctx, id) => getStore().testRuns.filter((run) => run.tenant_id === ctx.tenantId && run.target_id === id && run.check_id === INITIAL_EDGE_CHECK_ID)
    .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))[0],
  activeScan: (ctx, target) => (getStore().validationScans ?? []).some((scan) => scan.tenant_id === ctx.tenantId
    && ['pending', 'running'].includes(scan.status) && scanIncludesTarget(scan, target.id, target.target_group_id)),
  ownership: (ctx, target) => targetOwnershipProof(ctx, { id: target.target_group_id }, target.id).verified,
  startTestRun: testRuns.startTestRun,
});
