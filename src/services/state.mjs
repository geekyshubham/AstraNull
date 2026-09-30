import { getStore } from '../store.mjs';
import { computeReadiness, evidenceBackedVerdictForRun } from './readiness.mjs';
import { activeTargetGroupsForTenant } from './targetGroups.mjs';
import { buildGetStatePayload } from '../lib/statePayload.mjs';

function tenantStateRollup(store, tenantId) {
  const rollups = store.stateRollups;
  if (!rollups || typeof rollups !== 'object') return null;
  const rollup = rollups[tenantId];
  return rollup && typeof rollup === 'object' ? rollup : null;
}

/**
 * Dev-json / memory dashboard aggregate for GET /v1/state.
 * @param {{ tenantId: string }} ctx
 */
export async function getState(ctx) {
  const store = getStore();
  const tenantId = ctx.tenantId;
  const rollup = tenantStateRollup(store, tenantId);
  const tenantHighScaleRequests = Array.isArray(store.highScaleRequests)
    ? store.highScaleRequests.filter((h) => h.tenant_id === tenantId)
    : [];
  const recentRuns = store.testRuns
    .filter((run) => run.tenant_id === tenantId)
    .sort((left, right) =>
      String(left.started_at ?? left.created_at ?? '').localeCompare(
        String(right.started_at ?? right.created_at ?? ''),
      ) || String(left.id ?? '').localeCompare(String(right.id ?? '')),
    )
    .slice(-5)
    .map((run) => ({
      ...run,
      verdict: ['completed', 'verdicted'].includes(run.status)
        ? evidenceBackedVerdictForRun(store, run.id)
        : null,
    }));

  return buildGetStatePayload({
    tenantId,
    rollup,
    computed: {
      readiness: computeReadiness(tenantId),
      target_groups: activeTargetGroupsForTenant(tenantId).length,
      recent_runs: recentRuns,
      open_findings: store.findings.filter(
        (f) => f.tenant_id === tenantId && (f.status === 'open' || f.state === 'open'),
      ).length,
      high_scale_requests: tenantHighScaleRequests.length,
    },
    killSwitch: store.socKillSwitch,
    highScaleWired: Array.isArray(store.highScaleRequests),
    highScaleRequests: tenantHighScaleRequests,
  });
}