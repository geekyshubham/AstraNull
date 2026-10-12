import { getStore } from '../store.mjs';
import { projectReadiness, verifiedVerdicts } from '../lib/readinessProjection.mjs';
import { COVERAGE_FRESHNESS_POLICY } from '../lib/protectionCoverage.mjs';

export const RECENT_EVIDENCE_WINDOW_DAYS = 7;
export const RECENT_EVIDENCE_WINDOW_MS = COVERAGE_FRESHNESS_POLICY.max_age_ms;
// Compatibility exports. Only current compatible passing scenario coverage earns positive credit.
export const WEIGHT_COVERAGE = 100;
export const WEIGHT_VERDICTS = 0;
export const WEIGHT_EVIDENCE_FRESHNESS = 0;
export const WEIGHT_SOC_GOVERNANCE = 0;

export function evidenceBackedVerdictForRun(store, runId) {
  const run = (store.testRuns ?? []).find((row) => row.id === runId);
  if (!run) return null;
  return verifiedVerdicts({ tenantId: run.tenant_id, runs: [run], verdicts: store.verdicts, events: store.events, evidenceItems: store.evidenceVault }).get(runId)?.verdict ?? null;
}

export function computeReadiness(tenantId, options = {}) {
  const store = getStore();
  const killSwitch = store.socKillSwitch?.tenants?.[tenantId] ?? store.socKillSwitch;
  const result = projectReadiness({
    tenantId, asOf: options.now ?? new Date(), catalog: options.catalog,
    targets: store.targets, groups: store.targetGroups, policies: store.testPolicies,
    runs: store.testRuns, verdicts: store.verdicts, events: store.events,
    evidenceItems: store.evidenceVault, findings: store.findings,
    highScaleRequests: store.highScaleRequests, killSwitch, auditEntries: store.auditLog,
    input_complete: true,
    legacy_snapshot: store.stateRollups?.[tenantId]?.readiness ?? store.readiness?.[tenantId],
  });
  // Cache is a projection output, never an authoritative evidence input. Legacy history stays intact.
  store.readiness ??= {};
  store.readiness[tenantId] = result;
  return result;
}
