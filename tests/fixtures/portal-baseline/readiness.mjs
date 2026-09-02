/**
 * Store mutations that produce distinct evidence-backed readiness scores for FT-PROV-dyn-01.
 */
import { PORTAL_BASELINE_IDS } from './seed.mjs';

const FROZEN = PORTAL_BASELINE_IDS.frozenAt;
const NOW = new Date().toISOString();

function resolveReadinessRun(store) {
  const ids = PORTAL_BASELINE_IDS;
  const run = store.testRuns.find((entry) => (
    entry.id === ids.readinessRunId && entry.check_id === ids.checkId
  ));
  if (!run) {
    throw new Error(`Portal readiness fixture is missing ${ids.readinessRunId} bound to ${ids.checkId}.`);
  }

  for (const field of ['tenant_id', 'target_group_id', 'target_id', 'check_id']) {
    if (typeof run[field] !== 'string' || !run[field]) {
      throw new Error(`Portal readiness run ${run.id} is missing ${field}.`);
    }
  }
  return run;
}

/** Baseline + recent verdict evidence → a stable non-zero readiness score. */
export function applyPortalBaselineReadinessBoost(store) {
  const ids = PORTAL_BASELINE_IDS;
  const run = resolveReadinessRun(store);
  const tenantId = run.tenant_id;
  const targetGroupId = run.target_group_id;
  const targetId = run.target_id;
  const checkId = run.check_id;
  const agent = store.agents.find((entry) => (
    entry.id === ids.agentId && entry.tenant_id === tenantId
  ));
  if (agent) agent.status = 'online';

  const evidenceId = 'evt_portal_baseline_boost';
  run.status = 'completed';
  run.completed_at = NOW;
  run.verdict_at = NOW;
  store.events.push({
    id: evidenceId,
    tenant_id: tenantId,
    test_run_id: run.id,
    target_group_id: targetGroupId,
    target_id: targetId,
    check_id: checkId,
    signal_type: 'probe_result',
    source: 'probe_worker',
    producer_kind: 'signed_probe',
    timestamp: NOW,
    metadata: { external_result: 'blocked' },
  });

  store.verdicts.push({
    id: 'vrd_portal_baseline_boost',
    tenant_id: tenantId,
    test_run_id: run.id,
    target_group_id: targetGroupId,
    target_id: targetId,
    check_id: checkId,
    verdict: 'protected',
    evidence_ids: [evidenceId],
    created_at: NOW,
  });

  return { run, tenantId, targetGroupId, targetId, checkId };
}

/** Open-finding pressure drops the boosted score. */
export function applyPortalBaselineReadinessPenalty(store) {
  const { run, tenantId, targetGroupId, targetId, checkId } = applyPortalBaselineReadinessBoost(store);

  for (const finding of store.findings) {
    if (finding.tenant_id !== tenantId) continue;
    finding.status = 'open';
    finding.state = 'open';
  }

  store.findings.push({
    id: 'fnd_portal_baseline_penalty',
    tenant_id: tenantId,
    test_run_id: run.id,
    target_group_id: targetGroupId,
    target_id: targetId,
    check_id: checkId,
    severity: 's2',
    title: 'Penalty finding',
    status: 'open',
    state: 'open',
    opened_at: FROZEN,
    owner_group: 'edge-sre',
  });
}