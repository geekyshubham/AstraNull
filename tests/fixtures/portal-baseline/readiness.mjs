/**
 * Store mutations that produce distinct evidence-backed readiness scores for FT-PROV-dyn-01.
 */
import { PORTAL_BASELINE_IDS } from './seed.mjs';

const FROZEN = PORTAL_BASELINE_IDS.frozenAt;
const NOW = new Date().toISOString();

/** Baseline + recent verdict evidence → a stable non-zero readiness score (typically 25). */
export function applyPortalBaselineReadinessBoost(store) {
  const ids = PORTAL_BASELINE_IDS;
  const agent = store.agents.find((entry) => entry.id === ids.agentId);
  if (agent) agent.status = 'online';

  const run = store.testRuns[0];
  const evidenceId = 'evt_portal_baseline_boost';
  if (run) {
    run.status = 'completed';
    run.completed_at = NOW;
    run.verdict_at = NOW;
    store.events.push({
      id: evidenceId,
      tenant_id: ids.tenantId,
      test_run_id: run.id,
      target_group_id: ids.targetGroupId,
      target_id: ids.targetId,
      signal_type: 'probe_result',
      source: 'probe_worker',
      producer_kind: 'signed_probe',
      timestamp: NOW,
      metadata: { external_result: 'blocked' },
    });
  }

  store.verdicts.push({
    id: 'vrd_portal_baseline_boost',
    tenant_id: ids.tenantId,
    test_run_id: run?.id,
    target_group_id: ids.targetGroupId,
    target_id: ids.targetId,
    verdict: 'pass',
    evidence_ids: run ? [evidenceId] : [],
    created_at: NOW,
  });
}

/** Open-finding pressure drops the boosted score (typically 25 → 5). */
export function applyPortalBaselineReadinessPenalty(store) {
  applyPortalBaselineReadinessBoost(store);
  const ids = PORTAL_BASELINE_IDS;

  for (const finding of store.findings) {
    if (finding.tenant_id !== ids.tenantId) continue;
    finding.status = 'open';
    finding.state = 'open';
  }

  store.findings.push({
    id: 'fnd_portal_baseline_penalty',
    tenant_id: ids.tenantId,
    target_group_id: ids.targetGroupId,
    target_id: ids.targetId,
    severity: 's2',
    title: 'Penalty finding',
    status: 'open',
    state: 'open',
    opened_at: FROZEN,
    owner_group: 'edge-sre',
  });
}