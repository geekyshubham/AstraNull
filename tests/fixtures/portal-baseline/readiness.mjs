/**
 * Store mutations that produce distinct evidence-backed readiness scores for FT-PROV-dyn-01.
 */
import { PORTAL_BASELINE_IDS } from './seed.mjs';
import { CHECK_CATALOG, isCustomerRunnable } from '../../../src/contracts/checks.mjs';
import { addAssuredObservation } from '../../helpers/assurance-fixtures.mjs';

const FROZEN = PORTAL_BASELINE_IDS.frozenAt;
const NOW = new Date().toISOString();
const SEEDED_RUN_START_OFFSET_MS = 61 * 60 * 1000;

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

/** A genuinely broad test-only signed-marker cohort, not one legacy fingerprint.
 * No requests are sent. Production scoring consumes these fixture transcripts through
 * the same version/scope/completeness/actual-event gate as recorded observations.
 */
export function applyPortalBaselineReadinessBoost(store, { observedAt = NOW } = {}) {
  const ids = PORTAL_BASELINE_IDS;
  const original = resolveReadinessRun(store); // Preserve and check the original historical fixture.
  const tenantId = original.tenant_id;
  const approvedIds = new Set(['tgt_checkout_1', 'tgt_checkout_2']);
  const targets = store.targets.filter((target) => target.tenant_id === tenantId && approvedIds.has(target.id));
  const catalog = CHECK_CATALOG.filter((check) => isCustomerRunnable(check)
    && check.supported_targets.includes('fqdn')
    && !check.observation_only && check.readiness_conclusion !== false);
  const prefix = 'run_portal_assurance_';
  store.testRuns = store.testRuns.filter((run) => !run.id.startsWith(prefix));
  store.events = store.events.filter((event) => !String(event.test_run_id).startsWith(prefix));
  store.verdicts = store.verdicts.filter((verdict) => !String(verdict.test_run_id).startsWith(prefix));
  const world = { tenantId, targets, catalog,
    groups: store.targetGroups.filter((group) => group.tenant_id === tenantId), runs: [], events: [], verdicts: [] };
  // Seeded history must not consume the tenant's live hourly safe-run budget, so each run starts outside that window.
  const startedAt = new Date(Math.min(Date.parse(observedAt), Date.now() - SEEDED_RUN_START_OFFSET_MS)).toISOString();
  for (const target of targets) for (const check of catalog) {
    const evidence = addAssuredObservation(world, { target, check, observedAt, startedAt, id: `${prefix}${target.id}_${check.check_id}` });
    Object.assign(evidence.event.metadata, { source_perspective: 'test-fixture', fixture_evidence: true });
  }
  store.testRuns.push(...world.runs); store.events.push(...world.events); store.verdicts.push(...world.verdicts);
  const run = world.runs[0];
  if (!run) throw new Error('Current approved marker definitions are missing from the readiness fixture.');
  return { run, tenantId: run.tenant_id, targetGroupId: run.target_group_id, targetId: run.target_id, checkId: run.check_id };
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