import { getStore } from '../store.mjs';
import { REQUIRED_ARTIFACT_TYPES } from './highScale.mjs';
import { runVerdictSupportsReadiness } from '../lib/readinessVerdicts.mjs';
import { activeTargetGroupsForTenant, isArchivedTarget } from './targetGroups.mjs';
import { isTrustedProducerEvent } from '../lib/trustedEventProvenance.mjs';

/** Evidence older than this window earns no freshness credit. */
export const RECENT_EVIDENCE_WINDOW_DAYS = 30;
export const RECENT_EVIDENCE_WINDOW_MS = RECENT_EVIDENCE_WINDOW_DAYS * 24 * 60 * 60 * 1000;

// ADR-0008 removed the "Agent placement & health" factor (was weight 25). Its weight is
// redistributed proportionally across the four remaining factors so the score still totals 100:
// original non-agent weights summed to 90 (coverage 40, verdicts 25, freshness 15, soc 10);
// each is scaled by 100/90 and rounded to keep an integer sum of 100 (44 + 28 + 17 + 11 = 100).
export const WEIGHT_COVERAGE = 44;
export const WEIGHT_VERDICTS = 28;
export const WEIGHT_EVIDENCE_FRESHNESS = 17;
export const WEIGHT_SOC_GOVERNANCE = 11;

const RUN_EVIDENCE_TIMESTAMP_FIELDS = [
  'verdict_at',
  'completed_at',
  'updated_at',
  'created_at',
];

const GOVERNED_HS_STATES = new Set(['scheduled', 'running', 'stopped', 'closed']);

const SOC_KILL_SWITCH_ACTIONS = new Set(['soc.kill_switch.activated', 'soc.kill_switch.cleared']);

const PASS_POSTURE_VERDICTS = new Set([
  'protected',
  'pass',
  'passed',
  'success',
  'ok',
  'allowed_as_expected',
]);
const GAP_POSTURE_VERDICTS = new Set([
  'exposed',
  'unprotected',
  'gap',
  'fail',
  'failed',
  'bypassable',
  'penetrated',
  'edge_exposed',
]);

function parseTs(value) {
  if (!value) return null;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms : null;
}

function isRecentMs(ms, nowMs = Date.now()) {
  if (ms == null || !Number.isFinite(ms)) return false;
  if (ms > nowMs) return false;
  return nowMs - ms <= RECENT_EVIDENCE_WINDOW_MS;
}

function isRecentTimestamp(value, nowMs = Date.now()) {
  return isRecentMs(parseTs(value), nowMs);
}

function runStatusEligible(run) {
  return run.status === 'completed' || run.status === 'verdicted';
}

export function evidenceBackedVerdictForRun(store, runId) {
  const verdict = store.verdicts.find((v) => v.test_run_id === runId) ?? null;
  if (!verdict) return null;
  const evidenceIds = new Set(Array.isArray(verdict.evidence_ids) ? verdict.evidence_ids : []);
  if (evidenceIds.size === 0) return null;
  return [
    ...eventsForRun(store, runId),
    ...vaultForRun(store, runId),
  ].some((evidence) => evidenceIds.has(evidence.id)) ? verdict : null;
}

function eventsForRun(store, runId) {
  return store.events.filter(
    (event) => event.test_run_id === runId && isTrustedProducerEvent(event),
  );
}

function vaultForRun(store, runId) {
  const trustedEventIds = new Set(eventsForRun(store, runId).map((event) => event.id));
  return (store.evidenceVault ?? []).filter((e) => e.test_run_id === runId
    && (!e.related_event_id || trustedEventIds.has(e.related_event_id)));
}

function readinessVerdictForRun(store, run) {
  const verdict = evidenceBackedVerdictForRun(store, run.id);
  return runVerdictSupportsReadiness(run, verdict) ? verdict : null;
}

function readinessPostureForRuns(store, runs) {
  const latestByCheck = new Map();
  for (const run of runs) {
    if (!runStatusEligible(run)) continue;
    const verdict = readinessVerdictForRun(store, run);
    if (!verdict) continue;
    const checkId = String(run.check_id ?? verdict.check_id ?? '').trim();
    if (!checkId) continue;
    const at = parseTs(verdict.created_at ?? run.completed_at ?? run.started_at ?? run.created_at) ?? 0;
    const previous = latestByCheck.get(checkId);
    if (
      !previous
      || at > previous.at
      || (at === previous.at && String(run.id).localeCompare(previous.runId) > 0)
    ) {
      latestByCheck.set(checkId, { at, runId: String(run.id), verdict: verdict.verdict });
    }
  }

  const posture = { pass: 0, review: 0, gap: 0, total: 0 };
  for (const entry of latestByCheck.values()) {
    const value = String(entry.verdict ?? '').trim().toLowerCase();
    if (PASS_POSTURE_VERDICTS.has(value)) posture.pass += 1;
    else if (GAP_POSTURE_VERDICTS.has(value)) posture.gap += 1;
    else posture.review += 1;
  }
  posture.total = posture.pass + posture.review + posture.gap;
  return posture;
}

function runHasEvidenceBacking(store, run) {
  return Boolean(readinessVerdictForRun(store, run));
}

function collectEvidenceTimestamps(store, run) {
  const stamps = [];
  for (const field of RUN_EVIDENCE_TIMESTAMP_FIELDS) {
    const ms = parseTs(run[field]);
    if (ms != null) stamps.push(ms);
  }
  const verdict = evidenceBackedVerdictForRun(store, run.id);
  if (verdict) {
    const vMs = parseTs(verdict.created_at);
    if (vMs != null) stamps.push(vMs);
  }
  for (const ev of eventsForRun(store, run.id)) {
    const eMs = parseTs(ev.timestamp ?? ev.created_at);
    if (eMs != null) stamps.push(eMs);
  }
  for (const rec of vaultForRun(store, run.id)) {
    const rMs = parseTs(rec.created_at);
    if (rMs != null) stamps.push(rMs);
  }
  return stamps;
}

function evidenceFreshnessForRun(store, run, nowMs) {
  if (!runStatusEligible(run) || !runHasEvidenceBacking(store, run)) {
    return { recent: false, stale: false, backed: false };
  }
  const stamps = collectEvidenceTimestamps(store, run);
  if (stamps.length === 0) {
    return { recent: false, stale: false, backed: true };
  }
  const hasRecent = stamps.some((ms) => isRecentMs(ms, nowMs));
  const hasStaleOnly = !hasRecent;
  return { recent: hasRecent, stale: hasStaleOnly, backed: true };
}

function acceptedArtifacts(req) {
  return (req.artifacts ?? []).filter((a) => a.status === 'accepted');
}

function authorizationPackComplete(req) {
  const types = new Set(acceptedArtifacts(req).map((a) => a.type));
  for (const t of REQUIRED_ARTIFACT_TYPES) {
    if (!types.has(t)) return false;
  }
  if (req.provider_context?.requires_provider_approval) {
    if (!types.has('provider_approval')) return false;
  }
  return true;
}

function distinctSocApprovalCount(req) {
  return new Set((req.soc_approvals ?? []).map((a) => a.user_id)).size;
}

function killSwitchEvidenceForTenant(store, tenantId) {
  const ks = store.socKillSwitch ?? {};
  const ksTenant = ks.tenant_id ?? null;
  const tenantScoped =
    ksTenant === tenantId ||
    (ks.tenants && typeof ks.tenants === 'object' && ks.tenants[tenantId]);
  if (tenantScoped && parseTs(ks.updated_at) != null) {
    return { kind: 'kill_switch_state', detail: 'Kill switch state recorded for tenant.' };
  }
  const auditHit = (store.auditLog ?? []).find(
    (a) => a.tenant_id === tenantId && SOC_KILL_SWITCH_ACTIONS.has(a.action),
  );
  if (auditHit) {
    return { kind: 'kill_switch_audit', detail: 'Kill switch audit trail recorded for tenant.' };
  }
  return null;
}

function highScaleGovernanceEvidence(store, tenantId) {
  const requests = store.highScaleRequests.filter((h) => h.tenant_id === tenantId);
  const hits = [];

  for (const req of requests) {
    const packOk = authorizationPackComplete(req);
    const approvals = distinctSocApprovalCount(req);
    if (packOk && approvals >= 2) {
      hits.push({
        requestId: req.id,
        kind: 'approved_pack',
        detail: `Request ${req.id}: authorization pack accepted with ${approvals} SOC approver(s).`,
      });
    }
    if (GOVERNED_HS_STATES.has(req.state) && (req.audit_trail?.length ?? 0) > 0) {
      hits.push({
        requestId: req.id,
        kind: 'governed_lifecycle',
        detail: `Request ${req.id}: governed lifecycle state "${req.state}" with audit trail.`,
      });
    }
  }

  return hits;
}

function pendingHighScaleGates(store, tenantId) {
  const pending = store.highScaleRequests.filter(
    (h) => h.tenant_id === tenantId && !['closed', 'rejected'].includes(h.state),
  );
  const gates = [];
  for (const req of pending) {
    const missing = [];
    if (!authorizationPackComplete(req)) {
      const have = new Set(acceptedArtifacts(req).map((a) => a.type));
      const need = REQUIRED_ARTIFACT_TYPES.filter((t) => !have.has(t));
      if (need.length) missing.push(`missing accepted artifacts: ${need.join(', ')}`);
    }
    const approvals = distinctSocApprovalCount(req);
    if (approvals < 2) {
      missing.push(`SOC approvals ${approvals}/2`);
    }
    if (missing.length) {
      gates.push({ requestId: req.id, state: req.state, missing });
    }
  }
  return gates;
}

function scoreSocGovernance(store, tenantId) {
  const kill = killSwitchEvidenceForTenant(store, tenantId);
  const hsHits = highScaleGovernanceEvidence(store, tenantId);
  const pendingGates = pendingHighScaleGates(store, tenantId);

  const hasEvidence = Boolean(kill) || hsHits.length > 0;
  if (!hasEvidence) {
    let detail = 'No high-scale governance evidence recorded yet.';
    if (pendingGates.length) {
      const parts = pendingGates.map(
        (g) => `${g.requestId} (${g.state}): ${g.missing.join('; ')}`,
      );
      detail = `Pending high-scale workflow — gates remain: ${parts.join(' | ')}.`;
    }
    return { score: 0, detail };
  }

  let score = WEIGHT_SOC_GOVERNANCE;
  const detailParts = [];
  if (kill) detailParts.push(kill.detail);
  for (const h of hsHits) detailParts.push(h.detail);
  if (pendingGates.length) {
    const parts = pendingGates.map(
      (g) => `${g.requestId}: ${g.missing.join('; ')}`,
    );
    detailParts.push(`Other request(s) still pending gates: ${parts.join(' | ')}.`);
  }

  return {
    score,
    detail: detailParts.join(' '),
  };
}

export function computeReadiness(tenantId) {
  const store = getStore();
  // Persisted readiness rollups are unversioned and can predate scoring/evidence rules.
  // Recompute from authoritative tenant state; store.readiness remains an output cache only.
  const nowMs = Date.now();
  const policyIds = new Set(activeTargetGroupsForTenant(tenantId).map((policy) => policy.id));
  const targets = store.targets.filter((target) => target.tenant_id === tenantId && !isArchivedTarget(target) && policyIds.has(target.target_group_id));
  const runs = store.testRuns.filter((r) => r.tenant_id === tenantId);
  const findings = store.findings.filter((f) => f.tenant_id === tenantId && f.status === 'open');
  const verdicts = runs
    .map((run) => readinessVerdictForRun(store, run))
    .filter(Boolean);

  const factors = [];

  const declaredTargetIds = new Set(targets.map((target) => target.id));
  const policyByTarget = new Map(targets.map((target) => [target.id, target.target_group_id]));
  const coveredTargetIds = new Set();
  let staleBackedRuns = 0;
  let recentBackedRuns = 0;

  for (const run of runs) {
    const freshness = evidenceFreshnessForRun(store, run, nowMs);
    if (!freshness.backed) continue;
    if (
      freshness.recent &&
      run.target_id &&
      declaredTargetIds.has(run.target_id) && policyByTarget.get(run.target_id) === run.target_group_id
    ) {
      coveredTargetIds.add(run.target_id);
      recentBackedRuns += 1;
    } else if (freshness.stale) {
      staleBackedRuns += 1;
    }
  }

  const totalTargets = targets.length;
  const coveredCount = coveredTargetIds.size;
  const coverageRatio = totalTargets ? coveredCount / totalTargets : 0;
  const coverageScore = Math.round(Math.min(WEIGHT_COVERAGE, coverageRatio * WEIGHT_COVERAGE));

  let coverageDetail;
  if (!totalTargets) {
    coverageDetail = 'No declared domains.';
  } else if (coveredCount === 0) {
    if (staleBackedRuns > 0) {
      coverageDetail = `0 of ${totalTargets} domain(s) covered by recent evidence-backed validations; stale evidence exists on ${staleBackedRuns} run(s).`;
    } else {
      coverageDetail = `0 of ${totalTargets} domain(s) have evidence-backed validations in the last ${RECENT_EVIDENCE_WINDOW_DAYS} days.`;
    }
  } else {
    const missing = totalTargets - coveredCount;
    coverageDetail = `${coveredCount} of ${totalTargets} domain(s) have recent evidence-backed validations.`;
    if (missing > 0) {
      coverageDetail += ` ${missing} domain(s) lack recent validation evidence.`;
    }
  }

  factors.push({
    key: 'coverage',
    label: 'Validation coverage',
    score: coverageScore,
    weight: WEIGHT_COVERAGE,
    detail: coverageDetail,
  });

  const recentVerdicts = verdicts.filter((v) => isRecentTimestamp(v.created_at, nowMs));
  const staleVerdicts = verdicts.filter((v) => {
    const ms = parseTs(v.created_at);
    return ms != null && ms <= nowMs && nowMs - ms > RECENT_EVIDENCE_WINDOW_MS;
  });

  let verdictScore = 0;
  let verdictDetail;
  if (verdicts.length === 0) {
    verdictDetail =
      'No verdict evidence recorded; absence of findings is not proof of readiness until verdict evidence exists.';
  } else if (recentVerdicts.length === 0) {
    verdictDetail = `${findings.length} open finding(s); ${verdicts.length} verdict(s) recorded (0 recent`;
    if (staleVerdicts.length) verdictDetail += `, ${staleVerdicts.length} stale`;
    verdictDetail +=
      '). Stale or missing recent verdict evidence does not support full posture credit.';
  } else {
    const penalty = Math.min(WEIGHT_VERDICTS, findings.length * 10);
    verdictScore = Math.max(0, WEIGHT_VERDICTS - penalty);
    verdictDetail = `${findings.length} open finding(s); ${verdicts.length} verdict(s) recorded (${recentVerdicts.length} recent`;
    if (staleVerdicts.length) verdictDetail += `, ${staleVerdicts.length} stale`;
    verdictDetail += ').';
  }

  factors.push({
    key: 'verdicts',
    label: 'Open findings impact',
    score: Math.round(verdictScore),
    weight: WEIGHT_VERDICTS,
    detail: verdictDetail,
  });

  let freshnessScore = 0;
  let freshnessDetail;
  if (recentBackedRuns > 0 || coveredCount > 0) {
    freshnessScore = WEIGHT_EVIDENCE_FRESHNESS;
    freshnessDetail = `Recent evidence-backed validation within ${RECENT_EVIDENCE_WINDOW_DAYS} days (${recentBackedRuns} run(s), ${coveredCount} domain(s)).`;
  } else if (staleBackedRuns > 0) {
    freshnessScore = 0;
    freshnessDetail = `Evidence exists but is stale (older than ${RECENT_EVIDENCE_WINDOW_DAYS} days); no freshness credit awarded.`;
  } else {
    freshnessScore = 0;
    freshnessDetail = 'No evidence-backed validations yet.';
  }

  factors.push({
    key: 'evidence_freshness',
    label: 'Evidence freshness',
    score: freshnessScore,
    weight: WEIGHT_EVIDENCE_FRESHNESS,
    detail: freshnessDetail,
  });

  const soc = scoreSocGovernance(store, tenantId);
  factors.push({
    key: 'soc_readiness',
    label: 'SOC governance posture',
    score: soc.score,
    weight: WEIGHT_SOC_GOVERNANCE,
    detail: soc.detail,
  });

  const score = Math.min(100, Math.round(factors.reduce((s, f) => s + f.score, 0)));
  const result = {
    score,
    factors,
    posture: readinessPostureForRuns(store, runs),
    updated_at: new Date().toISOString(),
  };
  store.readiness[tenantId] = result;
  return result;
}
