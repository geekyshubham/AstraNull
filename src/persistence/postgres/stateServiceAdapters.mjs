import {
  REQUIRED_ARTIFACT_TYPES,
  authorizationPackComplete,
  distinctSocApprovalCount,
} from '../../lib/highScalePolicy.mjs';
import { buildGetStatePayload } from '../../lib/statePayload.mjs';
import { isTrustedProducerEvent } from '../../lib/trustedEventProvenance.mjs';
import { runVerdictSupportsReadiness } from '../../lib/readinessVerdicts.mjs';

/** Evidence older than this window earns no freshness credit. */
const RECENT_EVIDENCE_WINDOW_DAYS = 30;
const RECENT_EVIDENCE_WINDOW_MS = RECENT_EVIDENCE_WINDOW_DAYS * 24 * 60 * 60 * 1000;

// ADR-0008 removed the "Agent placement & health" factor (was weight 25). Remaining weights are
// scaled by 100/90 and rounded to keep an integer sum of 100 (see services/readiness.mjs).
const WEIGHT_COVERAGE = 44;
const WEIGHT_VERDICTS = 28;
const WEIGHT_EVIDENCE_FRESHNESS = 17;
const WEIGHT_SOC_GOVERNANCE = 11;

const RUN_EVIDENCE_TIMESTAMP_FIELDS = [
  'verdict_at',
  'completed_at',
  'updated_at',
  'created_at',
];

const GOVERNED_HS_STATES = new Set(['scheduled', 'running', 'stopped', 'closed']);

const TEST_RUN_LIST_LIMIT = 500;
const EVIDENCE_LIST_LIMIT = 500;
const RUN_EVENTS_LIMIT = 1000;
const RUN_EVENT_FETCH_RUN_LIMIT = 30;
const RECENT_RUNS_LIMIT = 5;

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

/** @type {readonly string[]} */
export const STATE_CORE_CATALOG_REPOSITORY_METHODS = Object.freeze(['listTargetGroups', 'listTargets']);

/** @type {readonly string[]} */
export const STATE_VALIDATION_EVIDENCE_REPOSITORY_METHODS = Object.freeze([
  'listTestRuns',
  'loadRunEvidenceBatch',
  'listEvidence',
  'countOpenFindings',
]);

/** @type {readonly string[]} */
export const STATE_HIGH_SCALE_REPOSITORY_METHODS = Object.freeze(['listHighScaleRequests']);

/** @type {readonly string[]} */
export const STATE_KILL_SWITCH_REPOSITORY_METHODS = Object.freeze(['getKillSwitchRecord']);

/** @type {readonly string[]} */
export const POSTGRES_STATE_SERVICE_METHODS = Object.freeze(['getState']);

function parseTs(value) {
  if (!value) return null;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms : null;
}

function isRecentMs(ms, nowMs) {
  if (ms == null || !Number.isFinite(ms)) return false;
  if (ms > nowMs) return false;
  return nowMs - ms <= RECENT_EVIDENCE_WINDOW_MS;
}

function runStatusEligible(run) {
  return run.status === 'completed' || run.status === 'verdicted';
}

function readinessPostureForRuns(runs, verdictByRun) {
  const latestByCheck = new Map();
  for (const run of runs) {
    if (!runStatusEligible(run)) continue;
    const verdict = verdictByRun.get(run.id) ?? null;
    if (!runVerdictSupportsReadiness(run, verdict)) continue;
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

function assertStateRepositories(repositories) {
  const coreCatalog = repositories?.coreCatalog;
  if (!coreCatalog || typeof coreCatalog !== 'object') {
    throw new Error('Postgres state service adapter requires repositories.coreCatalog.');
  }
  for (const method of STATE_CORE_CATALOG_REPOSITORY_METHODS) {
    if (typeof coreCatalog[method] !== 'function') {
      throw new Error(`Postgres state service adapter requires coreCatalog.${method}().`);
    }
  }

  const validationEvidence = repositories?.validationEvidence;
  if (!validationEvidence || typeof validationEvidence !== 'object') {
    throw new Error('Postgres state service adapter requires repositories.validationEvidence.');
  }
  for (const method of STATE_VALIDATION_EVIDENCE_REPOSITORY_METHODS) {
    if (typeof validationEvidence[method] !== 'function') {
      throw new Error(`Postgres state service adapter requires validationEvidence.${method}().`);
    }
  }

  const highScale = repositories?.highScale;
  if (!highScale || typeof highScale !== 'object') {
    throw new Error('Postgres state service adapter requires repositories.highScale.');
  }
  for (const method of STATE_HIGH_SCALE_REPOSITORY_METHODS) {
    if (typeof highScale[method] !== 'function') {
      throw new Error(`Postgres state service adapter requires highScale.${method}().`);
    }
  }

  const killSwitch = repositories?.killSwitch;
  if (!killSwitch || typeof killSwitch !== 'object') {
    throw new Error('Postgres state service adapter requires repositories.killSwitch.');
  }
  for (const method of STATE_KILL_SWITCH_REPOSITORY_METHODS) {
    if (typeof killSwitch[method] !== 'function') {
      throw new Error(`Postgres state service adapter requires killSwitch.${method}().`);
    }
  }
}

function runHasEvidenceBacking(run, verdict) {
  return runVerdictSupportsReadiness(run, verdict);
}

function collectEvidenceTimestamps(run, verdict, events, vaultItems) {
  const stamps = [];
  for (const field of RUN_EVIDENCE_TIMESTAMP_FIELDS) {
    const ms = parseTs(run[field]);
    if (ms != null) stamps.push(ms);
  }
  if (verdict) {
    const vMs = parseTs(verdict.created_at);
    if (vMs != null) stamps.push(vMs);
  }
  for (const ev of events) {
    const eMs = parseTs(ev.timestamp ?? ev.created_at);
    if (eMs != null) stamps.push(eMs);
  }
  for (const rec of vaultItems) {
    const rMs = parseTs(rec.created_at);
    if (rMs != null) stamps.push(rMs);
  }
  return stamps;
}

function evidenceFreshnessForRun(run, verdict, events, vaultItems, nowMs) {
  if (!runStatusEligible(run) || !runHasEvidenceBacking(run, verdict, events, vaultItems)) {
    return { recent: false, stale: false, backed: false };
  }
  const stamps = collectEvidenceTimestamps(run, verdict, events, vaultItems);
  if (stamps.length === 0) {
    return { recent: false, stale: false, backed: true };
  }
  const hasRecent = stamps.some((ms) => isRecentMs(ms, nowMs));
  return { recent: hasRecent, stale: !hasRecent, backed: true };
}

function computeReadinessSummary({
  tenantId,
  targets,
  runs,
  openFindingsCount,
  verdictByRun,
  eventsByRun,
  evidenceByRun,
  highScaleRequests,
  killSwitch,
  nowMs,
}) {
  const factors = [];

  const declaredTargetIds = new Set(targets.map((target) => target.id));
  const policyByTarget = new Map(targets.map((target) => [target.id, target.target_group_id]));
  const coveredTargetIds = new Set();
  let staleBackedRuns = 0;
  let recentBackedRuns = 0;

  for (const run of runs) {
    const verdict = verdictByRun.get(run.id) ?? null;
    const events = eventsByRun.get(run.id) ?? [];
    const vaultItems = evidenceByRun.get(run.id) ?? [];
    const freshness = evidenceFreshnessForRun(run, verdict, events, vaultItems, nowMs);
    if (!freshness.backed) continue;
    if (
      freshness.recent
      && run.target_id
      && declaredTargetIds.has(run.target_id) && policyByTarget.get(run.target_id) === run.target_group_id
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

  const runsById = new Map(runs.map((run) => [run.id, run]));
  const verdicts = [...verdictByRun.entries()]
    .filter(([runId, verdict]) => runVerdictSupportsReadiness(runsById.get(runId), verdict))
    .map(([, verdict]) => verdict);
  const recentVerdicts = verdicts.filter((v) => isRecentMs(parseTs(v.created_at), nowMs));
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
    verdictDetail = `${openFindingsCount} open finding(s); ${verdicts.length} verdict(s) recorded (0 recent`;
    if (staleVerdicts.length) verdictDetail += `, ${staleVerdicts.length} stale`;
    verdictDetail +=
      '). Stale or missing recent verdict evidence does not support full posture credit.';
  } else {
    const penalty = Math.min(WEIGHT_VERDICTS, openFindingsCount * 10);
    verdictScore = Math.max(0, WEIGHT_VERDICTS - penalty);
    verdictDetail = `${openFindingsCount} open finding(s); ${verdicts.length} verdict(s) recorded (${recentVerdicts.length} recent`;
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
    freshnessDetail = `Evidence exists but is stale (older than ${RECENT_EVIDENCE_WINDOW_DAYS} days); no freshness credit awarded.`;
  } else {
    freshnessDetail = 'No evidence-backed validations yet.';
  }

  factors.push({
    key: 'evidence_freshness',
    label: 'Evidence freshness',
    score: freshnessScore,
    weight: WEIGHT_EVIDENCE_FRESHNESS,
    detail: freshnessDetail,
  });

  const socGovernance = scoreSocGovernance({ highScaleRequests, killSwitch, nowMs });
  factors.push({
    key: 'soc_readiness',
    label: 'SOC governance posture',
    score: socGovernance.score,
    weight: WEIGHT_SOC_GOVERNANCE,
    detail: socGovernance.detail,
  });

  const score = Math.min(100, Math.round(factors.reduce((s, f) => s + f.score, 0)));
  return {
    score,
    factors,
    posture: readinessPostureForRuns(runs, verdictByRun),
    updated_at: new Date(nowMs).toISOString(),
    persistence: 'postgres',
  };
}

function indexEvidenceByRun(evidenceItems) {
  /** @type {Map<string, object[]>} */
  const map = new Map();
  for (const item of evidenceItems) {
    const runId = item.test_run_id;
    if (!runId) continue;
    if (!map.has(runId)) map.set(runId, []);
    map.get(runId).push(item);
  }
  return map;
}


function evidenceBackedByTrustedLinkedEvent(item, eventsByRun) {
  if (!item.related_event_id) return true;
  return (eventsByRun.get(item.test_run_id) ?? [])
    .some((event) => event.id === item.related_event_id);
}
function sortRunsNewestFirst(runs) {
  return [...runs].sort((a, b) => {
    const time = (parseTs(b.started_at ?? b.created_at) ?? 0) - (parseTs(a.started_at ?? a.created_at) ?? 0);
    return time || String(b.id ?? '').localeCompare(String(a.id ?? ''));
  });
}

function verdictBackedByTrustedEvidence(verdict, runId, eventsByRun, evidenceByRun) {
  const evidenceIds = new Set(Array.isArray(verdict?.evidence_ids) ? verdict.evidence_ids : []);
  if (evidenceIds.size === 0) return false;
  return [
    ...(eventsByRun.get(runId) ?? []),
    ...(evidenceByRun.get(runId) ?? []),
  ].some((evidence) => evidenceIds.has(evidence.id));
}

function acceptedArtifactTypes(req) {
  return new Set(
    (req.artifacts ?? [])
      .filter((artifact) => artifact?.status === 'accepted')
      .map((artifact) => artifact.type),
  );
}

function pendingHighScaleGates(requests, nowMs = Date.now()) {
  const gates = [];
  for (const req of requests) {
    if (['closed', 'rejected'].includes(req.state)) continue;
    const missing = [];
    if (!authorizationPackComplete(req, nowMs)) {
      const accepted = acceptedArtifactTypes(req);
      const missingTypes = REQUIRED_ARTIFACT_TYPES.filter((type) => !accepted.has(type));
      if (missingTypes.length > 0) {
        missing.push(`missing accepted artifacts: ${missingTypes.join(', ')}`);
      }
    }
    const approvals = distinctSocApprovalCount(req);
    if (approvals < 2) {
      missing.push(`SOC approvals ${approvals}/2`);
    }
    if (missing.length > 0) {
      gates.push({ requestId: req.id, state: req.state, missing });
    }
  }
  return gates;
}

function killSwitchHasEvidence(killSwitch) {
  return Boolean(killSwitch?.updated_at);
}

function highScaleGovernanceEvidence(requests, nowMs = Date.now()) {
  const hits = [];
  for (const req of requests) {
    const approvals = distinctSocApprovalCount(req);
    if (authorizationPackComplete(req, nowMs) && approvals >= 2) {
      hits.push({
        requestId: req.id,
        detail: `Request ${req.id}: authorization pack accepted with ${approvals} SOC approver(s).`,
      });
    }
    if (GOVERNED_HS_STATES.has(req.state) && (req.audit_trail?.length ?? 0) > 0) {
      hits.push({
        requestId: req.id,
        detail: `Request ${req.id}: governed lifecycle state "${req.state}" with audit trail.`,
      });
    }
  }
  return hits;
}

function scoreSocGovernance({ highScaleRequests, killSwitch, nowMs = Date.now() }) {
  const pendingGates = pendingHighScaleGates(highScaleRequests, nowMs);
  const hsHits = highScaleGovernanceEvidence(highScaleRequests, nowMs);
  const hasKillSwitchEvidence = killSwitchHasEvidence(killSwitch);

  if (!hasKillSwitchEvidence && hsHits.length === 0) {
    let detail = 'No high-scale governance evidence recorded yet.';
    if (pendingGates.length > 0) {
      const parts = pendingGates.map(
        (gate) => `${gate.requestId} (${gate.state}): ${gate.missing.join('; ')}`,
      );
      detail = `Pending high-scale workflow gates remain: ${parts.join(' | ')}.`;
    }
    return { score: 0, detail };
  }

  const details = [];
  if (hasKillSwitchEvidence) details.push('Kill switch state recorded for tenant.');
  for (const hit of hsHits) details.push(hit.detail);
  if (pendingGates.length > 0) {
    const parts = pendingGates.map(
      (gate) => `${gate.requestId}: ${gate.missing.join('; ')}`,
    );
    details.push(`Other request(s) still pending gates: ${parts.join(' | ')}.`);
  }

  return { score: WEIGHT_SOC_GOVERNANCE, detail: details.join(' ') };
}

function sanitizeKillSwitchRecord(record, tenantId) {
  return {
    tenant_id: record?.tenant_id ?? tenantId,
    active: Boolean(record?.active),
    reason: record?.reason ?? null,
    updated_at: record?.updated_at ?? null,
    updated_by: record?.updated_by ?? null,
  };
}

/**
 * @param {{
 *   coreCatalog?: Record<string, unknown>,
 *   validationEvidence?: Record<string, unknown>,
 *   highScale?: Record<string, unknown>,
 *   killSwitch?: Record<string, unknown>,
 * }} repositories
 * @param {{ now?: () => Date }} [options]
 */
export function createPostgresStateServices(repositories, options = {}) {
  assertStateRepositories(repositories);
  const coreCatalog = repositories.coreCatalog;
  const validationEvidence = repositories.validationEvidence;
  const highScale = repositories.highScale;
  const killSwitch = repositories.killSwitch;
  const nowFn = options.now ?? (() => new Date());

  return {
    async queryAuditEntries(ctx, options = {}) {
      if (typeof repositories.audit?.queryAuditEntries !== 'function') {
        const error = new Error('Audit reads are not wired.');
        error.status = 503;
        error.code = 'postgres_route_not_wired';
        throw error;
      }
      return repositories.audit.queryAuditEntries(ctx, options);
    },

    async getAuditEntry(ctx, id) {
      if (typeof repositories.audit?.getAuditEntry !== 'function') {
        const error = new Error('Audit reads are not wired.');
        error.status = 503;
        error.code = 'postgres_route_not_wired';
        throw error;
      }
      return repositories.audit.getAuditEntry(ctx, id);
    },

    async getState(ctx) {
      const tenantId = ctx.tenantId;
      const nowMs = nowFn().getTime();

      // dashboard_rollup.readiness is unversioned and may reflect obsolete scoring rules.
      // Repository-backed evidence below is the authoritative Postgres readiness source.
      const highScaleWired = typeof highScale.listHighScaleRequests === 'function';

      const [
        groups,
        targets,
        runs,
        evidenceItems,
        openFindingsCount,
        highScaleRequests,
        killSwitchRecord,
      ] = await Promise.all([
        coreCatalog.listTargetGroups(ctx),
        coreCatalog.listTargets(ctx),        validationEvidence.listTestRuns(ctx, { limit: TEST_RUN_LIST_LIMIT }),
        validationEvidence.listEvidence(ctx, { limit: EVIDENCE_LIST_LIMIT }),
        validationEvidence.countOpenFindings(ctx),
        highScale.listHighScaleRequests(ctx),
        killSwitch.getKillSwitchRecord(ctx),
      ]);

      const sortedRuns = sortRunsNewestFirst(runs);

      const eligibleRuns = runs.filter(runStatusEligible);
      const eligibleRunIds = new Set(eligibleRuns.map((run) => run.id));
      const eventRunIds = new Set(
        sortedRuns
          .filter(runStatusEligible)
          .slice(0, RUN_EVENT_FETCH_RUN_LIMIT)
          .map((run) => run.id),
      );
      for (const item of evidenceItems) {
        if (item.related_event_id && item.test_run_id) eventRunIds.add(item.test_run_id);
      }
      const baseEventRunIds = sortedRuns
        .filter((run) => eventRunIds.has(run.id))
        .map((run) => run.id);
      const runEvidence = await validationEvidence.loadRunEvidenceBatch(ctx, {
        runIds: eligibleRuns.map((run) => run.id),
        eventRunIds: baseEventRunIds,
        eventLimitPerRun: RUN_EVENTS_LIMIT,
      });

      /** @type {Map<string, object>} */
      const verdictByRun = new Map();
      for (const verdict of Array.isArray(runEvidence?.verdicts) ? runEvidence.verdicts : []) {
        if (eligibleRunIds.has(verdict?.test_run_id)) {
          verdictByRun.set(verdict.test_run_id, verdict);
        }
      }

      const selectedEventRunIds = new Set(baseEventRunIds);
      for (const [runId, verdict] of verdictByRun) {
        if (Array.isArray(verdict.evidence_ids) && verdict.evidence_ids.length > 0) {
          selectedEventRunIds.add(runId);
        }
      }
      /** @type {Map<string, object[]>} */
      const eventsByRun = new Map();
      for (const runId of selectedEventRunIds) eventsByRun.set(runId, []);
      for (const event of Array.isArray(runEvidence?.events) ? runEvidence.events : []) {
        if (!selectedEventRunIds.has(event?.test_run_id) || !isTrustedProducerEvent(event)) continue;
        eventsByRun.get(event.test_run_id).push(event);
      }
      const evidenceByRun = indexEvidenceByRun(
        evidenceItems.filter((item) => evidenceBackedByTrustedLinkedEvent(item, eventsByRun)),
      );
      for (const [runId, verdict] of verdictByRun) {
        if (!verdictBackedByTrustedEvidence(verdict, runId, eventsByRun, evidenceByRun)) {
          verdictByRun.delete(runId);
        }
      }

      const readiness = computeReadinessSummary({
        tenantId,
        targets,
        runs,
        openFindingsCount,
        verdictByRun,
        eventsByRun,
        evidenceByRun,
        highScaleRequests,
        killSwitch: killSwitchRecord,
        nowMs,
      });

      const tenantHighScaleRequests = Array.isArray(highScaleRequests)
        ? highScaleRequests.filter((row) => row.tenant_id === tenantId)
        : [];

      return buildGetStatePayload({
        tenantId,
        rollup: null,
        computed: {
          readiness,
          target_groups: groups.length,
          targets: targets.length,
          recent_runs: sortedRuns
            .slice(0, RECENT_RUNS_LIMIT)
            .reverse()
            .map((run) => ({ ...run, verdict: verdictByRun.get(run.id) ?? null })),
          open_findings: openFindingsCount,
          high_scale_requests: tenantHighScaleRequests.length,
        },
        killSwitch: sanitizeKillSwitchRecord(killSwitchRecord, tenantId),
        highScaleWired,
        highScaleRequests: tenantHighScaleRequests,
      });
    },
  };
}
