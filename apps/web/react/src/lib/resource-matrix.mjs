/**
 * DET-024 resource-exhaustion matrix derivation.
 *
 * A matrix cell is not a policy/run activity counter. It summarizes only stored verdicts for
 * completed runs, joins supporting evidence by test_run_id, and keeps freshness and target-kind
 * applicability explicit. The React component hydrates run details because the list endpoint
 * intentionally omits verdict records.
 */

import { itemCheckId, itemTargetGroupId } from './vector-coverage.mjs';

export const RESOURCE_EVIDENCE_FRESHNESS_DAYS = 30;
export const RESOURCE_EVIDENCE_FRESHNESS_MS = RESOURCE_EVIDENCE_FRESHNESS_DAYS * 24 * 60 * 60 * 1000;

/** The twelve taxonomy families, in dashboard display order. */
export const RESOURCE_FAMILIES = [
  { id: 'volumetric', label: 'Volumetric', metric: 'Gbps/Tbps' },
  { id: 'packet_processing', label: 'Packet-processing', metric: 'Mpps/Bpps' },
  { id: 'state_exhaustion', label: 'State exhaustion', metric: 'CPS / states' },
  { id: 'application_l7', label: 'Application L7', metric: 'RPS' },
  { id: 'computational', label: 'Computational', metric: 'CPU / RPS' },
  { id: 'memory_exhaustion', label: 'Memory exhaustion', metric: 'Connections' },
  { id: 'backend_exhaustion', label: 'Backend exhaustion', metric: 'Queries/s' },
  { id: 'dns_exhaustion', label: 'DNS exhaustion', metric: 'QPS' },
  { id: 'reflection', label: 'Reflection', metric: 'pps / bps' },
  { id: 'amplification', label: 'Amplification', metric: 'Ratio' },
  { id: 'exploit_dos', label: 'Exploit-based DoS', metric: 'Varies' },
  { id: 'delivery_pattern', label: 'Delivery pattern', metric: 'Cross-cutting' },
];

const TERMINAL_RUN_STATUSES = new Set(['completed', 'verdicted']);
const PROTECTED_VERDICTS = new Set([
  'pass',
  'passed',
  'protected',
  'success',
  'ok',
  'edge_protected',
  'allowed_as_expected',
]);
const EXPOSED_VERDICTS = new Set([
  'exposed',
  'unprotected',
  'gap',
  'fail',
  'failed',
  'penetrated',
  'bypassable',
  'edge_exposed',
]);
const NON_VERDICTS = new Set(['', 'pending', 'planned', 'queued', 'running', 'collecting']);

function asRecord(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function stringValue(value) {
  return value === undefined || value === null ? '' : String(value).trim();
}

function runId(run) {
  return stringValue(run.id ?? run.test_run_id);
}

function evidenceRunId(evidence) {
  return stringValue(evidence.test_run_id ?? evidence.testRunId);
}

function parseTimestamp(value) {
  if (!value) return null;
  const parsed = new Date(value).getTime();
  return Number.isFinite(parsed) ? parsed : null;
}

function latestNonFutureTimestamp(values, nowMs) {
  const timestamps = values
    .map(parseTimestamp)
    .filter((value) => value !== null && value <= nowMs);
  return timestamps.length > 0 ? Math.max(...timestamps) : null;
}

function runVerdictValue(run) {
  const verdict = asRecord(run.verdict);
  return stringValue(
    verdict?.verdict
      ?? verdict?.status
      ?? verdict?.result
      ?? (typeof run.verdict === 'string' ? run.verdict : ''),
  ).toLowerCase();
}

function classifyVerdict(value) {
  if (NON_VERDICTS.has(value)) return null;
  if (PROTECTED_VERDICTS.has(value)) return 'protected';
  if (EXPOSED_VERDICTS.has(value)) return 'exposed';
  // A stored terminal verdict that is neither a known pass nor gap remains reviewable; never
  // silently coerce it to protected or discard it as if no run happened.
  return 'inconclusive';
}

function outcomeTimestamp(run, verdict, matchingEvidence, nowMs) {
  return latestNonFutureTimestamp([
    verdict?.created_at,
    verdict?.verdict_at,
    ...matchingEvidence.flatMap((item) => [item.observed_at, item.timestamp, item.created_at]),
    // Match the backend readiness scorer: once a run has evidence backing, terminal run
    // timestamps are valid fallback freshness markers.
    run.verdict_at,
    run.completed_at,
    run.updated_at,
    run.created_at,
    run.started_at,
  ], nowMs);
}

/** Active target groups are never display-capped; archived/deleted rows are excluded explicitly. */
export function resourceMatrixGroups(targetGroups) {
  return targetGroups.filter((group) => group.archived_at == null && group.deleted_at == null);
}

/** Check ids assigned to one resource family by the API-declared taxonomy field. */
export function resourceFamilyCheckIds(checks, family) {
  return new Set(
    checks
      .filter((check) => check.exhausted_resource === family.id)
      .map((check) => stringValue(check.check_id ?? check.id))
      .filter(Boolean),
  );
}

/**
 * Narrow a family to checks that support at least one declared target kind in the group.
 * When inventory did not load, retain every mapped check so the caller cannot manufacture a
 * confident "not applicable" result from missing data.
 */
export function applicableResourceFamilyCheckIds({
  checks,
  family,
  groupId,
  targets,
  targetInventoryLoaded = true,
}) {
  const mapped = checks.filter((check) => check.exhausted_resource === family.id);
  if (!targetInventoryLoaded) return resourceFamilyCheckIds(checks, family);
  if (!groupId) return new Set();

  const targetKinds = new Set(
    targets
      .filter((target) => itemTargetGroupId(target) === groupId)
      .map((target) => stringValue(target.kind ?? target.target_kind).toLowerCase())
      .filter(Boolean),
  );
  if (targetKinds.size === 0) return new Set();

  return new Set(
    mapped
      .filter((check) => {
        const supported = Array.isArray(check.supported_targets)
          ? check.supported_targets.map((value) => stringValue(value).toLowerCase()).filter(Boolean)
          : [];
        // Catalog entries without an explicit target constraint remain potentially applicable;
        // prerequisites affect runnability, not target-kind applicability.
        return supported.length === 0 || supported.some((kind) => targetKinds.has(kind));
      })
      .map((check) => stringValue(check.check_id ?? check.id))
      .filter(Boolean),
  );
}

/**
 * Summarize the latest evidence-backed verdict for each applicable check in one matrix cell.
 *
 * Precedence is intentionally conservative: a fresh exposed verdict wins, then fresh
 * inconclusive; any stale latest verdict prevents a protected family label. Protected is shown
 * only when every applicable check has a fresh protected verdict; an untested applicable check
 * makes otherwise passing evidence inconclusive rather than dominant green.
 */
export function resourceFamilyVerdictState({
  checkIds,
  groupId,
  runs,
  evidence,
  nowMs = Date.now(),
  freshnessWindowMs = RESOURCE_EVIDENCE_FRESHNESS_MS,
}) {
  const base = {
    applicableCheckCount: checkIds.size,
    testedCheckCount: 0,
    freshCheckCount: 0,
    staleCheckCount: 0,
    protectedCount: 0,
    exposedCount: 0,
    inconclusiveCount: 0,
    latestEvidenceAt: null,
  };
  if (!groupId || checkIds.size === 0) return { status: 'not_applicable', ...base };

  const evidenceByRun = new Map();
  for (const item of evidence) {
    const id = evidenceRunId(item);
    if (!id) continue;
    const bucket = evidenceByRun.get(id) ?? [];
    bucket.push(item);
    evidenceByRun.set(id, bucket);
  }

  const latestByCheck = new Map();
  for (const run of runs) {
    const checkId = itemCheckId(run);
    if (itemTargetGroupId(run) !== groupId || !checkIds.has(checkId)) continue;
    if (!TERMINAL_RUN_STATUSES.has(stringValue(run.status).toLowerCase())) continue;

    const verdictValue = runVerdictValue(run);
    const classification = classifyVerdict(verdictValue);
    if (!classification) continue;

    const id = runId(run);
    const matchingEvidence = id ? evidenceByRun.get(id) ?? [] : [];
    const verdict = asRecord(run.verdict);
    const runTargetId = stringValue(run.target_id ?? run.targetId);
    const verdictEvidenceIds = Array.isArray(verdict?.evidence_ids)
      ? verdict.evidence_ids.map(stringValue).filter(Boolean)
      : [];
    const persistedVerdictIsBound = Boolean(
      verdict
      && id
      && stringValue(verdict.test_run_id ?? verdict.testRunId) === id
      && stringValue(verdict.check_id ?? verdict.checkId) === checkId
      && (!runTargetId || stringValue(verdict.target_id ?? verdict.targetId) === runTargetId)
      && verdictEvidenceIds.length > 0,
    );
    // Detail verdicts must bind to this exact run/check/target and cite evidence ids. A legacy
    // plain-string verdict is accepted only when a separate vault row binds to this exact run.
    if (!persistedVerdictIsBound && matchingEvidence.length === 0) continue;

    const evidenceAtMs = outcomeTimestamp(run, persistedVerdictIsBound ? verdict : null, matchingEvidence, nowMs);
    const outcome = { classification, evidenceAtMs };
    const prior = latestByCheck.get(checkId);
    const outcomeRank = outcome.classification === 'exposed' ? 3 : outcome.classification === 'inconclusive' ? 2 : 1;
    const priorRank = prior?.classification === 'exposed' ? 3 : prior?.classification === 'inconclusive' ? 2 : 1;
    if (
      !prior
      || (outcome.evidenceAtMs ?? -Infinity) > (prior.evidenceAtMs ?? -Infinity)
      || (
        (outcome.evidenceAtMs ?? -Infinity) === (prior.evidenceAtMs ?? -Infinity)
        && outcomeRank > priorRank
      )
    ) {
      latestByCheck.set(checkId, outcome);
    }
  }

  const outcomes = [...latestByCheck.values()];
  if (outcomes.length === 0) return { status: 'not_run', ...base };

  const fresh = outcomes.filter((outcome) => (
    outcome.evidenceAtMs !== null
    && nowMs - outcome.evidenceAtMs <= freshnessWindowMs
  ));
  const stale = outcomes.filter((outcome) => !fresh.includes(outcome));
  const protectedCount = outcomes.filter((outcome) => outcome.classification === 'protected').length;
  const exposedCount = outcomes.filter((outcome) => outcome.classification === 'exposed').length;
  const inconclusiveCount = outcomes.filter((outcome) => outcome.classification === 'inconclusive').length;
  const latestEvidenceMs = outcomes.reduce(
    (latest, outcome) => outcome.evidenceAtMs === null ? latest : Math.max(latest, outcome.evidenceAtMs),
    -Infinity,
  );

  const everyApplicableCheckHasFreshPass = outcomes.length === checkIds.size
    && fresh.length === checkIds.size
    && fresh.every((outcome) => outcome.classification === 'protected');

  let status = 'inconclusive';
  if (fresh.some((outcome) => outcome.classification === 'exposed')) status = 'exposed';
  else if (fresh.some((outcome) => outcome.classification === 'inconclusive')) status = 'inconclusive';
  else if (stale.length > 0) status = 'stale';
  else if (everyApplicableCheckHasFreshPass) status = 'protected';

  return {
    status,
    ...base,
    testedCheckCount: outcomes.length,
    freshCheckCount: fresh.length,
    staleCheckCount: stale.length,
    protectedCount,
    exposedCount,
    inconclusiveCount,
    latestEvidenceAt: Number.isFinite(latestEvidenceMs) ? new Date(latestEvidenceMs).toISOString() : null,
  };
}
