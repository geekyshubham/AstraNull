import { getCheckById } from '../contracts/checks.mjs';
import {
  buildReportComplianceSummary,
  normalizeReportKind,
  normalizeReportPeriod,
} from '../contracts/complianceReports.mjs';
import { scrubVerdictForReportExport } from './outsideInEvidence.mjs';
import { presentTargetDeclaration } from './targetDeclarations.mjs';

/** Explicit id lists larger than this are rejected. They are not truncated. */
export const MAX_REPORT_SCOPE_IDS = 100;
/** Omitted `run_ids` keep the historical recent window and record the true total beside it. */
export const MAX_CAPTURED_RUNS = 10;
export const MAX_SNAPSHOT_FINDINGS = 100;
export const MAX_SNAPSHOT_EVIDENCE = 100;
export const MAX_DECLARED_MEMBERS = 100;
const MAX_EVIDENCE_IDS_PER_ROW = 50;
const DAY_MS = 24 * 60 * 60 * 1000;
const ID_RE = /^[A-Za-z0-9_.:-]{1,80}$/;

/**
 * Keys that would change which records a report covers. Unknown ones are rejected.
 * Unrelated body fields (a stray credential, for example) stay ignored and are not stored.
 */
const SCOPE_ALIAS_KEYS = new Set([
  'target_id',
  'targets',
  'target_group_id',
  'group_id',
  'group_ids',
  'groups',
  'scope',
  'cohort',
  'cohort_id',
  'cohort_ids',
  'window',
  'filters',
  'filter',
  'evidence_ids',
  'finding_ids',
  'primary_run_id',
  'run_id',
  'check_ids',
  'estate',
  'workspace',
  'all',
  'all_targets',
]);

function scopeFailure(error, extra = {}) {
  return { ok: false, error: { error, status: 400, ...extra } };
}

function readIdList(source, field) {
  if (!Object.hasOwn(source, field)) return null;
  const value = source[field];
  if (!Array.isArray(value) || value.length === 0) {
    return scopeFailure('invalid_scope', { field, reason: 'nonempty_string_array' });
  }
  if (value.length > MAX_REPORT_SCOPE_IDS) {
    return scopeFailure('scope_too_large', { field, limit: MAX_REPORT_SCOPE_IDS, count: value.length });
  }
  const ids = [];
  const seen = new Set();
  for (const entry of value) {
    if (typeof entry !== 'string' || !ID_RE.test(entry)) {
      return scopeFailure('invalid_scope', { field, reason: 'id_format' });
    }
    if (seen.has(entry)) return scopeFailure('invalid_scope', { field, reason: 'duplicate_id' });
    seen.add(entry);
    ids.push(entry);
  }
  return { ok: true, ids };
}

/**
 * Accepted create body: `kind`, `title`, `period`, and optional exact
 * `target_ids`, `target_group_ids`, `run_ids`. Omitted scope is the tenant.
 * @param {unknown} body
 */
export function parseReportCreateBody(body) {
  const source = body == null ? {} : body;
  if (typeof source !== 'object' || Array.isArray(source)) {
    return scopeFailure('invalid_scope', { field: 'body', reason: 'body_must_be_object' });
  }
  const unrecognized = Object.keys(source).filter((key) => SCOPE_ALIAS_KEYS.has(key));
  if (unrecognized.length > 0) {
    return scopeFailure('unrecognized_scope', { fields: unrecognized });
  }
  const targetIds = readIdList(source, 'target_ids');
  if (targetIds && !targetIds.ok) return targetIds;
  const targetGroupIds = readIdList(source, 'target_group_ids');
  if (targetGroupIds && !targetGroupIds.ok) return targetGroupIds;
  const runIds = readIdList(source, 'run_ids');
  if (runIds && !runIds.ok) return runIds;
  const explicit = Boolean(targetIds || targetGroupIds || runIds);
  const title = typeof source.title === 'string' && source.title.trim() ? source.title.trim().slice(0, 200) : 'AstraNull Readiness Summary';
  return {
    ok: true,
    value: {
      kind: normalizeReportKind(source.kind),
      title,
      period: normalizeReportPeriod(source.period),
      targetIds: targetIds ? targetIds.ids : null,
      targetGroupIds: targetGroupIds ? targetGroupIds.ids : null,
      runIds: runIds ? runIds.ids : null,
      explicit,
    },
  };
}

/** Period label → inclusive window ending at generation. Quarter is the UTC calendar quarter. */
export function reportPeriodBounds(period, asOfIso) {
  const asOfMs = Date.parse(asOfIso ?? '');
  if (!period) {
    return { status: 'not_recorded', label: null, start: null, end: null, source: 'period_omitted' };
  }
  if (!Number.isFinite(asOfMs)) {
    return { status: 'not_included', label: period, start: null, end: null, source: 'generation_clock_unreadable' };
  }
  const end = new Date(asOfMs).toISOString();
  if (period === 'all-time') {
    return { status: 'unbounded', label: period, start: null, end, source: 'period_label' };
  }
  if (period === 'last-7-days' || period === 'last-30-days') {
    const days = period === 'last-7-days' ? 7 : 30;
    return {
      status: 'bounded',
      label: period,
      start: new Date(asOfMs - days * DAY_MS).toISOString(),
      end,
      source: 'generation_clock',
    };
  }
  if (period === 'quarter') {
    const date = new Date(asOfMs);
    const quarter = Math.floor(date.getUTCMonth() / 3);
    return {
      status: 'bounded',
      label: period,
      start: new Date(Date.UTC(date.getUTCFullYear(), quarter * 3, 1)).toISOString(),
      end,
      source: 'utc_calendar_quarter',
    };
  }
  return { status: 'not_recorded', label: null, start: null, end: null, source: 'period_unrecognized' };
}

export function asArray(value) {
  return Array.isArray(value) ? value : [];
}

export function isActiveTarget(row) {
  return Boolean(row) && row.deleted_at == null;
}

export function isActiveGroup(row) {
  return Boolean(row) && row.deleted_at == null && row.archived_at == null;
}

export function runInstantMs(run) {
  const raw = run?.started_at ?? run?.created_at ?? null;
  const ms = raw == null || raw === '' ? NaN : Date.parse(raw);
  return Number.isFinite(ms) ? ms : null;
}

export function rowInstantMs(row, fields) {
  for (const field of fields) {
    const raw = row?.[field];
    if (raw == null || raw === '') continue;
    const ms = Date.parse(raw);
    if (Number.isFinite(ms)) return ms;
  }
  return null;
}

/** @returns {true | false | null} null means a bounded window cannot be proven. */
export function withinPeriod(ms, bounds) {
  if (!bounds || bounds.status !== 'bounded') return true;
  if (ms == null) return null;
  return ms >= Date.parse(bounds.start) && ms <= Date.parse(bounds.end);
}

export function compareNewest(instant) {
  return (left, right) => {
    const delta = (instant(right) ?? -1) - (instant(left) ?? -1);
    if (delta !== 0) return delta;
    return String(right.id).localeCompare(String(left.id));
  };
}

function stringIds(value) {
  return asArray(value).filter((id) => typeof id === 'string' && id.length > 0 && id.length <= 80).slice(0, MAX_EVIDENCE_IDS_PER_ROW);
}

function plainText(value) {
  if (typeof value !== 'string') return null;
  const cleaned = value.replace(/[\u0000-\u001f]/g, '').trim();
  return cleaned ? cleaned.slice(0, 200) : null;
}

function countGap(total, included) {
  if (total == null) return { total: null, included, excluded: null, total_status: 'unknown' };
  return { total, included, excluded: Math.max(0, total - included), total_status: 'complete' };
}

function declarationItem(member) {
  const presented = presentTargetDeclaration(member.declaration ?? {}, member.group_declaration ?? {});
  return {
    target_id: member.id,
    target_group_id: member.target_group_id ?? null,
    kind: member.kind ?? null,
    value: plainText(member.value),
    purpose: presented.purpose,
    purpose_status: presented.purpose_status,
    purpose_source: presented.purpose_source,
    service_roles: presented.service_roles,
    service_roles_status: presented.service_roles_status,
    service_roles_source: presented.service_roles_source,
    owner_status: presented.owner?.status ?? 'unassigned',
    owner_label: presented.owner?.label ?? null,
    owner_source: presented.owner?.source ?? null,
    criticality_status: presented.criticality?.status ?? 'unassigned',
    criticality: presented.criticality?.value ?? null,
    criticality_source: presented.criticality?.source ?? null,
  };
}

function snapshotRun(run) {
  const check = getCheckById(run.check_id);
  return {
    id: run.id,
    check_id: run.check_id ?? null,
    target_id: run.target_id ?? null,
    target_group_id: run.target_group_id ?? null,
    status: run.status ?? null,
    vector_family: run.vector_family ?? check?.vector_family ?? null,
    safety_class: run.safety_class ?? check?.safety_class ?? null,
    started_at: run.started_at ?? null,
    completed_at: run.completed_at ?? null,
    created_at: run.created_at ?? null,
  };
}

function snapshotVerdict(verdict) {
  return scrubVerdictForReportExport({
    id: verdict.id ?? null,
    test_run_id: verdict.test_run_id,
    target_id: verdict.target_id ?? null,
    check_id: verdict.check_id ?? null,
    verdict: verdict.verdict ?? null,
    confidence: verdict.confidence ?? null,
    evidence_ids: stringIds(verdict.evidence_ids),
    explanation: typeof verdict.explanation === 'string' ? verdict.explanation : null,
    created_at: verdict.created_at ?? null,
  });
}

function snapshotFinding(finding) {
  return {
    id: finding.id,
    target_id: finding.target_id ?? null,
    target_group_id: finding.target_group_id ?? null,
    test_run_id: finding.test_run_id ?? null,
    check_id: finding.check_id ?? null,
    title: plainText(finding.title),
    severity: finding.severity ?? null,
    status: finding.status ?? null,
    evidence_ids: stringIds(finding.evidence_ids),
    created_at: finding.created_at ?? null,
    updated_at: finding.updated_at ?? null,
  };
}

function snapshotEvidence(row) {
  return {
    id: row.id,
    test_run_id: row.test_run_id ?? null,
    label: plainText(row.label),
    created_at: row.created_at ?? null,
  };
}

/**
 * Sample lists from repositories that cannot count. `run_total` stays null when the
 * sample filled the cap so a capped page is not reported as the estate size.
 */
export function worldFromListSamples(runs, findings, { runLimit = MAX_CAPTURED_RUNS } = {}) {
  const runRows = asArray(runs);
  const findingRows = asArray(findings);
  const open = findingRows.filter((finding) => finding.status === 'open').length;
  const runsKnown = runRows.length < runLimit;
  return {
    legacy: true,
    found_targets: null,
    found_groups: null,
    found_runs: null,
    members: [],
    member_total: null,
    runs: runRows,
    run_total: runsKnown ? runRows.length : null,
    run_total_unwindowed: runsKnown ? runRows.length : null,
    findings: findingRows.slice(0, MAX_SNAPSHOT_FINDINGS),
    finding_total: findingRows.length,
    finding_total_unwindowed: findingRows.length,
    open_finding_total: open,
    verdicts: [],
    evidence: [],
    evidence_total: null,
  };
}
function orderedVerdicts(runs, verdicts) {
  const byRun = new Map();
  for (const verdict of verdicts ?? []) {
    const list = byRun.get(verdict.test_run_id) ?? [];
    list.push(verdict);
    byRun.set(verdict.test_run_id, list);
  }
  const ordered = [];
  for (const run of runs) {
    const list = (byRun.get(run.id) ?? []).slice().sort((left, right) => String(left.id).localeCompare(String(right.id)));
    ordered.push(...list);
  }
  return ordered;
}

/**
 * Validate scope and build the stored report. Does not read or write the store.
 * Target-scoped reports do not receive the tenant readiness formula.
 */
export function buildGeneratedReportRecord({ ctx, parsed, world, readiness, now, id, readinessSource }) {
  const bounds = reportPeriodBounds(parsed.period, now);
  if (parsed.targetIds) {
    const found = new Map(asArray(world.found_targets).map((row) => [row.id, row]));
    const missing = parsed.targetIds.filter((targetId) => !found.has(targetId));
    if (missing.length > 0) return scopeFailure('unknown_target', { target_ids: missing });
    const inactive = parsed.targetIds.filter((targetId) => !isActiveTarget(found.get(targetId)));
    if (inactive.length > 0) return scopeFailure('inactive_target', { target_ids: inactive });
  }
  if (parsed.targetGroupIds) {
    const found = new Map(asArray(world.found_groups).map((row) => [row.id, row]));
    const missing = parsed.targetGroupIds.filter((groupId) => !found.has(groupId));
    if (missing.length > 0) return scopeFailure('unknown_target_group', { target_group_ids: missing });
    const inactive = parsed.targetGroupIds.filter((groupId) => !isActiveGroup(found.get(groupId)));
    if (inactive.length > 0) return scopeFailure('inactive_target_group', { target_group_ids: inactive });
  }
  if (parsed.targetIds && parsed.targetGroupIds) {
    const found = new Map(asArray(world.found_targets).map((row) => [row.id, row]));
    const groupSet = new Set(parsed.targetGroupIds);
    const mismatched = parsed.targetIds.filter((targetId) => !groupSet.has(found.get(targetId)?.target_group_id));
    if (mismatched.length > 0) {
      return scopeFailure('scope_mismatch', { reason: 'target_not_in_group', target_ids: mismatched });
    }
    const seenGroups = new Set(parsed.targetIds.map((targetId) => found.get(targetId)?.target_group_id));
    const emptyGroups = parsed.targetGroupIds.filter((groupId) => !seenGroups.has(groupId));
    if (emptyGroups.length > 0) {
      return scopeFailure('scope_mismatch', { reason: 'group_has_no_requested_target', target_group_ids: emptyGroups });
    }
  }
  if ((parsed.targetIds || parsed.targetGroupIds) && (world.member_total ?? 0) > MAX_DECLARED_MEMBERS) {
    return scopeFailure('scope_too_large', {
      field: 'declared_members',
      limit: MAX_DECLARED_MEMBERS,
      count: world.member_total,
    });
  }

  let includedRuns;
  if (parsed.runIds) {
    const found = new Map(asArray(world.found_runs).map((row) => [row.id, row]));
    const missing = parsed.runIds.filter((runId) => !found.has(runId));
    if (missing.length > 0) return scopeFailure('unknown_run', { run_ids: missing });
    const memberIds = parsed.targetIds
      ? new Set(parsed.targetIds)
      : parsed.targetGroupIds
        ? new Set(asArray(world.members).map((row) => row.id))
        : null;
    const groupIds = parsed.targetGroupIds ? new Set(parsed.targetGroupIds) : null;
    const outside = [];
    const untimed = [];
    const outsidePeriod = [];
    for (const runId of parsed.runIds) {
      const run = found.get(runId);
      const targetMiss = memberIds ? !memberIds.has(run.target_id) : false;
      const groupMiss = groupIds ? !groupIds.has(run.target_group_id) : false;
      if (targetMiss || groupMiss) outside.push(runId);
      const periodHit = withinPeriod(runInstantMs(run), bounds);
      if (periodHit === null) untimed.push(runId);
      else if (periodHit === false) outsidePeriod.push(runId);
    }
    if (outside.length > 0) return scopeFailure('run_outside_scope', { run_ids: outside });
    if (untimed.length > 0) return scopeFailure('run_time_not_recorded', { run_ids: untimed });
    if (outsidePeriod.length > 0) return scopeFailure('run_outside_period', { run_ids: outsidePeriod });
    includedRuns = parsed.runIds.map((runId) => found.get(runId));
  } else {
    includedRuns = asArray(world.runs);
  }

  const findingItems = asArray(world.findings).slice(0, MAX_SNAPSHOT_FINDINGS).map(snapshotFinding);
  const evidenceItems = asArray(world.evidence).slice(0, MAX_SNAPSHOT_EVIDENCE).map(snapshotEvidence);
  const verdictItems = orderedVerdicts(includedRuns, world.verdicts).map(snapshotVerdict);
  const runItems = includedRuns.map(snapshotRun);
  const runIdList = runItems.map((run) => run.id);

  const evidenceIds = [];
  const seenEvidence = new Set();
  for (const verdict of verdictItems) {
    for (const evidenceId of verdict.evidence_ids ?? []) {
      if (seenEvidence.has(evidenceId)) continue;
      seenEvidence.add(evidenceId);
      evidenceIds.push(evidenceId);
    }
  }
  for (const finding of findingItems) {
    for (const evidenceId of finding.evidence_ids ?? []) {
      if (seenEvidence.has(evidenceId)) continue;
      seenEvidence.add(evidenceId);
      evidenceIds.push(evidenceId);
    }
  }

  const checkIds = [];
  const seenChecks = new Set();
  for (const row of [...runItems, ...findingItems]) {
    if (!row.check_id || seenChecks.has(row.check_id)) continue;
    seenChecks.add(row.check_id);
    checkIds.push(row.check_id);
  }

  let mode = 'tenant';
  if (parsed.targetIds && parsed.targetGroupIds) mode = 'targets_and_groups';
  else if (parsed.targetIds) mode = 'targets';
  else if (parsed.targetGroupIds) mode = 'target_groups';
  else if (parsed.runIds) mode = 'runs';

  const memberRows = parsed.targetIds
    ? parsed.targetIds.map((targetId) => asArray(world.members).find((row) => row.id === targetId)).filter(Boolean)
    : asArray(world.members).slice(0, MAX_DECLARED_MEMBERS);
  const memberCounts = countGap(world.member_total, memberRows.length);
  const runCounts = parsed.runIds
    ? { total: parsed.runIds.length, included: runIdList.length, excluded: 0, total_status: 'complete' }
    : countGap(world.run_total, runIdList.length);
  const findingCounts = countGap(world.finding_total, findingItems.length);
  const evidenceCounts = countGap(world.evidence_total, evidenceItems.length);
  const periodExcluded = world.run_total == null || world.run_total_unwindowed == null
    ? null
    : Math.max(0, world.run_total_unwindowed - world.run_total);

  const published = !parsed.explicit
    && readiness
    && typeof readiness.score === 'number'
    && Array.isArray(readiness.factors);
  const readinessFactors = parsed.explicit
    ? []
    : (readiness?.factors ?? []);

  const declarationStatus = world.member_total == null
    ? 'not_included'
    : memberCounts.excluded > 0
      ? 'partial'
      : 'included';

  const groupFound = new Map(asArray(world.found_groups).map((row) => [row.id, row]));
  const summary = {
    readiness_score: published ? readiness.score : null,
    readiness_factors: readinessFactors,
    readiness_score_status: published ? 'published' : 'unknown',
    readiness_score_scope: parsed.explicit ? 'not_target_scoped' : 'tenant',
    readiness_score_source: published
      ? (readinessSource ?? 'published_tenant_formula')
      : (parsed.explicit ? 'not_applied' : (readinessSource ?? 'not_recorded')),
    readiness_score_reason: published
      ? null
      : (parsed.explicit
        ? 'published_readiness_formula_is_tenant_wide'
        : (readiness?.factors?.status ?? 'readiness_unavailable')),
    open_findings: world.open_finding_total ?? 0,
    open_findings_semantics: {
      total: world.open_finding_total ?? null,
      predicate: "status = 'open' inside scope and period",
      source: 'findings.status_at_generation',
      total_status: world.open_finding_total == null ? 'unknown' : 'complete',
    },
    recent_runs: runItems.map((run) => ({ id: run.id, status: run.status, check_id: run.check_id })),
    compliance: buildReportComplianceSummary(parsed.kind),
    period: parsed.period,
    as_of: now,
    as_of_source: 'report_generation_clock',
    snapshot_frozen: world.legacy !== true,
    primary_run_id: null,
    primary_target_id: null,
    run_ids: runIdList,
    check_ids: checkIds,
    evidence_ids: evidenceIds,
    scope: {
      mode,
      selection: parsed.explicit ? 'explicit' : 'omitted_defaults_to_tenant',
      target_ids: parsed.targetIds ?? [],
      target_group_ids: parsed.targetGroupIds ?? [],
      declared_member_ids: memberRows.map((row) => row.id),
      declared_members: { ...memberCounts, source: 'active_declared_targets', complete: memberCounts.total_status === 'complete' && memberCounts.excluded === 0 },
      group_refs: parsed.targetGroupIds
        ? parsed.targetGroupIds.map((groupId) => ({ id: groupId, name: plainText(groupFound.get(groupId)?.name) }))
        : [],
      primary_target_id: null,
      primary_run_id: null,
      period: bounds,
    },
    run_capture: {
      mode: parsed.runIds ? 'explicit' : 'bounded_recent',
      ordered_by: parsed.runIds ? 'request' : 'started_at_or_created_at_desc_id_desc',
      primary_run_id: null,
      limit: parsed.runIds ? null : MAX_CAPTURED_RUNS,
      ...runCounts,
      excluded_by_period: parsed.runIds ? 0 : periodExcluded,
      source: 'test_runs.started_at_or_created_at',
    },
    runs_snapshot: runItems,
    verdicts_snapshot: verdictItems,
    findings_snapshot: {
      as_of: now,
      source: 'findings_at_generation',
      lifecycle: 'status_at_generation',
      predicate: parsed.runIds ? 'scope_and_explicit_run_ids_and_period' : 'scope_and_period',
      ...findingCounts,
      excluded_by_period: world.finding_total == null || world.finding_total_unwindowed == null
        ? null
        : Math.max(0, world.finding_total_unwindowed - world.finding_total),
      open_total: world.open_finding_total ?? null,
      complete: findingCounts.total_status === 'complete' && findingCounts.excluded === 0,
      items: findingItems,
    },
    evidence_summaries: {
      source: 'evidence_vault_without_metadata',
      ...evidenceCounts,
      complete: evidenceCounts.total_status === 'complete' && evidenceCounts.excluded === 0,
      items: evidenceItems,
    },
    declaration_snapshot: {
      status: declarationStatus,
      source: declarationStatus === 'not_included' ? 'not_loaded' : 'declaration_json',
      reason: declarationStatus === 'not_included' ? 'declared_members_not_loaded' : null,
      ...memberCounts,
      items: declarationStatus === 'not_included' ? [] : memberRows.map(declarationItem),
    },
    sections: {
      period: bounds.status === 'not_recorded'
        ? { status: 'not_included', reason: 'period_not_recorded' }
        : { status: 'included', label: bounds.label, start: bounds.start, end: bounds.end, source: bounds.source },
      readiness_factors: published
        ? { status: 'included', source: readinessSource ?? 'published_tenant_formula', scope: 'tenant' }
        : {
          status: 'not_included',
          reason: parsed.explicit ? 'published_readiness_formula_is_tenant_wide' : (readiness?.factors?.status ?? 'readiness_unavailable'),
        },
      declaration: {
        status: declarationStatus === 'included' ? 'included' : 'not_included',
        reason: declarationStatus === 'included' ? null : declarationStatus,
      },
      protection_profile: {
        status: 'not_included',
        reason: 'no_frozen_protection_profile_on_declared_target',
      },
      findings: findingCounts.total_status === 'unknown'
        ? { status: 'not_included', reason: 'finding_total_unknown' }
        : { status: findingCounts.excluded > 0 ? 'partial' : 'included', source: 'findings_at_generation' },
    },
  };

  return {
    ok: true,
    record: {
      id,
      tenant_id: ctx.tenantId,
      kind: parsed.kind,
      title: parsed.title,
      status: 'ready',
      period: parsed.period,
      summary,
      run_ids: runIdList,
      created_at: now,
      created_by: ctx.userId,
    },
  };
}

/** Frozen snapshots export themselves. Older reports keep the live run/verdict lookup. */
export function reportExportSources(report) {
  const summary = report?.summary;
  if (summary?.snapshot_frozen === true && Array.isArray(summary.runs_snapshot) && Array.isArray(summary.verdicts_snapshot)) {
    return { frozen: true, runs: summary.runs_snapshot, verdicts: summary.verdicts_snapshot };
  }
  return { frozen: false, runs: null, verdicts: null };
}

export function readinessExportText(summary) {
  if (summary?.readiness_score_status === 'unknown') {
    return `Not included (${summary.readiness_score_reason ?? 'unknown'})`;
  }
  if (summary?.readiness_score == null) return 'n/a';
  return String(summary.readiness_score);
}
