import type { DataItem } from './types';

export type ReportDiffFinding = { id: string; title: string; severity: string; status: string };
export type ReportDiffChange = ReportDiffFinding & { from: string; to: string };
export type ReportFactorChange = { key: string; label: string; from: number | null; to: number | null };

export type ReportReadinessDiff =
  | { compared: true; from: number; to: number; delta: number; factors: ReportFactorChange[] }
  | { compared: false; reason: string };

export type ReportDiff =
  | { status: 'not_compared'; reason: string }
  | {
    status: 'compared';
    baselineId: string;
    added: ReportDiffFinding[];
    removed: ReportDiffFinding[];
    statusChanged: Array<ReportDiffChange & { acceptedRisk: boolean }>;
    severityChanged: ReportDiffChange[];
    unchanged: number;
    readiness: ReportReadinessDiff;
  };

const ACCEPTED_RISK_STATUSES = new Set(['accepted_risk', 'accepted']);

function record(value: unknown): DataItem | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as DataItem : null;
}

function text(value: unknown) {
  return value === null || value === undefined ? '' : String(value).trim();
}

function summaryOf(report: DataItem | null | undefined) {
  return record(report?.summary);
}

function findingsSnapshotOf(report: DataItem | null | undefined) {
  return record(summaryOf(report)?.findings_snapshot);
}

/** Generation instant used to order snapshots: summary.as_of, then generated_at, then created_at. */
export function reportAsOf(report: DataItem | null | undefined) {
  const summary = summaryOf(report);
  const raw = text(summary?.as_of) || text(summary?.generated_at) || text(report?.created_at);
  const ms = raw ? new Date(raw).getTime() : NaN;
  return Number.isFinite(ms) ? ms : NaN;
}

function sortedIds(value: unknown) {
  return Array.isArray(value) ? value.map(text).filter(Boolean).sort() : [];
}

/** Scope identity: mode plus sorted target IDs and target group IDs; '' when no scope was recorded. */
export function reportScopeKey(report: DataItem | null | undefined) {
  const scope = record(summaryOf(report)?.scope);
  if (!scope) return '';
  const mode = text(scope.mode);
  if (!mode) return '';
  return `${mode}|${sortedIds(scope.target_ids).join(',')}|${sortedIds(scope.target_group_ids).join(',')}`;
}

/** Earlier reports of the same kind and scope, newest first. */
export function eligibleBaselines(current: DataItem, reports: DataItem[]) {
  const currentId = text(current.id);
  const kind = text(current.kind);
  const scopeKey = reportScopeKey(current);
  const asOf = reportAsOf(current);
  if (!scopeKey || !Number.isFinite(asOf)) return [];
  return reports
    .filter((report) => text(report.id) !== currentId
      && text(report.kind) === kind
      && reportScopeKey(report) === scopeKey
      && reportAsOf(report) < asOf)
    .sort((left, right) => reportAsOf(right) - reportAsOf(left));
}

export function defaultBaseline(current: DataItem, reports: DataItem[]) {
  return eligibleBaselines(current, reports)[0] ?? null;
}

function snapshotItems(report: DataItem) {
  const items = findingsSnapshotOf(report)?.items;
  const rows = Array.isArray(items) ? items.map(record).filter((item): item is DataItem => Boolean(item && text(item.id))) : [];
  return new Map(rows.map((item) => [text(item.id), {
    id: text(item.id),
    title: text(item.title),
    severity: text(item.severity),
    status: text(item.status)
  }]));
}

function publishedScore(report: DataItem) {
  const summary = summaryOf(report);
  if (text(summary?.readiness_score_status) !== 'published') return null;
  const score = summary?.readiness_score;
  return typeof score === 'number' && Number.isFinite(score) ? score : null;
}

function factorScores(report: DataItem) {
  const factors = summaryOf(report)?.readiness_factors;
  const rows = Array.isArray(factors) ? factors.map(record).filter((factor): factor is DataItem => Boolean(factor)) : [];
  return new Map(rows.map((factor) => {
    const key = text(factor.key) || text(factor.label);
    const score = typeof factor.score === 'number' && Number.isFinite(factor.score) ? factor.score : null;
    return [key, { label: text(factor.label) || key, score }];
  }).filter(([key]) => Boolean(key)) as Array<[string, { label: string; score: number | null }]>);
}

function compareReadiness(current: DataItem, baseline: DataItem): ReportReadinessDiff {
  const to = publishedScore(current);
  const from = publishedScore(baseline);
  if (to === null || from === null) {
    return { compared: false, reason: 'Readiness is compared only when both reports published a readiness score.' };
  }
  const currentFactors = factorScores(current);
  const baselineFactors = factorScores(baseline);
  const keys = [...new Set([...baselineFactors.keys(), ...currentFactors.keys()])];
  const factors = keys
    .map((key) => ({
      key,
      label: currentFactors.get(key)?.label ?? baselineFactors.get(key)?.label ?? key,
      from: baselineFactors.get(key)?.score ?? null,
      to: currentFactors.get(key)?.score ?? null
    }))
    .filter((factor) => factor.from !== factor.to);
  return { compared: true, from, to, delta: to - from, factors };
}

/** Difference between two stored report snapshots; refuses rather than guessing when either is incomplete. */
export function diffReports(current: DataItem, baseline: DataItem | null | undefined): ReportDiff {
  if (!baseline) {
    return { status: 'not_compared', reason: 'No earlier report with the same kind and scope is available.' };
  }
  if (summaryOf(current)?.snapshot_frozen !== true || summaryOf(baseline)?.snapshot_frozen !== true) {
    return { status: 'not_compared', reason: 'One of the reports is a legacy report whose inputs were not frozen at generation.' };
  }
  if (findingsSnapshotOf(current)?.complete !== true || findingsSnapshotOf(baseline)?.complete !== true) {
    return { status: 'not_compared', reason: 'One of the reports captured only part of its findings, so a missing finding cannot be told apart from a truncated list.' };
  }
  const now = snapshotItems(current);
  const before = snapshotItems(baseline);
  const added: ReportDiffFinding[] = [];
  const removed: ReportDiffFinding[] = [];
  const statusChanged: Array<ReportDiffChange & { acceptedRisk: boolean }> = [];
  const severityChanged: ReportDiffChange[] = [];
  let unchanged = 0;
  for (const [id, item] of now) {
    const prior = before.get(id);
    if (!prior) {
      added.push(item);
      continue;
    }
    let changed = false;
    if (prior.status !== item.status) {
      statusChanged.push({ ...item, from: prior.status, to: item.status, acceptedRisk: ACCEPTED_RISK_STATUSES.has(item.status) && !ACCEPTED_RISK_STATUSES.has(prior.status) });
      changed = true;
    }
    if (prior.severity !== item.severity) {
      severityChanged.push({ ...item, from: prior.severity, to: item.severity });
      changed = true;
    }
    if (!changed) unchanged += 1;
  }
  for (const [id, item] of before) {
    if (!now.has(id)) removed.push(item);
  }
  return {
    status: 'compared',
    baselineId: text(baseline.id),
    added,
    removed,
    statusChanged,
    severityChanged,
    unchanged,
    readiness: compareReadiness(current, baseline)
  };
}
