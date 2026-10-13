import type { DataItem, ReadinessPostureSegment, StatePayload } from './types';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

type PostureKey = ReadinessPostureSegment['key'];

function classifyRunVerdict(verdict: string): 'pass' | 'review' | 'gap' | null {
  const key = verdict.trim().toLowerCase();
  if (['pass', 'passed', 'protected', 'success', 'ok'].includes(key)) return 'pass';
  if (['review', 'warn', 'warning', 'inconclusive', 'underprotected', 'edge_protected', 'stale', 'partial'].includes(key)) return 'review';
  if (['gap', 'fail', 'failed', 'danger', 'penetrated', 'bypassable', 'unprotected', 'exposed', 'edge_exposed'].includes(key)) return 'gap';
  return null;
}

function finiteCount(value: unknown): number | null {
  const count = Number(value);
  return Number.isFinite(count) && count >= 0 ? count : null;
}

export function resolveReadinessPostureSegments(
  state: StatePayload | null,
  runs: DataItem[],
  _checks: DataItem[]
): { segments: ReadinessPostureSegment[]; total: number; score: number | null; delta: number | null } {
  const posture = state?.readiness?.posture as (Record<string, unknown> | undefined);
  const score = typeof state?.readiness?.score === 'number' ? state.readiness.score : null;
  const delta = typeof state?.readiness?.delta === 'number' ? state.readiness.delta : null;

  if (posture && typeof posture === 'object') {
    const pass = finiteCount(posture.pass) ?? 0;
    const review = finiteCount(posture.review) ?? 0;
    const gap = finiteCount(posture.gap) ?? 0;
    const total = finiteCount(posture.total) ?? pass + review + gap;
    const notRun = finiteCount(posture.not_run) ?? Math.max(0, total - pass - review - gap);
    if (total > 0) {
      return { score, delta, total, segments: buildSegments(pass, review, gap, notRun, total) };
    }
  }

  const latestByCheck = new Map<string, { verdict: string; at: string }>();
  for (const run of runs) {
    const checkId = getString(run, ['check_id'], '');
    if (!checkId) continue;
    const status = getString(run, ['status'], '');
    if (!['completed', 'verdicted'].includes(status)) continue;
    const verdict = getString(run, ['verdict'], getNestedVerdict(run));
    if (!verdict) continue;
    const at = String(run.updated_at ?? run.completed_at ?? run.created_at ?? '');
    const prev = latestByCheck.get(checkId);
    if (!prev || at.localeCompare(prev.at) >= 0) latestByCheck.set(checkId, { verdict, at });
  }

  let pass = 0;
  let review = 0;
  let gap = 0;
  for (const { verdict } of latestByCheck.values()) {
    const bucket = classifyRunVerdict(verdict);
    if (bucket === 'pass') pass += 1;
    else if (bucket === 'review') review += 1;
    else if (bucket === 'gap') gap += 1;
  }

  const total = pass + review + gap;
  return { score, delta, total, segments: buildSegments(pass, review, gap, null, total) };
}

function getNestedVerdict(run: DataItem) {
  const verdict = run.verdict;
  if (!verdict || typeof verdict !== 'object' || Array.isArray(verdict)) return '';
  return getString(verdict as DataItem, ['verdict', 'status'], '');
}

function buildSegments(pass: number, review: number, gap: number, notRun: number | null, total: number): ReadinessPostureSegment[] {
  const safeTotal = total > 0 ? total : 1;
  const segment = (key: PostureKey, label: string, count: number): ReadinessPostureSegment => ({ key, label, count, pct: Math.round((count / safeTotal) * 100) });
  const results = [segment('pass', 'Pass', pass), segment('review', 'Review', review), segment('gap', 'Gap', gap)];
  return notRun === null ? results : [...results, segment('not_run', 'Not run', notRun)];
}

const SEGMENT_SEPARATOR_PCT = 0.6;

export const NOT_RUN_SEGMENT_COLOR = 'color-mix(in oklab, var(--bg), var(--fg) 22%)';

export const POSTURE_SEGMENT_COLORS: Record<PostureKey, string> = {
  pass: 'var(--success)',
  review: 'var(--warn)',
  gap: 'var(--danger)',
  not_run: NOT_RUN_SEGMENT_COLOR
};

/**
 * Ring arcs are proportional to the real pass/review/gap/not-run counts (docs/ux/14 §7.4).
 * Not-run scenarios are a muted neutral, never amber: an unexecuted check is not a review result.
 */
export function buildConicGradient(segments: ReadinessPostureSegment[]) {
  const colorByKey = POSTURE_SEGMENT_COLORS;
  const track = 'color-mix(in oklab, var(--bg), var(--fg) 6%)';

  const present = segments.filter((segment) => segment.count > 0);
  const total = present.reduce((sum, segment) => sum + segment.count, 0);
  if (total <= 0) {
    return `conic-gradient(from -90deg, ${track} 0% 100%)`;
  }

  const separators = present.length - 1;
  const arcBudget = 100 - separators * SEGMENT_SEPARATOR_PCT;
  const at = (value: number) => `${Math.round(value * 100) / 100}%`;
  let cursor = 0;
  const stops: string[] = [];

  present.forEach((segment, index) => {
    const isLast = index === present.length - 1;
    const end = isLast ? 100 : cursor + (segment.count / total) * arcBudget;
    stops.push(`${colorByKey[segment.key]} ${at(cursor)} ${at(end)}`);
    cursor = end;
    if (!isLast) {
      const separatorEnd = cursor + SEGMENT_SEPARATOR_PCT;
      stops.push(`${track} ${at(cursor)} ${at(separatorEnd)}`);
      cursor = separatorEnd;
    }
  });

  return `conic-gradient(from -90deg, ${stops.join(', ')})`;
}