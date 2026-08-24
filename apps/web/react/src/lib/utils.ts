import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * A route the running deployment does not wire (postgres route guard 503).
 * Distinct from a transient outage: it will never succeed in this deployment, so
 * surfaces must report it as a mode limitation and must not offer Retry.
 *
 * Lives here, not in lib/api.ts, so generic UI primitives can recognize it
 * without depending on the API layer.
 */
export const DEPLOYMENT_MODE_GAP_MESSAGE = 'Not available in this deployment mode.';

export function formatNumber(value: unknown, fallback = '0') {
  if (typeof value !== 'number' || !Number.isFinite(value)) return fallback;
  return new Intl.NumberFormat('en-US').format(value);
}

export function formatDate(value: unknown) {
  if (!value) return 'Not recorded';
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

export function asArray<T = Record<string, unknown>>(value: unknown): T[] {
  if (Array.isArray(value)) return value as T[];
  if (value && typeof value === 'object' && Array.isArray((value as { items?: unknown }).items)) {
    return (value as { items: T[] }).items;
  }
  return [];
}

export function scoreTone(score: number) {
  if (score >= 80) return 'success';
  if (score >= 55) return 'warn';
  return 'danger';
}

export function clamp(value: number, min = 0, max = 100) {
  return Math.min(max, Math.max(min, value));
}

const SEVERITY_LABELS: Record<string, string> = {
  s1: 'Severity 1 · Critical',
  s2: 'Severity 2 · High',
  s3: 'Severity 3 · Medium',
  s4: 'Severity 4 · Low',
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info'
};

export function formatSeverityLabel(severity: string, fallback = 'Unknown') {
  const key = severity.trim().toLowerCase();
  if (!key) return fallback;
  return SEVERITY_LABELS[key] ?? severity.replace(/_/g, ' ');
}

export function formatAuditAction(action: string, fallback = 'Unknown action') {
  const key = action.trim();
  if (!key) return fallback;
  return key.replace(/\./g, ' · ').replace(/_/g, ' ');
}

export function formatResourceTypeLabel(resourceType: string, fallback = 'Record') {
  const key = resourceType.trim().toLowerCase();
  if (!key) return fallback;
  return key.replace(/_/g, ' ');
}

const EXPECTED_BEHAVIOR_LABELS: Record<string, string> = {
  must_block_before_origin: 'Must be blocked before origin',
  must_allow_baseline_health: 'Must allow baseline health',
  must_challenge_or_rate_limit: 'Must challenge or rate-limit',
  must_not_expose_direct_ip: 'Must not expose direct IP'
};

export function formatExpectedBehavior(value: string) {
  return EXPECTED_BEHAVIOR_LABELS[value] ?? value.replace(/_/g, ' ');
}

/** Naive English plural for counted nouns; pass `plural` for irregular words. */
export function pluralize(count: number, singular: string, plural?: string) {
  return Math.abs(count) === 1 ? singular : plural ?? `${singular}s`;
}

/** `${count} ${noun}` with the noun agreeing with the count. */
export function countLabel(count: number, singular: string, plural?: string) {
  return `${count} ${pluralize(count, singular, plural)}`;
}

const SECONDS_PER_MINUTE = 60;
const SECONDS_PER_HOUR = 60 * SECONDS_PER_MINUTE;
const SECONDS_PER_DAY = 24 * SECONDS_PER_HOUR;

/**
 * Humanized elapsed time so multi-day spans stay readable: `42s`, `5m 12s`,
 * `2h 05m`, `53d 16h`. Negative or non-finite input yields the shared empty placeholder.
 */
export function formatDurationSeconds(totalSeconds: number, fallback = '—') {
  if (!Number.isFinite(totalSeconds) || totalSeconds < 0) return fallback;
  const whole = Math.round(totalSeconds);
  if (whole < SECONDS_PER_MINUTE) return `${whole}s`;
  if (whole < SECONDS_PER_HOUR) {
    const minutes = Math.floor(whole / SECONDS_PER_MINUTE);
    return `${minutes}m ${String(whole % SECONDS_PER_MINUTE).padStart(2, '0')}s`;
  }
  if (whole < SECONDS_PER_DAY) {
    const hours = Math.floor(whole / SECONDS_PER_HOUR);
    const minutes = Math.floor((whole % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE);
    return `${hours}h ${String(minutes).padStart(2, '0')}m`;
  }
  const days = Math.floor(whole / SECONDS_PER_DAY);
  const hours = Math.floor((whole % SECONDS_PER_DAY) / SECONDS_PER_HOUR);
  return `${days}d ${hours}h`;
}

/**
 * Elapsed wall-clock time of one run row, humanized by `formatDurationSeconds`.
 * Shared by the runs table and target-detail runs panel so both read identically.
 */
export function formatRunDuration(run: Record<string, unknown>, fallback = '—') {
  const start = Date.parse(String(run.started_at ?? run.created_at ?? ''));
  const end = Date.parse(String(run.completed_at ?? run.finalized_at ?? run.updated_at ?? ''));
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return fallback;
  return formatDurationSeconds((end - start) / 1000, fallback);
}
