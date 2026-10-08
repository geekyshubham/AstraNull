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
  const date = new Date(typeof value === 'number' ? value : String(value));
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

const AUDIT_ACTION_LABELS: Record<string, string> = {
  'rbac.denied': 'Access denied (missing permission)',
  'auth.login.succeeded': 'Signed in',
  'auth.login.failed': 'Sign-in failed',
  'auth.password.set': 'Password set',
  'auth.password.invite_issued': 'Password invite issued',
  'test_run.started': 'Validation run started',
  'test_run.cancelled': 'Validation run cancelled',
  'test_run.verdicted': 'Validation result published',
  'kill_switch.activated': 'Emergency stop activated',
  'kill_switch.deactivated': 'Emergency stop cleared',
};

const RESOURCE_TYPE_LABELS: Record<string, string> = {
  api: 'Access control',
  test_run: 'Validation run',
  target_group: 'Retained execution policy',
  high_scale_request: 'SOC-governed test',
  waf_offensive_request: 'SOC-governed WAF test',
  service_account: 'Service account',
};

const LABEL_ACRONYMS = new Set(['waf', 'soc', 'api', 'dns', 'tls', 'loa', 'mfa', 'oidc', 'cve', 'ip', 'cdn', 'sla', 'rbac']);

function sentenceCase(value: string) {
  const words = value.replace(/[._]+/g, ' ').replace(/\s+/g, ' ').trim()
    .split(' ')
    .map((word) => (LABEL_ACRONYMS.has(word.toLowerCase()) ? word.toUpperCase() : word))
    .join(' ');
  return words ? `${words[0].toUpperCase()}${words.slice(1)}` : words;
}

export function formatAuditAction(action: string, fallback = 'Unknown action') {
  const key = action.trim();
  if (!key) return fallback;
  return AUDIT_ACTION_LABELS[key.toLowerCase()] ?? sentenceCase(key.replace(/^target_group(?=[.:_]|$)/, 'target_policy'));
}

export function formatResourceTypeLabel(resourceType: string, fallback = 'Record') {
  const key = resourceType.trim().toLowerCase();
  if (!key) return fallback;
  return RESOURCE_TYPE_LABELS[key] ?? sentenceCase(key);
}

// Security follow-up: credential resource ids (password invites, reset tokens, sessions) are
// secrets-adjacent. Operators need to know the action happened, not the raw handle, so the audit
// UI shows this friendly label and keeps the id only in a tooltip. Targets/runs/findings stay
// verbatim because operators pivot on them. Returns null for non-sensitive resource types.
const SENSITIVE_RESOURCE_LABELS: Record<string, string> = {
  user_password_invite: 'Password invite',
  user_password_reset: 'Password reset',
  password_invite: 'Password invite',
  password_reset: 'Password reset',
  session: 'Session',
  user_session: 'Session'
};

export function sensitiveResourceLabel(resourceType: string): string | null {
  return SENSITIVE_RESOURCE_LABELS[resourceType.trim().toLowerCase()] ?? null;
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
  return `${formatNumber(count)} ${pluralize(count, singular, plural)}`;
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

/** Trigger a client-side download of a JSON payload (evidence artifact export with custody manifest). */
export function triggerJsonDownload(filename: string, payload: unknown) {
  triggerTextDownload(filename, JSON.stringify(payload, null, 2), 'application/json');
}

/** Trigger a client-side download of already-serialized content (report Markdown/HTML exports). */
export function triggerTextDownload(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
