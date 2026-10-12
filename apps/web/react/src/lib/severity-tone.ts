import type { StatusTone } from './status-tone';

const SEVERITY_TONE: Record<string, StatusTone> = {
  critical: 'danger',
  s1: 'danger',
  high: 'danger',
  s2: 'danger',
  medium: 'warn',
  moderate: 'warn',
  s3: 'warn',
  low: 'muted',
  s4: 'muted',
  info: 'muted'
};

/** One finding-severity badge tone for every surface; orange stays brand-only. */
export function severityTone(severity: string | null | undefined): StatusTone {
  return SEVERITY_TONE[String(severity ?? '').trim().toLowerCase()] ?? 'muted';
}

/** A severity count chip: muted when nothing is open at that severity. */
export function severityCountTone(severity: string, count: number): StatusTone {
  return count > 0 ? severityTone(severity) : 'muted';
}
