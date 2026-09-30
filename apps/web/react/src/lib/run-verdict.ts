import type { DataItem } from './types';

const NON_PUBLISHED_VERDICTS = new Set([
  '',
  'none',
  'unknown',
  'pending',
  'planned',
  'queued',
  'running',
  'collecting'
]);

function getString(item: DataItem, keys: string[], fallback = '') {
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function getStringArray(item: DataItem, key: string) {
  const value = item[key];
  return Array.isArray(value)
    ? value.map((entry) => String(entry ?? '').trim()).filter(Boolean)
    : [];
}

export function isActiveTargetGroup(group: DataItem) {
  return group.archived_at == null;
}

/** Return a verdict only when the run carries an explicit, non-pending verdict value. */
export function publishedRunVerdict(run: DataItem) {
  const raw = run.verdict;
  const value = typeof raw === 'string'
    ? raw
    : raw && typeof raw === 'object' && !Array.isArray(raw)
      ? getString(raw as DataItem, ['verdict', 'result'], '')
      : '';
  const normalized = value.trim().toLowerCase();
  return NON_PUBLISHED_VERDICTS.has(normalized) ? '' : value.trim();
}

/**
 * A terminal run status is not evidence. Readiness credit requires both an explicit
 * published verdict and evidence bound either by the verdict or the evidence vault.
 */
export function hasEvidenceBackedVerdict(run: DataItem, evidence: DataItem[]) {
  if (!publishedRunVerdict(run)) return false;
  const rawVerdict = run.verdict;
  if (getStringArray(run, 'evidence_ids').length > 0) return true;
  if (rawVerdict && typeof rawVerdict === 'object' && !Array.isArray(rawVerdict)) {
    if (getStringArray(rawVerdict as DataItem, 'evidence_ids').length > 0) return true;
  }
  const runId = getString(run, ['id', 'test_run_id'], '');
  return Boolean(runId) && evidence.some((record) => getString(record, ['test_run_id'], '') === runId);
}
