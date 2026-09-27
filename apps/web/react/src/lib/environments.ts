import { isFindingOpen } from './finding-lifecycle.mjs';
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

export type EnvironmentReadinessRow = {
  id: string;
  environment: DataItem;
  name: string;
  lifecycleStatus: string;
  timezone: string;
  groups: DataItem[];
  /** Active declared target groups in this authoritative environment. */
  groupCount: number;
  evidenceBackedRuns: number;
  groupsWithEvidence: number;
  openFindings: number;
  coverage: number;
  latestEvidenceAt: string;
  state: 'covered' | 'partial evidence' | 'needs evidence';
};

/** Join authoritative environments to exact active-group, verdict, evidence, and finding records. */
export function buildEnvironmentReadinessRows(input: {
  environments: DataItem[];
  targetGroups: DataItem[];
  runs: DataItem[];
  findings: DataItem[];
  evidence: DataItem[];
}): EnvironmentReadinessRow[] {
  const activeGroups = input.targetGroups.filter(isActiveTargetGroup);

  return input.environments
    .map((environment) => {
      const id = getString(environment, ['id'], '');
      const groups = activeGroups.filter((group) => getString(group, ['environment_id'], '') === id);
      const groupIds = new Set(groups.map((group) => getString(group, ['id'], '')).filter(Boolean));
      const evidenceBackedRuns = input.runs.filter((run) =>
        groupIds.has(getString(run, ['target_group_id'], '')) &&
        hasEvidenceBackedVerdict(run, input.evidence)
      );
      const groupsWithEvidence = new Set(
        evidenceBackedRuns.map((run) => getString(run, ['target_group_id'], '')).filter(Boolean)
      ).size;
      const openFindings = input.findings.filter((finding) =>
        groupIds.has(getString(finding, ['target_group_id'], '')) && isFindingOpen(finding)
      ).length;
      const coverage = groups.length
        ? Math.round((groupsWithEvidence / groups.length) * 100)
        : 0;
      const state: EnvironmentReadinessRow['state'] = coverage === 100 && openFindings === 0
        ? 'covered'
        : coverage > 0
          ? 'partial evidence'
          : 'needs evidence';
      const latestEvidenceAt = evidenceBackedRuns.reduce((latest, run) => {
        const stamp = String(run.completed_at ?? run.verdicted_at ?? run.updated_at ?? run.created_at ?? '');
        return stamp > latest ? stamp : latest;
      }, '');

      return {
        id,
        environment,
        name: getString(environment, ['name'], id || 'Unnamed environment'),
        lifecycleStatus: getString(environment, ['status'], 'unknown'),
        timezone: getString(environment, ['timezone'], 'not recorded'),
        groups,
        groupCount: groups.length,
        evidenceBackedRuns: evidenceBackedRuns.length,
        groupsWithEvidence,
        openFindings,
        coverage,
        latestEvidenceAt,
        state
      };
    })
    .filter((row) => Boolean(row.id))
    .sort((left, right) => left.name.localeCompare(right.name) || left.id.localeCompare(right.id));
}
