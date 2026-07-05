import type { DataItem } from './types';

const EVIDENCE_RUN_STATUSES = new Set(['completed', 'verdicted']);

function getString(item: DataItem, keys: string[], fallback = '') {
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

export function isActiveTargetGroup(group: DataItem) {
  return group.archived_at == null;
}

export type EnvironmentReadinessRow = {
  id: string;
  groups: DataItem[];
  /** Active declared target groups in this environment. */
  groupCount: number;
  completedRuns: number;
  groupsWithEvidence: number;
  openFindings: number;
  coverage: number;
  state: 'covered' | 'partial evidence' | 'needs evidence';
};

/** Derive environment readiness cards from active target groups, runs, and findings. */
export function buildEnvironmentReadinessRows(input: {
  targetGroups: DataItem[];
  runs: DataItem[];
  findings: DataItem[];
}): EnvironmentReadinessRow[] {
  const activeGroups = input.targetGroups.filter(isActiveTargetGroup);

  return [...activeGroups.reduce((map, group) => {
    const environmentId = getString(group, ['environment_id'], 'unassigned');
    const current = map.get(environmentId) ?? { id: environmentId, groups: [] as DataItem[] };
    current.groups.push(group);
    map.set(environmentId, current);
    return map;
  }, new Map<string, { id: string; groups: DataItem[] }>()).values()]
    .map((environment) => {
      const groupIds = new Set(environment.groups.map((group) => getString(group, ['id'], '')));
      const completedRuns = input.runs.filter((run) => {
        const status = getString(run, ['status'], '');
        return groupIds.has(getString(run, ['target_group_id'], '')) && EVIDENCE_RUN_STATUSES.has(status);
      }).length;
      const groupsWithEvidence = environment.groups.filter((group) => {
        const groupId = getString(group, ['id'], '');
        return input.runs.some((run) =>
          getString(run, ['target_group_id'], '') === groupId &&
          EVIDENCE_RUN_STATUSES.has(getString(run, ['status'], ''))
        );
      }).length;
      const openFindings = input.findings.filter((finding) =>
        groupIds.has(getString(finding, ['target_group_id'], '')) &&
        getString(finding, ['status'], 'open') === 'open'
      ).length;
      const coverage = environment.groups.length
        ? Math.round((groupsWithEvidence / environment.groups.length) * 100)
        : 0;
      const state: EnvironmentReadinessRow['state'] = coverage === 100 && openFindings === 0
        ? 'covered'
        : coverage > 0
          ? 'partial evidence'
          : 'needs evidence';
      return {
        ...environment,
        groupCount: environment.groups.length,
        completedRuns,
        groupsWithEvidence,
        openFindings,
        coverage,
        state
      };
    })
    .sort((left, right) => left.id.localeCompare(right.id));
}