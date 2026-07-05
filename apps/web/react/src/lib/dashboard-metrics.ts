import type { DataItem, PortalData } from './types';

function getString(item: DataItem, keys: string[], fallback = '') {
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

export function countActiveTargetGroups(targetGroups: DataItem[]) {
  return targetGroups.filter((group) => group.archived_at == null).length;
}

export function countAgentsOnline(agents: DataItem[]) {
  return agents.filter((agent) => getString(agent, ['status']) === 'online').length;
}

export function countOpenFindings(findings: DataItem[]) {
  return findings.filter((finding) => getString(finding, ['status'], 'open') === 'open').length;
}

export function countHighScaleRequests(highScale: DataItem[]) {
  return highScale.length;
}

export type DashboardMetrics = {
  targetGroups: number;
  agentsOnline: number;
  openFindings: number;
  highScaleRequests: number;
};

/** Prefer `/v1/state` fields; fall back to list APIs with the same semantics as `src/services/state.mjs`. */
export function resolveDashboardMetrics(data: PortalData): DashboardMetrics {
  return {
    targetGroups: data.state?.target_groups ?? countActiveTargetGroups(data.targetGroups),
    agentsOnline: data.state?.agents_online ?? countAgentsOnline(data.agents),
    openFindings: data.state?.open_findings ?? countOpenFindings(data.findings),
    highScaleRequests: data.state?.high_scale_requests ?? countHighScaleRequests(data.highScale)
  };
}

export function resolveRecentRuns(data: PortalData, limit = 5) {
  const fromState = Array.isArray(data.state?.recent_runs) ? data.state.recent_runs : null;
  const source = fromState ?? data.runs;
  return [...source].slice(-limit).reverse();
}