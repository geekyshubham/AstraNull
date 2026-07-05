import type { DataItem } from './types';

const PLACEMENT_STATUS_COPY: Record<string, { label: string; hint: string }> = {
  proven: {
    label: 'Ready',
    hint: 'An agent on this group has recently seen traffic.',
  },
  needs_baseline: {
    label: 'Needs a test run',
    hint: 'Agent is installed — run a safe check so it can observe traffic.',
  },
  missing_agent: {
    label: 'No agent',
    hint: 'Install an agent on this group\'s traffic path.',
  },
  misplaced_risk: {
    label: 'Agent offline',
    hint: 'An agent is assigned but not checking in.',
  },
};

export function formatPlacementStatus(status: string, options: { withHint?: boolean } = {}) {
  const copy = PLACEMENT_STATUS_COPY[status];
  if (!copy) return status || 'Unknown';
  return options.withHint ? `${copy.label} — ${copy.hint}` : copy.label;
}

export function placementStatusHint(status: string) {
  return PLACEMENT_STATUS_COPY[status]?.hint ?? '';
}

export function formatPlacementOverview(summary: DataItem | null | undefined) {
  if (!summary) return 'Checking your declared target groups…';
  const total = Number(summary.total_groups ?? 0);
  if (!total) return 'No target groups declared yet.';
  const ready = Number(summary.proven ?? 0);
  const needsTest = Number(summary.needs_baseline ?? 0);
  const needsAgent = Number(summary.missing_agent ?? 0);
  const offline = Number(summary.misplaced_risk ?? 0);
  const parts = [`${ready} of ${total} groups ready`];
  if (needsAgent > 0) parts.push(`${needsAgent} need an agent`);
  if (needsTest > 0) parts.push(`${needsTest} need a test run`);
  if (offline > 0) parts.push(`${offline} have offline agents`);
  return parts.join(' · ');
}