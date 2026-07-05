import type { DataItem } from './types';

export type FindingTabId = 'open' | 'target-group' | 'vector' | 'accepted-risk' | 'closed' | 'sla';

export const FINDING_SLA_HOURS: Record<string, number> = {
  critical: 24,
  high: 48,
  medium: 72,
  low: 168,
};

const VECTOR_FAMILY_LABELS: Record<string, string> = {
  origin: 'Origin',
  path: 'Path',
  l3_l4: 'L3/L4',
  dns: 'DNS',
  l7: 'L7/API',
  waf: 'WAF',
  tls: 'TLS',
  protocol: 'Protocol',
  operations: 'Operations',
  high_scale: 'High-scale',
};

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

export function formatVectorFamilyLabel(family: string) {
  return VECTOR_FAMILY_LABELS[family] ?? family.replace(/_/g, ' ');
}

export function parseFindingTimestamp(value: unknown): number | null {
  if (!value) return null;
  const ms = Date.parse(String(value));
  return Number.isFinite(ms) ? ms : null;
}

export function findingSlaHours(severity: string) {
  return FINDING_SLA_HOURS[severity.toLowerCase()] ?? 168;
}

export function isFindingOpen(finding: DataItem) {
  return getString(finding, ['status']) === 'open';
}

export function findingSlaDueAt(finding: DataItem) {
  const created = parseFindingTimestamp(finding.created_at);
  if (created === null) return null;
  return created + findingSlaHours(getString(finding, ['severity'], 'low')) * 60 * 60 * 1000;
}

export function isFindingSlaBreach(finding: DataItem, now = Date.now()) {
  if (!isFindingOpen(finding)) return false;
  const dueAt = findingSlaDueAt(finding);
  return dueAt !== null && now > dueAt;
}

export function isFindingClosedWithin30Days(finding: DataItem, now = Date.now()) {
  if (getString(finding, ['status']) !== 'closed') return false;
  const updated = parseFindingTimestamp(finding.updated_at ?? finding.created_at);
  if (updated === null) return false;
  return now - updated <= 30 * 24 * 60 * 60 * 1000;
}

export function getFindingVectorFamily(finding: DataItem, checks: DataItem[]) {
  const direct = getString(finding, ['vector_family'], '');
  if (direct) return direct;
  const checkId = getString(finding, ['check_id'], '');
  const check = checks.find((entry) => getString(entry, ['check_id']) === checkId);
  return getString(check ?? {}, ['vector_family'], 'other');
}

export function computeFindingKpis(findings: DataItem[], now = Date.now()) {
  const open = findings.filter(isFindingOpen);
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  open.forEach((finding) => {
    const severity = getString(finding, ['severity'], 'low').toLowerCase();
    if (severity in severityCounts) {
      severityCounts[severity as keyof typeof severityCounts] += 1;
    } else {
      severityCounts.low += 1;
    }
  });
  const openSeverityBreakdown = ['critical', 'high', 'medium', 'low']
    .filter((severity) => severityCounts[severity as keyof typeof severityCounts] > 0)
    .map((severity) => `${severityCounts[severity as keyof typeof severityCounts]} ${severity}`)
    .join(', ');

  return {
    openCount: open.length,
    openSeverityBreakdown: openSeverityBreakdown || 'No open severities',
    acceptedRiskCount: findings.filter((finding) => getString(finding, ['status']) === 'accepted_risk').length,
    closed30dCount: findings.filter((finding) => isFindingClosedWithin30Days(finding, now)).length,
    slaBreachCount: findings.filter((finding) => isFindingSlaBreach(finding, now)).length,
  };
}

/** Grouped target-group and vector tabs intentionally list open findings only. */
export const GROUPED_FINDINGS_OPEN_ONLY_NOTE = 'Grouped views show open findings only.';

export function findingsListSubtitle(tab: FindingTabId): string | null {
  if (tab === 'target-group' || tab === 'vector') return GROUPED_FINDINGS_OPEN_ONLY_NOTE;
  return null;
}

export function groupedFindingsBadgeLabel(tab: FindingTabId, count: number): string {
  if (tab === 'target-group' || tab === 'vector') return `${count} findings`;
  return `${count} open`;
}

export function filterFindingsByTab(
  findings: DataItem[],
  tab: FindingTabId,
  checks: DataItem[],
  now = Date.now()
) {
  switch (tab) {
    case 'open':
      return findings.filter(isFindingOpen);
    case 'accepted-risk':
      return findings.filter((finding) => getString(finding, ['status']) === 'accepted_risk');
    case 'closed':
      return findings.filter((finding) => getString(finding, ['status']) === 'closed');
    case 'sla':
      return findings.filter((finding) => isFindingSlaBreach(finding, now));
    case 'target-group':
    case 'vector':
      return findings.filter(isFindingOpen);
    default:
      return findings;
  }
}

export function groupFindingsByTargetGroup(findings: DataItem[], targetGroups: DataItem[]) {
  const groups = new Map<string, DataItem[]>();
  findings.forEach((finding) => {
    const groupId = getString(finding, ['target_group_id'], 'ungrouped');
    const bucket = groups.get(groupId) ?? [];
    bucket.push(finding);
    groups.set(groupId, bucket);
  });
  return [...groups.entries()].map(([groupId, items]) => ({
    groupId,
    label: getString(
      targetGroups.find((group) => getString(group, ['id']) === groupId) ?? null,
      ['name', 'display_name', 'id'],
      groupId === 'ungrouped' ? 'Unassigned target group' : groupId
    ),
    items,
  }));
}

export function groupFindingsByVector(findings: DataItem[], checks: DataItem[]) {
  const groups = new Map<string, DataItem[]>();
  findings.forEach((finding) => {
    const family = getFindingVectorFamily(finding, checks);
    const bucket = groups.get(family) ?? [];
    bucket.push(finding);
    groups.set(family, bucket);
  });
  return [...groups.entries()].map(([family, items]) => ({
    family,
    label: formatVectorFamilyLabel(family),
    items,
  }));
}

export function resolveFindingRetestAction(finding: DataItem) {
  const checkId = getString(finding, ['check_id'], '');

  if (checkId.startsWith('waf.posture.')) {
    const wafAssetId = getString(finding, ['waf_asset_id'], '') || checkId.slice('waf.posture.'.length);
    if (!wafAssetId) return null;
    return {
      kind: 'waf-validation' as const,
      wafAssetId,
    };
  }

  const cvePipelineItemId = getString(finding, ['cve_pipeline_item_id', 'cve_item_id'], '');
  if (checkId.startsWith('cve.') || cvePipelineItemId) {
    const pipelineId = cvePipelineItemId
      || (checkId.startsWith('cve.pipeline.') ? checkId.slice('cve.pipeline.'.length) : '');
    if (!pipelineId) return null;
    return {
      kind: 'cve-retest' as const,
      pipelineId,
    };
  }

  const retestUrl = getString(finding, ['retest_url'], '');
  if (retestUrl.includes('/v1/waf/cve-pipeline/') && (retestUrl.includes('/retest') || retestUrl.includes('/coordinated-retest'))) {
    return {
      kind: 'cve-retest-url' as const,
      retestUrl,
    };
  }

  if (!checkId) return null;
  return {
    kind: 'safe-run' as const,
    checkId,
  };
}