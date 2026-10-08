import { findingStatus as normalizeFindingStatus, isFindingOpen as lifecycleIsFindingOpen } from './finding-lifecycle.mjs';
import { plainCheckName, plainFindingTitle, plainVerdictLabel } from './plain-language.mjs';
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

export function findingStatus(finding: DataItem) {
  return normalizeFindingStatus(finding);
}

export function formatVectorFamilyLabel(family: string) {
  return VECTOR_FAMILY_LABELS[family] ?? family.replace(/_/g, ' ');
}

export function parseFindingTimestamp(value: unknown): number | null {
  if (!value) return null;
  const ms = Date.parse(String(value));
  return Number.isFinite(ms) ? ms : null;
}

export type NormalizedSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';

const SEVERITY_ALIASES: Record<string, NormalizedSeverity> = {
  critical: 'critical',
  s1: 'critical',
  high: 'high',
  s2: 'high',
  medium: 'medium',
  moderate: 'medium',
  s3: 'medium',
  low: 'low',
  s4: 'low',
  info: 'info',
};

/**
 * Maps recorded severities (named or S1-S4 scale) onto one class, matching the tone the
 * severity badges use. Unrecognized values stay 'unknown' instead of being guessed.
 */
export function normalizeSeverity(severity: unknown): NormalizedSeverity {
  return SEVERITY_ALIASES[String(severity ?? '').trim().toLowerCase()] ?? 'unknown';
}

export function findingSlaHours(severity: string) {
  return FINDING_SLA_HOURS[normalizeSeverity(severity)] ?? 168;
}

export function isFindingOpen(finding: DataItem) {
  return lifecycleIsFindingOpen(finding);
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
  if (!['closed', 'resolved'].includes(findingStatus(finding))) return false;
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
  const severityCounts: Record<NormalizedSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
  open.forEach((finding) => {
    severityCounts[normalizeSeverity(finding.severity)] += 1;
  });
  const openSeverityBreakdown = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
    .filter((severity) => severityCounts[severity as keyof typeof severityCounts] > 0)
    .map((severity) => `${severityCounts[severity as keyof typeof severityCounts]} ${severity}`)
    .join(', ');

  return {
    openCount: open.length,
    openSeverityBreakdown: openSeverityBreakdown || 'No open severities',
    acceptedRiskCount: findings.filter((finding) => ['accepted', 'accepted_risk'].includes(findingStatus(finding))).length,
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
      return findings.filter((finding) => ['accepted', 'accepted_risk'].includes(findingStatus(finding)));
    case 'closed':
      return findings.filter((finding) => ['closed', 'resolved'].includes(findingStatus(finding)));
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

/* ------------------------------------------------------------------ */
/* Rule grouping: one queue row per check outcome, many affected assets */
/* ------------------------------------------------------------------ */

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  s1: 0,
  high: 1,
  s2: 1,
  medium: 2,
  moderate: 2,
  s3: 2,
  low: 3,
  s4: 3,
  info: 4,
};

/** Lower is worse. Unknown severities sort after every recorded class. */
export function findingSeverityRank(severity: unknown) {
  return SEVERITY_RANK[String(severity ?? '').trim().toLowerCase()] ?? 9;
}

/** Matches the backend-generated title `Finding: <verdict> on <target>` (src/services/findings.mjs). */
const GENERATED_FINDING_TITLE = /^Finding:\s*([a-z][a-z0-9_-]*)\s+on\s+(.+)$/i;

function asRecord(value: unknown): DataItem | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as DataItem : null;
}

function generatedTitleParts(finding: DataItem) {
  const match = getString(finding, ['title', 'summary', 'label'], '').trim().match(GENERATED_FINDING_TITLE);
  return match ? { verdict: match[1] ?? '', target: (match[2] ?? '').trim() } : null;
}

/** The recorded outcome for a finding, normalized. Empty when the record carries none. */
export function findingVerdictKey(finding: DataItem) {
  const direct = typeof finding.verdict === 'string' ? finding.verdict : '';
  const nested = asRecord(finding.verdict);
  const value = direct
    || getString(finding, ['outcome', 'result', 'reason_code'], '')
    || getString(nested, ['verdict', 'result', 'status'], '')
    || generatedTitleParts(finding)?.verdict
    || '';
  return value.trim().toLowerCase();
}

function normalizeRuleText(value: string) {
  return value.trim().toLowerCase().replace(/\s+/g, ' ');
}

/**
 * Stable rule identity: the plain-language outcome the queue shows as the rule title.
 * The backend titles every finding `Finding: <verdict> on <target>`, and one verdict (for
 * example edge_exposed, "Direct server access was found") is emitted by many checks, so the
 * same outcome on many assets, from any check, is one rule. Severity never splits a rule.
 * Findings with neither a title nor a verdict fall back to their check id, then their own id.
 *
 * Grouping contract (ADR-0009): a Classic "rule" is NOT the same entity as a Refined "alert"
 * (findingGroupKey in finding-groups.mjs, check id + issue identity). One rule can span
 * several alerts, and a custom per-asset title can split one alert into several rules. Rule
 * counts, rule-card asset counts, and finding-detail siblings (findingRuleSiblings) follow
 * this key; changing it changes those numbers. Pinned by tests/unit/finding-grouping-contracts.test.mjs.
 */
export function findingRuleKey(finding: DataItem) {
  const rawTitle = getString(finding, ['title', 'summary', 'label'], '').trim();
  if (rawTitle || findingVerdictKey(finding)) return `rule:${normalizeRuleText(findingRuleTitle(finding))}`;
  const checkId = getString(finding, ['check_id', 'check'], '').trim();
  if (checkId) return `check:${checkId}`;
  return `id:${getString(finding, ['id'], '')}`;
}

/** Rule-level title with no asset name in it, e.g. "Direct server access was found". */
export function findingRuleTitle(finding: DataItem, checks: DataItem[] = []) {
  const rawTitle = getString(finding, ['title', 'summary', 'label'], '').trim();
  const generated = generatedTitleParts(finding);
  const verdict = findingVerdictKey(finding);
  if (generated || (!rawTitle && verdict)) return plainVerdictLabel(verdict);
  if (rawTitle) return plainCheckName(rawTitle);
  const checkId = getString(finding, ['check_id', 'check'], '');
  const check = checks.find((entry) => getString(entry, ['check_id', 'id'], '') === checkId);
  const checkName = plainCheckName(getString(check ?? null, ['name', 'title'], checkId));
  return checkName || 'Evidence-backed finding';
}

/** Label for a finding that records neither a target nor a target-group scope. */
export const UNRECORDED_ASSET_LABEL = 'Asset not recorded';

export type FindingAssetIdentity = {
  /** `target:<id>`, `label:<name>`, `group:<id>`, or `finding:<id>`, in that preference. */
  key: string;
  label: string;
};

/**
 * The one asset identity every rule card, detail summary and asset count uses. A recorded
 * target id wins, then a recorded asset name (hostname, value, generated title), then the
 * recorded target-group scope, and only then the finding itself: two group-scoped findings
 * in different groups are two assets, and an unscoped finding is never merged with another.
 */
export function findingAssetIdentity(finding: DataItem, targets: DataItem[] = [], targetGroups: DataItem[] = []): FindingAssetIdentity {
  const targetId = getString(finding, ['target_id'], '');
  const embedded = asRecord(finding.target);
  const target = targetId ? targets.find((entry) => getString(entry, ['id', 'target_id'], '') === targetId) : undefined;
  const name = getString(finding, ['target_hostname', 'target_value'], '')
    || getString(embedded, ['hostname', 'value', 'name', 'label'], '')
    || getString(target ?? null, ['hostname', 'value', 'name', 'label'], '')
    || generatedTitleParts(finding)?.target
    || '';
  if (targetId) return { key: `target:${targetId}`, label: name || targetId };
  if (name) return { key: `label:${name}`, label: name };
  return { key: `finding:${getString(finding, ['id'], '') || 'unknown'}`, label: UNRECORDED_ASSET_LABEL };
}

/** Human asset name for a finding: hostname or IP when recorded, else the declared target id, else its recorded scope. */
export function findingAssetLabel(finding: DataItem, targets: DataItem[] = [], targetGroups: DataItem[] = []) {
  return findingAssetIdentity(finding, targets, targetGroups).label;
}

/** Latest recorded observation: last_observed_at, else updated_at (set on re-observation), else opened. */
export function findingObservedAt(finding: DataItem) {
  return parseFindingTimestamp(finding.last_observed_at ?? finding.updated_at ?? finding.created_at ?? finding.opened_at);
}

function findingOpenedAt(finding: DataItem) {
  return parseFindingTimestamp(finding.created_at ?? finding.opened_at);
}

export type FindingRuleAsset = { key: string; label: string };

export type FindingRuleGroup = {
  key: string;
  title: string;
  /** Check id of the representative member. */
  checkId: string;
  /** Every distinct check that recorded this outcome, in member order. */
  checkIds: string[];
  members: DataItem[];
  /** Raw severity string of the worst member. */
  worstSeverity: string;
  statusCounts: Record<string, number>;
  assets: FindingRuleAsset[];
  targetGroupIds: string[];
  owners: string[];
  /** Member the queue opens first: open before closed, then worst severity, then oldest. */
  representativeId: string;
  firstOpenedAt: number | null;
  lastOpenedAt: number | null;
  lastObservedAt: number | null;
  /**
   * Latest recorded closure (closed_at / resolved_at) among closed or resolved members. Null
   * when none recorded one; never derived from observation or update time.
   */
  lastClosedAt: number | null;
  /** Earliest SLA due time among open members, null when none is open or dated. */
  earliestOpenSlaDueAt: number | null;
};

const CLOSED_STATUSES = ['closed', 'resolved'];
const ACCEPTED_STATUSES = ['accepted', 'accepted_risk'];
const ACTIVE_SLA_STATUSES = ['open', 'remediation_pending'];

/** Recorded closure event time for a closed or resolved finding; null for any other lifecycle. */
export function findingClosedAt(finding: DataItem) {
  if (!CLOSED_STATUSES.includes(findingStatus(finding))) return null;
  return parseFindingTimestamp(getString(finding, ['closed_at', 'resolved_at', 'closedAt', 'resolvedAt'], ''));
}

function compareRepresentative(left: DataItem, right: DataItem) {
  const openDelta = Number(isFindingOpen(right)) - Number(isFindingOpen(left));
  if (openDelta) return openDelta;
  const severityDelta = findingSeverityRank(left.severity) - findingSeverityRank(right.severity);
  if (severityDelta) return severityDelta;
  return (findingOpenedAt(left) ?? Number.MAX_SAFE_INTEGER) - (findingOpenedAt(right) ?? Number.MAX_SAFE_INTEGER);
}

/**
 * Collapse findings that share a rule into one group. Pass the already-filtered members:
 * a group then exists only when at least one member matched, and every count reflects
 * matched members only. Group order follows first appearance.
 */
export function groupFindingsByRule(
  findings: DataItem[],
  { targets = [], checks = [], targetGroups = [] }: { targets?: DataItem[]; checks?: DataItem[]; targetGroups?: DataItem[] } = {}
): FindingRuleGroup[] {
  const buckets = new Map<string, DataItem[]>();
  findings.forEach((finding) => {
    const key = findingRuleKey(finding);
    const bucket = buckets.get(key) ?? [];
    bucket.push(finding);
    buckets.set(key, bucket);
  });

  return [...buckets.entries()].map(([key, members]) => {
    const ranked = [...members].sort(compareRepresentative);
    const lead = ranked[0] ?? members[0] ?? {};
    const worst = [...members].sort((a, b) => findingSeverityRank(a.severity) - findingSeverityRank(b.severity))[0] ?? lead;
    const statusCounts: Record<string, number> = {};
    const assets = new Map<string, FindingRuleAsset>();
    const targetGroupIds = new Set<string>();
    const owners = new Set<string>();
    const checkIds = new Set<string>();
    let firstOpenedAt: number | null = null;
    let lastOpenedAt: number | null = null;
    let lastObservedAt: number | null = null;
    let lastClosedAt: number | null = null;
    let earliestOpenSlaDueAt: number | null = null;

    ranked.forEach((member) => {
      const status = findingStatus(member);
      statusCounts[status] = (statusCounts[status] ?? 0) + 1;
      const asset = findingAssetIdentity(member, targets, targetGroups);
      if (!assets.has(asset.key)) assets.set(asset.key, asset);
      const closed = findingClosedAt(member);
      if (closed !== null && (lastClosedAt === null || closed > lastClosedAt)) lastClosedAt = closed;
      const groupId = getString(member, ['target_group_id'], '');
      if (groupId) targetGroupIds.add(groupId);
      owners.add(getString(member, ['assignee', 'owner', 'rem_owner'], 'unassigned'));
      const opened = findingOpenedAt(member);
      if (opened !== null && (firstOpenedAt === null || opened < firstOpenedAt)) firstOpenedAt = opened;
      if (opened !== null && (lastOpenedAt === null || opened > lastOpenedAt)) lastOpenedAt = opened;
      const memberCheck = getString(member, ['check_id', 'check'], '');
      if (memberCheck) checkIds.add(memberCheck);
      const observed = findingObservedAt(member);
      if (observed !== null && (lastObservedAt === null || observed > lastObservedAt)) lastObservedAt = observed;
      if (isFindingOpen(member)) {
        const due = findingSlaDueAt(member);
        if (due !== null && (earliestOpenSlaDueAt === null || due < earliestOpenSlaDueAt)) earliestOpenSlaDueAt = due;
      }
    });

    return {
      key,
      title: findingRuleTitle(lead, checks),
      checkId: getString(lead, ['check_id', 'check'], ''),
      checkIds: [...checkIds],
      members: ranked,
      worstSeverity: getString(worst, ['severity'], 'unknown'),
      statusCounts,
      assets: [...assets.values()],
      targetGroupIds: [...targetGroupIds],
      owners: [...owners].sort(),
      representativeId: getString(lead, ['id'], ''),
      firstOpenedAt,
      lastOpenedAt,
      lastObservedAt,
      lastClosedAt,
      earliestOpenSlaDueAt,
    };
  });
}

export type FindingRuleSlaMeta = {
  label: string;
  tone: 'danger' | 'warn' | 'muted';
  due: string;
};

/**
 * SLA cell for a rule. Open members carry an SLA from recorded severity and created_at; a
 * rule with none open has no active SLA, and its wording follows the recorded lifecycle:
 * accepted risk is never presented as closure, and a closure date appears only when a
 * closed or resolved member recorded one. `formatDate` is injected so this stays pure.
 */
export function findingRuleSlaMeta(
  group: Pick<FindingRuleGroup, 'members' | 'earliestOpenSlaDueAt' | 'lastClosedAt'>,
  formatDate: (value: number) => string,
  now = Date.now()
): FindingRuleSlaMeta {
  const activeMembers = group.members.filter((member) => ACTIVE_SLA_STATUSES.includes(findingStatus(member)));
  if (activeMembers.length === 0) {
    const statuses = group.members.map(findingStatus);
    const hasClosed = statuses.some((status) => CLOSED_STATUSES.includes(status));
    const hasAccepted = statuses.some((status) => ACCEPTED_STATUSES.includes(status));
    const closedOn = group.lastClosedAt !== null ? formatDate(group.lastClosedAt) : '';
    if (hasClosed && !hasAccepted && statuses.every((status) => CLOSED_STATUSES.includes(status))) {
      return { label: closedOn ? `Closed ${closedOn}` : 'Closed', tone: 'muted', due: '' };
    }
    if (hasAccepted && !hasClosed && statuses.every((status) => ACCEPTED_STATUSES.includes(status))) {
      return { label: 'Risk accepted', tone: 'muted', due: 'No active SLA' };
    }
    return { label: 'No active SLA', tone: 'muted', due: closedOn ? `Last closed ${closedOn}` : '' };
  }
  const breached = activeMembers.filter((member) => isFindingSlaBreach(member, now)).length;
  const dueAt = group.earliestOpenSlaDueAt;
  if (breached > 0) {
    return {
      label: group.members.length > 1 ? `${breached} overdue` : 'Overdue',
      tone: 'danger',
      due: dueAt ? `Earliest due ${formatDate(dueAt)}` : ''
    };
  }
  if (!dueAt) {
    const recorded = getString(activeMembers[0] ?? {}, ['rem_sla', 'remSla', 'sla'], '');
    return { label: recorded || 'Pending', tone: 'muted', due: '' };
  }
  const hoursLeft = Math.max(0, Math.round((dueAt - now) / 3_600_000));
  return {
    label: hoursLeft <= 24 ? `${hoursLeft}h left` : 'On track',
    tone: hoursLeft <= 24 ? 'warn' : 'muted',
    due: formatDate(dueAt)
  };
}

export type FindingRuleSortKey = 'severity' | 'recent' | 'oldest' | 'sla' | 'title' | 'assets';

export function sortFindingRuleGroups(groups: FindingRuleGroup[], sort: FindingRuleSortKey) {
  const copy = [...groups];
  copy.sort((left, right) => {
    if (sort === 'title') return left.title.localeCompare(right.title);
    if (sort === 'assets') return right.assets.length - left.assets.length || left.title.localeCompare(right.title);
    if (sort === 'sla') return (left.earliestOpenSlaDueAt ?? Number.MAX_SAFE_INTEGER) - (right.earliestOpenSlaDueAt ?? Number.MAX_SAFE_INTEGER);
    if (sort === 'recent') return (right.lastOpenedAt ?? 0) - (left.lastOpenedAt ?? 0);
    if (sort === 'oldest') return (left.firstOpenedAt ?? Number.MAX_SAFE_INTEGER) - (right.firstOpenedAt ?? Number.MAX_SAFE_INTEGER);
    return findingSeverityRank(left.worstSeverity) - findingSeverityRank(right.worstSeverity)
      || right.assets.length - left.assets.length
      || left.title.localeCompare(right.title);
  });
  return copy;
}

const STATUS_SUMMARY_ORDER = ['open', 'remediation_pending', 'accepted_risk', 'accepted', 'resolved', 'closed'];

/** "2 open, 1 accepted risk" in lifecycle order; unknown statuses follow alphabetically. */
export function summarizeFindingStatuses(statusCounts: Record<string, number>) {
  const keys = Object.keys(statusCounts).filter((key) => (statusCounts[key] ?? 0) > 0);
  keys.sort((a, b) => {
    const ai = STATUS_SUMMARY_ORDER.indexOf(a);
    const bi = STATUS_SUMMARY_ORDER.indexOf(b);
    if (ai === -1 && bi === -1) return a.localeCompare(b);
    if (ai === -1) return 1;
    if (bi === -1) return -1;
    return ai - bi;
  });
  return keys.map((key) => `${statusCounts[key]} ${key.replace(/_/g, ' ')}`).join(', ');
}

/** Distinct affected assets across a set of findings, by the same identity the rule cards use. */
export function countFindingAssets(findings: DataItem[], targets: DataItem[] = []) {
  return new Set(findings.map((finding) => findingAssetIdentity(finding, targets).key)).size;
}

/** Preview of asset names for a queue row: first names plus a remainder count. */
export function previewRuleAssets(assets: FindingRuleAsset[], limit = 2) {
  const shown = assets.slice(0, limit).map((asset) => asset.label);
  return { shown, remaining: Math.max(0, assets.length - shown.length) };
}

/**
 * Every finding that shares the given finding's rule, the finding itself included even when
 * the loaded list does not contain it. Ordered open first, worst severity, then asset name.
 */
export function findingRuleSiblings(finding: DataItem, findings: DataItem[], targets: DataItem[] = []) {
  const key = findingRuleKey(finding);
  const id = getString(finding, ['id'], '');
  const siblings = findings.filter((entry) => findingRuleKey(entry) === key && getString(entry, ['id'], '') !== id);
  const all = [finding, ...siblings];
  return all.sort((left, right) => {
    const openDelta = Number(isFindingOpen(right)) - Number(isFindingOpen(left));
    if (openDelta) return openDelta;
    const severityDelta = findingSeverityRank(left.severity) - findingSeverityRank(right.severity);
    if (severityDelta) return severityDelta;
    return findingAssetLabel(left, targets).localeCompare(findingAssetLabel(right, targets));
  });
}

/** Route query that asks the finding detail view to land on its rule-wide asset list. */
export const FINDING_RULE_ASSETS_FOCUS = 'rule-assets';

/**
 * Hash (without `#`) a grouped queue row opens. Single-asset rules open the finding directly;
 * multi-asset rules open the representative finding focused on the affected-asset list.
 */
export function findingRuleDetailHash(group: Pick<FindingRuleGroup, 'representativeId' | 'assets' | 'members'>) {
  if (!group.representativeId) return '';
  const base = `finding-detail?id=${encodeURIComponent(group.representativeId)}`;
  return group.members.length > 1 ? `${base}&focus=${FINDING_RULE_ASSETS_FOCUS}` : base;
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

export type TargetDeduplicatedFinding = {
  key: string;
  id: string;
  representativeId: string;
  representative: DataItem;
  title: string;
  severity: string;
  status: string;
  state: string;
  assignee: string;
  firstOpenedAt: string | null;
  lastOpenedAt: string | null;
  firstOpenedTimestamp: number | null;
  lastOpenedTimestamp: number | null;
  detectionCount: number;
  detections: DataItem[];
  evidenceIds: string[];
  testRunIds: string[];
};

/**
 * Groups and deduplicates recurring finding detections on a single target into unique findings,
 * tracking full detection history, occurrence counts, and timestamps.
 */
export function dedupeFindingsForTarget(
  findings: DataItem[],
  target: DataItem | null = null,
  checks: DataItem[] = []
): TargetDeduplicatedFinding[] {
  const buckets = new Map<string, DataItem[]>();

  findings.forEach((finding) => {
    const checkId = getString(finding, ['check_id', 'check'], '').trim();
    const ruleKey = findingRuleKey(finding);
    const groupKey = `${checkId}::${ruleKey}` || getString(finding, ['id'], '');
    const bucket = buckets.get(groupKey) ?? [];
    bucket.push(finding);
    buckets.set(groupKey, bucket);
  });

  return [...buckets.entries()].map(([key, rawMembers]) => {
    const sorted = [...rawMembers].sort((a, b) => {
      const timeA = parseFindingTimestamp(a.opened_at ?? a.created_at) ?? 0;
      const timeB = parseFindingTimestamp(b.opened_at ?? b.created_at) ?? 0;
      return timeB - timeA || String(b.id ?? '').localeCompare(String(a.id ?? ''));
    });

    const ranked = [...sorted].sort((a, b) => {
      const openDelta = Number(isFindingOpen(b)) - Number(isFindingOpen(a));
      if (openDelta) return openDelta;
      const sevDelta = findingSeverityRank(a.severity) - findingSeverityRank(b.severity);
      if (sevDelta) return sevDelta;
      const timeA = parseFindingTimestamp(a.opened_at ?? a.created_at) ?? 0;
      const timeB = parseFindingTimestamp(b.opened_at ?? b.created_at) ?? 0;
      return timeB - timeA;
    });

    const lead = ranked[0] ?? sorted[0] ?? {};
    const leadId = getString(lead, ['id'], '');
    const worst = [...sorted].sort((a, b) => findingSeverityRank(a.severity) - findingSeverityRank(b.severity))[0] ?? lead;

    let firstOpenedTimestamp: number | null = null;
    let lastOpenedTimestamp: number | null = null;
    let firstOpenedAt: string | null = null;
    let lastOpenedAt: string | null = null;
    const evidenceSet = new Set<string>();
    const testRunSet = new Set<string>();

    sorted.forEach((member) => {
      const rawOpened = getString(member, ['opened_at', 'created_at', 'openedAt', 'createdAt'], '');
      const parsedTime = parseFindingTimestamp(rawOpened);
      if (parsedTime !== null) {
        if (firstOpenedTimestamp === null || parsedTime < firstOpenedTimestamp) {
          firstOpenedTimestamp = parsedTime;
          firstOpenedAt = rawOpened;
        }
        if (lastOpenedTimestamp === null || parsedTime > lastOpenedTimestamp) {
          lastOpenedTimestamp = parsedTime;
          lastOpenedAt = rawOpened;
        }
      }
      const evIds = Array.isArray(member.evidence_ids) ? member.evidence_ids : [];
      evIds.forEach((id: string) => evidenceSet.add(String(id)));
      const trId = getString(member, ['test_run_id', 'testRunId'], '');
      if (trId) testRunSet.add(trId);
    });

    const targetList = target ? [target] : [];
    const title = plainFindingTitle(lead, targetList, checks);
    const status = findingStatus(lead);

    return {
      key,
      id: leadId,
      representativeId: leadId,
      representative: lead,
      title,
      severity: getString(worst, ['severity'], 'medium'),
      status,
      state: status,
      assignee: getString(lead, ['assignee', 'owner', 'rem_owner'], ''),
      firstOpenedAt,
      lastOpenedAt,
      firstOpenedTimestamp,
      lastOpenedTimestamp,
      detectionCount: sorted.length,
      detections: sorted,
      evidenceIds: [...evidenceSet],
      testRunIds: [...testRunSet],
    };
  });
}