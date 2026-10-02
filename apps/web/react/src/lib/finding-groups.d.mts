export type FindingStatusBucket = 'open' | 'accepted' | 'closed' | 'other';
export type FindingSlaStateKey = 'inactive' | 'undated' | 'breached' | 'due_soon' | 'on_track';
export type FindingGroupSortKey = 'severity' | 'assets' | 'recent' | 'oldest' | 'sla' | 'title';
export type FindingIssueSource = 'verdict' | 'title' | 'vector' | 'none';

export interface FindingSlaState {
  state: FindingSlaStateKey;
  /** Epoch ms, null when the finding is not open or has no created_at. */
  dueAt: number | null;
  /** Rounded hours until due; negative once breached. */
  hoursLeft: number | null;
}

/** One member finding on an affected asset, with its own lifecycle and SLA position. */
export interface FindingGroupAssetMember {
  findingId: string;
  status: string;
  statusBucket: FindingStatusBucket;
  severity: string;
  owner: string;
  targetGroupId: string;
  targetGroupName: string;
  openedAt: string | null;
  slaState: FindingSlaStateKey;
  slaDueAt: string | null;
  slaHoursLeft: number | null;
}

export interface FindingGroupAsset {
  /** `target:<id>`, `host:<hostname>`, or `scope:<group or finding id>`. */
  key: string;
  targetId: string;
  /** Hostname or declared value, '' when none is recorded. */
  host: string;
  /** Declared display name, '' when none is recorded. */
  name: string;
  /** name, else host, else target id, else 'Target-group scope'. */
  label: string;
  targetGroupId: string;
  targetGroupName: string;
  /** True when target_id matched a record in the targets dataset. */
  resolved: boolean;
  /** Representative finding for this asset (open first, worst severity, oldest). */
  findingId: string;
  /** Every member finding recorded for this asset in the group. */
  findingIds: string[];
  /** Every member finding on this asset, ranked open first, worst severity, oldest. */
  members: FindingGroupAssetMember[];
  /** Member lifecycle counts; an asset is "in" a lifecycle when its count is above zero. */
  statusCounts: Record<FindingStatusBucket, number>;
  statusBreakdown: Record<string, number>;
  /** Distinct member owners, sorted. */
  owners: string[];
  unassignedCount: number;
  /** Distinct target groups recorded across all members. */
  targetGroupIds: string[];
  targetGroupNames: string[];
  /** Representative member's lifecycle and SLA fields (kept for compact display). */
  status: string;
  statusBucket: FindingStatusBucket;
  severity: string;
  owner: string;
  openedAt: string | null;
  slaState: FindingSlaStateKey;
  slaDueAt: string | null;
  slaHoursLeft: number | null;
}

export interface FindingGroup {
  /** `<check id>|<issue>`, each part URI-encoded. */
  key: string;
  /** Plain-language, target-agnostic alert title. */
  title: string;
  issueSource: FindingIssueSource;
  checkId: string;
  /** Plain-language check name, '' when the members carry no check id. */
  checkLabel: string;
  /** Catalog check description, '' when the check is not in the loaded catalog. */
  checkDescription: string;
  vectorFamily: string;
  /** Lowercased verdict of the representative member, '' when none was recorded. */
  verdict: string;
  verdictLabel: string;
  /** Every distinct recorded verdict among members. */
  verdicts: string[];
  /** Raw severity string of the worst member, '' when none was recorded. */
  severity: string;
  /** Members ranked open first, then worst severity, then oldest. */
  findings: Record<string, unknown>[];
  findingIds: string[];
  representativeId: string;
  statusCounts: Record<FindingStatusBucket, number>;
  /** Raw lifecycle status counts, e.g. { open: 2, remediation_pending: 1 }. */
  statusBreakdown: Record<string, number>;
  openCount: number;
  /** De-duplicated affected assets in member rank order. */
  assets: FindingGroupAsset[];
  /** Assets with at least one open member. */
  openAssetCount: number;
  /** Target groups recorded on any member finding. */
  targetGroupIds: string[];
  owners: string[];
  unassignedCount: number;
  /** Earliest member opening (oldest-first semantics). */
  earliestOpenedAt: string | null;
  /** Latest member opening (recently-opened semantics). */
  latestOpenedAt: string | null;
  lastObservedAt: string | null;
  /** Earliest SLA due time among open members. */
  nearestSlaDueAt: string | null;
  slaBreachCount: number;
  hasSlaBreach: boolean;
  /** Open members with a computable SLA deadline. */
  openDatedCount: number;
  /** Open members without an opened date, so no deadline can be computed. */
  openUndatedCount: number;
}

/** Prebuilt target/check/target-group indexes plus a per-finding derivation cache. */
export interface FindingGroupIndex {
  readonly targetsById: ReadonlyMap<string, Record<string, unknown>>;
  readonly checksById: ReadonlyMap<string, Record<string, unknown>>;
  readonly groupsById: ReadonlyMap<string, Record<string, unknown>>;
  readonly now: number;
}

export interface FindingGroupSlaSummary {
  state: 'breached' | 'due_soon' | 'on_track' | 'unknown' | 'inactive';
  /** complete: every open member dated; partial: some undated; unknown: none dated; none: no open members. */
  assessment: 'complete' | 'partial' | 'unknown' | 'none';
  label: string;
  breachCount: number;
  datedOpenCount: number;
  undatedOpenCount: number;
  nearestDueAt: string | null;
  hoursLeft: number | null;
}

export interface FindingGroupContext {
  targets?: unknown[];
  checks?: unknown[];
  targetGroups?: unknown[];
  now?: number;
}

export interface FindingFilters {
  status?: FindingStatusBucket | 'all' | string;
  severity?: string;
  owner?: string;
  targetGroup?: string;
  search?: string;
}

export const FINDING_GROUP_SLA_HOURS: Readonly<Record<'critical' | 'high' | 'medium' | 'low', number>>;

export function findingGroupSeverityRank(severity: unknown): number;
export function findingGroupSlaHours(severity: unknown): number;
export function findingStatusBucket(finding: unknown): FindingStatusBucket;
export function createFindingGroupIndex(context?: FindingGroupContext): FindingGroupIndex;
export function findingLookupContext(
  finding: unknown,
  index: FindingGroupIndex
): { targets: Record<string, unknown>[]; checks: Record<string, unknown>[] };
export function findingIssueIdentity(
  finding: Record<string, unknown> | null | undefined,
  context?: { targets?: unknown[]; checks?: unknown[] } | FindingGroupIndex
): { source: FindingIssueSource; issue: string; title: string };
export function findingGroupKey(
  finding: Record<string, unknown> | null | undefined,
  context?: { targets?: unknown[]; checks?: unknown[] } | FindingGroupIndex
): string;
export function findingGroupHref(key: string): string;
export function findingSlaState(finding: unknown, now?: number): FindingSlaState;
export function groupFindings(findings: unknown[] | null | undefined, context?: FindingGroupContext | FindingGroupIndex): FindingGroup[];
export function assetHasLifecycle(asset: Pick<FindingGroupAsset, 'statusCounts'> | null | undefined, lifecycle: FindingStatusBucket | 'all' | string): boolean;
export function assetMembersInLifecycle(asset: Pick<FindingGroupAsset, 'members'> | null | undefined, lifecycle: FindingStatusBucket | 'all' | string): FindingGroupAssetMember[];
export function groupSlaSummary(
  group: Pick<FindingGroup, 'openCount' | 'slaBreachCount' | 'nearestSlaDueAt' | 'openDatedCount' | 'openUndatedCount'>,
  now?: number
): FindingGroupSlaSummary;
export function sortFindingGroups(groups: FindingGroup[], sort: FindingGroupSortKey | string): FindingGroup[];
export function findGroupByKey(groups: FindingGroup[], key: string | null | undefined): FindingGroup | null;
export function matchesFindingFilters(
  finding: unknown,
  filters: FindingFilters,
  options?: { searchText?: (finding: Record<string, unknown>) => string }
): boolean;
