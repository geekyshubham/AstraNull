/**
 * Group findings that describe the same alert, so the Refined findings view can show
 * "one problem, N affected assets" instead of N near-identical rows.
 *
 * Same alert = same check (check_id) + same normalized issue. The issue is, in order:
 *   1. the recorded verdict when the title is the backend-generated `Finding: <verdict> on <target>`
 *      or no title is recorded,
 *   2. the recorded title with target-specific tokens (id, hostname, value, name) removed,
 *   3. the vector family,
 *   4. `none`.
 *
 * Grouping contract (ADR-0009): a Refined "alert" is a different entity from a Classic
 * "rule" (findingRuleKey in findings-helpers.ts, keyed by the displayed outcome and merging
 * checks). Two checks reporting the same verdict are one rule but two alerts; per-asset
 * titles from one check are one alert but separate rules. Alert counts and the
 * #finding-group-detail membership follow findingGroupKey only. Pinned by
 * tests/unit/finding-grouping-contracts.test.mjs.
 *
 * Pure ESM so node:test can exercise it directly. Every value shown in the UI comes from
 * the finding, target, target-group, or check records; nothing is inferred.
 *
 * Scale: targets, checks and target groups are indexed once per context
 * (createFindingGroupIndex), and each finding's identity, asset and SLA facts are derived
 * once per index and cached by record. Summary and filtered grouping that share one index
 * therefore stay linear in the number of findings instead of findings x targets.
 */
import { findingStatus } from './finding-lifecycle.mjs';
import { plainCheckName, plainVerdictLabel } from './plain-language.mjs';

/** Mirrors FINDING_SLA_HOURS in findings-helpers.ts (parity is unit-tested). */
export const FINDING_GROUP_SLA_HOURS = Object.freeze({ critical: 24, high: 48, medium: 72, low: 168 });
const DEFAULT_SLA_HOURS = 168;
const DUE_SOON_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

/** Higher is worse. Unknown severities rank 0, below every recorded class. */
const SEVERITY_RANK = Object.freeze({
  critical: 5, s1: 5, high: 4, s2: 4, medium: 3, moderate: 3, s3: 3, low: 2, s4: 2, info: 1
});

const GENERATED_TITLE = /^Finding:\s*([a-z][a-z0-9_-]*)\s+on\s+(.+)$/i;

/** @param {unknown} value */
function asRecord(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? /** @type {Record<string, unknown>} */ (value) : {};
}

/**
 * @param {Record<string, unknown>} record
 * @param {string[]} keys
 */
function pick(record, keys) {
  for (const key of keys) {
    const value = record[key];
    if (value !== undefined && value !== null && typeof value !== 'object') {
      const text = String(value).trim();
      if (text) return text;
    }
  }
  return '';
}

/** @param {unknown} value */
function timestamp(value) {
  if (!value) return null;
  const ms = Date.parse(String(value));
  return Number.isFinite(ms) ? ms : null;
}

/** @param {unknown} severity */
export function findingGroupSeverityRank(severity) {
  return SEVERITY_RANK[/** @type {keyof typeof SEVERITY_RANK} */ (String(severity ?? '').trim().toLowerCase())] ?? 0;
}

/** @param {unknown} severity */
export function findingGroupSlaHours(severity) {
  const raw = String(severity ?? '').trim().toLowerCase();
  // S1-S4 and 'moderate' share the named class windows, matching normalizeSeverity in findings-helpers.ts.
  const key = SEVERITY_SLA_ALIASES[/** @type {keyof typeof SEVERITY_SLA_ALIASES} */ (raw)] ?? raw;
  return FINDING_GROUP_SLA_HOURS[/** @type {keyof typeof FINDING_GROUP_SLA_HOURS} */ (key)] ?? DEFAULT_SLA_HOURS;
}

const SEVERITY_SLA_ALIASES = Object.freeze({ s1: 'critical', s2: 'high', s3: 'medium', moderate: 'medium', s4: 'low' });

/**
 * Lifecycle bucket used by the status tabs: open, accepted, closed, or other
 * (for example remediation_pending). Matches the classic queue's tab semantics.
 * @param {unknown} finding
 */
export function findingStatusBucket(finding) {
  const status = findingStatus(asRecord(finding));
  if (status === 'open') return 'open';
  if (status === 'accepted' || status === 'accepted_risk') return 'accepted';
  if (status === 'closed' || status === 'resolved') return 'closed';
  return 'other';
}

/** @param {Record<string, unknown>} finding */
function findingVerdict(finding) {
  if (typeof finding.verdict === 'string' && finding.verdict.trim()) return finding.verdict.trim().toLowerCase();
  const nested = asRecord(finding.verdict);
  const recorded = pick(finding, ['outcome', 'result', 'reason_code']) || pick(nested, ['verdict', 'result', 'status']);
  if (recorded) return recorded.toLowerCase();
  const generated = pick(finding, ['title', 'summary', 'label']).match(GENERATED_TITLE);
  return generated ? String(generated[1]).toLowerCase() : '';
}

/** @param {string} value */
function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * The title with target-specific tokens removed: "Origin reachable on a.example.test" and
 * "Origin reachable on b.example.test" both become "Origin reachable".
 * @param {Record<string, unknown>} finding
 * @param {Record<string, unknown> | null} target
 */
function targetAgnosticTitle(finding, target) {
  const raw = pick(finding, ['title', 'summary', 'label']);
  if (!raw) return '';
  const embedded = asRecord(finding.target);
  const tokens = [
    pick(finding, ['target_id']),
    pick(finding, ['target_hostname']),
    pick(finding, ['target_value']),
    pick(embedded, ['hostname']),
    pick(embedded, ['value']),
    pick(embedded, ['name']),
    pick(target ?? {}, ['hostname']),
    pick(target ?? {}, ['value']),
    pick(target ?? {}, ['name']),
    pick(target ?? {}, ['label'])
  ].filter((token) => token.length >= 3);
  // Longest first so a hostname is removed before a shorter name it contains.
  let title = raw;
  for (const token of [...new Set(tokens)].sort((a, b) => b.length - a.length)) {
    // Whole-token match only, so a target named "api" never edits "API gateway".
    title = title.replace(new RegExp(`(?<![\\w.-])${escapeRegExp(token)}(?![\\w.-])`, 'gi'), ' ');
  }
  return title
    .replace(/\s+(?:on|for|at|against)\s*(?=$|[·:,;()\-])/gi, ' ')
    .replace(/\s+(?:on|for|at|against)\s*$/i, '')
    .replace(/[\s·:,;(\-]+$/u, '')
    .replace(/^[\s·:,;)\-]+/u, '')
    .replace(/\(\s*\)/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * @param {Record<string, unknown>} finding
 * @param {Record<string, unknown> | null} check
 */
function vectorFamilyOf(finding, check) {
  return pick(finding, ['vector_family', 'vector']) || pick(check ?? {}, ['vector_family']);
}

/** Marks a value built by createFindingGroupIndex, so callers can pass either an index or a raw context. */
const INDEX_MARK = Symbol('findingGroupIndex');

/**
 * Index the grouping context once: targets by id, checks by id, target groups by id, plus a
 * per-index cache of each finding's derived facts. Build it once per dataset (for example in a
 * useMemo keyed on the arrays) and pass it to groupFindings for both the whole inventory and
 * the filtered subset; the filtered pass then reuses every per-finding derivation.
 * @param {{ targets?: unknown[]; checks?: unknown[]; targetGroups?: unknown[]; now?: number }} [context]
 */
export function createFindingGroupIndex(context = {}) {
  const ctx = asRecord(context);
  /** @type {Map<string, Record<string, unknown>>} */
  const targetsById = new Map();
  for (const raw of Array.isArray(ctx.targets) ? ctx.targets : []) {
    const entry = asRecord(raw);
    const id = pick(entry, ['id', 'target_id']);
    // First record wins, matching the previous Array#find lookup.
    if (id && !targetsById.has(id)) targetsById.set(id, entry);
  }
  /** @type {Map<string, Record<string, unknown>>} */
  const checksById = new Map();
  for (const raw of Array.isArray(ctx.checks) ? ctx.checks : []) {
    const entry = asRecord(raw);
    const id = pick(entry, ['check_id', 'id']);
    if (id && !checksById.has(id)) checksById.set(id, entry);
  }
  /** @type {Map<string, Record<string, unknown>>} */
  const groupsById = new Map();
  for (const raw of Array.isArray(ctx.targetGroups) ? ctx.targetGroups : []) {
    const entry = asRecord(raw);
    const id = pick(entry, ['id']);
    if (id) groupsById.set(id, entry);
  }
  return Object.freeze({
    [INDEX_MARK]: true,
    targetsById,
    checksById,
    groupsById,
    now: typeof ctx.now === 'number' ? ctx.now : Date.now(),
    /** @type {WeakMap<object, any>} */
    facts: new WeakMap()
  });
}

/** @param {unknown} context */
function resolveIndex(context) {
  const record = asRecord(context);
  return record[/** @type {any} */ (INDEX_MARK)] ? /** @type {any} */ (record) : createFindingGroupIndex(/** @type {any} */ (record));
}

/** @param {string} status */
function bucketOfStatus(status) {
  if (status === 'open') return 'open';
  if (status === 'accepted' || status === 'accepted_risk') return 'accepted';
  if (status === 'closed' || status === 'resolved') return 'closed';
  return 'other';
}

/**
 * @param {Record<string, unknown>} record
 * @param {Record<string, unknown> | null} target
 * @param {Record<string, unknown> | null} check
 */
function issueIdentityOf(record, target, check) {
  const rawTitle = pick(record, ['title', 'summary', 'label']);
  const verdict = findingVerdict(record);
  if (verdict && (!rawTitle || GENERATED_TITLE.test(rawTitle))) {
    return { source: 'verdict', issue: `v:${verdict}`, title: plainVerdictLabel(verdict) };
  }
  const stripped = targetAgnosticTitle(record, target);
  if (stripped) {
    return { source: 'title', issue: `t:${stripped.toLowerCase()}`, title: plainCheckName(stripped) };
  }
  if (verdict) return { source: 'verdict', issue: `v:${verdict}`, title: plainVerdictLabel(verdict) };
  const family = vectorFamilyOf(record, check);
  if (family) return { source: 'vector', issue: `f:${family.toLowerCase()}`, title: '' };
  return { source: 'none', issue: 'none', title: '' };
}

/**
 * @param {string} bucket
 * @param {Record<string, unknown>} record
 * @param {number} now
 */
function slaOf(bucket, record, now) {
  if (bucket !== 'open') return { state: 'inactive', dueAt: null, hoursLeft: null };
  const created = timestamp(record.created_at);
  if (created === null) return { state: 'undated', dueAt: null, hoursLeft: null };
  const dueAt = created + findingGroupSlaHours(pick(record, ['severity']) || 'low') * HOUR_MS;
  const hoursLeft = Math.round((dueAt - now) / HOUR_MS);
  if (now > dueAt) return { state: 'breached', dueAt, hoursLeft };
  if (dueAt - now <= DUE_SOON_MS) return { state: 'due_soon', dueAt, hoursLeft };
  return { state: 'on_track', dueAt, hoursLeft };
}

/**
 * Everything grouping needs from one finding, derived once per index with O(1) lookups.
 * @param {Record<string, unknown>} record
 * @param {ReturnType<typeof createFindingGroupIndex>} index
 */
function findingFacts(record, index) {
  const cached = index.facts.get(record);
  if (cached) return cached;
  const targetId = pick(record, ['target_id']);
  const target = targetId ? index.targetsById.get(targetId) ?? null : null;
  const checkId = pick(record, ['check_id', 'check']);
  const check = checkId ? index.checksById.get(checkId) ?? null : null;
  const identity = issueIdentityOf(record, target, check);
  const status = findingStatus(record);
  const bucket = bucketOfStatus(status);
  const severity = pick(record, ['severity']);
  const facts = {
    key: `${encodeURIComponent(checkId || 'unknown-check')}|${encodeURIComponent(identity.issue)}`,
    id: pick(record, ['id', 'finding_id']),
    checkId,
    check,
    identity,
    verdict: findingVerdict(record),
    status,
    bucket,
    severity,
    severityRank: findingGroupSeverityRank(severity),
    owner: ownerOf(record),
    opened: timestamp(record.created_at ?? record.opened_at),
    observed: timestamp(record.updated_at ?? record.last_observed_at ?? record.created_at ?? record.opened_at),
    sla: slaOf(bucket, record, index.now),
    asset: assetIdentity(record, target, index.groupsById)
  };
  index.facts.set(record, facts);
  return facts;
}

/**
 * The normalized issue part of a group key plus where it came from.
 * @param {Record<string, unknown> | null | undefined} finding
 * @param {{ targets?: unknown[]; checks?: unknown[] } | ReturnType<typeof createFindingGroupIndex>} [context]
 */
export function findingIssueIdentity(finding, context = {}) {
  const record = asRecord(finding);
  const index = resolveIndex(context);
  const targetId = pick(record, ['target_id']);
  const checkId = pick(record, ['check_id', 'check']);
  return issueIdentityOf(
    record,
    targetId ? index.targetsById.get(targetId) ?? null : null,
    checkId ? index.checksById.get(checkId) ?? null : null
  );
}

/**
 * Stable, URL-safe group key: `<check id>|<issue>`, each part URI-encoded, so `|` only
 * ever appears as the separator. Place it in a hash with findingGroupHref.
 * @param {Record<string, unknown> | null | undefined} finding
 * @param {{ targets?: unknown[]; checks?: unknown[] } | ReturnType<typeof createFindingGroupIndex>} [context]
 */
export function findingGroupKey(finding, context = {}) {
  const record = asRecord(finding);
  const checkId = pick(record, ['check_id', 'check']) || 'unknown-check';
  const { issue } = findingIssueIdentity(record, context);
  return `${encodeURIComponent(checkId)}|${encodeURIComponent(issue)}`;
}

/**
 * The single target and check record a finding refers to, as one-element arrays, so
 * array-based display helpers (plainFindingTitle, findingAssetLabel) avoid a full scan.
 * A generated `Finding: <verdict> on <host>` title without target_id is resolved by host, the
 * same fallback plainFindingTitle applies.
 * @param {unknown} finding
 * @param {ReturnType<typeof createFindingGroupIndex>} index
 */
export function findingLookupContext(finding, index) {
  const record = asRecord(finding);
  const resolved = resolveIndex(index);
  const generated = pick(record, ['title', 'summary', 'label']).match(GENERATED_TITLE);
  const targetId = pick(record, ['target_id']) || (generated ? String(generated[2]).trim() : '');
  const checkId = pick(record, ['check_id']);
  const target = targetId ? resolved.targetsById.get(targetId) : undefined;
  const check = checkId ? resolved.checksById.get(checkId) : undefined;
  return { targets: target ? [target] : [], checks: check ? [check] : [] };
}

/**
 * Hash link for the grouped-alert detail page.
 * @param {string} key
 */
export function findingGroupHref(key) {
  return `#finding-group-detail?key=${encodeURIComponent(key)}`;
}

/**
 * SLA position of one finding, from its recorded severity and created_at.
 * Only open findings carry an SLA clock, matching computeFindingKpis.
 * @param {unknown} finding
 * @param {number} [now]
 */
export function findingSlaState(finding, now = Date.now()) {
  const record = asRecord(finding);
  return slaOf(findingStatusBucket(record), record, now);
}

/** @param {Record<string, unknown>} finding */
function ownerOf(finding) {
  return pick(finding, ['assignee', 'owner', 'rem_owner']);
}

/**
 * Representative order: open before anything else, then worst severity, then oldest.
 * @param {{ facts: any }} left
 * @param {{ facts: any }} right
 */
function compareRepresentative(left, right) {
  const openDelta = Number(right.facts.bucket === 'open') - Number(left.facts.bucket === 'open');
  if (openDelta) return openDelta;
  const severityDelta = right.facts.severityRank - left.facts.severityRank;
  if (severityDelta) return severityDelta;
  return (left.facts.opened ?? Number.MAX_SAFE_INTEGER) - (right.facts.opened ?? Number.MAX_SAFE_INTEGER);
}

/**
 * @param {Record<string, unknown>} finding
 * @param {Record<string, unknown> | null} target
 * @param {Map<string, Record<string, unknown>>} groupsById
 */
function assetIdentity(finding, target, groupsById) {
  const targetId = pick(finding, ['target_id']);
  const embedded = asRecord(finding.target);
  const generated = pick(finding, ['title', 'summary', 'label']).match(GENERATED_TITLE);
  const host = pick(finding, ['target_hostname', 'target_value'])
    || pick(embedded, ['hostname', 'value'])
    || pick(target ?? {}, ['hostname', 'value'])
    || (generated ? String(generated[2]).trim() : '');
  const name = pick(embedded, ['name', 'label']) || pick(target ?? {}, ['name', 'label', 'display_name']);
  const targetGroupId = pick(finding, ['target_group_id']) || pick(target ?? {}, ['target_group_id']);
  const targetGroupName = targetGroupId ? pick(groupsById.get(targetGroupId) ?? {}, ['name', 'display_name']) : '';
  const label = name || host || targetId || 'Target not recorded';
  const key = targetId
    ? `target:${targetId}`
    : host
      ? `host:${host.toLowerCase()}`
      : `scope:${targetGroupId || pick(finding, ['id']) || 'unknown'}`;
  return { key, targetId, host, name, label, targetGroupId, targetGroupName, resolved: Boolean(target) };
}

/** @param {number | null} ms */
function iso(ms) {
  return ms === null ? null : new Date(ms).toISOString();
}

/**
 * One member finding as shown on an asset row.
 * @param {any} facts
 */
function assetMember(facts) {
  return {
    findingId: facts.id,
    status: facts.status,
    statusBucket: facts.bucket,
    severity: facts.severity,
    owner: facts.owner,
    targetGroupId: facts.asset.targetGroupId,
    targetGroupName: facts.asset.targetGroupName,
    openedAt: iso(facts.opened),
    slaState: facts.sla.state,
    slaDueAt: iso(facts.sla.dueAt),
    slaHoursLeft: facts.sla.hoursLeft
  };
}

/**
 * @param {string} key
 * @param {Array<{ record: Record<string, unknown>; facts: any }>} entries
 */
function buildGroup(key, entries) {
  const ranked = [...entries].sort(compareRepresentative);
  const lead = ranked[0]?.facts;
  const checkId = lead?.checkId ?? '';
  const check = lead?.check ?? null;
  const checkLabel = checkId ? plainCheckName(pick(check ?? {}, ['name', 'title']) || checkId) : '';
  const identity = lead?.identity ?? { source: 'none', title: '' };
  const verdict = lead?.verdict ?? '';

  const statusCounts = { open: 0, accepted: 0, closed: 0, other: 0 };
  /** @type {Record<string, number>} */
  const statusBreakdown = {};
  /** @type {Map<string, any>} */
  const assets = new Map();
  const owners = new Set();
  const verdicts = new Set();
  const targetGroupIds = new Set();
  /** @type {string[]} */
  const findingIds = [];
  let unassignedCount = 0;
  let severity = '';
  let earliestOpenedAt = null;
  let latestOpenedAt = null;
  let lastObservedAt = null;
  let nearestSlaDueAt = null;
  let slaBreachCount = 0;
  let openDatedCount = 0;
  let openUndatedCount = 0;

  for (const { facts } of ranked) {
    statusCounts[/** @type {'open'} */ (facts.bucket)] += 1;
    statusBreakdown[facts.status] = (statusBreakdown[facts.status] ?? 0) + 1;
    if (facts.verdict) verdicts.add(facts.verdict);
    if (facts.id) findingIds.push(facts.id);
    if (facts.asset.targetGroupId) targetGroupIds.add(facts.asset.targetGroupId);

    if (facts.severity && (!severity || facts.severityRank > findingGroupSeverityRank(severity))) severity = facts.severity;

    if (facts.owner) owners.add(facts.owner);
    else unassignedCount += 1;

    if (facts.opened !== null) {
      if (earliestOpenedAt === null || facts.opened < earliestOpenedAt) earliestOpenedAt = facts.opened;
      if (latestOpenedAt === null || facts.opened > latestOpenedAt) latestOpenedAt = facts.opened;
    }
    if (facts.observed !== null && (lastObservedAt === null || facts.observed > lastObservedAt)) lastObservedAt = facts.observed;

    const sla = facts.sla;
    if (sla.state === 'breached') slaBreachCount += 1;
    if (sla.state === 'undated') openUndatedCount += 1;
    else if (sla.dueAt !== null) openDatedCount += 1;
    if (sla.dueAt !== null && (nearestSlaDueAt === null || sla.dueAt < nearestSlaDueAt)) nearestSlaDueAt = sla.dueAt;

    const member = assetMember(facts);
    let asset = assets.get(facts.asset.key);
    if (!asset) {
      // Members are ranked, so the first finding seen for an asset is its representative.
      asset = {
        ...facts.asset,
        findingId: member.findingId,
        findingIds: [],
        members: [],
        statusCounts: { open: 0, accepted: 0, closed: 0, other: 0 },
        statusBreakdown: {},
        owners: [],
        unassignedCount: 0,
        targetGroupIds: [],
        targetGroupNames: [],
        status: member.status,
        statusBucket: member.statusBucket,
        severity: member.severity,
        owner: member.owner,
        openedAt: member.openedAt,
        slaState: member.slaState,
        slaDueAt: member.slaDueAt,
        slaHoursLeft: member.slaHoursLeft
      };
      assets.set(facts.asset.key, asset);
    }
    asset.members.push(member);
    if (member.findingId) asset.findingIds.push(member.findingId);
    asset.statusCounts[member.statusBucket] += 1;
    asset.statusBreakdown[member.status] = (asset.statusBreakdown[member.status] ?? 0) + 1;
    if (member.owner) {
      if (!asset.owners.includes(member.owner)) asset.owners.push(member.owner);
    } else {
      asset.unassignedCount += 1;
    }
    if (member.targetGroupId && !asset.targetGroupIds.includes(member.targetGroupId)) {
      asset.targetGroupIds.push(member.targetGroupId);
      asset.targetGroupNames.push(member.targetGroupName || member.targetGroupId);
    }
  }

  const assetList = [...assets.values()];
  for (const asset of assetList) asset.owners.sort((/** @type {string} */ a, /** @type {string} */ b) => a.localeCompare(b));

  return {
    key,
    title: identity.title || checkLabel || 'Evidence-backed finding',
    issueSource: identity.source,
    checkId,
    checkLabel,
    checkDescription: pick(check ?? {}, ['description']),
    vectorFamily: ranked[0] ? vectorFamilyOf(ranked[0].record, check) : '',
    verdict,
    verdictLabel: verdict ? plainVerdictLabel(verdict) : 'No conclusion yet',
    verdicts: [...verdicts],
    severity,
    findings: ranked.map((entry) => entry.record),
    findingIds,
    representativeId: lead?.id ?? '',
    statusCounts,
    statusBreakdown,
    openCount: statusCounts.open,
    assets: assetList,
    openAssetCount: assetList.filter((asset) => asset.statusCounts.open > 0).length,
    targetGroupIds: [...targetGroupIds],
    owners: [...owners].sort((a, b) => a.localeCompare(b)),
    unassignedCount,
    earliestOpenedAt: iso(earliestOpenedAt),
    latestOpenedAt: iso(latestOpenedAt),
    lastObservedAt: iso(lastObservedAt),
    nearestSlaDueAt: iso(nearestSlaDueAt),
    slaBreachCount,
    hasSlaBreach: slaBreachCount > 0,
    openDatedCount,
    openUndatedCount
  };
}

/**
 * Group findings into alerts. Pass an index from createFindingGroupIndex to share target,
 * check and per-finding work across calls; a plain context builds a throwaway index.
 * @param {unknown[]} findings
 * @param {{ targets?: unknown[]; checks?: unknown[]; targetGroups?: unknown[]; now?: number } | ReturnType<typeof createFindingGroupIndex>} [context]
 */
export function groupFindings(findings, context = {}) {
  const index = resolveIndex(context);
  /** @type {Map<string, Array<{ record: Record<string, unknown>; facts: any }>>} */
  const buckets = new Map();
  for (const raw of Array.isArray(findings) ? findings : []) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
    const record = /** @type {Record<string, unknown>} */ (raw);
    const facts = findingFacts(record, index);
    const bucket = buckets.get(facts.key);
    if (bucket) bucket.push({ record, facts });
    else buckets.set(facts.key, [{ record, facts }]);
  }
  const groups = [...buckets.entries()].map(([key, entries]) => buildGroup(key, entries));
  return sortFindingGroups(groups, 'severity');
}

/**
 * Asset lifecycle filter: an asset is in a lifecycle when any member finding is.
 * @param {{ statusCounts?: Record<string, number> } | null | undefined} asset
 * @param {string} lifecycle open | accepted | closed | other | all
 */
export function assetHasLifecycle(asset, lifecycle) {
  if (!asset) return false;
  if (!lifecycle || lifecycle === 'all') return true;
  return (asset.statusCounts?.[lifecycle] ?? 0) > 0;
}

/**
 * Member findings on an asset in one lifecycle, in representative rank order.
 * @param {{ members?: Array<{ statusBucket: string }> } | null | undefined} asset
 * @param {string} lifecycle
 */
export function assetMembersInLifecycle(asset, lifecycle) {
  const members = Array.isArray(asset?.members) ? asset.members : [];
  if (!lifecycle || lifecycle === 'all') return [...members];
  return members.filter((member) => member.statusBucket === lifecycle);
}

/**
 * Group-level SLA assessment that keeps unknown deadlines visible instead of reporting
 * them as within SLA.
 *   state: breached | due_soon | on_track | unknown (open members, none dated) | inactive (no open members)
 *   assessment: complete | partial (some open members undated) | unknown (all undated) | none (no open members)
 * @param {{ openCount?: number; slaBreachCount?: number; nearestSlaDueAt?: string | null; openDatedCount?: number; openUndatedCount?: number }} group
 * @param {number} [now]
 */
export function groupSlaSummary(group, now = Date.now()) {
  const openCount = group?.openCount ?? 0;
  const breachCount = group?.slaBreachCount ?? 0;
  const undated = group?.openUndatedCount ?? 0;
  const dated = group?.openDatedCount ?? Math.max(0, openCount - undated);
  const due = timestamp(group?.nearestSlaDueAt);
  const hoursLeft = due === null ? null : Math.round((due - now) / HOUR_MS);

  const assessment = openCount === 0 ? 'none' : undated === 0 ? 'complete' : dated === 0 ? 'unknown' : 'partial';
  let state = 'inactive';
  if (breachCount > 0) state = 'breached';
  else if (due !== null) state = due - now <= DUE_SOON_MS ? 'due_soon' : 'on_track';
  else if (openCount > 0) state = 'unknown';

  let label = 'No clock';
  if (state === 'breached') label = `${breachCount} overdue`;
  else if (assessment === 'unknown') label = 'SLA unknown';
  else if (assessment === 'partial') label = 'Partially assessed';
  else if (state === 'due_soon' || state === 'on_track') label = 'Within SLA';

  return {
    state,
    assessment,
    label,
    breachCount,
    datedOpenCount: dated,
    undatedOpenCount: undated,
    nearestDueAt: due === null ? null : new Date(due).toISOString(),
    hoursLeft
  };
}

/**
 * @param {Array<any>} groups
 * @param {string} sort severity | assets | recent | oldest | sla | title
 */
export function sortFindingGroups(groups, sort) {
  const copy = Array.isArray(groups) ? [...groups] : [];
  const ts = (/** @type {unknown} */ value, /** @type {number} */ fallback) => timestamp(value) ?? fallback;
  copy.sort((left, right) => {
    const tieBreak = left.title.localeCompare(right.title) || left.key.localeCompare(right.key);
    if (sort === 'title') return tieBreak;
    if (sort === 'assets') return right.assets.length - left.assets.length || tieBreak;
    if (sort === 'sla') return ts(left.nearestSlaDueAt, Number.MAX_SAFE_INTEGER) - ts(right.nearestSlaDueAt, Number.MAX_SAFE_INTEGER) || tieBreak;
    // Recently opened ranks by the newest member opening, so a long-lived alert that just
    // reached another asset rises; oldest ranks by the first opening.
    if (sort === 'recent') return ts(right.latestOpenedAt ?? right.earliestOpenedAt, 0) - ts(left.latestOpenedAt ?? left.earliestOpenedAt, 0) || tieBreak;
    if (sort === 'oldest') return ts(left.earliestOpenedAt, Number.MAX_SAFE_INTEGER) - ts(right.earliestOpenedAt, Number.MAX_SAFE_INTEGER) || tieBreak;
    return (right.openCount > 0 ? 1 : 0) - (left.openCount > 0 ? 1 : 0)
      || findingGroupSeverityRank(right.severity) - findingGroupSeverityRank(left.severity)
      || right.assets.length - left.assets.length
      || tieBreak;
  });
  return copy;
}

/**
 * @param {Array<{ key: string }>} groups
 * @param {string | null | undefined} key
 */
export function findGroupByKey(groups, key) {
  if (!key || !Array.isArray(groups)) return null;
  return groups.find((group) => group.key === key) ?? null;
}

/**
 * The classic queue's filter contract, shared by both Refined views. Filtering runs on
 * individual findings first; groups are then built from the matches only.
 * @param {unknown} finding
 * @param {{ status?: string; severity?: string; owner?: string; targetGroup?: string; search?: string }} filters
 * @param {{ searchText?: (finding: Record<string, unknown>) => string }} [options]
 */
export function matchesFindingFilters(finding, filters, options = {}) {
  const record = asRecord(finding);
  const status = filters.status ?? 'all';
  if (status !== 'all' && findingStatusBucket(record) !== status) return false;
  const severity = pick(record, ['severity']) || 'unknown';
  if (filters.severity && filters.severity !== 'all' && severity !== filters.severity) return false;
  const owner = ownerOf(record) || 'unassigned';
  if (filters.owner && filters.owner !== 'all' && owner !== filters.owner) return false;
  const groupId = pick(record, ['target_group_id']);
  if (filters.targetGroup && filters.targetGroup !== 'all' && groupId !== filters.targetGroup) return false;
  const needle = String(filters.search ?? '').trim().toLowerCase();
  if (!needle) return true;
  const haystack = [
    pick(record, ['id']),
    pick(record, ['title', 'summary']),
    pick(record, ['check_id']),
    pick(record, ['target_id', 'target_hostname', 'target_value']),
    owner,
    groupId,
    options.searchText ? options.searchText(record) : ''
  ].join(' ').toLowerCase();
  return haystack.includes(needle);
}
