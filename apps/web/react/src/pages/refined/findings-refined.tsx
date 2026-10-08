import { useCallback, useEffect, useMemo, useRef, useState, type HTMLAttributes } from 'react';
import { CircleCheck, CircleDot, Clock, Search, ShieldMinus, TriangleAlert } from 'lucide-react';
import { FindingCard } from '../../components/findings/finding-card';
import { Badge } from '../../components/ui/badge';
import { Button } from '../../components/ui/button';
import { EmptyState } from '../../components/ui/empty-state';
import { Select } from '../../components/ui/select';
import { DataTable, type TableColumn } from '../../components/ui/table';
import { Toast } from '../../components/ui/toast';
import { useInspectorRef, useListReturnState, useOpenInspector, useRestoreListPosition } from '../../components/evidence/use-inspector';
import { getRouteParam, replaceRouteParams } from '../../lib/route-params';
import { navScopeKey } from '../../lib/nav-state.mjs';
import { useInteractionHold, useStableList } from '../../components/evidence/use-stable-list';
import type { DesignVariant } from '../../lib/design-variant';
import {
  createFindingGroupIndex,
  findingGroupHref,
  findingSlaState,
  findingStatusBucket,
  groupFindings,
  groupSlaSummary,
  sortFindingGroups,
  type FindingGroup,
  type FindingGroupSortKey,
  type FindingSlaStateKey
} from '../../lib/finding-groups.mjs';
import {
  FINDING_SEVERITY_CLASSES,
  FINDING_SEVERITY_CLASS_LABELS,
  FINDING_STATUS_GROUPS,
  FINDING_STATUS_LABELS,
  FINDINGS_LIMIT_MAX,
  findingSeverityClass,
  findingStatusFilter,
  findingsComplete,
  type FindingStatus
} from '../../lib/findings-query.mjs';
import { useFindingStatusTotals, useFindingsPage, useProgressiveFindings, type StatusTotals } from '../../components/findings/use-server-findings';
import { findingStatus } from '../../lib/finding-lifecycle.mjs';
import { computeFindingKpis, findingAssetLabel, summarizeFindingStatuses } from '../../lib/findings-helpers';
import type { DataItem, PortalConfig, PortalData, Session } from '../../lib/types';
import { formatDate, formatNumber, formatSeverityLabel, pluralize } from '../../lib/utils';
import './findings-refined.css';

/**
 * Everything the Refined findings view needs. Refresh, busy, and feedback state stay owned
 * by ValidationSurfacePage; triage mutations live on finding-detail, unchanged.
 */
export interface FindingsRefinedProps {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  /** Legacy props kept for callers; the customer UI ships one presentation and ignores them. */
  variant?: DesignVariant;
  onVariantChange?: (next: DesignVariant) => void;
  /** '' when idle, 'refresh' while the surface refresh runs. */
  busy: string;
  message: string;
  error: string;
  findingKpis: ReturnType<typeof computeFindingKpis>;
  /** data.loadErrors.findings ?? '' */
  findingsLoadError: string;
  /** handleSurfaceRefresh: refreshes all route datasets and reports failures. */
  onRefresh: () => void;
}

type ViewMode = 'grouped' | 'all';
/** One exact server status, or every status. No status filter spans several statuses. */
type StatusFilter = FindingStatus | 'all';

const EMPTY_FINDINGS: DataItem[] = [];
// The server compares canonical severity classes (`S2` is `high`), so the filter offers each class once.
const SEVERITY_OPTIONS = [
  { value: 'all', label: 'All severities' },
  ...FINDING_SEVERITY_CLASSES.map((value) => ({ value, label: FINDING_SEVERITY_CLASS_LABELS[value] })),
];

function severityChoice(value: string | undefined) {
  const raw = (value ?? '').trim();
  return !raw || raw.toLowerCase() === 'all' ? 'all' : findingSeverityClass(raw);
}

const SORT_KEYS: FindingGroupSortKey[] = ['severity', 'assets', 'recent', 'oldest', 'sla', 'title'];

const VIEW_STORAGE_KEY = 'astranull.findings-refined.view';
const PAGE_SIZES = [25, 50, 100] as const;
const SORT_OPTIONS: Array<{ value: FindingGroupSortKey; label: string }> = [
  { value: 'severity', label: 'Worst severity' },
  { value: 'assets', label: 'Most affected assets' },
  { value: 'recent', label: 'Recently opened' },
  { value: 'oldest', label: 'Oldest first' },
  { value: 'sla', label: 'SLA remaining' },
  { value: 'title', label: 'Title A to Z' }
];

function readStoredView(): ViewMode {
  try {
    return window.localStorage.getItem(VIEW_STORAGE_KEY) === 'all' ? 'all' : 'grouped';
  } catch {
    return 'grouped';
  }
}

function storeView(view: ViewMode) {
  try {
    window.localStorage.setItem(VIEW_STORAGE_KEY, view);
  } catch {
    // Per-viewer convenience only; blocked storage keeps the in-memory choice.
  }
}

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

export function severityTone(severity: string) {
  const key = severity.toLowerCase();
  if (['critical', 'high', 's1', 's2'].includes(key)) return 'danger' as const;
  if (['medium', 'moderate', 's3'].includes(key)) return 'warn' as const;
  return 'muted' as const;
}

export function statusTone(status: string) {
  const bucket = findingStatusBucket({ status });
  if (bucket === 'closed') return 'success' as const;
  if (bucket === 'accepted') return 'info' as const;
  if (bucket === 'open' || status === 'remediation_pending') return 'warn' as const;
  return 'muted' as const;
}

/** Status badge: text plus icon, never color alone. */
export function FindingStatusBadge({ status }: { status: string }) {
  const bucket = findingStatusBucket({ status });
  const Icon = bucket === 'closed' ? CircleCheck : bucket === 'accepted' ? ShieldMinus : CircleDot;
  return (
    <Badge tone={statusTone(status)}>
      <Icon size={12} />
      {status.replace(/_/g, ' ')}
    </Badge>
  );
}

/** SLA badge for one finding's recorded SLA position. */
export function slaPresentation(state: FindingSlaStateKey, hoursLeft: number | null) {
  if (state === 'breached') return { label: 'Overdue', tone: 'danger' as const, overdue: true };
  if (state === 'due_soon') return { label: `${Math.max(0, hoursLeft ?? 0)}h left`, tone: 'warn' as const, overdue: false };
  if (state === 'on_track') return { label: 'On track', tone: 'muted' as const, overdue: false };
  if (state === 'undated') return { label: 'Not dated', tone: 'muted' as const, overdue: false };
  return { label: 'No SLA clock', tone: 'muted' as const, overdue: false };
}

export function SlaBadge({ label, tone, overdue }: { label: string; tone: 'danger' | 'warn' | 'muted'; overdue: boolean }) {
  return (
    <Badge tone={tone}>
      {overdue ? <TriangleAlert size={12} /> : <Clock size={12} />}
      {label}
    </Badge>
  );
}

function groupSla(group: FindingGroup) {
  const summary = groupSlaSummary(group);
  // Undated open members cannot be assessed, so the hint says so instead of implying compliance.
  const undatedNote = summary.undatedOpenCount > 0 ? `${summary.undatedOpenCount} not dated` : '';
  if (summary.state === 'breached') {
    return {
      badge: { label: group.findings.length > 1 ? `${summary.breachCount} overdue` : 'Overdue', tone: 'danger' as const, overdue: true },
      hint: [summary.nearestDueAt ? `Earliest due ${formatDate(summary.nearestDueAt)}` : '', undatedNote].filter(Boolean).join(', ')
    };
  }
  if (summary.nearestDueAt) {
    const hoursLeft = Math.max(0, summary.hoursLeft ?? 0);
    const badge = summary.assessment === 'partial'
      ? { label: 'Partially assessed', tone: 'warn' as const, overdue: false }
      : summary.state === 'due_soon'
        ? { label: `${hoursLeft}h left`, tone: 'warn' as const, overdue: false }
        : { label: 'On track', tone: 'muted' as const, overdue: false };
    return { badge, hint: [`Due ${formatDate(summary.nearestDueAt)}`, undatedNote].filter(Boolean).join(', ') };
  }
  if (summary.state === 'unknown') return { badge: { label: 'SLA unknown', tone: 'muted' as const, overdue: false }, hint: 'No opened date recorded' };
  return { badge: { label: 'No SLA clock', tone: 'muted' as const, overdue: false }, hint: 'No open findings' };
}

function OwnerCell({ owners, unassigned }: { owners: string[]; unassigned: number }) {
  if (owners.length === 0) return <span className="rf-cell-muted">Unassigned</span>;
  const [first = ''] = owners;
  return (
    <span className="rf-cell-stack">
      <strong>{owners.length === 1 ? first : `${owners.length} owners`}</strong>
      {owners.length > 1 ? <small>{owners.slice(0, 2).join(', ')}{owners.length > 2 ? ` +${owners.length - 2}` : ''}</small> : null}
      {unassigned > 0 ? <small>{unassigned} unassigned</small> : null}
    </span>
  );
}

function navigate(href: string) {
  window.location.hash = href.replace(/^#/, '');
}

/** Router entry: the current refined findings presentation is the only customer view. */
export function FindingsPage({ data, config, session, onRefresh }: { data: PortalData; config: PortalConfig; session: Session; onRefresh: () => Promise<void> }) {
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const findingKpis = useMemo(() => computeFindingKpis(data.findings), [data.findings]);
  const refresh = useCallback(async () => {
    setBusy('refresh');
    setError('');
    try {
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Refresh failed.');
    } finally {
      setBusy('');
    }
  }, [onRefresh]);
  return (
    <FindingsRefined
      data={data}
      config={config}
      session={session}
      busy={busy}
      message=""
      error={error}
      findingKpis={findingKpis}
      findingsLoadError={data.loadErrors.findings ?? ''}
      onRefresh={() => void refresh()}
    />
  );
}

export function FindingsRefined(props: FindingsRefinedProps) {
  const { data, message, error, session, config } = props;
  const { initial, save } = useListReturnState(session, 'findings');
  // An explicit address predicate (for example a dashboard count) wins over remembered filters.
  const urlStatus = getRouteParam('status');
  const urlSeverity = getRouteParam('severity');
  // Exact-domain links override remembered filters.
  const urlTargetRaw = getRouteParam('target_id') || getRouteParam('target');
  const urlTarget = /^[A-Za-z0-9_.:-]{1,128}$/.test(urlTargetRaw) ? urlTargetRaw : '';
  // A linked count opens exactly its own predicate, so remembered search, filters and page do not mix in.
  const [urlPredicate] = useState(() => Boolean(urlStatus || urlSeverity || urlTarget));
  const initialFilters: Record<string, string> = urlPredicate
    ? { ...(urlStatus ? { status: urlStatus } : {}), ...(urlSeverity ? { severity: urlSeverity } : {}), ...(urlTarget ? { target: urlTarget } : {}) }
    : { ...(initial.filters ?? {}) };
  const [view, setView] = useState<ViewMode>(() => (initial.view === 'all' || initial.view === 'grouped' ? initial.view : readStoredView()));
  const [statusFilter, setStatusFilter] = useState<StatusFilter>(() => initialStatus(initialFilters.status, urlPredicate));
  const [severityFilter, setSeverityFilter] = useState(() => severityChoice(initialFilters.severity));
  const [targetFilter, setTargetFilter] = useState(initialFilters.target ?? 'all');
  const [search, setSearch] = useState(initialFilters.q ?? '');
  const [debouncedSearch, setDebouncedSearch] = useState((initialFilters.q ?? '').trim());
  const [sort, setSort] = useState<FindingGroupSortKey>(() => (SORT_KEYS.includes(initial.sort as FindingGroupSortKey) ? initial.sort as FindingGroupSortKey : 'severity'));
  const [pageSize, setPageSize] = useState<(typeof PAGE_SIZES)[number]>(() => (PAGE_SIZES as readonly number[]).includes(initial.pageSize ?? 0) ? initial.pageSize as (typeof PAGE_SIZES)[number] : 25);
  // Each finding: the 1-based server page. Grouped: a 0-based page over the groups built so far.
  const [page, setPage] = useState(() => (urlPredicate ? 1 : Math.max(1, initial.page ?? 1)));
  const [groupPage, setGroupPage] = useState(0);
  const [reloadKey, setReloadKey] = useState(0);
  const [filtersHydrated, setFiltersHydrated] = useState(false);
  const inspected = useInspectorRef();
  const { holding, handlers: holdHandlers } = useInteractionHold();
  const idOfFinding = useCallback((finding: DataItem) => getString(finding, ['id']), []);
  const openInspector = useOpenInspector();

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedSearch(search.trim()), 250);
    return () => window.clearTimeout(timer);
  }, [search]);

  // A new linked predicate while this page is open (for example from the inspector) replaces the
  // current filters the same way a cold link does; other address changes leave them alone.
  const linkedRef = useRef(urlPredicate ? `${urlStatus}|${urlSeverity}|${urlTarget}` : '');
  useEffect(() => {
    function onHashChange() {
      const status = getRouteParam('status');
      const severity = getRouteParam('severity');
      const rawTarget = getRouteParam('target_id') || getRouteParam('target');
      const target = /^[A-Za-z0-9_.:-]{1,128}$/.test(rawTarget) ? rawTarget : '';
      if (!status && !severity && !target) return;
      const linked = `${status}|${severity}|${target}`;
      if (linked === linkedRef.current) return;
      linkedRef.current = linked;
      setStatusFilter(initialStatus(status, true));
      setSeverityFilter(severityChoice(severity));
      setTargetFilter(target || 'all');
      setSearch('');
      setDebouncedSearch('');
    }
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  // A filter change returns to the first page, but the restored page survives the first render.
  useEffect(() => {
    if (!filtersHydrated) {
      setFiltersHydrated(true);
      return;
    }
    setPage(1);
    setGroupPage(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view, statusFilter, severityFilter, targetFilter, debouncedSearch, pageSize]);

  // Once the predicate itself changes (not the view or page size), the linked one no longer describes
  // the address; a repeat link applies again.
  const predicateKey = `${statusFilter}|${severityFilter}|${targetFilter}|${debouncedSearch}`;
  const shownPredicate = useRef(predicateKey);
  useEffect(() => {
    if (shownPredicate.current === predicateKey) return;
    shownPredicate.current = predicateKey;
    replaceRouteParams({ status: null, severity: null, target_id: null, target: null });
    linkedRef.current = '';
  }, [predicateKey]);

  useEffect(() => {
    setGroupPage(0);
  }, [sort]);

  useEffect(() => {
    save({
      view,
      sort,
      page,
      pageSize,
      filters: { status: statusFilter, severity: severityFilter, target: targetFilter, q: debouncedSearch },
    });
  }, [save, view, sort, page, pageSize, statusFilter, severityFilter, targetFilter, debouncedSearch]);

  // Every count and list below is a server predicate. The same filters drive the status totals,
  // the paged list and the grouped read, so a count always opens the rows it reports.
  const baseFilters = useMemo(() => ({
    q: debouncedSearch,
    severity: severityFilter === 'all' ? '' : severityFilter,
    target_id: targetFilter === 'all' ? '' : targetFilter,
  }), [debouncedSearch, severityFilter, targetFilter]);
  const listFilters = useMemo(() => ({ ...baseFilters, status: statusFilter === 'all' ? '' : statusFilter }), [baseFilters, statusFilter]);
  const filtered = Boolean(baseFilters.q || baseFilters.severity || baseFilters.target_id);
  const statusTotals = useFindingStatusTotals(config, session, baseFilters, reloadKey);
  // The summary strip is the whole tenant; it needs its own read only while a filter is applied.
  const unfilteredTotals = useFindingStatusTotals(config, session, {}, reloadKey, filtered);
  const estateTotals = filtered ? unfilteredTotals : statusTotals;
  const openSample = useFindingsPage(config, session, { status: 'open', limit: FINDINGS_LIMIT_MAX }, reloadKey);
  const serverPage = useFindingsPage(config, session, { ...listFilters, limit: pageSize, page }, reloadKey, view === 'all');
  const grouped = useProgressiveFindings(config, session, listFilters, reloadKey, view === 'grouped');

  const sourceRows = view === 'all' ? serverPage.envelope?.items ?? EMPTY_FINDINGS : grouped.items;
  // Keyed on the predicate of the rows on screen, which lags the requested one while a read is in
  // flight, so the answer to a filter, page or "read more" request is never held as an update.
  const listKey = view === 'all' ? `each|${serverPage.envelopePath}` : `grouped|${grouped.itemsKey}|${grouped.pagesRead}`;
  // Same-scope refreshes never move the row under the pointer, the focused row or the inspected
  // finding; they wait behind "Show updates". A filter, page or scope change applies at once.
  const live = useStableList(sourceRows, {
    scope: `${navScopeKey(session) || 'anon'}|findings|${listKey}`,
    idOf: idOfFinding,
    hold: holding || Boolean(inspected),
  });
  const findings = live.items;

  function changeView(next: ViewMode) {
    setView(next);
    storeView(next);
  }

  function refresh() {
    setReloadKey((value) => value + 1);
    props.onRefresh();
  }

  const groupIndex = useMemo(
    () => createFindingGroupIndex({ targets: data.targets, checks: data.checks }),
    [data.targets, data.checks]
  );

  // Groups are built from the rows read so far. Until every matching row is read they are labelled
  // partial: a group's members, targets and status mix may still grow.
  const builtGroups = useMemo(() => (view === 'grouped' ? groupFindings(findings, groupIndex) : []), [view, findings, groupIndex]);
  const sortedGroups = useMemo(() => sortFindingGroups(builtGroups, sort), [builtGroups, sort]);
  const groupsComplete = grouped.complete;

  // Open-finding summary: exact totals from the server; SLA, groups and targets from the newest open
  // findings, labelled when the server holds more open findings than one page can carry.
  const openEnvelope = openSample.envelope;
  const openRows = openEnvelope?.items ?? EMPTY_FINDINGS;
  const openComplete = findingsComplete(openEnvelope, openRows.length);
  const openKpis = useMemo(() => computeFindingKpis(openRows), [openRows]);
  const openGroups = useMemo(() => groupFindings(openRows, groupIndex), [openRows, groupIndex]);
  const openAssets = useMemo(() => {
    const keys = new Set<string>();
    openGroups.forEach((group) => group.assets.forEach((asset) => keys.add(asset.key)));
    return keys.size;
  }, [openGroups]);

  const targetOptions = useMemo(() => {
    const options = [{ value: 'all', label: 'All domains' }, ...data.targets.map((target) => ({ value: getString(target, ['id']), label: getString(target, ['value', 'id']) }))];
    if (targetFilter !== 'all' && !options.some((option) => option.value === targetFilter)) options.push({ value: targetFilter, label: 'Unavailable domain' });
    return options;
  }, [data.targets, targetFilter]);

  const envelope = view === 'all' ? serverPage.envelope : grouped.envelope;
  const matchTotal = envelope?.total ?? null;
  const serverPages = Math.max(1, serverPage.envelope?.pages ?? 1);
  const listError = view === 'all' ? serverPage.error : grouped.error && grouped.state === 'error' ? grouped.error : '';
  const listLoading = view === 'all' ? serverPage.state === 'loading' && !serverPage.envelope : grouped.state === 'loading';
  const groupCount = sortedGroups.length;
  const groupPageCount = Math.max(1, Math.ceil(groupCount / pageSize));
  const currentGroupPage = Math.min(groupPage, groupPageCount - 1);
  const groupPageStart = currentGroupPage * pageSize;
  const visibleGroups = sortedGroups.slice(groupPageStart, groupPageStart + pageSize);
  const pageStart = ((serverPage.envelope?.page ?? page) - 1) * pageSize;
  useRestoreListPosition(Boolean(envelope) && findings.length > 0, initial);
  const inspectedFindingId = inspected && (inspected.entry === 'finding' || inspected.entry === 'group_member') ? inspected.finding_id ?? '' : '';

  function inspectFinding(finding: DataItem) {
    const id = getString(finding, ['id']);
    if (!id) return;
    const focusKey = `finding-${id}`;
    save({ selectedRowId: id, focusKey });
    openInspector({ entry: 'finding', finding_id: id, target_id: getString(finding, ['target_id']) || undefined, check_id: getString(finding, ['check_id']) || undefined }, focusKey);
  }

  const groupColumns: TableColumn<FindingGroup>[] = [
    {
      key: 'alert',
      label: 'Finding group',
      render: (group) => {
        const shown = group.assets.slice(0, 3);
        const remaining = group.assets.length - shown.length;
        return (
          <a
            className="rf-alert-link"
            href={findingGroupHref(group.key)}
            data-focus-key={`group-${group.key}`}
            onClick={() => save({ selectedRowId: group.key, focusKey: `group-${group.key}` })}
            aria-label={`Open finding group ${group.title}, ${formatSeverityLabel(group.severity)}, ${group.assets.length}${groupsComplete ? '' : ' or more'} ${pluralize(group.assets.length, 'affected target')}`}
          >
            <strong className="rf-alert-title">{group.title}</strong>
            {group.checkLabel ? <span className="rf-alert-check">{group.checkLabel}</span> : null}
            <span className="rf-asset-chips">
              {shown.map((asset) => (
                <span key={asset.key} className="rf-chip rf-asset-chip" title={asset.host || asset.label}>{asset.label}</span>
              ))}
              {remaining > 0 ? <span className="rf-chip rf-asset-more">+{remaining} more</span> : null}
            </span>
          </a>
        );
      }
    },
    {
      key: 'severity',
      label: 'Worst severity',
      render: (group) => <Badge tone={severityTone(group.severity)}>{formatSeverityLabel(group.severity)}</Badge>
    },
    {
      key: 'assets',
      label: 'Affected targets',
      render: (group) => (
        <span className="rf-cell-stack">
          <strong className="tabular-nums">{group.assets.length}{groupsComplete ? '' : '+'}</strong>
          <small>{group.openAssetCount} with open findings · {group.findings.length} {pluralize(group.findings.length, 'finding')}{groupsComplete ? '' : ' read so far'}</small>
        </span>
      )
    },
    {
      key: 'status',
      label: 'Status',
      render: (group) => (
        <span className="rf-cell-stack">
          <FindingStatusBadge status={findingStatus(group.findings[0] ?? {})} />
          {group.findings.length > 1 ? <small>{summarizeFindingStatuses(group.statusBreakdown)}</small> : null}
        </span>
      )
    },
    {
      key: 'sla',
      label: 'SLA',
      render: (group) => {
        const sla = groupSla(group);
        return <span className="rf-cell-stack"><SlaBadge {...sla.badge} />{sla.hint ? <small>{sla.hint}</small> : null}</span>;
      }
    },
    {
      key: 'owner',
      label: 'Owner',
      render: (group) => <OwnerCell owners={group.owners} unassigned={group.owners.length ? group.unassignedCount : 0} />
    }
  ];

  const findingColumns: TableColumn<DataItem>[] = [
    {
      key: 'finding',
      label: 'Finding',
      render: (finding) => (
        <FindingCard
          finding={finding}
          checks={data.checks}
          targets={data.targets}
          active={getString(finding, ['id']) === inspectedFindingId}
          onOpen={() => inspectFinding(finding)}
        />
      )
    },
    {
      key: 'severity',
      label: 'Severity',
      render: (finding) => {
        const severity = getString(finding, ['severity'], 'unknown');
        return <Badge tone={severityTone(severity)}>{formatSeverityLabel(severity)}</Badge>;
      }
    },
    {
      key: 'asset',
      label: 'Target',
      render: (finding) => <span className="rf-mono">{findingAssetLabel(finding, data.targets)}</span>
    },
    {
      key: 'status',
      label: 'Status',
      render: (finding) => <FindingStatusBadge status={findingStatus(finding)} />
    },
    {
      key: 'sla',
      label: 'SLA',
      render: (finding) => {
        const sla = findingSlaState(finding);
        return (
          <span className="rf-cell-stack">
            <SlaBadge {...slaPresentation(sla.state, sla.hoursLeft)} />
            {sla.dueAt !== null ? <small>Due {formatDate(sla.dueAt)}</small> : null}
          </span>
        );
      }
    },
    {
      key: 'owner',
      label: 'Owner',
      render: (finding) => {
        const owner = getString(finding, ['assignee', 'owner', 'rem_owner']);
        return owner ? owner : <span className="rf-cell-muted">Unassigned</span>;
      }
    }
  ];

  // The primary anchor is each row's single keyboard stop; the row click is a pointer convenience.
  function groupRowProps(group: FindingGroup): Omit<HTMLAttributes<HTMLTableRowElement>, 'key'> {
    return {
      className: 'rf-clickable-row',
      onClick: (event) => {
        if ((event.target as HTMLElement).closest('a, button')) return;
        save({ selectedRowId: group.key, focusKey: `group-${group.key}` });
        navigate(findingGroupHref(group.key));
      },
    };
  }

  function findingRowProps(finding: DataItem): Omit<HTMLAttributes<HTMLTableRowElement>, 'key'> {
    const id = getString(finding, ['id']);
    if (!id) return {};
    const selected = id === inspectedFindingId;
    return {
      className: selected ? 'rf-clickable-row is-selected' : 'rf-clickable-row',
      'aria-current': selected ? 'true' : undefined,
      onClick: (event) => {
        if ((event.target as HTMLElement).closest('a, button')) return;
        inspectFinding(finding);
      },
    };
  }

  function clearFilters() {
    setStatusFilter('all');
    setSeverityFilter('all');
    setTargetFilter('all');
    setSearch('');
  }

  const estateEmpty = estateTotals.totals.all === 0;
  const emptyState = (
    <EmptyState
      icon={TriangleAlert}
      title="No matching findings"
      body={estateEmpty ? 'Findings appear only after a bounded check on a target publishes an evidence-backed gap.' : envelope?.emptyReason ?? 'No finding matches the current status, severity, group or search.'}
      actionLabel={estateEmpty ? 'Open targets' : 'Clear filters'}
      actionHref={estateEmpty ? '#targets' : undefined}
      onAction={estateEmpty ? undefined : clearFilters}
    />
  );

  const total = (status: string) => {
    const value = estateTotals.totals[status];
    return typeof value === 'number' ? value : null;
  };
  const closedTotal = ['resolved', 'closed', 'false_positive'].reduce<number | null>((sum, status) => (sum === null || total(status) === null ? null : sum + (total(status) as number)), 0);
  const statValue = (value: number | null) => (estateTotals.state === 'error' ? 'Unavailable' : value === null ? (estateTotals.state === 'loading' ? '...' : 'Not reported') : formatNumber(value));
  const sampleNote = openComplete ? '' : openEnvelope?.total ? ` Based on the newest ${formatNumber(openRows.length)} of ${formatNumber(openEnvelope.total)} open findings.` : '';

  return (
    <div className="content refined rf-findings">
      <header className="rf-header">
        <div className="rf-header-copy">
          <p className="rf-eyebrow">Triage &amp; remediate</p>
          <h1>Findings</h1>
          <p className="rf-header-description">
            Evidence-backed gaps on your declared targets. Select a finding to see the evidence that opened it beside the queue.
          </p>
        </div>
        <div className="rf-header-actions">
          <Button variant="secondary" size="sm" loading={props.busy === 'refresh'} disabled={props.busy !== ''} onClick={refresh}>Refresh</Button>
        </div>
      </header>

      <section className="rf-summary-strip rf-findings-summary" aria-label="Finding summary">
        <div className="rf-stat">
          <span className="rf-stat-label">Open</span>
          <span className="rf-stat-value">{statValue(total('open'))}</span>
          <span className="rf-stat-hint">{openSample.state === 'ready' && openComplete ? openKpis.openSeverityBreakdown : 'Server count of every open finding'}</span>
        </div>
        <div className="rf-stat">
          <span className="rf-stat-label">In progress</span>
          <span className="rf-stat-value">{statValue(total('in_progress'))}</span>
          <span className="rf-stat-hint">Server count</span>
        </div>
        <div className="rf-stat">
          <span className="rf-stat-label">Accepted risk</span>
          <span className="rf-stat-value">{statValue(total('accepted_risk'))}</span>
          <span className="rf-stat-hint">{total('accepted') ? `Plus ${formatNumber(total('accepted') ?? 0)} accepted` : 'Risk acceptance on record'}</span>
        </div>
        <div className="rf-stat">
          <span className="rf-stat-label">Closed</span>
          <span className="rf-stat-value">{statValue(closedTotal)}</span>
          <span className="rf-stat-hint">Resolved, closed and false positive</span>
        </div>
        <div className="rf-stat" data-tone={openKpis.slaBreachCount > 0 ? 'danger' : undefined}>
          <span className="rf-stat-label">SLA breached</span>
          <span className="rf-stat-value">
            {openSample.state !== 'ready' ? (openSample.state === 'error' ? 'Unavailable' : '...') : (
              <>
                {openKpis.slaBreachCount > 0 ? <TriangleAlert size={16} aria-hidden="true" /> : null}
                {formatNumber(openKpis.slaBreachCount)}{openComplete ? '' : '+'}
              </>
            )}
          </span>
          <span className="rf-stat-hint">{openSample.state === 'ready' ? (openRows.length === 0 ? 'No open findings' : `Open past severity SLA.${sampleNote}`) : 'Open past severity SLA'}</span>
        </div>
        <div className="rf-stat">
          <span className="rf-stat-label">Affected targets</span>
          <span className="rf-stat-value">{openSample.state === 'ready' ? `${formatNumber(openAssets)}${openComplete ? '' : '+'}` : openSample.state === 'error' ? 'Unavailable' : '...'}</span>
          <span className="rf-stat-hint">Distinct targets with an open finding.{openSample.state === 'ready' ? sampleNote : ''}</span>
        </div>
      </section>

      {message || error ? (
        <Toast
          message={error || message}
          tone={error ? 'error' : 'success'}
          duration={5000}
        />
      ) : null}

      <section className="rf-section" aria-labelledby="rf-findings-queue">
        <div className="rf-section-head">
          <h2 id="rf-findings-queue">Finding queue</h2>
          <div className="rf-segmented" role="group" aria-label="Finding view">
            <button type="button" aria-pressed={view === 'grouped'} onClick={() => changeView('grouped')}>Grouped by issue</button>
            <button type="button" aria-pressed={view === 'all'} onClick={() => changeView('all')}>Each finding</button>
          </div>
        </div>

        <div className="rf-panel rf-findings-filters">
          <div className="rf-status-groups" role="group" aria-label="Finding status filters">
            <button type="button" className="rf-status-chip" aria-pressed={statusFilter === 'all'} onClick={() => setStatusFilter('all')}>
              All
              <span className="rf-tab-count tabular-nums">{countLabel(statusTotals, 'all')}</span>
            </button>
            {FINDING_STATUS_GROUPS.map((group) => (
              <span key={group.id} className="rf-status-group">
                <span className="rf-status-group-label" aria-hidden="true">{group.label}</span>
                {group.statuses.map((status) => (
                  <button key={status} type="button" className="rf-status-chip" aria-pressed={statusFilter === status} onClick={() => setStatusFilter(status)}>
                    {FINDING_STATUS_LABELS[status]}
                    <span className="rf-tab-count tabular-nums">{countLabel(statusTotals, status)}</span>
                  </button>
                ))}
              </span>
            ))}
          </div>
          {statusTotals.state === 'error' ? <p className="rf-result-count" role="alert">Status counts are unavailable: {statusTotals.error}</p> : null}
          <div className="rf-filter-grid">
            <label className="field rf-search">
              <span>Search</span>
              <span className="rf-search-control">
                <Search className="rf-search-icon" size={15} aria-hidden="true" />
                <input
                  className="input"
                  type="search"
                  value={search}
                  maxLength={200}
                  aria-label="Search findings by title, finding ID, check ID, target ID, group ID, or owner"
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Title, finding, check, target, group or owner"
                />
              </span>
            </label>
            <Select label="Severity" value={severityFilter} options={SEVERITY_OPTIONS} onChange={setSeverityFilter} />
            <Select label="Domain" value={targetFilter} options={targetOptions} onChange={setTargetFilter} />
            {view === 'grouped' ? <Select label="Sort groups" value={sort} options={SORT_OPTIONS} onChange={(value) => setSort(value as FindingGroupSortKey)} /> : null}
          </div>
          <p className="rf-result-count" aria-live="polite">
            {matchTotal === null ? (
              envelope ? 'This server did not report a total for these filters, so no count is shown.' : 'Counting matching findings.'
            ) : view === 'grouped' ? (
              <>
                <span className="tabular-nums">{formatNumber(groupCount)}</span> {pluralize(groupCount, 'finding group')} built from <span className="tabular-nums">{formatNumber(grouped.items.length)}</span> of <span className="tabular-nums">{formatNumber(matchTotal)}</span> matching {pluralize(matchTotal, 'finding')}.
                {groupsComplete ? ' Every matching finding is read, so groups and their counts are complete.' : ' Groups and their counts are partial until every matching finding is read.'}
              </>
            ) : (
              <><span className="tabular-nums">{formatNumber(matchTotal)}</span> matching {pluralize(matchTotal, 'finding')}, newest first as the server orders them. Select a row to view its evidence.</>
            )}
          </p>
        </div>

        {live.pending ? (
          <div className="live-update-pill" role="status">
            <span>
              Newer results arrived
              {live.added ? ` (${live.added} new)` : ''}
              {live.removed ? ` (${live.removed} no longer listed)` : ''}
              {!live.added && !live.removed ? ' (changed records)' : ''}
              . List held as of {formatDate(live.committedAt)}.
            </span>
            <Button size="sm" variant="secondary" onClick={live.apply}>Show updates</Button>
          </div>
        ) : null}

        {listLoading ? (
          <EmptyState icon={TriangleAlert} variant="skeleton" title="Loading findings" body="Reading matching findings from the server." />
        ) : (
          <div className="rf-panel rf-panel-flush rf-findings-table rf-stack-table" {...holdHandlers}>
            {view === 'grouped' ? (
              <DataTable
                columns={groupColumns}
                items={visibleGroups}
                getRowId={(group) => group.key}
                getRowProps={groupRowProps}
                loadError={listError}
                onRetry={grouped.retry}
                empty={emptyState}
              />
            ) : (
              <DataTable
                columns={findingColumns}
                items={findings}
                getRowId={(finding, index) => getString(finding, ['id'], `finding-${pageStart + index}`)}
                getRowProps={findingRowProps}
                loadError={listError}
                onRetry={serverPage.retry}
                empty={emptyState}
              />
            )}
          </div>
        )}

        {view === 'grouped' && grouped.state === 'ready' && !groupsComplete && matchTotal !== null ? (
          <div className="rf-load-more">
            <p className="rf-pager-info">
              <span className="tabular-nums">{formatNumber(matchTotal - grouped.items.length)}</span> matching {pluralize(matchTotal - grouped.items.length, 'finding')} not read yet. Older findings may add members to these groups or new groups.
            </p>
            {grouped.error ? <p className="rf-pager-info" role="alert">{grouped.error}</p> : null}
            <Button size="sm" variant="secondary" loading={grouped.loadingMore} onClick={grouped.loadMore}>
              Read the next {formatNumber(Math.min(FINDINGS_LIMIT_MAX, matchTotal - grouped.items.length))} findings
            </Button>
          </div>
        ) : null}

        {view === 'all' && matchTotal ? (
          <div className="rf-pager">
            <p className="rf-pager-info">Showing <span className="tabular-nums">{findings.length ? formatNumber(pageStart + 1) : 0}</span> to <span className="tabular-nums">{formatNumber(pageStart + findings.length)}</span> of <span className="tabular-nums">{formatNumber(matchTotal)}</span> {pluralize(matchTotal, 'finding')}</p>
            <div className="rf-toolbar">
              <Select label="Rows" value={String(pageSize)} options={PAGE_SIZES.map((size) => ({ value: String(size), label: String(size) }))} onChange={(value) => setPageSize(Number(value) as (typeof PAGE_SIZES)[number])} />
              <Button variant="ghost" size="sm" disabled={page <= 1 || serverPage.state === 'loading'} aria-label="Previous findings page" onClick={() => setPage((value) => Math.max(1, value - 1))}>Previous</Button>
              <Button variant="ghost" size="sm" disabled={!serverPage.envelope?.hasMore || serverPage.state === 'loading'} aria-label="Next findings page" onClick={() => setPage((value) => value + 1)}>Next</Button>
              <span className="rf-pager-info">Page <span className="tabular-nums">{formatNumber(serverPage.envelope?.page ?? page)}</span> of <span className="tabular-nums">{formatNumber(serverPages)}</span></span>
            </div>
          </div>
        ) : null}

        {view === 'grouped' && groupCount > pageSize ? (
          <div className="rf-pager">
            <p className="rf-pager-info">Showing groups <span className="tabular-nums">{groupPageStart + 1}</span> to <span className="tabular-nums">{Math.min(groupCount, groupPageStart + pageSize)}</span> of <span className="tabular-nums">{groupCount}</span>{groupsComplete ? '' : ' built so far'}</p>
            <div className="rf-toolbar">
              <Select label="Rows" value={String(pageSize)} options={PAGE_SIZES.map((size) => ({ value: String(size), label: String(size) }))} onChange={(value) => setPageSize(Number(value) as (typeof PAGE_SIZES)[number])} />
              <Button variant="ghost" size="sm" disabled={currentGroupPage <= 0} aria-label="Previous group page" onClick={() => setGroupPage((value) => Math.max(0, value - 1))}>Previous</Button>
              <Button variant="ghost" size="sm" disabled={currentGroupPage >= groupPageCount - 1} aria-label="Next group page" onClick={() => setGroupPage((value) => Math.min(groupPageCount - 1, value + 1))}>Next</Button>
            </div>
          </div>
        ) : null}
      </section>
    </div>
  );
}

function countLabel(totals: StatusTotals, status: string) {
  if (totals.state === 'loading') return '...';
  const value = totals.totals[status];
  return typeof value === 'number' ? formatNumber(value) : 'n/a';
}

function initialStatus(value: string | undefined, linked = false): StatusFilter {
  if (!value || value === 'all') return value === 'all' || linked ? 'all' : 'open';
  const status = findingStatusFilter(value);
  return status || 'open';
}
