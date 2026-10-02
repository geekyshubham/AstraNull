import { useEffect, useMemo, useState, type HTMLAttributes } from 'react';
import { CircleCheck, CircleDot, Clock, Search, ShieldMinus, TriangleAlert } from 'lucide-react';
import { FindingCard } from '../../components/findings/finding-card';
import { Badge } from '../../components/ui/badge';
import { Button } from '../../components/ui/button';
import { EmptyState } from '../../components/ui/empty-state';
import { Select } from '../../components/ui/select';
import { DataTable, type TableColumn } from '../../components/ui/table';
import { VariantSwitch } from '../../components/ui/variant-switch';
import type { DesignVariant } from '../../lib/design-variant';
import {
  createFindingGroupIndex,
  findingGroupHref,
  findingGroupSeverityRank,
  findingLookupContext,
  findingSlaState,
  findingStatusBucket,
  groupFindings,
  groupSlaSummary,
  matchesFindingFilters,
  sortFindingGroups,
  type FindingGroup,
  type FindingGroupSortKey,
  type FindingSlaStateKey,
  type FindingStatusBucket
} from '../../lib/finding-groups.mjs';
import { findingStatus } from '../../lib/finding-lifecycle.mjs';
import { findingAssetLabel, summarizeFindingStatuses, type computeFindingKpis } from '../../lib/findings-helpers';
import { plainFindingTitle } from '../../lib/plain-language.mjs';
import type { DataItem, PortalConfig, PortalData, Session } from '../../lib/types';
import { formatDate, formatSeverityLabel, pluralize } from '../../lib/utils';
import './findings-refined.css';

/**
 * Everything the Refined findings view needs. Refresh, busy, and feedback state stay owned
 * by ValidationSurfacePage; triage mutations live on finding-detail, unchanged.
 */
export interface FindingsRefinedProps {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  variant: DesignVariant;
  onVariantChange: (next: DesignVariant) => void;
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
type StatusFilter = Exclude<FindingStatusBucket, 'other'> | 'all';

const VIEW_STORAGE_KEY = 'astranull.findings-refined.view';
const PAGE_SIZES = [12, 24, 48] as const;
const STATUS_FILTERS: Array<{ id: StatusFilter; label: string }> = [
  { id: 'open', label: 'Open' },
  { id: 'accepted', label: 'Accepted' },
  { id: 'closed', label: 'Closed' },
  { id: 'all', label: 'All' }
];
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

export function FindingsRefined(props: FindingsRefinedProps) {
  const { data, findingKpis, findingsLoadError, message, error } = props;
  const [view, setView] = useState<ViewMode>(readStoredView);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('open');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [ownerFilter, setOwnerFilter] = useState('all');
  const [groupFilter, setGroupFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [sort, setSort] = useState<FindingGroupSortKey>('severity');
  const [pageSize, setPageSize] = useState<(typeof PAGE_SIZES)[number]>(12);
  const [page, setPage] = useState(0);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedSearch(search.trim().toLowerCase()), 250);
    return () => window.clearTimeout(timer);
  }, [search]);

  useEffect(() => {
    setPage(0);
  }, [view, statusFilter, severityFilter, ownerFilter, groupFilter, debouncedSearch, sort, pageSize]);

  function changeView(next: ViewMode) {
    setView(next);
    storeView(next);
  }

  const findings = data.findings;
  // One index per dataset: target, check and target-group lookups plus a per-finding cache,
  // shared by the summary grouping, the filtered grouping, search and sorting.
  const groupIndex = useMemo(
    () => createFindingGroupIndex({ targets: data.targets, checks: data.checks, targetGroups: data.targetGroups }),
    [data.targets, data.checks, data.targetGroups]
  );
  // Plain titles and asset labels resolved once per finding through the index, not per keystroke or comparison.
  const findingText = useMemo(() => {
    const map = new Map<DataItem, { title: string; asset: string }>();
    findings.forEach((finding) => {
      const lookup = findingLookupContext(finding, groupIndex);
      map.set(finding, {
        title: plainFindingTitle(finding, lookup.targets, lookup.checks),
        asset: findingAssetLabel(finding, lookup.targets as DataItem[])
      });
    });
    return map;
  }, [findings, groupIndex]);
  const groupLabels = useMemo(
    () => new Map(data.targetGroups.map((group) => [getString(group, ['id']), getString(group, ['name', 'id'], 'Unnamed group')])),
    [data.targetGroups]
  );

  // Whole-inventory groups feed the summary strip; filtered groups feed the table.
  const allGroups = useMemo(() => groupFindings(findings, groupIndex), [findings, groupIndex]);
  const summary = useMemo(() => {
    const openAssets = new Set<string>();
    allGroups.forEach((group) => group.assets.forEach((asset) => {
      if (asset.statusCounts.open > 0) openAssets.add(asset.key);
    }));
    return {
      alerts: allGroups.length,
      openAlerts: allGroups.filter((group) => group.openCount > 0).length,
      openAssets: openAssets.size
    };
  }, [allGroups]);

  const owners = useMemo(() => [...new Set(findings.map((finding) => getString(finding, ['assignee', 'owner', 'rem_owner'], 'unassigned')))].sort(), [findings]);
  const severities = useMemo(
    () => [...new Set(findings.map((finding) => getString(finding, ['severity'], 'unknown')))].sort((a, b) => findingGroupSeverityRank(b) - findingGroupSeverityRank(a) || a.localeCompare(b)),
    [findings]
  );

  const statusCounts = useMemo(() => {
    const counts: Record<StatusFilter, number> = { open: 0, accepted: 0, closed: 0, all: findings.length };
    findings.forEach((finding) => {
      const bucket = findingStatusBucket(finding);
      if (bucket !== 'other') counts[bucket] += 1;
    });
    return counts;
  }, [findings]);

  const matchedFindings = useMemo(() => findings.filter((finding) => matchesFindingFilters(
    finding,
    { status: statusFilter, severity: severityFilter, owner: ownerFilter, targetGroup: groupFilter, search: debouncedSearch },
    {
      searchText: (record) => {
        const text = findingText.get(record as DataItem);
        return [text?.title ?? '', text?.asset ?? '', groupLabels.get(getString(record, ['target_group_id'])) ?? ''].join(' ');
      }
    }
  )), [findings, statusFilter, severityFilter, ownerFilter, groupFilter, debouncedSearch, findingText, groupLabels]);

  // Grouping is computed once per filter change; sorting is a separate, cheaper memo.
  const filteredGroups = useMemo(() => groupFindings(matchedFindings, groupIndex), [matchedFindings, groupIndex]);
  const matchedGroups = useMemo(() => sortFindingGroups(filteredGroups, sort), [filteredGroups, sort]);

  const sortedFindings = useMemo(() => {
    const now = Date.now();
    const opened = (finding: DataItem, fallback: number) => {
      const ms = Date.parse(String(finding.created_at ?? finding.opened_at ?? ''));
      return Number.isFinite(ms) ? ms : fallback;
    };
    const title = (finding: DataItem) => findingText.get(finding)?.title ?? '';
    return [...matchedFindings].sort((left, right) => {
      const tie = title(left).localeCompare(title(right));
      if (sort === 'title') return tie;
      if (sort === 'recent') return opened(right, 0) - opened(left, 0) || tie;
      if (sort === 'oldest') return opened(left, Number.MAX_SAFE_INTEGER) - opened(right, Number.MAX_SAFE_INTEGER) || tie;
      if (sort === 'sla') {
        return (findingSlaState(left, now).dueAt ?? Number.MAX_SAFE_INTEGER) - (findingSlaState(right, now).dueAt ?? Number.MAX_SAFE_INTEGER) || tie;
      }
      const openDelta = Number(findingStatusBucket(right) === 'open') - Number(findingStatusBucket(left) === 'open');
      return openDelta || findingGroupSeverityRank(right.severity) - findingGroupSeverityRank(left.severity) || tie;
    });
  }, [matchedFindings, sort, findingText]);

  const rowCount = view === 'grouped' ? matchedGroups.length : sortedFindings.length;
  const pageCount = Math.max(1, Math.ceil(rowCount / pageSize));
  const currentPage = Math.min(page, pageCount - 1);
  const pageStart = currentPage * pageSize;
  const rangeStart = rowCount === 0 ? 0 : pageStart + 1;
  const rangeEnd = Math.min(rowCount, pageStart + pageSize);
  const rowNoun = view === 'grouped' ? pluralize(rowCount, 'alert') : pluralize(rowCount, 'finding');

  const groupColumns: TableColumn<FindingGroup>[] = [
    {
      key: 'alert',
      label: 'Alert',
      render: (group) => {
        const shown = group.assets.slice(0, 3);
        const remaining = group.assets.length - shown.length;
        return (
          <a
            className="rf-alert-link"
            href={findingGroupHref(group.key)}
            aria-label={`Open alert ${group.title}, ${formatSeverityLabel(group.severity)}, ${group.assets.length} ${pluralize(group.assets.length, 'affected asset')}`}
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
      label: 'Affected assets',
      render: (group) => (
        <span className="rf-cell-stack">
          <strong className="tabular-nums">{group.assets.length}</strong>
          <small>{group.openAssetCount} with open findings</small>
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
      render: (finding) => <FindingCard finding={finding} checks={data.checks} targetGroups={data.targetGroups} targets={data.targets} />
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
      label: 'Asset',
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
    return { className: 'rf-clickable-row', onClick: () => navigate(findingGroupHref(group.key)) };
  }

  function findingRowProps(finding: DataItem): Omit<HTMLAttributes<HTMLTableRowElement>, 'key'> {
    const id = getString(finding, ['id']);
    if (!id) return {};
    return { className: 'rf-clickable-row', onClick: () => navigate(`#finding-detail?id=${encodeURIComponent(id)}`) };
  }

  const emptyState = (
    <EmptyState
      icon={TriangleAlert}
      title="No matching findings"
      body={findings.length ? 'Adjust the status, severity, owner, group, or search filters.' : 'Findings appear only after validation publishes an evidence-backed gap.'}
      actionLabel="Open test runs"
      actionHref="#runs"
    />
  );

  const loading = !data.loaded && findings.length === 0 && !findingsLoadError;
  const slaHint = findingKpis.openCount === 0
    ? 'No open findings'
    : findingKpis.slaBreachCount > 0 ? 'Open past severity SLA' : 'All open findings within SLA';

  return (
    <div className="content refined rf-findings">
      <header className="rf-header">
        <div className="rf-header-copy">
          <p className="rf-eyebrow">Triage &amp; remediate</p>
          <h1>Findings</h1>
          <p className="rf-header-description">
            Every finding links an observed verdict to evidence, declared business context, ownership, SLA, and a concrete remediation path.
          </p>
        </div>
        <div className="rf-header-actions">
          <VariantSwitch value={props.variant} onChange={props.onVariantChange} />
          <Button variant="secondary" size="sm" loading={props.busy === 'refresh'} disabled={props.busy !== ''} onClick={props.onRefresh}>Refresh</Button>
        </div>
      </header>

      {findingsLoadError ? (
        <p className="rf-summary-note">Finding summary unavailable until the inventory reloads.</p>
      ) : (
        <section className="rf-summary-strip rf-findings-summary" aria-label="Finding summary">
          <div className="rf-stat">
            <span className="rf-stat-label">Open</span>
            <span className="rf-stat-value">{findingKpis.openCount}</span>
            <span className="rf-stat-hint">{findingKpis.openSeverityBreakdown}</span>
          </div>
          <div className="rf-stat">
            <span className="rf-stat-label">Accepted risk</span>
            <span className="rf-stat-value">{findingKpis.acceptedRiskCount}</span>
            <span className="rf-stat-hint">Risk acceptance on record</span>
          </div>
          <div className="rf-stat">
            <span className="rf-stat-label">Closed in 30 days</span>
            <span className="rf-stat-value">{findingKpis.closed30dCount}</span>
            <span className="rf-stat-hint">Closed or resolved</span>
          </div>
          <div className="rf-stat" data-tone={findingKpis.slaBreachCount > 0 ? 'danger' : undefined}>
            <span className="rf-stat-label">SLA breached</span>
            <span className="rf-stat-value">
              {findingKpis.slaBreachCount > 0 ? <TriangleAlert size={16} aria-hidden="true" /> : null}
              {findingKpis.slaBreachCount}
            </span>
            <span className="rf-stat-hint">{slaHint}</span>
          </div>
          <div className="rf-stat">
            <span className="rf-stat-label">Distinct alerts</span>
            <span className="rf-stat-value">{summary.alerts}</span>
            <span className="rf-stat-hint">{summary.openAlerts} with open findings</span>
          </div>
          <div className="rf-stat">
            <span className="rf-stat-label">Affected assets</span>
            <span className="rf-stat-value">{summary.openAssets}</span>
            <span className="rf-stat-hint">With an open finding</span>
          </div>
        </section>
      )}

      {message || error ? (
        <div className={error ? 'form-banner error' : 'form-banner neutral'} role={error ? 'alert' : 'status'} aria-live="polite">{error || message}</div>
      ) : null}

      <section className="rf-section" aria-labelledby="rf-findings-queue">
        <div className="rf-section-head">
          <h2 id="rf-findings-queue">Finding queue</h2>
          <div className="rf-segmented" role="group" aria-label="Finding view">
            <button type="button" aria-pressed={view === 'grouped'} onClick={() => changeView('grouped')}>Grouped by alert</button>
            <button type="button" aria-pressed={view === 'all'} onClick={() => changeView('all')}>All findings</button>
          </div>
        </div>

        <div className="rf-panel rf-findings-filters">
          <div className="rf-segmented rf-status-tabs" role="group" aria-label="Finding status filters">
            {STATUS_FILTERS.map((filter) => (
              <button key={filter.id} type="button" aria-pressed={statusFilter === filter.id} onClick={() => setStatusFilter(filter.id)}>
                {filter.label}
                <span className="rf-tab-count tabular-nums">{statusCounts[filter.id]}</span>
              </button>
            ))}
          </div>
          <div className="rf-filter-grid">
            <label className="field rf-search">
              <span>Search</span>
              <span className="rf-search-control">
                <Search className="rf-search-icon" size={15} aria-hidden="true" />
                <input
                  className="input"
                  type="search"
                  value={search}
                  aria-label="Filter findings by id, title, asset, check, owner, or group"
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Title, asset, owner, check, or group"
                />
              </span>
            </label>
            <Select label="Severity" value={severityFilter} options={[{ value: 'all', label: 'All severities' }, ...severities.map((severity) => ({ value: severity, label: formatSeverityLabel(severity) }))]} onChange={setSeverityFilter} />
            <Select label="Owner" value={ownerFilter} options={[{ value: 'all', label: 'All owners' }, ...owners.map((owner) => ({ value: owner, label: owner === 'unassigned' ? 'Unassigned' : owner }))]} onChange={setOwnerFilter} />
            <Select label="Target group" value={groupFilter} options={[{ value: 'all', label: 'All groups' }, ...data.targetGroups.flatMap((group) => { const id = getString(group, ['id']); return id ? [{ value: id, label: getString(group, ['name', 'id'], id) }] : []; })]} onChange={setGroupFilter} />
            <Select label="Sort" value={sort} options={SORT_OPTIONS} onChange={(value) => setSort(value as FindingGroupSortKey)} />
          </div>
          <p className="rf-result-count" aria-live="polite">
            {view === 'grouped' ? (
              <><span className="tabular-nums">{matchedGroups.length}</span> {pluralize(matchedGroups.length, 'alert')} across <span className="tabular-nums">{matchedFindings.length}</span> matching {pluralize(matchedFindings.length, 'finding')}. Counts reflect the current filters.</>
            ) : (
              <><span className="tabular-nums">{matchedFindings.length}</span> matching {pluralize(matchedFindings.length, 'finding')}, one row per asset.</>
            )}
          </p>
        </div>

        {loading ? (
          <EmptyState icon={TriangleAlert} variant="skeleton" title="Loading findings" body="Fetching the finding inventory, declared targets, and check catalog." />
        ) : (
          <div className="rf-panel rf-panel-flush rf-findings-table rf-stack-table">
            {view === 'grouped' ? (
              <DataTable
                columns={groupColumns}
                items={matchedGroups.slice(pageStart, pageStart + pageSize)}
                getRowId={(group) => group.key}
                getRowProps={groupRowProps}
                loadError={findingsLoadError}
                onRetry={props.onRefresh}
                empty={emptyState}
              />
            ) : (
              <DataTable
                columns={findingColumns}
                items={sortedFindings.slice(pageStart, pageStart + pageSize)}
                getRowId={(finding, index) => getString(finding, ['id'], `finding-${pageStart + index}`)}
                getRowProps={findingRowProps}
                loadError={findingsLoadError}
                onRetry={props.onRefresh}
                empty={emptyState}
              />
            )}
          </div>
        )}

        {rowCount > 0 ? (
          <div className="rf-pager">
            <p className="rf-pager-info">Showing <span className="tabular-nums">{rangeStart}</span> to <span className="tabular-nums">{rangeEnd}</span> of <span className="tabular-nums">{rowCount}</span> {rowNoun}</p>
            <div className="rf-toolbar">
              <Select label="Rows" value={String(pageSize)} options={PAGE_SIZES.map((size) => ({ value: String(size), label: String(size) }))} onChange={(value) => setPageSize(Number(value) as (typeof PAGE_SIZES)[number])} />
              <Button variant="ghost" size="sm" disabled={currentPage <= 0} aria-label="Previous findings page" onClick={() => setPage((value) => Math.max(0, value - 1))}>Previous</Button>
              <Button variant="ghost" size="sm" disabled={currentPage >= pageCount - 1} aria-label="Next findings page" onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>Next</Button>
              <span className="rf-pager-info">Page <span className="tabular-nums">{currentPage + 1}</span> of <span className="tabular-nums">{pageCount}</span></span>
            </div>
          </div>
        ) : null}
      </section>
    </div>
  );
}
