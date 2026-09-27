import { useEffect, useMemo, useState, type HTMLAttributes } from 'react';
import { Search, TriangleAlert } from 'lucide-react';
import { FindingCard } from './finding-card';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { EmptyState } from '../ui/empty-state';
import { Select } from '../ui/select';
import { DataTable, type TableColumn } from '../ui/table';
import type { DataItem } from '../../lib/types';
import { findingStatus } from '../../lib/finding-lifecycle.mjs';
import { findingSlaDueAt, isFindingSlaBreach } from '../../lib/findings-helpers';
import { formatDate, formatSeverityLabel } from '../../lib/utils';
// @ts-ignore Plain ESM keeps executive labels directly testable with node:test.
import { plainFindingTitle } from '../../lib/plain-language.mjs';

type StatusFilter = 'open' | 'closed' | 'accepted' | 'all';
type SortKey = 'severity' | 'recent' | 'oldest' | 'sla' | 'title';

const PAGE_SIZES = [12, 24, 48] as const;

const SORT_OPTIONS: { value: SortKey; label: string }[] = [
  { value: 'severity', label: 'Severity' },
  { value: 'recent', label: 'Recently opened' },
  { value: 'oldest', label: 'Oldest first' },
  { value: 'sla', label: 'SLA remaining' },
  { value: 'title', label: 'Title A to Z' }
];

const FINDINGS_TABLE_STYLES = `
.findings-surface .findings-table .data-table { min-width: 920px; }
.findings-surface .finding-row-primary { display: flex; min-width: 250px; min-height: 44px; flex-direction: column; justify-content: center; gap: var(--space-1); border: 0; border-radius: var(--radius-sm); padding: var(--space-1) var(--space-2); color: inherit; text-decoration: none; }
.findings-surface .finding-row-primary:hover { border-color: transparent; background: color-mix(in oklab, var(--accent), transparent 94%); }
.findings-surface .finding-row-primary:focus-visible { outline: none; box-shadow: var(--focus-ring); }
.findings-surface .finding-row-primary .fc-headline { display: flex; align-items: flex-start; justify-content: space-between; gap: var(--space-2); margin: 0; }
.findings-surface .finding-row-primary .fc-headline strong { color: var(--fg); font-size: var(--text-sm); line-height: 1.35; }
.findings-surface .finding-row-primary .fc-meta { margin: 0; overflow-wrap: anywhere; }
.findings-surface .finding-row-primary .fc-facets { margin: 0; }
.findings-surface .finding-cell-stack { display: flex; min-width: 0; flex-direction: column; gap: 3px; }
.findings-surface .finding-cell-stack small { color: var(--fg-2); font-size: var(--text-xs); }
.findings-surface .findings-result-count { margin: 0; color: var(--fg-2); font-family: var(--font-mono); font-size: var(--text-xs); }
@media (pointer: coarse) {
  .findings-surface .ft-tab { min-height: 44px; }
}
@media (max-width: 680px) {
  .findings-surface .ft-controls { grid-template-columns: minmax(0, 1fr); }
  .findings-surface .ft-status { width: 100%; overflow-x: auto; }
  .findings-surface .ft-tab { flex: 1 0 auto; justify-content: center; }
  .findings-surface .findings-pager { align-items: stretch; flex-direction: column; }
}
`;

function getString(item: DataItem, keys: string[], fallback = '') {
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  s1: 0,
  high: 1,
  s2: 1,
  medium: 2,
  s3: 2,
  low: 3,
  s4: 3,
  info: 4
};

function statusMatches(finding: DataItem, filter: StatusFilter) {
  const status = findingStatus(finding);
  if (filter === 'all') return true;
  if (filter === 'open') return status === 'open';
  if (filter === 'closed') return status === 'closed' || status === 'resolved';
  if (filter === 'accepted') return status === 'accepted' || status === 'accepted_risk';
  return true;
}

function statusTone(status: string) {
  const key = status.toLowerCase();
  if (key === 'closed' || key === 'resolved') return 'success' as const;
  if (key === 'accepted' || key === 'accepted_risk') return 'info' as const;
  if (key === 'open' || key === 'remediation_pending') return 'warn' as const;
  return 'muted' as const;
}

function severityTone(severity: string) {
  const key = severity.toLowerCase();
  if (['critical', 'high', 's1', 's2'].includes(key)) return 'danger' as const;
  if (['medium', 's3'].includes(key)) return 'warn' as const;
  return 'muted' as const;
}

function slaMeta(finding: DataItem) {
  const status = findingStatus(finding);
  if (status !== 'open' && status !== 'remediation_pending') {
    return {
      label: finding.updated_at ?? finding.closed_at ? `Closed ${formatDate(finding.updated_at ?? finding.closed_at)}` : 'Closed',
      tone: 'muted' as const,
      due: ''
    };
  }
  const recorded = getString(finding, ['rem_sla', 'remSla', 'sla'], '');
  const dueAt = findingSlaDueAt(finding);
  if (isFindingSlaBreach(finding)) return { label: 'Overdue', tone: 'danger' as const, due: dueAt ? formatDate(dueAt) : recorded };
  if (!dueAt) return { label: recorded || 'Pending', tone: 'muted' as const, due: '' };
  const hoursLeft = Math.max(0, Math.round((dueAt - Date.now()) / 3_600_000));
  return { label: hoursLeft <= 24 ? `${hoursLeft}h left` : 'On track', tone: hoursLeft <= 24 ? 'warn' as const : 'muted' as const, due: formatDate(dueAt) };
}

function StatusFilterTabs({
  active,
  counts,
  onChange,
}: {
  active: StatusFilter;
  counts: Record<StatusFilter, number>;
  onChange: (filter: StatusFilter) => void;
}) {
  const filters: StatusFilter[] = ['open', 'closed', 'accepted', 'all'];
  return (
    <div className="ft-status" role="group" aria-label="Finding status filters">
      {filters.map((filter) => (
        <button
          key={filter}
          type="button"
          className={`ft-tab btn${active === filter ? ' is-active' : ''}`}
          aria-pressed={active === filter}
          onClick={() => onChange(filter)}
        >
          {filter === 'accepted' ? 'Accepted' : filter.charAt(0).toUpperCase() + filter.slice(1)}
          <span className="ft-count tabular-nums">{counts[filter]}</span>
        </button>
      ))}
    </div>
  );
}

function sortFindings(items: DataItem[], sort: SortKey) {
  const copy = [...items];
  copy.sort((left, right) => {
    if (sort === 'severity') {
      const leftRank = SEVERITY_RANK[getString(left, ['severity'], 'low').toLowerCase()] ?? 9;
      const rightRank = SEVERITY_RANK[getString(right, ['severity'], 'low').toLowerCase()] ?? 9;
      return leftRank - rightRank;
    }
    if (sort === 'title') return getString(left, ['title'], '').localeCompare(getString(right, ['title'], ''));
    if (sort === 'sla') return (findingSlaDueAt(left) ?? Number.MAX_SAFE_INTEGER) - (findingSlaDueAt(right) ?? Number.MAX_SAFE_INTEGER);
    const leftTs = String(left.created_at ?? left.opened_at ?? '');
    const rightTs = String(right.created_at ?? right.opened_at ?? '');
    return sort === 'oldest' ? leftTs.localeCompare(rightTs) : rightTs.localeCompare(leftTs);
  });
  return copy;
}

export function FindingsListView({
  findings,
  checks,
  targetGroups,
  targets,
  loadError = null,
  onRetry
}: {
  findings: DataItem[];
  checks: DataItem[];
  targetGroups: DataItem[];
  targets: DataItem[];
  loadError?: string | null;
  onRetry?: () => void;
}) {
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('open');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [ownerFilter, setOwnerFilter] = useState('all');
  const [groupFilter, setGroupFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [sort, setSort] = useState<SortKey>('severity');
  const [pageSize, setPageSize] = useState<(typeof PAGE_SIZES)[number]>(12);
  const [page, setPage] = useState(0);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedSearch(search.trim().toLowerCase()), 250);
    return () => window.clearTimeout(timer);
  }, [search]);

  useEffect(() => {
    setPage(0);
  }, [statusFilter, severityFilter, ownerFilter, groupFilter, debouncedSearch, sort, pageSize]);

  const owners = useMemo(() => [...new Set(findings.map((finding) => getString(finding, ['assignee', 'owner', 'rem_owner'], 'unassigned')))].sort(), [findings]);
  const severities = useMemo(() => [...new Set(findings.map((finding) => getString(finding, ['severity'], 'unknown')))].sort(), [findings]);
  const groupLabels = useMemo(() => new Map(targetGroups.map((group) => [getString(group, ['id'], ''), getString(group, ['name', 'id'], 'Unnamed group')])), [targetGroups]);

  const statusCounts = useMemo(() => ({
    open: findings.filter((finding) => statusMatches(finding, 'open')).length,
    closed: findings.filter((finding) => statusMatches(finding, 'closed')).length,
    accepted: findings.filter((finding) => statusMatches(finding, 'accepted')).length,
    all: findings.length
  }), [findings]);

  const filtered = useMemo(() => sortFindings(
    findings.filter((finding) => {
      if (!statusMatches(finding, statusFilter)) return false;
      const severity = getString(finding, ['severity'], 'unknown');
      const owner = getString(finding, ['assignee', 'owner', 'rem_owner'], 'unassigned');
      const groupId = getString(finding, ['target_group_id'], '');
      if (severityFilter !== 'all' && severity !== severityFilter) return false;
      if (ownerFilter !== 'all' && owner !== ownerFilter) return false;
      if (groupFilter !== 'all' && groupId !== groupFilter) return false;
      if (!debouncedSearch) return true;
      return [
        getString(finding, ['id']),
        getString(finding, ['title', 'summary']),
        getString(finding, ['check_id']),
        owner,
        groupId,
        groupLabels.get(groupId) ?? ''
      ].join(' ').toLowerCase().includes(debouncedSearch);
    }),
    sort
  ), [findings, statusFilter, severityFilter, ownerFilter, groupFilter, debouncedSearch, sort, groupLabels]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);
  const pageItems = filtered.slice(currentPage * pageSize, currentPage * pageSize + pageSize);
  const rangeStart = filtered.length === 0 ? 0 : currentPage * pageSize + 1;
  const rangeEnd = Math.min(filtered.length, (currentPage + 1) * pageSize);

  function openFinding(id: string) {
    if (id) window.location.hash = `finding-detail?id=${encodeURIComponent(id)}`;
  }

  const columns: TableColumn<DataItem>[] = [
    {
      key: 'finding',
      label: 'Finding',
      render: (finding) => <FindingCard finding={finding} checks={checks} targetGroups={targetGroups} targets={targets} onOpen={openFinding} />
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
      key: 'target-group',
      label: 'Target group',
      render: (finding) => {
        const groupId = getString(finding, ['target_group_id'], '');
        return <span className="finding-cell-stack"><strong>{(groupLabels.get(groupId) ?? groupId) || 'Ungrouped'}</strong>{groupId ? <small className="mono">{groupId}</small> : null}</span>;
      }
    },
    {
      key: 'owner',
      label: 'Owner',
      render: (finding) => getString(finding, ['assignee', 'owner', 'rem_owner'], 'Unassigned')
    },
    {
      key: 'sla',
      label: 'SLA',
      render: (finding) => {
        const sla = slaMeta(finding);
        return <span className="finding-cell-stack"><Badge tone={sla.tone}>{sla.label}</Badge>{sla.due ? <small>{sla.due}</small> : null}</span>;
      }
    },
    {
      key: 'status',
      label: 'Status',
      render: (finding) => {
        const status = findingStatus(finding);
        return <Badge tone={statusTone(status)}>{status.replaceAll('_', ' ')}</Badge>;
      }
    }
  ];

  function rowProps(finding: DataItem): Omit<HTMLAttributes<HTMLTableRowElement>, 'key'> {
    const id = getString(finding, ['id'], '');
    if (!id) return {};
    const title = plainFindingTitle(finding, targets, checks);
    return {
      role: 'link',
      tabIndex: 0,
      'aria-label': `Open finding ${title}`,
      onClick: () => openFinding(id),
      onKeyDown: (event) => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        openFinding(id);
      }
    };
  }

  return (
    <div className="findings-surface">
      <style>{FINDINGS_TABLE_STYLES}</style>
      <div className="findings-toolbar">
        <StatusFilterTabs active={statusFilter} counts={statusCounts} onChange={setStatusFilter} />
        <div className="ft-controls">
          <label className="field ft-field ft-search">
            <span className="ft-label">Search</span>
            <Search className="ft-search-icon" size={15} aria-hidden="true" />
            <input
              className="input"
              type="search"
              value={search}
              aria-label="Filter findings by id, title, check, owner, or group"
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search title, owner, check, or group"
            />
          </label>
          <Select className="ft-field" label="Severity" value={severityFilter} options={[{ value: 'all', label: 'All severities' }, ...severities.map((severity) => ({ value: severity, label: formatSeverityLabel(severity) }))]} onChange={setSeverityFilter} />
          <Select className="ft-field" label="Owner" value={ownerFilter} options={[{ value: 'all', label: 'All owners' }, ...owners.map((owner) => ({ value: owner, label: owner }))]} onChange={setOwnerFilter} />
          <Select className="ft-field" label="Target group" value={groupFilter} options={[{ value: 'all', label: 'All groups' }, ...targetGroups.flatMap((group) => { const id = getString(group, ['id'], ''); return id ? [{ value: id, label: getString(group, ['name', 'id'], id) }] : []; })]} onChange={setGroupFilter} />
          <Select className="ft-field" label="Sort" value={sort} options={SORT_OPTIONS} onChange={(value) => setSort(value as SortKey)} />
        </div>
        <p className="findings-result-count" aria-live="polite">{filtered.length} matching {filtered.length === 1 ? 'finding' : 'findings'}</p>
      </div>

      <DataTable
        className="findings-table"
        columns={columns}
        items={pageItems}
        getRowId={(finding, index) => getString(finding, ['id'], String(index))}
        getRowProps={rowProps}
        loadError={loadError}
        onRetry={onRetry}
        empty={<EmptyState icon={TriangleAlert} title="No matching findings" body={findings.length ? 'Adjust the status, severity, owner, group, or search filters.' : 'Findings appear only after validation publishes an evidence-backed gap.'} actionLabel="Open test runs" actionHref="#runs" />}
      />

      <div className="findings-pager">
        <p className="fp-info">Showing <span>{rangeStart}</span>–<span>{rangeEnd}</span> of <span>{filtered.length}</span></p>
        <div className="fp-controls">
          <Select label="Rows" value={String(pageSize)} options={PAGE_SIZES.map((size) => ({ value: String(size), label: String(size) }))} onChange={(value) => setPageSize(Number(value) as (typeof PAGE_SIZES)[number])} />
          <Button variant="ghost" size="sm" disabled={currentPage <= 0} aria-label="Previous findings page" onClick={() => setPage((value) => Math.max(0, value - 1))}>Previous</Button>
          <Button variant="ghost" size="sm" disabled={currentPage >= pageCount - 1} aria-label="Next findings page" onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>Next</Button>
          <span className="fp-info">Page <span>{currentPage + 1}</span> of <span>{pageCount}</span></span>
        </div>
      </div>
    </div>
  );
}
