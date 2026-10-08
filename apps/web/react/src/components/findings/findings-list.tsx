import { useEffect, useMemo, useState, type HTMLAttributes } from 'react';
import { Search, TriangleAlert } from 'lucide-react';
import { FindingRuleCard } from './finding-rule-card';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { EmptyState } from '../ui/empty-state';
import { Select } from '../ui/select';
import { DataTable, type TableColumn } from '../ui/table';
import type { DataItem } from '../../lib/types';
import { findingStatus } from '../../lib/finding-lifecycle.mjs';
import {
  findingAssetLabel,
  findingRuleDetailHash,
  findingRuleSlaMeta,
  findingRuleTitle,
  groupFindingsByRule,
  sortFindingRuleGroups,
  summarizeFindingStatuses,
  type FindingRuleGroup,
  type FindingRuleSortKey
} from '../../lib/findings-helpers';
import { formatDate, formatSeverityLabel } from '../../lib/utils';

type StatusFilter = 'open' | 'closed' | 'accepted' | 'all';
type SortKey = FindingRuleSortKey;

const PAGE_SIZES = [12, 24, 48] as const;

const SORT_OPTIONS: { value: SortKey; label: string }[] = [
  { value: 'severity', label: 'Worst severity' },
  { value: 'assets', label: 'Most affected assets' },
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

/** SLA for a rule: the earliest open due time, or lifecycle wording when none is open. */
function groupSlaMeta(group: FindingRuleGroup) {
  return findingRuleSlaMeta(group, (value) => formatDate(value));
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

export function FindingsListView({
  findings,
  checks,
  targets,
  loadError = null,
  onRetry
}: {
  findings: DataItem[];
  checks: DataItem[];
  targets: DataItem[];
  loadError?: string | null;
  onRetry?: () => void;
}) {
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('open');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [ownerFilter, setOwnerFilter] = useState('all');
  const [targetFilter, setTargetFilter] = useState('all');
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
  }, [statusFilter, severityFilter, ownerFilter, targetFilter, debouncedSearch, sort, pageSize]);

  const owners = useMemo(() => [...new Set(findings.map((finding) => getString(finding, ['assignee', 'owner', 'rem_owner'], 'unassigned')))].sort(), [findings]);
  const severities = useMemo(() => [...new Set(findings.map((finding) => getString(finding, ['severity'], 'unknown')))].sort(), [findings]);


  // Status tabs count findings (one per asset), so they agree with the page KPIs and the API.
  const statusCounts = useMemo(() => ({
    open: findings.filter((finding) => statusMatches(finding, 'open')).length,
    closed: findings.filter((finding) => statusMatches(finding, 'closed')).length,
    accepted: findings.filter((finding) => statusMatches(finding, 'accepted')).length,
    all: findings.length
  }), [findings]);

  // Filter individual findings first, then group: a rule appears when any member matches,
  // and every per-rule count reflects matched members only.
  const matchedFindings = useMemo(() => findings.filter((finding) => {
    if (!statusMatches(finding, statusFilter)) return false;
    const severity = getString(finding, ['severity'], 'unknown');
    const owner = getString(finding, ['assignee', 'owner', 'rem_owner'], 'unassigned');
    const targetId = getString(finding, ['target_id'], '');
    if (severityFilter !== 'all' && severity !== severityFilter) return false;
    if (ownerFilter !== 'all' && owner !== ownerFilter) return false;
    if (targetFilter !== 'all' && targetId !== targetFilter) return false;
    if (!debouncedSearch) return true;
    return [
      getString(finding, ['id']),
      getString(finding, ['title', 'summary']),
      findingRuleTitle(finding, checks),
      findingAssetLabel(finding, targets),
      getString(finding, ['check_id']),
      owner,
      targetId
    ].join(' ').toLowerCase().includes(debouncedSearch);
  }), [findings, statusFilter, severityFilter, ownerFilter, targetFilter, debouncedSearch, checks, targets]);

  const ruleGroups = useMemo(
    () => sortFindingRuleGroups(groupFindingsByRule(matchedFindings, { targets, checks }), sort),
    [matchedFindings, targets, checks, sort]
  );

  const pageCount = Math.max(1, Math.ceil(ruleGroups.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);
  const pageItems = ruleGroups.slice(currentPage * pageSize, currentPage * pageSize + pageSize);
  const rangeStart = ruleGroups.length === 0 ? 0 : currentPage * pageSize + 1;
  const rangeEnd = Math.min(ruleGroups.length, (currentPage + 1) * pageSize);
  const ruleNoun = ruleGroups.length === 1 ? 'rule' : 'rules';
  const findingNoun = matchedFindings.length === 1 ? 'finding' : 'findings';

  function openGroupHash(hash: string) {
    if (hash) window.location.hash = hash;
  }

  const columns: TableColumn<FindingRuleGroup>[] = [
    {
      key: 'finding',
      label: 'Finding',
      render: (group) => <FindingRuleCard group={group} checks={checks} onOpen={openGroupHash} />
    },
    {
      key: 'severity',
      label: 'Worst severity',
      render: (group) => <Badge tone={severityTone(group.worstSeverity)}>{formatSeverityLabel(group.worstSeverity)}</Badge>
    },
    {
      key: 'owner',
      label: 'Owner',
      render: (group) => {
        const names = group.owners.map((owner) => (owner === 'unassigned' ? 'Unassigned' : owner));
        if (names.length <= 1) return names[0] ?? 'Unassigned';
        const rest = names.length - 2;
        return <span className="finding-cell-stack"><strong>{names.length} owners</strong><small>{names.slice(0, 2).join(', ')}{rest > 0 ? ` and ${rest} more` : ''}</small></span>;
      }
    },
    {
      key: 'sla',
      label: 'SLA',
      render: (group) => {
        const sla = groupSlaMeta(group);
        return <span className="finding-cell-stack"><Badge tone={sla.tone}>{sla.label}</Badge>{sla.due ? <small>{sla.due}</small> : null}</span>;
      }
    },
    {
      key: 'status',
      label: 'Status',
      render: (group) => {
        const statuses = Object.keys(group.statusCounts);
        const lead = findingStatus(group.members[0] ?? {});
        if (group.members.length === 1 || statuses.length === 1) {
          return group.members.length === 1
            ? <Badge tone={statusTone(lead)}>{lead.replaceAll('_', ' ')}</Badge>
            : <Badge tone={statusTone(lead)}>{summarizeFindingStatuses(group.statusCounts)}</Badge>;
        }
        return (
          <span className="finding-cell-stack">
            <Badge tone={statusTone(lead)}>{lead.replaceAll('_', ' ')}</Badge>
            <small>{summarizeFindingStatuses(group.statusCounts)}</small>
          </span>
        );
      }
    }
  ];

  // The rule card anchor is the row's single keyboard stop and accessible name; the row
  // click is a pointer convenience only, so it carries no extra role or tab stop.
  function rowProps(group: FindingRuleGroup): Omit<HTMLAttributes<HTMLTableRowElement>, 'key'> {
    const hash = findingRuleDetailHash(group);
    if (!hash) return {};
    return {
      className: 'finding-rule-row',
      onClick: () => openGroupHash(hash)
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
              aria-label="Filter findings by id, title, domain, check, or owner"
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search title, domain, owner, or check"
            />
          </label>
          <Select className="ft-field" label="Severity" value={severityFilter} options={[{ value: 'all', label: 'All severities' }, ...severities.map((severity) => ({ value: severity, label: formatSeverityLabel(severity) }))]} onChange={setSeverityFilter} />
          <Select className="ft-field" label="Owner" value={ownerFilter} options={[{ value: 'all', label: 'All owners' }, ...owners.map((owner) => ({ value: owner, label: owner }))]} onChange={setOwnerFilter} />
          <Select className="ft-field" label="Domain" value={targetFilter} options={[{ value: 'all', label: 'All domains' }, ...targets.map((target) => ({ value: getString(target, ['id']), label: getString(target, ['value', 'id']) }))]} onChange={setTargetFilter} />
          <Select className="ft-field" label="Sort" value={sort} options={SORT_OPTIONS} onChange={(value) => setSort(value as SortKey)} />
        </div>
        <p className="findings-result-count" aria-live="polite">
          <span className="tabular-nums">{ruleGroups.length}</span> {ruleNoun} across <span className="tabular-nums">{matchedFindings.length}</span> matching {findingNoun}
        </p>
      </div>

      <DataTable
        className="findings-table"
        columns={columns}
        items={pageItems}
        getRowId={(group) => group.key}
        getRowProps={rowProps}
        loadError={loadError}
        onRetry={onRetry}
        empty={<EmptyState icon={TriangleAlert} title="No matching findings" body={findings.length ? 'Adjust the status, severity, owner, domain, or search filters.' : 'Findings appear only after validation publishes an evidence-backed gap.'} actionLabel="Open test runs" actionHref="#runs" />}
      />

      <div className="findings-pager">
        <p className="fp-info">Showing <span>{rangeStart}</span> to <span>{rangeEnd}</span> of <span>{ruleGroups.length}</span> {ruleNoun}</p>
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
