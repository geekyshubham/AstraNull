import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { RefreshCw, X } from 'lucide-react';
import { requestJson } from '../../lib/api';
import { classifyCohortError } from '../../lib/domain-checks.mjs';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import { formatDate, formatNumber } from '../../lib/utils';
import { buildDetailHref } from '../../lib/route-params';
import { resolveTargetVerificationProvenance, VerifyChip } from '../../lib/verify-chip';
import { AnchorButton, Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { DataTable, type TableColumn } from '../ui/table';
import { EmptyState } from '../ui/empty-state';
import { Target } from 'lucide-react';

const PAGE_LIMIT = 50;

const FILTER_LABELS: Record<string, string> = {
  q: 'Search',
  target_group_id: 'Target group',
  verification_state: 'Ownership',
  kind: 'Kind',
  tag: 'Tag',
  service_role: 'Declared role',
  criticality: 'Criticality',
  owner_status: 'Owner',
  owner: 'Owner label',
  family: 'Layer',
  family_status: 'Observation',
  freshness: 'Freshness',
  has_open_finding: 'Open finding',
};

const VALUE_LABELS: Record<string, string> = { waf: 'WAF', cdn: 'CDN', dns_verified: 'DNS verified', provider_verified: 'Provider verified' };

const BUCKET_LABELS: Record<string, { label: string; tone: 'default' | 'muted' | 'warn' }> = {
  detected: { label: 'Detected', tone: 'default' },
  not_detected: { label: 'Not detected', tone: 'muted' },
  inconclusive: { label: 'Inconclusive', tone: 'warn' },
  conflict: { label: 'Conflicting signals', tone: 'warn' },
  stale: { label: 'Stale', tone: 'warn' },
  not_checked: { label: 'Not checked', tone: 'muted' },
  not_recorded: { label: 'Not recorded', tone: 'muted' },
  unknown: { label: 'Unknown', tone: 'muted' },
};

function str(item: DataItem | null | undefined, key: string) {
  const value = item?.[key];
  return typeof value === 'string' ? value : typeof value === 'number' ? String(value) : '';
}

function rec(value: unknown): DataItem | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as DataItem : null;
}

function humanize(value: string) {
  const label = value.replace(/_/g, ' ');
  return label.charAt(0).toUpperCase() + label.slice(1);
}

type PageState = {
  state: 'loading' | 'ready' | 'unsupported' | 'denied' | 'error';
  items: DataItem[];
  total: number | null;
  complete: boolean;
  unit: string;
  units: { targetRecords: number | null; normalizedHosts: number | null };
  asOf: string;
  cohortVersion: string;
  nextCursor: string;
  message: string;
};

const EMPTY_PAGE: PageState = {
  state: 'loading', items: [], total: null, complete: true, unit: '', units: { targetRecords: null, normalizedHosts: null }, asOf: '', cohortVersion: '', nextCursor: '', message: '',
};

function finite(value: unknown) {
  const number = Number(value);
  return value === null || value === undefined || value === '' || !Number.isFinite(number) ? null : number;
}

/**
 * Server cohort list for `/v1/targets` with an exact filter set. Pages are keyset cursors from the
 * server; the total is the server's predicate total, never the number of loaded rows. A changed
 * cohort (409) refreshes the same filters; a cursor that no longer fits restarts at page one.
 */
export function TargetCohortList({
  filters,
  config,
  session,
  inventory,
  onClear,
}: {
  filters: Record<string, string>;
  config: PortalConfig;
  session: Session;
  /** Loaded inventory, only to name the other declared targets behind a hostname row. */
  inventory: DataItem[];
  onClear: () => void;
}) {
  const [cursors, setCursors] = useState<string[]>(['']);
  const [page, setPage] = useState<PageState>(EMPTY_PAGE);
  const [notice, setNotice] = useState('');
  const [reload, setReload] = useState(0);
  const versionRef = useRef('');
  const pageIndex = cursors.length - 1;
  const cursor = cursors[pageIndex];
  const filterKey = JSON.stringify(filters);

  const query = useCallback((withVersion: boolean, pageCursor: string) => {
    const params = new URLSearchParams(filters);
    params.set('limit', String(PAGE_LIMIT));
    if (pageCursor) params.set('cursor', pageCursor);
    else if (withVersion && versionRef.current) params.set('cohort_version', versionRef.current);
    return `/v1/targets?${params.toString()}`;
    // filterKey captures the filter identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterKey]);

  useEffect(() => {
    versionRef.current = '';
    setCursors(['']);
    setNotice('');
  }, [filterKey]);

  useEffect(() => {
    const controller = new AbortController();
    setPage((current) => ({ ...current, state: 'loading', message: '' }));
    async function load(withVersion: boolean) {
      try {
        const payload = await requestJson(config, session, query(withVersion, cursor), { signal: controller.signal }) as DataItem;
        if (controller.signal.aborted) return;
        const pageBlock = rec(payload.page);
        const total = finite(pageBlock?.total ?? payload.total);
        const items = Array.isArray(pageBlock?.items) ? pageBlock!.items as DataItem[] : Array.isArray(payload.items) ? payload.items as DataItem[] : [];
        if (total === null && payload.complete !== false) {
          setPage({ ...EMPTY_PAGE, state: 'unsupported', message: 'This server did not return a total for these filters, so no cohort list is shown.' });
          return;
        }
        versionRef.current = str(payload, 'cohort_version');
        setPage({
          state: 'ready',
          items,
          total,
          complete: payload.complete !== false,
          unit: str(payload, 'unit') || filters.unit || 'target',
          units: { targetRecords: finite(rec(payload.units)?.target_records), normalizedHosts: finite(rec(payload.units)?.normalized_hosts) },
          asOf: str(payload, 'as_of'),
          cohortVersion: str(payload, 'cohort_version'),
          nextCursor: str(pageBlock, 'next_cursor') || str(payload, 'next_cursor'),
          message: '',
        });
      } catch (error) {
        if (controller.signal.aborted) return;
        const outcome = classifyCohortError(error);
        if (outcome.action === 'refetch') {
          versionRef.current = '';
          setNotice('The set of matching targets changed since this list loaded. Showing the current set for the same filters; earlier rows are not kept as a snapshot.');
          setCursors(['']);
          if (!cursor) void load(false);
          return;
        }
        if (outcome.action === 'reset') {
          setNotice('Paging restarted at the first page because the page link no longer matched the current list. Your filters are unchanged.');
          versionRef.current = '';
          setCursors(['']);
          if (!cursor) void load(false);
          return;
        }
        const message = error instanceof Error ? error.message : 'The cohort could not load.';
        setPage({ ...EMPTY_PAGE, state: outcome.action === 'unsupported' ? 'unsupported' : outcome.action === 'denied' ? 'denied' : 'error', message: outcome.action === 'unsupported' ? `The server rejected these filters (${outcome.reason}). No list is shown and the full inventory is not substituted.` : message });
      }
    }
    void load(Boolean(versionRef.current) && !cursor);
    return () => controller.abort();
  }, [config, session, cursor, reload, query, filters.unit]);

  const inventoryById = useMemo(() => new Map(inventory.map((item) => [str(item, 'id'), item])), [inventory]);
  const hostUnit = page.unit === 'hostname';
  const pageStart = pageIndex * PAGE_LIMIT;

  const columns: TableColumn<DataItem>[] = [
    {
      key: 'target',
      label: hostUnit ? 'Hostname' : 'Target',
      render: (item) => {
        const analytics = rec(item.analytics);
        const memberIds = Array.isArray(analytics?.target_ids) ? (analytics!.target_ids as unknown[]).map(String) : [str(item, 'id')];
        const members = finite(analytics?.member_count) ?? memberIds.length;
        const label = hostUnit ? str(analytics, 'host_key') || str(item, 'value') : str(item, 'value');
        if (members <= 1) {
          const id = memberIds[0] || str(item, 'id');
          return (
            <span className="cohort-target">
              <strong>{label}</strong>
              <AnchorButton size="sm" variant="secondary" href={buildDetailHref('target-detail', id)} aria-label={`Open target ${label}`} data-focus-key={`cohort-${id}`}>Open</AnchorButton>
            </span>
          );
        }
        return (
          <span className="cohort-target">
            <strong>{label}</strong>
            <details className="cohort-members">
              <summary>{members} declared targets share this hostname</summary>
              <ul>
                {memberIds.map((id) => {
                  const known = inventoryById.get(id);
                  return (
                    <li key={id}>
                      <span className="mono">{str(known, 'value') || id}</span>
                      {known ? <span className="muted small"> · {str(known, 'kind')} · {str(known, 'target_group_name') || str(known, 'target_group_id')}</span> : null}
                      <AnchorButton size="sm" variant="ghost" href={buildDetailHref('target-detail', id)} aria-label={`Open declared target ${str(known, 'value') || id}`}>Open</AnchorButton>
                    </li>
                  );
                })}
              </ul>
              <p className="muted small">Choose the declared target to open. Checks and ownership are per declared target, so none is chosen for you.</p>
            </details>
          </span>
        );
      },
    },
    {
      key: 'ownership',
      label: 'Ownership',
      render: (item) => {
        const members = finite(rec(item.analytics)?.member_count) ?? 1;
        if (hostUnit && members > 1) return <span className="muted small">Per declared target</span>;
        const verification = rec(item.verification);
        return <VerifyChip state={str(item, 'verification_state') || 'unverified'} provenance={resolveTargetVerificationProvenance(item, verification)} />;
      },
    },
    ...(['waf', 'cdn'] as const).map((family) => ({
      key: family,
      label: family === 'waf' ? 'WAF' : 'CDN',
      render: (item: DataItem) => {
        const analytics = rec(item.analytics);
        const bucket = str(rec(rec(analytics?.families)?.[family]), 'bucket') || str(rec(rec(rec(item.protection_profile)?.families)?.[family]), 'status') || 'not_recorded';
        const meta = BUCKET_LABELS[bucket] ?? { label: humanize(bucket), tone: 'muted' as const };
        const disagree = rec(analytics?.family_disagreement)?.[family] === true;
        return (
          <span className="cohort-cell">
            <Badge tone={meta.tone}>{meta.label}</Badge>
            {disagree ? <small>Declared targets disagree</small> : null}
          </span>
        );
      },
    })),
    {
      key: 'validated',
      label: 'Last validation',
      render: (item) => {
        const members = finite(rec(item.analytics)?.member_count) ?? 1;
        if (hostUnit && members > 1) return <span className="muted small">Per declared target</span>;
        if (!Object.hasOwn(item, 'last_validation_at')) return <span className="muted small">Not available in inventory</span>;
        return item.last_validation_at ? <span className="mono small">{formatDate(item.last_validation_at)}</span> : <span className="muted small">Not checked</span>;
      },
    },
    {
      key: 'group',
      label: 'Target group',
      render: (item) => {
        const members = finite(rec(item.analytics)?.member_count) ?? 1;
        if (hostUnit && members > 1) return <span className="muted small">Per declared target</span>;
        return str(item, 'target_group_name') || str(item, 'target_group_id') || <span className="muted small">Not recorded</span>;
      },
    },
  ];

  const unitNoun = hostUnit ? 'distinct hostnames' : 'declared target records';
  const shownEnd = pageStart + page.items.length;

  return (
    <section className="cohort-panel" aria-labelledby="cohort-title">
      <header className="cohort-head">
        <div>
          <h2 id="cohort-title">Matching {hostUnit ? 'hostnames' : 'targets'}</h2>
          <ul className="cohort-filters" aria-label="Applied filters">
            {Object.entries(filters).filter(([key]) => key !== 'unit').map(([key, value]) => (
              <li key={key}><span className="cohort-filter-key">{FILTER_LABELS[key] ?? humanize(key)}</span> {VALUE_LABELS[value] ?? humanize(value)}</li>
            ))}
            <li><span className="cohort-filter-key">Counted as</span> {hostUnit ? 'Distinct hostnames' : 'Declared target records'}</li>
          </ul>
        </div>
        <div className="cohort-actions">
          <Button size="sm" variant="ghost" onClick={() => setReload((value) => value + 1)}><RefreshCw size={14} aria-hidden="true" />Refresh</Button>
          <Button size="sm" variant="secondary" onClick={onClear}><X size={14} aria-hidden="true" />Clear filters</Button>
        </div>
      </header>

      {notice ? <p className="form-banner" role="status">{notice}</p> : null}

      {page.state === 'ready' ? (
        <p className="cohort-count" aria-live="polite">
          {page.total !== null
            ? <>Showing <span className="tabular-nums">{page.items.length ? pageStart + 1 : 0}</span> to <span className="tabular-nums">{shownEnd}</span> of <span className="tabular-nums">{formatNumber(page.total)}</span> {unitNoun}.</>
            : <>Total not available for this read.</>}
          {' '}Same scope: <span className="tabular-nums">{page.units.targetRecords === null ? 'not reported' : formatNumber(page.units.targetRecords)}</span> declared target records and <span className="tabular-nums">{page.units.normalizedHosts === null ? 'not reported' : formatNumber(page.units.normalizedHosts)}</span> distinct hostnames.
          {page.asOf ? ` Current as of ${formatDate(page.asOf)}.` : ''}
        </p>
      ) : null}

      {page.state === 'loading' ? <div className="skeleton skeleton-row" aria-label="Loading matching targets" /> : null}
      {page.state === 'unsupported' || page.state === 'denied' || page.state === 'error' ? (
        <div className="form-banner error" role="alert">
          {page.state === 'denied' ? 'Your role cannot read this target list.' : page.message}
          {page.state === 'error' ? <> <Button size="sm" variant="ghost" onClick={() => setReload((value) => value + 1)}>Retry</Button></> : null}
        </div>
      ) : null}

      {page.state === 'ready' ? (
        <>
          <DataTable
            className="cohort-table"
            columns={columns}
            items={page.items}
            getRowId={(item, index) => `${str(rec(item.analytics), 'host_key') || str(item, 'id')}-${index}`}
            empty={<EmptyState icon={Target} title="No targets match these filters" body="Nothing in the current declared scope matches. The full inventory is not shown in its place." actionLabel="Clear filters" onAction={onClear} />}
          />
          <nav className="cohort-pager" aria-label="Matching targets pages">
            <Button size="sm" variant="ghost" disabled={pageIndex === 0} onClick={() => setCursors((stack) => stack.slice(0, -1))}>Previous</Button>
            <span className="muted small">Page <span className="tabular-nums">{pageIndex + 1}</span>{page.total !== null ? <> of <span className="tabular-nums">{Math.max(1, Math.ceil(page.total / PAGE_LIMIT))}</span></> : null}</span>
            <Button size="sm" variant="ghost" disabled={!page.nextCursor} onClick={() => setCursors((stack) => [...stack, page.nextCursor])}>Next</Button>
          </nav>
        </>
      ) : null}
    </section>
  );
}
