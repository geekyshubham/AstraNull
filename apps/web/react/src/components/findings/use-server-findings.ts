import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { requestJson } from '../../lib/api';
import { findingStatus } from '../../lib/finding-lifecycle.mjs';
import {
  FINDING_STATUSES,
  findingSeverityClass,
  findingsComplete,
  findingsPath,
  parseFindingsEnvelope,
  FINDINGS_LIMIT_MAX,
  type FindingsEnvelope,
  type FindingsFilters,
} from '../../lib/findings-query.mjs';
import type { DataItem, PortalConfig, Session } from '../../lib/types';

export type ServerFindingsPage = {
  state: 'loading' | 'ready' | 'error';
  envelope: FindingsEnvelope | null;
  /** Request path that produced `envelope`; it lags the requested path while the next page loads. */
  envelopePath: string;
  error: string;
  /** Server error code (for example `invalid_query_value`), '' when none. */
  code: string;
};

function errorCode(err: unknown) {
  const payload = (err as { payload?: unknown })?.payload;
  return payload && typeof payload === 'object' && typeof (payload as DataItem).error === 'string' ? String((payload as DataItem).error) : '';
}

function errorMessage(err: unknown, fallback: string) {
  return err instanceof Error && err.message ? err.message : fallback;
}

/**
 * One server page of `GET /v1/findings` for one predicate. The previous envelope stays visible
 * while the next one loads, so paging never blanks the table.
 */
export function useFindingsPage(config: PortalConfig, session: Session, filters: FindingsFilters, reloadKey = 0, enabled = true): ServerFindingsPage & { retry: () => void } {
  const path = findingsPath(filters);
  const [retryKey, setRetryKey] = useState(0);
  const [page, setPage] = useState<ServerFindingsPage>({ state: 'loading', envelope: null, envelopePath: '', error: '', code: '' });
  useEffect(() => {
    if (!enabled) return undefined;
    const controller = new AbortController();
    setPage((current) => ({ ...current, state: 'loading', error: '', code: '' }));
    requestJson(config, session, path, { signal: controller.signal })
      .then((body) => {
        if (!controller.signal.aborted) setPage({ state: 'ready', envelope: parseFindingsEnvelope(body), envelopePath: path, error: '', code: '' });
      })
      .catch((err) => {
        if (!controller.signal.aborted) setPage({ state: 'error', envelope: null, envelopePath: '', error: errorMessage(err, 'Findings could not load.'), code: errorCode(err) });
      });
    return () => controller.abort();
  }, [config, session, path, reloadKey, retryKey, enabled]);
  const retry = useCallback(() => setRetryKey((value) => value + 1), []);
  return { ...page, retry };
}

export type StatusTotals = {
  state: 'loading' | 'ready' | 'error';
  /** Exact server total per key. null when the server sent no total. */
  totals: Record<string, number | null>;
  error: string;
};

export type FindingPages = {
  state: 'loading' | 'ready' | 'error';
  /** First server page per key; `total` is that predicate's full count. */
  pages: Record<string, FindingsEnvelope>;
  error: string;
};

const PREDICATE_BATCH = 6;

/** First page of several predicates, a few reads at a time so a long list never floods the API. */
export function useFindingPages(config: PortalConfig, session: Session, entries: Record<string, FindingsFilters>, reloadKey = 0, enabled = true, limit = 1): FindingPages {
  const key = JSON.stringify(entries);
  const [result, setResult] = useState<FindingPages>({ state: 'loading', pages: {}, error: '' });
  useEffect(() => {
    if (!enabled) return undefined;
    const controller = new AbortController();
    const parsed = Object.entries(JSON.parse(key) as Record<string, FindingsFilters>);
    setResult((current) => ({ ...current, state: 'loading', error: '' }));
    async function load() {
      const pages: Record<string, FindingsEnvelope> = {};
      for (let index = 0; index < parsed.length; index += PREDICATE_BATCH) {
        const batch = parsed.slice(index, index + PREDICATE_BATCH);
        const read = await Promise.all(batch.map(([name, filters]) => requestJson(config, session, findingsPath({ ...filters, page: 1, limit }), { signal: controller.signal })
          .then((body) => [name, parseFindingsEnvelope(body)] as const)));
        read.forEach(([name, envelope]) => { pages[name] = envelope; });
      }
      return pages;
    }
    load()
      .then((pages) => {
        if (!controller.signal.aborted) setResult({ state: 'ready', pages, error: '' });
      })
      .catch((err) => {
        if (!controller.signal.aborted) setResult({ state: 'error', pages: {}, error: errorMessage(err, 'Finding counts could not load.') });
      });
    return () => controller.abort();
  }, [config, session, key, reloadKey, enabled, limit]);
  return result;
}

/** Exact server totals for several predicates, one `limit=1` read each. */
export function useFindingTotals(config: PortalConfig, session: Session, entries: Record<string, FindingsFilters>, reloadKey = 0, enabled = true): StatusTotals {
  const pages = useFindingPages(config, session, entries, reloadKey, enabled, 1);
  return useMemo(() => ({
    state: pages.state,
    totals: Object.fromEntries(Object.entries(pages.pages).map(([name, envelope]) => [name, envelope.total])),
    error: pages.error,
  }), [pages]);
}

/** True when a ready page holds every row the server matched, so counts over it are exact. */
function completePage(page: ServerFindingsPage) {
  return page.state === 'ready' && findingsComplete(page.envelope, page.envelope?.items.length ?? 0);
}

/**
 * Exact totals for each single lifecycle status (plus `all`) under the same other filters. One
 * 200-row read comes first; when the server says it holds every match, the per-status counts use
 * the server's own effective status over those rows. Otherwise each status is its own server total.
 */
export function useFindingStatusTotals(config: PortalConfig, session: Session, base: Omit<FindingsFilters, 'status' | 'page' | 'limit'>, reloadKey = 0, enabled = true): StatusTotals {
  const sample = useFindingsPage(config, session, { ...base, limit: FINDINGS_LIMIT_MAX }, reloadKey, enabled);
  const complete = completePage(sample);
  const entries = Object.fromEntries(['all', ...FINDING_STATUSES].map((status) => [status, { ...base, status: status === 'all' ? '' : status }]));
  const remote = useFindingTotals(config, session, entries, reloadKey, enabled && sample.state !== 'loading' && !complete);
  const derived = useMemo<StatusTotals | null>(() => {
    if (!complete || !sample.envelope) return null;
    const totals: Record<string, number | null> = Object.fromEntries(['all', ...FINDING_STATUSES].map((status) => [status, 0]));
    totals.all = sample.envelope.total;
    for (const row of sample.envelope.items) {
      const status = findingStatus(row);
      if (status in totals && status !== 'all') totals[status] = (totals[status] ?? 0) + 1;
    }
    return { state: 'ready', totals, error: '' };
  }, [complete, sample.envelope]);
  if (sample.state === 'loading' && enabled) return { state: 'loading', totals: {}, error: '' };
  return derived ?? remote;
}

/**
 * Server severity classes per display bucket, matching `severityKey` in lib/dashboard-metrics. The
 * server folds aliases (`S2` is `high`), so each class is one query and nothing is counted twice.
 */
export const SEVERITY_TOKENS: Record<'critical' | 'high' | 'medium' | 'low', readonly string[]> = {
  critical: ['critical'],
  high: ['high'],
  medium: ['medium'],
  low: ['low', 'info'],
};

const PRIORITY_TOKENS = [...SEVERITY_TOKENS.critical, ...SEVERITY_TOKENS.high, ...SEVERITY_TOKENS.medium, ...SEVERITY_TOKENS.low];

export type OpenFindingOverview = {
  state: 'loading' | 'ready' | 'error';
  error: string;
  /** Exact server total of `status=open`. */
  total: number | null;
  /** Exact per-bucket totals; `unrecorded` is total minus every known token. */
  severity: { critical: number; high: number; medium: number; low: number; unrecorded: number } | null;
  /** Up to `priorityLimit` open findings, most severe token first (server order inside a token). */
  priority: DataItem[];
  /** Up to `oldestLimit` oldest open findings, read from the last server pages. */
  oldest: DataItem[];
};

/**
 * Open-finding overview for the dashboard from server predicates only: the exact open total, exact
 * per-severity totals, the most severe open rows and the oldest open rows. Nothing is derived from
 * whichever page the shell happened to load.
 */
export function useOpenFindingOverview(config: PortalConfig, session: Session, reloadKey = 0, priorityLimit = 3, oldestLimit = 8, sample: ServerFindingsPage | null = null): OpenFindingOverview {
  // A complete `status=open` sample already holds every open row, so its counts are exact and the
  // per-class server reads are skipped. Without a complete sample every number is a server total.
  const sampleComplete = sample ? completePage(sample) : false;
  const remoteEnabled = !sample || sample.state === 'error' || (sample.state === 'ready' && !sampleComplete);
  const totals = useFindingTotals(config, session, {
    open: { status: 'open' },
    ...Object.fromEntries(PRIORITY_TOKENS.map((token) => [`sev:${token}`, { status: 'open', severity: token }])),
  }, reloadKey, remoteEnabled);
  const [rows, setRows] = useState<{ key: string; priority: DataItem[]; oldest: DataItem[]; error: string } | null>(null);
  const totalsKey = totals.state === 'ready' ? JSON.stringify(totals.totals) : '';

  useEffect(() => {
    if (!totalsKey || !remoteEnabled) return undefined;
    const counts = JSON.parse(totalsKey) as Record<string, number | null>;
    const controller = new AbortController();
    const get = (filters: FindingsFilters) => requestJson(config, session, findingsPath(filters), { signal: controller.signal }).then((body) => parseFindingsEnvelope(body).items);
    async function load() {
      const priority: DataItem[] = [];
      for (const token of PRIORITY_TOKENS) {
        if (priority.length >= priorityLimit) break;
        if (!counts[`sev:${token}`]) continue;
        priority.push(...await get({ status: 'open', severity: token, limit: priorityLimit - priority.length }));
      }
      const open = counts.open ?? 0;
      let oldest: DataItem[] = [];
      if (open > 0) {
        const lastPage = Math.ceil(open / oldestLimit);
        const pages = lastPage > 1 ? [lastPage - 1, lastPage] : [1];
        const read = await Promise.all(pages.map((page) => get({ status: 'open', limit: oldestLimit, page })));
        oldest = read.flat().reverse().slice(0, oldestLimit);
      }
      return { priority, oldest };
    }
    load()
      .then((result) => {
        if (!controller.signal.aborted) setRows({ key: totalsKey, ...result, error: '' });
      })
      .catch((err) => {
        if (!controller.signal.aborted) setRows({ key: totalsKey, priority: [], oldest: [], error: errorMessage(err, 'Open findings could not load.') });
      });
    return () => controller.abort();
  }, [config, session, totalsKey, priorityLimit, oldestLimit, remoteEnabled]);

  if (sample && sampleComplete && sample.envelope) return overviewFromCompleteRows(sample.envelope.items, sample.envelope.total, priorityLimit, oldestLimit);
  if (sample && sample.state === 'loading') return { state: 'loading', error: '', total: null, severity: null, priority: [], oldest: [] };
  if (totals.state !== 'ready') return { state: totals.state, error: totals.error, total: null, severity: null, priority: [], oldest: [] };
  const sum = (tokens: readonly string[]) => tokens.reduce((acc, token) => acc + (totals.totals[`sev:${token}`] ?? 0), 0);
  const total = totals.totals.open ?? null;
  const severity = total === null ? null : (() => {
    const critical = sum(SEVERITY_TOKENS.critical);
    const high = sum(SEVERITY_TOKENS.high);
    const medium = sum(SEVERITY_TOKENS.medium);
    const low = sum(SEVERITY_TOKENS.low);
    return { critical, high, medium, low, unrecorded: Math.max(0, total - critical - high - medium - low) };
  })();
  const current = rows && rows.key === totalsKey ? rows : null;
  return {
    state: current ? (current.error ? 'error' : 'ready') : 'loading',
    error: current?.error ?? '',
    total,
    severity,
    priority: current?.priority ?? [],
    oldest: current?.oldest ?? [],
  };
}

/** Overview from every open row (server-complete), using the server's severity classes and order. */
function overviewFromCompleteRows(rows: DataItem[], total: number | null, priorityLimit: number, oldestLimit: number): OpenFindingOverview {
  const byClass = new Map<string, DataItem[]>();
  for (const row of rows) {
    const key = findingSeverityClass(row.severity);
    byClass.set(key, [...(byClass.get(key) ?? []), row]);
  }
  const count = (key: string) => byClass.get(key)?.length ?? 0;
  const priority = PRIORITY_TOKENS.flatMap((token) => byClass.get(token) ?? []).slice(0, priorityLimit);
  const severity = total === null ? null : {
    critical: count('critical'),
    high: count('high'),
    medium: count('medium'),
    low: count('low') + count('info'),
    unrecorded: count('unknown'),
  };
  return { state: 'ready', error: '', total, severity, priority, oldest: rows.slice(-oldestLimit).reverse() };
}

export type ProgressiveFindings = {
  state: 'loading' | 'ready' | 'error';
  items: DataItem[];
  /** Envelope of the newest page read; `total` is the full predicate count. */
  envelope: FindingsEnvelope | null;
  pagesRead: number;
  /** Predicate key the loaded `items` belong to; '' until the first page of a predicate arrives. */
  itemsKey: string;
  /** Every matching row has been read. Until then, anything built from `items` is partial. */
  complete: boolean;
  loadingMore: boolean;
  error: string;
  loadMore: () => void;
  retry: () => void;
};

/**
 * Reads one predicate page by page at the server's maximum page size, only when asked for more.
 * Rows are appended in server order and de-duplicated by id; nothing is capped silently.
 */
export function useProgressiveFindings(config: PortalConfig, session: Session, filters: Omit<FindingsFilters, 'page' | 'limit'>, reloadKey = 0, enabled = true, pageSize = 200): ProgressiveFindings {
  const key = JSON.stringify(filters);
  const [retryKey, setRetryKey] = useState(0);
  const [state, setState] = useState<Omit<ProgressiveFindings, 'loadMore' | 'retry'>>({ state: 'loading', items: [], envelope: null, pagesRead: 0, itemsKey: '', complete: false, loadingMore: false, error: '' });
  const controllerRef = useRef<AbortController | null>(null);

  const read = useCallback((pageNumber: number, append: boolean) => {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    const base = JSON.parse(key) as FindingsFilters;
    setState((current) => append ? { ...current, loadingMore: true, error: '' } : { state: 'loading', items: [], envelope: null, pagesRead: 0, itemsKey: '', complete: false, loadingMore: false, error: '' });
    requestJson(config, session, findingsPath({ ...base, limit: pageSize, page: pageNumber }), { signal: controller.signal })
      .then((body) => {
        if (controller.signal.aborted) return;
        const envelope = parseFindingsEnvelope(body);
        setState((current) => {
          const seen = new Set(append ? current.items.map((item) => String(item.id ?? '')) : []);
          const items = [...(append ? current.items : []), ...envelope.items.filter((item) => {
            const id = String(item.id ?? '');
            if (!id || seen.has(id)) return !id;
            seen.add(id);
            return true;
          })];
          return { state: 'ready', items, envelope, pagesRead: pageNumber, itemsKey: key, complete: findingsComplete(envelope, items.length), loadingMore: false, error: '' };
        });
      })
      .catch((err) => {
        if (controller.signal.aborted) return;
        setState((current) => append
          ? { ...current, loadingMore: false, error: errorMessage(err, 'More findings could not load.') }
          : { state: 'error', items: [], envelope: null, pagesRead: 0, itemsKey: '', complete: false, loadingMore: false, error: errorMessage(err, 'Findings could not load.') });
      });
  }, [config, session, key, pageSize]);

  useEffect(() => {
    if (!enabled) return undefined;
    read(1, false);
    return () => controllerRef.current?.abort();
  }, [read, reloadKey, retryKey, enabled]);

  const loadMore = useCallback(() => {
    if (state.complete || state.loadingMore || state.state !== 'ready') return;
    read(state.pagesRead + 1, true);
  }, [read, state.complete, state.loadingMore, state.state, state.pagesRead]);
  const retry = useCallback(() => setRetryKey((value) => value + 1), []);
  return { ...state, loadMore, retry };
}
