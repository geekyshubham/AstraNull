import { useEffect, useId, useRef, useState } from 'react';
import { listTargetCandidates, type PvFailure, type TargetCandidate } from '../../../lib/protection-validation-api';
import type { PortalConfig, Session } from '../../../lib/types';
import { Button } from '../../ui/button';
import { FailureNotice } from './shared';

type PickerState =
  | { state: 'loading' }
  | { state: 'ready'; items: TargetCandidate[]; nextCursor: string; loadingMore: boolean; moreError: string }
  | { state: 'failed'; failure: PvFailure };

/** Paged picker over existing declared targets; it never discovers addresses or totals the estate from loaded pages. */
export function TargetCandidatePicker({
  config,
  session,
  legend,
  value,
  onChange,
  excludeIds = [],
  error,
  help,
}: {
  config: PortalConfig;
  session: Session;
  legend: string;
  value: string;
  onChange: (id: string, candidate: TargetCandidate | null) => void;
  excludeIds?: string[];
  error?: string;
  help?: string;
}) {
  const id = useId();
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const [reload, setReload] = useState(0);
  const [list, setList] = useState<PickerState>({ state: 'loading' });
  const listController = useRef<AbortController | null>(null);

  useEffect(() => {
    const handle = window.setTimeout(() => setQuery(search.trim()), 250);
    return () => window.clearTimeout(handle);
  }, [search]);

  useEffect(() => {
    const controller = new AbortController();
    listController.current = controller;
    setList({ state: 'loading' });
    listTargetCandidates(config, session, { q: query || undefined }, controller.signal)
      .then((result) => {
        if (controller.signal.aborted) return;
        setList(result.state === 'ready'
          ? { state: 'ready', items: result.value.items, nextCursor: result.value.nextCursor, loadingMore: false, moreError: '' }
          : { state: 'failed', failure: result });
      })
      .catch(() => undefined);
    return () => controller.abort();
  }, [config, session, query, reload]);

  async function loadMore() {
    const controller = listController.current;
    if (list.state !== 'ready' || list.loadingMore || !list.nextCursor || !controller || controller.signal.aborted) return;
    setList({ ...list, loadingMore: true, moreError: '' });
    const result = await listTargetCandidates(config, session, { q: query || undefined, cursor: list.nextCursor }, controller.signal);
    if (controller.signal.aborted) return;
    setList((current) => {
      if (current.state !== 'ready') return current;
      if (result.state !== 'ready') return { ...current, loadingMore: false, moreError: 'More targets could not load. Retry.' };
      const seen = new Set(current.items.map((item) => item.id));
      return { ...current, items: [...current.items, ...result.value.items.filter((item) => !seen.has(item.id))], nextCursor: result.value.nextCursor, loadingMore: false };
    });
  }

  const excluded = new Set(excludeIds);
  const items = list.state === 'ready' ? list.items.filter((item) => !excluded.has(item.id)) : [];
  const helpId = `${id}-help`;

  return (
    <fieldset className="pv-picker" aria-describedby={helpId} aria-invalid={error ? true : undefined}>
      <legend>{legend}</legend>
      <label className="td-field">
        <span>Search declared targets</span>
        <input type="search" value={search} onChange={(event) => setSearch(event.target.value)} autoComplete="off" />
      </label>
      {list.state === 'loading' ? <div className="skeleton skeleton-row" aria-label="Loading declared targets" /> : null}
      {list.state === 'failed' ? <FailureNotice failure={list.failure} subject="declared targets" onRetry={() => setReload((value) => value + 1)} /> : null}
      {list.state === 'ready' && !items.length ? (
        <p className="td-muted small">{query ? 'No declared target matches this search.' : 'No other declared target is available.'} Add the hostname, URL or IP as a target first. <a href="#targets">Go to targets</a></p>
      ) : null}
      {items.length ? (
        <ul className="pv-picker-list">
          {items.map((item) => (
            <li key={item.id}>
              <label className="pv-picker-option">
                <input type="radio" name={`${id}-target`} value={item.id} checked={value === item.id} onChange={() => onChange(item.id, item)} />
                <span>
                  <span className="mono pv-break">{item.value || item.id}</span>
                  <span className="td-muted small mono pv-break">{item.id}{item.kind ? ` · ${item.kind}` : ''}{item.verification_state ? ` · ${item.verification_state.replace(/_/g, ' ')}` : ''}</span>
                </span>
              </label>
            </li>
          ))}
        </ul>
      ) : null}
      {list.state === 'ready' ? (
        <div className="pv-actions">
          {list.nextCursor ? <Button size="sm" variant="ghost" loading={list.loadingMore} loadingText="Loading more" onClick={() => void loadMore()}>Load more targets</Button> : null}
          <span className="td-muted small" role="status">{list.nextCursor ? 'More declared targets are available; this list shows loaded pages only.' : items.length ? 'All matching declared targets are shown.' : ''}</span>
          {list.moreError ? <span className="td-form-error small" role="alert">{list.moreError}</span> : null}
        </div>
      ) : null}
      <span id={helpId} className={error ? 'td-form-error' : 'td-muted small'}>{error ?? help ?? 'Only existing declared targets can be chosen.'}</span>
    </fieldset>
  );
}
