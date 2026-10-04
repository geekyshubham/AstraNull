import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Eye } from 'lucide-react';
import {
  changeDirectionLabel,
  comparisonReasonLabel,
  presentObservation,
  type PresentedObservation,
} from '../../lib/domain-checks.mjs';
import { fetchTargetObservations } from '../../lib/target-detail-api';
import { getRouteParam, replaceRouteParams } from '../../lib/route-params';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import { formatDate } from '../../lib/utils';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';

const FAMILIES = [
  { id: '', label: 'All layers' },
  { id: 'waf', label: 'WAF' },
  { id: 'cdn', label: 'CDN' },
  { id: 'cloud', label: 'Cloud' },
  { id: 'dns', label: 'DNS provider' },
  { id: 'origin_hosting', label: 'Origin hosting' },
  { id: 'maintenance', label: 'Maintenance' },
] as const;

const FAMILY_LABEL: Record<string, string> = Object.fromEntries(FAMILIES.filter((family) => family.id).map((family) => [family.id, family.label]));

function familyLabel(family: string) {
  return FAMILY_LABEL[family] ?? (family ? family.replace(/_/g, ' ') : 'Layer not recorded');
}

function asItems(value: unknown): DataItem[] {
  return Array.isArray(value) ? value.filter((item): item is DataItem => Boolean(item) && typeof item === 'object' && !Array.isArray(item)) : [];
}

function rec(value: unknown): DataItem | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as DataItem : null;
}

function str(item: DataItem | null | undefined, key: string) {
  const value = item?.[key];
  return typeof value === 'string' ? value : '';
}

type PageState =
  | { state: 'loading' }
  | { state: 'ready'; items: PresentedObservation[]; nextCursor: string; loadingMore: boolean; moreError: string; gaps: DataItem[] }
  | { state: 'unsupported' }
  | { state: 'unavailable'; message: string };

function ObservationSummary({ row }: { row: PresentedObservation }) {
  return (
    <>
      <span className="td-history-outcome">{row.outcomeLabel}</span>
      <span className="td-muted">{row.observedAt ? formatDate(row.observedAt) : 'Time not recorded'}</span>
      {row.attempt !== 'successful' ? <Badge tone={row.attempt === 'failed_attempt' ? 'warn' : 'muted'}>{row.attemptLabel}</Badge> : null}
      {row.live === false ? <Badge tone="muted">Not live evidence</Badge> : null}
    </>
  );
}

function FamilyStateCard({ state }: { state: DataItem }) {
  const last = presentObservation(state.last_successful);
  const failed = presentObservation(state.latest_failed_attempt);
  const failedIsNewer = Boolean(failed && last && failed.observedAt > last.observedAt);
  return (
    <li className="td-family-state">
      <span className="td-label">{familyLabel(str(state, 'family'))}</span>
      <div>
        <span className="td-muted small">Last completed observation</span>
        {last ? (
          <p className="td-history-line"><ObservationSummary row={last} /></p>
        ) : <p className="td-muted">None recorded.</p>}
      </div>
      <div>
        <span className="td-muted small">Latest failed attempt</span>
        {failed ? (
          <p className="td-history-line"><span>{failed.outcomeLabel}</span><span className="td-muted">{failed.observedAt ? formatDate(failed.observedAt) : 'Time not recorded'}</span></p>
        ) : <p className="td-muted">None recorded.</p>}
      </div>
      {failedIsNewer ? <p className="td-muted small">A later attempt failed. It does not replace the last completed observation and is not a provider change.</p> : null}
    </li>
  );
}

/**
 * Target "Changes & history": retained family state, confirmed comparable changes and the paged
 * observation log from `GET /v1/targets/:id/observations`. Reads only; the selected observation is
 * kept across paging and filtering, and nothing here starts a probe.
 */
export function TargetChangesHistory({
  config,
  session,
  targetId,
  profile,
  checkName,
  onInspectRun,
}: {
  config: PortalConfig;
  session: Session;
  targetId: string;
  profile: DataItem | null;
  checkName: (checkId: string) => string;
  onInspectRun: (runId: string, checkId: string, focusKey: string) => void;
}) {
  const [family, setFamily] = useState(() => {
    const value = getRouteParam('hist_family');
    return FAMILIES.some((entry) => entry.id === value) ? value : '';
  });
  const [page, setPage] = useState<PageState>({ state: 'loading' });
  const [reload, setReload] = useState(0);
  const [notice, setNotice] = useState('');
  const [selected, setSelected] = useState<PresentedObservation | null>(null);
  const selectedIdRef = useRef(getRouteParam('obs'));
  const moreController = useRef<AbortController | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    moreController.current?.abort();
    setPage({ state: 'loading' });
    fetchTargetObservations(config, session, targetId, controller.signal, { family: family || undefined }).then((result) => {
      if (controller.signal.aborted) return;
      if (result.state === 'ready') {
        const items = result.items.map(presentObservation).filter((row): row is PresentedObservation => row !== null);
        const comparison = result.comparison;
        const gaps = comparison && comparison.scope === 'newest_page' ? asItems(comparison.comparison_gaps) : [];
        setPage({ state: 'ready', items, nextCursor: result.nextCursor, loadingMore: false, moreError: '', gaps });
        const wanted = selectedIdRef.current;
        if (wanted) setSelected((current) => current?.id === wanted ? current : items.find((row) => row.id === wanted) ?? current);
      } else if (result.state === 'unsupported') {
        setPage({ state: 'unsupported' });
      } else {
        setPage({ state: 'unavailable', message: result.message });
      }
    });
    return () => controller.abort();
  }, [config, session, targetId, family, reload]);

  const loadOlder = useCallback(() => {
    if (page.state !== 'ready' || !page.nextCursor || page.loadingMore) return;
    const controller = new AbortController();
    moreController.current = controller;
    const cursor = page.nextCursor;
    setPage({ ...page, loadingMore: true, moreError: '' });
    fetchTargetObservations(config, session, targetId, controller.signal, { family: family || undefined, cursor }).then((result) => {
      if (controller.signal.aborted) return;
      if (result.state === 'unavailable' && result.code === 'invalid_cursor') {
        setNotice('The older-page link expired, so history restarted at the newest page. Your layer filter is unchanged.');
        setReload((value) => value + 1);
        return;
      }
      if (result.state !== 'ready') {
        setPage((current) => current.state === 'ready'
          ? { ...current, loadingMore: false, moreError: result.state === 'unavailable' ? result.message : 'Older observations could not load.' }
          : current);
        return;
      }
      const incoming = result.items.map(presentObservation).filter((row): row is PresentedObservation => row !== null);
      const wanted = selectedIdRef.current;
      const match = wanted ? incoming.find((row) => row.id === wanted) : undefined;
      if (match) setSelected((current) => current ?? match);
      setPage((current) => {
        if (current.state !== 'ready') return current;
        const seen = new Set(current.items.map((row) => row.id));
        return { ...current, items: [...current.items, ...incoming.filter((row) => !seen.has(row.id))], nextCursor: result.nextCursor, loadingMore: false, moreError: '' };
      });
    });
  }, [config, session, targetId, family, page]);

  function select(row: PresentedObservation) {
    selectedIdRef.current = row.id;
    setSelected(row);
    replaceRouteParams({ obs: row.id });
  }

  function changeFamily(next: string) {
    setNotice('');
    setFamily(next);
    replaceRouteParams({ hist_family: next || null });
  }

  const states = Array.isArray(profile?.retained_family_states) ? asItems(profile!.retained_family_states) : null;
  const changes = Array.isArray(profile?.comparable_changes) ? asItems(profile!.comparable_changes) : null;
  const gaps = Array.isArray(profile?.comparison_gaps) ? asItems(profile!.comparison_gaps) : page.state === 'ready' ? page.gaps : [];
  const loadedById = useMemo(() => new Map(page.state === 'ready' ? page.items.map((row) => [row.id, row]) : []), [page]);
  const selectedLoaded = selected ? loadedById.has(selected.id) : false;
  const pendingSelection = !selected && selectedIdRef.current && page.state === 'ready';

  return (
    <>
      <section aria-labelledby="td-family-state-title">
        <header className="td-section-head">
          <div>
            <h2 id="td-family-state-title">Current state by layer</h2>
            <p>The last completed observation for each layer, kept separately from the latest failed attempt.</p>
          </div>
        </header>
        {states === null ? <p className="td-muted">This server does not report retained layer state yet.</p>
          : states.length ? <ul className="td-family-states">{states.map((state) => <FamilyStateCard key={str(state, 'family')} state={state} />)}</ul>
            : <p className="td-muted">No observations are retained for this target yet.</p>}
      </section>

      <section aria-labelledby="td-changes-title">
        <header className="td-section-head">
          <div>
            <h2 id="td-changes-title">Confirmed changes</h2>
            <p>Only two completed observations with the same check, scenario, corpus, layer and producer are compared.</p>
          </div>
        </header>
        {changes === null ? <p className="td-muted">This server does not report compared changes yet.</p> : (
          <ul className="td-change-list">
            {changes.map((change) => {
              const previous = loadedById.get(str(change, 'previous_id'));
              const next = loadedById.get(str(change, 'observation_id'));
              return (
                <li key={`${str(change, 'family')}-${str(change, 'observation_id')}`}>
                  <span className="td-label">{familyLabel(str(change, 'family'))}</span>
                  <strong>{changeDirectionLabel(change.direction)}</strong>
                  {str(rec(change.details), 'before_provider') || str(rec(change.details), 'after_provider') ? (
                    <span>{str(rec(change.details), 'before_provider') || 'not recorded'} to {str(rec(change.details), 'after_provider') || 'not recorded'}</span>
                  ) : null}
                  <span className="td-muted">
                    {previous ? `${previous.outcomeLabel}, ${formatDate(previous.observedAt)}` : 'Earlier completed observation'}
                    {' to '}
                    {next ? `${next.outcomeLabel}, ${formatDate(next.observedAt)}` : 'newest completed observation'}
                  </span>
                </li>
              );
            })}
            {gaps.map((gap) => (
              <li key={`gap-${str(gap, 'family')}-${str(gap, 'observation_id')}`}>
                <span className="td-label">{familyLabel(str(gap, 'family'))}</span>
                <strong>Not compared</strong>
                <span className="td-muted">{comparisonReasonLabel(gap.reason)}</span>
              </li>
            ))}
            {!changes.length && !gaps.length ? <li className="td-muted">No confirmed change between the two newest comparable observations of any layer.</li> : null}
          </ul>
        )}
      </section>

      <section aria-labelledby="td-observations-history-title">
        <header className="td-section-head">
          <div>
            <h2 id="td-observations-history-title">Observation history</h2>
            <p>Newest first, as recorded. Select one to see its scope and versions.</p>
          </div>
          <label className="td-field td-history-filter">
            <span>Layer</span>
            <select value={family} onChange={(event) => changeFamily(event.target.value)}>
              {FAMILIES.map((entry) => <option key={entry.id || 'all'} value={entry.id}>{entry.label}</option>)}
            </select>
          </label>
        </header>
        {notice ? <p className="form-banner" role="status">{notice}</p> : null}
        {page.state === 'loading' ? <div className="skeleton skeleton-row" aria-label="Loading observation history" /> : null}
        {page.state === 'unsupported' ? <p className="td-muted">Observation history is not available from this server yet. Only the current observation is shown on Overview.</p> : null}
        {page.state === 'unavailable' ? (
          <p className="td-form-error" role="alert">{page.message} <Button size="sm" variant="ghost" onClick={() => setReload((value) => value + 1)}>Retry</Button></p>
        ) : null}
        {page.state === 'ready' ? (
          <div className="td-history-layout">
            <div>
              {page.items.length ? (
                <ul className="td-observation-history" aria-label="Recorded observations">
                  {page.items.map((row) => (
                    <li key={row.id} className={selected?.id === row.id ? 'is-selected' : undefined}>
                      <span className="td-label">{familyLabel(row.family)}</span>
                      <ObservationSummary row={row} />
                      <Button size="sm" variant="ghost" aria-pressed={selected?.id === row.id} aria-label={`Select ${familyLabel(row.family)} observation, ${row.outcomeLabel}, ${row.observedAt ? formatDate(row.observedAt) : 'time not recorded'}`} onClick={() => select(row)}>
                        {selected?.id === row.id ? 'Selected' : 'Select'}
                      </Button>
                    </li>
                  ))}
                </ul>
              ) : <p className="td-muted">{family ? `No ${familyLabel(family)} observations recorded.` : 'No observations recorded for this target.'}</p>}
              <p className="td-muted small">Showing {page.items.length} loaded observation{page.items.length === 1 ? '' : 's'}{page.nextCursor ? '; older ones are available.' : '. This is the full retained history for this filter.'}</p>
              {page.moreError ? <p className="td-form-error" role="alert">{page.moreError}</p> : null}
              {page.nextCursor ? <Button size="sm" variant="secondary" loading={page.loadingMore} onClick={loadOlder}>Load older observations</Button> : null}
            </div>
            <aside className="td-observation-detail" aria-label="Selected observation" aria-live="polite">
              {selected ? (
                <>
                  <h3>{familyLabel(selected.family)}: {selected.outcomeLabel}</h3>
                  {!selectedLoaded ? <p className="td-muted small">Kept from an earlier page or filter.</p> : null}
                  <dl className="td-review-list">
                    <div><dt>Observed</dt><dd>{selected.observedAt ? formatDate(selected.observedAt) : 'Not recorded'}</dd></div>
                    <div><dt>Finalized</dt><dd>{selected.completedAt ? formatDate(selected.completedAt) : 'Not finalized'}</dd></div>
                    <div><dt>Attempt</dt><dd>{selected.attemptLabel}</dd></div>
                    <div><dt>Producer</dt><dd>{selected.producerLabel}{selected.live === false ? ' (not live external evidence)' : ''}</dd></div>
                    <div><dt>Check</dt><dd>{selected.checkId ? checkName(selected.checkId) : 'Not recorded'}</dd></div>
                    <div><dt>Versions</dt><dd>Check {selected.checkVersion || 'not recorded'} · scenario {selected.scenarioVersion || 'not recorded'} · corpus {selected.corpusVersion || 'not recorded'}</dd></div>
                    {selected.bindingId ? <div><dt>Origin relation</dt><dd className="mono">{selected.bindingId}</dd></div> : null}
                  </dl>
                  {selected.testRunId && selected.checkId ? (
                    <Button size="sm" variant="secondary" data-focus-key={`history-run-${selected.id}`} onClick={() => onInspectRun(selected.testRunId, selected.checkId, `history-run-${selected.id}`)}>
                      <Eye size={14} aria-hidden="true" />View run evidence
                    </Button>
                  ) : <p className="td-muted small">No run is recorded for this observation.</p>}
                </>
              ) : pendingSelection ? (
                <p className="td-muted">The selected observation is not in the loaded pages. Load older observations to find it.</p>
              ) : <p className="td-muted">Select an observation to see its scope, versions and source run.</p>}
            </aside>
          </div>
        ) : null}
      </section>
    </>
  );
}
