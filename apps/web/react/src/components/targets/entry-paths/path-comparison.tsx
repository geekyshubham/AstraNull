import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  cancelEntryPathComparison,
  cancelRun,
  getEntryPathComparison,
  listEntryPathComparisons,
  planEntryPathComparison,
  pvErrorCode,
  pvFailureOf,
  startEntryPathComparison,
  type ComparisonPlan,
  type ComparisonRequest,
  type EntryPath,
  type LayerExpectedOutcome,
  type PathComparison,
  type PvFailure,
} from '../../../lib/protection-validation-api';
import { ConfirmModal } from '../../../lib/crud-ui';
import { apiErrorMessage } from '../../../lib/error-messages';
import { expectationConflictLabel } from '../../../lib/expectation-conflicts.mjs';
import type { DataItem, PortalConfig, Session } from '../../../lib/types';
import { formatDate } from '../../../lib/utils';
import { Badge } from '../../ui/badge';
import { Button } from '../../ui/button';
import {
  compatibilityView,
  comparisonProgress,
  LAYER_LABELS,
  LAYER_OUTCOME_LABELS,
  labelFrom,
  PATH_OUTCOME_LABELS,
  PATH_OUTCOME_TONES,
  PROTECTION_LAYERS,
  RELATION_KIND_LABELS,
  summaryView,
  toneFrom,
  writeErrorCopy,
} from './presenter.mjs';
import { EvidenceRefList, FailureNotice, LimitationList, useStickySelection } from './shared';

const SCENARIO_PATTERN = /^[a-z0-9][a-z0-9_.:-]{0,95}$/;
const MAX_PATHS = 32;
const POLL_MS = 5000;

type ListState = { state: 'loading' } | { state: 'ready'; items: PathComparison[]; nextCursor: string } | { state: 'failed'; failure: PvFailure };
type DetailState = { state: 'idle' } | { state: 'loading' } | { state: 'ready'; value: PathComparison } | { state: 'failed'; failure: PvFailure };
type Draft = { primary: string; included: string[]; scenario: string; outcomes: Record<string, LayerExpectedOutcome> };

function str(item: DataItem | null | undefined, key: string) {
  const value = item?.[key];
  return typeof value === 'string' ? value : '';
}

function pathLabel(path: EntryPath | undefined, fallbackId: string) {
  if (!path) return fallbackId;
  return `${path.entry_target_value || path.entry_target_id} (${labelFrom(RELATION_KIND_LABELS, path.relation_kind)})`;
}

function defaultOutcomes(primary: EntryPath | undefined): Record<string, LayerExpectedOutcome> {
  return Object.fromEntries(PROTECTION_LAYERS.map((layer) => [layer, primary?.required_layers.includes(layer) ? 'enforce' : 'no_expectation'])) as Record<string, LayerExpectedOutcome>;
}

function draftFromComparison(comparison: PathComparison): Draft {
  const expectation = comparison.expectation ?? {};
  const outcomes = (expectation.layer_outcomes && typeof expectation.layer_outcomes === 'object' ? expectation.layer_outcomes : {}) as Record<string, LayerExpectedOutcome>;
  return {
    primary: comparison.primary_entry_path_id,
    included: [...new Set([comparison.primary_entry_path_id, ...comparison.items.map((item) => item.entry_path_id)])].filter(Boolean),
    scenario: str(expectation, 'scenario'),
    outcomes: { ...Object.fromEntries(PROTECTION_LAYERS.map((layer) => [layer, 'no_expectation'])), ...outcomes } as Record<string, LayerExpectedOutcome>,
  };
}

/** Reviewed entry-path comparisons: plan is passive, start needs an explicit confirmation of the exact plan, and reads never start checks. */
export function PathComparisonPanel({
  config,
  session,
  target,
  paths,
  canStart,
  ownershipDone,
  onStarted,
}: {
  config: PortalConfig;
  session: Session;
  target: DataItem;
  paths: EntryPath[];
  canStart: boolean;
  ownershipDone: boolean;
  onStarted: (message: string) => void;
}) {
  const targetId = str(target, 'id');
  const active = useMemo(() => paths.filter((path) => path.status === 'active'), [paths]);
  const byId = useMemo(() => new Map(paths.map((path) => [path.id, path])), [paths]);
  const [list, setList] = useState<ListState>({ state: 'loading' });
  const [reload, setReload] = useState(0);
  const [selectedId, setSelectedId] = useStickySelection(session, targetId, 'comparison');
  const [detail, setDetail] = useState<DetailState>({ state: 'idle' });
  const [composing, setComposing] = useState(false);
  const [draft, setDraft] = useState<Draft>({ primary: '', included: [], scenario: '', outcomes: defaultOutcomes(undefined) });
  const [draftErrors, setDraftErrors] = useState<{ primary?: string; included?: string; scenario?: string }>({});
  const [review, setReview] = useState<{ request: ComparisonRequest; plan: ComparisonPlan } | null>(null);
  const [planning, setPlanning] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [stopOpen, setStopOpen] = useState(false);
  const composeHeading = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    const controller = new AbortController();
    listEntryPathComparisons(config, session, targetId, {}, controller.signal)
      .then((result) => {
        if (controller.signal.aborted) return;
        setList(result.state === 'ready' ? { state: 'ready', items: result.value.items, nextCursor: result.value.nextCursor } : { state: 'failed', failure: result });
      })
      .catch(() => undefined);
    return () => controller.abort();
  }, [config, session, targetId, reload]);

  const loadDetail = useCallback(async (id: string, signal?: AbortSignal, quiet = false) => {
    if (!quiet) setDetail({ state: 'loading' });
    const result = await getEntryPathComparison(config, session, id, signal);
    if (signal?.aborted) return;
    setDetail((current) => {
      if (result.state === 'ready') return { state: 'ready', value: result.value };
      return quiet && current.state === 'ready' ? current : { state: 'failed', failure: result };
    });
  }, [config, session]);

  useEffect(() => {
    if (!selectedId) { setDetail({ state: 'idle' }); return undefined; }
    const controller = new AbortController();
    loadDetail(selectedId, controller.signal).catch(() => undefined);
    return () => controller.abort();
  }, [selectedId, loadDetail]);

  const running = detail.state === 'ready' && detail.value.status === 'running';
  useEffect(() => {
    if (!running || !selectedId) return undefined;
    const controller = new AbortController();
    const handle = window.setInterval(() => {
      if (document.visibilityState === 'hidden') return;
      loadDetail(selectedId, controller.signal, true).catch(() => undefined);
    }, POLL_MS);
    return () => { controller.abort(); window.clearInterval(handle); };
  }, [running, selectedId, loadDetail]);

  useEffect(() => { if (composing) composeHeading.current?.focus(); }, [composing]);

  function openCompose(from?: Draft) {
    const primary = active.find((path) => path.relation_kind === 'primary_route') ?? active[0];
    setDraft(from ?? { primary: primary?.id ?? '', included: primary ? [primary.id] : [], scenario: '', outcomes: defaultOutcomes(primary) });
    setDraftErrors({});
    setError('');
    setMessage('');
    setComposing(true);
  }

  function requestFromDraft(): ComparisonRequest | null {
    const errors: typeof draftErrors = {};
    const included = [...new Set([draft.primary, ...draft.included])].filter((id) => byId.get(id)?.status === 'active');
    if (!draft.primary || !byId.get(draft.primary)) errors.primary = 'Choose the primary route to compare against.';
    if (included.length < 2) errors.included = 'Include the primary route and at least one other declared path.';
    if (included.length > MAX_PATHS) errors.included = `A comparison covers at most ${MAX_PATHS} paths.`;
    if (!SCENARIO_PATTERN.test(draft.scenario.trim())) errors.scenario = 'Use a catalog scenario id, for example the marker scenario of an approved check.';
    setDraftErrors(errors);
    if (Object.keys(errors).length) return null;
    return {
      anchor_target_id: targetId,
      primary_entry_path_id: draft.primary,
      entry_path_ids: included.sort(),
      expectation: { scenario: draft.scenario.trim(), layer_outcomes: { ...draft.outcomes } },
    };
  }

  async function reviewPlan(request: ComparisonRequest | null) {
    if (!request) return;
    setPlanning(true);
    setError('');
    try {
      const plan = await planEntryPathComparison(config, session, request);
      setReview({ request, plan });
    } catch (err) {
      setError(writeErrorCopy(pvErrorCode(err), apiErrorMessage(err, 'The plan could not be prepared. Nothing was started.')));
    } finally {
      setPlanning(false);
    }
  }

  async function confirmStart() {
    if (!review) return;
    setBusy(true);
    setError('');
    try {
      const started = await startEntryPathComparison(config, session, review.request, review.plan.plan_digest);
      setReview(null);
      setComposing(false);
      if (started.id) setSelectedId(started.id);
      setReload((value) => value + 1);
      onStarted('Reviewed comparison started. Each path runs as its own bounded check; results appear here once finalized.');
    } catch (err) {
      const code = pvErrorCode(err);
      setError(writeErrorCopy(code, apiErrorMessage(err, 'The comparison could not start. Nothing was started.')));
      if (code === 'reviewed_plan_mismatch') {
        setReview(null);
        void reviewPlan(review.request);
      }
    } finally {
      setBusy(false);
    }
  }

  const progress = detail.state === 'ready' ? comparisonProgress(detail.value) : null;

  async function confirmStop() {
    if (!progress || !selectedId) return;
    setBusy(true);
    setError('');
    try {
      await cancelEntryPathComparison(config, session, selectedId, 'Stopped from entry-path comparison');
      setBusy(false);
      setStopOpen(false);
      setMessage('Stop requested. Completed results are kept; stopped and pending paths stay not tested.');
      void loadDetail(selectedId, undefined, true);
      return;
    } catch (err) {
      const failure = pvFailureOf(err);
      if (failure.state !== 'unsupported' && pvErrorCode(err) !== 'not_cancellable') {
        setBusy(false);
        setError(apiErrorMessage(err, 'The comparison could not stop. Refresh to see the current state.'));
        return;
      }
    }
    const results = await Promise.allSettled(progress.activeRunIds.map((runId) => cancelRun(config, session, runId, 'Stopped from entry-path comparison')));
    const failed = results.filter((result) => result.status === 'rejected' && pvErrorCode(result.reason) !== 'not_cancellable');
    setBusy(false);
    setStopOpen(false);
    if (failed.length) setError(`${failed.length} check${failed.length === 1 ? '' : 's'} could not stop. Refresh to see the current state.`);
    else setMessage('Stop requested. Completed results are kept; stopped paths stay not tested.');
    if (selectedId) void loadDetail(selectedId, undefined, true);
  }

  const startBlocker = !canStart ? 'Your role cannot start checks.'
    : !ownershipDone ? 'This target’s ownership is not verified, so checks cannot start from it.'
      : active.length < 2 ? 'Declare at least two active entry paths to compare them.' : '';

  return (
    <section className="pv-section" aria-labelledby="pv-compare-title">
      <header className="td-section-head">
        <div>
          <h3 id="pv-compare-title">Entry-path comparisons</h3>
          <p>Compare the primary route with other declared paths under one scenario. A primary-route result never counts for a path that was not tested.</p>
        </div>
        {!composing ? (
          <Button size="sm" variant="secondary" disabled={Boolean(startBlocker)} title={startBlocker || undefined} onClick={() => openCompose()}>Plan a comparison</Button>
        ) : null}
      </header>
      {startBlocker && !composing ? <p className="td-muted small">{startBlocker}</p> : null}
      {message ? <p className="form-banner" role="status">{message}</p> : null}
      {error && !review && !stopOpen ? <p className="td-form-error" role="alert">{error}</p> : null}

      {composing ? (
        <form className="pv-form" noValidate onSubmit={(event) => { event.preventDefault(); void reviewPlan(requestFromDraft()); }} aria-labelledby="pv-compose-title">
          <h3 id="pv-compose-title" ref={composeHeading} tabIndex={-1}>Plan a comparison</h3>
          <p className="pv-copy">Planning is passive. You review the exact checks, targets and upper bounds before anything starts.</p>
          <label className="td-field">
            <span>Primary route</span>
            <select value={draft.primary} aria-invalid={draftErrors.primary ? true : undefined} aria-describedby="pv-primary-help" onChange={(event) => setDraft((current) => ({ ...current, primary: event.target.value, included: [...new Set([event.target.value, ...current.included])] }))}>
              <option value="">Choose the primary route</option>
              {active.map((path) => <option key={path.id} value={path.id}>{pathLabel(path, path.id)}</option>)}
            </select>
            <span id="pv-primary-help" className={draftErrors.primary ? 'td-form-error' : 'td-muted small'}>{draftErrors.primary ?? 'Its healthy, enforcing result is the reference for every other path.'}</span>
          </label>
          <fieldset aria-describedby="pv-included-help" aria-invalid={draftErrors.included ? true : undefined}>
            <legend>Paths to compare</legend>
            {active.map((path) => (
              <label key={path.id} className="pv-check">
                <input
                  type="checkbox"
                  checked={draft.included.includes(path.id) || path.id === draft.primary}
                  disabled={path.id === draft.primary}
                  onChange={(event) => setDraft((current) => ({ ...current, included: event.target.checked ? [...current.included, path.id] : current.included.filter((id) => id !== path.id) }))}
                />
                <span className="pv-break">{pathLabel(path, path.id)}{path.currently_authorized === false ? ' — ownership not current, will be skipped' : ''}</span>
              </label>
            ))}
            <span id="pv-included-help" className={draftErrors.included ? 'td-form-error' : 'td-muted small'}>{draftErrors.included ?? 'Paths left out stay not tested.'}</span>
          </fieldset>
          <label className="td-field">
            <span>Scenario</span>
            <input value={draft.scenario} autoComplete="off" spellCheck={false} aria-invalid={draftErrors.scenario ? true : undefined} aria-describedby="pv-scenario-help" onChange={(event) => setDraft((current) => ({ ...current, scenario: event.target.value }))} />
            <span id="pv-scenario-help" className={draftErrors.scenario ? 'td-form-error' : 'td-muted small'}>{draftErrors.scenario ?? 'The catalog scenario id every path is checked with. A marker result covers that marker only.'}</span>
          </label>
          <fieldset>
            <legend>Expected outcome per layer</legend>
            <div className="pv-grid-2">
              {PROTECTION_LAYERS.map((layer) => (
                <label key={layer} className="td-field">
                  <span>{LAYER_LABELS[layer]}</span>
                  <select value={draft.outcomes[layer] ?? 'no_expectation'} onChange={(event) => setDraft((current) => ({ ...current, outcomes: { ...current.outcomes, [layer]: event.target.value as LayerExpectedOutcome } }))}>
                    {Object.entries(LAYER_OUTCOME_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                  </select>
                </label>
              ))}
            </div>
          </fieldset>
          <div className="row-actions">
            <Button type="submit" size="sm" loading={planning} loadingText="Preparing plan">Review plan</Button>
            <Button type="button" size="sm" variant="ghost" onClick={() => setComposing(false)}>Cancel</Button>
          </div>
        </form>
      ) : null}

      {list.state === 'loading' ? <div className="skeleton skeleton-row" aria-label="Loading comparisons" /> : null}
      {list.state === 'failed' ? <FailureNotice failure={list.failure} subject="entry-path comparisons" onRetry={() => setReload((value) => value + 1)} /> : null}
      {list.state === 'ready' && !list.items.length ? <p className="td-muted">No comparison has been recorded for this application yet.</p> : null}
      {list.state === 'ready' && list.items.length ? (
        <ul className="pv-list" aria-label="Recorded comparisons">
          {list.items.map((item) => (
            <li key={item.id} className="pv-card" aria-current={item.id === selectedId ? 'true' : undefined}>
              <div className="pv-card-head">
                <div className="pv-card-title">
                  <strong>{str(item.expectation, 'scenario') || 'Scenario not recorded'}</strong>
                  <span className="td-muted small mono pv-break">{item.id}{item.evaluated_at ? ` · ${formatDate(item.evaluated_at)}` : item.created_at ? ` · ${formatDate(item.created_at)}` : ''}</span>
                </div>
                <div className="pv-actions">
                  <Badge tone={item.status === 'running' ? 'info' : item.status === 'cancelled' ? 'warn' : 'muted'}>{item.status === 'running' ? 'Running' : item.status === 'cancelled' ? 'Stopped' : item.status === 'completed' ? 'Completed' : 'Status not recorded'}</Badge>
                  <Button size="sm" variant={item.id === selectedId ? 'secondary' : 'ghost'} aria-pressed={item.id === selectedId} onClick={() => setSelectedId(item.id === selectedId ? '' : item.id)}>
                    {item.id === selectedId ? 'Hide results' : 'View results'}
                  </Button>
                </div>
              </div>
            </li>
          ))}
        </ul>
      ) : null}

      {detail.state === 'loading' ? <div className="skeleton skeleton-row" aria-label="Loading comparison results" /> : null}
      {detail.state === 'failed' ? <FailureNotice failure={detail.failure} subject="this comparison" onRetry={() => selectedId && void loadDetail(selectedId)} /> : null}
      {detail.state === 'ready' ? (
        <ComparisonResult
          comparison={detail.value}
          pathsById={byId}
          progress={progress}
          canStop={canStart}
          canRetest={!startBlocker}
          onStop={() => { setError(''); setStopOpen(true); }}
          onRetest={() => openCompose(draftFromComparison(detail.value))}
        />
      ) : null}

      <ConfirmModal
        open={review !== null}
        title="Start these reviewed checks?"
        confirmTone="default"
        confirmLabel="Start reviewed checks"
        busy={busy}
        onCancel={() => { setReview(null); setError(''); }}
        onConfirm={() => void confirmStart()}
        description={review ? (
          <div className="stack-tight scan-review">
            <dl className="td-review-list">
              <div><dt>Application</dt><dd><span className="mono pv-break">{str(target, 'value') || targetId}</span></dd></div>
              <div><dt>Scenario</dt><dd className="mono pv-break">{review.request.expectation.scenario}</dd></div>
              <div><dt>Plan digest</dt><dd className="mono pv-break">{review.plan.plan_digest || 'Not returned'}</dd></div>
            </dl>
            <ul className="pv-refs" aria-label="Planned paths">
              {review.plan.items.map((item) => (
                <li key={item.entry_path_id} className="pv-ref">
                  <span className="pv-break">{pathLabel(byId.get(item.entry_path_id), item.entry_path_id)}</span>
                  <code>check {item.check_id || 'none'}{item.check_version ? ` v${item.check_version}` : ''} · target {item.target_id}{item.origin_binding_id ? ` · origin relation ${item.origin_binding_id}` : ''}</code>
                  {item.eligible ? <Badge tone="default">Will run</Badge> : <Badge tone="muted">Skipped: {(item.ineligible_reason ?? 'not eligible').replace(/_/g, ' ')}</Badge>}
                </li>
              ))}
            </ul>
            {review.plan.expectation_conflicts.length ? (
              <div className="td-form-error small" role="alert" data-state="expectation-conflicts">
                <p>Expectation conflicts with the declarations. Review before starting:</p>
                <ul aria-label="Expectation conflicts">
                  {review.plan.expectation_conflicts.map((entry) => (
                    <li key={entry.entry_path_id}>
                      <span className="pv-break">{pathLabel(byId.get(entry.entry_path_id), entry.entry_path_id)}</span>: {entry.conflicts.map(expectationConflictLabel).join('; ')}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
            {review.plan.items.some((item) => item.eligible) ? null : <p className="td-form-error small">No path in this plan is eligible, so starting it would run nothing.</p>}
            <LimitationList values={review.plan.limitations} />
            <p>Only eligible paths run, each as one bounded check through the existing signed workers, safe windows, rate limits and kill switches. If declarations or ownership changed since this review, the server starts nothing.</p>
            {error && review ? <p className="td-form-error" role="alert">{error}</p> : null}
          </div>
        ) : null}
      />

      <ConfirmModal
        open={stopOpen}
        title="Stop the running checks in this comparison?"
        confirmLabel="Stop checks"
        busy={busy}
        onCancel={() => setStopOpen(false)}
        onConfirm={() => void confirmStop()}
        description={(
          <div className="stack-tight">
            <p>{progress?.activeRunIds.length ?? 0} running check{progress?.activeRunIds.length === 1 ? '' : 's'} will be cancelled and no further paths will start. Finished results stay; stopped paths remain not tested.</p>
            {error && stopOpen ? <p className="td-form-error" role="alert">{error}</p> : null}
          </div>
        )}
      />
    </section>
  );
}

function ComparisonResult({
  comparison,
  pathsById,
  progress,
  canStop,
  canRetest,
  onStop,
  onRetest,
}: {
  comparison: PathComparison;
  pathsById: Map<string, EntryPath>;
  progress: ReturnType<typeof comparisonProgress> | null;
  canStop: boolean;
  canRetest: boolean;
  onStop: () => void;
  onRetest: () => void;
}) {
  const [openItem, setOpenItem] = useState('');
  const compat = compatibilityView(comparison.compatibility);
  const summary = summaryView(comparison.summary, 'path_validation');
  const running = comparison.status === 'running';
  return (
    <section className="pv-detail" aria-labelledby="pv-comparison-result-title" aria-busy={running || undefined}>
      <h4 id="pv-comparison-result-title">Results for <span className="mono pv-break">{str(comparison.expectation, 'scenario') || comparison.id}</span></h4>
      {running && progress ? (
        <div className="pv-progress" role="status">
          <progress max={Math.max(progress.started, 1)} value={progress.finished} aria-label="Finished checks" />
          <span className="small">{progress.finished} of {progress.started} started checks finished{progress.skipped ? `; ${progress.skipped} skipped` : ''}. Results update automatically.</span>
          {canStop ? <div><Button size="sm" variant="danger" onClick={onStop}>Stop</Button></div> : null}
        </div>
      ) : null}
      <div className="pv-badges">
        <Badge tone={summary.accepted ? 'success' : summary.partial ? 'warn' : 'muted'}>{summary.label}</Badge>
        {compat.state !== 'comparable' && compat.state !== 'unknown' ? <Badge tone="warn">{compat.label}</Badge> : null}
        {comparison.status === 'cancelled' ? <Badge tone="warn">Stopped before every path finished</Badge> : null}
      </div>
      {compat.reasons.length ? <ul className="pv-limits" aria-label="Why evidence is not comparable">{compat.reasons.map((reason) => <li key={reason.id}>{reason.label}</li>)}</ul> : null}
      <ul className="pv-list" aria-label="Per-path results">
        {comparison.items.map((item) => {
          const key = item.entry_path_id;
          const expanded = openItem === key;
          return (
            <li key={key} className="pv-card">
              <div className="pv-card-head">
                <div className="pv-card-title">
                  <strong>{pathLabel(pathsById.get(item.entry_path_id), item.entry_path_id)}</strong>
                  <span className="td-muted small">{item.attribution === 'attributed' ? 'Attributed by evidence' : 'Not attributed to a specific layer'}</span>
                </div>
                <div className="pv-actions">
                  <Badge tone={toneFrom(PATH_OUTCOME_TONES, item.outcome)}>{labelFrom(PATH_OUTCOME_LABELS, item.outcome)}</Badge>
                  <Button size="sm" variant="ghost" aria-expanded={expanded} aria-controls={`pv-item-${key}`} onClick={() => setOpenItem(expanded ? '' : key)}>{expanded ? 'Hide evidence' : 'Inspect evidence'}</Button>
                </div>
              </div>
              {expanded ? (
                <div id={`pv-item-${key}`} className="pv-section">
                  {item.reasons.length ? <p className="small">Reasons: {item.reasons.map((reason) => reason.replace(/_/g, ' ')).join('; ')}.</p> : null}
                  {item.compatibility_reasons.length ? <p className="small">{compatibilityView({ comparable: false, stale: false, reasons: item.compatibility_reasons }).reasons.map((reason) => reason.label).join('; ')}.</p> : null}
                  <LimitationList values={item.limitations} />
                  <EvidenceRefList refs={item.evidence_refs} focusPrefix={`pv-cmp-${comparison.id}-${key}`} />
                </div>
              ) : null}
            </li>
          );
        })}
      </ul>
      {!running ? (
        <div className="pv-actions">
          <Button size="sm" variant="secondary" disabled={!canRetest} onClick={onRetest}>Review retest of this comparison</Button>
          <span className="td-muted small">A retest re-plans the same paths and scenario; you review it before anything starts.</span>
        </div>
      ) : null}
    </section>
  );
}
