import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Plus } from 'lucide-react';
import {
  archiveFirewallExpectation,
  captureFirewallBaseline,
  createFirewallExpectation,
  evaluateFirewallComparison,
  getFirewallComparison,
  listFirewallBaselines,
  listFirewallComparisons,
  listFirewallExpectations,
  pvErrorCode,
  startReviewedRetest,
  type EvidenceRef,
  type FirewallBaseline,
  type FirewallComparison,
  type FirewallExpectation,
  type PvFailure,
  type TargetCandidate,
} from '../../../lib/protection-validation-api';
import { ConfirmModal } from '../../../lib/crud-ui';
import { apiErrorMessage } from '../../../lib/error-messages';
import type { DataItem, PortalConfig, Session } from '../../../lib/types';
import { formatDate } from '../../../lib/utils';
import { Badge } from '../../ui/badge';
import { Button } from '../../ui/button';
import {
  compatibilityView,
  FIREWALL_GAP_LABELS,
  FIREWALL_SIDE_STATE_LABELS,
  FIREWALL_STATUS_LABELS,
  FIREWALL_STATUS_TONES,
  firewallDraftErrors,
  firewallExpectationBody,
  firewallScopeText,
  freshnessView,
  labelFrom,
  summaryView,
  toneFrom,
  writeErrorCopy,
  type FirewallDraft,
} from './presenter.mjs';
import { RunPicker } from './run-picker';
import { EvidenceRefList, FailureNotice, LimitationList, useStickySelection } from './shared';
import { TargetCandidatePicker } from './target-candidate-picker';
import './entry-paths.css';

type Loaded<T> = { state: 'loading' } | { state: 'ready'; items: T[]; nextCursor: string } | { state: 'failed'; failure: PvFailure };
type Review =
  | { kind: 'expectation'; body: ReturnType<typeof firewallExpectationBody> }
  | { kind: 'archive'; expectation: FirewallExpectation }
  | { kind: 'baseline'; changeId: string; expectationIds: string[]; runIds: string[]; windowSeconds: number }
  | { kind: 'compare'; baseline: FirewallBaseline; runIds: string[] }
  | { kind: 'retest'; ref: EvidenceRef };

const DAY = 86400;
const WINDOW_CHOICES = [1, 7, 30, 90, 180];
const EMPTY_DRAFT: FirewallDraft = {
  destination_target_id: '',
  protocol: 'tcp',
  port: '',
  service: '',
  service_port: '',
  service_path: '',
  expected: '',
  source_perspective: 'astranull-signed-public-worker',
  change_id: '',
  owner: '',
  pre_destination_target_id: '',
};

function str(item: DataItem | null | undefined, key: string) {
  const value = item?.[key];
  return typeof value === 'string' ? value : '';
}

function baselineFreshness(baseline: FirewallBaseline) {
  const captured = Date.parse(baseline.captured_at);
  const windowSeconds = baseline.freshness_window_seconds ?? 0;
  if (!Number.isFinite(captured) || !windowSeconds) return freshnessView(null);
  return freshnessView({ expires_at: new Date(captured + windowSeconds * 1000).toISOString() });
}

/** Firewall change acceptance for this destination: declare expectations, capture an immutable pre-change baseline, compare explicitly chosen post-change runs. Nothing here sends traffic except a reviewed retest. */
export function FirewallChangeComparison({
  config,
  session,
  target,
  canWrite,
  canStart,
  ownershipDone,
  onStarted,
}: {
  config: PortalConfig;
  session: Session;
  target: DataItem;
  canWrite: boolean;
  canStart: boolean;
  ownershipDone: boolean;
  onStarted: (message: string) => void;
}) {
  const targetId = str(target, 'id');
  const [expectations, setExpectations] = useState<Loaded<FirewallExpectation>>({ state: 'loading' });
  const [reload, setReload] = useState(0);
  const [changeId, setChangeId] = useStickySelection(session, targetId, 'fw-change');
  const [baselineId, setBaselineId] = useStickySelection(session, targetId, 'fw-baseline');
  const [comparisonId, setComparisonId] = useStickySelection(session, targetId, 'fw-comparison');
  const [baselines, setBaselines] = useState<Loaded<FirewallBaseline> | null>(null);
  const [comparisons, setComparisons] = useState<Loaded<FirewallComparison> | null>(null);
  const [comparison, setComparison] = useState<{ state: 'loading' } | { state: 'ready'; value: FirewallComparison } | { state: 'failed'; failure: PvFailure } | null>(null);
  const [form, setForm] = useState<'' | 'expectation' | 'baseline' | 'compare'>('');
  const [draft, setDraft] = useState<FirewallDraft>({ ...EMPTY_DRAFT, destination_target_id: targetId });
  const [draftErrors, setDraftErrors] = useState<Partial<Record<keyof FirewallDraft, string>>>({});
  const [migrating, setMigrating] = useState(false);
  const [baselineDraft, setBaselineDraft] = useState<{ expectationIds: string[]; runIds: string[]; windowDays: number; error: string }>({ expectationIds: [], runIds: [], windowDays: 30, error: '' });
  const [compareRuns, setCompareRuns] = useState<{ runIds: string[]; error: string }>({ runIds: [], error: '' });
  const [review, setReview] = useState<Review | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [incompatible, setIncompatible] = useState('');
  const [message, setMessage] = useState('');
  const formHeading = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    const controller = new AbortController();
    listFirewallExpectations(config, session, { destination_target_id: targetId, limit: 100 }, controller.signal)
      .then((result) => {
        if (controller.signal.aborted) return;
        setExpectations(result.state === 'ready' ? { state: 'ready', items: result.value.items, nextCursor: result.value.nextCursor } : { state: 'failed', failure: result });
      })
      .catch(() => undefined);
    return () => controller.abort();
  }, [config, session, targetId, reload]);

  const changeIds = useMemo(() => (expectations.state === 'ready' ? [...new Set(expectations.items.map((item) => item.change_id).filter(Boolean))].sort() : []), [expectations]);
  const effectiveChange = changeIds.includes(changeId) ? changeId : changeIds[0] ?? '';
  const changeExpectations = useMemo(() => (expectations.state === 'ready' ? expectations.items.filter((item) => item.change_id === effectiveChange) : []), [expectations, effectiveChange]);
  const activeExpectations = changeExpectations.filter((item) => item.status === 'active');
  const expectationById = useMemo(() => new Map((expectations.state === 'ready' ? expectations.items : []).map((item) => [item.id, item])), [expectations]);

  useEffect(() => {
    if (!effectiveChange) { setBaselines(null); return undefined; }
    const controller = new AbortController();
    setBaselines({ state: 'loading' });
    listFirewallBaselines(config, session, { change_id: effectiveChange }, controller.signal)
      .then((result) => {
        if (controller.signal.aborted) return;
        setBaselines(result.state === 'ready' ? { state: 'ready', items: result.value.items, nextCursor: result.value.nextCursor } : { state: 'failed', failure: result });
      })
      .catch(() => undefined);
    return () => controller.abort();
  }, [config, session, effectiveChange, reload]);

  const baselineItems = baselines?.state === 'ready' ? baselines.items : [];
  const selectedBaseline = baselineItems.find((item) => item.id === baselineId) ?? null;

  useEffect(() => {
    if (!selectedBaseline) { setComparisons(null); return undefined; }
    const controller = new AbortController();
    setComparisons({ state: 'loading' });
    listFirewallComparisons(config, session, { baseline_id: selectedBaseline.id }, controller.signal)
      .then((result) => {
        if (controller.signal.aborted) return;
        setComparisons(result.state === 'ready' ? { state: 'ready', items: result.value.items, nextCursor: result.value.nextCursor } : { state: 'failed', failure: result });
      })
      .catch(() => undefined);
    return () => controller.abort();
  }, [config, session, selectedBaseline, reload]);

  const loadComparison = useCallback((id: string, signal?: AbortSignal) => {
    setComparison({ state: 'loading' });
    getFirewallComparison(config, session, id, signal)
      .then((result) => {
        if (signal?.aborted) return;
        setComparison(result.state === 'ready' ? { state: 'ready', value: result.value } : { state: 'failed', failure: result });
      })
      .catch(() => undefined);
  }, [config, session]);

  useEffect(() => {
    if (!comparisonId || !selectedBaseline) { setComparison(null); return undefined; }
    const controller = new AbortController();
    loadComparison(comparisonId, controller.signal);
    return () => controller.abort();
  }, [comparisonId, selectedBaseline, loadComparison]);

  useEffect(() => { if (form) formHeading.current?.focus(); }, [form]);

  const destinationTargets = useMemo(() => {
    const ids = new Set([targetId]);
    for (const item of activeExpectations) if (item.pre_post_mapping?.pre_destination_target_id) ids.add(item.pre_post_mapping.pre_destination_target_id);
    return [...ids].sort();
  }, [targetId, activeExpectations]);

  function openForm(kind: 'expectation' | 'baseline' | 'compare') {
    setForm(kind);
    setError('');
    setIncompatible('');
    setMessage('');
    if (kind === 'expectation') {
      setDraft({ ...EMPTY_DRAFT, destination_target_id: targetId, change_id: effectiveChange });
      setDraftErrors({});
      setMigrating(false);
    }
    if (kind === 'baseline') setBaselineDraft({ expectationIds: activeExpectations.map((item) => item.id), runIds: [], windowDays: 30, error: '' });
    if (kind === 'compare') setCompareRuns({ runIds: [], error: '' });
  }

  function reviewExpectation() {
    const next = { ...draft, pre_destination_target_id: migrating ? draft.pre_destination_target_id : '' };
    const errors = firewallDraftErrors(next);
    if (migrating && !next.pre_destination_target_id) errors.pre_destination_target_id = 'Choose the declared pre-change destination, or untick the migration option.';
    setDraftErrors(errors);
    if (Object.keys(errors).length) return;
    setReview({ kind: 'expectation', body: firewallExpectationBody(next) });
  }

  function reviewBaseline() {
    if (!baselineDraft.expectationIds.length) { setBaselineDraft((current) => ({ ...current, error: 'Choose at least one expectation.' })); return; }
    if (!baselineDraft.runIds.length) { setBaselineDraft((current) => ({ ...current, error: 'Choose at least one finalized pre-change run.' })); return; }
    setReview({ kind: 'baseline', changeId: effectiveChange, expectationIds: baselineDraft.expectationIds, runIds: baselineDraft.runIds, windowSeconds: baselineDraft.windowDays * DAY });
  }

  function reviewCompare() {
    if (!selectedBaseline) return;
    if (!compareRuns.runIds.length) { setCompareRuns((current) => ({ ...current, error: 'Choose at least one finalized post-change run.' })); return; }
    setReview({ kind: 'compare', baseline: selectedBaseline, runIds: compareRuns.runIds });
  }

  async function confirm() {
    if (!review) return;
    setBusy(true);
    setError('');
    setIncompatible('');
    try {
      if (review.kind === 'expectation') {
        const written = await createFirewallExpectation(config, session, review.body as unknown as DataItem);
        setMessage(written.replayed ? 'This expectation was already recorded; nothing changed.' : 'Expectation recorded and audited. No traffic was sent.');
        setChangeId(review.body.change_id);
        setForm('');
      } else if (review.kind === 'archive') {
        await archiveFirewallExpectation(config, session, review.expectation.id);
        setMessage('Expectation archived. Baselines and comparisons that used it stay unchanged.');
      } else if (review.kind === 'baseline') {
        const written = await captureFirewallBaseline(config, session, { change_id: review.changeId, expectation_ids: review.expectationIds, test_run_ids: review.runIds, freshness_window_seconds: review.windowSeconds });
        setMessage(written.replayed ? 'This baseline was already captured; nothing changed.' : 'Pre-change baseline captured. It is immutable and sent no traffic.');
        if (written.record.id) setBaselineId(written.record.id);
        setComparisonId('');
        setForm('');
      } else if (review.kind === 'compare') {
        const written = await evaluateFirewallComparison(config, session, { baseline_id: review.baseline.id, post_test_run_ids: review.runIds });
        setMessage('Comparison recorded. No traffic was sent.');
        if (written.record.id) setComparisonId(written.record.id);
        setForm('');
      } else {
        await startReviewedRetest(config, session, { check_id: review.ref.check_id, target_group_id: str(target, 'target_group_id'), target_id: review.ref.target_id });
        onStarted('Retest started for the exact check and target. Select its finalized run as post-change evidence when it finishes.');
      }
      setReview(null);
      setReload((value) => value + 1);
    } catch (err) {
      const code = pvErrorCode(err);
      const text = writeErrorCopy(code, apiErrorMessage(err, 'The request could not be completed. Nothing was changed.'));
      if (code === 'baseline_not_comparable' && review.kind === 'compare') {
        setIncompatible(text);
        setReview(null);
      } else setError(text);
    } finally {
      setBusy(false);
    }
  }

  const retestBlocker = !canStart ? 'Your role cannot start checks.' : !ownershipDone ? 'This target’s ownership is not verified, so a retest cannot start.' : '';

  return (
    <section className="pv-section td-firewall-change" aria-labelledby="pv-firewall-title">
      <header className="td-section-head">
        <div>
          <h2 id="pv-firewall-title">Firewall change comparison</h2>
          <p>Declare what should be allowed or denied at this destination, capture a pre-change baseline from finished runs, then compare runs you choose from after the change. It covers sampled public ingress only, not full rule-table, routing, NAT, egress or east-west equivalence.</p>
        </div>
        {canWrite && expectations.state === 'ready' && form !== 'expectation' ? (
          <Button size="sm" variant="secondary" onClick={() => openForm('expectation')}><Plus size={14} aria-hidden="true" />Declare expectation</Button>
        ) : null}
      </header>
      {message ? <p className="form-banner" role="status">{message}</p> : null}
      {error && !review ? <p className="td-form-error" role="alert">{error}</p> : null}

      {expectations.state === 'loading' ? <div className="skeleton skeleton-row" aria-label="Loading firewall expectations" /> : null}
      {expectations.state === 'failed' ? <FailureNotice failure={expectations.failure} subject="firewall change expectations" onRetry={() => setReload((value) => value + 1)} /> : null}

      {form === 'expectation' ? (
        <form className="pv-form" noValidate onSubmit={(event) => { event.preventDefault(); reviewExpectation(); }} aria-labelledby="pv-fw-form-title">
          <h3 id="pv-fw-form-title" ref={formHeading} tabIndex={-1}>Declare a firewall expectation</h3>
          <p className="pv-copy">Destination: <span className="mono pv-break">{str(target, 'value') || targetId}</span>. Recording it sends no traffic.</p>
          <div className="pv-grid-2">
            <label className="td-field">
              <span>Change identifier</span>
              <input value={draft.change_id} autoComplete="off" aria-invalid={draftErrors.change_id ? true : undefined} aria-describedby="pv-fw-change-help" onChange={(event) => setDraft({ ...draft, change_id: event.target.value })} />
              <span id="pv-fw-change-help" className={draftErrors.change_id ? 'td-form-error' : 'td-muted small'}>{draftErrors.change_id ?? 'Your change or ticket reference.'}</span>
            </label>
            <label className="td-field">
              <span>Protocol</span>
              <select value={draft.protocol} aria-invalid={draftErrors.protocol ? true : undefined} onChange={(event) => setDraft({ ...draft, protocol: event.target.value })}>
                <option value="tcp">TCP port</option>
                <option value="udp">UDP port</option>
                <option value="service">Service endpoint</option>
              </select>
            </label>
          </div>
          {draft.protocol === 'service' ? (
            <div className="pv-grid-2">
              <label className="td-field">
                <span>Service</span>
                <input value={draft.service} autoComplete="off" aria-invalid={draftErrors.service ? true : undefined} aria-describedby="pv-fw-service-help" onChange={(event) => setDraft({ ...draft, service: event.target.value })} />
                <span id="pv-fw-service-help" className={draftErrors.service ? 'td-form-error' : 'td-muted small'}>{draftErrors.service ?? 'For example https.'}</span>
              </label>
              <label className="td-field">
                <span>Service port</span>
                <input inputMode="numeric" value={draft.service_port} aria-invalid={draftErrors.service_port ? true : undefined} aria-describedby="pv-fw-sport-help" onChange={(event) => setDraft({ ...draft, service_port: event.target.value })} />
                <span id="pv-fw-sport-help" className={draftErrors.service_port ? 'td-form-error' : 'td-muted small'}>{draftErrors.service_port ?? 'One port on this declared target.'}</span>
              </label>
              <label className="td-field">
                <span>Path (optional)</span>
                <input value={draft.service_path} autoComplete="off" aria-invalid={draftErrors.service_path ? true : undefined} aria-describedby="pv-fw-path-help" onChange={(event) => setDraft({ ...draft, service_path: event.target.value })} />
                <span id="pv-fw-path-help" className={draftErrors.service_path ? 'td-form-error' : 'td-muted small'}>{draftErrors.service_path ?? 'Starts with /, no query.'}</span>
              </label>
            </div>
          ) : (
            <label className="td-field">
              <span>Port</span>
              <input inputMode="numeric" value={draft.port} aria-invalid={draftErrors.port ? true : undefined} aria-describedby="pv-fw-port-help" onChange={(event) => setDraft({ ...draft, port: event.target.value })} />
              <span id="pv-fw-port-help" className={draftErrors.port ? 'td-form-error' : 'td-muted small'}>{draftErrors.port ?? (draft.protocol === 'udp' ? 'UDP silence stays ambiguous; it never proves a deny.' : 'A TCP connection shows reachability, not enforcement.')}</span>
            </label>
          )}
          <div className="pv-grid-2">
            <label className="td-field">
              <span>Expected behavior</span>
              <select value={draft.expected} aria-invalid={draftErrors.expected ? true : undefined} aria-describedby="pv-fw-expected-help" onChange={(event) => setDraft({ ...draft, expected: event.target.value })}>
                <option value="">Choose allow or deny</option>
                <option value="allow">Allow (service must respond)</option>
                <option value="deny">Deny (explicit denial expected)</option>
              </select>
              <span id="pv-fw-expected-help" className={draftErrors.expected ? 'td-form-error' : 'td-muted small'}>{draftErrors.expected ?? 'Allow needs a valid service response; deny needs explicit denial evidence.'}</span>
            </label>
            <label className="td-field">
              <span>Source perspective</span>
              <input value={draft.source_perspective} autoComplete="off" spellCheck={false} aria-invalid={draftErrors.source_perspective ? true : undefined} aria-describedby="pv-fw-source-help" onChange={(event) => setDraft({ ...draft, source_perspective: event.target.value })} />
              <span id="pv-fw-source-help" className={draftErrors.source_perspective ? 'td-form-error' : 'td-muted small'}>{draftErrors.source_perspective ?? 'The approved external source identifier shown on your runs. The shared signed worker pool is astranull-signed-public-worker unless your workspace has named sources. Source addresses are never spoofed.'}</span>
            </label>
            <label className="td-field">
              <span>Owner (optional)</span>
              <input value={draft.owner} maxLength={120} aria-invalid={draftErrors.owner ? true : undefined} onChange={(event) => setDraft({ ...draft, owner: event.target.value })} />
            </label>
          </div>
          <label className="pv-check">
            <input type="checkbox" checked={migrating} onChange={(event) => setMigrating(event.target.checked)} />
            This change moves the service from another declared target
          </label>
          {migrating ? (
            <div>
              <TargetCandidatePicker
                config={config}
                session={session}
                legend="Pre-change destination"
                value={draft.pre_destination_target_id}
                excludeIds={[targetId]}
                error={draftErrors.pre_destination_target_id}
                help="An explicit pre/post mapping you declare. An inferred IP change is never comparable."
                onChange={(id: string, _candidate: TargetCandidate | null) => setDraft({ ...draft, pre_destination_target_id: id })}
              />
            </div>
          ) : null}
          <div className="row-actions">
            <Button type="submit" size="sm">Review expectation</Button>
            <Button type="button" size="sm" variant="ghost" onClick={() => setForm('')}>Cancel</Button>
          </div>
        </form>
      ) : null}

      {expectations.state === 'ready' && !changeIds.length && form !== 'expectation' ? (
        <p className="pv-notice" data-state="empty">No firewall change expectation is declared for this destination yet.{canWrite ? ' Declare one to capture a baseline before your change.' : ''}</p>
      ) : null}

      {changeIds.length ? (
        <div className="pv-section">
          <label className="td-field pv-field-narrow">
            <span>Change</span>
            <select value={effectiveChange} onChange={(event) => { setChangeId(event.target.value); setBaselineId(''); setComparisonId(''); }}>
              {changeIds.map((id) => <option key={id} value={id}>{id}</option>)}
            </select>
          </label>
          <ul className="pv-list" aria-label="Expectations for this change">
            {changeExpectations.map((item) => (
              <li key={item.id} className="pv-card">
                <div className="pv-card-head">
                  <div className="pv-card-title">
                    <strong>{firewallScopeText(item)}</strong>
                    <span className="td-muted small mono pv-break">{item.id}{item.expectation_version ? ` · version ${item.expectation_version}` : ''}{item.owner ? ` · ${item.owner}` : ''}</span>
                  </div>
                  <div className="pv-actions">
                    {item.status === 'active' ? <Badge tone="muted">Declared expectation</Badge> : <Badge tone="muted">Archived</Badge>}
                    {canWrite && item.status === 'active' ? <Button size="sm" variant="ghost" onClick={() => setReview({ kind: 'archive', expectation: item })}>Archive</Button> : null}
                  </div>
                </div>
                {item.pre_post_mapping ? <p className="td-muted small">Declared migration from <span className="mono pv-break">{item.pre_post_mapping.pre_destination_target_id}</span> to <span className="mono pv-break">{item.pre_post_mapping.post_destination_target_id}</span>.</p> : null}
              </li>
            ))}
          </ul>

          <section className="pv-section" aria-labelledby="pv-fw-baselines-title">
            <header className="td-section-head">
              <div>
                <h3 id="pv-fw-baselines-title">Pre-change baselines</h3>
                <p>Selecting a baseline only reads it. A captured baseline never changes, even if the expectation is later edited or archived.</p>
              </div>
              {canWrite && activeExpectations.length && form !== 'baseline' ? <Button size="sm" variant="secondary" onClick={() => openForm('baseline')}>Capture baseline</Button> : null}
            </header>
            {form === 'baseline' ? (
              <form className="pv-form" noValidate onSubmit={(event) => { event.preventDefault(); reviewBaseline(); }} aria-labelledby="pv-fw-baseline-form-title">
                <h3 id="pv-fw-baseline-form-title" ref={formHeading} tabIndex={-1}>Capture a pre-change baseline</h3>
                <fieldset>
                  <legend>Expectations</legend>
                  {activeExpectations.map((item) => (
                    <label key={item.id} className="pv-check">
                      <input type="checkbox" checked={baselineDraft.expectationIds.includes(item.id)} onChange={(event) => setBaselineDraft((current) => ({ ...current, error: '', expectationIds: event.target.checked ? [...current.expectationIds, item.id] : current.expectationIds.filter((id) => id !== item.id) }))} />
                      <span className="pv-break">{firewallScopeText(item)}</span>
                    </label>
                  ))}
                </fieldset>
                <RunPicker config={config} session={session} legend="Finalized pre-change runs" targetIds={destinationTargets} selected={baselineDraft.runIds} onChange={(ids) => setBaselineDraft((current) => ({ ...current, runIds: ids, error: '' }))} />
                <label className="td-field">
                  <span>Freshness window</span>
                  <select value={baselineDraft.windowDays} onChange={(event) => setBaselineDraft((current) => ({ ...current, windowDays: Number(event.target.value) }))}>
                    {WINDOW_CHOICES.map((days) => <option key={days} value={days}>{days === 1 ? '1 day' : `${days} days`}</option>)}
                  </select>
                </label>
                {baselineDraft.error ? <p className="td-form-error" role="alert">{baselineDraft.error}</p> : null}
                <div className="row-actions">
                  <Button type="submit" size="sm">Review baseline</Button>
                  <Button type="button" size="sm" variant="ghost" onClick={() => setForm('')}>Cancel</Button>
                </div>
              </form>
            ) : null}
            {baselines?.state === 'loading' ? <div className="skeleton skeleton-row" aria-label="Loading baselines" /> : null}
            {baselines?.state === 'failed' ? <FailureNotice failure={baselines.failure} subject="baselines" onRetry={() => setReload((value) => value + 1)} /> : null}
            {baselines?.state === 'ready' && !baselineItems.length ? <p className="td-muted">No baseline captured for this change yet.</p> : null}
            {baselineItems.length ? (
              <ul className="pv-list" aria-label="Captured baselines">
                {baselineItems.map((item) => {
                  const fresh = baselineFreshness(item);
                  const selected = item.id === selectedBaseline?.id;
                  return (
                    <li key={item.id} className="pv-card" aria-current={selected ? 'true' : undefined}>
                      <div className="pv-card-head">
                        <div className="pv-card-title">
                          <strong>Captured {item.captured_at ? formatDate(item.captured_at) : 'time not recorded'}</strong>
                          <span className="td-muted small mono pv-break">{item.id} · digest {item.baseline_digest ? item.baseline_digest.slice(0, 12) : 'not recorded'}</span>
                        </div>
                        <div className="pv-actions">
                          <Badge tone={fresh.state === 'stale' ? 'warn' : 'muted'}>{fresh.state === 'stale' ? 'Stale baseline' : fresh.label}</Badge>
                          <Button size="sm" variant={selected ? 'secondary' : 'ghost'} aria-pressed={selected} onClick={() => { setBaselineId(selected ? '' : item.id); setComparisonId(''); setIncompatible(''); }}>{selected ? 'Selected' : 'Select baseline'}</Button>
                        </div>
                      </div>
                      {selected ? (
                        <div className="pv-section">
                          {item.entries.map((entry) => (
                            <div key={entry.expectation_id} className="pv-detail">
                              <p className="small pv-break">{firewallScopeText(expectationById.get(entry.expectation_id))}</p>
                              <EvidenceRefList refs={entry.references} focusPrefix={`pv-fwb-${item.id}-${entry.expectation_id}`} />
                            </div>
                          ))}
                        </div>
                      ) : null}
                    </li>
                  );
                })}
              </ul>
            ) : null}
          </section>

          {selectedBaseline ? (
            <section className="pv-section" aria-labelledby="pv-fw-compare-title">
              <header className="td-section-head">
                <div>
                  <h3 id="pv-fw-compare-title">Post-change comparisons</h3>
                  <p>Choose finished runs from after the change. Evaluating them sends no traffic; incompatible evidence is never counted as a match.</p>
                </div>
                {canWrite && form !== 'compare' ? <Button size="sm" variant="secondary" onClick={() => openForm('compare')}>Compare post-change runs</Button> : null}
              </header>
              {baselineFreshness(selectedBaseline).state === 'stale' ? <p className="pv-notice" data-tone="warn" data-state="stale">This baseline is outside its freshness window. Comparisons against it are reported as stale; capture a new baseline before relying on a result.</p> : null}
              {incompatible ? <p className="pv-notice" data-tone="warn" data-state="incompatible-baseline" role="alert">{incompatible}</p> : null}
              {form === 'compare' ? (
                <form className="pv-form" noValidate onSubmit={(event) => { event.preventDefault(); reviewCompare(); }} aria-labelledby="pv-fw-compare-form-title">
                  <h3 id="pv-fw-compare-form-title" ref={formHeading} tabIndex={-1}>Compare post-change runs</h3>
                  <RunPicker config={config} session={session} legend="Finalized post-change runs" targetIds={[targetId]} selected={compareRuns.runIds} notBefore={selectedBaseline.captured_at} onChange={(ids) => setCompareRuns({ runIds: ids, error: '' })} error={compareRuns.error || undefined} />
                  <div className="row-actions">
                    <Button type="submit" size="sm">Review comparison</Button>
                    <Button type="button" size="sm" variant="ghost" onClick={() => setForm('')}>Cancel</Button>
                  </div>
                </form>
              ) : null}
              {comparisons?.state === 'loading' ? <div className="skeleton skeleton-row" aria-label="Loading comparisons" /> : null}
              {comparisons?.state === 'failed' ? <FailureNotice failure={comparisons.failure} subject="comparisons" onRetry={() => setReload((value) => value + 1)} /> : null}
              {comparisons?.state === 'ready' && !comparisons.items.length ? <p className="td-muted">No post-change comparison recorded against this baseline.</p> : null}
              {comparisons?.state === 'ready' && comparisons.items.length ? (
                <div className="pv-tabs-inline" role="group" aria-label="Recorded comparisons">
                  {comparisons.items.map((item) => (
                    <Button key={item.id} size="sm" variant={item.id === comparisonId ? 'secondary' : 'ghost'} aria-pressed={item.id === comparisonId} onClick={() => setComparisonId(item.id === comparisonId ? '' : item.id)}>
                      {item.evaluated_at ? formatDate(item.evaluated_at) : item.id}
                    </Button>
                  ))}
                </div>
              ) : null}
              {comparison?.state === 'loading' ? <div className="skeleton skeleton-row" aria-label="Loading comparison" /> : null}
              {comparison?.state === 'failed' ? <FailureNotice failure={comparison.failure} subject="this comparison" onRetry={() => loadComparison(comparisonId)} /> : null}
              {comparison?.state === 'ready' ? (
                <FirewallComparisonResult
                  comparison={comparison.value}
                  expectationById={expectationById}
                  targetId={targetId}
                  retestBlocker={retestBlocker}
                  onRetest={(ref) => { setError(''); setReview({ kind: 'retest', ref }); }}
                />
              ) : null}
            </section>
          ) : null}
        </div>
      ) : null}

      <ConfirmModal
        open={review !== null}
        title={review?.kind === 'expectation' ? 'Record this firewall expectation?'
          : review?.kind === 'archive' ? 'Archive this expectation?'
            : review?.kind === 'baseline' ? 'Capture this pre-change baseline?'
              : review?.kind === 'compare' ? 'Record this post-change comparison?'
                : 'Start this retest?'}
        confirmTone={review?.kind === 'archive' ? 'danger' : 'default'}
        confirmLabel={review?.kind === 'expectation' ? 'Record expectation'
          : review?.kind === 'archive' ? 'Archive expectation'
            : review?.kind === 'baseline' ? 'Capture baseline'
              : review?.kind === 'compare' ? 'Record comparison'
                : 'Start retest'}
        busy={busy}
        onCancel={() => { setReview(null); setError(''); }}
        onConfirm={() => void confirm()}
        description={(
          <div className="stack-tight scan-review">
            {review?.kind === 'expectation' ? (
              <>
                <dl className="td-review-list">
                  <div><dt>Change</dt><dd className="mono pv-break">{review.body.change_id}</dd></div>
                  <div><dt>Destination</dt><dd><span className="mono pv-break">{str(target, 'value') || targetId}</span></dd></div>
                  <div><dt>Scope</dt><dd className="pv-break">{firewallScopeText(review.body)}</dd></div>
                  {review.body.pre_post_mapping ? <div><dt>Declared migration</dt><dd className="mono pv-break">{review.body.pre_post_mapping.pre_destination_target_id} to {review.body.pre_post_mapping.post_destination_target_id}</dd></div> : null}
                </dl>
                <p>This records your expectation and is audited. It sends no traffic.</p>
              </>
            ) : null}
            {review?.kind === 'archive' ? <p>Archiving <span className="pv-break">{firewallScopeText(review.expectation)}</span> keeps every baseline and comparison that used it.</p> : null}
            {review?.kind === 'baseline' ? (
              <>
                <dl className="td-review-list">
                  <div><dt>Change</dt><dd className="mono pv-break">{review.changeId}</dd></div>
                  <div><dt>Expectations</dt><dd>{review.expectationIds.length}</dd></div>
                  <div><dt>Runs</dt><dd className="mono pv-break">{review.runIds.join(', ')}</dd></div>
                  <div><dt>Freshness window</dt><dd>{Math.round(review.windowSeconds / DAY)} days</dd></div>
                </dl>
                <p>The server keeps only finalized runs with a recorded source and worker. The baseline is immutable and capturing it sends no traffic.</p>
              </>
            ) : null}
            {review?.kind === 'compare' ? (
              <>
                <dl className="td-review-list">
                  <div><dt>Baseline</dt><dd className="mono pv-break">{review.baseline.id}</dd></div>
                  <div><dt>Post-change runs</dt><dd className="mono pv-break">{review.runIds.join(', ')}</dd></div>
                </dl>
                <p>Each expectation is compared only with compatible evidence: same expectation version, source, check and destination or declared mapping. Anything else is reported as not comparable, stale or not tested. No traffic is sent.</p>
              </>
            ) : null}
            {review?.kind === 'retest' ? (
              <>
                <dl className="td-review-list">
                  <div><dt>Check</dt><dd className="mono pv-break">{review.ref.check_id}</dd></div>
                  <div><dt>Target</dt><dd className="mono pv-break">{review.ref.target_id}</dd></div>
                  <div><dt>Retest of run</dt><dd className="mono pv-break">{review.ref.test_run_id}</dd></div>
                </dl>
                <p>This starts the same bounded check on the same declared target through the existing signed workers, safe windows, rate limits and kill switches. The server re-checks ownership now.</p>
              </>
            ) : null}
            {error && review ? <p className="td-form-error" role="alert">{error}</p> : null}
          </div>
        )}
      />
    </section>
  );
}

function FirewallComparisonResult({
  comparison,
  expectationById,
  targetId,
  retestBlocker,
  onRetest,
}: {
  comparison: FirewallComparison;
  expectationById: Map<string, FirewallExpectation>;
  targetId: string;
  retestBlocker: string;
  onRetest: (ref: EvidenceRef) => void;
}) {
  const [openItem, setOpenItem] = useStateKey(comparison.id);
  const compat = compatibilityView(comparison.compatibility);
  const summary = summaryView(comparison.summary, 'firewall_change');
  return (
    <section className="pv-detail" aria-labelledby="pv-fw-result-title">
      <h4 id="pv-fw-result-title">Comparison recorded {comparison.evaluated_at ? formatDate(comparison.evaluated_at) : ''}</h4>
      <div className="pv-badges">
        <Badge tone={summary.accepted ? 'success' : summary.partial ? 'warn' : 'muted'}>{summary.label}</Badge>
        {compat.state === 'stale' ? <Badge tone="warn">{compat.label}</Badge> : null}
        {compat.state === 'incompatible' ? <Badge tone="warn" data-state="incompatible-baseline">{compat.label}</Badge> : null}
      </div>
      {compat.reasons.length ? <ul className="pv-limits" aria-label="Why evidence is not comparable">{compat.reasons.map((reason) => <li key={reason.id}>{reason.label}</li>)}</ul> : null}
      <LimitationList values={comparison.limitations} />
      <ul className="pv-list" aria-label="Per-expectation results">
        {comparison.items.map((item) => {
          const expanded = openItem === item.expectation_id;
          const retestRef = item.evidence_refs.find((ref) => ref.target_id === targetId && ref.check_id) ?? null;
          return (
            <li key={item.expectation_id} className="pv-card" data-status={item.status}>
              <div className="pv-card-head">
                <div className="pv-card-title">
                  <strong>{firewallScopeText(expectationById.get(item.expectation_id))}</strong>
                  <span className="td-muted small">Before: {labelFrom(FIREWALL_SIDE_STATE_LABELS, item.pre_state)} · After: {labelFrom(FIREWALL_SIDE_STATE_LABELS, item.post_state)}{item.expectation_met === true ? ' · expectation met' : item.expectation_met === false ? ' · expectation not met' : ''}</span>
                </div>
                <div className="pv-actions">
                  <Badge tone={toneFrom(FIREWALL_STATUS_TONES, item.status)}>{labelFrom(FIREWALL_STATUS_LABELS, item.status)}</Badge>
                  {item.gap_kind ? <Badge tone="danger">{labelFrom(FIREWALL_GAP_LABELS, item.gap_kind)}</Badge> : null}
                  <Button size="sm" variant="ghost" aria-expanded={expanded} aria-controls={`pv-fw-item-${item.expectation_id}`} onClick={() => setOpenItem(expanded ? '' : item.expectation_id)}>{expanded ? 'Hide evidence' : 'Inspect'}</Button>
                </div>
              </div>
              {expanded ? (
                <div id={`pv-fw-item-${item.expectation_id}`} className="pv-section">
                  {item.gap_kind ? <p className="small">An observed acceptance gap for this sampled source and time. The responsible rule or root cause is not identified.</p> : null}
                  {item.reasons.length ? <p className="small">Reasons: {item.reasons.map((reason) => reason.replace(/_/g, ' ')).join('; ')}.</p> : null}
                  {item.compatibility_reasons.length ? <p className="small">{compatibilityView({ comparable: false, stale: false, reasons: item.compatibility_reasons }).reasons.map((reason) => reason.label).join('; ')}.</p> : null}
                  <LimitationList values={item.limitations} />
                  <EvidenceRefList refs={item.evidence_refs} focusPrefix={`pv-fwc-${comparison.id}-${item.expectation_id}`} />
                  {retestRef ? (
                    <div className="pv-actions">
                      <Button size="sm" variant="secondary" disabled={Boolean(retestBlocker)} title={retestBlocker || undefined} onClick={() => onRetest(retestRef)}>Review exact retest</Button>
                      {retestBlocker ? <span className="td-muted small">{retestBlocker}</span> : <span className="td-muted small">Re-runs {retestRef.check_id} on this target after you confirm.</span>}
                    </div>
                  ) : null}
                </div>
              ) : null}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function useStateKey(resetKey: string): [string, (value: string) => void] {
  const [state, setState] = useState<{ key: string; value: string }>({ key: resetKey, value: '' });
  const value = state.key === resetKey ? state.value : '';
  const update = useCallback((next: string) => setState({ key: resetKey, value: next }), [resetKey]);
  return [value, update];
}
