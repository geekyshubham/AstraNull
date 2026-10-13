import { useEffect, useRef, useState } from 'react';
import { Play } from 'lucide-react';
import { requestJson, sessionIdentity } from '../../lib/api';
import { apiErrorMessage } from '../../lib/error-messages';
import { ConfirmModal } from '../../lib/crud-ui';
import { formatDate } from '../../lib/utils';
import type { AcceptedExecution, DataItem, PortalConfig, Session } from '../../lib/types';
import {
  REVIEWED_SAFE_CHECK_ID, acceptedReviewedSafeExecution, reviewedSafePlanPresentation,
  reviewedSafeReviewPresentation, reviewedSafeStartBody,
} from '../../lib/reviewed-safe-check.mjs';
import { Button } from '../ui/button';

const record = (value: unknown): DataItem | null => value && typeof value === 'object' && !Array.isArray(value) ? value as DataItem : null;
const REVIEW_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;

type Props = {
  config: PortalConfig;
  session: Session;
  target: DataItem;
  blocked?: boolean;
  onStarted: (message: string, execution: AcceptedExecution) => void;
};

/** An explicit reviewed branch only; catalog-wide support and Run all are unchanged. */
export function ReviewedSafeCheck({ config, session, target, blocked = false, onStarted }: Props) {
  const scope = JSON.stringify([sessionIdentity(session), session.role, target.tenant_id, target.id,
    target.kind, target.value, target.protocol, target.port, target.target_group_id,
    target.expected_behavior, target.declaration_json, target.deleted_at]);
  const scopeRef = useRef(scope);
  scopeRef.current = scope;
  const blockedRef = useRef(blocked);
  blockedRef.current = blocked;
  const generation = useRef(0);
  const inFlight = useRef(false);
  const alive = useRef(true);
  const [reviewId, setReviewId] = useState('');
  const [declaredInert, setDeclaredInert] = useState(false);
  const [proposal, setProposal] = useState<{ record: DataItem; request: DataItem } | null>(null);
  const [review, setReview] = useState<DataItem | null>(null);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [confirm, setConfirm] = useState(false);
  const [, refreshClock] = useState(0);
  const options = { target, tenantId: session.tenant_id ?? '' };
  const state = reviewedSafeReviewPresentation(review, options);
  const preview = reviewedSafePlanPresentation(proposal?.record, options);
  const canApprove = ['owner', 'admin'].includes(session.role ?? '');

  useEffect(() => {
    generation.current += 1;
    inFlight.current = false;
    setReviewId(''); setDeclaredInert(false); setProposal(null); setReview(null);
    setBusy(''); setError(''); setMessage(''); setConfirm(false);
  }, [scope]);

  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; generation.current += 1; };
  }, []);

  useEffect(() => {
    if (!state.available || blocked) setConfirm(false);
  }, [state.available, blocked]);

  useEffect(() => {
    const expiresAt = String(record(review?.plan)?.expires_at ?? record(proposal?.record.plan)?.expires_at ?? '');
    const until = Date.parse(expiresAt);
    if (!Number.isFinite(until)) return;
    const timer = window.setTimeout(() => refreshClock((value) => value + 1), Math.max(0, Math.min(24 * 60 * 60 * 1000, until - Date.now() + 1)));
    return () => window.clearTimeout(timer);
  }, [review, proposal]);

  async function perform(action: string, work: (current: () => boolean) => Promise<void>) {
    if (inFlight.current) return;
    inFlight.current = true;
    const sequence = ++generation.current;
    const submittedScope = scope;
    const current = () => alive.current && scopeRef.current === submittedScope && generation.current === sequence;
    setBusy(action); setError(''); setMessage('');
    try { await work(current); }
    catch (failure) { if (current()) setError(apiErrorMessage(failure, 'The reviewed operation could not be completed.')); }
    finally { if (current()) { inFlight.current = false; setBusy(''); } }
  }

  async function loadReview() {
    if (!REVIEW_ID.test(reviewId)) { setError('Enter the exact recorded review ID.'); return; }
    const selectedId = reviewId;
    setProposal(null); setReview(null);
    await perform('load', async (current) => {
      const response = await requestJson(config, session, `/v1/reviewed-operations/${encodeURIComponent(selectedId)}`);
      if (!current()) return;
      const loaded = record(response);
      const presented = reviewedSafeReviewPresentation(loaded, options);
      if (!presented.valid || loaded?.id !== selectedId) { setError('This review does not match the exact target and fixed GET comparison.'); return; }
      setReview(loaded);
      setMessage('Review loaded passively. This action did not start a check.');
    });
  }

  async function previewPlan() {
    if (!declaredInert) return;
    setProposal(null); setReview(null);
    const request = { target_id: target.id, check_id: REVIEWED_SAFE_CHECK_ID, template: 'marker-query-v1',
      semantics: 'inert_diagnostic', side_effects: 'none', expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString() };
    await perform('preview', async (current) => {
      const response = record(await requestJson(config, session, '/v1/reviewed-operations/preview', { method: 'POST', body: request }));
      if (!current()) return;
      const presented = reviewedSafePlanPresentation(response, options);
      if (!presented.valid || !response) { setError('The preview did not match the exact fixed GET plan. No approval was created.'); return; }
      setProposal({ record: response, request });
    });
  }

  async function approvePlan() {
    if (!proposal || !declaredInert || !canApprove || !preview.valid) return;
    const selected = proposal;
    await perform('approve', async (current) => {
      const approved = record(await requestJson(config, session, '/v1/reviewed-operations', {
        method: 'POST', body: { ...selected.request, reviewed_plan_digest: preview.planDigest },
      }));
      if (!current()) return;
      const presented = reviewedSafeReviewPresentation(approved, options);
      if (!presented.current || !approved) { setError('Approval was returned without a current matching review. No check was started.'); return; }
      setReviewId(presented.reviewId); setProposal(null);
      const loaded = record(await requestJson(config, session, `/v1/reviewed-operations/${encodeURIComponent(presented.reviewId)}`));
      if (!current()) return;
      if (loaded?.id !== presented.reviewId || !reviewedSafeReviewPresentation(loaded, options).valid) {
        setError('The approved review could not be reloaded for this exact target. No check was started.'); return;
      }
      setReview(loaded);
      setMessage('Human review recorded. Approval is passive; start remains a separate action.');
    });
  }

  async function startCheck() {
    if (!state.available || !review || blocked || !confirm) return;
    const selectedId = state.reviewId;
    await perform('start', async (current) => {
      const latest = record(await requestJson(config, session, `/v1/reviewed-operations/${encodeURIComponent(selectedId)}`));
      if (!current()) return;
      setReview(latest);
      if (blockedRef.current) { setConfirm(false); setError('Starting became unavailable while the review was rechecked. No check was submitted.'); return; }
      const body = latest?.id === selectedId ? reviewedSafeStartBody(latest, options) : null;
      if (!body) { setConfirm(false); setError('The exact review is no longer current and available. No ordinary check was substituted.'); return; }
      const response = await requestJson(config, session, '/v1/test-runs', { method: 'POST', body });
      if (!current()) return;
      setConfirm(false);
      const accepted = acceptedReviewedSafeExecution(response, String(target.id));
      if (!accepted) { setError('Start returned no exact target/check/run identity. No historical run was substituted; refresh recorded activity.'); return; }
      onStarted('Reviewed fixed GET comparison started. Follow its progress and evidence in the Inspector.', accepted);
    });
  }

  return (
    <section className="pv-section" aria-labelledby="reviewed-get-title">
      <header className="td-section-head"><div>
        <h3 id="reviewed-get-title">Reviewed fixed GET comparison</h3>
        <p>Use an exact approved diagnostic URL for a fixed inert-marker comparison. Preview and approval are passive; neither starts traffic nor proves protection.</p>
      </div></header>
      <p className="td-muted small">The configured execution path allows at most three probe GET operations plus two destination DNS attempts, once, within the original maximum 120-second authority. An unhealthy permitted control stops the comparison. It does not establish origin receipt, CVE mitigation or DDoS capacity.</p>
      <details>
        <summary>Prepare or load an exact review</summary>
        <div className="pv-form">
          <label className="td-field"><span>Existing review ID</span>
            <input value={reviewId} autoComplete="off" spellCheck={false} disabled={Boolean(busy)} onChange={(event) => { setReviewId(event.target.value); setReview(null); setProposal(null); setError(''); }} />
          </label>
          <Button size="sm" variant="secondary" disabled={Boolean(busy) || !reviewId} onClick={() => void loadReview()}>Load review</Button>
          <label className="pv-check"><input type="checkbox" checked={declaredInert} disabled={Boolean(busy)} onChange={(event) => { setDeclaredInert(event.target.checked); setProposal(null); }} />
            <span>I declare that this exact endpoint is an inert diagnostic path with no side effects. This is my declaration, not observed enforcement or execution permission.</span>
          </label>
          <Button size="sm" variant="secondary" disabled={Boolean(busy) || !declaredInert} onClick={() => void previewPlan()}>Preview fixed GET plan</Button>
          {!canApprove ? <p className="td-muted small">A human owner or administrator must approve the exact plan. Other roles can load an existing review subject to server permissions.</p> : null}
        </div>
      </details>
      {proposal && preview.valid ? <div className="pv-card">
        <h4>Passive plan preview</h4>
        <dl className="td-review-list">
          <div><dt>Endpoint</dt><dd className="mono pv-break">{preview.endpoint}</dd></div>
          <div><dt>Check</dt><dd className="mono">{REVIEWED_SAFE_CHECK_ID}</dd></div>
          <div><dt>Check version</dt><dd className="mono pv-break">{preview.checkVersion}</dd></div>
          <div><dt>Scenario</dt><dd className="mono pv-break">{preview.scenarioVersion}</dd></div>
          <div><dt>Serializer</dt><dd>GET · fixed-asn-probe-query.v1 · no body</dd></div>
          <div><dt>Review bound</dt><dd>{preview.maximumProbeOperations} maximum future probe operations; no operations performed</dd></div>
          <div><dt>Review expires</dt><dd>{formatDate(preview.expiresAt)}</dd></div>
          <div><dt>Exact plan digest</dt><dd className="mono pv-break">{preview.planDigest}</dd></div>
        </dl>
        <Button size="sm" variant="secondary" disabled={!canApprove || !declaredInert || Boolean(busy)} onClick={() => void approvePlan()}>Approve this exact passive plan</Button>
      </div> : null}
      {review && state.valid ? <div className="pv-card" role="region" aria-label="Selected reviewed GET plan">
        <dl className="td-review-list">
          <div><dt>Review</dt><dd className="mono pv-break">{state.reviewId || String(review.id ?? '')}</dd></div>
          <div><dt>Endpoint</dt><dd className="mono pv-break">{state.endpoint}</dd></div>
          <div><dt>Expires</dt><dd>{formatDate(state.expiresAt)}</dd></div>
          <div><dt>Current review</dt><dd>{state.current ? 'Current passive review' : 'Not current; start unavailable'}</dd></div>
          <div><dt>Execution dependency</dt><dd>{state.available ? 'Specific reviewed path configured; admission still rechecks all gates' : 'Unavailable; no ordinary execution fallback'}</dd></div>
        </dl>
        <Button size="sm" disabled={!state.available || blocked || Boolean(busy)} onClick={() => setConfirm(true)}>
          <Play size={15} aria-hidden="true" />Review and start fixed GET comparison
        </Button>
        {blocked ? <p className="td-muted small">Starting is unavailable under the current role or active execution state.</p> : null}
      </div> : null}
      {review && !state.valid ? <p className="td-muted small" role="status">This review has expired or no longer matches the exact current scope. Reload or prepare a new passive review before starting; this review cannot enable a new start.</p> : null}
      {message ? <p className="form-banner" role="status">{message}</p> : null}
      {error ? <p className="td-form-error" role="alert">{error}</p> : null}
      <ConfirmModal open={confirm} title="Start this exact reviewed GET comparison?" description={(
        <div className="stack-tight">
          <p className="mono pv-break">{state.endpoint}</p>
          <p>Permitted GET control, fixed untransformed inert marker, then transformed inert marker. At most three probe operations and two DNS attempts; no retry or renewed authority.</p>
          <p>Starting rereads this exact review and the server rechecks ownership, material, safe windows, rate, concurrency and kill-switch gates. A reviewed plan is not a protection verdict.</p>
        </div>
      )} confirmLabel="Start reviewed comparison" busy={busy === 'start'} onCancel={() => setConfirm(false)} onConfirm={() => void startCheck()} />
    </section>
  );
}
