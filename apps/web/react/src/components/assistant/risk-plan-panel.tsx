import { useEffect, useRef, useState } from 'react';
import { requestJson } from '../../lib/api';
import { apiErrorMessage } from '../../lib/error-messages';
import { assistantAvailable, useAssistantStatus } from '../../lib/assistant-api';
import { useStructuredJob, unavailableMessage, type QueuedJob } from '../../lib/assistant-jobs';
import { generateRiskPlan, sanitizeRiskPlanAnnotation, type RiskPlanComputed, type RiskPlanPurpose } from '../../lib/assistant-risk-plan-api';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import { Button } from '../ui/button';
import { useOpenInspector } from '../evidence/use-inspector';
import { ValidationScanLauncher } from '../runs/validation-scan-launcher';
import { AiStatusBadge } from './ai-status-badge';
import './risk-plan.css';

type Props = { config: PortalConfig; session: Session; target: DataItem; checks: DataItem[]; canStart: boolean };

function Proposal({ computed, initialQueued, purpose, config, session, target, checks, canStart }: Props & { computed: RiskPlanComputed; initialQueued: QueuedJob; purpose: RiskPlanPurpose }) {
  const [queued, setQueued] = useState<QueuedJob | null>(initialQueued);
  const job = useStructuredJob(config, session, queued, purpose, (value) => sanitizeRiskPlanAnnotation(value, computed, purpose));
  const [selection, setSelection] = useState<string[]>(computed.check_ids ?? []);
  const [reviewed, setReviewed] = useState(false);
  const [launcher, setLauncher] = useState<{ targetIds: string[]; checkIds: string[] } | null>(null);
  const [notice, setNotice] = useState('');
  const [cancelBusy, setCancelBusy] = useState(false);
  const openInspector = useOpenInspector();
  useEffect(() => () => {
    if (initialQueued.status === 'queued') void requestJson(config, session, `/v1/assistant/jobs/${encodeURIComponent(initialQueued.jobId)}`, { method: 'DELETE' }).catch(() => {});
  }, [config, session, initialQueued]);
  const stories = job.value?.stories ?? computed.stories ?? [];
  const fallback = unavailableMessage(queued, job.failed, 'the computed proposal remains available');
  const candidates = computed.candidates ?? [];

  async function cancel() {
    if (!queued?.jobId) return;
    setCancelBusy(true);
    try {
      await requestJson(config, session, `/v1/assistant/jobs/${encodeURIComponent(queued.jobId)}`, { method: 'DELETE' });
      setQueued(null);
      setNotice('AI annotation cancelled. The computed proposal is unchanged.');
    } catch (error) { setNotice(apiErrorMessage(error, 'Cancellation was not confirmed. Try again.')); }
    finally { setCancelBusy(false); }
  }

  return <div className="ai-risk-result">
    <div className="ai-risk-status"><AiStatusBadge pending={job.pending || queued?.status === 'queued' && !job.value && !job.failed} ai={!!job.value} seconds={job.seconds} pendingLabel="Annotating" />
      {queued?.status === 'queued' && !job.value && !job.failed ? <Button variant="ghost" size="sm" disabled={cancelBusy} onClick={() => void cancel()}>Cancel AI annotation</Button> : null}
    </div>
    <p className="muted small">One declared target only · no subdomains · external-only evidence · snapshot {computed.as_of}</p>
    {computed.incomplete ? <p className="muted">Incomplete finding data: this is a bounded selection, not a complete target assessment.</p> : null}
    {fallback ? <p className="muted" role="status">{fallback} Generate again to retry.</p> : null}
    {notice ? <p role="status">{notice}</p> : null}
    {purpose === 'risk_story' ? <>
      <h4>Possible impact — hypotheses, not observed facts</h4>
      {stories.length ? <ol className="ai-risk-stories">{stories.map((story, index) => <li key={`${computed.snapshot_id}-${index}`}><p>{story.hypothesis}</p><span className="muted small">Source findings: {story.source_finding_ids.join(', ')}</span></li>)}</ol> : <p>No source findings were returned. This does not establish protection or absence of risk.</p>}
      <p className="muted small">{job.value ? 'AI-written hypotheses. Verify every claim against the recorded facts below.' : 'Computed conditional hypotheses. No exploitation, causal link or current exposure is established.'} Existing issue groups, scores and verdicts are unchanged.</p>
    </> : <>
      <p>{computed.selection_basis}</p>
      {job.value?.rationale ? <div><p><strong>AI suggestion:</strong> {job.value.rationale}</p><p className="muted small">Suggested order: {job.value.check_ids?.join(', ')}</p><Button variant="secondary" size="sm" onClick={() => { setSelection(job.value?.check_ids ?? []); setReviewed(false); }}>Use AI suggestion for review</Button></div> : null}
      <fieldset className="ai-risk-selection"><legend>Review exact checks for this target</legend>
        {candidates.length ? candidates.map((candidate) => <label key={candidate.check_id}><input type="checkbox" checked={selection.includes(candidate.check_id)} disabled={!canStart || !selection.includes(candidate.check_id) && selection.length >= 12} onChange={(event) => { setSelection((current) => event.target.checked ? [...current, candidate.check_id] : current.filter((id) => id !== candidate.check_id)); setReviewed(false); }} /><span>{candidate.name}<small className="muted">{candidate.check_id} · at most {candidate.max_requests ?? 'unknown'} requests{candidate.source_finding_ids.length ? ` · source findings: ${candidate.source_finding_ids.join(', ')}` : ''}</small></span></label>) : <p>No eligible checks in the current server answer. Review prerequisite exclusions below; nothing was started.</p>}
      </fieldset>
      {selection.length ? <p className="muted small">Selected review order: {selection.join(', ')}</p> : null}
      {canStart ? <><label className="ai-risk-review"><input type="checkbox" checked={reviewed} onChange={(event) => setReviewed(event.target.checked)} />I reviewed this target and these exact checks. Continue to the existing scan review; do not start yet.</label><Button variant="secondary" disabled={!reviewed || !selection.length} onClick={() => setLauncher({ targetIds: [computed.target_id], checkIds: [...selection] })}>Review selected checks in scan launcher</Button></> : <p className="muted">Your role can review recommendations but cannot start scans.</p>}
      <p className="muted small">{computed.admission} Generating and reviewing this proposal sends no probe and changes no schedule or provider.</p>
      <details><summary>Excluded checks and prerequisites ({computed.excluded?.length ?? 0})</summary><ul>{computed.excluded?.map((row) => <li key={row.check_id}><span className="mono">{row.check_id}</span> — {row.reason.replaceAll('_', ' ')}</li>)}</ul></details>
    </>}
    <details><summary>Observed facts and source evidence ({computed.observed_facts.length})</summary>
      <p className="muted small">Metadata recorded on the cited finding, not new probe observations. Evidence IDs are citations, not independent integrity verification. Review unknown, stale and incomplete labels before acting.</p>
      <ul className="ai-risk-facts">{computed.observed_facts.map((fact) => <li key={fact.finding_id}>
        <strong>{fact.finding_id}</strong><p>Recorded check: {fact.check_id ?? 'unknown'} · status: {fact.status} · severity: {fact.severity}</p>
        <p className="muted small">Recorded at: {fact.observed_at ?? 'unknown'} · {fact.data_labels.map((label) => label.replaceAll('_', ' ')).join(' · ')}</p>
        <p className="muted small">Evidence citations: {fact.evidence_ids.length ? fact.evidence_ids.join(', ') : 'unknown — none recorded in this snapshot'}</p>
        <Button variant="ghost" size="sm" data-focus-key={`risk-source-${purpose}-${fact.finding_id}`} onClick={() => openInspector({ entry: 'finding', finding_id: fact.finding_id, target_id: computed.target_id }, `risk-source-${purpose}-${fact.finding_id}`)}>View original finding evidence</Button>
      </li>)}</ul>
    </details>
    <details><summary>Scope and limitations</summary><ul>{computed.limitations.map((text) => <li key={text}>{text}</li>)}</ul></details>
    {launcher ? <ValidationScanLauncher open mode="create" config={config} session={session} checks={checks} initialTargets={[target]} initialSelection={launcher} onClose={() => setLauncher(null)} onScheduled={(scan) => { setLauncher(null); window.location.hash = `#scan-detail?id=${encodeURIComponent(String(scan.id))}`; }} onStarted={(scan) => { setLauncher(null); window.location.hash = `#scan-detail?id=${encodeURIComponent(String(scan.id))}`; }} /> : null}
  </div>;
}

function RiskPlanCard(props: Props & { purpose: RiskPlanPurpose }) {
  const { config, session, target, purpose } = props;
  const targetId = String(target.id);
  const [result, setResult] = useState<{ computed: RiskPlanComputed; queued: QueuedJob; session: Session; config: PortalConfig } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const request = useRef<AbortController | null>(null);
  useEffect(() => {
    setResult(null); setBusy(false); setError('');
    return () => request.current?.abort();
  }, [config, session, targetId]);
  const visible = result?.session === session && result.config === config && result.computed.target_id === targetId ? result : null;

  async function generate() {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setBusy(true); setError(''); setResult(null);
    try {
      const next = await generateRiskPlan(config, session, targetId, purpose, controller.signal);
      if (!controller.signal.aborted) setResult({ ...next, session, config });
    } catch (err) { if (!controller.signal.aborted) setError(apiErrorMessage(err, 'The proposal could not be generated. Retry Generate.')); }
    finally { if (!controller.signal.aborted) setBusy(false); }
  }

  return <section className="ai-risk-card" aria-label={purpose === 'risk_story' ? 'Risk stories' : 'Validation recommender'} aria-busy={busy || undefined}>
    <header><div><h3>{purpose === 'risk_story' ? 'Risk stories' : 'Validation recommender'}</h3><p className="muted small">{purpose === 'risk_story' ? 'Conditional impact linked to exact finding evidence, separate from recorded facts.' : 'A bounded check proposal, not a run, schedule or protection verdict.'}</p></div><Button variant="secondary" size="sm" disabled={busy} onClick={() => void generate()}>{visible ? 'Refresh proposal' : error ? 'Retry Generate' : 'Generate'}</Button></header>
    {busy ? <p role="status">Reading the authorized target snapshot… <Button variant="ghost" size="sm" onClick={() => { request.current?.abort(); setBusy(false); }}>Cancel request</Button></p> : null}
    {error ? <p role="alert">{error}</p> : null}
    {visible ? <Proposal key={visible.computed.snapshot_id} {...props} computed={visible.computed} initialQueued={visible.queued} /> : !busy && !error ? <p className="muted small">Generate explicitly to read a snapshot. Nothing is generated or executed on page load.</p> : null}
  </section>;
}

export function RiskPlanPanel(props: Props) {
  const { status } = useAssistantStatus(props.config, props.session);
  if (props.session.principal === 'staff' || !assistantAvailable(status)) return null;
  return <div className="ai-risk-panel"><RiskPlanCard {...props} purpose="risk_story" /><RiskPlanCard {...props} purpose="validation_plan" /></div>;
}
