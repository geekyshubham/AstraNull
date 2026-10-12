import { useEffect, useRef, useState } from 'react';
import { Square } from 'lucide-react';
import { requestJson } from '../../lib/api';
import { apiErrorMessage } from '../../lib/error-messages';
import { evidenceContextPath, inspectorLoadKey, normalizeEvidenceContext, resolveScanChild, type EvidenceContextModel, type EvidenceInspectorRef } from '../../lib/evidence-inspector.mjs';
import { activityIsLive, captureWarnings, stopStateLabel } from '../../lib/recorded-activity.mjs';
import { canStartRun } from '../../lib/run-permissions.mjs';
import { plainCheckName, plainVerdictLabel } from '../../lib/plain-language.mjs';
import { ConfirmModal } from '../../lib/crud-ui';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import { ProbeActivityView } from '../targets/probe-activity';
import { Button } from '../ui/button';
import { useRecordedActivity } from './use-recorded-activity';
import { useInspectorScopeKey, useScanDisplaySelection } from './use-inspector';

const str = (value: unknown) => typeof value === 'string' ? value : '';
const object = (value: unknown) => value && typeof value === 'object' && !Array.isArray(value) ? value as DataItem : null;

/** Only an explicit Stop confirmation mutates. Opening, following and reconnecting are passive. */
export function ExecutionInspector({ config, session, reference, checks, onEvidenceUpdate }: {
  config: PortalConfig; session: Session; reference: EvidenceInspectorRef; checks: DataItem[]; onEvidenceUpdate?: (state?: 'denied' | 'auth' | 'not_found') => void;
}) {
  const isScan = reference.entry === 'validation_scan';
  const [paused, setPaused] = useState(false);
  const { follow, pinnedChild, select } = useScanDisplaySelection(reference);
  const scopeKey = useInspectorScopeKey(config, session);
  const [confirm, setConfirm] = useState<{ kind: 'run' | 'scan'; id: string; scopeKey: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [requested, setRequested] = useState<{ id: string; label: string } | null>(null);
  const scanActivity = useRecordedActivity({ config, session, kind: 'scan', id: isScan ? reference.scan_id || '' : '', paused });
  const scan = scanActivity.record;
  const scanAccessDenied = [401, 403, 404].includes(Number((scanActivity.error as { status?: number } | null)?.status));
  // useRecordedActivity hides prior tenant/principal/credential records in the same render.
  // No persisted pin is fetched until this current scoped exact assessment proves membership.
  const selection = resolveScanChild(reference, scan, scanActivity.error);
  const scanBound = !isScan || Boolean(scan && scan.id === reference.scan_id && (scan.target_id === reference.target_id || (Array.isArray(scan.target_ids) && scan.target_ids.includes(reference.target_id))));
  const steps = selection.steps;
  const childId = isScan ? selection.runId : reference.test_run_id || '';
  const targetId = isScan ? selection.targetId : reference.target_id || '';
  const checkId = isScan ? selection.checkId : reference.check_id || '';
  const check = checks.find((item) => (item.check_id || item.id) === checkId);
  const checkName = plainCheckName(str(check?.name) || checkId) as string;
  const runActivity = useRecordedActivity({ config, session, id: scanBound ? childId : '', paused });
  const snapshot = runActivity.snapshot;
  const bound = scanBound && (!snapshot || (snapshot.run_id === childId && snapshot.target_id === targetId && snapshot.check_id === checkId));
  const activityStatus = Number((runActivity.error as { status?: number } | null)?.status);
  const activityDenied = [401, 403, 404].includes(activityStatus);
  const latestRevision = useRef(0);
  useEffect(() => {
    if (isScan || !bound) return;
    if (activityDenied) {
      onEvidenceUpdate?.(activityStatus === 401 ? 'auth' : activityStatus === 403 ? 'denied' : 'not_found');
    } else if (runActivity.revision > latestRevision.current) {
      latestRevision.current = runActivity.revision;
      onEvidenceUpdate?.();
    }
  }, [isScan, bound, activityDenied, activityStatus, runActivity.revision, onEvidenceUpdate]);
  const profile = object(check?.probe_profile);
  const maxRequests = profile?.max_requests != null && Number.isFinite(Number(profile.max_requests)) ? Number(profile.max_requests) : null;
  const runLive = bound && !activityDenied && (snapshot ? activityIsLive(snapshot) : Boolean(childId));
  const scanLive = scanBound && !scanAccessDenied && activityIsLive(scan);
  const stopAllowed = canStartRun(session.role);

  async function stop() {
    const kind = confirm?.kind;
    const id = confirm?.id;
    if (!confirm || confirm.scopeKey !== scopeKey || !kind || !id || !stopAllowed) return;
    // Recheck the captured identity, not whichever child the display now follows or pins.
    if (isScan) {
      if (!scanBound || scanAccessDenied) return;
      if (kind === 'run' && resolveScanChild({ ...reference, display_mode: 'pinned', pinned_run_id: id }, scan, scanActivity.error).state !== 'ready') return;
      if (kind === 'scan' && id !== reference.scan_id) return;
    } else if (kind !== 'run' || id !== reference.test_run_id || !bound || activityDenied) return;
    setBusy(true); setError('');
    try {
      await requestJson(config, session, `/v1/${kind === 'scan' ? 'validation-scans' : 'test-runs'}/${encodeURIComponent(id)}/cancel`, {
        method: 'POST', body: { reason: kind === 'scan' ? 'Stopped assessment from live Inspector' : 'Stopped exact check from live Inspector' },
      });
      setRequested({ id, label: 'Stop requested · worker acknowledgment pending. Cancellation is not measured Stop proof.' });
      setConfirm(null);
      scanActivity.refresh(); runActivity.refresh();
    } catch (reason) { setError(apiErrorMessage(reason, 'Stop could not be requested. Execution may still be active.')); }
    finally { setBusy(false); }
  }

  return <section className="ei-execution" aria-label="Live execution workspace">
    {isScan ? <>
      <dl className="ei-kv">
        <div><dt>Exact assessment</dt><dd className="mono">{reference.scan_id}</dd></div>
        <div><dt>Recorded state</dt><dd>{str(scan?.status).replaceAll('_', ' ') || 'Waiting for recorded assessment state'}</dd></div>
        <div><dt>Display selection</dt><dd>{follow ? 'Following the active child of this exact assessment' : 'Pinned child · does not switch when another check starts'}</dd></div>
        <div><dt>Last assessment update</dt><dd>{scanActivity.lastUpdated ? <time dateTime={scanActivity.lastUpdated}>{new Date(scanActivity.lastUpdated).toLocaleTimeString()}</time> : 'No successful update yet'}</dd></div>
      </dl>
      {scanActivity.snapshot ? <ul className="ei-note" aria-label="Assessment capture limitations">{captureWarnings(scanActivity.snapshot).map((warning) => <li key={warning}>{warning}</li>)}</ul> : null}
      <div className="ei-actions">
        {!childId ? <Button size="sm" variant="secondary" onClick={() => setPaused((value) => !value)}>{paused ? 'Resume assessment updates' : 'Pause assessment updates'}</Button> : null}
        <Button size="sm" variant="secondary" disabled={follow && !childId} onClick={() => select(follow ? childId : undefined)}>{follow ? 'Pin this check' : 'Follow active check'}</Button>
        {stopAllowed && scanLive && !stopStateLabel(scanActivity.snapshot?.stop) && requested?.id !== reference.scan_id ? <Button size="sm" variant="danger" onClick={() => reference.scan_id && setConfirm({ kind: 'scan', id: reference.scan_id, scopeKey })}><Square size={14} aria-hidden="true" />Stop assessment</Button> : null}
      </div>
      {steps.length ? <label className="ei-child-select">Inspect a recorded child<select value={childId} onChange={(event) => select(event.target.value)}>{!childId ? <option value="" disabled>{follow ? 'Waiting for an authorized child' : 'Pinned child unavailable'}</option> : null}{steps.map((step) => <option key={str(step.id) || str(step.test_run_id)} value={str(step.test_run_id)}>{str(step.check_id)} · {str(step.test_run_id)}</option>)}</select></label> : null}
      {scanActivity.error ? <p className="ei-partial" role="alert">Assessment refresh failed; the recorded view may be stale. <Button size="sm" variant="secondary" disabled={paused} onClick={scanActivity.refresh}>Reconnect assessment</Button></p> : null}
      {stopStateLabel(scanActivity.snapshot?.stop) ? <p className="ei-note" role="status">{stopStateLabel(scanActivity.snapshot?.stop)}. Finished child results are retained.</p> : null}
      {selection.state === 'loading' ? <p className="ei-note">Loading this exact assessment before reading its selected child.</p> : null}
      {selection.state === 'unavailable' || (!follow && (activityDenied || !bound)) ? <p className="ei-partial" role="alert">{follow ? 'Assessment selection unavailable' : 'Pinned child unavailable'}{pinnedChild ? ` · ${pinnedChild}` : ''}. The exact assessment/target relationship or access could not be confirmed. No other child was substituted.</p> : null}
      {selection.state === 'empty' ? <p className="ei-note">No child run has been dispatched for this target. Planned checks are not shown as requests sent.</p> : null}
    </> : <p className="ei-note">Pinned to the exact accepted or selected run. Newer runs never replace this inspection.</p>}
    {requested && (requested.id === childId || requested.id === reference.scan_id) && !stopStateLabel(requested.id === reference.scan_id ? scanActivity.snapshot?.stop : snapshot?.stop) ? <p className="ei-note" role="status">{requested.label}</p> : null}
    {error ? <p className="probe-activity-error" role="alert">{error}</p> : null}
    {!bound && (!isScan || follow) ? <p className="ei-partial" role="alert">The recorded execution does not match this target/check scope. No other run was substituted.</p> : null}
    {childId && bound && !activityDenied ? <ProbeActivityView
      runId={childId} checkName={checkName} running={runLive}
      canStop={stopAllowed && requested?.id !== childId} onStop={() => setConfirm({ kind: 'run', id: childId, scopeKey })}
      activity={runActivity} paused={paused} onPause={() => setPaused((value) => !value)} maxRequests={maxRequests}
      onFollowActive={isScan && !follow ? () => select() : undefined}
    /> : null}
    {isScan && childId && snapshot && bound && !activityDenied ? <ChildEvidence config={config} session={session} targetId={targetId} checkId={checkId} runId={childId} revision={runActivity.revision} paused={paused} accessDenied={activityDenied} /> : null}
    <ConfirmModal open={confirm !== null} title={confirm?.kind === 'scan' ? 'Stop this assessment?' : 'Stop this exact check?'}
      description={confirm?.kind === 'scan' ? 'Request cancellation of this assessment and its active child. Queued children cannot start. Completed evidence is kept; worker Stop requires acknowledgment.' : isScan ? 'Only this child is cancelled. Other checks in the assessment may continue. A bounded in-flight request can finish before the worker acknowledges Stop.' : 'Only this exact run is cancelled. A bounded in-flight request can finish before the worker acknowledges Stop.'}
      confirmLabel={confirm?.kind === 'scan' ? 'Stop assessment' : 'Stop check'} confirmTone="danger" busy={busy}
      onCancel={() => setConfirm(null)} onConfirm={() => void stop()} />
  </section>;
}

function ChildEvidence({ config, session, targetId, checkId, runId, revision, paused, accessDenied }: { config: PortalConfig; session: Session; targetId: string; checkId: string; runId: string; revision: number; paused: boolean; accessDenied: boolean }) {
  const scopeKey = useInspectorScopeKey(config, session);
  const key = inspectorLoadKey(scopeKey, `${targetId}|${checkId}|${runId}`);
  const [loaded, setLoaded] = useState<{ key: string; model: EvidenceContextModel | null; error: boolean }>({ key: '', model: null, error: false });
  useEffect(() => {
    if (!checkId || paused || accessDenied) return undefined;
    const controller = new AbortController();
    const ref: EvidenceInspectorRef = { entry: 'check_result', target_id: targetId, check_id: checkId, test_run_id: runId };
    void requestJson(config, session, evidenceContextPath(ref), { signal: controller.signal }).then((payload) => {
      if (controller.signal.aborted) return;
      const next = normalizeEvidenceContext(payload, ref);
      const unavailable = ['denied', 'auth', 'not_found', 'expired', 'unbound'].includes(next.state);
      setLoaded({ key, model: unavailable ? null : next, error: unavailable });
    }).catch((reason) => {
      if (controller.signal.aborted) return;
      const denied = [401, 403, 404].includes(Number(reason?.status));
      setLoaded((current) => ({ key, model: !denied && current.key === key ? current.model : null, error: true }));
    });
    return () => controller.abort();
  }, [config, session, key, revision, paused, accessDenied, checkId, targetId, runId]);
  const model = !accessDenied && loaded.key === key ? loaded.model : null;
  return <section className="ei-observation" aria-label="Active child evidence">
    <strong>Exact child evidence and evaluation</strong>
    {loaded.key === key && loaded.error ? <p className="ei-note" role="alert">Evidence refresh failed. Recorded activity does not establish the verdict.</p> : null}
    <dl className="ei-kv">
      <div><dt>Raw observation</dt><dd>{model?.answer?.observed || 'Not recorded'}</dd></div>
      <div><dt>Evaluated expectation</dt><dd>{model?.answer?.expected || 'Not recorded'}</dd></div>
      <div><dt>Final verdict</dt><dd>{model?.answer?.outcome ? plainVerdictLabel(model.answer.outcome) : 'Not recorded; activity is informational only'}</dd></div>
      <div><dt>Evidence references</dt><dd>{model?.primary?.evidenceIds.length ? model.primary.evidenceIds.map((id) => <a key={id} href={`#evidence-detail?id=${encodeURIComponent(id)}`}>{id} </a>) : 'No evidence references recorded'}</dd></div>
    </dl>
    {model?.answer?.explanation ? <p className="ei-note">{model.answer.explanation}</p> : null}
    <p className="ei-note">External probes only. A bounded scenario is not capacity proof; unobserved paths and internal layers are not tested.</p>
  </section>;
}
