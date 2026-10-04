import { Fragment, useEffect, useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, Pause, Play, Search, Square } from 'lucide-react';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { requestJson } from '../../lib/api';
import { apiErrorMessage } from '../../lib/error-messages';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import './probe-activity.css';

const LABELS: Record<string, string> = {
  job_started: 'Worker started', attempt_started: 'Attempt started', request_started: 'Request started',
  response_received: 'Response received', attempt_failed: 'Request failed', request_not_sent: 'Not sent',
  probe_completed: 'Probe finished', result_received: 'Result recorded',
  run_started: 'Run started', run_stopped: 'Run stopped',
  phase_completed: 'Phase finished',
};
function text(value: unknown) { return typeof value === 'string' ? value : ''; }
function time(value: unknown) {
  const at = new Date(text(value));
  return Number.isNaN(at.getTime()) ? 'Not recorded' : at.toLocaleTimeString(undefined, { hour12: false, fractionalSecondDigits: 3 });
}
function severity(item: DataItem) {
  if (item.stage === 'attempt_failed' || item.error_class) return 'error';
  if (item.stage === 'request_not_sent') return 'warning';
  return 'info';
}

export function ProbeActivity({ config, session, runId, checkName, running, canStop, onStop, onFollowActive, notSent }: {
  config: PortalConfig; session: Session; runId: string; checkName: string; running: boolean;
  canStop: boolean; onStop: () => void; onFollowActive?: () => void;
  notSent?: { reason: string; at: string } | null;
}) {
  const [snapshot, setSnapshot] = useState<DataItem | null>(null);
  const [error, setError] = useState('');
  const [paused, setPaused] = useState(false);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('all');
  const [expanded, setExpanded] = useState<string | null>(null);
  useEffect(() => { setSnapshot(null); setError(''); setExpanded(null); }, [runId]);
  useEffect(() => {
    if (!runId || paused) return undefined;
    const controller = new AbortController();
    let timer: number | undefined;
    let failures = 0;
    const poll = async () => {
      let active = running;
      try {
        const data = await requestJson(config, session, `/v1/test-runs/${encodeURIComponent(runId)}/activity?limit=200`, { signal: controller.signal }) as DataItem;
        if (controller.signal.aborted) return;
        setSnapshot(data); setError(''); failures = 0;
        active = ['running', 'collecting', 'planned'].includes(text(data.status));
      } catch (reason) {
        if (controller.signal.aborted) return;
        failures += 1;
        setError(apiErrorMessage(reason, 'Activity could not refresh. Previous recorded events remain visible.'));
      }
      if (active && !controller.signal.aborted) timer = window.setTimeout(() => { void poll(); }, Math.min(15_000, 2500 * (failures + 1)));
    };
    void poll();
    return () => { controller.abort(); if (timer !== undefined) window.clearTimeout(timer); };
  }, [config, session, runId, running, paused]);
  const items = useMemo(() => (Array.isArray(snapshot?.items) ? snapshot.items as DataItem[] : notSent ? [{ id: 'scan-decision', stage: 'request_not_sent', source: 'scan_state', reason: notSent.reason, at: notSent.at } as DataItem] : [])
    .filter((item) => filter === 'all' || severity(item) === filter)
    .filter((item) => !search.trim() || [item.operation, item.method, item.url, item.stage, item.status_code, item.error_class, item.reason].join(' ').toLowerCase().includes(search.trim().toLowerCase()))
    .slice().reverse(), [snapshot, filter, search, notSent]);
  return (
    <section className="probe-activity" aria-labelledby="probe-activity-title">
      <header className="probe-activity-head">
        <div><h2 id="probe-activity-title">Execution activity</h2><p>{checkName || 'Choose a recorded check to inspect its activity.'}</p></div>
        <div className="probe-activity-actions">
          {onFollowActive ? <Button size="sm" variant="ghost" onClick={onFollowActive}>Follow active check</Button> : null}
          {canStop && running ? <Button size="sm" variant="danger" onClick={onStop}><Square size={13} aria-hidden="true" />Stop check</Button> : null}
        </div>
      </header>
      <div className="probe-activity-tools">
        <label className="probe-activity-search"><Search size={15} aria-hidden="true" /><span className="sr-only">Search execution activity</span><input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search method, path, response or error" /></label>
        <label><span className="sr-only">Activity severity</span><select aria-label="Activity severity" value={filter} onChange={(event) => setFilter(event.target.value)}><option value="all">All events</option><option value="info">Info</option><option value="warning">Not sent</option><option value="error">Errors</option></select></label>
        <Button size="sm" variant="ghost" disabled={!runId} onClick={() => setPaused((value) => !value)}>{paused ? <Play size={14} aria-hidden="true" /> : <Pause size={14} aria-hidden="true" />}{paused ? 'Resume updates' : 'Pause updates'}</Button>
      </div>
      <div className="probe-activity-status" role="status" aria-live="polite">
        <span>{snapshot ? `${Array.isArray(snapshot.items) ? snapshot.items.length : 0} recorded events` : runId ? 'Waiting for recorded worker activity' : 'No check selected'}</span>
        <span>{paused ? 'Updates paused; execution continues' : running ? 'Live updates · every 2.5s' : text(snapshot?.status).replaceAll('_', ' ') || 'No execution recorded'}</span>
        {snapshot?.requests_sent != null ? <span>{String(snapshot.requests_sent)} attested operations</span> : null}
      </div>
      {error ? <p className="probe-activity-error" role="alert">{error}</p> : null}
      <div className="probe-activity-scroll" role="region" aria-label="Recorded request and response activity" tabIndex={0}>
        <table className="probe-activity-table">
          <caption className="sr-only">Worker-recorded activity for {checkName || 'the selected check'}. Query values, bodies and credential values are not shown.</caption>
          <thead><tr><th scope="col">Event</th><th scope="col">Time</th><th scope="col">Request / operation</th><th scope="col">Response</th><th scope="col"><span className="sr-only">Details</span></th></tr></thead>
          <tbody>
            {items.map((item) => {
              const id = text(item.id);
              const open = expanded === id;
              const level = severity(item);
              return <Fragment key={id}>
                <tr data-severity={level}>
                  <td><Badge tone={level === 'error' ? 'danger' : level === 'warning' ? 'warn' : 'default'}>{LABELS[text(item.stage)] ?? text(item.stage).replaceAll('_', ' ')}</Badge>{item.source === 'simulation' ? <small>Simulation · no target traffic</small> : null}</td>
                  <td><time dateTime={text(item.at)} title={text(item.at)}>{time(item.at)}</time></td>
                  <td><span className="probe-activity-operation">{text(item.method) || text(item.operation).replaceAll('_', ' ') || 'Not recorded'}</span>{item.url ? <code>{text(item.url)}</code> : null}</td>
                  <td>{item.status_code != null ? <strong>HTTP {String(item.status_code)}</strong> : text(item.error_class) || text(item.outcome) || text(item.reason).replaceAll('_', ' ') || '—'}{item.duration_ms != null ? <small>{String(item.duration_ms)} ms</small> : null}</td>
                  <td><button className="probe-activity-expand" aria-label={`Details for event ${id}`} aria-expanded={open} onClick={() => setExpanded(open ? null : id)}>{open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}</button></td>
                </tr>
                {open ? <tr className="probe-activity-detail"><td colSpan={5}><dl>{Object.entries(item).filter(([key]) => !['id', 'sequence', 'stage'].includes(key)).map(([key, value]) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{Array.isArray(value) ? value.join(', ') : value && typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value ?? 'Not recorded')}</dd></div>)}</dl></td></tr> : null}
              </Fragment>;
            })}
            {!items.length ? <tr><td colSpan={5} className="probe-activity-empty">{search || filter !== 'all' ? 'No recorded events match these filters.' : !runId ? 'Select a check with a run, or start a reviewed check.' : snapshot?.telemetry_recorded === false && !running ? 'This run has only its final recorded summary. Per-request activity was not captured by that worker.' : 'No worker events have arrived yet. Planned requests are not shown as sent.'}</td></tr> : null}
          </tbody>
        </table>
      </div>
      <p className="probe-activity-note">{snapshot?.truncated ? 'Showing the latest 200 events. ' : ''}Observed metadata only. Query values and request/response bodies are withheld. Expand an event for its recorded details.</p>
    </section>
  );
}
