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
  run_created: 'Run created',
  phase_completed: 'Phase finished',
  response_payload: 'Payload captured', response_body_completed: 'Response body read',
};
function text(value: unknown) { return typeof value === 'string' ? value : ''; }
function time(value: unknown) {
  const at = new Date(text(value));
  return Number.isNaN(at.getTime()) ? 'Not recorded' : at.toLocaleTimeString(undefined, { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 });
}
function severity(item: DataItem) {
  if (item.stage === 'attempt_failed' || item.error_class) return 'error';
  if (item.stage === 'request_not_sent') return 'warning';
  return 'info';
}

function describe(item: DataItem) {
  const vector = [item.vector_family, item.marker_class, item.phase].filter(Boolean).map((value) => String(value).replaceAll('_', ' ')).join(' / ');
  const identity = vector ? ` Vector: ${vector}.` : '';
  if (item.stage === 'request_started') return `The worker started ${text(item.method) || 'a protocol request'}${item.url ? ` to ${text(item.url)}` : ''}.${identity} ${item.body_bytes != null ? `The request body contained ${String(item.body_bytes)} bytes. ` : ''}The captured query and payload preview are listed below.`;
  if (item.stage === 'response_received') return `The target returned ${item.status_code != null ? `HTTP ${String(item.status_code)}` : 'a response with no recorded HTTP status'}.${identity} ${item.response_content_type ? `Recorded format: ${text(item.response_content_type)}. ` : 'The response format was not recorded. '}${item.duration_ms != null ? `Observed request duration: ${String(item.duration_ms)} ms.` : ''}`;
  if (item.response_payload_available === false) return `This check used the recorded response headers and did not consume the response body.${identity} The HTTP status and declared format remain visible; no response payload is invented.`;
  if (item.stage === 'response_payload' || item.stage === 'response_body_completed') return `The worker ${item.stage === 'response_body_completed' ? 'finished reading the bounded response body' : 'captured response bytes while reading the body'}.${identity} ${item.response_content_type ? `Format: ${text(item.response_content_type)}. ` : ''}${item.response_bytes_observed != null ? `${String(item.response_bytes_observed)} bytes observed. ` : ''}${item.response_payload_truncated ? 'The preview is partial.' : 'The captured preview is shown below with sensitive values redacted.'}`;
  if (item.stage === 'request_not_sent') return `This operation was not sent.${identity} Recorded reason: ${text(item.reason).replaceAll('_', ' ') || 'not recorded'}.`;
  if (item.stage === 'attempt_failed') return `The attempted operation failed.${identity} Recorded error: ${text(item.error_class) || 'not recorded'}.`;
  return `${LABELS[text(item.stage)] || text(item.stage).replaceAll('_', ' ')}.${identity} The fields below are the recorded facts for this event.`;
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
  useEffect(() => { setSnapshot(null); setError(''); setExpanded(null); setPaused(false); }, [runId]);
  useEffect(() => {
    if (!runId || paused) return undefined;
    const controller = new AbortController();
    let timer: number | undefined;
    let failures = 0;
    const poll = async () => {
      let active = running;
      try {
        const data = await requestJson(config, session, `/v1/test-runs/${encodeURIComponent(runId)}/activity?limit=256`, { signal: controller.signal }) as DataItem;
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
    .filter((item) => !search.trim() || [item.operation, item.method, item.url, item.stage, item.status_code, item.error_class, item.reason, item.vector_family, item.marker_class, item.phase, item.request_content_type, item.response_content_type].join(' ').toLowerCase().includes(search.trim().toLowerCase()))
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
        <label className="probe-activity-search"><Search size={15} aria-hidden="true" /><span className="sr-only">Search execution activity</span><input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search requests and responses" /></label>
        <label><span className="sr-only">Activity severity</span><select aria-label="Activity severity" value={filter} onChange={(event) => setFilter(event.target.value)}><option value="all">All events</option><option value="info">Info</option><option value="warning">Not sent</option><option value="error">Errors</option></select></label>
        <Button size="sm" variant="ghost" disabled={!runId} onClick={() => setPaused((value) => !value)}>{paused ? <Play size={14} aria-hidden="true" /> : <Pause size={14} aria-hidden="true" />}{paused ? 'Resume updates' : 'Pause updates'}</Button>
      </div>
      <div className="probe-activity-status" role="status" aria-live="polite">
        <span>{snapshot ? `${items.length} shown · ${Array.isArray(snapshot.items) ? snapshot.items.length : 0} recorded events` : notSent ? 'Recorded execution decision · no request dispatched' : runId ? 'Waiting for recorded worker activity' : 'No check selected'}</span>
        <span>{paused ? 'Updates paused; execution continues' : running ? 'Live updates · every 2.5s' : text(snapshot?.status).replaceAll('_', ' ') || 'No execution recorded'}</span>
        {snapshot?.requests_sent != null ? <span>{String(snapshot.requests_sent)} attested operations</span> : null}
      </div>
      {error ? <p className="probe-activity-error" role="alert">{error}</p> : null}
      <div className="probe-activity-scroll" role="region" aria-label="Recorded request and response activity" tabIndex={0}>
        <table className="probe-activity-table" role="table">
          <caption className="sr-only">Worker-recorded activity for {checkName || 'the selected check'}, including methods, vectors, response formats and redacted payload previews. Credentials and declared private query values are withheld.</caption>
          <thead role="rowgroup"><tr role="row"><th role="columnheader" scope="col">Event</th><th role="columnheader" scope="col">Time</th><th role="columnheader" scope="col">Request / operation</th><th role="columnheader" scope="col">Response</th><th role="columnheader" scope="col"><span className="sr-only">Details</span></th></tr></thead>
          <tbody role="rowgroup">
            {items.map((item) => {
              const id = text(item.id);
              const open = expanded === id;
              const level = severity(item);
              return <Fragment key={id}>
                <tr role="row" data-severity={level}>
                  <td role="cell" data-label="Event"><Badge tone={level === 'error' ? 'danger' : level === 'warning' ? 'warn' : 'default'}>{LABELS[text(item.stage)] ?? text(item.stage).replaceAll('_', ' ')}</Badge>{item.source === 'simulation' ? <small>Simulation · no target traffic</small> : null}</td>
                  <td role="cell" data-label="Time"><time dateTime={text(item.at)} title={text(item.at)}>{time(item.at)}</time></td>
                  <td role="cell" data-label="Request"><span className="probe-activity-operation">{text(item.method) || text(item.operation).replaceAll('_', ' ') || 'Not recorded'}</span>{item.url ? <code>{text(item.url)}</code> : null}<small>{[item.vector_family, item.marker_class, item.phase].filter(Boolean).map((value) => String(value).replaceAll('_', ' ')).join(' · ')}</small></td>
                  <td role="cell" data-label="Response">{item.status_code != null ? <strong>HTTP {String(item.status_code)}</strong> : text(item.error_class) || text(item.outcome) || text(item.reason).replaceAll('_', ' ') || '—'}{item.response_content_type ? <small>{text(item.response_content_type)}</small> : null}{item.duration_ms != null ? <small>{String(item.duration_ms)} ms</small> : null}</td>
                  <td role="cell" data-label="Details"><button className="probe-activity-expand" aria-label={`Details for event ${id}`} aria-expanded={open} onClick={() => setExpanded(open ? null : id)}>{open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}</button></td>
                </tr>
                {open ? <tr role="row" className="probe-activity-detail"><td role="cell" colSpan={5}><p className="probe-activity-description">{describe(item)}</p><dl>{Object.entries(item).filter(([key, value]) => !['id', 'sequence', 'stage'].includes(key) && !(value && typeof value === 'object' && !Object.keys(value).length)).map(([key, value]) => <div key={key} data-payload={key.includes('preview') || undefined}><dt>{key.replaceAll('_', ' ')}</dt><dd>{Array.isArray(value) ? value.join(', ') : value && typeof value === 'object' ? JSON.stringify(value, null, 2) : value === '' ? '(empty)' : String(value ?? 'Not recorded')}</dd></div>)}</dl></td></tr> : null}
              </Fragment>;
            })}
            {!items.length ? <tr><td colSpan={5} className="probe-activity-empty">{search || filter !== 'all' ? 'No recorded events match these filters.' : !runId ? 'Select a check with a run, or start a reviewed check.' : snapshot?.telemetry_recorded === false && !running ? 'This run has only its final recorded summary. Per-request activity was not captured by that worker.' : 'No worker events have arrived yet. Planned requests are not shown as sent.'}</td></tr> : null}
          </tbody>
        </table>
      </div>
      <p className="probe-activity-note">{snapshot?.truncated ? `Showing the latest ${String(snapshot.count)} events. ` : ''}Expand an event for the method, vector, format, status and captured payload. Previews retain up to 2 KiB; credentials and declared private query values are redacted. Non-HTTP checks show their recorded protocol fields.</p>
    </section>
  );
}
