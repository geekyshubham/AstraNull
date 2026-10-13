import { Fragment, useEffect, useId, useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, Pause, Play, Search, Square } from 'lucide-react';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { sessionIdentity } from '../../lib/api';
import { activityIsLive, captureWarnings, stopStateLabel, type RecordedActivityState } from '../../lib/recorded-activity.mjs';
import { activityRequestLimitLabel, activityRequestsSentLabel, activityValueLabel } from '../../lib/activity-labels.mjs';
import { useRecordedActivity } from '../evidence/use-recorded-activity';
import { apiErrorMessage } from '../../lib/error-messages';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import './probe-activity.css';

const LABELS: Record<string, string> = {
  job_started: 'Worker started', attempt_started: 'Attempt started', request_started: 'Request started',
  response_received: 'Response received', attempt_failed: 'Request failed', request_not_sent: 'Not sent',
  probe_completed: 'Probe finished', result_received: 'Probe result received',
  run_started: 'Run started', run_stopped: 'Cancellation recorded',
  run_created: 'Run created',
  phase_completed: 'Phase finished',
  response_payload: 'Payload captured', response_body_completed: 'Response body read',
};
function text(value: unknown) { return typeof value === 'string' ? value : ''; }
function time(value: unknown) {
  const at = new Date(text(value));
  return Number.isNaN(at.getTime()) ? 'Not recorded' : at.toLocaleTimeString(undefined, { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 });
}
function valueText(value: unknown) { return activityValueLabel(value).text; }
function ActivityValue({ value }: { value: unknown }) {
  const label = activityValueLabel(value);
  return label.code ? <span className="mono">{label.text}</span> : <>{label.text}</>;
}
function vectorParts(item: DataItem) { return [item.vector_family, item.marker_class, item.phase].filter(Boolean); }
function stageLabel(item: DataItem) { return LABELS[text(item.stage)] ?? valueText(item.stage); }
function severity(item: DataItem) {
  if (item.stage === 'attempt_failed' || item.error_class) return 'error';
  if (item.stage === 'request_not_sent') return 'warning';
  return 'info';
}

function describe(item: DataItem) {
  const vector = vectorParts(item).map(valueText).join(' / ');
  const identity = vector ? ` Vector: ${vector}.` : '';
  if (item.stage === 'request_started') return `The worker started ${text(item.method) || 'a protocol request'}${item.url ? ` to ${text(item.url)}` : ''}.${identity} ${item.body_bytes != null ? `The request body contained ${String(item.body_bytes)} bytes. ` : ''}The captured query and payload preview are listed below.`;
  if (item.stage === 'response_received') return `The target returned ${item.status_code != null ? `HTTP ${String(item.status_code)}` : 'a response with no recorded HTTP status'}.${identity} ${item.response_content_type ? `Recorded format: ${text(item.response_content_type)}. ` : 'The response format was not recorded. '}${item.duration_ms != null ? `Observed request duration: ${String(item.duration_ms)} ms.` : ''}`;
  if (item.response_payload_available === false) return `This check used the recorded response headers and did not consume the response body.${identity} The HTTP status and declared format remain visible; no response payload is invented.`;
  if (item.stage === 'response_payload' || item.stage === 'response_body_completed') return `The worker ${item.stage === 'response_body_completed' ? 'finished reading the bounded response body' : 'captured response bytes while reading the body'}.${identity} ${item.response_content_type ? `Format: ${text(item.response_content_type)}. ` : ''}${item.response_bytes_observed != null ? `${String(item.response_bytes_observed)} bytes observed. ` : ''}${item.response_payload_truncated ? 'The preview is partial.' : 'The captured preview is shown below with sensitive values redacted.'}`;
  if (item.stage === 'request_not_sent') return `This operation was not sent.${identity} Recorded reason: ${valueText(item.reason) || 'not recorded'}.`;
  if (item.stage === 'attempt_failed') return `The attempted operation failed.${identity} Recorded error: ${text(item.error_class) || 'not recorded'}.`;
  return `${stageLabel(item)}.${identity} The fields below are the recorded facts for this event.`;
}

type ActivityProps = {
  runId: string; checkName: string; running: boolean; canStop: boolean; onStop: () => void;
  onFollowActive?: () => void; notSent?: { reason: string; at: string } | null;
  maxRequests?: number | null; titleId?: string;
};

export function ProbeActivity({ config, session, ...props }: ActivityProps & { config: PortalConfig; session: Session }) {
  const [paused, setPaused] = useState(false);
  const scope = sessionIdentity(session);
  useEffect(() => { setPaused(false); }, [scope, props.runId]);
  const activity = useRecordedActivity({ config, session, id: props.runId, paused });
  return <ProbeActivityView {...props} activity={activity} paused={paused} onPause={() => setPaused((value) => !value)} titleId={props.titleId || 'probe-activity-title'} />;
}

/** Table and Inspector present the same retained, authenticated activity stream. */
export function ProbeActivityView({ runId, checkName, running: fallbackRunning, canStop, onStop, onFollowActive, notSent, maxRequests, titleId, activity, paused, onPause }: ActivityProps & {
  activity: RecordedActivityState & { refresh: () => void }; paused: boolean; onPause: () => void;
}) {
  const generatedId = useId();
  const headingId = titleId || `activity-${generatedId}`;
  const { snapshot, error, lastUpdated, updating } = activity;
  const accessDenied = [401, 403, 404].includes(Number((error as { status?: number } | null)?.status));
  const running = !accessDenied && (snapshot ? activityIsLive(snapshot) : fallbackRunning);
  const warnings = captureWarnings(snapshot);
  const stopLabel = stopStateLabel(snapshot?.stop);
  const stopPending = stopLabel !== '';
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('all');
  const [expanded, setExpanded] = useState<string | null>(null);
  useEffect(() => { setExpanded(null); }, [runId]);
  const items = useMemo(() => (Array.isArray(snapshot?.items) ? snapshot.items as DataItem[] : notSent ? [{ id: 'scan-decision', stage: 'request_not_sent', source: 'scan_state', reason: notSent.reason, at: notSent.at } as DataItem] : [])
    .filter((item) => filter === 'all' || severity(item) === filter)
    .filter((item) => !search.trim() || [item.operation, item.method, item.url, item.stage, item.status_code, item.error_class, item.reason, item.vector_family, item.marker_class, item.phase, item.request_content_type, item.response_content_type].join(' ').toLowerCase().includes(search.trim().toLowerCase()))
    .slice().reverse(), [snapshot, filter, search, notSent]);
  return (
    <section className="probe-activity" aria-labelledby={headingId}>
      <header className="probe-activity-head">
        <div><h2 id={headingId}>Execution activity</h2><p>{checkName || 'Choose a recorded check to inspect its activity.'}</p>{runId ? <code className="probe-activity-run">{runId}</code> : null}</div>
        <div className="probe-activity-actions">
          {onFollowActive ? <Button size="sm" variant="ghost" onClick={onFollowActive}>Follow active check</Button> : null}
          {canStop && running && !stopPending ? <Button size="sm" variant="danger" onClick={onStop}><Square size={13} aria-hidden="true" />Stop check</Button> : null}
        </div>
      </header>
      <div className="probe-activity-tools">
        <label className="probe-activity-search"><Search size={15} aria-hidden="true" /><span className="sr-only">Search execution activity</span><input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search requests and responses" /></label>
        <label><span className="sr-only">Activity severity</span><select aria-label="Activity severity" value={filter} onChange={(event) => setFilter(event.target.value)}><option value="all">All events</option><option value="info">Info</option><option value="warning">Not sent</option><option value="error">Errors</option></select></label>
        <Button size="sm" variant="ghost" disabled={!runId} onClick={onPause}>{paused ? <Play size={14} aria-hidden="true" /> : <Pause size={14} aria-hidden="true" />}{paused ? 'Resume updates' : 'Pause updates'}</Button>
      </div>
      <div className="probe-activity-status" role="status" aria-live="polite">
        <span>{snapshot ? `${items.length} shown · ${Array.isArray(snapshot.items) ? snapshot.items.length : 0} recorded events retained` : notSent ? 'Recorded execution decision · no request dispatched' : runId ? 'Waiting for recorded worker activity' : 'No check selected'}</span>
        <span>{paused ? 'Updates paused; execution continues' : error ? 'Disconnected · recorded view may be stale' : running ? 'Live updates · every 2.5s' : valueText(snapshot?.status) || 'No execution recorded'}</span>
        <span>{activityRequestsSentLabel(snapshot?.requests_sent)}</span>
        {activityRequestLimitLabel(maxRequests) ? <span>{activityRequestLimitLabel(maxRequests)}</span> : null}
        <span>{lastUpdated ? <>Last successful update <time dateTime={lastUpdated} title={lastUpdated}>{time(lastUpdated)}</time>{updating && !paused ? ' · refreshing' : ''}</> : 'No successful update yet'}</span>
      </div>
      {stopLabel ? <p className="probe-activity-note" role="status">{stopLabel}. Database cancellation is not proof that the worker stopped.</p> : ['cancelled', 'canceled'].includes(text(snapshot?.status)) ? <p className="probe-activity-note">Cancellation recorded; worker acknowledgment was not recorded. An in-flight bounded request may have finished.</p> : null}
      {error ? <p className="probe-activity-error" role="alert">{apiErrorMessage(error, 'Activity could not refresh. Previous recorded events remain visible.')} <Button size="sm" variant="ghost" disabled={paused} onClick={activity.refresh}>Reconnect</Button></p> : null}
      {runId && warnings.length ? <ul className="probe-activity-warnings" aria-label="Capture limitations">{warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul> : null}
      {snapshot ? <details className="probe-activity-authority"><summary>Recorded source and authorization bounds</summary><dl>
        {['worker_id', 'job_id', 'leased_at'].map((key) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{text((snapshot.source_context as DataItem | null)?.[key]) || 'Not recorded'}</dd></div>)}
        {['max_probe_requests', 'max_destination_resolver_attempts', 'max_total_operations', 'timeout_ms', 'not_after', 'authority_version'].map((key) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{(snapshot.authorized_bounds as DataItem | null)?.[key] != null ? String((snapshot.authorized_bounds as DataItem)[key]) : 'Not recorded'}</dd></div>)}
      </dl><p>These are signed authorization limits, not observed requests or duration. Worker identity is not a verified geographic or network perspective. Port, SNI and address family are shown only when an event recorded them.</p></details> : null}
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
                  <td role="cell" data-label="Event"><Badge tone={level === 'error' ? 'danger' : level === 'warning' ? 'warn' : 'default'}>{stageLabel(item)}</Badge>{item.source === 'simulation' ? <small>Simulation · no target traffic</small> : null}</td>
                  <td role="cell" data-label="Time"><time dateTime={text(item.at)} title={text(item.at)}>{time(item.at)}</time></td>
                  <td role="cell" data-label="Request"><span className="probe-activity-operation">{text(item.method) || (item.operation ? <ActivityValue value={item.operation} /> : 'Not recorded')}</span>{item.url ? <code>{text(item.url)}</code> : null}<small>{vectorParts(item).map((value, index) => <Fragment key={`${String(value)}-${index}`}>{index ? ' · ' : ''}<ActivityValue value={value} /></Fragment>)}</small></td>
                  <td role="cell" data-label="Response">{item.stage === 'result_received' && running ? <><span>Probe response: {valueText(item.outcome) || (item.status_code != null ? `HTTP ${String(item.status_code)}` : 'not recorded')}</span><small>Not a verdict · correlating</small></> : item.status_code != null ? <strong>HTTP {String(item.status_code)}</strong> : text(item.error_class) || valueText(item.outcome) || valueText(item.reason) || '—'}{item.response_content_type ? <small>{text(item.response_content_type)}</small> : null}{item.duration_ms != null ? <small>{String(item.duration_ms)} ms</small> : null}</td>
                  <td role="cell" data-label="Details"><button className="probe-activity-expand" aria-label={`Details for event ${id}`} aria-expanded={open} onClick={() => setExpanded(open ? null : id)}>{open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}</button></td>
                </tr>
                {open ? <tr role="row" className="probe-activity-detail"><td role="cell" colSpan={5}><p className="probe-activity-description">{describe(item)}</p><dl>{Object.entries(item).filter(([key, value]) => !['id', 'sequence', 'stage'].includes(key) && !(value && typeof value === 'object' && !Object.keys(value).length)).map(([key, value]) => <div key={key} data-payload={key.includes('preview') || undefined}><dt>{key.replaceAll('_', ' ')}</dt><dd>{Array.isArray(value) ? value.join(', ') : value && typeof value === 'object' ? JSON.stringify(value, null, 2) : value === '' ? '(empty)' : String(value ?? 'Not recorded')}</dd></div>)}</dl></td></tr> : null}
              </Fragment>;
            })}
            {!items.length ? <tr><td colSpan={5} className="probe-activity-empty">{search || filter !== 'all' ? 'No recorded events match these filters.' : !runId ? 'Select a check with a run, or start a reviewed check.' : snapshot?.telemetry_recorded === false && !running ? 'This run has only its final recorded summary. Per-request activity was not captured by that worker.' : 'No worker events have arrived yet. Planned requests are not shown as sent.'}</td></tr> : null}
          </tbody>
        </table>
      </div>
      <p className="probe-activity-note">Expand an event for the recorded method, endpoint, protocol, vector, status and bounded payload. Previews retain up to 2 KiB and may be partial; credentials and declared private query values are redacted. Missing port, SNI, address family or source perspective remain not recorded. Informational activity never substitutes for verdict evidence or internal-origin visibility.</p>
    </section>
  );
}
