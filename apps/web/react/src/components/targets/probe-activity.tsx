import { Fragment, useEffect, useId, useMemo, useState } from 'react';
import { ArrowRight, ChevronDown, ChevronRight, Copy, Pause, Play, Search, Square } from 'lucide-react';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { sessionIdentity } from '../../lib/api';
import { activityIsLive, captureWarnings, stopStateLabel, type RecordedActivityState } from '../../lib/recorded-activity.mjs';
import { activityRequestLimitLabel, activityRequestsSentLabel, activityValueLabel } from '../../lib/activity-labels.mjs';
import { captureHeaders, exchangeCopyText, recordedExchanges, safeCaptureText, safeCaptureUrl, type RecordedExchange } from '../../lib/http-exchanges.mjs';
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
  request_payload: 'Request payload captured', response_payload: 'Payload captured', response_body_completed: 'Response body read',
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
  if (item.stage === 'response_payload' || item.stage === 'response_body_completed') return `The worker ${item.stage === 'response_body_completed' ? 'finished reading the bounded response body' : 'captured response bytes while reading the body'}.${identity} ${item.response_content_type ? `Format: ${text(item.response_content_type)}. ` : ''}${item.response_bytes_observed != null ? `${String(item.response_bytes_observed)} bytes observed. ` : ''}${item.response_payload_truncated ? 'The preview is partial.' : 'The recorded payload is shown below.'}`;
  if (item.stage === 'request_not_sent') return `This operation was not sent.${identity} Recorded reason: ${valueText(item.reason) || 'not recorded'}.`;
  if (item.stage === 'attempt_failed') return `The attempted operation failed.${identity} Recorded error: ${text(item.error_class) || 'not recorded'}.`;
  return `${stageLabel(item)}.${identity} The fields below are the recorded facts for this event.`;
}

export function CaptureBlock({ label, value, empty = 'Empty recorded value' }: { label: string; value: unknown; empty?: string }) {
  return <div className="probe-exchange-field"><h5>{label}</h5>{value == null ? <p className="probe-exchange-missing">Not recorded by worker</p> : <pre>{safeCaptureText(value) || empty}</pre>}</div>;
}

export function ExchangeSide({ side, item, exchange }: { side: 'request' | 'response'; item: DataItem | null; exchange: RecordedExchange }) {
  const headers = captureHeaders(item?.[`${side}_headers`]);
  const title = side === 'request' ? 'Request' : 'Response';
  const available = item?.[`${side}_payload_available`];
  const partial = item?.[`${side}_payload_truncated`] === true;
  const preview = item?.[`${side}_payload_preview`];
  const encoding = text(item?.[`${side}_payload_encoding`]);
  return <section className="probe-exchange-side" aria-label={`${title} capture`}>
    <h4>{title}</h4>
    {!item ? <p className="probe-exchange-missing">{exchange.conflictFields.some((field) => field.startsWith(`${side}.`) || field.startsWith('exchange.')) ? 'Conflicting worker records. This capture is withheld; no merged counterpart is inferred.' : side === 'response' && exchange.failure ? 'No response recorded. The operation failed or was not sent.' : 'Not recorded by worker. No counterpart is inferred.'}</p> : <>
      <p className="probe-exchange-startline"><strong>{side === 'request' ? text(item.method) || 'Method not recorded' : item.status_code != null ? `HTTP ${String(item.status_code)}` : 'Status not recorded'}</strong>{item.url ? <code>{safeCaptureUrl(item.url)}</code> : null}</p>
      <dl className="probe-exchange-facts">
        <div><dt>Protocol</dt><dd>{text(item.http_version) || text(item.protocol) || 'Not recorded'}</dd></div>
        <div><dt>Content type</dt><dd>{safeCaptureText(item[`${side}_content_type`]) || 'Not recorded'}</dd></div>
        {item.duration_ms != null ? <div><dt>Duration</dt><dd>{String(item.duration_ms)} ms</dd></div> : null}
      </dl>
      <div className="probe-exchange-field"><h5>Headers <span>Recorded values</span></h5>{headers === null ? <p className="probe-exchange-missing">Not recorded by worker{Array.isArray(item.header_names) ? `; header names only: ${item.header_names.map(safeCaptureText).join(', ')}` : ''}</p> : headers.length ? <dl className="probe-exchange-headers">{headers.map((header, index) => <div key={`${header.name}-${index}`}><dt>{header.name}</dt><dd>{header.value || '(empty value)'}</dd></div>)}</dl> : <p className="probe-exchange-missing">Empty recorded header set. This does not imply no headers were sent.</p>}</div>
      {side === 'request' ? <CaptureBlock label="Query parameters" value={item.request_query_preview} empty="Empty recorded query" /> : null}
      <div className="probe-exchange-field"><h5>Body <span>{partial ? 'Partial capture' : preview != null ? encoding === 'base64' ? 'Base64' : 'Recorded payload' : 'Not recorded'}</span></h5>
        {available === false ? <p className="probe-exchange-missing">Not consumed by this check; no response body is inferred.</p> : preview == null ? <p className="probe-exchange-missing">Not recorded by worker{side === 'response' && !exchange.bodyComplete ? '; body completion was not recorded' : ''}.</p> : <pre>{safeCaptureText(preview) || 'Empty recorded body'}</pre>}
        {item[`${side}_bytes_observed`] != null ? <p className="probe-exchange-missing">{String(item[`${side}_bytes_observed`])} bytes observed{item[`${side}_bytes_captured`] != null ? `; ${String(item[`${side}_bytes_captured`])} bytes captured` : ''}.</p> : null}
      </div>
    </>}
  </section>;
}

function ExchangeInspector({ exchange, open, onToggle }: { exchange: RecordedExchange; open: boolean; onToggle: () => void }) {
  const [copyState, setCopyState] = useState('');
  const heading = exchange.request ?? exchange.response ?? exchange.events[0];
  const stateLabel = exchange.conflictFields.length ? 'Capture conflict' : { captured: 'Recorded exchange', partial: 'Partial capture', failed: 'Operation failed', not_sent: 'Not sent' }[exchange.state];
  async function copy() {
    try { await navigator.clipboard.writeText(exchangeCopyText(exchange)); setCopyState('Exchange copied'); }
    catch { setCopyState('Copy unavailable. Select the visible text instead.'); }
  }
  return <article className="probe-exchange" data-state={exchange.state}>
    <button type="button" className="probe-exchange-summary" aria-expanded={open} onClick={onToggle}>
      <span className="probe-exchange-method">{text(heading.method) || text(heading.operation) || 'Recorded operation'}</span>
      <span className="probe-exchange-endpoint">{safeCaptureUrl(heading.url) || 'Endpoint not recorded'}<small>{text(heading.phase) || 'Phase not recorded'} · {text(heading.http_version) || text(heading.protocol) || 'Protocol not recorded'}</small></span>
      <ArrowRight size={14} aria-hidden="true" />
      <span>{exchange.response?.status_code != null ? `HTTP ${String(exchange.response.status_code)}` : exchange.failure ? 'No response recorded' : 'Response not recorded'}</span>
      <Badge tone={exchange.state === 'failed' ? 'warn' : 'muted'}>{stateLabel}</Badge>
      {open ? <ChevronDown size={16} aria-hidden="true" /> : <ChevronRight size={16} aria-hidden="true" />}
    </button>
    {open ? <div className="probe-exchange-open">
      <div className="probe-exchange-meta"><span>Exchange <code>{exchange.exchangeId}</code></span><span>Attempt <code>{text(heading.attempt_id) || 'Not recorded'}</code></span><span>Operation <code>{text(heading.operation_id) || 'Not recorded'}</code></span><time dateTime={text(heading.at)}>{time(heading.at)}</time></div>
      {exchange.conflictFields.length ? <p className="probe-exchange-failure">Capture conflict: {exchange.conflictFields.join(', ')}. Conflicting capture withheld, not a protection verdict.</p> : null}
      {exchange.failure ? <p className="probe-exchange-failure">{stateLabel}: {safeCaptureText(exchange.failure.error_class || exchange.failure.reason) || 'Reason not recorded'}. Failure is not proof of blocking.</p> : null}
      <div className="probe-exchange-pair"><ExchangeSide side="request" item={exchange.request} exchange={exchange} /><ExchangeSide side="response" item={exchange.response} exchange={exchange} /></div>
      <footer className="probe-exchange-footer"><span>Job <code>{text(exchange.source.job_id)}</code> · lease <code>{text(exchange.source.leased_at)}</code></span><Button size="sm" variant="ghost" onClick={() => void copy()}><Copy size={14} aria-hidden="true" />Copy exchange</Button><span role="status">{copyState}</span></footer>
    </div> : null}
  </article>;
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
  const [expandedExchange, setExpandedExchange] = useState<string | null>(null);
  useEffect(() => { setExpanded(null); setExpandedExchange(null); }, [runId]);
  const recordedItems = useMemo(() => Array.isArray(snapshot?.items) ? snapshot.items as DataItem[] : notSent ? [{ id: 'scan-decision', stage: 'request_not_sent', source: 'scan_state', reason: notSent.reason, at: notSent.at } as DataItem] : [], [snapshot, notSent]);
  const grouped = useMemo(() => recordedExchanges(recordedItems), [recordedItems]);
  const matches = (item: DataItem) => (filter === 'all' || severity(item) === filter)
    && (!search.trim() || [item.exchange_id, item.operation, item.method, item.url, item.stage, item.status_code, item.error_class, item.reason, item.vector_family, item.marker_class, item.phase, item.request_content_type, item.response_content_type].join(' ').toLowerCase().includes(search.trim().toLowerCase()));
  // Filter whole exchanges, never remove one half before correlation.
  const exchanges = grouped.exchanges.filter((exchange) => exchange.events.some(matches)).slice().reverse();
  const items = grouped.lifecycle.filter(matches).slice().reverse();
  const accounting = snapshot?.accounting as DataItem | null;
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
        <span>{snapshot ? `${exchanges.length} ${exchanges.length === 1 ? 'exchange' : 'exchanges'} · ${items.length} lifecycle events shown · ${recordedItems.length} recorded events retained` : notSent ? 'Recorded execution decision · no request dispatched' : runId ? 'Waiting for recorded worker activity' : 'No check selected'}</span>
        <span>{paused ? 'Updates paused; execution continues' : error ? 'Disconnected · recorded view may be stale' : running ? 'Live updates · every 2.5s' : valueText(snapshot?.status) || 'No execution recorded'}</span>
        <span>{activityRequestsSentLabel(accounting?.total_operations ?? snapshot?.requests_sent)}</span>
        {accounting ? <><span>Probe logical attempts: {accounting.probe_logical_attempts == null ? 'not recorded' : String(accounting.probe_logical_attempts)}</span><span>Destination-vetting resolver attempts: {accounting.destination_vetting_resolver_attempts == null ? 'not recorded' : String(accounting.destination_vetting_resolver_attempts)}</span></> : null}
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
      <div className="probe-exchanges" role="region" aria-label="Correlated request and response exchanges">
        {exchanges.length || search || filter !== 'all' ? <><h3>Request / Response</h3><p className="probe-exchange-intro">Inspect the recorded request and response together. Sensitive values are hidden; older logs may not include all details.</p></> : null}
        {exchanges.map((exchange, index) => <ExchangeInspector key={exchange.id} exchange={exchange} open={expandedExchange === exchange.id || expandedExchange === null && index === 0} onToggle={() => setExpandedExchange(expandedExchange === exchange.id || expandedExchange === null && index === 0 ? '' : exchange.id)} />)}
        {!exchanges.length ? <p className="probe-exchange-empty">{search || filter !== 'all' ? 'No recorded exchanges match these filters.' : !runId ? 'Select a check to inspect its recorded exchange.' : grouped.lifecycle.length ? 'Correlated exchange capture was not recorded by this worker. Legacy lifecycle events remain available below and are not paired.' : running ? 'Waiting for worker-recorded exchanges. Planned requests are not shown as sent.' : 'No exchange capture recorded. A final summary does not reconstruct requests or responses.'}</p> : null}
      </div>
      <details className="probe-activity-technical" open={grouped.exchanges.length === 0}><summary>Technical lifecycle events ({grouped.lifecycle.length})</summary>
      <div className="probe-activity-scroll" role="region" aria-label="Recorded request and response activity" tabIndex={0}>
        <table className="probe-activity-table" role="table">
          <caption className="sr-only">Worker-recorded activity for {checkName || 'the selected check'}, including methods, vectors, response formats, headers, query values and payloads.</caption>
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
                  <td role="cell" data-label="Request"><span className="probe-activity-operation">{text(item.method) || (item.operation ? <ActivityValue value={item.operation} /> : 'Not recorded')}</span>{item.url ? <code>{safeCaptureUrl(item.url)}</code> : null}<small>{vectorParts(item).map((value, index) => <Fragment key={`${String(value)}-${index}`}>{index ? ' · ' : ''}<ActivityValue value={value} /></Fragment>)}</small></td>
                  <td role="cell" data-label="Response">{item.stage === 'result_received' && running ? <><span>Probe response: {valueText(item.outcome) || (item.status_code != null ? `HTTP ${String(item.status_code)}` : 'not recorded')}</span><small>Not a verdict · correlating</small></> : item.status_code != null ? <strong>HTTP {String(item.status_code)}</strong> : text(item.error_class) || valueText(item.outcome) || valueText(item.reason) || 'Not recorded'}{item.response_content_type ? <small>{text(item.response_content_type)}</small> : null}{item.duration_ms != null ? <small>{String(item.duration_ms)} ms</small> : null}</td>
                  <td role="cell" data-label="Details"><button className="probe-activity-expand" aria-label={`Details for event ${id}`} aria-expanded={open} onClick={() => setExpanded(open ? null : id)}>{open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}</button></td>
                </tr>
                {open ? <tr role="row" className="probe-activity-detail"><td role="cell" colSpan={5}><p className="probe-activity-description">{describe(item)}</p><dl>{Object.entries(item).filter(([key, value]) => !['id', 'sequence', 'stage'].includes(key) && !(value && typeof value === 'object' && !Object.keys(value).length)).map(([key, value]) => <div key={key} data-payload={key.includes('preview') || undefined}><dt>{key.replaceAll('_', ' ')}</dt><dd>{value === '' ? '(empty)' : safeCaptureText(value && typeof value === 'object' ? JSON.stringify(value, null, 2) : value ?? 'Not recorded')}</dd></div>)}</dl></td></tr> : null}
              </Fragment>;
            })}
            {!items.length ? <tr><td colSpan={5} className="probe-activity-empty">{search || filter !== 'all' ? 'No recorded events match these filters.' : !runId ? 'Select a check with a run, or start a reviewed check.' : snapshot?.telemetry_recorded === false && !running ? 'This run has only its final recorded summary. Per-request activity was not captured by that worker.' : 'No worker events have arrived yet. Planned requests are not shown as sent.'}</td></tr> : null}
          </tbody>
        </table>
      </div>
      </details>
      <details className="probe-activity-authority probe-activity-about"><summary>About recorded activity</summary><p>Expand an exchange or event for the recorded method, endpoint, protocol, vector, status, headers, query values and payload. Capture retains up to 1 MiB of bytes consumed by the check and marks missing or partial data. Older runs may contain values redacted before storage; rerun the check to record new values. Missing port, SNI, address family or source perspective remain not recorded. Informational activity never substitutes for verdict evidence or internal-origin visibility.</p></details>
    </section>
  );
}
