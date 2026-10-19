import { useEffect, useMemo, useRef, useState } from 'react';
import { ArrowDown, ChevronDown, ChevronRight, Copy, Search } from 'lucide-react';
import { Button } from '../ui/button';
import { recordedExchanges, exchangeCopyText, safeCaptureText, safeCaptureUrl, type RecordedExchange } from '../../lib/http-exchanges.mjs';
import { activityValueLabel } from '../../lib/activity-labels.mjs';
import { ExchangeSide } from '../targets/probe-activity';
import type { DataItem } from '../../lib/types';
import './unified-activity-log.css';

export type ActivityMarker = { id: string; at: string; severity: Severity; label: string; detail?: string };
type Severity = 'info' | 'ok' | 'warn' | 'error';

const STAGE_LABEL: Record<string, string> = {
  job_started: 'Worker started', attempt_started: 'Attempt started', request_started: 'Request sent',
  response_received: 'Response received', attempt_failed: 'Request failed', request_not_sent: 'Not sent',
  phase_completed: 'Phase finished', probe_completed: 'Probe finished', result_received: 'Probe result',
  request_payload: 'Request payload captured', response_payload: 'Response captured', response_body_completed: 'Response body read',
};
const FAMILY = { waf: 'WAF', cdn: 'CDN', dns: 'DNS' } as Record<string, string>;

function text(value: unknown) { return typeof value === 'string' ? value : ''; }
function time(value: unknown) {
  const at = new Date(text(value));
  return Number.isNaN(at.getTime()) ? '--:--:--' : at.toLocaleTimeString(undefined, { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
function vectorLabel(value: unknown) { const raw = text(value); return FAMILY[raw] ?? (raw ? activityValueLabel(raw).text : ''); }
function shortUrl(value: unknown) {
  const raw = safeCaptureUrl(value);
  try { const url = new URL(raw); return `${url.hostname}${url.pathname === '/' ? '' : url.pathname}${url.search}`; } catch { return raw; }
}
function eventSeverity(item: DataItem): Severity {
  if (item.stage === 'attempt_failed' || item.error_class) return 'error';
  if (item.stage === 'request_not_sent') return 'warn';
  return 'info';
}
function exchangeSeverity(exchange: RecordedExchange): Severity {
  if (exchange.state === 'failed') return 'error';
  if (exchange.state === 'not_sent' || exchange.conflictFields.length) return 'warn';
  return 'info';
}

type Row =
  | { kind: 'exchange'; id: string; at: string; seq: number; severity: Severity; exchange: RecordedExchange }
  | { kind: 'event'; id: string; at: string; seq: number; severity: Severity; item: DataItem }
  | { kind: 'marker'; id: string; at: string; seq: number; severity: Severity; marker: ActivityMarker };

export function UnifiedActivityLog({
  items, markers = [], active = false, requestsSent, maxRequests, emptyMessage = 'No probe activity recorded yet.', label,
}: {
  items: DataItem[];
  markers?: ActivityMarker[];
  active?: boolean;
  requestsSent?: number | null;
  maxRequests?: number | null;
  emptyMessage?: string;
  label?: string;
}) {
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<'all' | 'requests' | 'issues'>('all');
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [follow, setFollow] = useState(true);
  const [copied, setCopied] = useState('');
  const viewportRef = useRef<HTMLDivElement | null>(null);

  const rows = useMemo<Row[]>(() => {
    const list = Array.isArray(items) ? items : [];
    const { exchanges, lifecycle } = recordedExchanges(list);
    const out: Row[] = [];
    for (const exchange of exchanges) {
      const first = exchange.events[0] ?? {};
      out.push({ kind: 'exchange', id: exchange.id, at: text(first.at), seq: Number(first.sequence) || 0, severity: exchangeSeverity(exchange), exchange });
    }
    for (const item of lifecycle) {
      if (!STAGE_LABEL[text(item.stage)] && item.source !== 'simulation' && item.source !== 'scan_state') continue;
      out.push({ kind: 'event', id: text(item.id), at: text(item.at), seq: Number(item.sequence) || 0, severity: eventSeverity(item), item });
    }
    for (const marker of markers) out.push({ kind: 'marker', id: marker.id, at: marker.at, seq: -1, severity: marker.severity, marker });
    return out.sort((a, b) => a.at.localeCompare(b.at) || a.seq - b.seq);
  }, [items, markers]);

  const matches = (row: Row) => {
    if (filter === 'issues' && row.severity !== 'warn' && row.severity !== 'error') return false;
    if (filter === 'requests' && row.kind !== 'exchange') return false;
    if (!search.trim()) return true;
    const q = search.trim().toLowerCase();
    const summary = rowSummary(row);
    return `${summary.lead} ${summary.detail}`.toLowerCase().includes(q);
  };
  const visible = rows.filter(matches);

  useEffect(() => {
    if (!follow) return;
    const el = viewportRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [visible.length, follow]);

  function toggle(id: string) {
    setExpanded((prev) => { const next = new Set(prev); if (next.has(id)) next.delete(id); else next.add(id); return next; });
  }
  async function copyRow(exchange: RecordedExchange) {
    try { await navigator.clipboard.writeText(exchangeCopyText(exchange)); setCopied(exchange.id); setTimeout(() => setCopied(''), 1500); }
    catch { setCopied(''); }
  }

  return (
    <div className="ual" data-active={active || undefined} role="region" aria-label={label ? `Probe activity for ${label}` : 'Probe activity'}>
      <div className="ual-tools">
        <label className="ual-search"><Search size={14} aria-hidden="true" /><span className="sr-only">Search activity</span>
          <input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search requests and responses" /></label>
        <div className="ual-filters" role="group" aria-label="Filter activity">
          {([['all', 'All'], ['requests', 'Requests'], ['issues', 'Issues']] as const).map(([id, text]) => (
            <button key={id} type="button" className="ual-filter" aria-pressed={filter === id} onClick={() => setFilter(id)}>{text}</button>
          ))}
        </div>
        <Button size="sm" variant="ghost" className={follow ? 'ual-follow-on' : ''} aria-pressed={follow} onClick={() => setFollow((value) => !value)}>
          <ArrowDown size={13} aria-hidden="true" />{follow ? 'Following' : 'Follow'}
        </Button>
      </div>
      <div className="ual-meta" role="status" aria-live="polite">
        <span>{active ? <span className="ual-live"><span className="ual-beacon" aria-hidden="true" />Live</span> : `${rows.length} ${rows.length === 1 ? 'event' : 'events'}`}</span>
        {requestsSent != null ? <span className="tabular-nums">{requestsSent} operations{maxRequests ? ` · limit ${maxRequests}` : ''}</span> : null}
      </div>
      <div ref={viewportRef} className="ual-stream" tabIndex={0} role="log" aria-live="polite"
        onScroll={(event) => { const el = event.currentTarget; const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight <= 24; if (atBottom !== follow) setFollow(atBottom); }}>
        {visible.length === 0 ? <p className="ual-empty">{search || filter !== 'all' ? 'No activity matches this filter.' : emptyMessage}</p> : (
          <ol className="ual-rows">
            {visible.map((row) => {
              const open = expanded.has(row.id);
              const summary = rowSummary(row);
              const expandable = row.kind !== 'marker';
              return (
                <li key={row.id} className="ual-row" data-severity={row.severity} data-open={open || undefined}>
                  <button type="button" className="ual-line" aria-expanded={expandable ? open : undefined} disabled={!expandable} onClick={() => expandable && toggle(row.id)}>
                    <span className="ual-dot" aria-hidden="true" />
                    <time className="ual-time" dateTime={row.at}>{time(row.at)}</time>
                    <span className="ual-lead">{summary.lead}</span>
                    <span className="ual-detail">{summary.detail}</span>
                    {expandable ? (open ? <ChevronDown size={15} aria-hidden="true" /> : <ChevronRight size={15} aria-hidden="true" />) : <span className="ual-chevron-space" aria-hidden="true" />}
                  </button>
                  {open && row.kind === 'exchange' ? (
                    <div className="ual-open probe-exchange-open">
                      {row.exchange.failure ? <p className="probe-exchange-failure">Not completed: {safeCaptureText(row.exchange.failure.error_class || row.exchange.failure.reason) || 'reason not recorded'}.</p> : null}
                      <div className="probe-exchange-pair"><ExchangeSide side="request" item={row.exchange.request} exchange={row.exchange} /><ExchangeSide side="response" item={row.exchange.response} exchange={row.exchange} /></div>
                      <footer className="ual-open-foot"><Button size="sm" variant="ghost" onClick={() => void copyRow(row.exchange)}><Copy size={13} aria-hidden="true" />{copied === row.exchange.id ? 'Copied' : 'Copy'}</Button></footer>
                    </div>
                  ) : null}
                  {open && row.kind === 'event' ? (
                    <div className="ual-open"><dl className="ual-facts">
                      {Object.entries(row.item).filter(([key, value]) => !['id', 'sequence', 'stage', 'source', 'capture_version'].includes(key) && value != null && value !== '' && !(typeof value === 'object' && !Object.keys(value as object).length)).map(([key, value]) => (
                        <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{safeCaptureText(value && typeof value === 'object' ? JSON.stringify(value) : value)}</dd></div>
                      ))}
                    </dl></div>
                  ) : null}
                </li>
              );
            })}
          </ol>
        )}
      </div>
    </div>
  );
}

function rowSummary(row: Row): { lead: string; detail: string } {
  if (row.kind === 'marker') return { lead: row.marker.label, detail: row.marker.detail ?? '' };
  if (row.kind === 'exchange') {
    const ex = row.exchange;
    const head = ex.request ?? ex.response ?? ex.events[0] ?? {};
    const method = text(head.method) || 'Request';
    const status = ex.response?.status_code != null ? `HTTP ${ex.response.status_code}`
      : ex.failure ? (ex.failure.stage === 'request_not_sent' ? 'not sent' : 'failed') : 'no response';
    const duration = ex.response?.duration_ms ?? ex.request?.duration_ms;
    const vector = vectorLabel(head.vector_family);
    const detail = [status, duration != null ? `${duration} ms` : '', vector].filter(Boolean).join(' · ');
    return { lead: `${method} ${shortUrl(head.url)}`, detail };
  }
  const item = row.item;
  const lead = STAGE_LABEL[text(item.stage)] ?? (item.source === 'simulation' ? 'Simulation result' : activityValueLabel(item.stage).text || 'Event');
  const detail = [
    text(item.method) || (item.operation ? activityValueLabel(item.operation).text : ''),
    item.status_code != null ? `HTTP ${item.status_code}` : '',
    text(item.error_class) || (item.reason ? activityValueLabel(item.reason).text : ''),
    item.duration_ms != null ? `${item.duration_ms} ms` : '',
    vectorLabel(item.vector_family),
  ].filter(Boolean).join(' · ');
  return { lead, detail };
}
