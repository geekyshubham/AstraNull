import type { DataItem } from '../../lib/types';
import {
  buildVerdictExplanationFields,
  normalizeVerdictKey,
  trafficHopState,
  TRUTH_TABLE_ROWS,
} from '../../lib/verdict-explanation';
import { formatDate } from '../../lib/utils';

const TRAFFIC_HOPS = [
  { key: 'probe', label: 'External probe', sub: 'sent' },
  { key: 'edge', label: 'CDN / WAF', sub: 'blocked?' },
  { key: 'lb', label: 'Load balancer', sub: 'forwarded?' },
  { key: 'origin', label: 'Origin / agent', sub: 'observed?' },
] as const;

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function isDenseProofValue(value: string) {
  return value.length > 56 || value.includes(',') || value.includes('/');
}

export function ExplanationField({
  label,
  value,
  fullWidth = false,
}: {
  label: string;
  value: string;
  fullWidth?: boolean;
}) {
  const display = value || '—';
  return (
    <div className={`verdict-explanation-item${fullWidth ? ' verdict-explanation-item--full' : ''}`}>
      <span className="verdict-explanation-label">{label}</span>
      {isDenseProofValue(display) ? (
        <pre className="code verdict-explanation-value">{display}</pre>
      ) : (
        <span className="verdict-explanation-value">{display}</span>
      )}
    </div>
  );
}

function getNestedString(item: DataItem | null | undefined, path: string[], fallback = '') {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return fallback;
    current = (current as DataItem)[key];
  }
  if (current !== undefined && current !== null && current !== '') return String(current);
  return fallback;
}

export function TrafficPathPanel({ detail }: { detail: DataItem | null }) {
  const verdict = getNestedString(detail, ['verdict', 'verdict'], '');
  const confidence = getNestedString(detail, ['verdict', 'confidence'], '');
  const statusLine = verdict
    ? `Verdict evidence: ${verdict}${confidence ? ` (${confidence})` : ''}`
    : 'Awaiting correlated probe and agent evidence.';

  return (
    <section className="traffic-path" aria-labelledby="traffic-path-heading">
      <h4 id="traffic-path-heading">Traffic path</h4>
      <div className="traffic-path-track">
        {TRAFFIC_HOPS.map((hop, index) => (
          <span key={hop.key} className="traffic-path-hop">
            {index > 0 ? <span className="traffic-path-arrow" aria-hidden="true">→</span> : null}
            <div className={`traffic-path-node traffic-path-node--${trafficHopState(hop.key, verdict)}`}>
              <span className="traffic-path-label text-sm">{hop.label}</span>
              <span className="traffic-path-sub muted text-xs">{hop.sub}</span>
            </div>
          </span>
        ))}
      </div>
      <p className="muted text-sm traffic-path-caption">{statusLine}</p>
    </section>
  );
}

export function VerdictExplanationPanel({
  detail,
  events,
  finding = null,
  heading = 'Why this verdict?',
}: {
  detail: DataItem | null;
  events: DataItem[];
  finding?: DataItem | null;
  heading?: string;
}) {
  if (!detail?.verdict) {
    return (
      <section className="verdict-explanation verdict-explanation--pending">
        <h4>{heading}</h4>
        <p className="muted">Verdict evidence is still pending for this run.</p>
      </section>
    );
  }

  const fields = buildVerdictExplanationFields(detail, events, { finding });

  return (
    <section className="verdict-explanation">
      <h4>{heading}</h4>
      <div className="verdict-explanation-grid">
        {fields.map((field) => (
          <ExplanationField key={field.label} label={field.label} value={field.value} />
        ))}
      </div>
    </section>
  );
}

export function TruthTablePanel({ detail }: { detail: DataItem | null }) {
  const current = normalizeVerdictKey(getNestedString(detail, ['verdict', 'verdict'], ''));

  return (
    <section className="truth-table-viz" aria-labelledby="truth-table-heading">
      <h4 id="truth-table-heading">Verdict truth table</h4>
      <table className="truth-table data-table text-sm">
        <thead>
          <tr>
            <th>Outcome</th>
            <th>Meaning (evidence-oriented)</th>
          </tr>
        </thead>
        <tbody>
          {TRUTH_TABLE_ROWS.map((row) => (
            <tr key={row.key} className={current === row.key ? 'truth-row truth-row--active' : 'truth-row'}>
              <td><span className={`truth-outcome truth-outcome--${row.key}`}>{row.key}</span></td>
              <td>{row.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

export function RunTimelineViz({ events }: { events: DataItem[] }) {
  if (!events.length) {
    return <div className="run-timeline-viz empty muted">No timeline events yet.</div>;
  }

  const max = events.length - 1;

  return (
    <div className="run-timeline-viz" aria-label="Run event timeline">
      <div className="run-timeline-rail">
        {events.map((event, index) => {
          const pct = max ? (index / max) * 100 : 50;
          const label = `${getString(event, ['signal_type', 'type'], 'event')} · ${formatDate(event.timestamp ?? event.created_at).slice(11, 19) || '—'}`;
          return (
            <div key={getString(event, ['id'], String(index))} className="run-timeline-marker" style={{ left: `${pct}%` }}>
              <span className="run-timeline-dot" />
              <span className="run-timeline-tip text-xs">{label}</span>
            </div>
          );
        })}
      </div>
      <ol className="run-timeline-list">
        {events.map((event, index) => (
          <li key={getString(event, ['id'], String(index))}>
            {formatDate(event.timestamp ?? event.created_at)} · {getString(event, ['signal_type', 'type'], 'event')} · {getString(event, ['source'], '')}
          </li>
        ))}
      </ol>
    </div>
  );
}

export function RunProofPanels({
  detail,
  events,
}: {
  detail: DataItem | null;
  events: DataItem[];
}) {
  if (!detail) return null;

  return (
    <div className="run-proof-panels">
      <TrafficPathPanel detail={detail} />
      <VerdictExplanationPanel detail={detail} events={events} />
      <TruthTablePanel detail={detail} />
    </div>
  );
}