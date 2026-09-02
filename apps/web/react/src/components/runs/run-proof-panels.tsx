import type { DataItem } from '../../lib/types';
import {
  buildVerdictExplanationFields,
  isAuthenticatedAgentObservationEvent,
  isInternalControlPlaneNoObservationEvent,
  isSignedProbeEvidenceEvent,
  normalizeVerdictKey,
  TRUTH_TABLE_ROWS,
} from '../../lib/verdict-explanation';
import { formatDate } from '../../lib/utils';

const VERDICT_TRUTH_ROWS = [
  ...TRUTH_TABLE_ROWS,
  {
    key: 'inconclusive',
    description: 'Missing or partial correlation cannot establish Protected or a confirmed reach verdict.',
  },
];

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

export function TrafficPathPanel({
  detail,
  events = [],
}: {
  detail: DataItem | null;
  events?: DataItem[];
}) {
  const verdict = getNestedString(detail, ['verdict', 'verdict'], '');
  const confidence = getNestedString(detail, ['verdict', 'confidence'], '');
  const signedProbeCount = events.filter(isSignedProbeEvidenceEvent).length;
  const authenticatedObservationCount = events.filter(isAuthenticatedAgentObservationEvent).length;
  const noObservationCount = events.filter(isInternalControlPlaneNoObservationEvent).length;
  const statusLine = verdict
    ? `Stored verdict: ${verdict}${confidence ? ` (${confidence})` : ''}. Evidence states reflect only trusted events passed to this panel.`
    : 'No final verdict is recorded. Evidence states reflect only trusted events passed to this panel.';

  const internalEvidenceLabel = authenticatedObservationCount > 0
    ? `${authenticatedObservationCount} authenticated agent observation${authenticatedObservationCount === 1 ? '' : 's'} recorded`
    : noObservationCount > 0
      ? `${noObservationCount} control-plane no-observation event${noObservationCount === 1 ? '' : 's'} recorded`
      : 'No trusted internal observation recorded';

  return (
    <section className="traffic-path" aria-label="Recorded run evidence">
      <h3>Recorded evidence</h3>
      <div className="traffic-path-track">
        <div className="traffic-path-hop">
          <div className={`traffic-path-node traffic-path-node--${signedProbeCount > 0 ? 'ok' : 'muted'}`}>
            <span className="traffic-path-label text-sm">External probe</span>
            <span className="traffic-path-sub muted text-xs">
              {signedProbeCount > 0
                ? `${signedProbeCount} signed result${signedProbeCount === 1 ? '' : 's'} recorded`
                : 'No signed probe result recorded'}
            </span>
          </div>
        </div>
        <div className="traffic-path-hop">
          <div className={`traffic-path-node traffic-path-node--${authenticatedObservationCount > 0 ? 'ok' : noObservationCount > 0 ? 'warn' : 'muted'}`}>
            <span className="traffic-path-label text-sm">Internal observation</span>
            <span className="traffic-path-sub muted text-xs">{internalEvidenceLabel}</span>
          </div>
        </div>
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
  const verdict = getNestedString(detail, ['verdict', 'verdict'], '');
  if (!verdict) {
    return (
      <section className="verdict-explanation verdict-explanation--pending">
        <h3>{heading}</h3>
        <p className="muted">No final verdict evidence is recorded for this run yet.</p>
      </section>
    );
  }

  const fields = buildVerdictExplanationFields(detail, events, { finding });

  return (
    <section className="verdict-explanation">
      <h3>{heading}</h3>
      <div className="verdict-explanation-grid">
        {fields.map((field) => (
          <ExplanationField key={field.label} label={field.label} value={field.value} />
        ))}
      </div>
    </section>
  );
}

export function TruthTablePanel({ detail }: { detail: DataItem | null }) {
  const current = normalizeVerdictKey(getNestedString(detail, ['verdict', 'verdict'], '').toLowerCase());

  return (
    <section className="truth-table-viz" tabIndex={0} role="region" aria-labelledby="truth-table-heading">
      <h3 id="truth-table-heading">Verdict truth table</h3>
      {!current ? <p className="muted text-sm">No final verdict is recorded; no outcome is selected.</p> : null}
      <table className="truth-table data-table text-sm">
        <caption className="sr-only">Evidence meaning for each supported run verdict</caption>
        <thead>
          <tr>
            <th scope="col">Outcome</th>
            <th scope="col">Evidence meaning</th>
          </tr>
        </thead>
        <tbody>
          {VERDICT_TRUTH_ROWS.map((row) => {
            const isCurrent = current === row.key;
            return (
              <tr key={row.key} className={isCurrent ? 'truth-row truth-row--active' : 'truth-row'} aria-current={isCurrent ? 'true' : undefined}>
                <td>
                  <span className={`truth-outcome truth-outcome--${row.key}`}>{row.key}</span>
                  {isCurrent ? <span className="muted text-xs"> · current</span> : null}
                </td>
                <td>{row.description}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}

export function RunTimelineViz({ events }: { events: DataItem[] }) {
  if (!events.length) {
    return <div className="run-timeline-viz empty muted" role="status">No timeline events are recorded for this run yet.</div>;
  }

  return (
    <div className="run-timeline-viz" role="region" aria-label="Run event timeline">
      <ol className="run-timeline-list">
        {events.map((event, index) => {
          const eventId = getString(event, ['id'], '');
          const signal = getString(event, ['signal_type', 'type'], 'event');
          const source = getString(event, ['source'], '');
          const timestamp = event.timestamp ?? event.created_at;
          return (
            <li key={`${eventId || 'event'}-${index}`}>
              <time dateTime={typeof timestamp === 'string' ? timestamp : undefined}>{formatDate(timestamp)}</time>
              {' · '}{signal}
              {source ? <> · {source}</> : null}
              {eventId ? <> · <code className="mono small">{eventId}</code></> : null}
            </li>
          );
        })}
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
      <TrafficPathPanel detail={detail} events={events} />
      <VerdictExplanationPanel detail={detail} events={events} />
      <TruthTablePanel detail={detail} />
    </div>
  );
}
