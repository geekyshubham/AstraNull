import { buildConicGradient, POSTURE_SEGMENT_COLORS, resolveReadinessPostureSegments } from '../../lib/readiness-posture';
import type { DataItem, ReadinessPostureSegment, StatePayload } from '../../lib/types';
import { countLabel } from '../../lib/utils';
import { EmptyState } from '../ui/empty-state';
import { Activity } from 'lucide-react';
import './readiness-posture-donut.css';

const SEGMENT_COLORS = POSTURE_SEGMENT_COLORS;
const RESULT_KEYS = new Set(['pass', 'review', 'gap']);

function PostureLegendRow({ segment, total }: { segment: ReadinessPostureSegment; total: number }) {
  const swatch = SEGMENT_COLORS[segment.key];
  const title = `${segment.label} · ${segment.count} of ${countLabel(total, 'check')} · ${segment.pct}%`;

  return (
    <div className="legend-row" role="listitem" aria-label={title} title={title}>
      <span className="ld" style={{ background: swatch }} aria-hidden="true" />
      <span className="lg-label">{segment.label}</span>
      <span className="lg-bar-wrap" aria-hidden="true">
        <span className="lg-bar" style={{ width: `${segment.pct}%`, background: swatch }} />
      </span>
      <span className="lg-pct">{segment.pct}%</span>
      <b>{segment.count}/{total}</b>
    </div>
  );
}

export function ReadinessPostureDonut({
  state,
  runs,
  checks,
}: {
  state: StatePayload | null;
  runs: DataItem[];
  checks: DataItem[];
}) {
  const { segments, total } = resolveReadinessPostureSegments(state, runs, checks);
  const correlatedCount = segments.filter((segment) => RESULT_KEYS.has(segment.key)).reduce((sum, segment) => sum + segment.count, 0);
  const gradient = buildConicGradient(segments);
  const paintedSegments = segments.filter((segment) => segment.count > 0);
  const segmentSummary = paintedSegments
    .map((segment) => `${segment.label} ${countLabel(segment.count, 'check')} ${segment.pct} percent`)
    .join('. ');
  const passCount = segments.find((segment) => segment.key === 'pass')?.count ?? 0;
  const scoreSummary = `${passCount} of ${countLabel(total, 'check')} passed`;
  const correlationSummary = correlatedCount === 0
    ? 'No checks have run yet'
    : `${correlatedCount} of ${total} applicable ${total === 1 ? 'check has' : 'checks have'} a result this cycle`;
  const ariaLabel = [scoreSummary, correlationSummary, segmentSummary].filter(Boolean).join('. ');
  const ringTitle = [
    `${passCount} / ${total} checks passed`,
    correlationSummary,
    ...paintedSegments.map((segment) => `${segment.label} · ${segment.count} checks · ${segment.pct}%`),
  ].filter(Boolean).join(' · ');

  if (total <= 0) {
    return (
      <EmptyState
        icon={Activity}
        title="No checks have run yet."
        body="Check verdicts appear here after a bounded check on a verified target records a result."
      />
    );
  }

  return (
    <div className="dash-gauge-block">
      <div
        className="gauge gauge--segmented"
        role="img"
        aria-label={ariaLabel}
        title={ringTitle}
        style={{ ['--gauge-gradient' as string]: gradient }}
      >
        <div className="gauge-hole" style={{ background: 'var(--surface)' }}>
          <span className="gauge-score-cap" aria-hidden="true">Pass</span>
          <div className="gauge-score" aria-hidden="true">
            <span className="gauge-score-value">{passCount}</span>
            <span className="gauge-score-scale">/{total}</span>
          </div>
        </div>
      </div>
      <div className="gauge-side">
        <div className="gauge-legend" role="list" aria-label="Readiness posture breakdown">
          {segments.map((segment) => (
            <PostureLegendRow key={segment.key} segment={segment} total={total} />
          ))}
        </div>
        <p className="gauge-side-note">{correlationSummary}</p>
      </div>
    </div>
  );
}