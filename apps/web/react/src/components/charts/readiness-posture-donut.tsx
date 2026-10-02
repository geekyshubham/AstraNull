import { buildConicGradient, resolveReadinessPostureSegments } from '../../lib/readiness-posture';
import type { DataItem, ReadinessPostureSegment, StatePayload } from '../../lib/types';
import { countLabel } from '../../lib/utils';
import { EmptyState } from '../ui/empty-state';
import { Activity } from 'lucide-react';
import './readiness-posture-donut.css';

const SEGMENT_COLORS: Record<string, string> = {
  pass: 'var(--success)',
  review: 'var(--warn)',
  gap: 'var(--danger)',
};

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
  const { segments, total, score } = resolveReadinessPostureSegments(state, runs, checks);
  const correlatedCount = segments.reduce((sum, segment) => sum + segment.count, 0);
  const gradient = buildConicGradient(segments);
  const paintedSegments = segments.filter((segment) => segment.count > 0);
  const segmentSummary = paintedSegments
    .map((segment) => `${segment.label} ${countLabel(segment.count, 'check')} ${segment.pct} percent`)
    .join('. ');
  const scoreSummary = score === null ? 'Readiness score unavailable' : `Readiness score ${score} out of 100`;
  const correlationSummary = correlatedCount === total
    ? `${countLabel(correlatedCount, 'check')} correlated`
    : `${correlatedCount} of ${countLabel(total, 'check')} correlated`;
  const ariaLabel = [scoreSummary, correlationSummary, segmentSummary].filter(Boolean).join('. ');
  const ringTitle = [
    score === null ? null : `${score} / 100 readiness`,
    `${correlatedCount} / ${total} checks correlated`,
    ...paintedSegments.map((segment) => `${segment.label} · ${segment.count} checks · ${segment.pct}%`),
  ].filter(Boolean).join(' · ');

  if (total <= 0 && score === null) {
    return (
      <EmptyState
        icon={Activity}
        title="Readiness posture unavailable."
        body="Posture segments appear after checks are correlated to validation verdicts."
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
          <span className="gauge-score-cap" aria-hidden="true">Readiness</span>
          <div className="gauge-score" aria-hidden="true">
            <span className="gauge-score-value">{score ?? 'n/a'}</span>
            {score !== null ? <span className="gauge-score-scale">/100</span> : null}
          </div>
        </div>
      </div>
      <div className="gauge-side">
        <div className="gauge-legend" role="list" aria-label="Readiness posture breakdown">
          {segments.map((segment) => (
            <PostureLegendRow key={segment.key} segment={segment} total={total} />
          ))}
        </div>
        <p className="gauge-side-note">{correlationSummary} this cycle</p>
      </div>
    </div>
  );
}