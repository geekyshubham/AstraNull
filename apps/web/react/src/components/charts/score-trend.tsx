import type { DataItem } from '../../lib/types';
import { cn, scoreTone } from '../../lib/utils';

type ScoreTrendProps = {
  runs: DataItem[];
  currentScore: number;
  tone?: 'success' | 'warn' | 'danger';
};

/**
 * Real verdict-band values. Each point on the trend reflects a run's actual
 * published verdict classification — never a synthesized/interpolated value.
 */
const VERDICT_BAND: Record<'pass' | 'review' | 'gap', number> = {
  pass: 95,
  review: 60,
  gap: 20,
};

function runVerdictString(run: DataItem): string {
  const direct = run.verdict;
  if (typeof direct === 'string') return direct;
  if (direct && typeof direct === 'object' && !Array.isArray(direct)) {
    const nested = direct as DataItem;
    const value = nested.verdict ?? nested.status;
    if (typeof value === 'string') return value;
  }
  const status = run.status;
  return typeof status === 'string' ? status : '';
}

function classifyRunVerdict(verdict: string): 'pass' | 'review' | 'gap' | null {
  const key = verdict.trim().toLowerCase();
  if (!key || ['pending', 'planned', 'running', 'collecting'].includes(key)) return null;
  if (['pass', 'passed', 'protected', 'edge_protected', 'allowed_as_expected', 'success', 'ok'].includes(key)) {
    return 'pass';
  }
  if (['review', 'warn', 'warning', 'info', 'unknown', 'underprotected', 'inconclusive', 'misplaced_agent'].includes(key)) {
    return 'review';
  }
  if (['gap', 'fail', 'failed', 'danger', 'penetrated', 'bypassable', 'edge_exposed', 'unprotected'].includes(key)) {
    return 'gap';
  }
  return 'review';
}

export function ScoreTrend({ runs, currentScore, tone }: ScoreTrendProps) {
  const end = Number.isFinite(currentScore) ? currentScore : 0;

  // Build points ONLY from runs that carry a real, published verdict.
  const points = [...runs]
    .sort((left, right) =>
      String(left.created_at ?? left.id ?? '').localeCompare(String(right.created_at ?? right.id ?? ''))
    )
    .map((run) => ({ run, bucket: classifyRunVerdict(runVerdictString(run)) }))
    .filter((entry): entry is { run: DataItem; bucket: 'pass' | 'review' | 'gap' } => entry.bucket !== null)
    .map((entry) => ({
      value: VERDICT_BAND[entry.bucket],
      label: String(entry.run.id ?? '').slice(-6),
    }));

  const strokeTone = tone ?? scoreTone(end);

  // No verdicted runs yet — do not fabricate a curve. Show the honest state.
  if (points.length === 0) {
    return (
      <div className="score-trend score-trend--empty" role="img" aria-label="Readiness trend unavailable; no verdicted runs yet.">
        <span className="muted score-trend-caption">
          No verdicted runs yet · current {end}
        </span>
      </div>
    );
  }

  const width = 200;
  const height = 48;
  const padding = 4;
  const maxValue = Math.max(100, ...points.map((point) => point.value), 1);
  const coordinates = points
    .map((point, index) => {
      const x = padding + (index * (width - padding * 2)) / Math.max(1, points.length - 1);
      const y = height - padding - (point.value / maxValue) * (height - padding * 2);
      return `${x},${y}`;
    })
    .join(' ');

  const ariaLabel = `Readiness verdict trend across ${points.length} verdicted run${points.length === 1 ? '' : 's'}; current score ${end}`;

  return (
    <div className="score-trend" role="img" aria-label={ariaLabel}>
      <svg className="score-trend-svg" viewBox={`0 0 ${width} ${height}`} width="100%" preserveAspectRatio="xMidYMid meet">
        <polyline
          className={cn('score-trend-line', `score-trend-stroke--${strokeTone}`)}
          points={coordinates}
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          vectorEffect="non-scaling-stroke"
        />
        {points.map((point, index) => {
          const x = padding + (index * (width - padding * 2)) / Math.max(1, points.length - 1);
          const y = height - padding - (point.value / maxValue) * (height - padding * 2);
          return (
            <circle
              key={`${point.label}-${index}`}
              className={cn('score-trend-point', `score-trend-stroke--${strokeTone}`)}
              cx={x}
              cy={y}
              r="2.5"
              fill="currentColor"
            />
          );
        })}
      </svg>
      <span className="muted score-trend-caption">
        {points.length} verdicted run{points.length === 1 ? '' : 's'} · current {end}
      </span>
    </div>
  );
}
