import { clamp, scoreTone } from '../../lib/utils';
import { Badge } from '../ui/badge';
import { useAnimatedArc } from '../ui/motion';

type ReadinessGaugeProps = {
  score: number;
  label?: string;
};

const GAUGE_TRACK_STROKE = 'color-mix(in oklab, var(--fg), transparent 91%)';

const GAUGE_FILL_STROKE = {
  success: 'var(--success)',
  warn: 'var(--warn)',
  danger: 'var(--danger)',
} as const;

const GAUGE_RADIUS = 52;

export function ReadinessGauge({ score, label = 'Readiness' }: ReadinessGaugeProps) {
  const normalized = clamp(score);
  // One tween drives both the arc sweep and the numeral, so they can never
  // disagree mid-flight.
  const { dash, offset, value: swept } = useAnimatedArc({ percent: normalized, radius: GAUGE_RADIUS });
  const rounded = Math.round(normalized);
  const tone = scoreTone(normalized);
  const gaugeLabel = `${label} score ${rounded} out of 100`;

  return (
    <div className="readiness-gauge">
      <svg viewBox="0 0 140 140" role="img" aria-label={gaugeLabel} focusable="false">
        <title>{gaugeLabel}</title>
        <circle className="gauge-track" cx="70" cy="70" r={GAUGE_RADIUS} stroke={GAUGE_TRACK_STROKE} />
        <circle
          className={`gauge-fill gauge-fill-animate gauge-fill-${tone}`}
          cx="70"
          cy="70"
          r={GAUGE_RADIUS}
          stroke={GAUGE_FILL_STROKE[tone]}
          strokeDasharray={dash}
          strokeDashoffset={offset}
        />
        <text className="gauge-score" x="70" y="66" textAnchor="middle" fill="var(--fg)" aria-hidden="true">
          {Math.round(swept)}
          <tspan className="gauge-label" dx="4">/ 100</tspan>
        </text>
        <text className="gauge-label" x="70" y="91" textAnchor="middle" fill="var(--muted)" aria-hidden="true">
          {label}
        </text>
      </svg>
      <Badge tone={tone}>{normalized >= 80 ? 'Ready' : normalized >= 55 ? 'Needs work' : 'At risk'}</Badge>
    </div>
  );
}