import { clamp, scoreTone } from '../../lib/utils';
import { Badge } from '../ui/badge';

type ReadinessGaugeProps = {
  score: number;
  label?: string;
};

export function ReadinessGauge({ score, label = 'Readiness' }: ReadinessGaugeProps) {
  const normalized = clamp(score);
  const dash = 2 * Math.PI * 52;
  const offset = dash - (dash * normalized) / 100;
  const rounded = Math.round(normalized);
  const gaugeLabel = `${label} score ${rounded} out of 100`;

  return (
    <div className="readiness-gauge">
      <svg viewBox="0 0 140 140" role="img" aria-label={gaugeLabel}>
        <circle className="gauge-track" cx="70" cy="70" r="52" />
        <circle
          className={`gauge-fill gauge-fill-animate gauge-fill-${scoreTone(normalized)}`}
          cx="70"
          cy="70"
          r="52"
          strokeDasharray={dash}
          strokeDashoffset={offset}
        />
        <text className="gauge-score" x="70" y="68" textAnchor="middle" aria-hidden="true">
          {rounded}
        </text>
        <text className="gauge-label" x="70" y="90" textAnchor="middle" aria-hidden="true">
          {label}
        </text>
      </svg>
      <Badge tone={scoreTone(normalized)}>{normalized >= 80 ? 'Ready' : normalized >= 55 ? 'Needs work' : 'At risk'}</Badge>
    </div>
  );
}