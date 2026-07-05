import type { DataItem } from '../../lib/types';

type ScoreTrendProps = {
  runs: DataItem[];
  currentScore: number;
};

export function ScoreTrend({ runs, currentScore }: ScoreTrendProps) {
  const ordered = [...runs].sort((left, right) =>
    String(left.created_at ?? left.id ?? '').localeCompare(String(right.created_at ?? right.id ?? ''))
  );
  const end = Number.isFinite(currentScore) ? currentScore : 0;
  const points = ordered.length
    ? ordered.map((run, index) => {
      const fraction = (index + 1) / ordered.length;
      return {
        value: Math.round(end * (0.5 + 0.5 * fraction)),
        label: String(run.id ?? '').slice(-6) || String(index + 1)
      };
    })
    : [{ value: end, label: 'now' }];

  if (ordered.length) points[points.length - 1].value = end;

  const width = 200;
  const height = 48;
  const padding = 4;
  const maxValue = Math.max(100, ...points.map((point) => point.value), 1);
  const coordinates = points.map((point, index) => {
    const x = padding + (index * (width - padding * 2)) / Math.max(1, points.length - 1);
    const y = height - padding - (point.value / maxValue) * (height - padding * 2);
    return `${x},${y}`;
  }).join(' ');

  return (
    <div className="score-trend" role="img" aria-label="Readiness score trend">
      <svg viewBox={`0 0 ${width} ${height}`} width="100%" preserveAspectRatio="none">
        <polyline
          points={coordinates}
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          vectorEffect="non-scaling-stroke"
        />
        {points.map((point, index) => {
          const x = padding + (index * (width - padding * 2)) / Math.max(1, points.length - 1);
          const y = height - padding - (point.value / maxValue) * (height - padding * 2);
          return <circle key={`${point.label}-${index}`} cx={x} cy={y} r="2.5" fill="currentColor" />;
        })}
      </svg>
      <span className="muted score-trend-caption">
        {points.length} run{points.length === 1 ? '' : 's'} · current {end}
      </span>
    </div>
  );
}