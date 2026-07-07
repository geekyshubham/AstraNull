import { cn } from '../../lib/utils';

type MiniTrendProps = {
  points: number[];
  className?: string;
};

const MINI_TREND_FILL = 'color-mix(in oklab, var(--accent), transparent 88%)';
const MINI_TREND_STROKE = 'color-mix(in oklab, var(--accent), transparent 10%)';

export function MiniTrend({ points, className }: MiniTrendProps) {
  const hasTrend = points.length > 1;

  if (!hasTrend) {
    return (
      <div
        className={cn('mini-trend', 'mini-trend-empty', className)}
        role="img"
        aria-label="No trend data yet"
      >
        <span className="mini-trend-placeholder">No trend yet</span>
      </div>
    );
  }

  const max = Math.max(...points, 1);
  const min = Math.min(...points, 0);
  const first = points[0];
  const last = points[points.length - 1];
  const path = points
    .map((point, index) => {
      const x = (index / Math.max(points.length - 1, 1)) * 100;
      const y = 48 - ((point - min) / Math.max(max - min, 1)) * 36;
      return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
    })
    .join(' ');

  const trendLabel =
    first === last
      ? `Flat trend at ${last} across ${points.length} points`
      : `Trend from ${first} to ${last} across ${points.length} points`;

  return (
    <svg
      className={cn('mini-trend', className)}
      viewBox="0 0 100 56"
      preserveAspectRatio="xMidYMid meet"
      role="img"
      aria-label={trendLabel}
    >
      <path className="mini-trend-fill" d={`${path} L 100 56 L 0 56 Z`} fill={MINI_TREND_FILL} />
      <path
        className="mini-trend-line"
        d={path}
        fill="none"
        stroke={MINI_TREND_STROKE}
        strokeWidth={1.5}
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}