import { cn } from '../../lib/utils';

type MiniTrendProps = {
  points: number[];
  className?: string;
};

export function MiniTrend({ points, className }: MiniTrendProps) {
  const safePoints = points.length > 1 ? points : [38, 46, 51, 63, 71, 74];
  const max = Math.max(...safePoints, 1);
  const min = Math.min(...safePoints, 0);
  const path = safePoints
    .map((point, index) => {
      const x = (index / Math.max(safePoints.length - 1, 1)) * 100;
      const y = 48 - ((point - min) / Math.max(max - min, 1)) * 36;
      return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
    })
    .join(' ');
  return (
    <svg className={cn('mini-trend', className)} viewBox="0 0 100 56" preserveAspectRatio="none" aria-hidden="true">
      <path className="mini-trend-fill" d={`${path} L 100 56 L 0 56 Z`} />
      <path className="mini-trend-line" d={path} />
    </svg>
  );
}
