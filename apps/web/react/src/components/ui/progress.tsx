import { clamp, cn } from '../../lib/utils';

type ProgressProps = {
  value: number;
  className?: string;
};

export function Progress({ value, className }: ProgressProps) {
  return (
    <div className={cn('progress', className)} aria-valuenow={clamp(value)} aria-valuemin={0} aria-valuemax={100}>
      <span style={{ width: `${clamp(value)}%` }} />
    </div>
  );
}
