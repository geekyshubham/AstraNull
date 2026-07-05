import { clamp, cn } from '../../lib/utils';

export type ProgressTone = 'accent' | 'success' | 'warn' | 'danger';
export type ProgressSize = 'sm' | 'default' | 'lg';

type ProgressProps = {
  value: number;
  className?: string;
  tone?: ProgressTone;
  size?: ProgressSize;
};

export function Progress({ value, className, tone = 'accent', size = 'default' }: ProgressProps) {
  const clamped = clamp(value);

  return (
    <div
      className={cn(
        'progress',
        tone !== 'accent' && `progress-${tone}`,
        size !== 'default' && `progress-${size}`,
        className
      )}
      role="progressbar"
      aria-valuenow={clamped}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <span style={{ width: `${clamped}%` }} />
    </div>
  );
}