import { clamp, cn } from '../../lib/utils';
import './primitives.css';

export type ProgressTone = 'accent' | 'success' | 'warn' | 'danger';
export type ProgressSize = 'sm' | 'default' | 'lg';

type ProgressProps = {
  value: number;
  className?: string;
  tone?: ProgressTone;
  size?: ProgressSize;
  label?: string;
  /** Render the label and percentage above the bar instead of only naming it for assistive tech. */
  showValue?: boolean;
  /** Work is running but its size is unknown; omits aria-valuenow per ARIA. */
  indeterminate?: boolean;
};

export function Progress({
  value,
  className,
  tone = 'accent',
  size = 'default',
  label,
  showValue = false,
  indeterminate = false
}: ProgressProps) {
  const clamped = clamp(value);
  const accessibleName = indeterminate
    ? label ?? 'Progress'
    : label
      ? `${label}: ${clamped} percent`
      : `Progress ${clamped} percent`;

  const bar = (
    <div
      data-ui="progress"
      className={cn(
        'progress',
        tone !== 'accent' && `progress-${tone}`,
        size !== 'default' && `progress-${size}`,
        indeterminate && 'progress-indeterminate',
        !showValue && className
      )}
      role="progressbar"
      aria-label={accessibleName}
      aria-valuenow={indeterminate ? undefined : clamped}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuetext={indeterminate ? 'In progress' : `${clamped}%`}
    >
      <span
        className="progress-bar"
        style={indeterminate ? undefined : { transform: `scaleX(${clamped / 100})`, transformOrigin: 'left center' }}
      />
    </div>
  );

  if (!showValue) return bar;

  return (
    <div className={cn('progress-field', className)}>
      {/* Visible duplicate of the progressbar's accessible name; hidden so it is not read twice. */}
      <div className="progress-meta" aria-hidden="true">
        {label ? <span className="progress-meta-label">{label}</span> : <span />}
        <span className="progress-meta-value">{indeterminate ? 'In progress' : `${clamped}%`}</span>
      </div>
      {bar}
    </div>
  );
}
