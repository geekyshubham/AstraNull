import { clamp, cn } from '../../lib/utils';

const PROGRESS_STYLES = `
.progress .progress-bar {
  width: 100%;
}
@media (prefers-reduced-motion: no-preference) {
  .progress .progress-bar {
    transition: transform var(--motion-base) var(--motion-ease);
  }
}
@media (prefers-reduced-motion: reduce) {
  .progress .progress-bar {
    transition: none;
  }
}
`;

export type ProgressTone = 'accent' | 'success' | 'warn' | 'danger';
export type ProgressSize = 'sm' | 'default' | 'lg';

type ProgressProps = {
  value: number;
  className?: string;
  tone?: ProgressTone;
  size?: ProgressSize;
  label?: string;
};

export function Progress({ value, className, tone = 'accent', size = 'default', label }: ProgressProps) {
  const clamped = clamp(value);
  const accessibleName = label ? `${label}: ${clamped} percent` : `Progress ${clamped} percent`;

  return (
    <>
      <style>{PROGRESS_STYLES}</style>
      <div
        className={cn(
          'progress',
          tone !== 'accent' && `progress-${tone}`,
          size !== 'default' && `progress-${size}`,
          className
        )}
        role="progressbar"
        aria-label={accessibleName}
        aria-valuenow={clamped}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuetext={`${clamped}%`}
      >
        <span
          className="progress-bar"
          style={{ transform: `scaleX(${clamped / 100})`, transformOrigin: 'left center' }}
        />
      </div>
    </>
  );
}