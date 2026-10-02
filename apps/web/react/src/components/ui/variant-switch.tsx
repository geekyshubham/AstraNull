import type { DesignVariant } from '../../lib/design-variant';
import { cn } from '../../lib/utils';
import './variant-switch.css';

const OPTIONS: Array<{ id: DesignVariant; label: string }> = [
  { id: 'classic', label: 'Classic' },
  { id: 'refined', label: 'Refined' }
];

/**
 * Two-option segmented control for the page presentation. Rendered in both variants'
 * header actions, so its styles are global (variant-switch.css), not scoped to `.refined`.
 */
export function VariantSwitch({
  value,
  onChange,
  label = 'Page design',
  className
}: {
  value: DesignVariant;
  onChange: (next: DesignVariant) => void;
  label?: string;
  className?: string;
}) {
  return (
    <div className={cn('variant-switch', className)} role="group" aria-label={label}>
      {OPTIONS.map((option) => {
        const selected = option.id === value;
        return (
          <button
            key={option.id}
            type="button"
            className="variant-switch-option"
            aria-pressed={selected}
            onClick={() => {
              if (!selected) onChange(option.id);
            }}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}
