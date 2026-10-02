import * as React from 'react';
import { cn } from '../../lib/utils';

/**
 * Per-page presentation variant. "classic" is the refined default console
 * layout; "premium" is the alternate SaaS presentation of the same content.
 * Data, actions, and permissions are shared. Grouping on the Findings page is not
 * presentation-only: see ADR-0009 (Classic "rule" vs Refined "alert").
 */
export type DesignVariant = 'classic' | 'premium';

const STORAGE_PREFIX = 'astranull.design-variant.';
const VARIANTS: Array<{ id: DesignVariant; label: string }> = [
  { id: 'classic', label: 'Classic' },
  { id: 'premium', label: 'Premium' }
];

function readStoredVariant(pageKey: string): DesignVariant {
  try {
    const stored = window.localStorage.getItem(`${STORAGE_PREFIX}${pageKey}`);
    return stored === 'premium' ? 'premium' : 'classic';
  } catch {
    return 'classic';
  }
}

/** Remembered per page in browser storage; storage failure falls back to classic. */
export function useDesignVariant(pageKey: string): [DesignVariant, (next: DesignVariant) => void] {
  const [variant, setVariantState] = React.useState<DesignVariant>(() =>
    typeof window === 'undefined' ? 'classic' : readStoredVariant(pageKey)
  );
  const setVariant = React.useCallback(
    (next: DesignVariant) => {
      setVariantState(next);
      try {
        window.localStorage.setItem(`${STORAGE_PREFIX}${pageKey}`, next);
      } catch {
        // Best-effort preference persistence only.
      }
    },
    [pageKey]
  );
  return [variant, setVariant];
}

/** Two-option segmented radio group with roving arrow-key selection. */
export function DesignVariantSwitch({
  value,
  onChange,
  className,
  label = 'Page design'
}: {
  value: DesignVariant;
  onChange: (next: DesignVariant) => void;
  className?: string;
  label?: string;
}) {
  const refs = React.useRef<Array<HTMLButtonElement | null>>([]);

  function onKeyDown(event: React.KeyboardEvent<HTMLButtonElement>, index: number) {
    if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(event.key)) return;
    event.preventDefault();
    const step = event.key === 'ArrowLeft' || event.key === 'ArrowUp' ? -1 : 1;
    const nextIndex = (index + step + VARIANTS.length) % VARIANTS.length;
    onChange(VARIANTS[nextIndex].id);
    refs.current[nextIndex]?.focus();
  }

  return (
    <div className={cn('design-variant-switch', className)} role="radiogroup" aria-label={label}>
      {VARIANTS.map((option, index) => {
        const selected = option.id === value;
        return (
          <button
            key={option.id}
            ref={(node) => { refs.current[index] = node; }}
            type="button"
            role="radio"
            aria-checked={selected}
            tabIndex={selected ? 0 : -1}
            className={cn('design-variant-option', selected && 'is-selected')}
            onClick={() => onChange(option.id)}
            onKeyDown={(event) => onKeyDown(event, index)}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}
