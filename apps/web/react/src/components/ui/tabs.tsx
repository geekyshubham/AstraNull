import * as React from 'react';
import { cn } from '../../lib/utils';

export type TabOption<T extends string> = {
  id: T;
  label: string;
  count?: number;
};

type TabsProps<T extends string> = {
  value: T;
  options: TabOption<T>[];
  onChange: (value: T) => void;
  className?: string;
  /** When provided, sets `aria-controls` on each tab for paired tab panels. */
  getPanelId?: (tabId: T) => string | undefined;
};

export function Tabs<T extends string>({ value, options, onChange, className, getPanelId }: TabsProps<T>) {
  const tabRefs = React.useRef<Array<HTMLButtonElement | null>>([]);

  function focusTab(index: number) {
    const option = options[index];
    if (!option) return;
    onChange(option.id);
    requestAnimationFrame(() => {
      tabRefs.current[index]?.focus();
    });
  }

  function onTabKeyDown(event: React.KeyboardEvent<HTMLButtonElement>, index: number) {
    if (options.length === 0) return;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
      event.preventDefault();
      focusTab((index + 1) % options.length);
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
      event.preventDefault();
      focusTab((index - 1 + options.length) % options.length);
    } else if (event.key === 'Home') {
      event.preventDefault();
      focusTab(0);
    } else if (event.key === 'End') {
      event.preventDefault();
      focusTab(options.length - 1);
    }
  }

  return (
    <div className={cn('tabs', className)} role="tablist">
      {options.map((option, index) => {
        const selected = option.id === value;
        const panelId = getPanelId?.(option.id);

        return (
          <button
            key={option.id}
            ref={(node) => {
              tabRefs.current[index] = node;
            }}
            type="button"
            role="tab"
            aria-selected={selected}
            aria-controls={panelId}
            tabIndex={selected ? 0 : -1}
            className={cn('tab', selected && 'active')}
            onClick={() => onChange(option.id)}
            onKeyDown={(event) => onTabKeyDown(event, index)}
          >
            {option.label}
            {typeof option.count === 'number' ? (
              <span className="tab-count" aria-label={`${option.count} items`}>
                {option.count}
              </span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}
