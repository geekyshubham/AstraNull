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
  /** Accessible name when tab labels alone are insufficient. */
  ariaLabel?: string;
  /** When provided, sets `aria-controls` on each tab for paired tab panels. */
  getPanelId?: (tabId: T) => string | undefined;
  getTabId?: (tabId: T) => string | undefined;
};

type TabButtonProps<T extends string> = {
  option: TabOption<T>;
  selected: boolean;
  panelId: string | undefined;
  tabId: string | undefined;
  onSelect: () => void;
  onKeyDown: (event: React.KeyboardEvent<HTMLButtonElement>) => void;
  setRef: (node: HTMLButtonElement | null) => void;
};

function TabButton<T extends string>({
  option,
  selected,
  panelId,
  tabId,
  onSelect,
  onKeyDown,
  setRef
}: TabButtonProps<T>) {
  return (
    <button
      ref={setRef}
      type="button"
      id={tabId}
      role="tab"
      aria-selected={selected}
      aria-controls={panelId}
      tabIndex={selected ? 0 : -1}
      className={cn('tab', selected && 'active')}
      onClick={onSelect}
      onKeyDown={onKeyDown}
    >
      {option.label}
      {typeof option.count === 'number' ? (
        <span className="tab-count">
          <span className="sr-only">{option.count} items</span>
          <span aria-hidden="true">{option.count}</span>
        </span>
      ) : null}
    </button>
  );
}

export function Tabs<T extends string>({
  value,
  options,
  onChange,
  className,
  ariaLabel,
  getPanelId,
  getTabId
}: TabsProps<T>) {
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
    <div className={cn('tabs', className)} role="tablist" aria-label={ariaLabel}>
      {options.map((option, index) => {
        const selected = option.id === value;
        const panelId = getPanelId?.(option.id);
        const tabId = getTabId?.(option.id);

        return (
          <TabButton
            key={option.id}
            option={option}
            selected={selected}
            panelId={panelId}
            tabId={tabId}
            onSelect={() => onChange(option.id)}
            onKeyDown={(event) => onTabKeyDown(event, index)}
            setRef={(node) => {
              tabRefs.current[index] = node;
            }}
          />
        );
      })}
    </div>
  );
}