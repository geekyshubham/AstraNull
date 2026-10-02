import * as React from 'react';
import { scrollIntoInlineView } from '../../lib/motion';
import { cn } from '../../lib/utils';
import './primitives.css';

export type TabOption<T extends string> = {
  id: T;
  label: string;
  count?: number;
  /** Shown but not selectable; skipped by arrow-key navigation. */
  disabled?: boolean;
};

type TabsProps<T extends string> = {
  value: T;
  options: TabOption<T>[];
  onChange: (value: T) => void;
  className?: string;
  /** Accessible name when tab labels alone are insufficient. */
  ariaLabel: string;
  /** When provided, sets `aria-controls` on each tab for paired tab panels. */
  getPanelId?: (tabId: T) => string | undefined;
  getTabId?: (tabId: T) => string | undefined;
};

type TabButtonProps<T extends string> = {
  option: TabOption<T>;
  selected: boolean;
  focusable: boolean;
  panelId: string | undefined;
  tabId: string | undefined;
  onSelect: () => void;
  onKeyDown: (event: React.KeyboardEvent<HTMLButtonElement>) => void;
  setRef: (node: HTMLButtonElement | null) => void;
};

function TabButton<T extends string>({
  option,
  selected,
  focusable,
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
      aria-disabled={option.disabled || undefined}
      tabIndex={focusable ? 0 : -1}
      className={cn('tab', selected && 'active')}
      onClick={option.disabled ? undefined : onSelect}
      onKeyDown={onKeyDown}
    >
      <span className="tab-label">{option.label}</span>
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
  const listRef = React.useRef<HTMLDivElement>(null);
  const tabRefs = React.useRef<Array<HTMLButtonElement | null>>([]);
  const selectedIndex = options.findIndex((option) => option.id === value);
  // Roving tabindex: the selected tab owns the single tab stop; if nothing valid is
  // selected, the first enabled tab does, so the list is never unreachable.
  const rovingIndex =
    selectedIndex >= 0 && !options[selectedIndex]?.disabled
      ? selectedIndex
      : options.findIndex((option) => !option.disabled);

  // Keep the active tab visible inside a horizontally scrolling rail.
  React.useEffect(() => {
    if (selectedIndex < 0) return;
    scrollIntoInlineView(listRef.current, tabRefs.current[selectedIndex] ?? null);
  }, [selectedIndex]);

  function focusTab(index: number) {
    const option = options[index];
    if (!option || option.disabled) return;
    onChange(option.id);
    requestAnimationFrame(() => {
      tabRefs.current[index]?.focus();
    });
  }

  /** Next enabled index from `start` moving by `step`, wrapping; -1 when none. */
  function enabledFrom(start: number, step: 1 | -1) {
    const total = options.length;
    for (let offset = 0; offset < total; offset += 1) {
      const index = (((start + step * offset) % total) + total) % total;
      if (!options[index]?.disabled) return index;
    }
    return -1;
  }

  function onTabKeyDown(event: React.KeyboardEvent<HTMLButtonElement>, index: number) {
    if (options.length === 0) return;
    let next = -1;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
      next = enabledFrom(index + 1, 1);
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
      next = enabledFrom(index - 1, -1);
    } else if (event.key === 'Home') {
      next = enabledFrom(0, 1);
    } else if (event.key === 'End') {
      next = enabledFrom(options.length - 1, -1);
    } else {
      return;
    }
    event.preventDefault();
    if (next >= 0) focusTab(next);
  }

  return (
    <div
      ref={listRef}
      data-ui="tabs"
      className={cn('tabs', className)}
      role="tablist"
      aria-orientation="horizontal"
      aria-label={ariaLabel}
    >
      {options.map((option, index) => {
        const selected = option.id === value;
        const panelId = getPanelId?.(option.id);
        const tabId = getTabId?.(option.id);

        return (
          <TabButton
            key={option.id}
            option={option}
            selected={selected}
            focusable={index === rovingIndex}
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
