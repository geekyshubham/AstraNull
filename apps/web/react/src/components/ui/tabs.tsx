import * as React from 'react';
import { cn } from '../../lib/utils';

export type TabOption<T extends string> = {
  id: T;
  label: string;
};

type TabsProps<T extends string> = {
  value: T;
  options: TabOption<T>[];
  onChange: (value: T) => void;
  className?: string;
};

export function Tabs<T extends string>({ value, options, onChange, className }: TabsProps<T>) {
  return (
    <div className={cn('tabs', className)} role="tablist">
      {options.map((option) => (
        <button
          key={option.id}
          type="button"
          role="tab"
          aria-selected={option.id === value}
          className={cn('tab', option.id === value && 'active')}
          onClick={() => onChange(option.id)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}
