import { Check, ChevronDown } from 'lucide-react';
import type { KeyboardEvent as ReactKeyboardEvent } from 'react';
import { useEffect, useId, useRef, useState } from 'react';
import { cn } from '../../lib/utils';

export type SelectOption = {
  value: string;
  label: string;
  description?: string;
};

type SelectProps = {
  label: string;
  value: string;
  options: SelectOption[];
  onChange: (value: string) => void;
  className?: string;
};

export function Select({ label, value, options, onChange, className }: SelectProps) {
  const [open, setOpen] = useState(false);
  const shellRef = useRef<HTMLSpanElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const listId = useId();
  const selected = options.find((option) => option.value === value) ?? options[0];

  useEffect(() => {
    function onPointerDown(event: PointerEvent) {
      if (!shellRef.current?.contains(event.target as Node)) setOpen(false);
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setOpen(false);
        triggerRef.current?.focus();
      }
    }
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, []);

  function choose(nextValue: string) {
    onChange(nextValue);
    setOpen(false);
    triggerRef.current?.focus();
  }

  function onTriggerKeyDown(event: ReactKeyboardEvent<HTMLButtonElement>) {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setOpen(true);
      requestAnimationFrame(() => {
        shellRef.current?.querySelector<HTMLButtonElement>('[role="option"]')?.focus();
      });
    }
  }

  return (
    <label className={cn('field', className)}>
      <span>{label}</span>
      <span className={cn('select-shell', open && 'open')} ref={shellRef}>
        <select className="select-native" value={value} onChange={(event) => onChange(event.target.value)} tabIndex={-1} aria-hidden="true">
          {options.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
        <button
          ref={triggerRef}
          type="button"
          className="select-display"
          aria-label={label}
          aria-controls={listId}
          aria-expanded={open}
          aria-haspopup="listbox"
          onClick={() => setOpen((current) => !current)}
          onKeyDown={onTriggerKeyDown}
        >
          <span className="select-copy">
            <strong>{selected?.label}</strong>
            {selected?.description ? <small>{selected.description}</small> : null}
          </span>
          <ChevronDown size={16} />
        </button>
        <span id={listId} className="select-menu" role="listbox" aria-label={label} hidden={!open}>
          {options.map((option) => (
            <button
              type="button"
              role="option"
              aria-selected={option.value === value}
              className={cn('select-option', option.value === value && 'active')}
              key={option.value}
              onClick={() => choose(option.value)}
              onKeyDown={(event) => {
                if (event.key === 'Escape') {
                  event.preventDefault();
                  setOpen(false);
                  triggerRef.current?.focus();
                }
              }}
            >
              <span>
                <strong>{option.label}</strong>
                {option.description ? <small>{option.description}</small> : null}
              </span>
              <Check size={14} aria-hidden="true" />
            </button>
          ))}
        </span>
      </span>
    </label>
  );
}
