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
  name?: string;
  value: string;
  options: SelectOption[];
  onChange: (value: string) => void;
  className?: string;
  disabled?: boolean;
};

export function Select({ label, name, value, options, onChange, className, disabled = false }: SelectProps) {
  const [open, setOpen] = useState(false);
  const [placement, setPlacement] = useState<'down' | 'up'>('down');
  const shellRef = useRef<HTMLSpanElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const listId = useId();
  const selected = options.find((option) => option.value === value) ?? options[0];
  const selectedIndex = Math.max(0, options.findIndex((option) => option.value === selected?.value));

  useEffect(() => {
    if (disabled) {
      setOpen(false);
      setPlacement('down');
    }
  }, [disabled]);

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
    if (disabled) return;
    onChange(nextValue);
    setOpen(false);
    triggerRef.current?.focus();
  }

  function optionButtons() {
    return Array.from(shellRef.current?.querySelectorAll<HTMLButtonElement>('[role="option"]') ?? []);
  }

  function focusOption(index: number) {
    const buttons = optionButtons();
    if (buttons.length === 0) return;
    buttons[(index + buttons.length) % buttons.length]?.focus();
  }

  function updatePlacement() {
    if (typeof window === 'undefined') {
      setPlacement('down');
      return;
    }

    const rect = triggerRef.current?.getBoundingClientRect();
    if (!rect) {
      setPlacement('down');
      return;
    }

    const menuHeight = 288;
    const gap = 8;
    const below = window.innerHeight - rect.bottom - gap;
    const above = rect.top - gap;
    setPlacement(below < menuHeight && above > below ? 'up' : 'down');
  }

  function openAndFocus(index = selectedIndex) {
    updatePlacement();
    setOpen(true);
    requestAnimationFrame(() => focusOption(index));
  }

  function onTriggerKeyDown(event: ReactKeyboardEvent<HTMLButtonElement>) {
    if (disabled) return;
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      openAndFocus(selectedIndex);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      openAndFocus(Math.max(0, selectedIndex));
    } else if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      openAndFocus(selectedIndex);
    }
  }

  function onOptionKeyDown(event: ReactKeyboardEvent<HTMLButtonElement>, optionValue: string, index: number) {
    if (event.key === 'Escape') {
      event.preventDefault();
      setOpen(false);
      triggerRef.current?.focus();
    } else if (event.key === 'ArrowDown') {
      event.preventDefault();
      focusOption(index + 1);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      focusOption(index - 1);
    } else if (event.key === 'Home') {
      event.preventDefault();
      focusOption(0);
    } else if (event.key === 'End') {
      event.preventDefault();
      focusOption(options.length - 1);
    } else if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      choose(optionValue);
    }
  }

  function toggleOpen() {
    if (disabled) return;
    setOpen((current) => {
      if (!current) updatePlacement();
      return !current;
    });
  }

  return (
    <label className={cn('field', disabled && 'field-disabled', className)}>
      <span>{label}</span>
      <span
        className={cn(
          'select-shell',
          open && 'open',
          disabled && 'select-disabled',
          placement === 'up' && 'select-menu-up',
        )}
        ref={shellRef}
      >
        <select
          className="select-native"
          name={name}
          value={value}
          disabled={disabled}
          onChange={(event) => onChange(event.target.value)}
          tabIndex={-1}
          aria-hidden="true"
        >
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
          disabled={disabled}
          onClick={toggleOpen}
          onKeyDown={onTriggerKeyDown}
        >
          <span className="select-copy">
            <strong>{selected?.label}</strong>
            {selected?.description ? <small>{selected.description}</small> : null}
          </span>
          <ChevronDown size={16} />
        </button>
        <span id={listId} className="select-menu" role="listbox" aria-label={label} hidden={!open || disabled}>
          {options.map((option, index) => (
            <button
              type="button"
              role="option"
              aria-selected={option.value === value}
              className={cn('select-option', option.value === value && 'active')}
              key={option.value}
              onClick={() => choose(option.value)}
              onKeyDown={(event) => onOptionKeyDown(event, option.value, index)}
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
