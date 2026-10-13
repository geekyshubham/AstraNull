import { Check, ChevronDown } from 'lucide-react';
import type { CSSProperties, KeyboardEvent as ReactKeyboardEvent } from 'react';
import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { cn } from '../../lib/utils';
import './primitives.css';

const SELECT_MENU_MAX_HEIGHT = 280;
/**
 * Must equal the rendered `.select-menu` top offset in `styles.css`, which resolves to
 * `var(--space-2)` (8px). When this constant was smaller than the real offset, the computed
 * max-height left the menu hanging past its boundary by the difference.
 */
const SELECT_MENU_GAP = 8;
const SELECT_VIEWPORT_GUTTER = 8;

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
  /** Supporting text under the field, linked with aria-describedby. */
  hint?: string;
  /** Validation message under the field; marks the trigger aria-invalid. */
  error?: string;
  /** Muted trigger text shown while `value` matches no option; without it the first option is shown. */
  placeholder?: string;
};

type MenuPosition = {
  left: number;
  width: number;
  top?: number;
  bottom?: number;
};

const FIXED_CONTAINING_BLOCK_CONTAIN = /\b(paint|layout|strict|content)\b/;
const FIXED_CONTAINING_BLOCK_WILL_CHANGE = /\b(transform|perspective|filter|backdrop-filter|contain)\b/;

// The open menu is fixed so card overflow cannot clip it; a transformed or contained ancestor replaces the viewport as its containing block.
function fixedContainingBlock(element: HTMLElement | null) {
  let node = element?.parentElement ?? null;
  while (node && node !== document.body && node !== document.documentElement) {
    const style = window.getComputedStyle(node);
    const backdrop = style.backdropFilter || style.getPropertyValue('-webkit-backdrop-filter');
    if (
      (style.transform && style.transform !== 'none') ||
      (style.filter && style.filter !== 'none') ||
      (style.perspective && style.perspective !== 'none') ||
      (backdrop && backdrop !== 'none') ||
      FIXED_CONTAINING_BLOCK_CONTAIN.test(style.contain || '') ||
      FIXED_CONTAINING_BLOCK_WILL_CHANGE.test(style.willChange || '') ||
      (style.containerType && style.containerType !== 'normal')
    ) {
      const rect = node.getBoundingClientRect();
      return {
        top: rect.top + node.clientTop,
        left: rect.left + node.clientLeft,
        height: node.clientHeight,
      };
    }
    node = node.parentElement;
  }
  return { top: 0, left: 0, height: document.documentElement.clientHeight || window.innerHeight };
}

function menuStyle(maxHeight: number, position: MenuPosition | null): CSSProperties {
  const style = { '--select-menu-max-height': `${maxHeight}px` } as CSSProperties;
  if (!position) return style;
  return {
    ...style,
    position: 'fixed',
    left: position.left,
    right: 'auto',
    width: position.width,
    top: position.top ?? 'auto',
    bottom: position.bottom ?? 'auto',
  };
}

function SelectOptionCopy({
  label: optionLabel,
  description,
  id,
  className,
}: {
  label: string;
  description?: string;
  id?: string;
  className?: string;
}) {
  return (
    <span className={cn('select-copy', className)} id={id}>
      <strong>{optionLabel}</strong>
      {description ? <small>{description}</small> : null}
    </span>
  );
}

export function Select({
  label,
  name,
  value,
  options,
  onChange,
  className,
  disabled = false,
  hint,
  error,
  placeholder,
}: SelectProps) {
  const [open, setOpen] = useState(false);
  const [placement, setPlacement] = useState<'down' | 'up'>('down');
  const [menuMaxHeight, setMenuMaxHeight] = useState(SELECT_MENU_MAX_HEIGHT);
  const [menuPosition, setMenuPosition] = useState<MenuPosition | null>(null);
  const shellRef = useRef<HTMLSpanElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLSpanElement>(null);
  const listId = useId();
  const labelId = useId();
  const valueId = useId();
  const hintId = useId();
  const errorId = useId();
  const errorText = error?.trim() ?? '';
  const hintText = hint?.trim() ?? '';
  const describedBy = [errorText ? errorId : null, hintText ? hintId : null].filter(Boolean).join(' ') || undefined;
  const triggerDescribedBy = [valueId, describedBy].filter(Boolean).join(' ');
  const placeholderText = placeholder?.trim() ?? '';
  const matched = options.find((option) => option.value === value);
  const showPlaceholder = !matched && placeholderText !== '';
  const selected = matched ?? (showPlaceholder ? undefined : options[0]);
  const selectedIndex = Math.max(0, options.findIndex((option) => option.value === selected?.value));

  useEffect(() => {
    if (disabled) {
      setOpen(false);
      setPlacement('down');
      setMenuMaxHeight(SELECT_MENU_MAX_HEIGHT);
    }
  }, [disabled]);

  useEffect(() => {
    function onPointerDown(event: PointerEvent) {
      const target = event.target as Node;
      if (!shellRef.current?.contains(target) && !menuRef.current?.contains(target)) setOpen(false);
    }
    document.addEventListener('pointerdown', onPointerDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
    };
  }, []);

  function choose(nextValue: string) {
    if (disabled) return;
    onChange(nextValue);
    setOpen(false);
    triggerRef.current?.focus();
  }

  function optionButtons() {
    return Array.from(menuRef.current?.querySelectorAll<HTMLButtonElement>('[role="option"]') ?? []);
  }

  function focusOption(index: number) {
    const buttons = optionButtons();
    if (buttons.length === 0) return;
    buttons[(index + buttons.length) % buttons.length]?.focus();
  }

  const updatePlacement = useCallback(() => {
    if (typeof window === 'undefined') {
      setPlacement('down');
      setMenuMaxHeight(SELECT_MENU_MAX_HEIGHT);
      return;
    }

    const rect = triggerRef.current?.getBoundingClientRect();
    if (!rect) {
      setPlacement('down');
      setMenuMaxHeight(SELECT_MENU_MAX_HEIGHT);
      return;
    }

    const modalBody = triggerRef.current?.closest<HTMLElement>('.form-modal-body');
    const modalRect = modalBody?.getBoundingClientRect();
    const boundaryTop = Math.max(SELECT_VIEWPORT_GUTTER, modalRect?.top ?? SELECT_VIEWPORT_GUTTER);
    const boundaryBottom = Math.min(
      window.innerHeight - SELECT_VIEWPORT_GUTTER,
      modalRect?.bottom ?? window.innerHeight - SELECT_VIEWPORT_GUTTER,
    );
    const below = Math.max(0, boundaryBottom - rect.bottom - SELECT_MENU_GAP);
    const above = Math.max(0, rect.top - boundaryTop - SELECT_MENU_GAP);
    const desiredHeight = Math.min(
      SELECT_MENU_MAX_HEIGHT,
      menuRef.current?.scrollHeight || SELECT_MENU_MAX_HEIGHT,
    );
    const nextPlacement = below < desiredHeight && above > below ? 'up' : 'down';
    const available = nextPlacement === 'up' ? above : below;
    const containingBlock = fixedContainingBlock(menuRef.current);
    setPlacement(nextPlacement);
    setMenuMaxHeight(Math.max(0, Math.min(SELECT_MENU_MAX_HEIGHT, Math.floor(available))));
    setMenuPosition({
      left: rect.left - containingBlock.left,
      width: rect.width,
      ...(nextPlacement === 'up'
        ? { bottom: containingBlock.height - (rect.top - containingBlock.top) + SELECT_MENU_GAP }
        : { top: rect.bottom - containingBlock.top + SELECT_MENU_GAP }),
    });
  }, []);

  useLayoutEffect(() => {
    if (!open) return undefined;
    const modalBody = triggerRef.current?.closest<HTMLElement>('.form-modal-body');
    function onAncestorScroll(event: Event) {
      if (event.target instanceof Node && menuRef.current?.contains(event.target)) return;
      updatePlacement();
    }
    updatePlacement();
    window.addEventListener('resize', updatePlacement);
    window.addEventListener('scroll', onAncestorScroll, { capture: true, passive: true });
    // An ancestor's enter animation can end while the menu is open, which changes its fixed containing block.
    window.addEventListener('animationend', updatePlacement, { capture: true, passive: true });
    window.addEventListener('transitionend', updatePlacement, { capture: true, passive: true });
    modalBody?.addEventListener('scroll', updatePlacement, { passive: true });
    return () => {
      window.removeEventListener('resize', updatePlacement);
      window.removeEventListener('scroll', onAncestorScroll, { capture: true });
      window.removeEventListener('animationend', updatePlacement, { capture: true });
      window.removeEventListener('transitionend', updatePlacement, { capture: true });
      modalBody?.removeEventListener('scroll', updatePlacement);
    };
  }, [open, options.length, updatePlacement]);

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

  const menuOpen = open && !disabled;

  function toggleOpen() {
    if (disabled) return;
    setOpen((current) => {
      if (!current) updatePlacement();
      return !current;
    });
  }

  return (
    <label className={cn('field', disabled && 'field-disabled', errorText && 'field-invalid', open && 'select-open', className)} data-ui="select">
      <span id={labelId}>{label}</span>
      <span
        className={cn(
          'select-shell',
          open && 'open',
          disabled && 'select-disabled',
          placement === 'up' && 'select-menu-up',
        )}
        ref={shellRef}
        aria-disabled={disabled || undefined}
        onKeyDown={(event) => {
          if (open && event.key === 'Escape') {
            event.preventDefault();
            event.stopPropagation();
            setOpen(false);
            triggerRef.current?.focus();
          }
        }}
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
          {placeholderText ? <option value="">{placeholderText}</option> : null}
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
          aria-labelledby={labelId}
          aria-controls={menuOpen ? listId : undefined}
          aria-expanded={menuOpen}
          aria-haspopup="listbox"
          aria-describedby={triggerDescribedBy}
          aria-invalid={errorText ? true : undefined}
          disabled={disabled}
          onClick={toggleOpen}
          onKeyDown={onTriggerKeyDown}
        >
          {showPlaceholder ? (
            <SelectOptionCopy id={valueId} className="select-placeholder" label={placeholderText} />
          ) : (
            <SelectOptionCopy id={valueId} label={selected?.label ?? ''} description={selected?.description} />
          )}
          <ChevronDown className="select-chevron" size={16} aria-hidden="true" />
        </button>
        <span
          ref={menuRef}
          id={listId}
          className="select-menu"
          role="listbox"
          aria-labelledby={labelId}
          hidden={!open || disabled}
          style={menuStyle(menuMaxHeight, menuOpen ? menuPosition : null)}
        >
          {options.map((option, index) => (
            <button
              type="button"
              role="option"
              aria-selected={option.value === value}
              className={cn('select-option', option.value === value && 'active')}
              key={option.value}
              tabIndex={open && !disabled ? 0 : -1}
              onClick={() => choose(option.value)}
              onKeyDown={(event) => onOptionKeyDown(event, option.value, index)}
            >
              <SelectOptionCopy label={option.label} description={option.description} />
              <Check size={14} aria-hidden="true" />
            </button>
          ))}
        </span>
      </span>
      {errorText ? (
        <span id={errorId} className="field-error-text">
          {errorText}
        </span>
      ) : null}
      {hintText ? (
        <span id={hintId} className="field-hint-text">
          {hintText}
        </span>
      ) : null}
    </label>
  );
}