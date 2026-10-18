import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState, type CSSProperties, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from 'react';
import { MoreHorizontal } from 'lucide-react';
import './row-actions-menu.css';

export type RowAction = {
  key: string;
  label: ReactNode;
  ariaLabel?: string;
  icon?: ReactNode;
  tone?: 'danger';
  disabled?: boolean;
  onSelect: () => void;
};

type MenuPosition = { top: number; left: number; placement: 'below' | 'above' };

const MENU_GAP = 4;
const MENU_MIN_WIDTH = 176;

export function RowActionsMenu({ label, actions }: { label: string; actions: RowAction[] }) {
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState<MenuPosition | null>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuId = useId();

  const close = useCallback((restoreFocus: boolean) => {
    setOpen(false);
    if (restoreFocus) triggerRef.current?.focus();
  }, []);

  const place = useCallback(() => {
    const trigger = triggerRef.current;
    if (!trigger) return;
    const rect = trigger.getBoundingClientRect();
    const menuHeight = menuRef.current?.offsetHeight ?? 0;
    const below = rect.bottom + MENU_GAP + menuHeight <= window.innerHeight || rect.top - MENU_GAP - menuHeight < 0;
    setPosition({
      top: below ? rect.bottom + MENU_GAP : rect.top - MENU_GAP - menuHeight,
      left: Math.max(MENU_GAP, Math.min(rect.right - MENU_MIN_WIDTH, window.innerWidth - MENU_MIN_WIDTH - MENU_GAP)),
      placement: below ? 'below' : 'above'
    });
  }, []);

  useLayoutEffect(() => {
    if (!open) return;
    place();
    menuRef.current?.querySelector<HTMLButtonElement>('button:not(:disabled)')?.focus();
  }, [open, place]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node;
      if (menuRef.current?.contains(target) || triggerRef.current?.contains(target)) return;
      close(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        close(true);
      }
    };
    const onViewportChange = () => close(false);
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    window.addEventListener('resize', onViewportChange);
    window.addEventListener('scroll', onViewportChange, true);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
      window.removeEventListener('resize', onViewportChange);
      window.removeEventListener('scroll', onViewportChange, true);
    };
  }, [open, close]);

  function onMenuKeyDown(event: ReactKeyboardEvent<HTMLDivElement>) {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End', 'Tab'].includes(event.key)) return;
    if (event.key === 'Tab') {
      close(false);
      return;
    }
    event.preventDefault();
    const items = [...(menuRef.current?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)') ?? [])];
    if (!items.length) return;
    const index = items.indexOf(document.activeElement as HTMLButtonElement);
    const next = event.key === 'Home' ? 0
      : event.key === 'End' ? items.length - 1
        : event.key === 'ArrowDown' ? (index + 1) % items.length
          : (index - 1 + items.length) % items.length;
    items[next]?.focus();
  }

  if (actions.length === 0) return null;

  return (
    <span className="row-actions-menu">
      <button
        ref={triggerRef}
        type="button"
        data-ui="button"
        className="btn btn-secondary btn-icon row-actions-menu-trigger"
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => (open ? close(false) : setOpen(true))}
      >
        <MoreHorizontal size={16} aria-hidden="true" />
      </button>
      {open ? (
        <div
          ref={menuRef}
          id={menuId}
          role="menu"
          aria-label={label}
          className="row-actions-menu-list"
          data-placement={position?.placement}
          data-positioned={position ? 'true' : undefined}
          style={position ? ({ '--menu-top': `${position.top}px`, '--menu-left': `${position.left}px` } as CSSProperties) : undefined}
          onKeyDown={onMenuKeyDown}
        >
          {actions.map((action) => (
            <button
              key={action.key}
              type="button"
              role="menuitem"
              className="row-actions-menu-item"
              data-tone={action.tone}
              aria-label={action.ariaLabel}
              disabled={action.disabled}
              onClick={() => {
                close(true);
                action.onSelect();
              }}
            >
              {action.icon}
              <span>{action.label}</span>
            </button>
          ))}
        </div>
      ) : null}
    </span>
  );
}
