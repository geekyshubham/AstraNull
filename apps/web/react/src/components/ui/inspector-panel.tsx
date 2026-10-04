import { useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { ArrowLeft, X } from 'lucide-react';
import { Button } from './button';

export type InspectorPanelMode = 'docked' | 'drawer' | 'sheet';

const DOCKED_QUERY = '(min-width: 1360px)';
const SHEET_QUERY = '(max-width: 699px)';

function readMode(): InspectorPanelMode {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return 'drawer';
  if (window.matchMedia(DOCKED_QUERY).matches) return 'docked';
  if (window.matchMedia(SHEET_QUERY).matches) return 'sheet';
  return 'drawer';
}

/** Docked beside the work area on wide screens, a modal drawer on tablets, a full sheet on phones. */
export function useInspectorPanelMode(): InspectorPanelMode {
  const [mode, setMode] = useState<InspectorPanelMode>(readMode);
  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return undefined;
    const queries = [window.matchMedia(DOCKED_QUERY), window.matchMedia(SHEET_QUERY)];
    const update = () => setMode(readMode());
    queries.forEach((query) => query.addEventListener('change', update));
    return () => queries.forEach((query) => query.removeEventListener('change', update));
  }, []);
  return mode;
}

export type InspectorPanelProps = {
  open: boolean;
  title: ReactNode;
  /** Plain-text name for the region/dialog when the title is rich content. */
  accessibleTitle: string;
  eyebrow?: ReactNode;
  meta?: ReactNode;
  status?: string;
  busy?: boolean;
  onClose: () => void;
  /** Called after close with the element that should receive focus, if the caller knows it. */
  restoreFocus?: () => HTMLElement | null;
  children: ReactNode;
  footer?: ReactNode;
  /** Change this to move focus back to the heading (for example after Next/Previous). */
  focusToken?: string;
};

export function InspectorPanel({
  open,
  title,
  accessibleTitle,
  eyebrow,
  meta,
  status,
  busy,
  onClose,
  restoreFocus,
  children,
  footer,
  focusToken,
}: InspectorPanelProps) {
  const mode = useInspectorPanelMode();
  const headingId = useId();
  const dialogRef = useRef<HTMLDialogElement>(null);
  const asideRef = useRef<HTMLElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const openerRef = useRef<HTMLElement | null>(null);
  const restoreRef = useRef(restoreFocus);
  restoreRef.current = restoreFocus;
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useLayoutEffect(() => {
    if (!open) return undefined;
    const active = document.activeElement;
    openerRef.current = active instanceof HTMLElement && active !== document.body ? active : null;
    return () => {
      const target = restoreRef.current?.() ?? openerRef.current;
      if (target && target.isConnected) {
        window.requestAnimationFrame(() => target.focus({ preventScroll: true }));
      }
    };
  }, [open]);

  // Docked mode is non-modal, so Escape is honoured from the page too, unless something closer to
  // the user owns it: an editable field, an open popup, or a modal dialog.
  useEffect(() => {
    if (!open || mode !== 'docked') return undefined;
    function onKeyDown(event: KeyboardEvent) {
      if (event.key !== 'Escape' || event.defaultPrevented) return;
      const target = event.target as HTMLElement | null;
      if (target?.closest('input, textarea, select, [contenteditable="true"], [aria-expanded="true"], dialog[open]')) return;
      if (document.querySelector('dialog[open]:not(.inspector-panel)')) return;
      event.preventDefault();
      onCloseRef.current();
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [open, mode]);

  useEffect(() => {
    const root = document.documentElement;
    if (open && mode === 'docked') root.dataset.inspectorDocked = 'true';
    else delete root.dataset.inspectorDocked;
    return () => { delete root.dataset.inspectorDocked; };
  }, [open, mode]);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && mode !== 'docked') {
      if (!dialog.open) {
        try {
          dialog.showModal();
        } catch {
          dialog.setAttribute('open', '');
        }
      }
    } else if (dialog.open) {
      dialog.close();
    }
  }, [open, mode]);

  useEffect(() => {
    if (!open) return undefined;
    const frame = window.requestAnimationFrame(() => headingRef.current?.focus({ preventScroll: true }));
    return () => window.cancelAnimationFrame(frame);
  }, [open, mode, focusToken]);

  if (!open) return null;

  const body = (
    <>
      <header className="inspector-head">
        <div className="inspector-head-row">
          {mode === 'sheet' ? (
            <Button variant="ghost" size="sm" className="inspector-back" onClick={onClose}>
              <ArrowLeft size={16} aria-hidden="true" />Back
            </Button>
          ) : null}
          {eyebrow ? <p className="inspector-eyebrow">{eyebrow}</p> : <span />}
          <button type="button" className="inspector-close" aria-label={`Close ${accessibleTitle}`} onClick={onClose}>
            <X size={18} aria-hidden="true" />
          </button>
        </div>
        <h2 id={headingId} ref={headingRef} tabIndex={-1} className="inspector-title">{title}</h2>
        {meta ? <div className="inspector-meta">{meta}</div> : null}
        <p className="sr-only" role="status" aria-live="polite">{status ?? ''}</p>
      </header>
      <div className="inspector-body" aria-busy={busy || undefined}>{children}</div>
      {footer ? <footer className="inspector-foot">{footer}</footer> : null}
    </>
  );

  if (mode === 'docked') {
    return (
      <aside
        ref={asideRef}
        className="inspector-panel"
        data-mode="docked"
        role="region"
        aria-labelledby={headingId}
      >
        {body}
      </aside>
    );
  }

  return (
    <dialog
      ref={dialogRef}
      className="inspector-panel"
      data-mode={mode}
      aria-labelledby={headingId}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      onClick={(event) => {
        if (event.target === dialogRef.current) onClose();
      }}
    >
      <div className="inspector-surface">{body}</div>
    </dialog>
  );
}
