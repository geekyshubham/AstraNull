import { createContext, useCallback, useContext, useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import { EmptyState } from '../components/ui/empty-state';
import { Button } from '../components/ui/button';
import type { DataItem } from './types';

function useRestoreDialogFocus(open: boolean) {
  const openerRef = useRef<HTMLElement | null>(null);
  useEffect(() => {
    if (!open) return undefined;
    openerRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    return () => {
      const opener = openerRef.current;
      window.requestAnimationFrame(() => {
        if (opener?.isConnected && !document.querySelector('dialog[open]')) opener.focus();
      });
    };
  }, [open]);
}

export type FriendlyEmptyStateProps = {
  icon: LucideIcon;
  title: string;
  body: string;
  actionLabel?: string;
  actionHref?: string;
  onAction?: () => void;
};

/** Friendly empty state with optional Create CTA for CRUD list surfaces. */
export function renderFriendlyEmptyState(props: FriendlyEmptyStateProps) {
  return <EmptyState {...props} />;
}

export function extractAuditEntryId(payload: unknown): string {
  if (!payload || typeof payload !== 'object') return '';
  const item = payload as DataItem;
  const direct = item.audit_entry_id ?? item.audit_id ?? item.entry_id;
  if (direct != null && String(direct).trim()) return String(direct);
  const audit = item.audit;
  if (audit && typeof audit === 'object' && !Array.isArray(audit)) {
    const nested = (audit as DataItem).id ?? (audit as DataItem).entry_id;
    if (nested != null && String(nested).trim()) return String(nested);
  }
  return '';
}

export function formatMutationSuccessMessage(success: string, payload: unknown) {
  const auditId = extractAuditEntryId(payload);
  return auditId ? `${success} Audit entry: ${auditId}.` : success;
}

type ConfirmModalProps = {
  open: boolean;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  dismissLabel?: string;
  confirmTone?: 'danger' | 'default';
  requireTypedId?: string;
  typedPlaceholder?: string;
  busy?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
};

export function ConfirmModal({
  open,
  title,
  description,
  confirmLabel,
  dismissLabel = 'Cancel',
  confirmTone = 'danger',
  requireTypedId,
  typedPlaceholder,
  busy = false,
  onCancel,
  onConfirm
}: ConfirmModalProps) {
  const titleId = useId();
  const [typed, setTyped] = useState('');
  const dialogRef = useRef<HTMLDialogElement>(null);
  useRestoreDialogFocus(open);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  useEffect(() => {
    if (!open) setTyped('');
  }, [open]);

  const needsTyped = Boolean(requireTypedId?.trim());
  const typedOk = !needsTyped || typed.trim() === requireTypedId?.trim();

  if (!open) return null;

  return (
    <dialog ref={dialogRef} className="modal-confirm" aria-labelledby={titleId} onCancel={(event) => {
      event.preventDefault();
      onCancel();
    }}>
      <form
        method="dialog"
        className="modal-confirm-body"
        onSubmit={(event: FormEvent) => {
          event.preventDefault();
          if (!typedOk || busy) return;
          onConfirm();
        }}
      >
        <h3 id={titleId}>{title}</h3>
        <div className="modal-confirm-desc">{description}</div>
        {needsTyped ? (
          <label className="full">
            <span>Type <code>{requireTypedId}</code> to confirm</span>
            <input
              value={typed}
              onChange={(event) => setTyped(event.target.value)}
              placeholder={typedPlaceholder ?? requireTypedId}
              autoComplete="off"
              disabled={busy}
            />
          </label>
        ) : null}
        <div className="modal-confirm-actions">
          <Button type="button" variant="ghost" disabled={busy} onClick={onCancel}>{dismissLabel}</Button>
          <Button type="submit" variant={confirmTone === 'danger' ? 'danger' : 'default'} loading={busy} disabled={!typedOk || busy}>
            {confirmLabel}
          </Button>
        </div>
      </form>
    </dialog>
  );
}

/**
 * Reusable form popup built on the native <dialog> element (focus trap, Esc, and
 * backdrop for free). Controlled via `open`; renders a titled header with a Close
 * affordance and a scrollable body for the form. Errors/success should be rendered
 * inside `children` so they stay visible above the backdrop.
 */
export function FormModal({
  open,
  title,
  description,
  onClose,
  children,
  wide = false
}: {
  open: boolean;
  title: string;
  description?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  const titleId = useId();
  const descId = useId();
  const dialogRef = useRef<HTMLDialogElement>(null);
  useRestoreDialogFocus(open);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  if (!open) return null;

  return (
    <dialog
      ref={dialogRef}
      className={`modal-confirm form-modal${wide ? ' form-modal-wide' : ''}`}
      aria-labelledby={titleId}
      aria-describedby={description ? descId : undefined}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="form-modal-head">
        <div className="form-modal-heading">
          <h3 id={titleId}>{title}</h3>
          {description ? <p id={descId} className="form-modal-desc">{description}</p> : null}
        </div>
        <Button type="button" size="sm" variant="ghost" onClick={onClose} aria-label="Close dialog">Close</Button>
      </div>
      <div className="form-modal-body">{children}</div>
    </dialog>
  );
}

export type ConfirmRequest = {
  title: string;
  description: ReactNode;
  confirmLabel?: string;
  dismissLabel?: string;
  confirmTone?: 'danger' | 'default';
  requireTypedId?: string;
};

type ConfirmContextValue = {
  confirm: (request: ConfirmRequest) => Promise<boolean>;
};

const ConfirmContext = createContext<ConfirmContextValue | null>(null);

export function ConfirmModalProvider({ children }: { children: ReactNode }) {
  const [request, setRequest] = useState<ConfirmRequest | null>(null);
  const resolverRef = useRef<((accepted: boolean) => void) | null>(null);

  const settle = useCallback((accepted: boolean) => {
    const resolve = resolverRef.current;
    resolverRef.current = null;
    setRequest(null);
    resolve?.(accepted);
  }, []);

  const confirm = useCallback((next: ConfirmRequest) => {
    resolverRef.current?.(false);
    return new Promise<boolean>((resolve) => {
      resolverRef.current = resolve;
      setRequest(next);
    });
  }, []);

  useEffect(() => () => resolverRef.current?.(false), []);

  return (
    <ConfirmContext.Provider value={{ confirm }}>
      {children}
      <ConfirmModal
        open={Boolean(request)}
        title={request?.title ?? 'Confirm action'}
        description={request?.description ?? ''}
        confirmLabel={request?.confirmLabel ?? 'Confirm'}
        dismissLabel={request?.dismissLabel ?? 'Cancel'}
        confirmTone={request?.confirmTone ?? 'danger'}
        requireTypedId={request?.requireTypedId}
        onCancel={() => settle(false)}
        onConfirm={() => settle(true)}
      />
    </ConfirmContext.Provider>
  );
}

export function useConfirmModal() {
  const value = useContext(ConfirmContext);
  if (!value) throw new Error('useConfirmModal must be used inside ConfirmModalProvider.');
  return value;
}
