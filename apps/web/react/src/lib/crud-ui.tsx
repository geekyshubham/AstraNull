import { createContext, useCallback, useContext, useEffect, useId, useMemo, useRef, useState, type FormEvent, type ReactNode } from 'react';
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
        const remaining = [...document.querySelectorAll<HTMLDialogElement>('dialog[open]')].at(-1);
        if (opener?.isConnected && (!remaining || remaining.contains(opener))) opener.focus();
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

export type ConfirmReason = {
  label: string;
  placeholder?: string;
  required?: boolean;
  minLength?: number;
};

function reasonSatisfied(reason: ConfirmReason | undefined, text: string) {
  if (!reason) return true;
  const length = text.trim().length;
  if (reason.required && length === 0) return false;
  if (reason.minLength && length > 0 && length < reason.minLength) return false;
  return true;
}

function reasonHint(reason: ConfirmReason) {
  if (reason.minLength) return `${reason.required ? 'Required. ' : ''}At least ${reason.minLength} characters.`;
  return reason.required ? 'Required.' : '';
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
  reason?: ConfirmReason;
  confirmDisabled?: boolean;
  busy?: boolean;
  onCancel: () => void;
  onConfirm: (reason?: string) => void;
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
  reason,
  confirmDisabled = false,
  busy = false,
  onCancel,
  onConfirm
}: ConfirmModalProps) {
  const titleId = useId();
  const reasonId = useId();
  const reasonHintId = useId();
  const [typed, setTyped] = useState('');
  const [reasonText, setReasonText] = useState('');
  const dialogRef = useRef<HTMLDialogElement>(null);
  useRestoreDialogFocus(open);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
    return () => { if (dialog.open) dialog.close(); };
  }, [open]);

  useEffect(() => {
    if (open) return;
    setTyped('');
    setReasonText('');
  }, [open]);

  const needsTyped = Boolean(requireTypedId?.trim());
  const typedOk = !needsTyped || typed.trim() === requireTypedId?.trim();
  const reasonOk = reasonSatisfied(reason, reasonText);
  const canConfirm = typedOk && reasonOk && !confirmDisabled;
  const hint = reason ? reasonHint(reason) : '';

  if (!open) return null;

  return (
    <dialog ref={dialogRef} className="modal-confirm" aria-labelledby={titleId} onCancel={(event) => {
      event.preventDefault();
      event.stopPropagation();
      onCancel();
    }}>
      <form
        method="dialog"
        className="modal-confirm-body"
        onSubmit={(event: FormEvent) => {
          event.preventDefault();
          if (!canConfirm || busy) return;
          if (reason) onConfirm(reasonText.trim());
          else onConfirm();
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
        {reason ? (
          <label className="field full" htmlFor={reasonId}>
            <span>{reason.label}</span>
            <textarea
              id={reasonId}
              value={reasonText}
              onChange={(event) => setReasonText(event.target.value)}
              placeholder={reason.placeholder}
              required={reason.required || undefined}
              aria-required={reason.required || undefined}
              aria-describedby={hint ? reasonHintId : undefined}
              rows={3}
              disabled={busy}
            />
            {hint ? <span id={reasonHintId} className="muted small">{hint}</span> : null}
          </label>
        ) : null}
        <div className="modal-confirm-actions">
          <Button type="button" variant="ghost" disabled={busy} onClick={onCancel}>{dismissLabel}</Button>
          <Button type="submit" variant={confirmTone === 'danger' ? 'danger' : 'default'} loading={busy} disabled={!canConfirm || busy}>
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
    return () => { if (dialog.open) dialog.close(); };
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
  reason?: ConfirmReason;
  confirmDisabled?: boolean;
};

type ConfirmContextValue = {
  confirm: (request: ConfirmRequest) => Promise<boolean>;
  confirmWithReason: (request: ConfirmRequest) => Promise<string | null>;
};

type ConfirmOutcome = { accepted: boolean; reason: string };

const DEFAULT_CONFIRM_REASON: ConfirmReason = { label: 'Reason', required: true };

const ConfirmContext = createContext<ConfirmContextValue | null>(null);

export function ConfirmModalProvider({ children }: { children: ReactNode }) {
  const [request, setRequest] = useState<ConfirmRequest | null>(null);
  const resolverRef = useRef<((outcome: ConfirmOutcome) => void) | null>(null);

  const settle = useCallback((accepted: boolean, reason = '') => {
    const resolve = resolverRef.current;
    resolverRef.current = null;
    setRequest(null);
    resolve?.({ accepted, reason });
  }, []);

  const open = useCallback((next: ConfirmRequest) => {
    resolverRef.current?.({ accepted: false, reason: '' });
    return new Promise<ConfirmOutcome>((resolve) => {
      resolverRef.current = resolve;
      setRequest(next);
    });
  }, []);

  const confirm = useCallback(
    (next: ConfirmRequest) => open(next).then((outcome) => outcome.accepted),
    [open],
  );

  const confirmWithReason = useCallback(
    (next: ConfirmRequest) =>
      open({ ...next, reason: next.reason ?? DEFAULT_CONFIRM_REASON }).then((outcome) =>
        outcome.accepted ? outcome.reason.trim() : null,
      ),
    [open],
  );

  useEffect(() => () => resolverRef.current?.({ accepted: false, reason: '' }), []);

  const contextValue = useMemo(() => ({ confirm, confirmWithReason }), [confirm, confirmWithReason]);

  return (
    <ConfirmContext.Provider value={contextValue}>
      {children}
      <ConfirmModal
        open={Boolean(request)}
        title={request?.title ?? 'Confirm action'}
        description={request?.description ?? ''}
        confirmLabel={request?.confirmLabel ?? 'Confirm'}
        dismissLabel={request?.dismissLabel ?? 'Cancel'}
        confirmTone={request?.confirmTone ?? 'danger'}
        requireTypedId={request?.requireTypedId}
        reason={request?.reason}
        confirmDisabled={request?.confirmDisabled}
        onCancel={() => settle(false)}
        onConfirm={(reason) => settle(true, reason ?? '')}
      />
    </ConfirmContext.Provider>
  );
}

export function useConfirmModal() {
  const value = useContext(ConfirmContext);
  if (!value) throw new Error('useConfirmModal must be used inside ConfirmModalProvider.');
  return value;
}
