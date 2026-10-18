import { useEffect, useId, useRef, useState } from 'react';
import { requestJson, sessionIdentity } from '../../lib/api';
import { ConfirmModal, formatMutationSuccessMessage } from '../../lib/crud-ui';
import { apiErrorMessage } from '../../lib/error-messages';
import { sessionHasPermission } from '../../lib/dataset-access.mjs';
import type { PortalConfig, Session } from '../../lib/types';
import { Button } from '../ui/button';

type ErasureSummary = {
  tenant_id: string;
  dry_run: boolean;
  legal_hold: boolean;
  would_delete: { originClues: number; originClueBatches: number };
  audit_entry_id?: string | null;
};

type Props = {
  config: PortalConfig;
  session: Session;
  tenantId: string;
  legalHold: boolean;
};

export function OriginClueErasure(props: Props) {
  const identity = useRef({ session: props.session, generation: 0 });
  if (identity.current.session !== props.session) {
    identity.current = { session: props.session, generation: identity.current.generation + 1 };
  }
  return <ErasureForm key={`${props.tenantId}:${sessionIdentity(props.session)}:${identity.current.generation}`} {...props} />;
}

function ErasureForm({ config, session, tenantId, legalHold }: Props) {
  const headingId = useId();
  const reasonId = useId();
  const hintId = useId();
  const reasonErrorId = useId();
  const [reason, setReason] = useState('');
  const [preview, setPreview] = useState<ErasureSummary | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const pending = useRef(false);
  const mounted = useRef(true);
  const context = useRef({ session, tenantId, legalHold });
  context.current = { session, tenantId, legalHold };
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);
  const canWrite = sessionHasPermission(session, 'tenant:write');
  const blocked = legalHold || Boolean(preview?.legal_hold);
  const reasonHasControl = /[\u0000-\u001f\u007f]/.test(reason.trim());
  const validReason = reason.trim().length > 0 && reason.trim().length <= 500 && !reasonHasControl;

  async function submit(dryRun: boolean) {
    if (pending.current || !canWrite || !tenantId || !validReason || (!dryRun && (!preview || blocked))) return;
    const capturedSession = session;
    pending.current = true;
    setBusy(dryRun ? 'preview' : 'erase');
    setError('');
    setMessage('');
    const current = () => mounted.current && context.current.session === capturedSession && context.current.tenantId === tenantId;
    try {
      const result = await requestJson(config, capturedSession, '/v1/tenants/current/origin-clues/erase', {
        method: 'POST',
        body: { confirmation_tenant_id: tenantId, reason: reason.trim(), dry_run: dryRun },
      });
      if (!current()) return;
      if (!result || result.tenant_id !== tenantId || result.dry_run !== dryRun || typeof result.legal_hold !== 'boolean'
        || !Number.isSafeInteger(result.would_delete?.originClues) || result.would_delete.originClues < 0
        || !Number.isSafeInteger(result.would_delete?.originClueBatches) || result.would_delete.originClueBatches < 0
        || (!dryRun && (result.legal_hold || typeof result.audit_entry_id !== 'string' || !result.audit_entry_id.trim()))) {
        throw new Error('Erasure response did not match this workspace and operation. Refresh before trying again.');
      }
      if (dryRun) setPreview(result);
      else {
        setPreview(null);
        setConfirming(false);
        setReason('');
        setMessage(formatMutationSuccessMessage('Stored origin clues and collection responses erased for this workspace.', result));
      }
    } catch (err) {
      if (current()) {
        setError(apiErrorMessage(err, 'Origin-clue erasure failed. No automatic retry was made.'));
        setPreview(null);
        setConfirming(false);
      }
    } finally {
      pending.current = false;
      if (current()) setBusy('');
    }
  }

  return (
    <section className="stack-tight" aria-labelledby={headingId}>
      <h3 id={headingId}>Erase stored origin clues</h3>
      <p>Remove this workspace’s origin associations, collection batches, and saved response copies, including records for archived targets. This works even when origin-clue collection is disabled.</p>
      <p className="muted small">Targets, origin bindings, runs, findings, and audit records are not erased. This is not whole-workspace deletion or a guarantee of backup erasure. A later, separately authorized collection can create new clues.</p>
      {canWrite ? (
        <>
          <label className="field full" htmlFor={reasonId}>
            <span>Erasure reason</span>
            <textarea id={reasonId} rows={3} maxLength={500} value={reason} disabled={busy !== '' || confirming} aria-invalid={reasonHasControl || undefined} aria-describedby={reasonHasControl ? `${hintId} ${reasonErrorId}` : hintId} onChange={event => { setReason(event.target.value); setPreview(null); setError(''); setMessage(''); }} />
            <span id={hintId} className="muted small">Required, up to 500 characters. Recorded in the audit log; do not include credentials or clue payloads.</span>
            {reasonHasControl ? <span id={reasonErrorId} className="field-error">Use a single line without control characters.</span> : null}
          </label>
          {blocked ? <p role="status">Legal hold blocks erasure. No hold bypass is available here.</p> : null}
          {preview ? <p role="status">Current preview: {preview.would_delete.originClues} clues and {preview.would_delete.originClueBatches} collection batches. Counts may change before confirmation; the server rechecks the hold and erases the current workspace records atomically.</p> : null}
          {error ? <p className="field-error" role="alert">{error}</p> : null}
          {message ? <p role="status">{message}</p> : null}
          <div className="form-actions full">
            <Button variant="secondary" loading={busy === 'preview'} disabled={busy !== '' || !tenantId || !validReason} onClick={() => void submit(true)}>Preview origin-clue erasure</Button>
            <Button variant="danger" disabled={busy !== '' || !preview || blocked || !validReason} onClick={() => setConfirming(true)}>Erase origin clues</Button>
          </div>
          <ConfirmModal open={confirming && canWrite} title="Erase this workspace’s origin clues?" description={(
            <div className="stack-tight">
              <p>Erase all stored origin clues and saved collection responses for <code>{tenantId}</code>? This cannot be undone from this application.</p>
              <p>Targets, origin bindings, runs, findings, and audit records are not erased.</p>
              <p><strong>Reason:</strong> {reason.trim()}</p>
            </div>
          )} requireTypedId={tenantId} confirmLabel="Erase origin clues" confirmTone="danger" confirmDisabled={blocked || !preview || !validReason} busy={busy === 'erase'} onCancel={() => setConfirming(false)} onConfirm={() => void submit(false)} />
        </>
      ) : <p className="muted">Only an owner or admin with tenant-write permission can preview or erase stored origin clues.</p>}
    </section>
  );
}
