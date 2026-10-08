import { useEffect, useState, type FormEvent } from 'react';
import { requestJson } from '../../lib/api';
import { apiErrorMessage } from '../../lib/error-messages';
import { FormModal } from '../../lib/crud-ui';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import { Button } from '../ui/button';

/** Ownership and authorization are separate; recording a declaration never starts traffic. */
export function TargetAuthorization({ target, config, session, canWrite, ownershipDone }: {
  target: DataItem; config: PortalConfig; session: Session; canWrite: boolean; ownershipDone: boolean;
}) {
  const id = String(target.id ?? '');
  const [record, setRecord] = useState<DataItem | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [reload, setReload] = useState(0);
  useEffect(() => {
    let stopped = false; setLoading(true); setError(''); setRecord(null);
    void requestJson(config, session, `/v1/targets/${encodeURIComponent(id)}/authorization`).then((value) => {
      if (!stopped) setRecord((value as DataItem).authorization as DataItem | null ?? null);
    }).catch((err) => { if (!stopped) setError(apiErrorMessage(err, 'Authorization could not load.')); })
      .finally(() => { if (!stopped) setLoading(false); });
    return () => { stopped = true; };
  }, [id, config, session, reload]);
  async function sign(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = new FormData(event.currentTarget); setBusy(true); setError('');
    try {
      await requestJson(config, session, `/v1/targets/${encodeURIComponent(id)}/authorization`, { method: 'POST', body: {
        signer_name: String(form.get('signer_name') ?? '').trim(), signer_email: String(form.get('signer_email') ?? '').trim(),
        attested: form.get('attested') === 'on',
      } });
      setOpen(false); setReload((value) => value + 1);
    } catch (err) { setError(apiErrorMessage(err, 'Authorization could not be recorded.')); }
    finally { setBusy(false); }
  }
  return <section className="td-section td-authorization" aria-labelledby="td-authorization-title">
    <header className="td-section-head"><div><h2 id="td-authorization-title">Target authorization</h2><p>Authorization for {String(target.value ?? id)}. Recording it sends no probe traffic. High-scale execution still requires a complete authorization pack and SOC approval.</p></div>
      {canWrite && !record ? <Button variant="secondary" disabled={loading || !ownershipDone} onClick={() => setOpen(true)}>Record authorization</Button> : null}
    </header>
    {loading ? <p role="status">Loading authorization…</p> : record ? <p>Recorded authorization · {String(record.signer_name ?? 'Signer not recorded')} · {String(record.signed_at ?? 'Time not recorded')}</p> : <p>No active authorization covers this domain.{!ownershipDone ? ' Prove ownership before recording authorization.' : ''}</p>}
    {error ? <p role="alert">{error} <Button size="sm" variant="ghost" onClick={() => setReload((value) => value + 1)}>Retry</Button></p> : null}
    <FormModal open={open} title={`Authorize ${String(target.value ?? id)}`} description="Only this declared domain is included. This records authorization metadata; it does not approve or start a high-scale test." onClose={() => { if (!busy) setOpen(false); }}>
      <form className="product-form" onSubmit={(event) => void sign(event)}>
        <label><span>Signer name</span><input name="signer_name" required maxLength={160} /></label>
        <label><span>Signer email</span><input name="signer_email" type="email" required maxLength={254} /></label>
        <label className="check-row full"><input type="checkbox" name="attested" required /><span>I am authorized to approve defensive validation for this exact domain.</span></label>
        {error ? <p className="form-error full" role="alert">{error}</p> : null}
        <div className="form-actions full"><Button type="button" variant="ghost" disabled={busy} onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" loading={busy}>Record authorization</Button></div>
      </form>
    </FormModal>
  </section>;
}
