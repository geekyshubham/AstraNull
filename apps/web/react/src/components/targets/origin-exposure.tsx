import { useEffect, useRef, useState } from 'react';
import { ArrowDownToLine, FileUp, Network, RefreshCw } from 'lucide-react';
import { requestJson } from '../../lib/api';
import { apiErrorMessage } from '../../lib/error-messages';
import { ConfirmModal } from '../../lib/crud-ui';
import { buildDetailHref } from '../../lib/route-params';
import { ORIGIN_IMPORT_MAX_BYTES, originClueImportBody, originClueSourceLabel, originCluesErrorState, originCluesPage } from '../../lib/origin-exposure.mjs';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import { formatDate } from '../../lib/utils';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import './origin-exposure.css';

const text = (value: unknown) => typeof value === 'string' ? value : '';
const record = (value: unknown): DataItem => value && typeof value === 'object' && !Array.isArray(value) ? value as DataItem : {};
const strings = (value: unknown): string[] => Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
const itemsOf = (value: unknown): DataItem[] => Array.isArray(value) ? value.map(record) : [];
const when = (value: unknown) => typeof value === 'string' && Number.isFinite(Date.parse(value)) ? formatDate(value) : 'Observation time unknown';

type Load = { state: 'loading' | 'ready' | 'disabled' | 'forbidden' | 'unsupported' | 'error'; page?: DataItem; error?: string };
type Review = { kind: 'collect' | 'import'; body: DataItem; key: string; filename?: string };

export function OriginExposure({ config, session, target, canWrite, enabled }: {
  config: PortalConfig; session: Session; target: DataItem; canWrite: boolean; enabled: boolean;
}) {
  const targetId = text(target.id);
  const path = `/v1/targets/${encodeURIComponent(targetId)}/origin-clues`;
  const [load, setLoad] = useState<Load>({ state: 'loading' });
  const [refresh, setRefresh] = useState(0);
  const [busy, setBusy] = useState(false);
  const [pageBusy, setPageBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [formOpen, setFormOpen] = useState(false);
  const [sourceKind, setSourceKind] = useState('historical_dns');
  const [sourceRef, setSourceRef] = useState('');
  const [file, setFile] = useState<{ name: string; content: string } | null>(null);
  const [fileBusy, setFileBusy] = useState(false);
  const [includeMail, setIncludeMail] = useState(false);
  const [review, setReview] = useState<Review | null>(null);
  const controllerRef = useRef<AbortController | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const fileGeneration = useRef(0);
  const readGeneration = useRef(0);

  useEffect(() => {
    const controller = new AbortController();
    controllerRef.current?.abort();
    controllerRef.current = controller;
    readGeneration.current += 1;
    setLoad({ state: 'loading' }); setError(''); setBusy(false); setPageBusy(false); setReview(null); setFileBusy(false);
    if (!enabled) setLoad({ state: 'disabled' });
    else void requestJson(config, session, `${path}?limit=50`, { signal: controller.signal }).then((payload) => {
      if (!controller.signal.aborted) setLoad({ state: 'ready', page: originCluesPage(payload, targetId) });
    }).catch((failure) => {
      if (!controller.signal.aborted) setLoad({ state: originCluesErrorState(failure), error: apiErrorMessage(failure, 'Origin associations could not be loaded.') });
    });
    return () => { controller.abort(); fileGeneration.current += 1; };
  }, [config, session, path, targetId, refresh, enabled]);

  async function more() {
    const cursor = text(load.page?.next_cursor);
    const controller = controllerRef.current;
    if (!cursor || pageBusy || !controller || controller.signal.aborted) return;
    const generation = readGeneration.current;
    setPageBusy(true); setError('');
    try {
      const payload = originCluesPage(await requestJson(config, session, `${path}?limit=50&cursor=${encodeURIComponent(cursor)}`, { signal: controller.signal }), targetId);
      if (controller.signal.aborted || generation !== readGeneration.current) return;
      setLoad((current) => {
        const byId = new Map([...itemsOf(current.page?.items), ...itemsOf(payload.items)].map((row) => [text(row.id), row]));
        return { state: 'ready', page: { ...payload, items: [...byId.values()] } };
      });
    } catch (failure) {
      if (controller.signal.aborted || generation !== readGeneration.current) return;
      const state = originCluesErrorState(failure);
      if (state === 'forbidden' || state === 'disabled') setLoad({ state });
      else setError(apiErrorMessage(failure, 'More associations could not be loaded. Previously loaded records are still shown.'));
    } finally { if (generation === readGeneration.current) setPageBusy(false); }
  }

  async function chooseFile(chosen: File | undefined) {
    const generation = ++fileGeneration.current;
    setFile(null); setError(''); setFileBusy(false);
    if (!chosen) return;
    if (chosen.size > ORIGIN_IMPORT_MAX_BYTES) { setError('Choose a file smaller than 128 KiB.'); return; }
    setFileBusy(true);
    try {
      const content = await chosen.text();
      if (generation === fileGeneration.current) setFile({ name: chosen.name, content });
    } catch { if (generation === fileGeneration.current) setError('The records file could not be read. Try selecting it again.'); }
    finally { if (generation === fileGeneration.current) setFileBusy(false); }
  }

  function reviewImport() {
    setError('');
    try {
      const body = originClueImportBody({ sourceKind, sourceRef, content: file?.content ?? '' });
      setReview({ kind: 'import', body, key: crypto.randomUUID(), filename: file?.name });
    } catch (failure) { setError(failure instanceof Error ? failure.message : 'The import could not be reviewed.'); }
  }

  async function confirm() {
    const controller = controllerRef.current;
    if (!review || !controller || controller.signal.aborted || busy || !canWrite || !enabled || load.state !== 'ready') return;
    const action = review;
    setBusy(true); setError(''); setMessage('');
    try {
      const payload = record(await requestJson(config, session, `${path}/${action.kind}`, {
        method: 'POST', body: action.body, headers: { 'Idempotency-Key': action.key }, signal: controller.signal,
      }));
      if (controller.signal.aborted) return;
      if (payload.target_id !== targetId) throw new Error('The association update did not match this target. Refresh to read its persisted state.');
      const created = Number.isInteger(payload.created) ? Number(payload.created) : null;
      const duplicate = Number.isInteger(payload.deduplicated) ? Number(payload.deduplicated) : null;
      setMessage(`${action.kind === 'collect' ? 'DNS collection' : 'Record import'} recorded${created !== null ? `: ${created} new associations` : ''}${duplicate !== null ? `; ${duplicate} duplicates` : ''}. No targets, origin relations or application probes were created. These are partial source observations, not verified origins.`);
      setReview(null); setFormOpen(false); setFile(null);
      setRefresh((value) => value + 1);
      heading.current?.focus({ preventScroll: true });
    } catch (failure) {
      if (!controller.signal.aborted) setError(apiErrorMessage(failure, 'The origin association action could not be completed. Retry uses the same idempotency key.'));
    } finally { if (!controller.signal.aborted) setBusy(false); }
  }

  const items = itemsOf(load.page?.items);
  const coverage = record(load.page?.coverage);
  const sources = itemsOf(coverage.sources);
  const unavailable = sources.filter((source) => source.status === 'unavailable').length;
  const ready = enabled && load.state === 'ready';
  const canMutate = ready && canWrite && !busy;
  const relationsHref = `${buildDetailHref('target-detail', targetId)}&tab=overview&section=origin-relations`;
  const disabledCopy = load.state === 'disabled' ? 'Optional origin associations are not enabled for this tenant. An administrator can opt this tenant in; core target validation and declared origin relations remain available.'
    : load.state === 'forbidden' ? 'Your role cannot read this target’s origin associations. No exposure conclusion can be drawn from unavailable records.'
      : load.state === 'unsupported' ? 'This server does not provide origin associations yet. Existing origin relations remain available below.' : '';

  return <section className="td-origin-exposure" aria-labelledby="td-origin-exposure-title" data-state={load.state}>
    <header className="td-section-head">
      <div>
        <div className="oe-eyebrow"><Network size={14} aria-hidden="true" /><span>Outside-in · Optional enrichment</span></div>
        <h2 id="td-origin-exposure-title" ref={heading} tabIndex={-1}>Origin exposure</h2>
        <p>Review public address associations, then validate only origins you declare and independently verify.</p>
      </div>
      <Badge tone="muted">{load.state === 'disabled' ? 'Not enabled' : 'No automatic probing'}</Badge>
    </header>

    {disabledCopy ? null : <ol className="oe-workflow" aria-label="Origin validation steps">
      <li><span className="oe-step" aria-hidden="true">1</span><div><strong>Review associations</strong><p>DNS and imported records are clues, not ownership or application proof.</p></div></li>
      <li><span className="oe-step" aria-hidden="true">2</span><div><strong>Declare and verify</strong><p>Declare the IP separately, prove ownership, then bind its exact Host/SNI scope.</p></div></li>
      <li><span className="oe-step" aria-hidden="true">3</span><div><strong>Review a bounded check</strong><p>Direct responses, policy violations and paired identity proof remain distinct.</p></div></li>
    </ol>}

    {message ? <p className="form-banner" role="status">{message}</p> : null}
    {load.state === 'loading' ? <div className="oe-notice" role="status">Reading persisted origin associations. No DNS queries or application probes are started by this page.</div> : null}
    {disabledCopy ? <p className="oe-notice" role="note">{disabledCopy}</p> : null}
    {load.state === 'error' ? <div className="oe-notice" role="alert"><p>{load.error}</p><Button variant="secondary" size="sm" onClick={() => setRefresh((value) => value + 1)}>Retry associations</Button></div> : null}
    {error && !review ? <p className="td-form-error" role="alert">{error}</p> : null}

    {ready ? <>
      <div className="oe-toolbar">
        <div><h3>Public associations</h3><p className="td-muted small">{items.length} loaded record{items.length === 1 ? '' : 's'}{text(load.page?.next_cursor) ? ' · More available' : ''} · Partial source coverage</p></div>
        <div className="td-actions">
          <Button size="sm" variant="ghost" disabled={busy || pageBusy} onClick={() => setRefresh((value) => value + 1)}><RefreshCw size={14} aria-hidden="true" />Refresh records</Button>
          {canWrite ? <>
            <Button size="sm" variant="secondary" disabled={!canMutate} onClick={() => { setFormOpen((value) => !value); setError(''); }} aria-expanded={formOpen} aria-controls="oe-import-form"><FileUp size={14} aria-hidden="true" />Import records</Button>
            <Button size="sm" disabled={!canMutate} onClick={() => { setError(''); setReview({ kind: 'collect', body: { include_mail: includeMail }, key: crypto.randomUUID() }); }}>Review DNS collection</Button>
          </> : null}
        </div>
      </div>
      {unavailable ? <p className="oe-notice" role="status">{unavailable} DNS source question{unavailable === 1 ? ' was' : 's were'} unavailable in the latest collection. Recorded associations may be incomplete; this is not evidence that the origin is hidden.</p> : null}
      {!canWrite ? <p className="td-muted small">Read-only role. Collecting or importing associations requires target write access.</p> : null}
      {formOpen ? <form className="td-declaration-form oe-import" id="oe-import-form" onSubmit={(event) => { event.preventDefault(); reviewImport(); }}>
        <h3>Import origin association records</h3>
        <p className="td-muted small">Supply records you are authorized to use. Nothing is downloaded from the source reference. No candidate address is contacted.</p>
        <label className="td-field"><span id="oe-source-label">Record source</span><select aria-labelledby="oe-source-label" value={sourceKind} disabled={busy} onChange={(event) => { setSourceKind(event.target.value); setError(''); }}>
          <option value="historical_dns">Historical DNS · JSON</option><option value="certificate_host">Certificate host index · JSON</option><option value="trickest_csv">Trickest certificate dataset · CSV</option>
        </select></label>
        <label className="td-field"><span id="oe-reference-label">Source reference</span><input aria-labelledby="oe-reference-label" value={sourceRef} maxLength={512} required disabled={busy} onChange={(event) => setSourceRef(event.target.value)} aria-describedby="oe-reference-help" /><span id="oe-reference-help" className="td-muted small">A report name, dataset revision or reference. Recorded as provenance, never fetched.</span></label>
        <label className="td-field"><span id="oe-file-label">Records file</span><input aria-labelledby="oe-file-label" type="file" accept={sourceKind === 'trickest_csv' ? '.csv,text/csv' : '.json,application/json'} disabled={busy} onChange={(event) => void chooseFile(event.target.files?.[0])} aria-describedby="oe-file-help" /><span id="oe-file-help" className="td-muted small">Up to 200 records; the complete request must fit 128 KiB. Certificate-index CSV supports the documented IP Address, Common Name and Subject Alternative DNS Name columns.</span></label>
        <details className="oe-details"><summary>JSON format and evidence limits</summary><p>Use an array of records with <code>candidate_ip</code> and <code>associated_hostname</code>; optionally include <code>source_observed_at</code>. Certificate-host imports also require <code>certificate_names</code> with a matching exact or valid one-label wildcard name. Only this domain and its descendants are accepted. Unknown observation times stay unknown. Certificates and historical records may be stale or shared.</p></details>
        <div className="row-actions"><Button type="submit" size="sm" disabled={!file || fileBusy || busy || !sourceRef.trim()}>Review import</Button><Button size="sm" variant="ghost" disabled={busy} onClick={() => { setFormOpen(false); setError(''); }}>Cancel import</Button></div>
        {fileBusy ? <p role="status">Reading selected file locally…</p> : null}
      </form> : null}
      {items.length ? <ul className="oe-clues" aria-label="Recorded origin associations">{items.map((item) => <li key={text(item.id)} className="oe-clue">
        <div className="oe-clue-main"><div className="oe-address"><span className="mono">{text(item.candidate_ip) || text(item.related_hostname) || 'Hostname association only'}</span><Badge tone="warn">Unverified association</Badge></div><p className="td-muted small"><span className="mono">{text(item.associated_hostname)}</span> · {originClueSourceLabel(text(item.source_kind))}{item.address_family ? ` · IPv${item.address_family}` : ''}</p></div>
        <dl className="oe-times"><div><dt>Source observed</dt><dd>{when(item.source_observed_at)}</dd></div><div><dt>Imported / collected</dt><dd>{when(item.retrieved_at)}</dd></div></dl>
        <details className="oe-details"><summary>Source and limitations</summary><dl className="oe-source"><div><dt>Reference</dt><dd>{text(item.source_ref) || 'Not recorded'}</dd></div><div><dt>Record</dt><dd className="mono">{text(item.id)}</dd></div><div><dt>Source digest</dt><dd className="mono">{text(item.source_digest) || 'Not recorded'}</dd></div><div><dt>Address-index hint</dt><dd>{item.edge_classification === 'known_edge' ? 'Known CDN edge range; not origin identity' : 'Unknown; not evidence that an address is an origin'}</dd></div>{text(item.reference) ? <div><dt>DNS reference</dt><dd className="mono">{text(item.reference)}</dd></div> : null}{strings(item.certificate_names).length ? <div><dt>Certificate names</dt><dd className="mono">{strings(item.certificate_names).join(', ')}</dd></div> : null}</dl><p>No ownership, origin identity, lockdown or capacity assurance. {strings(item.limitations).map((value) => value.replace(/_/g, ' ')).join('; ')}.</p><a href="#targets">Declare an address separately in Targets</a></details>
      </li>)}</ul> : <div className="oe-empty"><ArrowDownToLine size={22} aria-hidden="true" /><div><h3>No associations recorded</h3><p>No association observed in these sources. This does not mean the origin is hidden or protected. Collect bounded DNS records or import a source you have reviewed.</p></div></div>}
      {text(load.page?.next_cursor) ? <Button size="sm" variant="secondary" loading={pageBusy} disabled={busy} onClick={() => void more()}>Load more associations</Button> : null}
      <details className="oe-details"><summary>Source coverage and what this cannot prove</summary><p>Coverage is partial. Collection reads only this declared hostname’s DNS (and separately selected declared hosts, when supplied). It does not resolve mail-provider hosts, expand SPF ranges, scan cloud networks or fetch certificate datasets.</p>{sources.length ? <ul aria-label="Latest source coverage">{sources.map((source, index) => <li key={`${text(source.hostname)}:${text(source.type)}:${index}`}><span className="mono">{text(source.hostname)} {text(source.type)}</span>{text(source.source_kind) ? ` ${originClueSourceLabel(text(source.source_kind))}` : ''} · {source.status === 'unavailable' ? 'Unavailable — no conclusion' : source.status === 'no_answer' ? 'No answer observed — not protection evidence' : source.status === 'observed' ? 'DNS response recorded' : source.status === 'supplied_import' ? 'Supplied import only' : 'Partial / omitted record'}{source.truncated === true ? ' · Answer list truncated' : ''}</li>)}</ul> : null}<p>CT contains hostname clues, not a current origin-IP map. Certificate/history imports do not prove the same application is still served. Repeated or shared feeds are not independent confirmation.</p>{strings(coverage.limitations).length ? <ul>{strings(coverage.limitations).map((limitation) => <li key={limitation}>{limitation.replace(/_/g, ' ')}</li>)}</ul> : null}<p>AstraNull observes exposure from outside. Queries to passive third-party indexes are not reliably visible in target logs; this is not an attacker-discovery detector.</p></details>
    </> : null}
    {disabledCopy ? null : <p className="oe-boundary">Ready to validate an address you own? <a href={relationsHref}>Review declared origin relations below</a>. Selecting or inspecting an association sends no traffic to it.</p>}

    <ConfirmModal open={review !== null} title={review?.kind === 'collect' ? 'Collect DNS associations for this target?' : 'Import these origin associations?'} confirmLabel={review?.kind === 'collect' ? 'Collect DNS records' : 'Import associations'} busy={busy} onCancel={() => { setReview(null); setError(''); }} onConfirm={() => void confirm()} description={<div className="stack-tight scan-review">
      <dl className="td-review-list"><div><dt>Declared target</dt><dd className="mono">{text(target.value)} ({targetId})</dd></div><div><dt>Action</dt><dd>{review?.kind === 'collect' ? 'Bounded DNS collection; no HTTP/TLS requests to candidate addresses' : 'Append supplied source records; no network collection'}</dd></div>{review?.filename ? <div><dt>Local file</dt><dd>{review.filename}</dd></div> : null}{review?.kind === 'import' ? <div><dt>Source</dt><dd>{originClueSourceLabel(text(review.body.source_kind))}: {text(review.body.source_ref)}</dd></div> : null}</dl>
      {review?.kind === 'collect' ? <label className="oe-checkbox"><input type="checkbox" checked={includeMail} disabled={busy} onChange={(event) => { setIncludeMail(event.target.checked); setReview((current) => current ? { ...current, body: { ...current.body, include_mail: event.target.checked }, key: crypto.randomUUID() } : null); }} /><span>Include this hostname’s MX/TXT associations (referenced hosts are not resolved).</span></label> : null}
      <p>Records are retained with source provenance and an audit entry. No target is added, no origin relation is created, and no application check starts. Public association is not permission to probe.</p>
      {error && review ? <p className="td-form-error" role="alert">{error}</p> : null}
    </div>} />
  </section>;
}
