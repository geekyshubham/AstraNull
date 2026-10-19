import { useEffect, useId, useRef, useState } from 'react';
import { LayoutPanelTop, Pencil, Plus, RefreshCw, Sparkles, Trash2 } from 'lucide-react';
import { requestJson, sessionIdentity } from '../../lib/api';
import { cancelAssistantJob } from '../../lib/assistant-api';
import { sanitizeQueuedJob, unavailableMessage, useStructuredJob, type QueuedJob } from '../../lib/assistant-jobs';
import { sanitizeWidget, sanitizeWidgetCommentary, sanitizeWidgetConfig, sanitizeWidgetData, sanitizeWidgetDefinition, type PersonalWidget, type WidgetConfig, type WidgetData, type WidgetDefinition } from '../../lib/assistant-widgets.mjs';
import { sessionHasPermission } from '../../lib/dataset-access.mjs';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import { formatDate } from '../../lib/utils';
import { Button } from '../ui/button';
import { ConfirmModal } from '../../lib/crud-ui';
import { AiStatusBadge } from './ai-status-badge';
import './ai-motion.css';
import './personal-widgets.css';

type Props = { config: PortalConfig; session: Session; targets: DataItem[]; enabled: boolean };
type ApiBody = Record<string, unknown>;
const EMPTY_CONFIG: WidgetConfig = { name: '', question: '', template: 'summary' };
const errorCopy = 'This widget could not be loaded or saved. If it changed elsewhere, reload the widgets before editing again.';

function WidgetResult({ data, template }: { data: WidgetData; template: WidgetConfig['template'] }) {
  return <div className="personal-widget-result ai-fade">
    <div className="personal-widget-number"><strong>{data.count.toLocaleString()}</strong><span>{data.count_is_total ? 'matching findings' : 'findings in the bounded sample'}</span></div>
    {!data.count_is_total ? <p className="muted small">This sample is incomplete. It is not a workspace total or a readiness score.</p> : null}
    {template === 'finding_list' && data.rows.length ? <ul className="personal-widget-findings">{data.rows.map((row) => <li key={row.id}><a href={`#finding-detail?id=${encodeURIComponent(row.id)}`}>{row.title}</a><span className="muted small">{row.severity} · {row.status.replaceAll('_', ' ')}</span></li>)}</ul> : null}
    {data.count === 0 ? <p className="muted">No matching findings in the returned data. This is not proof of protection.</p> : null}
    <p className="muted small">Data refreshed {formatDate(data.observed_at)} · external evidence only</p>
  </div>;
}

function WidgetNarrative({ config, session, queued, data, onCancel, onSettled }: { config: PortalConfig; session: Session; queued: QueuedJob | null; data: WidgetData | null; onCancel: () => void; onSettled: () => void }) {
  const job = useStructuredJob(config, session, queued, 'widget_commentary', (value) => sanitizeWidgetCommentary(value, data));
  useEffect(() => { if (job.value || job.failed) onSettled(); }, [job.value, job.failed, onSettled]);
  return <>
    {job.pending ? <div className="personal-widget-actions" role="status"><AiStatusBadge pending ai={false} seconds={job.seconds} /><Button size="sm" variant="ghost" onClick={onCancel}>Cancel AI</Button></div> : null}
    {job.value ? <aside className="personal-widget-commentary"><span className="ai-badge is-ai">AI commentary · advisory</span><p>{job.value.text}</p>{job.value.citations.length ? <div className="personal-widget-citations" aria-label="Commentary sources">{job.value.citations.map((id, index) => <a key={id} href={`#finding-detail?id=${encodeURIComponent(id)}`}>Finding {index + 1}</a>)}</div> : null}</aside> : null}
    {unavailableMessage(queued, job.failed, 'the observed data remains available') ? <p className="muted small" role="status">{unavailableMessage(queued, job.failed, 'the observed data remains available')}</p> : null}
  </>;
}

function SavedWidget({ widget, config, session, onEdit, onRemove, onReload }: { widget: PersonalWidget; config: PortalConfig; session: Session; onEdit: () => void; onRemove: () => void; onReload: () => void }) {
  const [data, setData] = useState<WidgetData | null>(null);
  const [queued, setQueued] = useState<QueuedJob | null>(null);
  const [aiBusy, setAiBusy] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const request = useRef<AbortController | null>(null);
  const currentJob = useRef<QueuedJob | null>(null);
  currentJob.current = queued;
  async function refresh(narrative: boolean) {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setBusy(true); setError(''); setQueued(null);
    try {
      // Preserve a late AI creation response so disposal can cancel the server job too.
      const response = await requestJson(config, session, `/v1/assistant/widgets/${encodeURIComponent(widget.id)}/refresh`, { method: 'POST', body: { narrative }, ...(narrative ? {} : { signal: controller.signal }) }) as ApiBody;
      const nextQueued = sanitizeQueuedJob(response.narrative);
      if (controller.signal.aborted) {
        if (nextQueued.status === 'queued') void cancelAssistantJob(config, session, nextQueued.jobId).catch(() => {});
        return;
      }
      const definition = sanitizeWidget(response.widget);
      const next = sanitizeWidgetData(response.data);
      if (!definition || definition.id !== widget.id || definition.version !== widget.version || JSON.stringify(definition.config) !== JSON.stringify(widget.config) || !next) {
        if (nextQueued.status === 'queued') void cancelAssistantJob(config, session, nextQueued.jobId).catch(() => {});
        throw new Error('invalid or changed widget data');
      }
      currentJob.current = nextQueued;
      setData(next); setQueued(nextQueued); setAiBusy(nextQueued.status === 'queued');
    } catch {
      if (!controller.signal.aborted) { setData(null); setError('Widget data is unavailable or its saved definition changed. Reload widgets before trying again.'); }
    } finally { if (!controller.signal.aborted) setBusy(false); }
  }
  useEffect(() => {
    void refresh(false);
    return () => {
      request.current?.abort();
      if (currentJob.current?.status === 'queued') void cancelAssistantJob(config, session, currentJob.current.jobId).catch(() => {});
    };
  }, [config, session, widget.id, widget.version]);
  function cancel() {
    if (queued?.status === 'queued') void cancelAssistantJob(config, session, queued.jobId).catch(() => setError('Cancellation could not be confirmed. The request may still finish.'));
    currentJob.current = null;
    setQueued(null); setAiBusy(false);
  }
  return <article className="personal-widget-card" aria-label={widget.config.name}>
    <header><div><span className="personal-widget-eyebrow">Personal · {widget.config.template === 'summary' ? 'Measured summary' : 'Finding list'}</span><h3>{widget.config.name}</h3></div><div className="personal-widget-actions"><Button size="sm" variant="ghost" aria-label={`Edit ${widget.config.name}`} disabled={busy || aiBusy} onClick={onEdit}><Pencil size={15} aria-hidden="true" /></Button><Button size="sm" variant="ghost" aria-label={`Remove ${widget.config.name}`} disabled={busy} onClick={onRemove}><Trash2 size={15} aria-hidden="true" /></Button></div></header>
    <p className="personal-widget-question">{widget.config.question}</p>
    {data ? <WidgetResult data={data} template={widget.config.template} /> : null}
    {busy ? <p className="muted small" role="status">Reading current evidence…</p> : null}
    {error ? <div className="personal-widget-actions"><p className="field-error small" role="alert">{error}</p><Button size="sm" variant="secondary" onClick={onReload}>Reload widgets</Button></div> : null}
    <WidgetNarrative config={config} session={session} queued={queued} data={data} onCancel={cancel} onSettled={() => setAiBusy(false)} />
    <footer className="personal-widget-actions"><Button size="sm" variant="secondary" disabled={busy} onClick={() => { cancel(); void refresh(false); }}><RefreshCw size={14} aria-hidden="true" />Refresh data</Button><Button size="sm" variant="ghost" disabled={busy || aiBusy} onClick={() => void refresh(true)}><Sparkles size={14} aria-hidden="true" />Ask AI</Button></footer>
  </article>;
}

function WidgetEditor({ widget, config, session, targets, onClose, onSaved }: { widget: PersonalWidget | null; config: PortalConfig; session: Session; targets: DataItem[]; onClose: () => void; onSaved: () => void }) {
  const prefix = useId();
  const [draft, setDraft] = useState<WidgetConfig>(widget?.config ?? EMPTY_CONFIG);
  const [preview, setPreview] = useState<WidgetData | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const controller = useRef<AbortController | null>(null);
  const nameInput = useRef<HTMLInputElement>(null);
  useEffect(() => { nameInput.current?.focus(); return () => controller.current?.abort(); }, []);
  function change(next: WidgetConfig) { setDraft(next); setPreview(null); setError(''); }
  const valid = sanitizeWidgetConfig(draft);
  async function submit(save: boolean) {
    if (!valid || (save && !preview)) return;
    controller.current?.abort(); const request = new AbortController(); controller.current = request;
    setBusy(true); setError('');
    try {
      const url = save ? `/v1/assistant/widgets${widget ? `/${encodeURIComponent(widget.id)}` : ''}` : '/v1/assistant/widgets/preview';
      const response = await requestJson(config, session, url, { method: save && widget ? 'PATCH' : 'POST', body: save ? { config: valid, ...(widget ? { expected_version: widget.version } : {}) } : { config: valid, narrative: false }, signal: request.signal }) as ApiBody;
      if (request.signal.aborted) return;
      if (save) { if (!sanitizeWidget(response.widget)) throw new Error('invalid widget'); onSaved(); }
      else { const data = sanitizeWidgetData(response.data); if (!data) throw new Error('invalid preview'); setPreview(data); }
    } catch { if (!request.signal.aborted) setError(errorCopy); }
    finally { if (!request.signal.aborted) setBusy(false); }
  }
  return <section className="personal-widget-editor" aria-labelledby={`${prefix}-heading`}>
    <div><span className="personal-widget-eyebrow">Read-only by design</span><h3 id={`${prefix}-heading`}>{widget ? 'Edit personal widget' : 'Create personal widget'}</h3><p className="muted small">Choose measured data, then preview it. Your question is saved privately; only Ask AI sends it for optional commentary. Do not include secrets.</p></div>
    <form onSubmit={(event) => { event.preventDefault(); void submit(false); }} className="personal-widget-form">
      <label className="field full" htmlFor={`${prefix}-name`}><span>Widget name</span><input ref={nameInput} id={`${prefix}-name`} value={draft.name} maxLength={80} required disabled={busy} onChange={(event) => change({ ...draft, name: event.target.value })} placeholder="High-priority review" /></label>
      <label className="field full" htmlFor={`${prefix}-template`}><span id={`${prefix}-template-label`}>Display</span><select aria-labelledby={`${prefix}-template-label`} id={`${prefix}-template`} className="input" value={draft.template} disabled={busy} onChange={(event) => change({ ...draft, template: event.target.value as WidgetConfig['template'] })}><option value="summary">Measured summary</option><option value="finding_list">Finding list</option></select></label>
      <label className="field full personal-widget-form-wide" htmlFor={`${prefix}-question`}><span id={`${prefix}-question-label`}>Question for optional AI commentary</span><textarea aria-labelledby={`${prefix}-question-label`} id={`${prefix}-question`} rows={2} value={draft.question} maxLength={500} required disabled={busy} onChange={(event) => change({ ...draft, question: event.target.value })} placeholder="What should I review first, based on these findings?" /><span className="muted small">The filters below define the data. A question does not change them or create a new metric.</span></label>
      <label className="field full" htmlFor={`${prefix}-severity`}><span id={`${prefix}-severity-label`}>Severity</span><select aria-labelledby={`${prefix}-severity-label`} id={`${prefix}-severity`} className="input" value={draft.severity ?? ''} disabled={busy} onChange={(event) => { const { severity: _severity, ...rest } = draft; change(event.target.value ? { ...rest, severity: event.target.value } : rest); }}><option value="">All severities</option>{['critical', 'high', 'medium', 'low', 'info', 'unknown'].map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
      {sessionHasPermission(session, 'target_group:read') ? <label className="field full" htmlFor={`${prefix}-target`}><span id={`${prefix}-target-label`}>Declared target</span><select aria-labelledby={`${prefix}-target-label`} id={`${prefix}-target`} className="input" value={draft.target_id ?? ''} disabled={busy} onChange={(event) => { const { target_id: _target, ...rest } = draft; change(event.target.value ? { ...rest, target_id: event.target.value } : rest); }}><option value="">All permitted targets</option>{draft.target_id && !targets.some((target) => target.id === draft.target_id) ? <option value={draft.target_id}>{draft.target_id} · access checked on preview</option> : null}{targets.slice(0, 200).map((target) => <option key={String(target.id)} value={String(target.id)}>{String(target.value ?? target.name ?? target.id)}</option>)}</select></label> : null}
      <div className="personal-widget-actions personal-widget-form-wide"><Button type="submit" variant="secondary" size="sm" disabled={!valid || busy} loading={busy}>Preview data</Button><Button type="button" variant="default" size="sm" disabled={!preview || busy} onClick={() => void submit(true)}>{widget ? 'Save changes' : 'Save widget'}</Button><Button type="button" variant="ghost" size="sm" disabled={busy} onClick={onClose}>Cancel</Button></div>
    </form>
    {error ? <div className="personal-widget-actions"><p className="field-error small" role="alert">{error}</p><Button size="sm" variant="secondary" disabled={busy} onClick={onSaved}>Discard draft and reload widgets</Button></div> : null}
    {preview ? <div className="personal-widget-preview" role="region" aria-label="Widget preview"><span className="personal-widget-eyebrow">Preview · not saved</span><WidgetResult data={preview} template={draft.template} /></div> : null}
  </section>;
}

function WidgetCollection({ config, session, targets }: Omit<Props, 'enabled'>) {
  const [widgets, setWidgets] = useState<WidgetDefinition[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [reload, setReload] = useState(0);
  const [editor, setEditor] = useState<PersonalWidget | 'new' | null>(null);
  const [remove, setRemove] = useState<Pick<PersonalWidget, 'id' | 'version'> | null>(null);
  const [removing, setRemoving] = useState(false);
  const [available, setAvailable] = useState(true);
  const mutation = useRef<AbortController | null>(null);
  const addButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const controller = new AbortController(); setLoading(true); setError('');
    requestJson(config, session, '/v1/assistant/widgets', { signal: controller.signal }).then((value) => {
      if (controller.signal.aborted) return;
      const rows = (value as ApiBody)?.widgets;
      if (!Array.isArray(rows) || rows.length > 12) throw new Error('invalid widgets');
      const parsed = rows.map(sanitizeWidgetDefinition);
      if (parsed.some((row) => !row) || new Set(parsed.map((row) => row?.id)).size !== parsed.length) throw new Error('invalid widgets');
      setWidgets(parsed as WidgetDefinition[]); setAvailable(true);
    }).catch(() => { if (!controller.signal.aborted) { setWidgets([]); setAvailable(false); setError('Personal widgets are unavailable for this session. Existing dashboard data is unaffected.'); } }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [config, session, reload]);
  useEffect(() => () => mutation.current?.abort(), []);
  function closeEditor() { setEditor(null); window.requestAnimationFrame(() => addButton.current?.focus()); }
  async function deleteWidget() {
    if (!remove) return;
    const controller = new AbortController(); mutation.current = controller; setRemoving(true);
    try {
      await requestJson(config, session, `/v1/assistant/widgets/${encodeURIComponent(remove.id)}`, { method: 'DELETE', body: { expected_version: remove.version }, signal: controller.signal });
      if (!controller.signal.aborted) { setRemove(null); setReload((value) => value + 1); }
    } catch { if (!controller.signal.aborted) { setRemove(null); setError(errorCopy); } }
    finally { if (!controller.signal.aborted) setRemoving(false); }
  }
  return <section className="personal-widgets" aria-labelledby="personal-widgets-title">
    <header className="personal-widgets-header"><div><span className="personal-widget-eyebrow"><LayoutPanelTop size={14} aria-hidden="true" />Your workspace, your lens</span><h2 id="personal-widgets-title">Personal AI widgets</h2><p className="muted small">Saved views of observed findings. Measured data first, optional AI commentary second.</p></div><Button ref={addButton} size="sm" variant="secondary" disabled={!available || loading || widgets.length >= 12 || editor !== null} onClick={() => setEditor('new')}><Plus size={15} aria-hidden="true" />Add widget</Button></header>
    {error ? <div className="personal-widget-actions"><p className="field-error small" role="alert">{error}</p><Button variant="ghost" size="sm" onClick={() => { setEditor(null); setReload((value) => value + 1); }}>Reload widgets</Button></div> : null}
    {loading ? <p className="muted small" role="status">Loading personal widget definitions…</p> : null}
    {editor ? <WidgetEditor key={editor === 'new' ? 'new' : `${editor.id}:${editor.version}`} widget={editor === 'new' ? null : editor} config={config} session={session} targets={targets} onClose={closeEditor} onSaved={() => { closeEditor(); setReload((value) => value + 1); }} /> : null}
    {!loading && available && !widgets.length && !editor ? <div className="personal-widget-empty"><LayoutPanelTop size={24} aria-hidden="true" /><div><h3>A focused view, without a new dashboard</h3><p className="muted small">Create a finding list or measured summary for a declared target or severity. No checks run and no settings change.</p></div></div> : null}
    {!loading ? <div className="personal-widget-grid">{widgets.map((widget) => 'unavailable' in widget ? <article key={`${widget.id}:${widget.version}`} className="personal-widget-card" aria-label="Unavailable personal widget"><header><h3>Unavailable personal widget</h3></header><p className="muted small">Its target scope is not available in this session. The saved definition still uses one slot. Remove it to free that slot without changing any findings or targets.</p><Button size="sm" variant="ghost" disabled={removing} onClick={() => setRemove(widget)}><Trash2 size={15} aria-hidden="true" />Remove unavailable widget</Button></article> : <SavedWidget key={`${widget.id}:${widget.version}`} widget={widget} config={config} session={session} onEdit={() => setEditor(widget)} onRemove={() => setRemove(widget)} onReload={() => setReload((value) => value + 1)} />)}</div> : null}
    <ConfirmModal open={Boolean(remove)} title="Remove personal widget?" description="This removes only your saved widget definition. Findings, evidence and targets remain unchanged." confirmLabel="Remove widget" confirmTone="danger" busy={removing} onCancel={() => setRemove(null)} onConfirm={() => void deleteWidget()} />
  </section>;
}

export function PersonalWidgets({ enabled, ...props }: Props) {
  const boundary = useRef({ identity: '', credential: '', epoch: 0 });
  const identity = sessionIdentity(props.session);
  const credential = props.session.access_token ?? '';
  if (boundary.current.identity !== identity || boundary.current.credential !== credential) {
    boundary.current = { identity, credential, epoch: boundary.current.epoch + 1 };
  }
  if (!enabled || props.session.staff_role || props.session.staff_id || !sessionHasPermission(props.session, 'finding:read')) return null;
  return <WidgetCollection key={boundary.current.epoch} {...props} />;
}
