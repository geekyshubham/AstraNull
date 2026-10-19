import { useEffect, useRef, useState } from 'react';
import { requestJson, sessionIdentity } from '../../lib/api';
import { useAssistantStatus, assistantAvailable } from '../../lib/assistant-api';
import { sanitizeQueuedJob, useStructuredJob, unavailableMessage, type QueuedJob } from '../../lib/assistant-jobs';
import { sanitizeFixPack, fixPackCopyText, type FixPack, type FixPackScope } from '../../lib/assistant-fix-packs.mjs';
import type { PortalConfig, Session } from '../../lib/types';
import { AiStatusBadge } from '../assistant/ai-status-badge';
import { Button } from '../ui/button';
import './provider-fix-pack.css';

type Props = { config: PortalConfig; session: Session; scope: FixPackScope };

/** A changed session/provider/finding unmounts all old output before it can render. */
export function ProviderFixPack(props: Props) {
  const identity = `${sessionIdentity(props.session)}:${props.session.expires_at ?? ''}:${props.scope.findingId}:${props.scope.provider}:${props.scope.controlFamily}:${props.scope.docs.join('|')}`;
  const epoch = useRef({ identity, credential: props.session.access_token, revision: 0 });
  if (epoch.current.identity !== identity || epoch.current.credential !== props.session.access_token) {
    epoch.current = { identity, credential: props.session.access_token, revision: epoch.current.revision + 1 };
  }
  return <FixPackRequest key={epoch.current.revision} {...props} />;
}

function FixPackRequest({ config, session, scope }: Props) {
  const { status } = useAssistantStatus(config, session);
  const [baseline, setBaseline] = useState<FixPack | null>(null);
  const [queued, setQueued] = useState<QueuedJob | null>(null);
  const [requesting, setRequesting] = useState(false);
  const [message, setMessage] = useState('');
  const [copied, setCopied] = useState(false);
  const generation = useRef(0);
  const currentJob = useRef('');
  const structured = useStructuredJob(config, session, queued, 'fix_pack', (value) => sanitizeFixPack(value, scope));
  const cancelRemote = (id: string) => { if (id) void requestJson(config, session, `/v1/assistant/jobs/${encodeURIComponent(id)}`, { method: 'DELETE' }).catch(() => undefined); };
  useEffect(() => () => {
    generation.current += 1;
    // Keep a bounded creation request alive long enough to learn and cancel a late job ID.
    const id = currentJob.current;
    if (id) void requestJson(config, session, `/v1/assistant/jobs/${encodeURIComponent(id)}`, { method: 'DELETE' }).catch(() => undefined);
  }, [config, session]);
  // A completed job no longer needs cancellation, but cancelling it is also safe server-side.
  const pending = requesting || Boolean(queued?.status === 'queued' && !structured.value && !structured.failed);
  const pack = structured.value ?? baseline;

  async function generate() {
    cancelRemote(currentJob.current);
    currentJob.current = '';
    const attempt = ++generation.current;
    const abort = new AbortController();
    const timeout = window.setTimeout(() => abort.abort(), 20_000);
    setRequesting(true); setMessage(''); setCopied(false); setQueued(null); setBaseline(null);
    try {
      const result = await requestJson(config, session, '/v1/assistant/fix-packs', { method: 'POST', body: { finding_id: scope.findingId, provider: scope.provider }, signal: abort.signal }) as Record<string, unknown>;
      const next = sanitizeQueuedJob(result?.narrative);
      if (attempt !== generation.current || abort.signal.aborted) { cancelRemote(next.jobId); return; }
      const staticPack = sanitizeFixPack(result?.pack, scope);
      if (!staticPack) { cancelRemote(next.jobId); throw new Error('invalid_fix_pack'); }
      setBaseline(staticPack); setQueued(next); currentJob.current = next.jobId;
    } catch {
      if (attempt === generation.current) setMessage('The fix pack could not be generated. Your original provider guidance is unchanged. Try again.');
    } finally {
      window.clearTimeout(timeout);
      if (attempt === generation.current) setRequesting(false);
    }
  }

  function cancel() {
    generation.current += 1; cancelRemote(currentJob.current);
    currentJob.current = ''; setQueued(null); setRequesting(false); setMessage('Generation cancelled. Original provider guidance is unchanged.');
  }

  async function copy() {
    if (!pack) return;
    const attempt = generation.current;
    try {
      await navigator.clipboard.writeText(fixPackCopyText(pack));
      if (attempt === generation.current) setCopied(true);
    } catch { if (attempt === generation.current) setMessage('Copy is unavailable. Select and copy the text manually.'); }
  }

  if (!assistantAvailable(status)) return null;
  const fallbackMessage = unavailableMessage(queued, structured.failed, 'the published fix pack and original provider guidance remain available');
  return <section className="provider-fix-pack" aria-label="Provider fix pack">
    <div className="provider-fix-pack-actions">
      <Button variant="secondary" size="sm" onClick={() => void generate()} disabled={pending}>{baseline || message ? 'Retry fix pack' : 'Generate fix pack'}</Button>
      {pending ? <Button variant="ghost" size="sm" onClick={cancel}>Cancel generation</Button> : null}
      {baseline || pending ? <AiStatusBadge pending={pending} ai={Boolean(structured.value)} seconds={structured.seconds} pendingLabel="Tailoring" /> : null}
    </div>
    <p className="muted small">Reviewable advice for this selected provider, not provider attribution. Nothing is applied or re-tested.</p>
    <div role="status" aria-live="polite">{message || fallbackMessage}</div>
    {pack ? <div className="provider-fix-pack-content">
      <h4>{pack.title}</h4>
      {(['prerequisites', 'steps', 'verification', 'rollback', 'limitations'] as const).map((key) => <section key={key}>
        <h5>{key[0].toUpperCase() + key.slice(1)}</h5>
        <ol>{pack[key].map((line, index) => <li key={index}><code className="provider-fix-pack-text">{line}</code></li>)}</ol>
      </section>)}
      {pack.sources.length ? <ul aria-label="Fix pack sources">{pack.sources.map((source) => <li key={source.id}><a href={source.url} target="_blank" rel="noopener noreferrer nofollow">{source.title}</a> <span className="muted small">{source.id}</span></li>)}</ul> : null}
      <p className="muted small">Citations: {pack.citations.join(', ')}</p>
      <p className="muted small">Advice only. Verify with your provider. Applying changes, running a re-test and closing findings remain separate, explicit actions.</p>
      <Button variant="ghost" size="sm" onClick={() => void copy()}>{copied ? 'Copied fix pack' : 'Copy fix pack'}</Button>
    </div> : null}
  </section>;
}
