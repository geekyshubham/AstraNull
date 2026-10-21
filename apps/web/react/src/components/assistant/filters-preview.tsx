import { useEffect, useId, useRef, useState } from 'react';
import { requestJson, sessionIdentity } from '../../lib/api';
import { cancelAssistantJob } from '../../lib/assistant-api';
import { sanitizeQueuedJob, unavailableMessage, useStructuredJob, type QueuedJob } from '../../lib/assistant-jobs';
import { FILTER_QUESTION_MAX, sanitizeFindingFilterPreview, type AssistantFindingFilters, type FindingFilterPreview } from '../../lib/assistant-filters.mjs';
import type { PortalConfig, Session } from '../../lib/types';
import { Button } from '../ui/button';
import './filters-preview.css';

function PreviewResult({ preview, onApply }: { preview: FindingFilterPreview; onApply: (filters: AssistantFindingFilters) => void }) {
  return (
    <div className="ai-filter-result">
      <p>{preview.explanation}</p>
      <dl className="ai-filter-predicate" aria-label="Proposed exact filters">
        {Object.entries(preview.filters).length ? Object.entries(preview.filters).map(([key, value]) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{value}</dd></div>) : <div><dt>Status</dt><dd>All findings, no filters</dd></div>}
      </dl>
      <Button type="button" size="sm" onClick={() => onApply(preview.filters)}>Apply filters</Button>
    </div>
  );
}

function QueuedPreview({ config, session, queued, onApply }: { config: PortalConfig; session: Session; queued: QueuedJob; onApply: (filters: AssistantFindingFilters) => void }) {
  const job = useStructuredJob(config, session, queued, 'filters', sanitizeFindingFilterPreview);
  return <div role="status" aria-live="polite">
    {job.value ? <PreviewResult preview={job.value} onApply={onApply} /> : <p>{job.failed ? 'No exact filter preview was returned. Try one status, severity, target, check, run, or a literal search. No filters changed.' : `Preparing filter preview… ${job.seconds}s. No filters changed.`}</p>}
  </div>;
}

function FiltersPreviewForm({ config, session, onApply, onClear }: { config: PortalConfig; session: Session; onApply: (filters: AssistantFindingFilters) => void; onClear: () => void }) {
  const labelId = useId();
  const hintId = useId();
  const [question, setQuestion] = useState('');
  const [pending, setPending] = useState(false);
  const [preview, setPreview] = useState<FindingFilterPreview | null>(null);
  const [queued, setQueued] = useState<QueuedJob | null>(null);
  const [notice, setNotice] = useState('');
  const active = useRef<AbortController | null>(null);
  const sequence = useRef(0);
  const currentJob = useRef<QueuedJob | null>(null);
  currentJob.current = queued;
  function cancelCurrent() {
    if (currentJob.current?.status === 'queued') void cancelAssistantJob(config, session, currentJob.current.jobId).catch(() => {});
    currentJob.current = null;
  }

  function invalidate() {
    sequence.current += 1;
    active.current?.abort();
    cancelCurrent();
    setPending(false);
    setPreview(null);
    setQueued(null);
    setNotice('');
  }

  useEffect(() => {
    invalidate();
    return () => { sequence.current += 1; active.current?.abort(); cancelCurrent(); };
  }, [config, session]);

  async function prepare() {
    invalidate();
    const requestSequence = sequence.current;
    const controller = new AbortController();
    active.current = controller;
    setPending(true);
    try {
      // Preserve the creation response after logical abort so a late job can be deleted.
      const result = await requestJson(config, session, '/v1/assistant/filters', { method: 'POST', body: { question: question.trim(), kind: 'findings' } }) as Record<string, unknown>;
      const job = sanitizeQueuedJob(result.narrative);
      if (controller.signal.aborted || sequence.current !== requestSequence) {
        if (job.status === 'queued') void cancelAssistantJob(config, session, job.jobId).catch(() => {});
        return;
      }
      const direct = sanitizeFindingFilterPreview({ filters: result.filters, explanation: result.interpretation });
      if (direct) setPreview(direct);
      else if (job.status === 'queued') { currentJob.current = job; setQueued(job); }
      else setNotice(unavailableMessage(job, false, 'no filters changed') || 'That request cannot be represented exactly. Try one status, severity, target, check, run, or a literal search. No filters changed.');
    } catch {
      if (!controller.signal.aborted && sequence.current === requestSequence) setNotice('Filter preview is unavailable or not allowed for this session. Use the manual filters. No filters changed.');
    } finally {
      if (!controller.signal.aborted && sequence.current === requestSequence) setPending(false);
    }
  }

  function apply(filters: AssistantFindingFilters) {
    invalidate();
    onApply(filters);
  }

  return (
    <section className="ai-filter-preview" aria-labelledby={labelId}>
      <form onSubmit={(event) => { event.preventDefault(); void prepare(); }}>
        <label className="field" htmlFor={`${labelId}-question`}><span id={labelId}>Filter in plain language</span></label>
        <div className="ai-filter-controls">
          <input id={`${labelId}-question`} className="input" value={question} maxLength={FILTER_QUESTION_MAX} aria-describedby={hintId} placeholder="Show open high severity findings" onChange={(event) => { invalidate(); setQuestion(event.target.value); }} />
          <Button type="submit" size="sm" variant="secondary" disabled={!question.trim() || pending} loading={pending} loadingText="Preparing preview">Preview filters</Button>
          {pending || queued ? <Button type="button" size="sm" variant="ghost" onClick={() => { invalidate(); setNotice('Preview cancelled. No filters changed.'); }}>Cancel preview</Button> : null}
          <Button type="button" size="sm" variant="ghost" onClick={() => { invalidate(); setQuestion(''); onClear(); }}>Clear</Button>
        </div>
        <p id={hintId} className="ai-filter-hint">Preview first, then apply. Replaces current filters; never changes findings or starts a run. No OR, dates or provider filters.</p>
      </form>
      {pending ? <p role="status">Preparing filter preview. No filters changed.</p> : null}
      {notice ? <p role="status">{notice}</p> : null}
      {preview ? <PreviewResult preview={preview} onApply={apply} /> : null}
      {queued ? <QueuedPreview key={queued.jobId} config={config} session={session} queued={queued} onApply={apply} /> : null}
    </section>
  );
}

/** Remount on scope/identity changes so an earlier request can never be applied to a new queue. */
export function FiltersPreview(props: { config: PortalConfig; session: Session; scopeKey: string; onApply: (filters: AssistantFindingFilters) => void; onClear: () => void }) {
  const boundary = useRef({ identity: '', credential: '', epoch: 0 });
  const identity = `${sessionIdentity(props.session)}|${props.scopeKey}`;
  const credential = props.session.access_token ?? '';
  if (boundary.current.identity !== identity || boundary.current.credential !== credential) boundary.current = { identity, credential, epoch: boundary.current.epoch + 1 };
  return <FiltersPreviewForm key={boundary.current.epoch} {...props} />;
}
