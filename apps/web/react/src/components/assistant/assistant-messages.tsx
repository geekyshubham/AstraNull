import { useEffect, useMemo, useState } from 'react';
import { Check, ChevronRight, Copy, Database, ExternalLink, RotateCcw, Search, Square, TriangleAlert } from 'lucide-react';
import { hostOf, markdownToPlainText } from '../../lib/assistant-markdown.mjs';
import type { AssistantMessage } from '../../lib/assistant-storage.mjs';
import { splitAnswer, unplacedResults, type ToolCall } from '../../lib/assistant-visuals.mjs';
import { Button } from '../ui/button';
import { AssistantMarkdown } from './assistant-markdown';
import { AssistantVisual } from './assistant-visual';

function Elapsed({ since }: { since: string }) {
  const start = Date.parse(since);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  const seconds = Number.isFinite(start) ? Math.max(0, Math.round((now - start) / 1000)) : 0;
  return <span className="as-elapsed tabular-nums">{seconds}s</span>;
}

const MARKER_TEXT = /^\s*\[\[data:Q\d{1,3}(?:\|[a-z]+)?\]\]\s*$/gm;

function toolLabel(name: string) {
  const plain = name.replace(/^(query|list|get|count|search|read|find)[_.-]/i, '').replace(/[_.-]+/g, ' ').trim();
  return plain ? plain.charAt(0).toUpperCase() + plain.slice(1) : name;
}

function ToolActivity({ calls }: { calls: ToolCall[] }) {
  const labels = [...new Set(calls.map((call) => toolLabel(call.name)))];
  return (
    <details className="as-searches as-tools">
      <summary><ChevronRight size={13} aria-hidden="true" /><Database size={13} aria-hidden="true" />Checked your data: {labels.join(' · ')}</summary>
      <ul>
        {calls.map((call, index) => (
          <li key={`${call.name}-${index}`}><strong>{toolLabel(call.name)}</strong>{call.summary ? ` — ${call.summary}` : ''}</li>
        ))}
      </ul>
    </details>
  );
}

function CopyAnswer({ content }: { content: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(markdownToPlainText(content.replace(MARKER_TEXT, '')).replace(/\n{3,}/g, '\n\n'));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  }
  return (
    <button type="button" className="as-icon-btn as-copy" onClick={() => void copy()} aria-label={copied ? 'Answer copied' : 'Copy answer'}>
      {copied ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
      <span>{copied ? 'Copied' : 'Copy'}</span>
    </button>
  );
}

function AnswerBody({ content, results }: { content: string; results: NonNullable<AssistantMessage['data_results']> }) {
  const segments = useMemo(() => splitAnswer(content, results), [content, results]);
  const extra = useMemo(() => unplacedResults(segments, results), [segments, results]);
  const byId = new Map(results.map((result) => [result.id, result]));
  return (
    <>
      {segments.map((segment, index) => {
        if (segment.type === 'markdown') return <AssistantMarkdown key={index} content={segment.text} />;
        const result = byId.get(segment.id);
        return result ? <AssistantVisual key={`${segment.id}-${index}`} result={result} requested={segment.visual} /> : null;
      })}
      {extra.length ? (
        <details className="as-searches as-data-used">
          <summary><ChevronRight size={13} aria-hidden="true" /><Database size={13} aria-hidden="true" />Data used ({extra.length})</summary>
          <div className="as-data-used-body">
            {extra.map((result) => <AssistantVisual key={result.id} result={result} requested="table" />)}
          </div>
        </details>
      ) : null}
    </>
  );
}

function AssistantAnswer({ message, onRetry, onStop }: { message: AssistantMessage; onRetry: () => void; onStop: () => void }) {
  if (message.status === 'pending') {
    return (
      <div className="as-msg as-msg-ai" data-status="pending">
        <div className="as-pending" role="status">
          <span className="as-dots" aria-hidden="true"><span /><span /><span /></span>
          <span>Researching</span>
          <Elapsed since={message.created_at} />
          <Button size="sm" variant="ghost" className="as-stop" onClick={onStop} aria-label="Stop this answer">
            <Square size={12} aria-hidden="true" />Stop
          </Button>
        </div>
      </div>
    );
  }
  if (message.status === 'failed' || message.status === 'cancelled') {
    return (
      <div className="as-msg as-msg-ai" data-status={message.status}>
        <div className="as-notice" role={message.status === 'failed' ? 'alert' : 'status'}>
          <TriangleAlert size={15} aria-hidden="true" />
          <span>{message.status === 'cancelled' ? 'Stopped. Nothing else will run for this question.' : message.error || 'The assistant could not finish this answer.'}</span>
          <Button size="sm" variant="secondary" onClick={onRetry}><RotateCcw size={13} aria-hidden="true" />Retry</Button>
        </div>
      </div>
    );
  }
  const searches = message.searches ?? [];
  const sources = message.sources ?? [];
  const tools = message.tool_calls ?? [];
  const results = message.data_results ?? [];
  return (
    <div className="as-msg as-msg-ai" data-status="done">
      <AnswerBody content={message.content} results={results} />
      {tools.length ? <ToolActivity calls={tools} /> : null}
      {searches.length ? (
        <details className="as-searches">
          <summary><ChevronRight size={13} aria-hidden="true" /><Search size={13} aria-hidden="true" />Searched the web ({searches.length})</summary>
          <p>{searches.join(' · ')}</p>
        </details>
      ) : null}
      {sources.length ? (
        <div className="as-sources">
          <span className="as-sources-label">Sources</span>
          <ul>
            {sources.map((source) => (
              <li key={source.url}>
                <a href={source.url} target="_blank" rel="noopener noreferrer nofollow">
                  <span className="as-source-host">{hostOf(source.url)}</span>
                  {source.title ? <span className="as-source-title">{source.title}</span> : null}
                  <ExternalLink size={12} aria-hidden="true" />
                </a>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <div className="as-answer-foot">
        <span className="as-disclaimer">AI advice — verify with your provider, then re-run the check.</span>
        <CopyAnswer content={message.content} />
      </div>
    </div>
  );
}

export function AssistantMessages({ messages, onRetry, onStop }: { messages: AssistantMessage[]; onRetry: (id: string) => void; onStop: (id: string) => void }) {
  return (
    <ol className="as-thread" aria-label="Conversation">
      {messages.map((message) => (
        <li key={message.id} className="as-turn" data-role={message.role}>
          {message.role === 'user'
            ? <div className="as-msg as-msg-user"><p>{message.content}</p></div>
            : <AssistantAnswer message={message} onRetry={() => onRetry(message.id)} onStop={() => onStop(message.id)} />}
        </li>
      ))}
    </ol>
  );
}
