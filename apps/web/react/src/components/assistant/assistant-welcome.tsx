import { ArrowRight, Sparkles } from 'lucide-react';
import { pageSuggestions } from '../../lib/assistant-page-context.mjs';

export function AssistantWelcome({ kind, pageTitle, onPick, disabled }: { kind?: string; pageTitle?: string; onPick: (prompt: string) => void; disabled: boolean }) {
  return (
    <div className="as-welcome">
      <span className="as-welcome-mark" aria-hidden="true"><Sparkles size={18} /></span>
      <h3>How can I help?</h3>
      <p>
        I can read your targets, findings, runs and checks, chart them, and explain how to fix a gap for your CDN, WAF or firewall vendor.
        {pageTitle ? <> I already know you&apos;re on <strong>{pageTitle}</strong>.</> : null}
      </p>
      <ul className="as-suggestions" aria-label="Suggested questions">
        {pageSuggestions(kind).map((prompt) => (
          <li key={prompt}>
            <button type="button" disabled={disabled} onClick={() => onPick(prompt)}>
              <span>{prompt}</span>
              <ArrowRight size={14} aria-hidden="true" />
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
