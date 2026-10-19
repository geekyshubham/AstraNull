import { forwardRef, useEffect, useImperativeHandle, useRef, useState, type KeyboardEvent } from 'react';
import { ArrowUp } from 'lucide-react';

const LIMIT = 4000;

export type ComposerHandle = { focus: () => void; setDraft: (value: string) => void };

export const AssistantComposer = forwardRef<ComposerHandle, {
  disabled: boolean;
  disabledReason?: string;
  busy: boolean;
  onSend: (value: string) => void;
}>(function AssistantComposer({ disabled, disabledReason, busy, onSend }, ref) {
  const [draft, setDraft] = useState('');
  const area = useRef<HTMLTextAreaElement>(null);

  useImperativeHandle(ref, () => ({
    focus: () => area.current?.focus(),
    setDraft: (value: string) => { setDraft(value.slice(0, LIMIT)); window.requestAnimationFrame(() => area.current?.focus()); },
  }), []);

  useEffect(() => {
    const node = area.current;
    if (!node) return;
    node.style.height = 'auto';
    node.style.height = `${Math.min(node.scrollHeight, 160)}px`;
  }, [draft]);

  const blocked = disabled || busy;
  const canSend = !blocked && draft.trim().length > 0;

  function submit() {
    if (!canSend) return;
    onSend(draft);
    setDraft('');
  }

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault();
      submit();
    }
  }

  const remaining = LIMIT - draft.length;
  return (
    <form className="as-composer" onSubmit={(event) => { event.preventDefault(); submit(); }}>
      <label className="sr-only" htmlFor="as-composer-input">Ask the AstraNull assistant</label>
      <textarea
        id="as-composer-input"
        ref={area}
        rows={1}
        value={draft}
        maxLength={LIMIT}
        disabled={disabled}
        placeholder={disabled ? disabledReason || 'The assistant is unavailable.' : 'Ask how to fix a gap, or what a finding means'}
        onChange={(event) => setDraft(event.target.value)}
        onKeyDown={onKeyDown}
        aria-describedby={remaining <= 500 ? 'as-composer-count' : undefined}
      />
      <div className="as-composer-row">
        <span className="as-composer-hint">{busy ? 'Waiting for the answer…' : 'Enter to send · Shift+Enter for a new line'}</span>
        {remaining <= 500 ? <span id="as-composer-count" className="as-composer-count tabular-nums" data-low={remaining <= 100 || undefined}>{remaining} left</span> : null}
        <button type="submit" className="as-send" disabled={!canSend} aria-label="Send">
          <ArrowUp size={16} aria-hidden="true" />
        </button>
      </div>
    </form>
  );
});
