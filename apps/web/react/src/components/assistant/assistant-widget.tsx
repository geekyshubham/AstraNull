import { useCallback, useEffect, useRef, useState } from 'react';
import { History, Maximize2, Minimize2, PanelRight, PlugZap, Plus, RotateCcw, Sparkles, X } from 'lucide-react';
import { assistantAvailable, useAssistantStatus } from '../../lib/assistant-api';
import { onAssistantOpen } from '../../lib/assistant-bus';
import { contextIds, describePageContext } from '../../lib/assistant-page-context.mjs';
import { capturePageContext, useAssistantPageContext } from '../../lib/assistant-page-store';
import type { AssistantContext } from '../../lib/assistant-storage.mjs';
import type { PortalConfig, PortalData, Session } from '../../lib/types';
import { Button } from '../ui/button';
import { AssistantComposer, type ComposerHandle } from './assistant-composer';
import { AssistantHistory } from './assistant-history';
import { AssistantMessages } from './assistant-messages';
import { AssistantWelcome } from './assistant-welcome';
import { useAssistantChat } from './use-assistant-chat';
import './assistant.css';

type Layout = 'float' | 'drawer' | 'full';

/** Record ids the user pinned (an "Ask AI" button), without the page snapshot. */
function pinnedIds(context: AssistantContext | null | undefined): AssistantContext | null {
  if (!context?.label) return null;
  const { page: _page, ...rest } = context;
  return Object.values(rest).some(Boolean) ? rest : null;
}

export function AssistantWidget({ config, session, data }: { config: PortalConfig; session: Session; data: PortalData }) {
  const { status, refresh } = useAssistantStatus(config, session);
  const [open, setOpen] = useState(false);
  const [layout, setLayout] = useState<Layout>('float');
  const [unread, setUnread] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [draftContext, setDraftContext] = useState<AssistantContext | null>(null);
  const [pageOff, setPageOff] = useState(false);
  const [announcement, setAnnouncement] = useState('');
  const openRef = useRef(open);
  openRef.current = open;
  const launcher = useRef<HTMLButtonElement>(null);
  const composer = useRef<ComposerHandle>(null);
  const thread = useRef<HTMLDivElement>(null);
  const dataRef = useRef(data);
  dataRef.current = data;

  const chat = useAssistantChat(config, session, {
    onAnswer: () => {
      setAnnouncement('The assistant answered.');
      if (!openRef.current) setUnread(true);
    },
    onRunnerOffline: () => void refresh(),
  });
  const chatRef = useRef(chat);
  chatRef.current = chat;

  const runnerOffline = Boolean(status && !status.runner_online);
  const pinned = pinnedIds(chat.activeSession ? chat.activeSession.context : draftContext);
  const livePage = useAssistantPageContext(data, open);
  const pageKey = livePage ? `${livePage.route}|${livePage.entity?.id ?? ''}` : '';
  const shownPage = pageOff ? null : livePage;
  const chipLabel = pinned?.label || (shownPage ? describePageContext(shownPage) : '');
  const messages = chat.activeSession?.messages ?? [];

  useEffect(() => { setPageOff(false); }, [pageKey]);

  /** Context captured at send time: pinned ids win; otherwise the open page's own record and facts. */
  const sendContext = useCallback((): AssistantContext | null => {
    const page = pageOff ? null : capturePageContext(dataRef.current);
    const ids = pinned ?? (page ? contextIds(page) : {});
    const merged: AssistantContext = { ...ids, ...(page ? { page } : {}) };
    return Object.keys(merged).length ? merged : null;
  }, [pageOff, pinned]);

  const show = useCallback((nextContext?: AssistantContext | null) => {
    setOpen(true);
    setUnread(false);
    if (nextContext !== undefined) setDraftContext(nextContext);
    window.requestAnimationFrame(() => composer.current?.focus());
  }, []);

  const close = useCallback(() => {
    setOpen(false);
    setHistoryOpen(false);
    window.requestAnimationFrame(() => launcher.current?.focus());
  }, []);

  useEffect(() => onAssistantOpen((request) => {
    const current = chatRef.current;
    const requestContext = request.context ?? null;
    const sameContext = current.activeSession
      && (current.activeSession.context?.finding_id ?? '') === (requestContext?.finding_id ?? '')
      && (current.activeSession.context?.target_id ?? '') === (requestContext?.target_id ?? '');
    if (!sameContext) current.setActiveId(null);
    show(requestContext);
    const page = capturePageContext(dataRef.current);
    const outgoing = requestContext || page ? { ...(requestContext ?? {}), ...(page ? { page } : {}) } : null;
    if (request.send && request.prompt) current.send(request.prompt, outgoing, !sameContext);
    else if (request.prompt) composer.current?.setDraft(request.prompt);
  }), [show]);

  useEffect(() => {
    if (!open) return undefined;
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || event.defaultPrevented) return;
      if (layout === 'full') setLayout('float');
      else close();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, layout, close]);

  useEffect(() => {
    const node = thread.current;
    if (node) node.scrollTop = node.scrollHeight;
  }, [messages.length, messages[messages.length - 1]?.status, open]);

  if (!assistantAvailable(status) || session.principal === 'staff') return null;

  function toggle() {
    if (open) {
      close();
      return;
    }
    show(chat.activeSession ? undefined : null);
  }

  function newChat() {
    chat.setActiveId(null);
    setDraftContext(null);
    setPageOff(false);
    setHistoryOpen(false);
    window.requestAnimationFrame(() => composer.current?.focus());
  }

  function send(content: string) {
    chat.send(content, sendContext());
  }

  function removeContext() {
    setPageOff(true);
    if (chat.activeSession) chat.clearContext(chat.activeSession.id);
    else setDraftContext(null);
  }

  return (
    <>
      <button
        ref={launcher}
        type="button"
        className="as-launcher"
        data-open={open || undefined}
        data-busy={chat.hasPending || undefined}
        aria-expanded={open}
        aria-controls="as-panel"
        aria-label={open ? 'Close AstraNull AI' : unread ? 'Open AstraNull AI, new answer' : 'Open AstraNull AI'}
        onClick={toggle}
      >
        {open ? <X size={20} aria-hidden="true" /> : <Sparkles size={20} aria-hidden="true" />}
        {unread && !open ? <span className="as-unread" aria-hidden="true" /> : null}
      </button>
      {open ? (
        <section id="as-panel" className="as-panel" data-layout={layout} role="dialog" aria-modal="false" aria-label="AstraNull AI assistant">
          <header className="as-head">
            <span className="as-head-title"><Sparkles size={16} aria-hidden="true" />AstraNull AI</span>
            <span className="as-head-actions">
              <button type="button" className="as-icon-btn" onClick={newChat} aria-label="New chat"><Plus size={16} aria-hidden="true" /></button>
              <button type="button" className="as-icon-btn" onClick={() => setHistoryOpen((value) => !value)} aria-label="Chat history" aria-expanded={historyOpen}><History size={16} aria-hidden="true" /></button>
              <button
                type="button"
                className="as-icon-btn as-hide-mobile"
                onClick={() => setLayout((value) => (value === 'drawer' ? 'float' : 'drawer'))}
                aria-label={layout === 'drawer' ? 'Show as floating panel' : 'Dock to the side'}
                aria-pressed={layout === 'drawer'}
              >
                <PanelRight size={16} aria-hidden="true" />
              </button>
              <button
                type="button"
                className="as-icon-btn"
                onClick={() => setLayout((value) => (value === 'full' ? 'float' : 'full'))}
                aria-label={layout === 'full' ? 'Exit full screen' : 'Full screen'}
              >
                {layout === 'full' ? <Minimize2 size={16} aria-hidden="true" /> : <Maximize2 size={16} aria-hidden="true" />}
              </button>
              <button type="button" className="as-icon-btn" onClick={close} aria-label="Close assistant"><X size={16} aria-hidden="true" /></button>
            </span>
            {historyOpen ? (
              <AssistantHistory
                sessions={chat.sessions}
                activeId={chat.activeId}
                onSelect={(id) => { chat.setActiveId(id); setHistoryOpen(false); }}
                onDelete={chat.removeSession}
                onClose={() => setHistoryOpen(false)}
              />
            ) : null}
          </header>
          <div className="as-body" ref={thread}>
            {runnerOffline ? (
              <div className="as-setup" role="status">
                <span className="as-setup-mark" aria-hidden="true"><PlugZap size={18} /></span>
                <strong>The AI runner isn&apos;t connected.</strong>
                <p>Ask your admin to start it. Saved chats are still here.</p>
                <Button size="sm" variant="secondary" onClick={() => void refresh()}><RotateCcw size={13} aria-hidden="true" />Retry</Button>
              </div>
            ) : null}
            {messages.length
              ? <AssistantMessages messages={messages} onRetry={chat.retry} onStop={chat.stop} />
              : runnerOffline ? null : <AssistantWelcome kind={pinned?.finding_id ? 'finding' : shownPage?.kind} pageTitle={shownPage?.title} disabled={runnerOffline} onPick={send} />}
          </div>
          <footer className="as-foot">
            {chipLabel ? (
              <div className="as-context">
                <span className="as-context-label">{pinned?.label ? 'Asking about:' : 'Using this page:'}</span>
                <span className="as-context-value" title={chipLabel}>{chipLabel}</span>
                <button type="button" className="as-icon-btn" aria-label="Don't send this page's context" onClick={removeContext}><X size={13} aria-hidden="true" /></button>
              </div>
            ) : null}
            <AssistantComposer
              ref={composer}
              disabled={runnerOffline}
              disabledReason="The AI runner isn't connected."
              busy={chat.activePending}
              onSend={send}
            />
          </footer>
          <p className="sr-only" aria-live="polite">{announcement}</p>
        </section>
      ) : null}
    </>
  );
}
