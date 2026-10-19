import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { PortalConfig, Session } from '../../lib/types';
import {
  cancelAssistantJob,
  createAssistantJob,
  getAssistantJob,
  isTerminal,
  pollDelay,
  type AssistantRequestError,
} from '../../lib/assistant-api';
import {
  MAX_MESSAGES,
  conversationForRequest,
  loadPendingJobs,
  loadSessions,
  newId,
  savePendingJobs,
  saveSessions,
  storageKey,
  titleFrom,
  type AssistantContext,
  type AssistantMessage,
  type AssistantSession,
  type PendingJobs,
} from '../../lib/assistant-storage.mjs';

function browserStorage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

function nowIso() {
  return new Date().toISOString();
}

function reconcile(sessions: AssistantSession[], pending: PendingJobs) {
  return sessions.map((item) => ({
    ...item,
    messages: item.messages.map((message) => (message.status === 'pending' && !pending[message.id]
      ? { ...message, status: 'failed' as const, error: message.error || 'This answer did not finish. Ask again.' }
      : message)),
  }));
}

function requestErrorText(error: AssistantRequestError) {
  if (error.status === 429) return `Too many questions in a short time. Try again in ${error.retryAfterSeconds ?? 60} seconds.`;
  if (error.status === 503 || error.code === 'assistant_runner_offline') return 'The AI runner is not connected right now.';
  if (error.status === 403) return 'The assistant is not enabled for this workspace.';
  if (error.status === 404 && error.code === 'not_found') return 'That finding is no longer available.';
  return error.message || 'The assistant request failed.';
}

export type AssistantChat = ReturnType<typeof useAssistantChat>;

export function useAssistantChat(config: PortalConfig, session: Session, options: { onAnswer?: () => void; onRunnerOffline?: () => void } = {}) {
  const key = storageKey(session.tenant_id, session.user_id);
  const [pending, setPending] = useState<PendingJobs>(() => loadPendingJobs(browserStorage(), key));
  const [sessions, setSessions] = useState<AssistantSession[]>(() => reconcile(loadSessions(browserStorage(), key), loadPendingJobs(browserStorage(), key)));
  const [activeId, setActiveId] = useState<string | null>(null);
  const polling = useRef(new Map<string, () => void>());
  const optionsRef = useRef(options);
  optionsRef.current = options;

  useEffect(() => {
    const restored = loadPendingJobs(browserStorage(), key);
    setPending(restored);
    setSessions(reconcile(loadSessions(browserStorage(), key), restored));
    setActiveId(null);
  }, [key]);

  useEffect(() => { saveSessions(browserStorage(), key, sessions); }, [key, sessions]);
  useEffect(() => { savePendingJobs(browserStorage(), key, pending); }, [key, pending]);

  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (event.key === key) setSessions(loadSessions(browserStorage(), key));
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, [key]);

  const updateMessage = useCallback((sessionId: string, messageId: string, patch: Partial<AssistantMessage>) => {
    setSessions((current) => current.map((item) => (item.id !== sessionId ? item : {
      ...item,
      updated_at: nowIso(),
      messages: item.messages.map((message) => (message.id === messageId ? { ...message, ...patch } : message)),
    })));
  }, []);

  const finishPending = useCallback((messageId: string) => {
    polling.current.get(messageId)?.();
    polling.current.delete(messageId);
    setPending((current) => {
      if (!current[messageId]) return current;
      const next = { ...current };
      delete next[messageId];
      return next;
    });
  }, []);

  useEffect(() => {
    for (const [messageId, entry] of Object.entries(pending)) {
      if (polling.current.has(messageId)) continue;
      let stopped = false;
      let timer = 0;
      const controller = new AbortController();
      polling.current.set(messageId, () => { stopped = true; window.clearTimeout(timer); controller.abort(); });
      let attempt = 0;
      const tick = async () => {
        if (stopped) return;
        try {
          const job = await getAssistantJob(config, session, entry.job_id, controller.signal);
          if (stopped) return;
          if (job && isTerminal(job.status)) {
            if (job.status === 'done' && job.response) {
              updateMessage(entry.session_id, messageId, {
                status: 'done',
                content: job.response.content || 'The assistant returned an empty answer.',
                searches: job.response.searches,
                sources: job.response.sources,
                model: job.response.model,
                tool_calls: job.response.tool_calls,
                data_results: job.response.data_results,
              });
              optionsRef.current.onAnswer?.();
            } else if (job.status === 'cancelled') {
              updateMessage(entry.session_id, messageId, { status: 'cancelled' });
            } else {
              updateMessage(entry.session_id, messageId, { status: 'failed', error: job.error || 'The assistant could not finish this answer.' });
            }
            finishPending(messageId);
            return;
          }
        } catch (error) {
          if (stopped) return;
          const failure = error as AssistantRequestError;
          if (failure.status === 404 || failure.status === 403) {
            updateMessage(entry.session_id, messageId, { status: 'failed', error: 'This answer is no longer available. Ask again.' });
            finishPending(messageId);
            return;
          }
        }
        timer = window.setTimeout(() => void tick(), pollDelay(attempt, Date.now() - entry.started_at));
        attempt += 1;
      };
      void tick();
    }
  }, [pending, config, session, updateMessage, finishPending]);

  useEffect(() => () => {
    for (const stop of polling.current.values()) stop();
    polling.current.clear();
  }, []);

  const activeSession = useMemo(() => sessions.find((item) => item.id === activeId) ?? null, [sessions, activeId]);

  const ask = useCallback(async (sessionId: string, history: AssistantMessage[], context: AssistantContext | null) => {
    const reply: AssistantMessage = { id: newId('msg'), role: 'assistant', content: '', created_at: nowIso(), status: 'pending' };
    setSessions((current) => current.map((item) => (item.id !== sessionId ? item : {
      ...item,
      updated_at: nowIso(),
      messages: [...item.messages, reply].slice(-MAX_MESSAGES),
    })));
    try {
      const jobId = await createAssistantJob(config, session, { messages: conversationForRequest(history), context });
      updateMessage(sessionId, reply.id, { job_id: jobId });
      setPending((current) => ({ ...current, [reply.id]: { job_id: jobId, session_id: sessionId, started_at: Date.now() } }));
    } catch (error) {
      const failure = error as AssistantRequestError;
      if (failure.status === 503) optionsRef.current.onRunnerOffline?.();
      updateMessage(sessionId, reply.id, { status: 'failed', error: requestErrorText(failure) });
    }
  }, [config, session, updateMessage]);

  const send = useCallback((content: string, context: AssistantContext | null, fresh = false) => {
    const trimmed = content.trim().slice(0, 4000);
    if (!trimmed) return;
    const userMessage: AssistantMessage = { id: newId('msg'), role: 'user', content: trimmed, created_at: nowIso() };
    const existing = !fresh ? sessions.find((item) => item.id === activeId) ?? null : null;
    if (existing) {
      const history = [...existing.messages, userMessage];
      const nextContext = context ?? existing.context;
      setSessions((current) => current.map((item) => (item.id !== existing.id ? item : { ...item, updated_at: nowIso(), context: nextContext, messages: history.slice(-MAX_MESSAGES) })));
      void ask(existing.id, history, nextContext);
      return;
    }
    const created: AssistantSession = { id: newId('chat'), title: titleFrom(trimmed), created_at: nowIso(), updated_at: nowIso(), context, messages: [userMessage] };
    setSessions((current) => [created, ...current]);
    setActiveId(created.id);
    void ask(created.id, created.messages, context);
  }, [sessions, activeId, ask]);

  const retry = useCallback((messageId: string) => {
    const owner = sessions.find((item) => item.messages.some((message) => message.id === messageId));
    if (!owner) return;
    const index = owner.messages.findIndex((message) => message.id === messageId);
    const history = owner.messages.slice(0, index);
    if (!history.some((message) => message.role === 'user')) return;
    setSessions((current) => current.map((item) => (item.id !== owner.id ? item : { ...item, messages: history })));
    void ask(owner.id, history, owner.context);
  }, [sessions, ask]);

  const stop = useCallback((messageId: string) => {
    const entry = pending[messageId];
    const owner = sessions.find((item) => item.messages.some((message) => message.id === messageId));
    if (entry) void cancelAssistantJob(config, session, entry.job_id);
    finishPending(messageId);
    if (owner) updateMessage(owner.id, messageId, { status: 'cancelled' });
  }, [pending, sessions, config, session, finishPending, updateMessage]);

  const removeSession = useCallback((sessionId: string) => {
    for (const [messageId, entry] of Object.entries(pending)) {
      if (entry.session_id === sessionId) {
        void cancelAssistantJob(config, session, entry.job_id);
        finishPending(messageId);
      }
    }
    setSessions((current) => current.filter((item) => item.id !== sessionId));
    setActiveId((current) => (current === sessionId ? null : current));
  }, [pending, config, session, finishPending]);

  const clearContext = useCallback((sessionId: string) => {
    setSessions((current) => current.map((item) => (item.id === sessionId ? { ...item, context: null } : item)));
  }, []);

  const hasPending = Object.keys(pending).length > 0;
  const activePending = activeSession ? activeSession.messages.some((message) => message.status === 'pending') : false;

  return {
    sessions,
    activeSession,
    activeId,
    setActiveId,
    send,
    retry,
    stop,
    removeSession,
    clearContext,
    hasPending,
    activePending,
  };
}
