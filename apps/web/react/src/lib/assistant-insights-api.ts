import { useCallback, useEffect, useRef, useState } from 'react';
import { requestJson, sessionIdentity } from './api';
import { pollDelay } from './assistant-api';
import {
  INSIGHT_CACHE_TTL_MS,
  insightCacheKey,
  insightRequestBody,
  sanitizeBoard,
  sanitizeNarrative,
  sanitizeNarrativeState,
  sanitizeScope,
  type InsightBoard,
  type InsightNarrative,
  type InsightScope,
  type NarrativeState,
} from './assistant-insights.mjs';
import type { PortalConfig, Session } from './types';

type CacheEntry = { at: number; board: InsightBoard; narrative: InsightNarrative | null; narrativeState: NarrativeState };

const cache = new Map<string, CacheEntry>();
const NARRATIVE_DEADLINE_MS = 150_000;

let publishedScope: InsightScope | null = null;
const scopeListeners = new Set<() => void>();

function notifyScope() {
  for (const listener of scopeListeners) listener();
}

/** A page with a scope the route cannot express (a finding group's members) publishes it here. */
export function usePublishInsightScope(scope: InsightScope | null) {
  const signature = scope ? JSON.stringify(sanitizeScope(scope)) : '';
  useEffect(() => {
    if (!signature || signature === 'null') return undefined;
    publishedScope = JSON.parse(signature) as InsightScope;
    notifyScope();
    return () => {
      if (publishedScope && JSON.stringify(publishedScope) === signature) {
        publishedScope = null;
        notifyScope();
      }
    };
  }, [signature]);
}

export function usePublishedInsightScope() {
  const [scope, setScope] = useState<InsightScope | null>(publishedScope);
  useEffect(() => {
    const update = () => setScope(publishedScope);
    scopeListeners.add(update);
    update();
    return () => {
      scopeListeners.delete(update);
    };
  }, []);
  return scope;
}

export type InsightsErrorCode = 'forbidden' | 'not_found' | 'disabled' | 'failed';
export type InsightsState = {
  phase: 'loading' | 'ready' | 'error';
  board: InsightBoard | null;
  narrative: InsightNarrative | null;
  narrativeState: NarrativeState;
  narrativePending: boolean;
  narrativeFailed: boolean;
  error: InsightsErrorCode | null;
  refreshing: boolean;
};

const IDLE: NarrativeState = { status: 'not_requested', jobId: '', reason: '' };

function errorCode(error: unknown): InsightsErrorCode {
  const status = (error as { status?: number })?.status;
  if (status === 403) return 'forbidden';
  if (status === 404) {
    const code = (error as { payload?: { error?: string } })?.payload?.error ?? '';
    return code === 'assistant_disabled' ? 'disabled' : 'not_found';
  }
  return 'failed';
}

function wait(ms: number, signal: AbortSignal) {
  return new Promise<void>((resolve) => {
    const timer = window.setTimeout(resolve, ms);
    signal.addEventListener('abort', () => {
      window.clearTimeout(timer);
      resolve();
    }, { once: true });
  });
}

async function pollNarrative(config: PortalConfig, session: Session, jobId: string, signal: AbortSignal): Promise<InsightNarrative | null> {
  const started = Date.now();
  for (let attempt = 0; !signal.aborted && Date.now() - started < NARRATIVE_DEADLINE_MS; attempt += 1) {
    await wait(pollDelay(attempt, Date.now() - started), signal);
    if (signal.aborted) return null;
    const job = await requestJson(config, session, `/v1/assistant/jobs/${encodeURIComponent(jobId)}`, { signal }) as Record<string, unknown> | null;
    const status = String(job?.status ?? '');
    if (status === 'done') {
      const response = job?.response && typeof job.response === 'object' ? job.response as Record<string, unknown> : {};
      return sanitizeNarrative(response.insight);
    }
    if (status === 'failed' || status === 'cancelled') return null;
  }
  return null;
}

/** Loads the board for a scope once the dialog opens, then enriches it with the AI summary. */
export function useInsights(config: PortalConfig, session: Session, scope: InsightScope | null, open: boolean) {
  const [state, setState] = useState<InsightsState>({ phase: 'loading', board: null, narrative: null, narrativeState: IDLE, narrativePending: false, narrativeFailed: false, error: null, refreshing: false });
  const controllerRef = useRef<AbortController | null>(null);
  const key = scope ? insightCacheKey(sessionIdentity(session), scope) : '';
  const scopeRef = useRef(scope);
  scopeRef.current = scope;

  const load = useCallback((force = false) => {
    const scope = scopeRef.current;
    if (!scope || !key) return;
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    const cached = force ? null : cache.get(key);
    if (cached && Date.now() - cached.at < INSIGHT_CACHE_TTL_MS) {
      setState({ phase: 'ready', board: cached.board, narrative: cached.narrative, narrativeState: cached.narrativeState, narrativePending: false, narrativeFailed: false, error: null, refreshing: false });
      return;
    }
    setState((previous) => (force && previous.board
      ? { ...previous, refreshing: true }
      : { phase: 'loading', board: null, narrative: null, narrativeState: IDLE, narrativePending: false, narrativeFailed: false, error: null, refreshing: false }));
    void (async () => {
      try {
        const payload = await requestJson(config, session, '/v1/assistant/insights', {
          method: 'POST',
          body: insightRequestBody(scope, { refresh: force }),
          signal: controller.signal,
        }) as Record<string, unknown> | null;
        if (controller.signal.aborted) return;
        const board = sanitizeBoard(payload?.board);
        if (!board) throw Object.assign(new Error('empty board'), { status: 502 });
        const narrativeState = sanitizeNarrativeState(payload?.narrative);
        const pending = narrativeState.status === 'queued';
        setState({ phase: 'ready', board, narrative: null, narrativeState, narrativePending: pending, narrativeFailed: false, error: null, refreshing: false });
        if (!pending) {
          cache.set(key, { at: Date.now(), board, narrative: null, narrativeState });
          return;
        }
        let narrative: InsightNarrative | null = null;
        try {
          narrative = await pollNarrative(config, session, narrativeState.jobId, controller.signal);
        } catch {
          narrative = null;
        }
        if (controller.signal.aborted) return;
        setState((previous) => ({ ...previous, narrative, narrativePending: false, narrativeFailed: !narrative }));
        if (narrative) cache.set(key, { at: Date.now(), board, narrative, narrativeState });
      } catch (error) {
        if (controller.signal.aborted) return;
        setState((previous) => (previous.board && force
          ? { ...previous, refreshing: false }
          : { phase: 'error', board: null, narrative: null, narrativeState: IDLE, narrativePending: false, narrativeFailed: false, error: errorCode(error), refreshing: false }));
      }
    })();
  }, [config, session, key]);

  useEffect(() => {
    if (!open) return undefined;
    load();
    return () => controllerRef.current?.abort();
  }, [open, load]);

  return { ...state, reload: () => load(true) };
}

export function clearInsightsCache() {
  cache.clear();
}
