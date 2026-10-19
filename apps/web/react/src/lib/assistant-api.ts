import { useCallback, useEffect, useState } from 'react';
import { requestJson, sessionIdentity } from './api';
import type { PortalConfig, Session } from './types';
import { safeHref } from './assistant-markdown.mjs';
import type { AssistantContext, AssistantSource } from './assistant-storage.mjs';
import { sanitizeDataResults, sanitizeToolCalls, type DataResult, type ToolCall } from './assistant-visuals.mjs';

export type AssistantStatus = {
  enabled: boolean;
  tenant_enabled: boolean;
  runner_online: boolean;
  model: string;
  reason: null | 'disabled' | 'tenant_not_enabled' | 'runner_offline';
  capabilities: { data_tools: boolean; visuals: boolean; page_context: boolean };
};

export type AssistantJobStatus = 'queued' | 'running' | 'done' | 'failed' | 'cancelled';

export type AssistantJob = {
  id: string;
  status: AssistantJobStatus;
  created_at: string;
  updated_at: string;
  response?: { content: string; searches: string[]; sources: AssistantSource[]; model: string; tool_calls: ToolCall[]; data_results: DataResult[] };
  error?: string;
};

export type AssistantRequestError = Error & { status?: number; code?: string; retryAfterSeconds?: number };

const STATUS_TTL_MS = 60_000;
const OFF: AssistantStatus = { enabled: false, tenant_enabled: false, runner_online: false, model: '', reason: 'disabled', capabilities: { data_tools: false, visuals: false, page_context: false } };

type StatusEntry = { key: string; at: number; value: AssistantStatus | null; promise: Promise<AssistantStatus> | null };
let statusEntry: StatusEntry = { key: '', at: 0, value: null, promise: null };
const listeners = new Set<(value: AssistantStatus) => void>();

function bool(value: unknown) {
  return value === true;
}

export function normalizeStatus(payload: unknown): AssistantStatus {
  const body = payload && typeof payload === 'object' ? payload as Record<string, unknown> : {};
  const reason = ['disabled', 'tenant_not_enabled', 'runner_offline'].includes(String(body.reason)) ? body.reason as AssistantStatus['reason'] : null;
  return {
    enabled: bool(body.enabled),
    tenant_enabled: bool(body.tenant_enabled),
    runner_online: bool(body.runner_online),
    model: typeof body.model === 'string' ? body.model.slice(0, 80) : '',
    reason,
    capabilities: (() => {
      const caps = body.capabilities && typeof body.capabilities === 'object' ? body.capabilities as Record<string, unknown> : {};
      return { data_tools: bool(caps.data_tools), visuals: bool(caps.visuals), page_context: bool(caps.page_context) };
    })(),
  };
}

function publish(value: AssistantStatus) {
  for (const listener of listeners) listener(value);
}

export function loadAssistantStatus(config: PortalConfig, session: Session, force = false): Promise<AssistantStatus> {
  const key = sessionIdentity(session);
  const fresh = statusEntry.key === key && statusEntry.value && Date.now() - statusEntry.at < STATUS_TTL_MS;
  if (!force && fresh && statusEntry.value) return Promise.resolve(statusEntry.value);
  if (!force && statusEntry.key === key && statusEntry.promise) return statusEntry.promise;
  const promise = requestJson(config, session, '/v1/assistant/status')
    .then(normalizeStatus)
    .catch(() => OFF)
    .then((value) => {
      if (statusEntry.promise === promise) statusEntry = { key, at: Date.now(), value, promise: null };
      publish(value);
      return value;
    });
  statusEntry = { key, at: statusEntry.key === key ? statusEntry.at : 0, value: statusEntry.key === key ? statusEntry.value : null, promise };
  return promise;
}

/** Shared status: every caller reads one cached request per session, refreshed every minute. */
export function useAssistantStatus(config: PortalConfig, session: Session) {
  const key = sessionIdentity(session);
  const [status, setStatus] = useState<AssistantStatus | null>(() => (statusEntry.key === key ? statusEntry.value : null));
  useEffect(() => {
    let active = true;
    const listener = (value: AssistantStatus) => { if (active) setStatus(value); };
    listeners.add(listener);
    void loadAssistantStatus(config, session).then(listener);
    const timer = window.setInterval(() => void loadAssistantStatus(config, session), STATUS_TTL_MS);
    return () => { active = false; listeners.delete(listener); window.clearInterval(timer); };
  }, [config, session, key]);
  const refresh = useCallback(() => loadAssistantStatus(config, session, true), [config, session]);
  return { status, refresh };
}

export function assistantAvailable(status: AssistantStatus | null) {
  return Boolean(status?.enabled && status.tenant_enabled);
}

function toRequestError(error: unknown): AssistantRequestError {
  const source = error as { status?: number; payload?: Record<string, unknown>; message?: string };
  const payload = source?.payload && typeof source.payload === 'object' ? source.payload : {};
  const out = new Error(typeof payload.message === 'string' ? payload.message : source?.message || 'The assistant request failed.') as AssistantRequestError;
  out.status = source?.status;
  out.code = typeof payload.error === 'string' ? payload.error : undefined;
  const retry = Number(payload.retry_after_seconds);
  if (Number.isFinite(retry) && retry > 0) out.retryAfterSeconds = Math.ceil(retry);
  return out;
}

export function normalizeJob(payload: unknown): AssistantJob | null {
  const body = payload && typeof payload === 'object' ? payload as Record<string, unknown> : null;
  if (!body || typeof body.id !== 'string') return null;
  const status = ['queued', 'running', 'done', 'failed', 'cancelled'].includes(String(body.status)) ? body.status as AssistantJobStatus : 'failed';
  const response = body.response && typeof body.response === 'object' ? body.response as Record<string, unknown> : null;
  return {
    id: body.id,
    status,
    created_at: String(body.created_at ?? ''),
    updated_at: String(body.updated_at ?? ''),
    ...(response ? {
      response: {
        content: typeof response.content === 'string' ? response.content : '',
        searches: Array.isArray(response.searches) ? response.searches.filter((item): item is string => typeof item === 'string').slice(0, 12) : [],
        sources: Array.isArray(response.sources)
          ? response.sources.flatMap((item) => {
            const record = item && typeof item === 'object' ? item as Record<string, unknown> : {};
            const url = safeHref(record.url);
            return url ? [{ url, ...(typeof record.title === 'string' && record.title.trim() ? { title: record.title.trim().slice(0, 200) } : {}) }] : [];
          }).slice(0, 12)
          : [],
        model: typeof response.model === 'string' ? response.model : '',
        tool_calls: sanitizeToolCalls(response.tool_calls),
        data_results: sanitizeDataResults(response.data_results),
      },
    } : {}),
    ...(typeof body.error === 'string' ? { error: body.error } : {}),
  };
}

export async function createAssistantJob(
  config: PortalConfig,
  session: Session,
  body: { messages: Array<{ role: 'user' | 'assistant'; content: string }>; context?: AssistantContext | null },
) {
  const context = body.context ? Object.fromEntries(Object.entries(body.context).filter(([key, value]) => key !== 'label' && value)) : undefined;
  try {
    const payload = await requestJson(config, session, '/v1/assistant/jobs', {
      method: 'POST',
      body: { messages: body.messages, ...(context && Object.keys(context).length ? { context } : {}) },
    }) as Record<string, unknown> | null;
    const jobId = typeof payload?.job_id === 'string' ? payload.job_id : '';
    if (!jobId) throw Object.assign(new Error('The assistant did not return a job.'), { status: 502 });
    return jobId;
  } catch (error) {
    throw toRequestError(error);
  }
}

export async function getAssistantJob(config: PortalConfig, session: Session, jobId: string, signal?: AbortSignal) {
  try {
    return normalizeJob(await requestJson(config, session, `/v1/assistant/jobs/${encodeURIComponent(jobId)}`, { signal }));
  } catch (error) {
    throw toRequestError(error);
  }
}

export async function cancelAssistantJob(config: PortalConfig, session: Session, jobId: string) {
  try {
    await requestJson(config, session, `/v1/assistant/jobs/${encodeURIComponent(jobId)}`, { method: 'DELETE' });
  } catch {
    /* cancelling is best effort; the job still times out on the server */
  }
}

/** Poll quickly at first, then settle: 400ms, 600ms, 900ms, 1.2s, then 1.5s, then 3s after 20s. */
export function pollDelay(attempt: number, elapsedMs: number) {
  const early = [400, 600, 900, 1200];
  if (attempt < early.length) return early[attempt];
  return elapsedMs < 20_000 ? 1500 : 3000;
}

export function isTerminal(status: AssistantJobStatus) {
  return status === 'done' || status === 'failed' || status === 'cancelled';
}
