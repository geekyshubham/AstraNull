import { useEffect, useRef, useState } from 'react';
import { requestJson } from './api';
import { pollDelay } from './assistant-api';
import type { PortalConfig, Session } from './types';

/** How the server answered a request for an AI job: queued with an id, or why it could not. */
export type QueuedJob = { status: 'queued' | 'unavailable' | 'rate_limited' | 'not_requested'; jobId: string; reason: string };

const DEFAULT_DEADLINE_MS = 200_000;

export function sanitizeQueuedJob(value: unknown): QueuedJob {
  const body = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  const status = ['queued', 'unavailable', 'rate_limited', 'not_requested'].includes(String(body.status)) ? body.status as QueuedJob['status'] : 'unavailable';
  const jobId = typeof body.job_id === 'string' && /^[A-Za-z0-9_]{1,64}$/.test(body.job_id) ? body.job_id : '';
  const reason = typeof body.reason === 'string' ? body.reason.replace(/[^a-z_]/g, '').slice(0, 60) : '';
  return { status: status === 'queued' && !jobId ? 'unavailable' : status, jobId, reason };
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

/** Polls a structured AI job until it finishes; returns the sanitized response[key] or null. */
export async function pollStructuredJob<T>(
  config: PortalConfig,
  session: Session,
  jobId: string,
  key: string,
  sanitize: (value: unknown) => T | null,
  signal: AbortSignal,
  deadlineMs = DEFAULT_DEADLINE_MS,
): Promise<T | null> {
  const started = Date.now();
  for (let attempt = 0; !signal.aborted && Date.now() - started < deadlineMs; attempt += 1) {
    await wait(pollDelay(attempt, Date.now() - started), signal);
    if (signal.aborted) return null;
    const job = await requestJson(config, session, `/v1/assistant/jobs/${encodeURIComponent(jobId)}`, { signal }) as Record<string, unknown> | null;
    const status = String(job?.status ?? '');
    if (status === 'done') {
      const response = job?.response && typeof job.response === 'object' ? job.response as Record<string, unknown> : {};
      return sanitize(response[key]);
    }
    if (status === 'failed' || status === 'cancelled') return null;
  }
  return null;
}

export type StructuredJobState<T> = { pending: boolean; value: T | null; failed: boolean; seconds: number };

/** Follows a queued structured job and ticks elapsed seconds while it runs. */
export function useStructuredJob<T>(
  config: PortalConfig,
  session: Session,
  queued: QueuedJob | null,
  key: string,
  sanitize: (value: unknown) => T | null,
): StructuredJobState<T> {
  const [state, setState] = useState<StructuredJobState<T>>({ pending: false, value: null, failed: false, seconds: 0 });
  const sanitizeRef = useRef(sanitize);
  sanitizeRef.current = sanitize;
  const jobId = queued?.status === 'queued' ? queued.jobId : '';
  useEffect(() => {
    if (!jobId) {
      setState({ pending: false, value: null, failed: false, seconds: 0 });
      return undefined;
    }
    const controller = new AbortController();
    const started = Date.now();
    setState({ pending: true, value: null, failed: false, seconds: 0 });
    const timer = window.setInterval(() => setState((previous) => (previous.pending ? { ...previous, seconds: Math.floor((Date.now() - started) / 1000) } : previous)), 1000);
    pollStructuredJob(config, session, jobId, key, (value) => sanitizeRef.current(value), controller.signal)
      .catch(() => null)
      .then((value) => {
        if (controller.signal.aborted) return;
        setState({ pending: false, value, failed: !value, seconds: Math.floor((Date.now() - started) / 1000) });
      })
      .finally(() => window.clearInterval(timer));
    return () => {
      controller.abort();
      window.clearInterval(timer);
    };
  }, [config, session, jobId, key]);
  return state;
}

export function unavailableMessage(queued: QueuedJob | null, failed: boolean, fallback = 'the computed result is shown') {
  if (failed) return `The AI answer did not finish, so ${fallback}.`;
  if (!queued) return '';
  if (queued.status === 'rate_limited') return `AI is paused for a minute because of the request limit, so ${fallback}.`;
  if (queued.reason === 'assistant_runner_offline') return `The AI runner is offline, so ${fallback}.`;
  if (queued.status === 'unavailable') return `AI is not available right now, so ${fallback}.`;
  return '';
}
