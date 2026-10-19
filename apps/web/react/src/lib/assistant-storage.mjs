/**
 * Browser-local assistant history: sessions and in-flight job ids per tenant and user.
 * Every value read back is re-validated, so a tampered or stale entry can never render as markup.
 */
import { safeHref } from './assistant-markdown.mjs';
import { sanitizePageContext } from './assistant-page-context.mjs';
import { sanitizeDataResults, sanitizeToolCalls } from './assistant-visuals.mjs';

export const MAX_SESSIONS = 20;
export const MAX_MESSAGES = 50;
export const MAX_CONTENT = 20_000;
export const MAX_USER_CONTENT = 4000;
export const PENDING_JOB_TTL_MS = 30 * 60 * 1000;

const ROLES = new Set(['user', 'assistant']);
const STATUSES = new Set(['pending', 'done', 'failed', 'cancelled']);

function text(value, max) {
  return typeof value === 'string' ? value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').slice(0, max) : '';
}

function time(value) {
  const ms = Date.parse(String(value ?? ''));
  return Number.isFinite(ms) ? new Date(ms).toISOString() : new Date(0).toISOString();
}

export function storageKey(tenantId, userId) {
  return `astranull.assistant.v1:${text(tenantId, 120) || 'tenant'}:${text(userId, 120) || 'user'}`;
}

export function newId(prefix) {
  const random = typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID().replace(/-/g, '').slice(0, 16) : Math.random().toString(16).slice(2, 18);
  return `${prefix}_${random}`;
}

export function sanitizeContext(value) {
  if (!value || typeof value !== 'object') return null;
  const context = {};
  for (const key of ['finding_id', 'target_id', 'run_id', 'check_id', 'scan_id']) {
    const item = text(value[key], 200).trim();
    if (item) context[key] = item;
  }
  const page = sanitizePageContext(value.page);
  if (page) context.page = page;
  const label = text(value.label, 160).trim();
  if (label) context.label = label;
  return Object.keys(context).length ? context : null;
}

export function sanitizeMessage(value) {
  if (!value || typeof value !== 'object' || !ROLES.has(value.role)) return null;
  const message = {
    id: text(value.id, 64) || newId('msg'),
    role: value.role,
    content: text(value.content, value.role === 'user' ? MAX_USER_CONTENT : MAX_CONTENT),
    created_at: time(value.created_at),
  };
  if (value.role === 'assistant') {
    message.status = STATUSES.has(value.status) ? value.status : 'done';
    const jobId = text(value.job_id, 64);
    if (jobId) message.job_id = jobId;
    const searches = Array.isArray(value.searches) ? value.searches.map((item) => text(item, 200).trim()).filter(Boolean).slice(0, 12) : [];
    if (searches.length) message.searches = searches;
    const sources = Array.isArray(value.sources)
      ? value.sources.flatMap((item) => {
        const url = safeHref(item?.url);
        return url ? [{ url, ...(text(item?.title, 200).trim() ? { title: text(item.title, 200).trim() } : {}) }] : [];
      }).slice(0, 12)
      : [];
    if (sources.length) message.sources = sources;
    const error = text(value.error, 300);
    if (error) message.error = error;
    const model = text(value.model, 80);
    if (model) message.model = model;
    const toolCalls = sanitizeToolCalls(value.tool_calls);
    if (toolCalls.length) message.tool_calls = toolCalls;
    const dataResults = sanitizeDataResults(value.data_results);
    if (dataResults.length) message.data_results = dataResults;
  }
  return message;
}

export function sanitizeSession(value) {
  if (!value || typeof value !== 'object') return null;
  const messages = (Array.isArray(value.messages) ? value.messages : []).map(sanitizeMessage).filter(Boolean).slice(-MAX_MESSAGES);
  return {
    id: text(value.id, 64) || newId('chat'),
    title: text(value.title, 80) || 'New chat',
    created_at: time(value.created_at),
    updated_at: time(value.updated_at ?? value.created_at),
    context: sanitizeContext(value.context),
    messages,
  };
}

export function titleFrom(content) {
  const line = text(content, 400).replace(/\s+/g, ' ').trim();
  return line.length > 60 ? `${line.slice(0, 57)}…` : line || 'New chat';
}

export function loadSessions(storage, key) {
  try {
    const parsed = JSON.parse(storage?.getItem(key) ?? '[]');
    return (Array.isArray(parsed) ? parsed : [])
      .map(sanitizeSession)
      .filter((session) => session && session.messages.length)
      .sort((left, right) => right.updated_at.localeCompare(left.updated_at))
      .slice(0, MAX_SESSIONS);
  } catch {
    return [];
  }
}

/** Writes the newest sessions; on quota errors it keeps halving until the write fits. */
export function saveSessions(storage, key, sessions) {
  if (!storage) return 0;
  let keep = sessions
    .map(sanitizeSession)
    .filter((session) => session && session.messages.length)
    .sort((left, right) => right.updated_at.localeCompare(left.updated_at))
    .slice(0, MAX_SESSIONS);
  while (true) {
    try {
      storage.setItem(key, JSON.stringify(keep));
      return keep.length;
    } catch {
      if (keep.length <= 1) {
        try { storage.removeItem(key); } catch { /* storage unavailable */ }
        return 0;
      }
      keep = keep.slice(0, Math.ceil(keep.length / 2));
    }
  }
}

export function loadPendingJobs(storage, key, now = Date.now()) {
  try {
    const parsed = JSON.parse(storage?.getItem(`${key}:jobs`) ?? '{}');
    const out = {};
    for (const [messageId, entry] of Object.entries(parsed && typeof parsed === 'object' ? parsed : {})) {
      const jobId = text(entry?.job_id, 64);
      const sessionId = text(entry?.session_id, 64);
      const startedAt = Number(entry?.started_at);
      if (jobId && sessionId && Number.isFinite(startedAt) && now - startedAt < PENDING_JOB_TTL_MS) {
        out[text(messageId, 64)] = { job_id: jobId, session_id: sessionId, started_at: startedAt };
      }
    }
    return out;
  } catch {
    return {};
  }
}

export function savePendingJobs(storage, key, jobs) {
  try {
    if (Object.keys(jobs).length) storage?.setItem(`${key}:jobs`, JSON.stringify(jobs));
    else storage?.removeItem(`${key}:jobs`);
  } catch {
    /* storage unavailable */
  }
}

/** Conversation sent to the server: finished turns only, newest 20. */
export function conversationForRequest(messages) {
  return messages
    .filter((message) => message.role === 'user' || (message.status === 'done' && message.content))
    .slice(-20)
    .map((message) => ({ role: message.role, content: message.content.slice(0, message.role === 'user' ? MAX_USER_CONTENT : 8000) }));
}
