import type { AssistantPageContext } from './assistant-page-context.mjs';
import type { DataResult, ToolCall } from './assistant-visuals.mjs';

export type AssistantContext = {
  finding_id?: string;
  target_id?: string;
  run_id?: string;
  check_id?: string;
  scan_id?: string;
  page?: AssistantPageContext;
  label?: string;
};
export type AssistantSource = { url: string; title?: string };
export type AssistantMessage = {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  created_at: string;
  status?: 'pending' | 'done' | 'failed' | 'cancelled';
  job_id?: string;
  searches?: string[];
  sources?: AssistantSource[];
  error?: string;
  model?: string;
  tool_calls?: ToolCall[];
  data_results?: DataResult[];
};
export type AssistantSession = {
  id: string;
  title: string;
  created_at: string;
  updated_at: string;
  context: AssistantContext | null;
  messages: AssistantMessage[];
};
export type PendingJobs = Record<string, { job_id: string; session_id: string; started_at: number }>;
type StorageLike = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> | null | undefined;

export const MAX_SESSIONS: number;
export const MAX_MESSAGES: number;
export const MAX_CONTENT: number;
export const MAX_USER_CONTENT: number;
export const PENDING_JOB_TTL_MS: number;
export function storageKey(tenantId: unknown, userId: unknown): string;
export function newId(prefix: string): string;
export function sanitizeContext(value: unknown): AssistantContext | null;
export function sanitizeMessage(value: unknown): AssistantMessage | null;
export function sanitizeSession(value: unknown): AssistantSession | null;
export function titleFrom(content: string): string;
export function loadSessions(storage: StorageLike, key: string): AssistantSession[];
export function saveSessions(storage: StorageLike, key: string, sessions: AssistantSession[]): number;
export function loadPendingJobs(storage: StorageLike, key: string, now?: number): PendingJobs;
export function savePendingJobs(storage: StorageLike, key: string, jobs: PendingJobs): void;
export function conversationForRequest(messages: AssistantMessage[]): Array<{ role: 'user' | 'assistant'; content: string }>;
