import type { FindingStatus } from './findings-query.mjs';
export type AssistantFindingFilters = { q?: string; status?: FindingStatus; severity?: string; check_id?: string; target_id?: string; test_run_id?: string };
export type FindingFilterPreview = { filters: AssistantFindingFilters; explanation: string };
export const FILTER_QUESTION_MAX: number;
export const ASSISTANT_FILTER_KEYS: readonly string[];
export function sanitizeFindingFilterPreview(value: unknown): FindingFilterPreview | null;
export function assistantFindingQuery(preview: unknown, paging?: { limit?: number; page?: number }): string | null;
