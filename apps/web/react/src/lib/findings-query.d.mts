import type { DataItem } from './types';
export type FindingStatus = 'open' | 'in_progress' | 'accepted_risk' | 'accepted' | 'resolved' | 'closed' | 'false_positive';
export const FINDING_STATUSES: readonly FindingStatus[];
export const FINDING_STATUS_LABELS: Readonly<Record<FindingStatus, string>>;
export const FINDING_STATUS_GROUPS: ReadonlyArray<{ id: string; label: string; statuses: readonly FindingStatus[] }>;
export const FINDINGS_LIMIT_MAX: number;
export type FindingSeverityClass = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
export const FINDING_SEVERITY_CLASSES: readonly FindingSeverityClass[];
export const FINDING_SEVERITY_CLASS_LABELS: Readonly<Record<FindingSeverityClass, string>>;
export function findingSeverityClass(value: unknown): FindingSeverityClass;
export type FindingsFilters = {
  q?: string; status?: string; severity?: string; check_id?: string; target_group_id?: string; target_id?: string; test_run_id?: string; limit?: number; page?: number;
};
export type FindingsEnvelope = {
  items: DataItem[]; total: number | null; page: number; pages: number | null; limit: number | null; hasMore: boolean; emptyReason: string | null; exact: boolean;
};
export function findingStatusFilter(value: unknown): FindingStatus | '';
export function findingsQuery(filters?: FindingsFilters): string;
export function findingsPath(filters?: FindingsFilters): string;
export function parseFindingsEnvelope(body: unknown): FindingsEnvelope;
export function findingsComplete(envelope: FindingsEnvelope | null | undefined, loadedCount: number): boolean;
export function findingGroupCheckId(groupKey: unknown): string;
