import type { DataItem } from './types';

export const SCAN_STATUSES: readonly string[];
export const ACTIVE_SCAN_STATUSES: readonly string[];
export const CANCELLABLE_SCAN_STATUSES: readonly string[];
export const TERMINAL_SCAN_STATUSES: readonly string[];
export const STEP_STATUSES: readonly string[];
export const ACTIVE_STEP_STATUSES: readonly string[];
export const SCAN_RECURRENCE_CADENCES: readonly string[];
export const MAX_SCAN_CHECKS: number;
export const MIN_SCHEDULE_LEAD_MS: number;
export const MAX_SCAN_NAME_LENGTH: number;
export const SCAN_POLL_BASE_MS: number;
export const SCAN_POLL_MAX_MS: number;
export const SCAN_POLL_SCHEDULED_MS: number;
export const SCAN_ERROR_COPY: Readonly<Record<string, string>>;

export type ScanTone = 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted';

export type ScanForm = {
  targetIds: string[];
  checkIds: string[];
  name: string;
  schedule: 'now' | 'later';
  scheduledForLocal: string;
  recurrence: string;
  timezone: string;
};

export type ScanPayload = {
  target_ids: string[];
  check_ids: string[];
  target_id?: string;
  name?: string;
  scheduled_for?: string;
  recurrence?: string | { cadence: string; timezone: string };
};

export type ScanPatch = Partial<{
  target_ids: string[];
  check_ids: string[];
  name: string | null;
  scheduled_for: string | null;
  recurrence: string | { cadence: string; timezone: string };
}>;

export type ActivityItem = DataItem & { id: string | number; at?: string | null };

export function humanizeReason(code: unknown): string;
export function scanErrorMessage(payload: unknown, fallback?: string): string;
export function isScanActive(scan: DataItem | null | undefined): boolean;
export function isScanCancellable(scan: DataItem | null | undefined): boolean;
export function isScanEditable(scan: DataItem | null | undefined): boolean;
export function isScanTerminal(scan: DataItem | null | undefined): boolean;
export function isScanScheduled(scan: DataItem | null | undefined): boolean;
export function scanStatusTone(status: unknown): ScanTone;
export function stepStatusTone(status: unknown): ScanTone;
export function scanStatusLabel(status: unknown): string;
export function stepStatusLabel(status: unknown): string;
export function isStepActive(step: DataItem | null | undefined): boolean;
export function scanProgressPercent(summary: unknown): number;
export function formatStepRequest(request: unknown): string;
export function formatStepResponse(response: unknown): string;
export function formatRequestsSent(step: unknown): string;
export function mergeActivity<T extends ActivityItem>(existing: T[], incoming: T[]): T[];
export function nextPollDelay(input?: { status?: unknown; errorCount?: number }): number | null;
export function scopeLabel(scan: DataItem | null | undefined): string;
export function recurrenceLabel(recurrence: unknown): string;
export function scanDisplayName(scan: DataItem | null | undefined): string;
export function isoToLocalDatetime(iso: unknown): string;
export function localDatetimeToIso(value: unknown): string;
export function minScheduleLocalValue(now?: number | Date): string;
export function emptyScanForm(overrides?: Partial<ScanForm>): ScanForm;
export function scanFormFromScan(scan: DataItem | null | undefined, mode?: 'edit' | 'reschedule'): ScanForm;
export function validateScanForm(form: ScanForm, options?: { now?: number | Date }): { ok: boolean; errors: Record<string, string> };
export function buildScanPayload(form: ScanForm): ScanPayload;
export function buildScanPatch(scan: DataItem, form: ScanForm): ScanPatch;
