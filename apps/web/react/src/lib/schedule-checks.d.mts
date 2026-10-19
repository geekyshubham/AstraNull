import type { DataItem } from './types';

export interface ScheduleCheckEntry {
  id: string;
  name: string;
  category: string;
  selectable: boolean;
  reason: string;
  check: DataItem;
}

export const SOC_GOVERNED_LABEL: string;
export const SOC_GOVERNED_REASON: string;
export function isScheduleCheckSelectable(check: DataItem | null | undefined, allChecksRunnable?: boolean): boolean;
export function scheduleCheckEntries(checks: DataItem[], options?: { allChecksRunnable?: boolean }): ScheduleCheckEntry[];
export function filterScheduleCheckEntries(entries: ScheduleCheckEntry[], options?: { query?: string; category?: string; keepId?: string }): ScheduleCheckEntry[];
export function scheduleCheckCategoryCounts(entries: ScheduleCheckEntry[]): Array<{ id: string; label: string; count: number }>;
