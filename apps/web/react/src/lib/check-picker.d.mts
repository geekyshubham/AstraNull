import type { DataItem } from './types';

export const OTHER_SECTION_ID: string;
export const OTHER_SECTION_LABEL: string;
export const MONITOR_ONLY_TIER: string;

export type CheckExclusionReason = 'soc_gated' | 'monitor_only' | 'not_customer_runnable' | 'unknown_check';

export type CheckSection = { id: string; label: string; checks: DataItem[] };

export type SelectionSummary = {
  selectedCount: number;
  stepCount: number;
  requestUpperBound: number | null;
  incompatible: { check_id: string; name: string; supported_targets: string[] }[];
  applicableTargetCount: number;
  targetCount: number;
};

export function checkExclusionReason(check: DataItem | null | undefined): CheckExclusionReason | null;
export function selectableChecks(checks: DataItem[]): {
  checks: DataItem[];
  excluded: { soc_gated: number; monitor_only: number; not_customer_runnable: number; total: number };
};
export function groupChecksBySection(checks: DataItem[]): CheckSection[];
export function checkSupportsTarget(check: DataItem | null | undefined, target: DataItem | null | undefined): boolean;
export function checkTargetCoverage(check: DataItem, targets: DataItem[]): { supported: number; total: number; supportedTargetIds: string[] };
export function checkProbeSummary(check: DataItem | null | undefined): { kind: string | null; maxRequests: number | null; timeoutMs: number | null };
export function filterChecks(checks: DataItem[], query: string): DataItem[];
export function summarizeSelection(input: {
  checks: DataItem[];
  selectedIds: string[];
  targets: DataItem[];
  targetId?: string | null;
}): SelectionSummary;
