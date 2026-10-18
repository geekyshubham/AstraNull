import type { DataItem } from './types';

export type VectorAvailability = {
  id: 'soc_gated' | 'monitor_only' | 'select_target' | 'safe_runnable' | 'target_not_supported' | 'additional_input';
  label: string;
  detail: string;
  tone: 'success' | 'warn' | 'muted' | 'info';
  runnableChecks: DataItem[];
};

export function effectiveVectorTargetKind(target: DataItem): string;
export function vectorCheckSupportsTarget(check: DataItem | null | undefined, target: DataItem | null | undefined): boolean;
export function evidenceCapabilityCopy(capability: unknown): { label: string; detail: string; tone: 'success' | 'warn' | 'muted' | 'info' };
export function vectorTargetAvailability(vector: DataItem, checks: DataItem[], target: DataItem | null): VectorAvailability;
export function searchAndFilterVectors(vectors: DataItem[], options?: {
  query?: string;
  section?: string;
  capability?: string;
  execution?: string;
  targetAvailability?: string;
  checks?: DataItem[];
  target?: DataItem | null;
}): DataItem[];
export function preferredRunnableCheck(vector: DataItem, availability: VectorAvailability): DataItem | null;
export function sortVectorsByTargetFit(vectors: DataItem[], checks: DataItem[], target: DataItem | null): DataItem[];
export function countCompatibleSafeChecks(pairs: DataItem[], checks: DataItem[]): number;
export interface VectorCheckGroup {
  checkId: string;
  check: DataItem;
  vectors: DataItem[];
}
export function groupVectorsByCheck(vectors: DataItem[], checks: DataItem[]): { groups: VectorCheckGroup[]; unmapped: DataItem[] };
export function latestRunForCheckOnTarget(runs: DataItem[], checkId: string, targetId: string): DataItem | null;
export interface CheckCategory {
  id: string;
  label: string;
  families: readonly string[];
}
export const CHECK_CATEGORIES: readonly CheckCategory[];
export const MISC_CATEGORY_ID: 'misc';
export function checkCategoryId(check: DataItem | null | undefined): string;
export function categorizeCheckGroups(groups: VectorCheckGroup[], unmapped: DataItem[], category?: string): {
  counts: Record<string, number>;
  groups: VectorCheckGroup[];
  unmapped: DataItem[];
};
