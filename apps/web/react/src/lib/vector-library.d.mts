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
