export interface ResourceFamily {
  id: string;
  label: string;
  metric: string;
}

export type ResourceMatrixStatus =
  | 'protected'
  | 'exposed'
  | 'inconclusive'
  | 'not_run'
  | 'not_applicable'
  | 'stale';

export interface ResourceFamilyVerdictState {
  status: ResourceMatrixStatus;
  applicableCheckCount: number;
  testedCheckCount: number;
  freshCheckCount: number;
  staleCheckCount: number;
  protectedCount: number;
  exposedCount: number;
  inconclusiveCount: number;
  latestEvidenceAt: string | null;
}

export const RESOURCE_EVIDENCE_FRESHNESS_DAYS: number;
export const RESOURCE_EVIDENCE_FRESHNESS_MS: number;
export const RESOURCE_FAMILIES: ResourceFamily[];

export function resourceMatrixGroups(
  targetGroups: Array<Record<string, unknown>>,
): Array<Record<string, unknown>>;

export function resourceFamilyCheckIds(
  checks: Array<Record<string, unknown>>,
  family: ResourceFamily,
): Set<string>;

export function applicableResourceFamilyCheckIds(input: {
  checks: Array<Record<string, unknown>>;
  family: ResourceFamily;
  groupId: string;
  targets: Array<Record<string, unknown>>;
  targetInventoryLoaded?: boolean;
}): Set<string>;

export function resourceFamilyVerdictState(input: {
  checkIds: Set<string>;
  groupId: string;
  runs: Array<Record<string, unknown>>;
  evidence: Array<Record<string, unknown>>;
  nowMs?: number;
  freshnessWindowMs?: number;
}): ResourceFamilyVerdictState;
