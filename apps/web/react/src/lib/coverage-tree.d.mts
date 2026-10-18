export type CoverageOutcome = 'gap' | 'review' | 'stale' | 'partial' | 'pass' | 'untested' | 'na';

export interface CoverageCell {
  outcome: CoverageOutcome;
  testedChecks: number;
  applicableChecks: number;
  hosts: number;
  testedHosts: number;
}

export const COVERAGE_OUTCOME_LABEL: Readonly<Record<CoverageOutcome, string>>;
export const COVERAGE_OUTCOME_TONE: Readonly<Record<CoverageOutcome, 'danger' | 'warn' | 'success' | 'muted'>>;

export function openFindingChecksByTarget(findings: Array<Record<string, unknown>>): Map<string, Set<string>>;

export function coverageCell(input: {
  checkIds: Set<string>;
  targetId: string;
  runs: Array<Record<string, unknown>>;
  evidence: Array<Record<string, unknown>>;
  openChecks?: Set<string>;
  nowMs?: number;
}): CoverageCell;

export function rollUpCoverage(cells: CoverageCell[]): CoverageCell;

export function rowHasResult(cells: CoverageCell[]): boolean;

export interface AttackFamily { id: string; label: string; keys: string[] }
export const ATTACK_FAMILIES: ReadonlyArray<AttackFamily>;
export function attackFamilyCheckIds(checks: Array<Record<string, unknown>>, family: AttackFamily): Set<string>;
