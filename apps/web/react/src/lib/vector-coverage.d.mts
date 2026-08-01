/**
 * Types for vector-coverage.mjs. The implementation is plain ESM so `node --test` can import
 * the real shipped logic instead of a copy; this declaration lets the `.tsx` import it too.
 */
export type FamilyCoverageStatus = 'evidence' | 'run' | 'policy' | 'none' | 'no-data';

export type FamilyCoverage = {
  status: FamilyCoverageStatus;
  policyCount: number;
  runCount: number;
  evidenceCount: number;
};

export type VectorFamily = { label: string; keys: string[] };

export declare const VECTOR_FAMILIES: VectorFamily[];

export declare function stringValue(item: Record<string, unknown>, key: string): string;

export declare function nestedString(
  item: Record<string, unknown>,
  key: string,
  nestedKey: string,
): string;

export declare function itemCheckId(item: Record<string, unknown>): string;

export declare function itemTargetGroupId(item: Record<string, unknown>): string;

export declare function checkMatchesFamily(
  check: Record<string, unknown>,
  family: { keys: string[] },
): boolean;

export declare function familyCheckIds(
  checks: Record<string, unknown>[],
  family: { keys: string[] },
): Set<string>;

export declare function familyCoverage(input: {
  checkIds: Set<string>;
  groupId: string;
  testPolicies: Record<string, unknown>[];
  runs: Record<string, unknown>[];
  evidence: Record<string, unknown>[];
}): FamilyCoverage;
