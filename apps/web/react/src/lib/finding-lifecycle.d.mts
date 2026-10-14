export function findingStatus(
  finding: Record<string, unknown> | null | undefined
): string;

export function isFindingOpen(
  finding: Record<string, unknown> | null | undefined
): boolean;

export const SLA_ACTIVE_STATUSES: readonly string[];

export function isFindingSlaActive(
  finding: Record<string, unknown> | null | undefined
): boolean;

export const FIX_VERIFIED_BASIS_LABELS: Readonly<Record<'violation_not_reproduced' | 'passing_retest', string>>;
export const FIX_VERIFIED_BASIS_UNKNOWN: string;
export type FixVerifiedBasis = { basis: string; label: string; source: 'finding' | 'audit' | '' };
export function fixVerifiedBasis(
  finding: Record<string, unknown> | null | undefined,
  auditItems?: unknown[]
): FixVerifiedBasis;
export const FIX_VERIFIED_BASIS_HINTS: Readonly<Record<'violation_not_reproduced' | 'passing_retest', string>>;
export function fixVerifiedBasisHint(
  finding: Record<string, unknown> | null | undefined
): '' | 'No longer reproduced' | 'Passing retest';
