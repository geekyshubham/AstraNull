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
