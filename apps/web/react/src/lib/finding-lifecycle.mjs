/**
 * Normalize the lifecycle aliases returned by the core and portal-revamp findings APIs.
 * Missing lifecycle data remains open for compatibility with the existing portal contract.
 *
 * @param {Record<string, unknown> | null | undefined} finding
 */
export function findingStatus(finding) {
  if (!finding || typeof finding !== 'object' || Array.isArray(finding)) return 'open';
  for (const key of ['status', 'state']) {
    const value = finding[key];
    if (value === undefined || value === null) continue;
    const normalized = String(value).trim().toLowerCase();
    if (normalized) return normalized;
  }
  return 'open';
}

/**
 * @param {Record<string, unknown> | null | undefined} finding
 */
export function isFindingOpen(finding) {
  return findingStatus(finding) === 'open';
}

/** Statuses whose severity SLA clock keeps running: work has not finished on them. */
export const SLA_ACTIVE_STATUSES = Object.freeze(['open', 'in_progress']);

/**
 * @param {Record<string, unknown> | null | undefined} finding
 */
export function isFindingSlaActive(finding) {
  return SLA_ACTIVE_STATUSES.includes(findingStatus(finding));
}
