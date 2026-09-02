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
