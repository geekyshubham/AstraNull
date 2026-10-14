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

/** How AstraNull proved a `fix_verified` closure (`verification_basis` on the finding or its `finding.fix_verified` audit). */
export const FIX_VERIFIED_BASIS_LABELS = Object.freeze({
  violation_not_reproduced: 'Fixed — violation no longer reproduced (same perspective, ≥2 agreeing samples, all declared ports probed)',
  passing_retest: 'Fixed — passing retest',
});

export const FIX_VERIFIED_BASIS_UNKNOWN = 'Fixed — verified by a later re-check (how it was verified is not recorded)';

function basisText(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function stampOf(event) {
  for (const key of ['ts', 'created_at', 'at']) {
    const parsed = Date.parse(basisText(event?.[key]));
    if (Number.isFinite(parsed)) return parsed;
  }
  return 0;
}

/** Closure basis for a fix-verified finding: the finding's own field first, else the newest matching audit event. */
export function fixVerifiedBasis(finding, auditItems = []) {
  const own = basisText(finding?.verification_basis);
  if (own) return { basis: own, label: FIX_VERIFIED_BASIS_LABELS[own] ?? FIX_VERIFIED_BASIS_UNKNOWN, source: 'finding' };
  const runId = basisText(finding?.verifying_run_id);
  const events = (Array.isArray(auditItems) ? auditItems : [])
    .filter((event) => event && typeof event === 'object' && basisText(event.action).toLowerCase() === 'finding.fix_verified')
    .map((event) => ({ event, metadata: event.metadata && typeof event.metadata === 'object' ? event.metadata : {} }))
    .filter(({ metadata }) => basisText(metadata.verification_basis))
    .sort((left, right) => stampOf(right.event) - stampOf(left.event));
  const match = events.find(({ metadata }) => runId && basisText(metadata.verifying_run_id ?? metadata.test_run_id) === runId) ?? events[0];
  if (match) {
    const basis = basisText(match.metadata.verification_basis);
    return { basis, label: FIX_VERIFIED_BASIS_LABELS[basis] ?? FIX_VERIFIED_BASIS_UNKNOWN, source: 'audit' };
  }
  return { basis: '', label: FIX_VERIFIED_BASIS_UNKNOWN, source: '' };
}

/** Short list wording for each closure basis. */
export const FIX_VERIFIED_BASIS_HINTS = Object.freeze({
  violation_not_reproduced: 'No longer reproduced',
  passing_retest: 'Passing retest',
});

/** List hint for a fix-verified finding; '' unless the finding itself carries a known `verification_basis`. */
export function fixVerifiedBasisHint(finding) {
  if (findingStatus(finding) !== 'fix_verified') return '';
  return FIX_VERIFIED_BASIS_HINTS[basisText(finding?.verification_basis)] ?? '';
}
