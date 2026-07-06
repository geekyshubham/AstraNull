/** Default cap aligned with legacy bounded port-scan limit. */
export const DEFAULT_PROBE_REQUEST_BUDGET = 15;

/**
 * Resolve the outbound request budget for a capability probe job.
 * Prefers signed job constraints, then probe profile, then a positive default.
 */
export function resolveProbeRequestBudget(job) {
  const fromConstraints = job?.constraints?.max_requests;
  if (Number.isInteger(fromConstraints) && fromConstraints > 0) {
    return fromConstraints;
  }
  const fromProfile = job?.probe_profile?.max_requests;
  if (Number.isInteger(fromProfile) && fromProfile > 0) {
    return fromProfile;
  }
  return DEFAULT_PROBE_REQUEST_BUDGET;
}

/** Cap a probe sequence length (e.g. rate-limit HEADs) by job budget and a hard ceiling. */
export function resolveBoundedSequenceBudget(job, { ceiling = 5 } = {}) {
  return Math.min(ceiling, resolveProbeRequestBudget(job));
}

/**
 * AXFR probe accounting: one resolveNs attempt plus optional single TCP-53 query.
 * @param {{ nameserverResolved: boolean, tcpAttempted: boolean }} counts
 */
export function countAxfrProbeRequests({ nameserverResolved, tcpAttempted }) {
  let n = 0;
  if (nameserverResolved) n += 1;
  if (tcpAttempted) n += 1;
  return n;
}