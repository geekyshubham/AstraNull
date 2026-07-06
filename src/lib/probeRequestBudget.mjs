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