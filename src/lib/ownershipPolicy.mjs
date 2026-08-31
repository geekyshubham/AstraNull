/**
 * Ownership-proof policy: does the customer demonstrably control this exact target?
 *
 * Pure and persistence-free so both runtimes share one threshold. A target group's
 * `ownership_status` is presentation-only summary data: it must never authorize egress to a
 * sibling or newly declared target.
 */

/** Ordered strength of verification states. Higher means stronger evidence of control. */
export const VERIFICATION_RANK = Object.freeze({
  unverified: 0,
  pending: 1,
  dns_verified: 2,
  provider_verified: 2,
  agent_verified: 3,
  user_confirmed: 4,
});

/** Weakest target-bound state accepted as proof of control. */
export const MIN_PROOF_RANK = VERIFICATION_RANK.dns_verified;

/**
 * Decides ownership exclusively from the current verification bound to the requested target.
 * `groupState` is intentionally not accepted, even if older callers still pass it.
 *
 * @param {{ groupState?: string|null, targetState?: string|null }} [states]
 * @returns {{ verified: boolean, state: string, source: 'target'|null }}
 */
export function ownershipProofFromStates({ targetState } = {}) {
  const target = String(targetState ?? 'unverified');
  if ((VERIFICATION_RANK[target] ?? 0) >= MIN_PROOF_RANK) {
    return { verified: true, state: target, source: 'target' };
  }
  return { verified: false, state: target, source: null };
}

/**
 * Computes an all-target group summary without turning that summary into authorization.
 * The weakest active target wins, so adding an unverified target cannot retain an old
 * group-wide verified presentation state.
 *
 * @param {Array<string|null|undefined>} states
 * @returns {keyof typeof VERIFICATION_RANK}
 */
export function ownershipSummaryFromTargetStates(states = []) {
  if (!Array.isArray(states) || states.length === 0) return 'unverified';
  let summary = 'user_confirmed';
  let minimum = VERIFICATION_RANK.user_confirmed;
  for (const value of states) {
    const state = String(value ?? 'unverified');
    const rank = VERIFICATION_RANK[state] ?? VERIFICATION_RANK.unverified;
    if (rank < minimum) {
      minimum = rank;
      summary = Object.hasOwn(VERIFICATION_RANK, state) ? state : 'unverified';
    }
  }
  return summary;
}
