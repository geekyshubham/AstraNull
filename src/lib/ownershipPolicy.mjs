/**
 * Ownership-proof policy: does the customer demonstrably control this exact target?
 *
 * Pure and persistence-free so both runtimes share one threshold. A target group's
 * `ownership_status` is presentation-only summary data: it must never authorize egress to a
 * sibling or newly declared target.
 */

/**
 * Ordered strength of verification states. Higher means stronger evidence of control.
 *
 * Outside-in only (ADR-0008): there is no agent, so `agent_verified` is intentionally absent
 * from this map. Any legacy row still stored as `agent_verified` falls through to rank 0
 * (unverified) via the `?? 0` lookups below and must re-prove control with DNS/HTTP before
 * it authorizes any egress.
 */
export const VERIFICATION_RANK = Object.freeze({
  unverified: 0,
  pending: 1,
  dns_verified: 2,
  provider_verified: 2,
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

/**
 * OWNERSHIP-01: canonicalize a DNS-challenge state for *reads*. A challenge that is still stored
 * as `pending` but whose `expires_at` is in the past is no longer actionable — presenting it as
 * `pending` makes the UI tell operators to publish a dead TXT record. This normalizes the
 * presented state to `expired` without mutating or persisting the row, so API reads and the
 * target-detail page stay honest the instant the clock passes expiry.
 *
 * This is read-only: `verifyChallenge`/reissue paths key off the *stored* row (not this value),
 * so lazy expiry here never races the authoritative state machine. The stored row still
 * transitions to `expired` on the next verify (race-safe, audited).
 *
 * @param {string|null|undefined} state stored challenge state
 * @param {string|null|undefined} expiresAt ISO expiry timestamp
 * @param {number} [now] epoch ms (injectable for clock-controlled tests)
 * @returns {string} the state to present
 */
export function normalizeChallengeStateForRead(state, expiresAt, now = Date.now()) {
  if (state !== 'pending') return state;
  const expiry = Date.parse(expiresAt);
  if (Number.isFinite(expiry) && expiry <= now) return 'expired';
  return state;
}
