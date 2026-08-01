/**
 * Ownership-proof policy: does the customer demonstrably control this target?
 *
 * Pure and persistence-free so both runtimes share one threshold. Developer validation reads
 * the JSON store and Postgres reads repositories; when this logic lived in
 * services/ownershipVerification.mjs, the Postgres side could not import it without pulling in
 * the dev store, so the rule got duplicated — and immediately drifted (the group path briefly
 * required `agent_verified`, which would have denied Postgres tenants whose DNS proof
 * legitimately lands as a group-level `dns_verified`).
 */

/** Ordered strength of verification states. Higher means stronger evidence of control. */
export const VERIFICATION_RANK = Object.freeze({
  unverified: 0,
  pending: 1,
  dns_verified: 2,
  agent_verified: 3,
  user_confirmed: 4,
});

/**
 * Weakest state accepted as proof of control.
 *
 * `dns_verified` qualifies: publishing a server-generated nonce in the domain's TXT records
 * demonstrates control of that domain, the same evidence ACME and search-console verification
 * rely on. `pending` does not — it means only that a challenge was issued, which any tenant can
 * do against a domain they do not own.
 */
export const MIN_PROOF_RANK = VERIFICATION_RANK.dns_verified;

/**
 * Decides ownership from the two places the product records it.
 *
 * Both are accepted because either alone produces false denials:
 *   - `groupState` (`target_groups.ownership_status`) is what the agent ownership challenge
 *     sets, and what the Postgres DNS flow sets — a group can be verified with no per-target
 *     rows at all.
 *   - `targetState` (latest `target_verifications` row) is how developer-validation mode records
 *     DNS TXT proof, and carries signed per-target confirmations.
 *
 * @param {{ groupState?: string|null, targetState?: string|null }} [states]
 * @returns {{ verified: boolean, state: string, source: 'target'|'group'|null }}
 */
export function ownershipProofFromStates({ groupState, targetState } = {}) {
  const group = String(groupState ?? 'unverified');
  const target = String(targetState ?? 'unverified');
  if ((VERIFICATION_RANK[group] ?? 0) >= MIN_PROOF_RANK) {
    return { verified: true, state: group, source: 'group' };
  }
  if ((VERIFICATION_RANK[target] ?? 0) >= MIN_PROOF_RANK) {
    return { verified: true, state: target, source: 'target' };
  }
  // Report whichever state is further along, so a denial names the real blocker.
  const best = (VERIFICATION_RANK[target] ?? 0) >= (VERIFICATION_RANK[group] ?? 0) ? target : group;
  return { verified: false, state: best, source: null };
}
