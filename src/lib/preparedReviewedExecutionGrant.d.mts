import type { GrantClock, GrantFailure, ReviewedExecutionGrant, ReviewedExecutionGrantContext, ReviewedExecutionGrantEnvelope } from '../contracts/reviewedExecutionGrant.mjs';
import type { ReviewedExecutionGrantTrust, ReviewedExecutionGrantSigningAdapter } from './reviewedExecutionGrant.mjs';
/** Exact persisted envelope; no durability or current database authority is implied by this helper. */
export function signPreparedReviewedExecutionGrant(input: { envelope: ReviewedExecutionGrantEnvelope;
  context: ReviewedExecutionGrantContext; trust: ReviewedExecutionGrantTrust; signingAdapter: ReviewedExecutionGrantSigningAdapter;
  timeoutMs?: number; signal?: AbortSignal; now?: () => GrantClock }):
  Promise<GrantFailure | { ok: true; grant: Readonly<ReviewedExecutionGrant> }>;
