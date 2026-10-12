import type { GrantClock } from '../contracts/reviewedExecutionGrant.mjs';
import type { ReviewedExecutionGrantSigningAdapter, ReviewedExecutionGrantTrust } from './reviewedExecutionGrant.mjs';
export function createEnvReviewedExecutionGrantAdapter(env?: Record<string, string | undefined>, options?: {
  now?: () => GrantClock;
}): ReviewedExecutionGrantSigningAdapter;
export function createExternalReviewedExecutionGrantAdapter(config?: {
  env?: Record<string, string | undefined>;
  trust: ReviewedExecutionGrantTrust;
  fetchFn?: typeof fetch;
  now?: () => GrantClock;
}): ReviewedExecutionGrantSigningAdapter;
