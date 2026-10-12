import type { AcceptedExecution, DataItem } from './types';

export const REVIEWED_SAFE_CHECK_ID: 'waf.evasion_base64_wrap.safe';
export type ReviewedSafeOptions = { target: DataItem | null; tenantId: string; now?: number };
export type ReviewedSafePlanPresentation = {
  valid: boolean;
  reason: string | null;
  planDigest: string;
  endpoint: string;
  expiresAt: string;
  checkVersion: string;
  scenarioVersion: string;
  maximumProbeOperations: number | null;
};
export type ReviewedSafeReviewPresentation = ReviewedSafePlanPresentation & {
  reviewId: string;
  current: boolean;
  available: boolean;
};
export function reviewedSafePlanPresentation(proposal: unknown, options: ReviewedSafeOptions): ReviewedSafePlanPresentation;
export function reviewedSafeReviewPresentation(review: unknown, options: ReviewedSafeOptions): ReviewedSafeReviewPresentation;
export function reviewedSafeStartBody(review: unknown, options: ReviewedSafeOptions): {
  target_group_id: string;
  target_id: string;
  check_id: typeof REVIEWED_SAFE_CHECK_ID;
  reviewed_operation_id: string;
} | null;
export function acceptedReviewedSafeExecution(response: unknown, targetId: string): AcceptedExecution | null;
