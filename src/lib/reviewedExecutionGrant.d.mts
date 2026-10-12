import type { GrantClock, GrantFailure, KeyReference, ReviewedExecutionGrant, ReviewedExecutionGrantContext,
  ReviewedExecutionGrantEnvelope, ReviewedExecutionGrantReceipt, GrantVerificationMode } from '../contracts/reviewedExecutionGrant.mjs';
export interface ReviewedExecutionGrantPublicKey {
  algorithm: 'ed25519';
  public_key_spki_der_base64: string;
  public_key_fingerprint_sha256: string;
  signing_enabled: boolean;
}
/** PUBLIC-ONLY; private keys, worker secrets and custody trust are forbidden. */
export interface ReviewedExecutionGrantTrust {
  version: 'reviewed-execution-grant-trust.v1';
  purpose: 'astranull.reviewed-operation.execution-grant';
  tenants: { [tenantId: string]: { [keyReference: KeyReference]: ReviewedExecutionGrantPublicKey } };
}
export interface ReviewedExecutionGrantSigningAdapter {
  signEnvelope(input: { envelope: Readonly<ReviewedExecutionGrantEnvelope>; signal: AbortSignal }):
    Promise<ReviewedExecutionGrantReceipt | { error: string; status: number }>;
}
export type ReviewedGrantVerification = GrantFailure | { ok: true; verification: 'current' }
  | { ok: true; verification: 'historical'; execution_valid: false };
export const REVIEWED_EXECUTION_GRANT_TRUST_VERSION: 'reviewed-execution-grant-trust.v1';
export function resolveReviewedExecutionGrantTrust(input: { trust: unknown; tenantId: string; keyReference: KeyReference; issuance?: boolean }):
  GrantFailure | { ok: true; material: { algorithm: 'ed25519'; keyReference: string; signingEnabled: boolean;
    publicKeyDerBase64: string; publicKeyFingerprintSha256: string } };
export function loadReviewedExecutionGrantTrust(env?: Record<string, string | undefined>):
  GrantFailure | { ok: true; trust: Readonly<ReviewedExecutionGrantTrust> };
export function reviewedExecutionGrantReceiptValid(receipt: unknown): receipt is ReviewedExecutionGrantReceipt;
/** Cryptographic signature-only adapter helper; not current execution/context validity. */
export function verifyReviewedExecutionGrantEnvelopeSignature(input: { envelope: unknown; signature: unknown;
  trust: unknown; issuance?: boolean }): GrantFailure | { ok: true };
export function verifyReviewedExecutionGrant(input: { grant: unknown; context: ReviewedExecutionGrantContext;
  trust: ReviewedExecutionGrantTrust; mode?: GrantVerificationMode }): ReviewedGrantVerification;
export function signReviewedExecutionGrant(input: { context: ReviewedExecutionGrantContext; trust: ReviewedExecutionGrantTrust;
  keyReference: KeyReference; signingAdapter: ReviewedExecutionGrantSigningAdapter; now?: () => GrantClock;
  timeoutMs?: number; signal?: AbortSignal }): Promise<GrantFailure | { ok: true; grant: Readonly<ReviewedExecutionGrant> }>;
