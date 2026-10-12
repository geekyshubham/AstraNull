export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };
export type KeyReference = `key://${string}`;
export type GrantClock = string | number | Date;
export type GrantFailure = { ok: false; error: string; status: number };
export interface ReviewedOperationIdentity {
  binding_version: 'reviewed-operation-binding.v1';
  review_id: string;
  plan_version: 'reviewed-inert-operation.v1';
  plan_digest: string;
}
export interface ReviewedExecutionReservation {
  version: 'execution-reservation.v1';
  id: string;
  worker_id: string;
  leased_at: string;
  reserved_at: string;
  not_after: string;
  max_probe_requests: number;
  max_destination_resolver_attempts: number;
  max_total_operations: number;
  state: 'reserved_unknown';
  reviewed_operation: ReviewedOperationIdentity;
}
export interface ReviewedOriginalJob {
  id: string;
  tenant_id: string;
  test_run_id: string;
  target_id: string;
  check_id: string;
  nonce_hash: string;
  job_signature: string;
  target: JsonObject & { id: string; kind: 'url'; value: string };
  probe_profile: JsonObject;
  constraints: JsonObject;
  leased_by: string;
  leased_at: string;
  [key: string]: unknown;
}
/** Worker/lease/tenant must be authenticated caller context, never supplied grant metadata. */
export interface ReviewedExecutionGrantContext {
  originalJob: ReviewedOriginalJob;
  reservation: ReviewedExecutionReservation;
  check: JsonObject;
  tenantId: string;
  workerId: string;
  leasedAt: string;
  now: GrantClock;
}
export interface ReviewedExecutionGrantSigner {
  algorithm: 'ed25519';
  key_reference: KeyReference;
  public_key_fingerprint_sha256: string;
}
export interface ReviewedExecutionGrantEnvelope extends ReviewedExecutionGrantSigner {
  version: 'reviewed-execution-grant-envelope.v1';
  purpose: 'astranull.reviewed-operation.execution-grant';
  content_canonicalization: 'json-key-sorted-v1';
  tenant_id: string;
  job: { id: string; test_run_id: string; check_id: string; target_id: string; nonce_hash: string };
  /** Byte-identical canonical payload of the eight original HMAC-signed job fields. */
  original_job_payload: string;
  /** SHA-256 of the unchanged original lowercase hex HMAC signature string (UTF-8). */
  original_job_signature_sha256: string;
  worker: { id: string; leased_at: string };
  reservation: ReviewedExecutionReservation;
  budgets: { max_probe_requests: number; max_destination_resolver_attempts: number; max_total_operations: number;
    execution_attempts: 1; timeout_ms: number };
  authority: { issued_at: string; original_not_after: string; not_after: string; grant_issued_at: string };
}
export interface ReviewedExecutionGrant {
  version: 'reviewed-execution-grant.v1';
  envelope: ReviewedExecutionGrantEnvelope;
  signature: string;
}
export interface ReviewedExecutionGrantReceipt extends ReviewedExecutionGrantSigner {
  version: 'reviewed-execution-grant-signature.v1';
  signature: string;
}
export type GrantVerificationMode = 'current' | 'historical';
export const REVIEWED_EXECUTION_GRANT_VERSION: 'reviewed-execution-grant.v1';
export const REVIEWED_EXECUTION_GRANT_ENVELOPE_VERSION: 'reviewed-execution-grant-envelope.v1';
export const REVIEWED_EXECUTION_GRANT_PURPOSE: 'astranull.reviewed-operation.execution-grant';
export const REVIEWED_EXECUTION_GRANT_SIGNATURE_VERSION: 'reviewed-execution-grant-signature.v1';
export const ORIGINAL_JOB_SIGNED_KEYS: readonly string[];
export function reviewedGrantRecord(value: unknown): value is Record<string, unknown>;
export function reviewedGrantExact(value: unknown, keys: readonly string[]): boolean;
export function reviewedGrantJson(value: unknown): value is JsonValue;
export function reviewedGrantUtc(value: unknown): number;
export function reviewedGrantClock(value: unknown): number;
export function freezeReviewedGrant<T>(value: T): Readonly<T>;
export function buildReviewedExecutionGrantEnvelope(input: ReviewedExecutionGrantContext, signer: ReviewedExecutionGrantSigner):
  GrantFailure | { ok: true; envelope: Readonly<ReviewedExecutionGrantEnvelope> };
export function validateReviewedExecutionGrantEnvelope(envelope: unknown, context: ReviewedExecutionGrantContext, mode?: GrantVerificationMode):
  GrantFailure | { ok: true };
