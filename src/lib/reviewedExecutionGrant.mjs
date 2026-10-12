import { createPublicKey, verify } from 'node:crypto';
import { canonicalJsonStringify } from './custody.mjs';
import { resolveTenantVerificationMaterial } from './evidenceSigning.mjs';
import {
  REVIEWED_EXECUTION_GRANT_VERSION, REVIEWED_EXECUTION_GRANT_ENVELOPE_VERSION,
  REVIEWED_EXECUTION_GRANT_PURPOSE, REVIEWED_EXECUTION_GRANT_SIGNATURE_VERSION,
  buildReviewedExecutionGrantEnvelope, validateReviewedExecutionGrantEnvelope,
  reviewedGrantExact, reviewedGrantRecord, reviewedGrantJson, reviewedGrantClock, reviewedGrantUtc, freezeReviewedGrant,
} from '../contracts/reviewedExecutionGrant.mjs';

export const REVIEWED_EXECUTION_GRANT_TRUST_VERSION = 'reviewed-execution-grant-trust.v1';
const TRUST_ENTRY_KEYS = ['algorithm', 'public_key_spki_der_base64', 'public_key_fingerprint_sha256', 'signing_enabled'];
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const KEY = /^key:\/\/[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/;
const HEX = /^[a-f0-9]{64}$/;
const fail = (error, status = 409) => ({ ok: false, error, status });

/** Separate PUBLIC-ONLY namespace. No private-key derivation or symmetric verification fallback. */
export function resolveReviewedExecutionGrantTrust(input = {}) {
  try {
    if (!reviewedGrantRecord(input) || Object.keys(input).some((key) => !['trust', 'tenantId', 'keyReference', 'issuance'].includes(key))
      || input.issuance !== undefined && typeof input.issuance !== 'boolean') return fail('reviewed_grant_trust_invalid', 503);
    const { trust, tenantId, keyReference, issuance = false } = input;
    if (!reviewedGrantExact(trust, ['version', 'purpose', 'tenants']) || !reviewedGrantJson(trust)
      || trust.version !== REVIEWED_EXECUTION_GRANT_TRUST_VERSION || trust.purpose !== REVIEWED_EXECUTION_GRANT_PURPOSE
      || !reviewedGrantRecord(trust.tenants) || typeof tenantId !== 'string' || !ID.test(tenantId)
      || typeof keyReference !== 'string' || !KEY.test(keyReference)) return fail('reviewed_grant_trust_invalid', 503);
    for (const [tenant, bucket] of Object.entries(trust.tenants)) {
      if (!ID.test(tenant) || !reviewedGrantRecord(bucket)) return fail('reviewed_grant_trust_invalid', 503);
      for (const [reference, entry] of Object.entries(bucket)) {
        if (!KEY.test(reference) || !reviewedGrantExact(entry, TRUST_ENTRY_KEYS) || entry.algorithm !== 'ed25519'
          || typeof entry.public_key_spki_der_base64 !== 'string' || entry.public_key_spki_der_base64.length !== 60
          || typeof entry.public_key_fingerprint_sha256 !== 'string'
          || !HEX.test(entry.public_key_fingerprint_sha256) || typeof entry.signing_enabled !== 'boolean') return fail('reviewed_grant_trust_invalid', 503);
      }
    }
    const entry = trust.tenants[tenantId]?.[keyReference];
    if (!entry) return fail('reviewed_grant_key_untrusted', 503);
    // Shared evidenceSigning import checks canonical DER, nonidentity prime-order points and
    // torsion freedom. Feed only the strict public entry, never the ambient custody key map.
    const material = resolveTenantVerificationMaterial({ tenantId, keyReference, algorithm: 'ed25519',
      env: { ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON: JSON.stringify({ [tenantId]: { [keyReference]: entry } }) } });
    if (material.error || material.publicKeyFingerprintSha256 !== entry.public_key_fingerprint_sha256) return fail('reviewed_grant_trust_invalid', 503);
    if (issuance && !material.signingEnabled) return fail('reviewed_grant_key_retired');
    return { ok: true, material };
  } catch { return fail('reviewed_grant_trust_invalid', 503); }
}

export function loadReviewedExecutionGrantTrust(env = process.env) {
  try {
    // Deliberately no fallback to custody keys, worker secrets, or private signing config.
    const descriptor = Object.getOwnPropertyDescriptor(env, 'ASTRANULL_REVIEWED_EXECUTION_GRANT_TRUST_JSON');
    const raw = descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
    if (typeof raw !== 'string' || !raw.length || raw.length > 262144) return fail('reviewed_grant_trust_invalid', 503);
    const trust = JSON.parse(raw);
    if (!reviewedGrantJson(trust) || !reviewedGrantExact(trust, ['version', 'purpose', 'tenants'])
      || trust.version !== REVIEWED_EXECUTION_GRANT_TRUST_VERSION || trust.purpose !== REVIEWED_EXECUTION_GRANT_PURPOSE
      || !reviewedGrantRecord(trust.tenants) || !Object.keys(trust.tenants).length) return fail('reviewed_grant_trust_invalid', 503);
    for (const [tenantId, bucket] of Object.entries(trust.tenants)) {
      if (!reviewedGrantRecord(bucket) || !Object.keys(bucket).length) return fail('reviewed_grant_trust_invalid', 503);
      for (const keyReference of Object.keys(bucket)) {
        if (!resolveReviewedExecutionGrantTrust({ trust, tenantId, keyReference }).ok) return fail('reviewed_grant_trust_invalid', 503);
      }
    }
    return { ok: true, trust: freezeReviewedGrant(trust) };
  } catch { return fail('reviewed_grant_trust_invalid', 503); }
}

export function reviewedExecutionGrantReceiptValid(receipt) {
  if (!reviewedGrantExact(receipt, ['version', 'algorithm', 'key_reference', 'public_key_fingerprint_sha256', 'signature'])
    || receipt.version !== REVIEWED_EXECUTION_GRANT_SIGNATURE_VERSION || receipt.algorithm !== 'ed25519'
    || typeof receipt.key_reference !== 'string' || !KEY.test(receipt.key_reference)
    || typeof receipt.public_key_fingerprint_sha256 !== 'string' || !HEX.test(receipt.public_key_fingerprint_sha256)
    || typeof receipt.signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(receipt.signature)) return false;
  const bytes = Buffer.from(receipt.signature, 'base64');
  return bytes.length === 64 && bytes.toString('base64') === receipt.signature;
}

/** Purpose-only cryptographic check used by adapters; NOT a context/capability validator. */
export function verifyReviewedExecutionGrantEnvelopeSignature(input = {}) {
  try {
    if (!reviewedGrantRecord(input) || Object.keys(input).some((key) => !['envelope', 'signature', 'trust', 'issuance'].includes(key))
      || input.issuance !== undefined && typeof input.issuance !== 'boolean') return fail('reviewed_grant_envelope_invalid');
    const { envelope, signature, trust, issuance = true } = input;
    if (!reviewedGrantJson(envelope) || envelope?.version !== REVIEWED_EXECUTION_GRANT_ENVELOPE_VERSION
      || envelope?.purpose !== REVIEWED_EXECUTION_GRANT_PURPOSE || envelope?.algorithm !== 'ed25519') return fail('reviewed_grant_envelope_invalid');
    const resolved = resolveReviewedExecutionGrantTrust({ trust, tenantId: envelope.tenant_id,
      keyReference: envelope.key_reference, issuance });
    if (!resolved.ok) return resolved;
    const material = resolved.material;
    const receipt = { version: REVIEWED_EXECUTION_GRANT_SIGNATURE_VERSION, algorithm: envelope.algorithm,
      key_reference: envelope.key_reference, public_key_fingerprint_sha256: envelope.public_key_fingerprint_sha256, signature };
    if (!reviewedExecutionGrantReceiptValid(receipt)
      || envelope.public_key_fingerprint_sha256 !== material.publicKeyFingerprintSha256) return fail('reviewed_grant_signature_invalid');
    const publicKey = createPublicKey({ key: Buffer.from(material.publicKeyDerBase64, 'base64'), type: 'spki', format: 'der' });
    return verify(null, Buffer.from(canonicalJsonStringify(envelope), 'utf8'), publicKey, Buffer.from(signature, 'base64'))
      ? { ok: true } : fail('reviewed_grant_signature_invalid');
  } catch { return fail('reviewed_grant_signature_invalid'); }
}

/** Pure signature + capability correctness, not DNS/egress permission or a current DB-read substitute.
 * Worker must first verify the original HMAC itself, re-read current review/ownership/reservation,
 * and accept only verification === 'current'. Historical results always have execution_valid:false.
 */
export function verifyReviewedExecutionGrant(input = {}) {
  try {
    if (!reviewedGrantRecord(input) || Object.keys(input).some((key) => !['grant', 'context', 'trust', 'mode'].includes(key))) return fail('reviewed_grant_invalid');
    const { grant, context, trust, mode = 'current' } = input;
    if (!reviewedGrantExact(grant, ['version', 'envelope', 'signature']) || !reviewedGrantJson(grant)
      || grant.version !== REVIEWED_EXECUTION_GRANT_VERSION || !['current', 'historical'].includes(mode)) return fail('reviewed_grant_invalid');
    const compared = validateReviewedExecutionGrantEnvelope(grant.envelope, context, mode);
    if (!compared.ok) return compared;
    const verified = verifyReviewedExecutionGrantEnvelopeSignature({ envelope: grant.envelope, signature: grant.signature,
      trust, issuance: mode === 'current' });
    if (!verified.ok) return verified;
    return mode === 'historical' ? { ok: true, verification: 'historical', execution_valid: false }
      : { ok: true, verification: 'current' };
  } catch { return fail('reviewed_grant_invalid'); }
}

/** Adapter is purpose-specific signEnvelope({envelope, signal}), NEVER signDigest/custody signing.
 * Both signer wait and body consumption must be bounded. Cancellation/expiry produces no grant.
 * No renewal, reissue, writes, accounting refunds or reservation persistence occur here.
 */
export async function signReviewedExecutionGrant(input = {}) {
  let timer, abortListener, signal;
  const controller = new AbortController();
  try {
    if (!reviewedGrantRecord(input) || Object.keys(input).some((key) => !['context', 'trust', 'keyReference', 'signingAdapter', 'now', 'timeoutMs', 'signal'].includes(key))) return fail('reviewed_grant_input_invalid', 400);
    const { context, trust, keyReference, signingAdapter, now = () => Date.now(), timeoutMs = 5000 } = input;
    signal = input.signal;
    if (signal !== undefined && !(signal instanceof AbortSignal)) { signal = undefined; return fail('reviewed_grant_input_invalid', 400); }
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000
      || typeof now !== 'function' || typeof signingAdapter?.signEnvelope !== 'function') return fail('reviewed_grant_signer_invalid', 503);
    if (signal?.aborted) return fail('reviewed_grant_signing_cancelled', 503);
    const before = reviewedGrantClock(now());
    if (!Number.isFinite(before) || !reviewedGrantRecord(context)) return fail('reviewed_grant_clock_invalid');
    const resolved = resolveReviewedExecutionGrantTrust({ trust, tenantId: context.tenantId, keyReference, issuance: true });
    if (!resolved.ok) return resolved;
    const built = buildReviewedExecutionGrantEnvelope({ ...context, now: before }, { algorithm: 'ed25519', key_reference: keyReference,
      public_key_fingerprint_sha256: resolved.material.publicKeyFingerprintSha256 });
    if (!built.ok) return built;
    const immutableContext = freezeReviewedGrant({ ...context, now: before });
    const deadline = new Promise((_, reject) => {
      const stop = (error) => { controller.abort(); reject(Object.assign(new Error(error), { code: error })); };
      timer = setTimeout(() => stop('reviewed_grant_signing_timeout'), Math.min(timeoutMs, reviewedGrantUtc(built.envelope.authority.not_after) - before));
      abortListener = () => stop('reviewed_grant_signing_cancelled');
      signal?.addEventListener('abort', abortListener, { once: true });
    });
    const receipt = await Promise.race([Promise.resolve().then(() => signingAdapter.signEnvelope({ envelope: built.envelope, signal: controller.signal })), deadline]);
    const after = reviewedGrantClock(now());
    if (controller.signal.aborted || signal?.aborted) return fail('reviewed_grant_signing_cancelled', 503);
    if (!Number.isFinite(after) || after < before) return fail('reviewed_grant_clock_invalid');
    if (!reviewedExecutionGrantReceiptValid(receipt)) return fail('reviewed_grant_signer_response_invalid', 502);
    if (receipt.algorithm !== built.envelope.algorithm || receipt.key_reference !== built.envelope.key_reference
      || receipt.public_key_fingerprint_sha256 !== built.envelope.public_key_fingerprint_sha256) return fail('reviewed_grant_signer_response_invalid', 502);
    const grant = freezeReviewedGrant({ version: REVIEWED_EXECUTION_GRANT_VERSION, envelope: built.envelope, signature: receipt.signature });
    // Re-resolve active pinned trust and recheck actual current time AFTER independent signing.
    const verified = verifyReviewedExecutionGrant({ grant, context: { ...immutableContext, now: after }, trust });
    if (!verified.ok) return verified;
    return { ok: true, grant };
  } catch (err) {
    return fail(['reviewed_grant_signing_timeout', 'reviewed_grant_signing_cancelled'].includes(err?.code)
      ? err.code : 'reviewed_grant_signer_unavailable', 503);
  } finally {
    clearTimeout(timer);
    if (abortListener) signal?.removeEventListener('abort', abortListener);
    controller.abort();
  }
}
