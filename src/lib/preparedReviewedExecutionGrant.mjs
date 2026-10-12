import { canonicalJsonStringify } from './custody.mjs';
import { resolveReviewedExecutionGrantTrust, reviewedExecutionGrantReceiptValid, verifyReviewedExecutionGrant } from './reviewedExecutionGrant.mjs';
import { REVIEWED_EXECUTION_GRANT_VERSION, reviewedGrantRecord, reviewedGrantClock, reviewedGrantUtc,
  freezeReviewedGrant, validateReviewedExecutionGrantEnvelope } from '../contracts/reviewedExecutionGrant.mjs';

const failure = (error, status = 409) => ({ ok: false, error, status });

/** Signs EXACT previously persisted authority. It never builds/renews an envelope or its issuance clock.
 * This detached helper has no durable uniqueness itself; only the committed issuance owner may invoke it.
 * Production callers use the real clock (default); an injected clock is for focused pure tests only.
 */
export async function signPreparedReviewedExecutionGrant(input = {}) {
  let timer, onAbort, signal, invocationFailure;
  const controller = new AbortController();
  try {
    if (!reviewedGrantRecord(input) || Object.keys(input).some((key) =>
      !['envelope', 'context', 'trust', 'signingAdapter', 'timeoutMs', 'signal', 'now'].includes(key))) {
      return failure('reviewed_grant_input_invalid', 400);
    }
    const { envelope, context, trust, signingAdapter, timeoutMs = 5000, now = () => Date.now() } = input;
    signal = input.signal;
    if (signal !== undefined && !(signal instanceof AbortSignal)) { signal = undefined; return failure('reviewed_grant_input_invalid', 400); }
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000
      || typeof now !== 'function' || typeof signingAdapter?.signEnvelope !== 'function') return failure('reviewed_grant_signer_invalid', 503);
    if (signal?.aborted) return failure('reviewed_grant_signing_cancelled', 503);
    const before = reviewedGrantClock(now());
    const checked = validateReviewedExecutionGrantEnvelope(envelope, { ...context, now: before });
    if (!checked.ok) return checked;
    const resolved = resolveReviewedExecutionGrantTrust({ trust, tenantId: envelope.tenant_id, keyReference: envelope.key_reference, issuance: true });
    if (!resolved.ok) return resolved;
    if (resolved.material.publicKeyFingerprintSha256 !== envelope.public_key_fingerprint_sha256) return failure('reviewed_grant_key_untrusted', 503);
    const persisted = freezeReviewedGrant(envelope), immutableContext = freezeReviewedGrant(context);
    const bytes = canonicalJsonStringify(persisted);
    const deadline = new Promise((_, reject) => {
      const stop = (code) => { controller.abort(); reject(Object.assign(new Error(code), { code })); };
      timer = setTimeout(() => stop('reviewed_grant_signing_timeout'), Math.min(timeoutMs, reviewedGrantUtc(persisted.authority.not_after) - before));
      onAbort = () => stop('reviewed_grant_signing_cancelled');
      signal?.addEventListener('abort', onAbort, { once: true });
      if (signal?.aborted) onAbort();
    });
    let invocationClock;
    const response = await Promise.race([Promise.resolve().then(() => {
      if (controller.signal.aborted) throw Object.assign(new Error('cancelled'), { code: 'reviewed_grant_signing_cancelled' });
      invocationClock = reviewedGrantClock(now());
      const current = validateReviewedExecutionGrantEnvelope(persisted, { ...immutableContext, now: invocationClock });
      const pinned = resolveReviewedExecutionGrantTrust({ trust, tenantId: persisted.tenant_id, keyReference: persisted.key_reference, issuance: true });
      const invalid = !Number.isFinite(invocationClock) || invocationClock < before ? failure('reviewed_grant_clock_invalid')
        : !current.ok ? current : !pinned.ok ? pinned
          : pinned.material.publicKeyFingerprintSha256 !== persisted.public_key_fingerprint_sha256 ? failure('reviewed_grant_key_untrusted', 503) : null;
      if (invalid) { invocationFailure = invalid; throw new Error(invalid.error); }
      return signingAdapter.signEnvelope({ envelope: persisted, signal: controller.signal });
    }), deadline]);
    const after = reviewedGrantClock(now());
    if (controller.signal.aborted || signal?.aborted) return failure('reviewed_grant_signing_cancelled', 503);
    if (!Number.isFinite(after) || after < invocationClock) return failure('reviewed_grant_clock_invalid');
    if (!reviewedExecutionGrantReceiptValid(response) || response.key_reference !== persisted.key_reference
      || response.public_key_fingerprint_sha256 !== persisted.public_key_fingerprint_sha256
      || canonicalJsonStringify(persisted) !== bytes) return failure('reviewed_grant_signer_response_invalid', 502);
    const grant = freezeReviewedGrant({ version: REVIEWED_EXECUTION_GRANT_VERSION, envelope: persisted, signature: response.signature });
    // Independent Ed25519 verification, active pinned trust and ACTUAL post-wait clock.
    const verified = verifyReviewedExecutionGrant({ grant, context: { ...immutableContext, now: after }, trust });
    return verified.ok ? { ok: true, grant } : verified;
  } catch (error) {
    if (invocationFailure) return invocationFailure;
    return failure(['reviewed_grant_signing_cancelled', 'reviewed_grant_signing_timeout'].includes(error?.code)
      ? error.code : 'reviewed_grant_signer_unavailable', 503);
  } finally {
    clearTimeout(timer);
    if (onAbort) signal?.removeEventListener('abort', onAbort);
    controller.abort();
  }
}
