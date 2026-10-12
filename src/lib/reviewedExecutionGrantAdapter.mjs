import { canonicalJsonStringify } from './custody.mjs';
import { resolveTenantSigningMaterial, signEnvelopeWithMaterial } from './evidenceSigning.mjs';
import { createEvidenceSigningTransport } from './evidenceSigningTransport.mjs';
import { resolveReviewedExecutionGrantTrust, reviewedExecutionGrantReceiptValid,
  verifyReviewedExecutionGrantEnvelopeSignature } from './reviewedExecutionGrant.mjs';
import {
  REVIEWED_EXECUTION_GRANT_ENVELOPE_VERSION, REVIEWED_EXECUTION_GRANT_PURPOSE, REVIEWED_EXECUTION_GRANT_SIGNATURE_VERSION,
  reviewedGrantJson, reviewedGrantRecord, reviewedGrantExact, reviewedGrantClock, reviewedGrantUtc,
} from '../contracts/reviewedExecutionGrant.mjs';

const ENVELOPE_KEYS = ['version', 'purpose', 'content_canonicalization', 'algorithm', 'key_reference',
  'public_key_fingerprint_sha256', 'tenant_id', 'job', 'original_job_payload', 'original_job_signature_sha256',
  'worker', 'reservation', 'budgets', 'authority'];
const failure = () => ({ error: 'reviewed_grant_signer_unavailable', status: 503 });
function ready(envelope, now, signal) {
  if (signal?.aborted || !reviewedGrantExact(envelope, ENVELOPE_KEYS) || !reviewedGrantJson(envelope)
    || envelope.version !== REVIEWED_EXECUTION_GRANT_ENVELOPE_VERSION || envelope.purpose !== REVIEWED_EXECUTION_GRANT_PURPOSE
    || envelope.algorithm !== 'ed25519' || envelope.content_canonicalization !== 'json-key-sorted-v1'
    || !reviewedGrantExact(envelope.authority, ['issued_at', 'original_not_after', 'not_after', 'grant_issued_at'])) return false;
  const at = reviewedGrantClock(now()), issued = reviewedGrantUtc(envelope.authority.grant_issued_at), until = reviewedGrantUtc(envelope.authority.not_after);
  return Number.isFinite(at) && Number.isFinite(issued) && Number.isFinite(until) && at >= issued && at < until;
}
function receipt(envelope, signature) {
  return { version: REVIEWED_EXECUTION_GRANT_SIGNATURE_VERSION, algorithm: 'ed25519', key_reference: envelope.key_reference,
    public_key_fingerprint_sha256: envelope.public_key_fingerprint_sha256, signature };
}

/** Local private keys have a dedicated purpose namespace; trust remains separate/public-only. */
export function createEnvReviewedExecutionGrantAdapter(env = process.env, { now = () => Date.now() } = {}) {
  return {
    async signEnvelope(input) {
      try {
        if (!reviewedGrantRecord(input) || Object.keys(input).some((key) => !['envelope', 'signal'].includes(key))) return failure();
        const { envelope, signal } = input;
        if (signal !== undefined && !(signal instanceof AbortSignal) || !ready(envelope, now, signal)) return failure();
        const raw = env.ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_KEYS_JSON;
        if (typeof raw !== 'string' || raw.length > 262144) return failure();
        const map = JSON.parse(raw), entry = map?.[envelope.tenant_id]?.[envelope.key_reference];
        if (!reviewedGrantJson(map) || !reviewedGrantExact(entry, ['algorithm', 'private_key_pkcs8_der_base64', 'public_key_spki_der_base64', 'signing_enabled'])
          || entry.algorithm !== 'ed25519' || entry.signing_enabled !== true) return failure();
        const material = resolveTenantSigningMaterial({ tenantId: envelope.tenant_id, keyReference: envelope.key_reference, algorithm: 'ed25519',
          env: { ...env, ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON: JSON.stringify({ [envelope.tenant_id]: { [envelope.key_reference]: entry } }) } });
        if (material.error || material.publicKeyFingerprintSha256 !== envelope.public_key_fingerprint_sha256) return failure();
        const signed = receipt(envelope, signEnvelopeWithMaterial(envelope, material));
        return ready(envelope, now, signal) ? signed : failure();
      } catch { return failure(); }
    },
  };
}

// Reuse the shared bounded parser but additionally make caller cancellation cover custom
// fetch implementations and stalled body readers, even when they ignore AbortSignal.
async function cancellableFetch(fetchFn, url, options) {
  const signal = options.signal;
  let onAbort;
  const aborted = new Promise((_, reject) => {
    onAbort = () => reject(new Error('reviewed_grant_cancelled'));
    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) onAbort();
  });
  const fetched = Promise.resolve().then(() => fetchFn(url, options)).then((response) => {
    if (signal.aborted) {
      try { Promise.resolve(response?.body?.cancel()).catch(() => {}); } catch { /* Redacted failure. */ }
      throw new Error('reviewed_grant_cancelled');
    }
    return response;
  });
  let response;
  try { response = await Promise.race([fetched, aborted]); }
  finally { signal.removeEventListener('abort', onAbort); }
  if (!response?.body || typeof response.body.getReader !== 'function') return response;
  const reader = response.body.getReader();
  let ended = false, bodyAbort;
  const body = new ReadableStream({
    start(controller) {
      bodyAbort = () => {
        if (ended) return;
        ended = true;
        signal.removeEventListener('abort', bodyAbort);
        Promise.resolve(reader.cancel()).catch(() => {});
        controller.error(new Error('reviewed_grant_cancelled'));
      };
      signal.addEventListener('abort', bodyAbort, { once: true });
      if (signal.aborted) bodyAbort();
    },
    async pull(controller) {
      try {
        const { value, done } = await reader.read();
        if (ended) return;
        if (done) { ended = true; signal.removeEventListener('abort', bodyAbort); controller.close(); }
        else controller.enqueue(value);
      } catch {
        if (!ended) { ended = true; signal.removeEventListener('abort', bodyAbort); controller.error(new Error('reviewed_grant_body_unavailable')); }
      }
    },
    cancel() { ended = true; signal.removeEventListener('abort', bodyAbort); Promise.resolve(reader.cancel()).catch(() => {}); },
  });
  return { ok: response.ok, status: response.status, headers: response.headers, body };
}

/** Bounded HTTPS only, dedicated endpoint/auth/origin namespace and purpose-separated path.
 * Sends the FULL typed envelope, not a custody digest. Actual returned signature is verified
 * by signReviewedExecutionGrant against pinned public-only trust before any grant is returned.
 */
export function createExternalReviewedExecutionGrantAdapter({ env = process.env, trust, fetchFn = globalThis.fetch,
  now = () => Date.now() } = {}) {
  const endpoint = env.ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_ENDPOINT;
  // Deliberately replace every generic transport setting: none may fall back to custody KMS.
  const transportEnv = {
    ASTRANULL_DEPLOYMENT_PROFILE: 'production', NODE_ENV: 'production',
    ASTRANULL_KMS_SIGNING_ENDPOINT: endpoint,
    ASTRANULL_KMS_SIGNING_ALLOWED_ORIGINS: env.ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_ALLOWED_ORIGINS ?? '',
    ASTRANULL_KMS_SIGNING_BEARER_TOKEN: env.ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_BEARER_TOKEN ?? '',
    ASTRANULL_KMS_SIGNING_FETCH_TIMEOUT_MS: env.ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_FETCH_TIMEOUT_MS,
    ASTRANULL_KMS_SIGNING_MAX_RESPONSE_BYTES: env.ASTRANULL_REVIEWED_EXECUTION_GRANT_SIGNING_MAX_RESPONSE_BYTES,
  };
  return {
    async signEnvelope(input) {
      try {
        if (!reviewedGrantRecord(input) || Object.keys(input).some((key) => !['envelope', 'signal'].includes(key))) return failure();
        const { envelope, signal } = input;
        if (signal !== undefined && !(signal instanceof AbortSignal) || !ready(envelope, now, signal)) return failure();
        const resolved = resolveReviewedExecutionGrantTrust({ trust, tenantId: envelope.tenant_id, keyReference: envelope.key_reference, issuance: true });
        if (!resolved.ok || resolved.material.publicKeyFingerprintSha256 !== envelope.public_key_fingerprint_sha256) return failure();
        const call = createEvidenceSigningTransport({ env: transportEnv, endpoint,
          fetchFn: (url, options) => cancellableFetch(fetchFn, url,
            { ...options, signal: signal ? AbortSignal.any([signal, options.signal]) : options.signal }) });
        const response = await call('/v1/reviewed-execution-grants/sign', { envelope });
        if (response.error || !ready(envelope, now, signal) || !reviewedExecutionGrantReceiptValid(response.body)) return failure();
        if (canonicalJsonStringify({ ...response.body, signature: '' }) !== canonicalJsonStringify({ ...receipt(envelope, ''), signature: '' })) return failure();
        const verified = verifyReviewedExecutionGrantEnvelopeSignature({ envelope, signature: response.body.signature, trust });
        return verified.ok && ready(envelope, now, signal) ? response.body : failure();
      } catch { return failure(); }
    },
  };
}
