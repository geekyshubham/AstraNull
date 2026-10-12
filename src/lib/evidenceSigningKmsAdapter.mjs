import { createHmac, sign } from 'node:crypto';
import { canonicalJsonStringify } from './custody.mjs';
import {
  buildCustodySigningEnvelope,
  isValidKeyReference,
  parseEvidenceSigningKeyMap,
  resolveTenantSigningMaterial,
  resolveTenantVerificationMaterial,
  evidenceSigningRequiresAsymmetric,
  verifyCustodyManifestSignature,
  SHA256_HEX_RE,
} from './evidenceSigning.mjs';

import { createEvidenceSigningTransport } from './evidenceSigningTransport.mjs';

function normalizeAlgorithm(raw) {
  if (typeof raw !== 'string') return null;
  const value = raw.trim().toLowerCase();
  return value === 'ed25519' || value === 'hmac-sha256' ? value : null;
}

/**
 * Load tenant signing key map from inline JSON or a file path (`ASTRANULL_EVIDENCE_SIGNING_KEY`).
 * @param {NodeJS.ProcessEnv} env
 */
export function loadEvidenceSigningKeyMapEnv(env = process.env) {
  return parseEvidenceSigningKeyMap(env);
}

function signEnvelopeLocally(envelope, material) {
  const message = Buffer.from(canonicalJsonStringify(envelope), 'utf8');
  if (material.algorithm === 'ed25519') {
    const signature = sign(null, message, material.privateKey);
    return signature.toString('base64');
  }
  return createHmac('sha256', material.secret).update(message).digest('base64');
}

/**
 * @param {NodeJS.ProcessEnv} env
 * @param {{ now?: () => Date }} [options]
 */
export function createEnvBackedEvidenceSigningAdapter(env = process.env, options = {}) {
  const envRef = env;
  return {
    mode: 'env',
    async resolveSigningKey({ tenantId, keyReference, algorithm }) {
      const normalizedAlgorithm = normalizeAlgorithm(algorithm);
      const normalizedReference = typeof keyReference === 'string' ? keyReference.trim() : '';
      if (!isValidKeyReference(normalizedReference)) {
        return { error: 'invalid_key_reference', status: 400 };
      }
      if (!normalizedAlgorithm) {
        return { error: 'invalid_algorithm', status: 400 };
      }
      let keyMap;
      try {
        keyMap = loadEvidenceSigningKeyMapEnv(envRef);
      } catch (err) {
        return { error: 'invalid_signing_key_config', status: 500, detail: err.message };
      }
      const material = resolveTenantSigningMaterial({
        tenantId,
        keyReference: normalizedReference,
        algorithm: normalizedAlgorithm,
        env: { ...envRef, ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON: JSON.stringify(keyMap) },
      });
      if (material.error) {
        return { error: material.error, status: material.status ?? 400 };
      }
      return {
        algorithm: normalizedAlgorithm,
        keyReference: normalizedReference,
        publicKeyFingerprintSha256: material.publicKeyFingerprintSha256,
        source: 'env',
      };
    },
    async signDigest({ tenantId, algorithm, digest, keyReference }) {
      const normalizedAlgorithm = normalizeAlgorithm(algorithm);
      const normalizedReference = typeof keyReference === 'string' ? keyReference.trim() : '';
      const digestHex = String(digest ?? '');
      if (!SHA256_HEX_RE.test(digestHex)) {
        return { error: 'custody_manifest_digest_invalid', status: 400 };
      }
      if (!isValidKeyReference(normalizedReference)) {
        return { error: 'invalid_key_reference', status: 400 };
      }
      if (!normalizedAlgorithm) {
        return { error: 'invalid_algorithm', status: 400 };
      }
      let keyMap;
      try {
        keyMap = loadEvidenceSigningKeyMapEnv(envRef);
      } catch (err) {
        return { error: 'invalid_signing_key_config', status: 500, detail: err.message };
      }
      const material = resolveTenantSigningMaterial({
        tenantId,
        keyReference: normalizedReference,
        algorithm: normalizedAlgorithm,
        env: { ...envRef, ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON: JSON.stringify(keyMap) },
      });
      if (material.error) {
        return { error: material.error, status: material.status ?? 400 };
      }
      const envelope = buildCustodySigningEnvelope({
        tenantId,
        custodyManifestDigest: digestHex,
      });
      const signature = signEnvelopeLocally(envelope, material);
      return {
        signature,
        publicKeyFingerprintSha256: material.publicKeyFingerprintSha256,
        source: 'env',
      };
    },
  };
}

/**
 * @param {{
 *   endpoint: string,
 *   env?: NodeJS.ProcessEnv,
 *   fetchFn?: typeof fetch,
 *   fetchTimeoutMs?: number,
 * }} config
 */
export function createExternalKmsEvidenceSigningAdapter(config) {
  const endpoint = String(config.endpoint ?? '').trim().replace(/\/+$/, '');
  const envRef = config.env ?? process.env;
  const callKms = createEvidenceSigningTransport({ ...config, endpoint, env: envRef });

  function verificationMaterial(tenantId, keyReference, algorithm) {
    try {
      if (evidenceSigningRequiresAsymmetric(envRef) && algorithm === 'hmac-sha256') {
        return { error: 'hmac_signing_forbidden_in_production', status: 400 };
      }
    } catch { return { error: 'invalid_signing_deployment_config', status: 503 }; }
    const material = resolveTenantVerificationMaterial({ tenantId, keyReference, algorithm, env: envRef });
    if (!material.error && !material.signingEnabled) return { error: 'signing_key_retired', status: 400 };
    return material;
  }

  return {
    mode: 'kms',
    endpoint,
    async resolveSigningKey({ tenantId, keyReference, algorithm }) {
      const normalizedAlgorithm = normalizeAlgorithm(algorithm);
      const normalizedReference = typeof keyReference === 'string' ? keyReference.trim() : '';
      if (!isValidKeyReference(normalizedReference)) {
        return { error: 'invalid_key_reference', status: 400 };
      }
      if (!normalizedAlgorithm) {
        return { error: 'invalid_algorithm', status: 400 };
      }
      const material = verificationMaterial(tenantId, normalizedReference, normalizedAlgorithm);
      if (material.error) return material;
      const kmsResult = await callKms('/v1/signing-keys/resolve', {
        tenant_id: tenantId,
        key_reference: normalizedReference,
        algorithm: normalizedAlgorithm,
      });
      if (kmsResult.error) {
        return kmsResult;
      }
      const body = kmsResult.body;
      const fingerprint = typeof body?.public_key_fingerprint_sha256 === 'string'
        ? body.public_key_fingerprint_sha256.trim()
        : '';
      if (fingerprint !== material.publicKeyFingerprintSha256) {
        return { error: 'kms_signing_response_invalid', status: 502 };
      }
      return {
        algorithm: normalizedAlgorithm,
        keyReference: normalizedReference,
        publicKeyFingerprintSha256: fingerprint,
        source: 'kms',
      };
    },
    async signDigest({ tenantId, algorithm, digest, keyReference }) {
      const normalizedAlgorithm = normalizeAlgorithm(algorithm);
      const normalizedReference = typeof keyReference === 'string' ? keyReference.trim() : '';
      const digestHex = String(digest ?? '');
      if (!SHA256_HEX_RE.test(digestHex)) {
        return { error: 'custody_manifest_digest_invalid', status: 400 };
      }
      if (!isValidKeyReference(normalizedReference)) {
        return { error: 'invalid_key_reference', status: 400 };
      }
      if (!normalizedAlgorithm) {
        return { error: 'invalid_algorithm', status: 400 };
      }
      const material = verificationMaterial(tenantId, normalizedReference, normalizedAlgorithm);
      if (material.error) return material;
      const kmsResult = await callKms('/v1/sign', {
        tenant_id: tenantId,
        key_reference: normalizedReference,
        algorithm: normalizedAlgorithm,
        digest: digestHex,
      });
      if (kmsResult.error) {
        return kmsResult;
      }
      const body = kmsResult.body;
      const signature = typeof body?.signature === 'string' ? body.signature : '';
      const fingerprint = typeof body?.public_key_fingerprint_sha256 === 'string'
        ? body.public_key_fingerprint_sha256.trim()
        : '';
      const expectedLength = normalizedAlgorithm === 'ed25519' ? 64 : 32;
      const bytes = Buffer.from(signature, 'base64');
      if (signature.length !== Math.ceil(expectedLength / 3) * 4
        || bytes.length !== expectedLength || bytes.toString('base64') !== signature
        || fingerprint !== material.publicKeyFingerprintSha256
        || (body.algorithm !== undefined && body.algorithm !== normalizedAlgorithm)
        || (body.key_reference !== undefined && body.key_reference !== normalizedReference)) {
        return { error: 'kms_signing_response_invalid', status: 502 };
      }
      const verified = verifyCustodyManifestSignature({ tenantId, custodyManifestDigest: digestHex,
        signer: { algorithm: normalizedAlgorithm, key_reference: normalizedReference, signature }, env: envRef });
      if (!verified.ok) return { error: verified.error, status: 502 };
      return { signature, algorithm: normalizedAlgorithm, keyReference: normalizedReference,
        publicKeyFingerprintSha256: fingerprint, source: 'kms' };
    },
  };
}

/**
 * Select env-backed or external KMS signing adapter.
 * @param {{ env?: NodeJS.ProcessEnv, fetchFn?: typeof fetch, fetchTimeoutMs?: number }} [options]
 */
export function createEvidenceSigningKmsAdapter(options = {}) {
  const env = options.env ?? process.env;
  const endpoint = String(env.ASTRANULL_KMS_SIGNING_ENDPOINT ?? '').trim();
  if (endpoint) {
    return createExternalKmsEvidenceSigningAdapter({
      endpoint,
      env,
      fetchFn: options.fetchFn,
      fetchTimeoutMs: options.fetchTimeoutMs,
    });
  }
  return createEnvBackedEvidenceSigningAdapter(env, options);
}