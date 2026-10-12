import { evidenceSigningRequiresAsymmetric, parseEvidenceSigningKeyMap, resolveTenantSigningMaterial, resolveTenantVerificationMaterial } from './evidenceSigning.mjs';
import { validateEvidenceSigningTransportConfig } from './evidenceSigningTransport.mjs';

/** Configuration readiness only: this never claims a live signer/retention acceptance. */
export function loadEvidenceSigningConfig(env = process.env) {
  const rawRequired = String(env.ASTRANULL_REQUIRE_EVIDENCE_SIGNING ?? '').trim();
  if (rawRequired && !['0', '1'].includes(rawRequired)) throw new Error('ASTRANULL_REQUIRE_EVIDENCE_SIGNING must be 1 or 0.');
  const required = rawRequired === '1';
  const asymmetricRequired = evidenceSigningRequiresAsymmetric(env);
  const external = Boolean(String(env.ASTRANULL_KMS_SIGNING_ENDPOINT ?? '').trim());
  const configured = external || Boolean(String(env.ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON ?? '').trim())
    || Boolean(String(env.ASTRANULL_EVIDENCE_SIGNING_KEY ?? '').trim());
  if (!configured) {
    if (required) throw new Error('Evidence signing is required but no signing configuration is supplied.');
    return { required, configured: false, configurationReady: false, asymmetricRequired, external: false, operationalAcceptance: 'not_verified' };
  }
  if (external) {
    const checked = validateEvidenceSigningTransportConfig({ env });
    if (checked.error) throw new Error(`Evidence signer configuration rejected: ${checked.error}.`);
  }
  const keyMap = parseEvidenceSigningKeyMap(env);
  let activeKeys = 0;
  for (const [tenantId, bucket] of Object.entries(keyMap)) {
    if (!bucket || typeof bucket !== 'object' || Array.isArray(bucket)) throw new Error('Invalid evidence signing tenant key configuration.');
    for (const [keyReference, entry] of Object.entries(bucket)) {
      const algorithm = entry?.algorithm;
      const material = resolveTenantVerificationMaterial({ tenantId, keyReference, algorithm, env });
      if (material.error) throw new Error(`Evidence verification trust rejected: ${material.error}.`);
      if (asymmetricRequired && algorithm !== 'ed25519') continue;
      if (entry.signing_enabled === false) continue;
      if (external) activeKeys++;
      else {
        const signing = resolveTenantSigningMaterial({ tenantId, keyReference, algorithm, env });
        if (!signing.error) activeKeys++;
      }
    }
  }
  const configurationReady = activeKeys > 0;
  if (required && !configurationReady) throw new Error('Evidence signing requires at least one active trusted signing key.');
  return { required, configured, configurationReady, asymmetricRequired, external, operationalAcceptance: 'not_verified' };
}
