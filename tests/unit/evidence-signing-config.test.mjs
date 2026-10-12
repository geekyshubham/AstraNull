import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { describe, it } from 'node:test';
import { loadEvidenceSigningConfig } from '../../src/lib/evidenceSigningConfig.mjs';
import { loadRuntimeConfig } from '../../src/config.mjs';

const tenantId = 'ten_config';
const keyReference = 'key://config/v1';
function fixture({ publicOnly = false, retired = false } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { NODE_ENV: 'test', ASTRANULL_REQUIRE_EVIDENCE_SIGNING: '1', ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON: JSON.stringify({
    [tenantId]: { [keyReference]: { algorithm: 'ed25519', public_key_spki_der_base64: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
      ...(!publicOnly ? { private_key_pkcs8_der_base64: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64') } : {}),
      signing_enabled: !retired } },
  }) };
}
describe('custody signing configuration readiness', () => {
  it('exposes absent optional custody as unavailable, not accepted', () => {
    const result = loadEvidenceSigningConfig({});
    assert.equal(result.configured, false);
    assert.equal(result.configurationReady, false);
    assert.equal(result.operationalAcceptance, 'not_verified');
  });
  it('refuses startup when required custody configuration is absent', () => {
    assert.throws(() => loadRuntimeConfig({ NODE_ENV: 'test', ASTRANULL_REQUIRE_EVIDENCE_SIGNING: '1' }), /required/);
  });
  it('rejects malformed required-setting values', () => {
    assert.throws(() => loadEvidenceSigningConfig({ ASTRANULL_REQUIRE_EVIDENCE_SIGNING: 'yes' }), /must be 1 or 0/);
  });
  it('accepts configured actual signing material without certifying operation', () => {
    const result = loadRuntimeConfig(fixture()).evidenceSigning;
    assert.equal(result.configurationReady, true);
    assert.equal(result.operationalAcceptance, 'not_verified');
    assert.ok(!JSON.stringify(result).includes('private_key'));
  });
  it('does not count public-only trust as a local signing key', () => {
    assert.throws(() => loadEvidenceSigningConfig(fixture({ publicOnly: true })), /active trusted signing key/);
  });
  it('does not count retired keys as active authority', () => {
    assert.throws(() => loadEvidenceSigningConfig(fixture({ retired: true })), /active trusted signing key/);
  });
  it('rejects corrupted tenant trust at startup', () => {
    const env = fixture();
    env.ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON = '{';
    assert.throws(() => loadRuntimeConfig(env), /valid JSON/);
  });
  it('rejects configured signer authentication failures at startup', () => {
    const env = { ...fixture({ publicOnly: true }), NODE_ENV: 'production', ASTRANULL_KMS_SIGNING_ENDPOINT: 'https://signer.example.test',
      ASTRANULL_KMS_SIGNING_ALLOWED_ORIGINS: 'https://signer.example.test' };
    assert.throws(() => loadEvidenceSigningConfig(env), /kms_signing_auth_invalid/);
  });
  it('accepts authenticated HTTPS and public trust as configuration only', () => {
    const env = { ...fixture({ publicOnly: true }), NODE_ENV: 'production', ASTRANULL_KMS_SIGNING_ENDPOINT: 'https://signer.example.test',
      ASTRANULL_KMS_SIGNING_ALLOWED_ORIGINS: 'https://signer.example.test', ASTRANULL_KMS_SIGNING_BEARER_TOKEN: 'fixture-token' };
    const result = loadEvidenceSigningConfig(env);
    assert.equal(result.configurationReady, true);
    assert.equal(result.external, true);
    assert.equal(result.operationalAcceptance, 'not_verified');
  });
});
