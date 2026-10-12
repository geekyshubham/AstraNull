import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { buildCustodyManifest, canonicalJsonStringify } from '../../src/lib/custody.mjs';
import { buildCustodySigningEnvelope, signCustodyManifestMetadataAsync, verifyCustodyManifestSignature, resolveTenantVerificationMaterial } from '../../src/lib/evidenceSigning.mjs';
import { signEvidenceSnapshotCustody } from '../../src/services/evidenceSnapshotSigning.mjs';
import { loadEvidenceSigningConfig } from '../../src/lib/evidenceSigningConfig.mjs';
import { ed25519 } from '@noble/curves/ed25519.js';

const tenantId = 'ten_receipt';
const keyReference = 'key://evidence/receipt/v1';
function fixture() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicDer = publicKey.export({ type: 'spki', format: 'der' });
  const env = { ASTRANULL_DEPLOYMENT_PROFILE: 'production', NODE_ENV: 'production',
    ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON: JSON.stringify({ [tenantId]: { [keyReference]: {
      algorithm: 'ed25519', public_key_spki_der_base64: publicDer.toString('base64'),
    } } }) };
  const custody = buildCustodyManifest({ tenant_id: tenantId, artifact_type: 'report_export', artifact_id: 'rpt_receipt',
    format: 'json', created_by: 'usr_review', created_at: '2026-10-09T00:00:00.000Z', content: { result: 'observed' } });
  const adapter = { async signDigest({ tenantId: tenant, digest }) {
    return { signature: sign(null, Buffer.from(canonicalJsonStringify(buildCustodySigningEnvelope({
      tenantId: tenant, custodyManifestDigest: digest,
    }))), privateKey).toString('base64'), publicKeyFingerprintSha256: createHash('sha256').update(publicDer).digest('hex'), source: 'kms' };
  } };
  return { env, custody, adapter };
}
function request(f, signingAdapter = f.adapter) {
  return { tenantId, keyReference, algorithm: 'ed25519', custody: f.custody, env: f.env, signingAdapter };
}
function corrupt(adapter, change) {
  return { async signDigest(input) { return { ...await adapter.signDigest(input), ...change }; } };
}

describe('independently verified signing receipts', () => {
  it('accepts a real signature with public-only operator trust', async () => {
    const f = fixture();
    const result = await signCustodyManifestMetadataAsync(request(f));
    assert.equal(result.error, undefined);
    assert.deepEqual(verifyCustodyManifestSignature({ tenantId, custodyManifestDigest: result.signed.custody_manifest_digest,
      signer: result.signed, env: f.env }), { ok: true });
  });
  for (const [name, change] of [
    ['forged signature', { signature: Buffer.alloc(64).toString('base64') }],
    ['non-canonical base64', { signature: 'not-a-signature' }],
    ['short signature', { signature: Buffer.alloc(32).toString('base64') }],
    ['wrong fingerprint', { publicKeyFingerprintSha256: '0'.repeat(64) }],
    ['wrong receipt algorithm', { algorithm: 'hmac-sha256' }],
    ['wrong receipt key', { keyReference: 'key://other/key' }],
  ]) it(`rejects ${name} without returning signed metadata`, async () => {
    const f = fixture();
    const result = await signCustodyManifestMetadataAsync(request(f, corrupt(f.adapter, change)));
    assert.ok(result.error, name);
    assert.equal(result.signed, undefined);
  });
  it('rejects a valid signature made by an untrusted key', async () => {
    const f = fixture();
    const result = await signCustodyManifestMetadataAsync(request(f, fixture().adapter));
    assert.ok(result.error);
    assert.equal(result.signed, undefined);
  });
  it('rejects unknown tenant/key trust before invoking the signer', async () => {
    const f = fixture();
    f.env.ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON = '{}';
    let calls = 0;
    const result = await signCustodyManifestMetadataAsync(request(f, { async signDigest() { calls++; return {}; } }));
    assert.ok(result.error);
    assert.equal(calls, 0);
  });
  for (const env of [{ NODE_ENV: 'production', ASTRANULL_DEPLOYMENT_PROFILE: 'local-staging' },
    { ASTRANULL_DEPLOYMENT_PROFILE: 'production' }, { ASTRANULL_DEPLOYMENT_PROFILE: 'invalid' }]) {
    it(`rejects new symmetric signing under ${JSON.stringify(env)}`, async () => {
      const f = fixture();
      let calls = 0;
      const result = await signCustodyManifestMetadataAsync({ ...request(f), env, algorithm: 'hmac-sha256',
        signingAdapter: { async signDigest() { calls++; return { signature: 'a'.repeat(44), publicKeyFingerprintSha256: 'b'.repeat(64) }; } } });
      assert.ok(result.error);
      assert.equal(calls, 0);
    });
  }
  it('rejects invalid deployment configuration for asymmetric signing too', async () => {
    const f = fixture();
    f.env.ASTRANULL_DEPLOYMENT_PROFILE = 'invalid';
    let calls = 0;
    const result = await signCustodyManifestMetadataAsync(request(f, { async signDigest() { calls++; return {}; } }));
    assert.ok(result.error);
    assert.equal(calls, 0);
  });
  it('loads public trust from the same key file used by the adapter', async () => {
    const f = fixture();
    const dir = mkdtempSync(path.join(tmpdir(), 'astranull-receipt-'));
    try {
      const keyFile = path.join(dir, 'trust.json');
      writeFileSync(keyFile, f.env.ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON);
      delete f.env.ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON;
      f.env.ASTRANULL_EVIDENCE_SIGNING_KEY = keyFile;
      const result = await signCustodyManifestMetadataAsync(request(f));
      assert.equal(result.error, undefined);
      assert.deepEqual(verifyCustodyManifestSignature({ tenantId, custodyManifestDigest: result.signed.custody_manifest_digest,
        signer: result.signed, env: f.env }), { ok: true });
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
  for (const [name, point] of [
    ['identity', Buffer.from([1, ...Array(31).fill(0)])],
    ['order four', Buffer.alloc(32)],
    ['order two', Buffer.from('ec' + 'ff'.repeat(30) + '7f', 'hex')],
    ['noncanonical identity sign', Buffer.from([1, ...Array(30).fill(0), 128])],
    ['noncanonical coordinate', Buffer.alloc(32, 255)],
    ['mixed torsion', Buffer.from(ed25519.Point.BASE.add(ed25519.Point.fromBytes(Buffer.alloc(32), false)).toBytes())],
  ]) it(`rejects ${name} Ed25519 trust at startup and before signer invocation`, async () => {
    const f = fixture();
    const publicDer = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), point]);
    f.env.ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON = JSON.stringify({ [tenantId]: { [keyReference]: {
      algorithm: 'ed25519', public_key_spki_der_base64: publicDer.toString('base64'),
    } } });
    assert.equal(resolveTenantVerificationMaterial({ tenantId, keyReference, algorithm: 'ed25519', env: f.env }).error, 'invalid_public_key');
    assert.throws(() => loadEvidenceSigningConfig({ ...f.env, ASTRANULL_REQUIRE_EVIDENCE_SIGNING: '1',
      ASTRANULL_KMS_SIGNING_ENDPOINT: 'https://signer.example.test',
      ASTRANULL_KMS_SIGNING_ALLOWED_ORIGINS: 'https://signer.example.test', ASTRANULL_KMS_SIGNING_BEARER_TOKEN: 'fixture-token' }));
    let calls = 0;
    const result = await signCustodyManifestMetadataAsync(request(f, { async signDigest() { calls++;
      return { signature: Buffer.from([1, ...Array(63).fill(0)]).toString('base64'),
        publicKeyFingerprintSha256: createHash('sha256').update(publicDer).digest('hex') }; } }));
    assert.ok(result.error); assert.equal(result.signed, undefined); assert.equal(calls, 0);
  });
  for (const name of ['tenant', 'digest']) it(`rejects a real signature for a different ${name}`, async () => {
    const f = fixture();
    const result = await signCustodyManifestMetadataAsync(request(f, { async signDigest(input) {
      return f.adapter.signDigest({ ...input, ...(name === 'tenant' ? { tenantId: 'ten_other' } : { digest: '0'.repeat(64) }) });
    } }));
    assert.equal(result.error, 'signature_verification_failed'); assert.equal(result.signed, undefined);
  });
  it('retired keys retain historical verification but cannot issue new signatures', async () => {
    const f = fixture();
    const original = await signCustodyManifestMetadataAsync(request(f));
    const keys = JSON.parse(f.env.ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON);
    keys[tenantId][keyReference].signing_enabled = false;
    f.env.ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON = JSON.stringify(keys);
    let calls = 0;
    assert.equal((await signCustodyManifestMetadataAsync(request(f, { async signDigest() { calls++; return {}; } }))).error, 'signing_key_retired');
    assert.equal(calls, 0);
    assert.deepEqual(verifyCustodyManifestSignature({ tenantId, custodyManifestDigest: original.signed.custody_manifest_digest,
      signer: original.signed, env: f.env }), { ok: true });
  });
  it('redacts custom adapter diagnostics and rejects structured receipt sources', async () => {
    const f = fixture();
    const result = await signCustodyManifestMetadataAsync(request(f, { async signDigest() {
      return { error: 'Bearer synthetic-diagnostic-token', status: 200, detail: 'synthetic-private-material' };
    } }));
    assert.deepEqual(result, { error: 'signing_adapter_unavailable', status: 503 });
    const structured = await signCustodyManifestMetadataAsync(request(f, corrupt(f.adapter, { source: { private_key: 'synthetic-private-material' } })));
    assert.deepEqual(structured, { error: 'signing_receipt_invalid', status: 502 });
    assert.doesNotMatch(JSON.stringify([result, structured]), /synthetic/);
  });
  for (const [name, adapter] of [['exception', { async signDigest() { throw new Error('synthetic-private-material'); } }],
    ['array', { async signDigest() { return []; } }], ['null', { async signDigest() { return null; } }]]) {
    it(`fails closed and redacts ${name} adapters`, async () => {
      const result = await signCustodyManifestMetadataAsync(request(fixture(), adapter));
      assert.ok(result.error); assert.equal(result.signed, undefined); assert.doesNotMatch(JSON.stringify(result), /synthetic/);
    });
  }
  it('does not audit a forged receipt as signed', async () => {
    const f = fixture();
    const entries = [];
    const result = await signEvidenceSnapshotCustody({ tenantId, userId: 'usr_review', role: 'soc', persistenceMode: 'postgres',
      auditService: { async appendAuditEvent(entry) { entries.push(entry); } } },
    { custody: f.custody, algorithm: 'ed25519', key_reference: keyReference },
    { env: f.env, signingAdapter: corrupt(f.adapter, { signature: Buffer.alloc(64).toString('base64') }) });
    assert.ok(result.error);
    assert.equal(entries.filter((entry) => entry.action === 'evidence.snapshot_signed').length, 0);
  });
});
