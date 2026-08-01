import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, randomBytes } from 'node:crypto';
import { afterEach, describe, it } from 'node:test';
import {
  buildCustodyManifest,
  canonicalJsonStringify,
  CUSTODY_SCHEMA_VERSION,
} from '../../src/lib/custody.mjs';
import {
  buildCustodySigningEnvelope,
  buildSignableCustodyManifestMetadata,
  digestCustodyManifestMetadata,
  deriveHmacSigningKeyId,
  EVIDENCE_SIGNING_KEY_ID_DOMAIN,
  resolveTenantSigningMaterial,
  resolveTenantVerificationMaterial,
  signCustodyManifestMetadata,
  validateHmacSecretEntropy,
  verifyCustodyManifestSignature,
} from '../../src/lib/evidenceSigning.mjs';
import { signEvidenceSnapshotCustody } from '../../src/services/evidenceSnapshotSigning.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';
import {
  computeSnapshotHash,
  validateEvidenceSnapshotBatch,
  validateSnapshotSignature,
} from '../../scripts/evidence-snapshot-manifest.mjs';

const TENANT = 'ten_a';
const KEY_REF = 'key://vault/astranull/evidence-signing/staging';
const HMAC_KEY_REF = 'key://vault/astranull/evidence-signing/hmac-dev';
const HMAC_SECRET = 'dev-only-hmac-secret-32-characters-min';
const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function ed25519KeyMaterial() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    private_key_pkcs8_der_base64: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    public_key_spki_der_base64: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  };
}

function custodyManifest(overrides = {}) {
  return buildCustodyManifest({
    tenant_id: TENANT,
    artifact_type: 'report_export',
    artifact_id: 'rpt_sign_1',
    format: 'json',
    created_by: 'usr_soc',
    content: { report_id: 'rpt_sign_1', title: 'Signed export' },
    created_at: '2026-07-03T12:00:00.000Z',
    ...overrides,
  });
}

function signingEnv(extra = {}) {
  const ed25519 = ed25519KeyMaterial();
  return {
    ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON: JSON.stringify({
      [TENANT]: {
        [KEY_REF]: {
          algorithm: 'ed25519',
          private_key_pkcs8_der_base64: ed25519.private_key_pkcs8_der_base64,
        },
        [HMAC_KEY_REF]: {
          algorithm: 'hmac-sha256',
          secret: HMAC_SECRET,
        },
        ...extra,
      },
    }),
  };
}

afterEach(() => {
  restoreEnv();
  freshStore();
});

describe('evidence signing library', () => {
  it('digests metadata-only custody manifests', () => {
    const custody = custodyManifest();
    const digestResult = digestCustodyManifestMetadata(custody);
    assert.equal(digestResult.ok, true);
    assert.match(digestResult.digest, /^[a-f0-9]{64}$/);
    assert.equal(digestResult.signable.schema_version, CUSTODY_SCHEMA_VERSION);
    assert.throws(
      () => buildSignableCustodyManifestMetadata({ ...custody, payload: { secret: true } }),
      /forbidden custody field/,
    );
  });

  it('signs custody manifest metadata with tenant-scoped Ed25519 key reference', () => {
    const env = signingEnv();
    const custody = custodyManifest();
    const signed = signCustodyManifestMetadata({
      tenantId: TENANT,
      custody,
      keyReference: KEY_REF,
      algorithm: 'ed25519',
      env,
      now: () => new Date('2026-07-03T12:01:00.000Z'),
    });
    assert.equal(signed.error, undefined);
    assert.equal(signed.signed.algorithm, 'ed25519');
    assert.equal(signed.signed.key_reference, KEY_REF);
    assert.equal(signed.signed.signed_at, '2026-07-03T12:01:00.000Z');
    assert.match(signed.signed.signature, /^[A-Za-z0-9+/]+={0,2}$/);

    const verification = verifyCustodyManifestSignature({
      tenantId: TENANT,
      custodyManifestDigest: signed.signed.custody_manifest_digest,
      signer: {
        key_reference: KEY_REF,
        algorithm: 'ed25519',
        signature: signed.signed.signature,
      },
      env,
    });
    assert.deepEqual(verification, { ok: true });
  });

  it('signs custody manifest metadata with tenant-scoped HMAC-SHA256 key reference', () => {
    const env = signingEnv();
    const custody = custodyManifest({ artifact_id: 'rpt_hmac_1' });
    const signed = signCustodyManifestMetadata({
      tenantId: TENANT,
      custody,
      keyReference: HMAC_KEY_REF,
      algorithm: 'hmac-sha256',
      env,
    });
    assert.equal(signed.error, undefined);
    assert.equal(signed.signed.algorithm, 'hmac-sha256');
    const verification = verifyCustodyManifestSignature({
      tenantId: TENANT,
      custodyManifestDigest: signed.signed.custody_manifest_digest,
      signer: {
        key_reference: HMAC_KEY_REF,
        algorithm: 'hmac-sha256',
        signature: signed.signed.signature,
      },
      env,
    });
    assert.deepEqual(verification, { ok: true });
  });

  it('rejects tenant mismatch and unknown key references', () => {
    const env = signingEnv();
    const custody = custodyManifest();
    const mismatch = signCustodyManifestMetadata({
      tenantId: 'ten_other',
      custody,
      keyReference: KEY_REF,
      algorithm: 'ed25519',
      env,
    });
    assert.equal(mismatch.error, 'tenant_id_mismatch');

    const unknown = signCustodyManifestMetadata({
      tenantId: TENANT,
      custody,
      keyReference: 'key://vault/astranull/evidence-signing/missing',
      algorithm: 'ed25519',
      env,
    });
    assert.equal(unknown.error, 'unknown_signing_key_reference');
  });

  it('rejects tampered signatures during verification', () => {
    const env = signingEnv();
    const custody = custodyManifest({ artifact_id: 'rpt_tamper' });
    const signed = signCustodyManifestMetadata({
      tenantId: TENANT,
      custody,
      keyReference: KEY_REF,
      algorithm: 'ed25519',
      env,
    });
    const tampered = Buffer.from(signed.signed.signature, 'base64');
    tampered[0] ^= 0xff;
    const verification = verifyCustodyManifestSignature({
      tenantId: TENANT,
      custodyManifestDigest: signed.signed.custody_manifest_digest,
      signer: {
        key_reference: KEY_REF,
        algorithm: 'ed25519',
        signature: tampered.toString('base64'),
      },
      env,
    });
    assert.equal(verification.ok, false);
    assert.equal(verification.error, 'signature_verification_failed');
  });

  it('builds deterministic signing envelopes from custody digests', () => {
    const envelope = buildCustodySigningEnvelope({
      tenantId: TENANT,
      custodyManifestDigest: 'a'.repeat(64),
    });
    assert.equal(envelope.tenant_id, TENANT);
    assert.equal(envelope.custody_manifest_digest, 'a'.repeat(64));
    assert.equal(envelope.schema_version, CUSTODY_SCHEMA_VERSION);
  });
});

describe('evidence signing HMAC key identifier exposure', () => {
  const legacyFingerprint = (secret) => createHash('sha256').update(secret, 'utf8').digest('hex');

  it('never publishes a bare sha256 digest of the shared secret', () => {
    const env = signingEnv();
    const signed = signCustodyManifestMetadata({
      tenantId: TENANT,
      custody: custodyManifest({ artifact_id: 'rpt_hmac_fp' }),
      keyReference: HMAC_KEY_REF,
      algorithm: 'hmac-sha256',
      env,
    });
    assert.equal(signed.error, undefined);
    const published = signed.signed.public_key_fingerprint_sha256;
    assert.match(published, /^[a-f0-9]{64}$/);
    // The published identifier must not be a digest an attacker can recompute
    // from a candidate secret without the key.
    assert.notEqual(published, legacyFingerprint(HMAC_SECRET));
    assert.equal(
      published,
      createHmac('sha256', HMAC_SECRET).update(EVIDENCE_SIGNING_KEY_ID_DOMAIN).digest('hex'),
    );
    // The secret itself must never appear in the signed record.
    assert.equal(JSON.stringify(signed.signed).includes(HMAC_SECRET), false);
  });

  it('derives the same key identifier on the signing and verification paths', () => {
    const env = signingEnv();
    const signing = resolveTenantSigningMaterial({
      tenantId: TENANT,
      keyReference: HMAC_KEY_REF,
      algorithm: 'hmac-sha256',
      env,
    });
    const verifying = resolveTenantVerificationMaterial({
      tenantId: TENANT,
      keyReference: HMAC_KEY_REF,
      algorithm: 'hmac-sha256',
      env,
    });
    assert.equal(signing.error, undefined);
    assert.equal(verifying.error, undefined);
    assert.equal(signing.publicKeyFingerprintSha256, verifying.publicKeyFingerprintSha256);
    assert.notEqual(signing.publicKeyFingerprintSha256, legacyFingerprint(HMAC_SECRET));
  });

  it('prefers an opaque operator-assigned key_id over any derived value', () => {
    const env = signingEnv({
      [HMAC_KEY_REF]: {
        algorithm: 'hmac-sha256',
        secret: HMAC_SECRET,
        key_id: 'evsign-2026-07-a',
      },
    });
    const signed = signCustodyManifestMetadata({
      tenantId: TENANT,
      custody: custodyManifest({ artifact_id: 'rpt_hmac_keyid' }),
      keyReference: HMAC_KEY_REF,
      algorithm: 'hmac-sha256',
      env,
    });
    assert.equal(signed.error, undefined);
    assert.equal(signed.signed.public_key_fingerprint_sha256, 'evsign-2026-07-a');
    assert.notEqual(signed.signed.public_key_fingerprint_sha256, legacyFingerprint(HMAC_SECRET));
  });

  it('signs and verifies an HMAC round-trip after the derivation change', () => {
    const env = signingEnv();
    const signed = signCustodyManifestMetadata({
      tenantId: TENANT,
      custody: custodyManifest({ artifact_id: 'rpt_hmac_rt' }),
      keyReference: HMAC_KEY_REF,
      algorithm: 'hmac-sha256',
      env,
    });
    assert.equal(signed.error, undefined);
    const verification = verifyCustodyManifestSignature({
      tenantId: TENANT,
      custodyManifestDigest: signed.signed.custody_manifest_digest,
      signer: {
        key_reference: HMAC_KEY_REF,
        algorithm: 'hmac-sha256',
        signature: signed.signed.signature,
      },
      env,
    });
    assert.deepEqual(verification, { ok: true });
  });

  it('still verifies manifests signed under the OLD sha256(secret) derivation', () => {
    const env = signingEnv();
    const digest = 'b'.repeat(64);
    // Reconstruct a record exactly as the pre-change signer emitted it: the
    // signature covers the signing envelope only, and the record carries the old
    // sha256(secret) fingerprint value.
    const envelope = buildCustodySigningEnvelope({ tenantId: TENANT, custodyManifestDigest: digest });
    const legacySignature = createHmac('sha256', HMAC_SECRET)
      .update(Buffer.from(canonicalJsonStringify(envelope), 'utf8'))
      .digest('base64');
    const legacyRecord = {
      key_reference: HMAC_KEY_REF,
      algorithm: 'hmac-sha256',
      signature: legacySignature,
      public_key_fingerprint_sha256: legacyFingerprint(HMAC_SECRET),
    };
    const verification = verifyCustodyManifestSignature({
      tenantId: TENANT,
      custodyManifestDigest: digest,
      signer: legacyRecord,
      env,
    });
    assert.deepEqual(verification, { ok: true });
  });

  it('verifies historical HMAC evidence even when the key would now fail the entropy floor', () => {
    // Provisioning-time policy must not retroactively strip the ability to verify
    // evidence that was already signed with a weaker key.
    const weakSecret = 'password-password-password-passwo';
    const env = {
      ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON: JSON.stringify({
        [TENANT]: { [HMAC_KEY_REF]: { algorithm: 'hmac-sha256', secret: weakSecret } },
      }),
    };
    assert.equal(validateHmacSecretEntropy(weakSecret).ok, false);
    const digest = 'c'.repeat(64);
    const envelope = buildCustodySigningEnvelope({ tenantId: TENANT, custodyManifestDigest: digest });
    const signature = createHmac('sha256', weakSecret)
      .update(Buffer.from(canonicalJsonStringify(envelope), 'utf8'))
      .digest('base64');

    // Signing with that key is now refused...
    const resigned = resolveTenantSigningMaterial({
      tenantId: TENANT,
      keyReference: HMAC_KEY_REF,
      algorithm: 'hmac-sha256',
      env,
    });
    assert.equal(resigned.error, 'hmac_secret_low_entropy');

    // ...but historical verification still succeeds.
    const verification = verifyCustodyManifestSignature({
      tenantId: TENANT,
      custodyManifestDigest: digest,
      signer: { key_reference: HMAC_KEY_REF, algorithm: 'hmac-sha256', signature },
      env,
    });
    assert.deepEqual(verification, { ok: true });
  });
});

describe('evidence signing HMAC secret entropy floor', () => {
  it('rejects 32-character but low-entropy secrets', () => {
    // Repeated-character secrets clear a character count but carry almost no
    // key material. 'a'.repeat(32) is also valid hex, so it decodes to 16 bytes.
    const repeatedHex = 'a'.repeat(32);
    assert.deepEqual(validateHmacSecretEntropy(repeatedHex), {
      ok: false,
      error: 'hmac_secret_too_short',
    });

    const weakPassphrase = 'password-password-password-passwo';
    assert.equal(weakPassphrase.length > 32, true);
    assert.deepEqual(validateHmacSecretEntropy(weakPassphrase), {
      ok: false,
      error: 'hmac_secret_low_entropy',
    });
  });

  it('validates decoded bytes rather than character count', () => {
    // 32 hex characters decode to only 16 bytes of key material.
    const hex16Bytes = randomBytes(16).toString('hex');
    assert.equal(hex16Bytes.length, 32);
    assert.deepEqual(validateHmacSecretEntropy(hex16Bytes), {
      ok: false,
      error: 'hmac_secret_too_short',
    });

    // 32 decoded bytes are accepted in hex, base64 and utf8 encodings.
    for (const secret of [
      randomBytes(32).toString('hex'),
      randomBytes(32).toString('base64'),
      'dev-only-hmac-secret-32-characters-min',
    ]) {
      assert.equal(validateHmacSecretEntropy(secret).ok, true, secret);
    }
  });

  it('surfaces the entropy rejection through signing key resolution', () => {
    const env = {
      ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON: JSON.stringify({
        [TENANT]: { [HMAC_KEY_REF]: { algorithm: 'hmac-sha256', secret: 'a'.repeat(32) } },
      }),
    };
    const signed = signCustodyManifestMetadata({
      tenantId: TENANT,
      custody: custodyManifest({ artifact_id: 'rpt_weak' }),
      keyReference: HMAC_KEY_REF,
      algorithm: 'hmac-sha256',
      env,
    });
    assert.equal(signed.error, 'hmac_secret_too_short');
    assert.equal(signed.status, 400);
  });

  it('rejects a missing or non-string secret', () => {
    for (const value of [undefined, null, 42, '', '   ']) {
      assert.equal(validateHmacSecretEntropy(value).ok, false);
    }
  });

  it('derives a stable key identifier without exposing the secret digest', () => {
    const secret = randomBytes(32).toString('base64');
    const first = deriveHmacSigningKeyId({ secret });
    assert.equal(first, deriveHmacSigningKeyId({ secret }));
    assert.notEqual(first, createHash('sha256').update(secret, 'utf8').digest('hex'));
  });
});

describe('evidence signing algorithm policy by deployment profile', () => {
  function hmacEnv(extra = {}) {
    return {
      ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON: JSON.stringify({
        [TENANT]: { [HMAC_KEY_REF]: { algorithm: 'hmac-sha256', secret: HMAC_SECRET } },
      }),
      ...extra,
    };
  }

  function signHmac(env) {
    return signCustodyManifestMetadata({
      tenantId: TENANT,
      custody: custodyManifest({ artifact_id: 'rpt_profile' }),
      keyReference: HMAC_KEY_REF,
      algorithm: 'hmac-sha256',
      env,
    });
  }

  it('refuses hmac-sha256 for evidence custody under the production profile', () => {
    const result = signHmac(hmacEnv({ ASTRANULL_DEPLOYMENT_PROFILE: 'production' }));
    assert.equal(result.error, 'hmac_signing_forbidden_in_production');
    assert.equal(result.status, 400);
  });

  it('permits hmac-sha256 under the hosted-staging profile even when NODE_ENV=production', () => {
    // astranull.site runs NODE_ENV=production with the hosted-staging profile.
    // Gating on NODE_ENV would break that deployment.
    const result = signHmac(hmacEnv({
      ASTRANULL_DEPLOYMENT_PROFILE: 'hosted-staging',
      NODE_ENV: 'production',
    }));
    assert.equal(result.error, undefined);
    assert.equal(result.signed.algorithm, 'hmac-sha256');
  });

  it('does not refuse hmac-sha256 on NODE_ENV alone with no profile set', () => {
    const result = signHmac(hmacEnv({ NODE_ENV: 'production' }));
    assert.equal(result.error, undefined);
    assert.equal(result.signed.algorithm, 'hmac-sha256');
  });

  it('still permits ed25519 under the production profile', () => {
    const env = signingEnv();
    const result = signCustodyManifestMetadata({
      tenantId: TENANT,
      custody: custodyManifest({ artifact_id: 'rpt_prod_ed' }),
      keyReference: KEY_REF,
      algorithm: 'ed25519',
      env: { ...env, ASTRANULL_DEPLOYMENT_PROFILE: 'production' },
    });
    assert.equal(result.error, undefined);
    assert.equal(result.signed.algorithm, 'ed25519');
  });

  it('still verifies existing hmac-sha256 evidence under the production profile', () => {
    // Refusing to *sign* must not orphan evidence signed before the profile changed.
    const env = hmacEnv();
    const signed = signHmac(env);
    assert.equal(signed.error, undefined);
    const verification = verifyCustodyManifestSignature({
      tenantId: TENANT,
      custodyManifestDigest: signed.signed.custody_manifest_digest,
      signer: {
        key_reference: HMAC_KEY_REF,
        algorithm: 'hmac-sha256',
        signature: signed.signed.signature,
      },
      env: { ...env, ASTRANULL_DEPLOYMENT_PROFILE: 'production' },
    });
    assert.deepEqual(verification, { ok: true });
  });
});

describe('evidence snapshot signing service', () => {
  it('audits metadata-only evidence.snapshot_signed events', async () => {
    Object.assign(process.env, signingEnv());
    const ctx = { tenantId: TENANT, userId: 'usr_soc', role: 'soc' };
    const result = await signEvidenceSnapshotCustody(ctx, {
      custody: custodyManifest(),
      key_reference: KEY_REF,
      algorithm: 'ed25519',
    });
    assert.equal(result.error, undefined);
    const auditEntry = getStore().auditLog.find((entry) => entry.action === 'evidence.snapshot_signed');
    assert.ok(auditEntry);
    assert.equal(auditEntry.metadata.custody_manifest_digest, result.signed.custody_manifest_digest);
    assert.equal(auditEntry.metadata.algorithm, 'ed25519');
    assert.equal('signature' in (auditEntry.metadata ?? {}), false);
  });
});

describe('evidence snapshot manifest signature verification', () => {
  function snapshotWithSignature(signature, digest) {
    const base = {
      snapshot_id: 'snap_2026_07_03_001',
      custody_manifest_digest: digest,
      storage_reference: 'evidence://immutable/tenant-a/2026-07-03/snap-001',
      retention_policy: {
        metadata_retention_days: 90,
        report_days: 365,
        audit_log_days: 2555,
        legal_hold: false,
      },
      signer: {
        key_reference: KEY_REF,
        algorithm: 'ed25519',
        signature_reference: 'evidence://signatures/staging/snap-001',
        signature,
      },
      previous_snapshot_hash: null,
      operator_signoff: {
        operator: 'custody-operator',
        signed_at: '2026-07-03T12:00:00.000Z',
        signoff_reference: 'signoff://custody/snapshot-batch-2026-07-03',
      },
    };
    return { ...base, snapshot_hash: computeSnapshotHash(base) };
  }

  it('accepts batches with valid signer.signature values', () => {
    const env = signingEnv();
    Object.assign(process.env, env);
    const custody = custodyManifest();
    const signed = signCustodyManifestMetadata({
      tenantId: TENANT,
      custody,
      keyReference: KEY_REF,
      algorithm: 'ed25519',
      env,
    });
    const batch = {
      schema_version: 1,
      artifact_type: 'immutable_evidence_snapshot_batch',
      tenant_id: TENANT,
      batch_id: 'snapbatch_2026_07_03',
      snapshots: [snapshotWithSignature(signed.signed.signature, signed.signed.custody_manifest_digest)],
    };
    const validation = validateEvidenceSnapshotBatch(batch);
    assert.equal(validation.ok, true, validation.gaps.join(', '));
  });

  it('reports signature verification gaps for invalid signatures', () => {
    const env = signingEnv();
    const custody = custodyManifest();
    const signed = signCustodyManifestMetadata({
      tenantId: TENANT,
      custody,
      keyReference: KEY_REF,
      algorithm: 'ed25519',
      env,
    });
    const gaps = validateSnapshotSignature({
      tenantId: TENANT,
      snapshot: snapshotWithSignature('invalid-signature', signed.signed.custody_manifest_digest),
      index: 0,
      env,
    });
    assert.ok(gaps.some((gap) => gap.endsWith('signature_verification_failed')));
  });
});