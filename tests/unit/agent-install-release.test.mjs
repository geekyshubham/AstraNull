import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { resolveAgentInstallRelease } from '../../apps/web/react/src/lib/agent-install-release.mjs';

const SIGNING_FINGERPRINT = 'b'.repeat(64);

function release(overrides = {}) {
  const version = '2.0.0';
  const artifactName = `astranull-agent-${version}.tar.gz`;
  return {
    id: 'aup_1',
    state: 'active',
    version,
    signing_fingerprint_sha256: SIGNING_FINGERPRINT,
    created_at: '2026-07-15T12:00:00.000Z',
    manifest: {
      package: 'astranull-agent',
      version,
      artifact: { name: artifactName, sha256: 'a'.repeat(64) },
      signing: { signed: true },
    },
    signature: 'detached-signature',
    distribution: {
      manifest_url: 'https://updates.example.com/2.0.0/manifest.json',
      signature_url: 'https://updates.example.com/2.0.0/manifest.json.sig',
      artifact_url: `https://updates.example.com/2.0.0/${artifactName}`,
    },
    ...overrides,
  };
}

const activeKeys = [{ id: 'key_1', status: 'active', fingerprint_sha256: SIGNING_FINGERPRINT }];

describe('agent install release metadata', () => {
  it('accepts an active signed tarball release and preserves exact distribution URLs', () => {
    const result = resolveAgentInstallRelease([release()], activeKeys);
    assert.equal(result.reason, '');
    assert.equal(result.release?.version, '2.0.0');
    assert.equal(result.release?.artifactUrl, 'https://updates.example.com/2.0.0/astranull-agent-2.0.0.tar.gz');
  });

  it('fails closed without an active trust key', () => {
    const result = resolveAgentInstallRelease([release()], [{ status: 'revoked' }]);
    assert.equal(result.release, null);
    assert.match(result.reason, /No active tenant-approved/);
  });

  it('rejects unsigned, inactive, version-mismatched, and incomplete releases', () => {
    const unsigned = release({ manifest: { ...release().manifest, signing: { signed: false } } });
    const inactive = release({ state: 'rollback_requested' });
    const mismatch = release({ manifest: { ...release().manifest, version: '1.0.0' } });
    const missingSignature = release({ signature: '' });
    assert.equal(resolveAgentInstallRelease([unsigned, inactive, mismatch, missingSignature], activeKeys).release, null);
  });

  it('rejects non-HTTPS, credentialed, and artifact-name-mismatched distribution URLs', () => {
    const base = release();
    const insecure = release({ distribution: { ...base.distribution, artifact_url: 'http://updates.example.com/agent.tar.gz' } });
    const credentialed = release({ distribution: { ...base.distribution, manifest_url: 'https://user:pass@updates.example.com/manifest.json' } });
    const wrongName = release({ distribution: { ...base.distribution, artifact_url: 'https://updates.example.com/wrong.tar.gz' } });
    assert.equal(resolveAgentInstallRelease([insecure, credentialed, wrongName], activeKeys).release, null);
  });

  it('rejects releases whose signer does not match an active trust key', () => {
    const wrongKey = [{ status: 'active', fingerprint_sha256: 'c'.repeat(64) }];
    const result = resolveAgentInstallRelease([release()], wrongKey);
    assert.equal(result.release, null);
    assert.match(result.reason, /signer matching an active tenant-approved trust key/);
  });

  it('rejects control characters in artifact names', () => {
    const base = release();
    const artifactName = 'astranull-agent-2.0.0\n.tar.gz';
    const poisoned = release({
      manifest: {
        ...base.manifest,
        artifact: { ...base.manifest.artifact, name: artifactName },
      },
      distribution: {
        ...base.distribution,
        artifact_url: `https://updates.example.com/2.0.0/${encodeURIComponent(artifactName)}`,
      },
    });
    assert.equal(resolveAgentInstallRelease([poisoned], activeKeys).release, null);
  });

  it('selects the newest complete active release', () => {
    const older = release({ id: 'old', created_at: '2026-01-01T00:00:00.000Z' });
    const newer = release({ id: 'new', created_at: '2026-08-01T00:00:00.000Z' });
    assert.equal(resolveAgentInstallRelease([newer, older], activeKeys).release?.id, 'new');
  });
});
