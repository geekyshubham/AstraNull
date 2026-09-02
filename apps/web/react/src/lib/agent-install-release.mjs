/** Portal-only validation for agent install download preparation. */

function asRecord(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function text(value) {
  return value === undefined || value === null ? '' : String(value).trim();
}

function parseHttpsUrl(value) {
  const raw = text(value);
  if (!raw) return null;
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || !parsed.hostname) return null;
    return parsed;
  } catch {
    return null;
  }
}

function artifactBasename(url) {
  const segment = url.pathname.split('/').filter(Boolean).pop() ?? '';
  if (!segment) return '';
  try {
    return decodeURIComponent(segment);
  } catch {
    return '';
  }
}

function candidateRelease(release) {
  const item = asRecord(release);
  if (!item || text(item.state).toLowerCase() !== 'active') return null;

  const version = text(item.version);
  const manifest = asRecord(item.manifest);
  const signing = asRecord(manifest?.signing);
  const artifact = asRecord(manifest?.artifact);
  const distribution = asRecord(item.distribution);
  const signature = text(item.signature);
  if (!version || !manifest || !artifact || !distribution) return null;
  if (manifest.package !== 'astranull-agent' || text(manifest.version) !== version) return null;
  if (signing?.signed !== true || !signature) return null;

  const artifactName = text(artifact.name);
  const digest = text(artifact.sha256).toLowerCase();
  const signingFingerprint = text(item.signing_fingerprint_sha256).toLowerCase();
  if (!/^[A-Za-z0-9][A-Za-z0-9._+-]*\.tar\.gz$/.test(artifactName)) return null;
  if (!/^[a-f0-9]{64}$/.test(digest) || !/^[a-f0-9]{64}$/.test(signingFingerprint)) return null;

  const manifestUrl = parseHttpsUrl(distribution.manifest_url);
  const signatureUrl = parseHttpsUrl(distribution.signature_url);
  const artifactUrl = parseHttpsUrl(distribution.artifact_url);
  if (!manifestUrl || !signatureUrl || !artifactUrl) return null;
  if (artifactBasename(artifactUrl) !== artifactName) return null;

  return {
    id: text(item.id),
    version,
    artifactName,
    digest,
    manifestUrl: manifestUrl.href,
    signatureUrl: signatureUrl.href,
    artifactUrl: artifactUrl.href,
    signingFingerprint,
    createdAt: text(item.created_at),
  };
}

/**
 * Resolve the newest portal-usable release. API acceptance is necessary but the portal still
 * fails closed if required public metadata is missing or no update trust key remains active.
 *
 * @param {Record<string, unknown>[]} releases
 * @param {Record<string, unknown>[]} trustKeys
 */
export function resolveAgentInstallRelease(releases, trustKeys) {
  const activeFingerprints = new Set(
    trustKeys
      .filter((key) => text(asRecord(key)?.status).toLowerCase() === 'active')
      .map((key) => text(asRecord(key)?.fingerprint_sha256).toLowerCase())
      .filter((fingerprint) => /^[a-f0-9]{64}$/.test(fingerprint)),
  );
  if (activeFingerprints.size === 0) {
    return { release: null, reason: 'No active tenant-approved agent update trust key is available.' };
  }

  const candidates = releases
    .map(candidateRelease)
    .filter((release) => release && activeFingerprints.has(release.signingFingerprint))
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  if (candidates.length === 0) {
    return {
      release: null,
      reason: 'No active signed tarball release has complete HTTPS metadata and a signer matching an active tenant-approved trust key.'
    };
  }
  return { release: candidates[0], reason: '' };
}
