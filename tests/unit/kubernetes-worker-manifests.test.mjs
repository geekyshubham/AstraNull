import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  DEFAULT_KUBERNETES_WORKER_SOURCE_DIR,
  KUBERNETES_WORKER_DIGEST_PLACEHOLDER,
  KUBERNETES_WORKER_IMAGE_COUNT,
  KUBERNETES_WORKER_MANIFESTS,
  KUBERNETES_WORKER_RELEASE_MANIFESTS,
  assertExactWorkerDigest,
  renderKubernetesWorkerManifests,
  validateKubernetesWorkerManifestSources,
  validateRenderedKubernetesWorkerManifests,
} from '../../scripts/render-kubernetes-worker-manifests.mjs';

const tempDirs = [];
function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-k8s-workers-'));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  while (tempDirs.length) rmSync(tempDirs.pop(), { recursive: true, force: true });
});

const DIGEST_A = `sha256:${'a'.repeat(64)}`;
const DIGEST_B = `sha256:${'b'.repeat(64)}`;

describe('Kubernetes worker exact-digest manifests', () => {
  it('keeps every checked-in worker image on the release placeholder', () => {
    assert.deepEqual(validateKubernetesWorkerManifestSources(), {
      manifest_count: KUBERNETES_WORKER_RELEASE_MANIFESTS.length,
      image_count: KUBERNETES_WORKER_IMAGE_COUNT,
    });
  });

  it('renders all five image references out-of-tree to one exact digest', () => {
    const outDir = tempDir();
    const result = renderKubernetesWorkerManifests({ digest: DIGEST_A, outDir });
    assert.equal(result.digest, DIGEST_A);
    assert.equal(result.image_count, 5);
    const rendered = KUBERNETES_WORKER_MANIFESTS
      .map((name) => readFileSync(path.join(outDir, name), 'utf8'))
      .join('\n');
    assert.equal(rendered.includes(KUBERNETES_WORKER_DIGEST_PLACEHOLDER), false);
    assert.equal((rendered.match(new RegExp(DIGEST_A, 'g')) ?? []).length, 5);
  });

  it('rejects malformed, uppercase, and all-zero digests', () => {
    for (const digest of [
      'latest',
      'sha256:abc',
      `sha256:${'A'.repeat(64)}`,
      `sha256:${'0'.repeat(64)}`,
    ]) {
      assert.throws(() => assertExactWorkerDigest(digest), /digest|zero|lowercase/i, digest);
    }
  });

  it('rejects mutable source images and mixed rendered digests', () => {
    const sourceDir = tempDir();
    cpSync(DEFAULT_KUBERNETES_WORKER_SOURCE_DIR, sourceDir, { recursive: true });
    const sourceFile = path.join(sourceDir, KUBERNETES_WORKER_MANIFESTS[0]);
    writeFileSync(
      sourceFile,
      readFileSync(sourceFile, 'utf8').replace(
        `@${KUBERNETES_WORKER_DIGEST_PLACEHOLDER}`,
        ':latest',
      ),
    );
    assert.throws(
      () => validateKubernetesWorkerManifestSources(sourceDir),
      /exact-digest release placeholder/,
    );

    const outDir = tempDir();
    renderKubernetesWorkerManifests({ digest: DIGEST_A, outDir });
    const renderedFile = path.join(outDir, KUBERNETES_WORKER_MANIFESTS[0]);
    writeFileSync(
      renderedFile,
      readFileSync(renderedFile, 'utf8').replace(DIGEST_A, DIGEST_B),
    );
    assert.throws(
      () => validateRenderedKubernetesWorkerManifests(outDir),
      /all use one exact digest/,
    );
  });

  it('rejects missing deadlines, token automount, and non-empty worker RBAC', () => {
    const sourceDir = tempDir();
    cpSync(DEFAULT_KUBERNETES_WORKER_SOURCE_DIR, sourceDir, { recursive: true });
    const cronjob = path.join(sourceDir, 'notification-retry-scheduler.yaml');
    const original = readFileSync(cronjob, 'utf8');
    writeFileSync(cronjob, original.replace('      activeDeadlineSeconds: 180\n', ''));
    assert.throws(() => validateKubernetesWorkerManifestSources(sourceDir), /activeDeadlineSeconds/);

    writeFileSync(cronjob, original.replace('automountServiceAccountToken: false', 'automountServiceAccountToken: true'));
    assert.throws(() => validateKubernetesWorkerManifestSources(sourceDir), /token automount/);

    writeFileSync(cronjob, original);
    const rbac = path.join(sourceDir, 'worker-rbac.yaml');
    writeFileSync(
      rbac,
      readFileSync(rbac, 'utf8').replace('rules: []', 'rules:\n  - apiGroups: ["*"]\n    resources: ["*"]\n    verbs: ["*"]'),
    );
    assert.throws(() => validateKubernetesWorkerManifestSources(sourceDir), /zero-permission Role/);
  });

  it('publishes only the exact CI-tested SHA with verified signature and provenance', () => {
    const workflow = readFileSync(
      path.resolve(import.meta.dirname, '../../.github/workflows/publish-kubernetes-worker.yml'),
      'utf8',
    );
    assert.match(workflow, /workflow_run:[\s\S]*workflows: \["CI"\][\s\S]*branches: \["main"\]/);
    assert.match(workflow, /conclusion == 'success'/);
    assert.match(workflow, /event == 'push'/);
    assert.match(workflow, /head_repository\.full_name == github\.repository/);
    assert.match(workflow, /packages: write/);
    assert.match(workflow, /id-token: write/);
    assert.match(workflow, /attestations: write/);
    assert.match(workflow, /ref: \$\{\{ github\.event\.workflow_run\.head_sha \}\}/);
    assert.match(workflow, /persist-credentials: false/);
    assert.match(workflow, /ghcr\.io\/astranull\/astranull-worker/);
    assert.match(workflow, /file: ops\/kubernetes\/Dockerfile\.worker[\s\S]*push: true/);
    assert.match(workflow, /cosign sign --yes "\$IMAGE@\$DIGEST"/);
    assert.match(workflow, /actions\/attest-build-provenance@[0-9a-f]{40}/);
    assert.match(workflow, /subject-digest: \$\{\{ steps\.build\.outputs\.digest \}\}/);
    assert.match(workflow, /push-to-registry: true/);
    assert.match(workflow, /cosign verify-attestation[\s\S]*--type slsaprovenance/);
    assert.match(workflow, /render-kubernetes-worker-manifests\.mjs[\s\S]*--digest "\$DIGEST"/);
    assert.match(workflow, /release-evidence\.json/);
    for (const action of workflow.matchAll(/^\s*uses:\s*([^\s]+)$/gm)) {
      assert.match(action[1], /@[0-9a-f]{40}$/, `action must be SHA-pinned: ${action[1]}`);
    }
  });

  it('refuses to render over checked-in source manifests', () => {
    assert.throws(
      () => renderKubernetesWorkerManifests({
        digest: DIGEST_A,
        outDir: DEFAULT_KUBERNETES_WORKER_SOURCE_DIR,
      }),
      /out-of-tree/,
    );
  });
});
