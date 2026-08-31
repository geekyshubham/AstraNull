import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  DEFAULT_KUBERNETES_WORKER_SOURCE_DIR,
  KUBERNETES_WORKER_DIGEST_PLACEHOLDER,
  KUBERNETES_WORKER_IMAGE_COUNT,
  KUBERNETES_WORKER_IMAGE_REPOSITORY_PLACEHOLDER,
  KUBERNETES_WORKER_MANIFESTS,
  KUBERNETES_WORKER_RELEASE_MANIFESTS,
  assertExactWorkerDigest,
  assertKubernetesWorkerImageRepository,
  deriveKubernetesWorkerImageRepository,
  renderKubernetesWorkerManifests,
  validateKubernetesWorkerManifestSources,
  validateRenderedKubernetesWorkerManifests,
} from '../../scripts/render-kubernetes-worker-manifests.mjs';

const ROOT = path.resolve(import.meta.dirname, '../..');
const RENDERER = path.join(ROOT, 'scripts/render-kubernetes-worker-manifests.mjs');
const WORKFLOW = path.join(ROOT, '.github/workflows/publish-kubernetes-worker.yml');
const IMAGE_REPOSITORY = 'ghcr.io/test-owner/astranull-worker';
const OLD_IMAGE_REPOSITORY = ['ghcr.io', 'astranull', 'astranull-worker'].join('/');
const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-k8s-workers-'));
  tempDirs.push(dir);
  return dir;
}

function workerManifestSources(directory = DEFAULT_KUBERNETES_WORKER_SOURCE_DIR) {
  return KUBERNETES_WORKER_MANIFESTS
    .map((name) => readFileSync(path.join(directory, name), 'utf8'))
    .join('\n');
}

afterEach(() => {
  while (tempDirs.length) rmSync(tempDirs.pop(), { recursive: true, force: true });
});

const DIGEST_A = `sha256:${'a'.repeat(64)}`;
const DIGEST_B = `sha256:${'b'.repeat(64)}`;

describe('Kubernetes worker exact-digest manifests', () => {
  it('keeps all five checked-in images on repository and digest placeholders', () => {
    assert.deepEqual(validateKubernetesWorkerManifestSources(), {
      manifest_count: KUBERNETES_WORKER_RELEASE_MANIFESTS.length,
      image_count: KUBERNETES_WORKER_IMAGE_COUNT,
    });
    const source = workerManifestSources();
    const placeholderReference = `${KUBERNETES_WORKER_IMAGE_REPOSITORY_PLACEHOLDER}@${KUBERNETES_WORKER_DIGEST_PLACEHOLDER}`;
    assert.equal(source.split(placeholderReference).length - 1, KUBERNETES_WORKER_IMAGE_COUNT);
    assert.equal(
      source.split(KUBERNETES_WORKER_IMAGE_REPOSITORY_PLACEHOLDER).length - 1,
      KUBERNETES_WORKER_IMAGE_COUNT,
    );
    assert.equal(
      source.split(KUBERNETES_WORKER_DIGEST_PLACEHOLDER).length - 1,
      KUBERNETES_WORKER_IMAGE_COUNT,
    );
  });

  it('derives a lowercase worker repository only from strict GitHub owner names', () => {
    assert.equal(
      deriveKubernetesWorkerImageRepository('Test-Owner'),
      IMAGE_REPOSITORY,
    );
    for (const owner of ['', '-owner', 'owner-', 'owner--name', 'owner/name', 'a'.repeat(40)]) {
      assert.throws(
        () => deriveKubernetesWorkerImageRepository(owner),
        /GitHub repository owner/,
        owner,
      );
    }
  });

  it('rejects non-GHCR, uppercase, tagged, digested, and malformed repositories', () => {
    assert.equal(assertKubernetesWorkerImageRepository(IMAGE_REPOSITORY), IMAGE_REPOSITORY);
    for (const repository of [
      '',
      'docker.io/test-owner/astranull-worker',
      'ghcr.io/Test-Owner/astranull-worker',
      'ghcr.io/test-owner/ASTRANULL-worker',
      'ghcr.io/-test-owner/astranull-worker',
      'ghcr.io/test--owner/astranull-worker',
      'ghcr.io/test-owner/astranull-worker:latest',
      `ghcr.io/test-owner/astranull-worker@${DIGEST_A}`,
      'ghcr.io/test-owner/nested/astranull-worker',
      KUBERNETES_WORKER_IMAGE_REPOSITORY_PLACEHOLDER,
    ]) {
      assert.throws(
        () => assertKubernetesWorkerImageRepository(repository),
        /strict lowercase ghcr\.io/,
        repository,
      );
    }
  });

  it('renders and validates all five images as one exact repository@digest', () => {
    const outDir = tempDir();
    const result = renderKubernetesWorkerManifests({
      digest: DIGEST_A,
      imageRepository: IMAGE_REPOSITORY,
      outDir,
    });
    const expectedReference = `${IMAGE_REPOSITORY}@${DIGEST_A}`;
    assert.equal(result.image, expectedReference);
    assert.equal(result.image_repository, IMAGE_REPOSITORY);
    assert.equal(result.digest, DIGEST_A);
    assert.equal(result.image_count, KUBERNETES_WORKER_IMAGE_COUNT);
    const rendered = workerManifestSources(outDir);
    assert.equal(rendered.includes(KUBERNETES_WORKER_IMAGE_REPOSITORY_PLACEHOLDER), false);
    assert.equal(rendered.includes(KUBERNETES_WORKER_DIGEST_PLACEHOLDER), false);
    assert.equal(rendered.split(expectedReference).length - 1, KUBERNETES_WORKER_IMAGE_COUNT);
    assert.deepEqual(
      validateRenderedKubernetesWorkerManifests(outDir, DIGEST_A, IMAGE_REPOSITORY),
      result,
    );
  });

  it('requires an explicit repository except for the validated GitHub Actions CI fallback', () => {
    assert.throws(
      () => renderKubernetesWorkerManifests({ digest: DIGEST_A, outDir: tempDir() }),
      /strict lowercase ghcr\.io/,
    );

    const localOut = tempDir();
    const localEnv = { ...process.env };
    delete localEnv.GITHUB_ACTIONS;
    delete localEnv.GITHUB_REPOSITORY_OWNER;
    const local = spawnSync(
      process.execPath,
      [RENDERER, '--digest', DIGEST_A, '--out-dir', localOut],
      { encoding: 'utf8', env: localEnv },
    );
    assert.notEqual(local.status, 0);
    assert.match(local.stderr, /requires --image-repository/);

    const ciOut = tempDir();
    const ci = spawnSync(
      process.execPath,
      [RENDERER, '--digest', DIGEST_A, '--out-dir', ciOut],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          GITHUB_ACTIONS: 'true',
          GITHUB_REPOSITORY_OWNER: 'CI-Owner',
        },
      },
    );
    assert.equal(ci.status, 0, ci.stderr);
    assert.equal(
      validateRenderedKubernetesWorkerManifests(ciOut).image,
      `ghcr.io/ci-owner/astranull-worker@${DIGEST_A}`,
    );
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

  it('rejects mutable source images and mixed rendered repositories or digests', () => {
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
      /repository and exact-digest release placeholders/,
    );

    const mixedRepositoryDir = tempDir();
    renderKubernetesWorkerManifests({
      digest: DIGEST_A,
      imageRepository: IMAGE_REPOSITORY,
      outDir: mixedRepositoryDir,
    });
    const repositoryFile = path.join(mixedRepositoryDir, KUBERNETES_WORKER_MANIFESTS[0]);
    writeFileSync(
      repositoryFile,
      readFileSync(repositoryFile, 'utf8').replace(
        IMAGE_REPOSITORY,
        'ghcr.io/other-owner/astranull-worker',
      ),
    );
    assert.throws(
      () => validateRenderedKubernetesWorkerManifests(mixedRepositoryDir),
      /one concrete repository@sha256 digest/,
    );

    const mixedDigestDir = tempDir();
    renderKubernetesWorkerManifests({
      digest: DIGEST_A,
      imageRepository: IMAGE_REPOSITORY,
      outDir: mixedDigestDir,
    });
    const digestFile = path.join(mixedDigestDir, KUBERNETES_WORKER_MANIFESTS[0]);
    writeFileSync(
      digestFile,
      readFileSync(digestFile, 'utf8').replace(DIGEST_A, DIGEST_B),
    );
    assert.throws(
      () => validateRenderedKubernetesWorkerManifests(mixedDigestDir),
      /one concrete repository@sha256 digest/,
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

  it('rejects duplicate top-level Kubernetes YAML keys in source and rendered documents', () => {
    const sourceDir = tempDir();
    cpSync(DEFAULT_KUBERNETES_WORKER_SOURCE_DIR, sourceDir, { recursive: true });
    const sourceFile = path.join(sourceDir, KUBERNETES_WORKER_MANIFESTS[0]);
    const sourceOriginal = readFileSync(sourceFile, 'utf8');
    const renderedDir = tempDir();
    renderKubernetesWorkerManifests({
      digest: DIGEST_A,
      imageRepository: IMAGE_REPOSITORY,
      outDir: renderedDir,
    });
    const renderedFile = path.join(renderedDir, KUBERNETES_WORKER_MANIFESTS[0]);
    const renderedOriginal = readFileSync(renderedFile, 'utf8');

    for (const key of ['apiVersion', 'kind', 'metadata', 'spec']) {
      const duplicateKey = (source) => source.replace(
        new RegExp(`^${key}:.*$`, 'm'),
        (line) => `${line}\n${line}`,
      );
      const expectedError = new RegExp(`duplicate top-level YAML key "${key}"`, 'i');

      writeFileSync(sourceFile, duplicateKey(sourceOriginal));
      assert.throws(() => validateKubernetesWorkerManifestSources(sourceDir), expectedError);
      writeFileSync(sourceFile, sourceOriginal);

      writeFileSync(renderedFile, duplicateKey(renderedOriginal));
      assert.throws(() => validateRenderedKubernetesWorkerManifests(renderedDir), expectedError);
      writeFileSync(renderedFile, renderedOriginal);
    }
  });

  it('rejects nested hardening-key overrides in sources, rendering, and rendered manifests', () => {
    const sourceDir = tempDir();
    cpSync(DEFAULT_KUBERNETES_WORKER_SOURCE_DIR, sourceDir, { recursive: true });
    const sourceFile = path.join(sourceDir, 'waf-orchestrator-runner.yaml');
    const sourceOriginal = readFileSync(sourceFile, 'utf8');
    const renderedDir = tempDir();
    renderKubernetesWorkerManifests({
      digest: DIGEST_A,
      imageRepository: IMAGE_REPOSITORY,
      outDir: renderedDir,
    });
    const renderedFile = path.join(renderedDir, 'waf-orchestrator-runner.yaml');
    const renderedOriginal = readFileSync(renderedFile, 'utf8');
    const overrides = new Map([
      ['automountServiceAccountToken', 'true'],
      ['serviceAccountName', 'default'],
      ['runAsNonRoot', 'false'],
    ]);

    for (const [key, value] of overrides) {
      const injectOverride = (source) => source.replace(
        new RegExp(`^(\\s*)${key}:.*$`, 'm'),
        (line, indent) => `${line}\n${indent}${key}: ${value}`,
      );
      const expectedError = new RegExp(`duplicate YAML key "${key}"`, 'i');

      writeFileSync(sourceFile, injectOverride(sourceOriginal));
      assert.throws(() => validateKubernetesWorkerManifestSources(sourceDir), expectedError);
      assert.throws(
        () => renderKubernetesWorkerManifests({
          digest: DIGEST_A,
          imageRepository: IMAGE_REPOSITORY,
          outDir: tempDir(),
          sourceDir,
        }),
        expectedError,
      );
      writeFileSync(sourceFile, sourceOriginal);

      writeFileSync(renderedFile, injectOverride(renderedOriginal));
      assert.throws(() => validateRenderedKubernetesWorkerManifests(renderedDir), expectedError);
      writeFileSync(renderedFile, renderedOriginal);
    }
  });

  it('derives one repository output for build, cosign, provenance, render, and evidence', () => {
    const workflow = readFileSync(WORKFLOW, 'utf8');
    const repositoryOutput = '${{ steps.image.outputs.repository }}';
    assert.match(workflow, /workflow_run:[\s\S]*workflows: \["CI"\][\s\S]*branches: \["main"\]/);
    assert.match(workflow, /conclusion == 'success'/);
    assert.match(workflow, /event == 'push'/);
    assert.match(workflow, /head_repository\.full_name == github\.repository/);
    assert.match(workflow, /packages: write/);
    assert.match(workflow, /id-token: write/);
    assert.match(workflow, /attestations: write/);
    assert.match(workflow, /REPOSITORY_OWNER: \$\{\{ github\.repository_owner \}\}/);
    assert.match(workflow, /LC_ALL=C tr '\[:upper:\]' '\[:lower:\]'/);
    assert.equal(
      workflow.includes('[[ ! "$owner" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]'),
      true,
    );
    assert.match(workflow, /\$\{#owner\} > 39/);
    assert.match(workflow, /repository=ghcr\.io\/%s\/astranull-worker/);
    assert.equal(workflow.split(repositoryOutput).length - 1, 5);
    assert.match(workflow, /ref: \$\{\{ github\.event\.workflow_run\.head_sha \}\}/);
    assert.match(workflow, /persist-credentials: false/);

    const checkout = workflow.indexOf('uses: actions/checkout@');
    const githubShaInvariant = workflow.indexOf('[[ "$GITHUB_SHA" == "$RELEASE_SHA" ]]');
    const checkoutHeadInvariant = workflow.indexOf(
      '[[ "$(git rev-parse HEAD)" == "$RELEASE_SHA" ]]',
    );
    const buildAction = workflow.indexOf('uses: docker/build-push-action@');
    const pushInput = workflow.indexOf('          push: true', buildAction);
    const provenanceAction = workflow.indexOf('uses: actions/attest-build-provenance@');
    const releaseEvidence = workflow.indexOf('> output/kubernetes-worker/release-evidence.json');
    for (const [name, index] of [
      ['checkout', checkout],
      ['GITHUB_SHA invariant', githubShaInvariant],
      ['checkout HEAD invariant', checkoutHeadInvariant],
      ['build action', buildAction],
      ['push input', pushInput],
      ['provenance action', provenanceAction],
      ['release evidence', releaseEvidence],
    ]) {
      assert.notEqual(index, -1, `${name} must exist`);
    }
    assert.ok(checkout < githubShaInvariant, 'revision checks must follow checkout');
    assert.ok(githubShaInvariant < checkoutHeadInvariant, 'both SHA checks must run together');
    for (const [name, index] of [
      ['build action', buildAction],
      ['push input', pushInput],
      ['provenance action', provenanceAction],
      ['release evidence', releaseEvidence],
    ]) {
      assert.ok(githubShaInvariant < index, `GITHUB_SHA invariant must precede ${name}`);
      assert.ok(checkoutHeadInvariant < index, `checkout HEAD invariant must precede ${name}`);
    }

    assert.equal(
      workflow.includes('tags: ${{ steps.image.outputs.repository }}:${{ env.RELEASE_SHA }}'),
      true,
    );
    const installCosign = workflow.indexOf('uses: sigstore/cosign-installer@');
    const buildStep = workflow.slice(buildAction, installCosign);
    assert.equal(buildStep.includes('          push: true'), true);
    assert.equal(
      buildStep.includes([
        '          labels: |',
        '            org.opencontainers.image.source=${{ github.server_url }}/${{ github.repository }}',
        '            org.opencontainers.image.revision=${{ env.RELEASE_SHA }}',
      ].join('\n')),
      true,
    );
    assert.equal((workflow.match(/org\.opencontainers\.image\.source=/g) ?? []).length, 1);
    assert.equal((workflow.match(/org\.opencontainers\.image\.revision=/g) ?? []).length, 1);
    assert.match(workflow, /file: ops\/kubernetes\/Dockerfile\.worker[\s\S]*push: true/);
    assert.equal(
      (workflow.match(/IMAGE_REFERENCE="\$IMAGE_REPOSITORY@\$DIGEST"/g) ?? []).length,
      3,
    );
    assert.match(workflow, /cosign sign --yes "\$IMAGE_REFERENCE"/);
    assert.match(workflow, /cosign verify[\s\S]*"\$IMAGE_REFERENCE" >\/dev\/null/);
    assert.match(
      workflow,
      /cosign verify-attestation[\s\S]*--type slsaprovenance[\s\S]*"\$IMAGE_REFERENCE" >\/dev\/null/,
    );
    assert.match(workflow, /actions\/attest-build-provenance@[0-9a-f]{40}/);
    assert.equal(workflow.includes(`subject-name: ${repositoryOutput}`), true);
    assert.match(workflow, /subject-digest: \$\{\{ steps\.build\.outputs\.digest \}\}/);
    assert.match(workflow, /push-to-registry: true/);
    assert.equal(
      (workflow.match(/--image-repository "\$IMAGE_REPOSITORY"/g) ?? []).length,
      2,
    );
    assert.match(workflow, /"image_repository":"%s","image":"%s","digest":"%s"/);
    assert.match(
      workflow,
      /"\$RELEASE_SHA" "\$IMAGE_REPOSITORY" "\$IMAGE_REFERENCE" "\$DIGEST" "\$GITHUB_RUN_ID"/,
    );
    assert.match(workflow, /release-evidence\.json/);
    for (const action of workflow.matchAll(/^\s*uses:\s*([^\s]+)$/gm)) {
      assert.match(action[1], /@[0-9a-f]{40}$/, `action must be SHA-pinned: ${action[1]}`);
    }
  });

  it('contains no stale static OCI source or former nonexistent GHCR owner', () => {
    const dockerfile = readFileSync(
      path.join(ROOT, 'ops/kubernetes/Dockerfile.worker'),
      'utf8',
    );
    const sources = [
      readFileSync(WORKFLOW, 'utf8'),
      dockerfile,
      readFileSync(RENDERER, 'utf8'),
      workerManifestSources(),
    ];
    for (const source of sources) {
      assert.equal(source.includes(OLD_IMAGE_REPOSITORY), false);
      assert.equal(source.includes('https://github.com/astranull/astranull'), false);
    }
    assert.equal(dockerfile.includes('org.opencontainers.image.source='), false);
    assert.equal(dockerfile.includes('org.opencontainers.image.revision='), false);
  });

  it('refuses to render over checked-in source manifests', () => {
    assert.throws(
      () => renderKubernetesWorkerManifests({
        digest: DIGEST_A,
        imageRepository: IMAGE_REPOSITORY,
        outDir: DEFAULT_KUBERNETES_WORKER_SOURCE_DIR,
      }),
      /out-of-tree/,
    );
  });
});
