#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');

export const KUBERNETES_WORKER_IMAGE_REPOSITORY = 'ghcr.io/astranull/astranull-worker';
export const KUBERNETES_WORKER_DIGEST_PLACEHOLDER = '__ASTRANULL_WORKER_IMAGE_DIGEST__';
export const KUBERNETES_WORKER_MANIFESTS = Object.freeze([
  'waf-orchestrator-runner.yaml',
  'waf-drift-runner.yaml',
  'connector-poll-runner.yaml',
  'notification-retry-scheduler.yaml',
]);
export const KUBERNETES_WORKER_SUPPORT_MANIFESTS = Object.freeze([
  'worker-rbac.yaml',
]);
export const KUBERNETES_WORKER_RELEASE_MANIFESTS = Object.freeze([
  ...KUBERNETES_WORKER_MANIFESTS,
  ...KUBERNETES_WORKER_SUPPORT_MANIFESTS,
]);
export const KUBERNETES_WORKER_IMAGE_COUNT = 5;
export const DEFAULT_KUBERNETES_WORKER_SOURCE_DIR = path.join(
  ROOT,
  'ops',
  'kubernetes',
  'cronjobs',
);

function readUtf8(filePath) {
  return readFileSync(filePath, 'utf8');
}

function imageReferences(source) {
  return [...source.matchAll(/^\s*image:\s*([^\s#]+)\s*(?:#.*)?$/gm)].map((match) => match[1]);
}

function assertCronJobRuntimeHardening(source, name) {
  const documents = source.split(/^---\s*$/m).filter((document) => /kind:\s*CronJob/.test(document));
  if (documents.length === 0) throw new Error(`${name} must contain at least one CronJob.`);
  for (const document of documents) {
    if (!/^apiVersion:\s*batch\/v1\s*$/m.test(document)) {
      throw new Error(`${name} CronJobs must use batch/v1.`);
    }
    if (!/^\s{6}activeDeadlineSeconds:\s*(?:1[2-9][0-9]|[2-9][0-9]{2,})\s*$/m.test(document)) {
      throw new Error(`${name} CronJobs must have a bounded activeDeadlineSeconds of at least 120.`);
    }
    if (!/^\s{10}automountServiceAccountToken:\s*false\s*$/m.test(document)) {
      throw new Error(`${name} Pods must disable service-account token automount.`);
    }
    if (!/^\s{10}serviceAccountName:\s*astranull-worker\s*$/m.test(document)) {
      throw new Error(`${name} Pods must use the explicit zero-permission worker service account.`);
    }
  }
}

function assertZeroPermissionWorkerRbac(directory) {
  const source = readUtf8(path.join(directory, 'worker-rbac.yaml'));
  if (!/kind:\s*ServiceAccount[\s\S]*name:\s*astranull-worker[\s\S]*automountServiceAccountToken:\s*false/.test(source)) {
    throw new Error('worker-rbac.yaml must define the no-token astranull-worker service account.');
  }
  if (!/kind:\s*Role[\s\S]*name:\s*astranull-worker-zero-permission[\s\S]*rules:\s*\[\]/.test(source)) {
    throw new Error('worker-rbac.yaml must define an explicit zero-permission Role.');
  }
  if (!/kind:\s*RoleBinding[\s\S]*kind:\s*ServiceAccount[\s\S]*name:\s*astranull-worker[\s\S]*kind:\s*Role[\s\S]*name:\s*astranull-worker-zero-permission/.test(source)) {
    throw new Error('worker-rbac.yaml must bind only the worker service account to the zero-permission Role.');
  }
}

function kustomizationResources(directory) {
  const source = readUtf8(path.join(directory, 'kustomization.yaml'));
  return [...source.matchAll(/^\s{2}-\s+([^\s#]+)\s*$/gm)].map((match) => match[1]);
}

export function assertExactWorkerDigest(digest) {
  const normalized = String(digest ?? '').trim();
  if (!/^sha256:[0-9a-f]{64}$/.test(normalized)) {
    throw new Error('Kubernetes worker digest must be exact lowercase sha256:<64 hex>.');
  }
  if (normalized === `sha256:${'0'.repeat(64)}`) {
    throw new Error('Kubernetes worker digest must not be the all-zero placeholder.');
  }
  return normalized;
}

function assertManifestInventory(directory) {
  const resources = kustomizationResources(directory);
  if (
    resources.length !== KUBERNETES_WORKER_RELEASE_MANIFESTS.length
    || KUBERNETES_WORKER_RELEASE_MANIFESTS.some((name) => !resources.includes(name))
  ) {
    throw new Error(
      `Kubernetes worker kustomization must contain exactly: ${KUBERNETES_WORKER_RELEASE_MANIFESTS.join(', ')}.`,
    );
  }
}

export function validateKubernetesWorkerManifestSources(
  sourceDir = DEFAULT_KUBERNETES_WORKER_SOURCE_DIR,
) {
  assertManifestInventory(sourceDir);
  const expected = `${KUBERNETES_WORKER_IMAGE_REPOSITORY}@${KUBERNETES_WORKER_DIGEST_PLACEHOLDER}`;
  let imageCount = 0;
  for (const name of KUBERNETES_WORKER_MANIFESTS) {
    const source = readUtf8(path.join(sourceDir, name));
    assertCronJobRuntimeHardening(source, name);
    const refs = imageReferences(source);
    if (refs.length === 0 || refs.some((ref) => ref !== expected)) {
      throw new Error(`${name} must use only the worker exact-digest release placeholder.`);
    }
    imageCount += refs.length;
  }
  if (imageCount !== KUBERNETES_WORKER_IMAGE_COUNT) {
    throw new Error(
      `Kubernetes worker source must contain exactly ${KUBERNETES_WORKER_IMAGE_COUNT} image references; found ${imageCount}.`,
    );
  }
  assertZeroPermissionWorkerRbac(sourceDir);
  return { manifest_count: KUBERNETES_WORKER_RELEASE_MANIFESTS.length, image_count: imageCount };
}

export function validateRenderedKubernetesWorkerManifests(directory, expectedDigest = null) {
  assertManifestInventory(directory);
  const requiredDigest = expectedDigest == null ? null : assertExactWorkerDigest(expectedDigest);
  let observedDigest = null;
  let imageCount = 0;
  for (const name of KUBERNETES_WORKER_MANIFESTS) {
    const source = readUtf8(path.join(directory, name));
    assertCronJobRuntimeHardening(source, name);
    const refs = imageReferences(source);
    if (refs.length === 0) throw new Error(`${name} has no worker image reference.`);
    for (const ref of refs) {
      const prefix = `${KUBERNETES_WORKER_IMAGE_REPOSITORY}@`;
      if (!ref.startsWith(prefix)) {
        throw new Error(`${name} contains a mutable or unexpected worker image reference.`);
      }
      const digest = assertExactWorkerDigest(ref.slice(prefix.length));
      if (requiredDigest && digest !== requiredDigest) {
        throw new Error(`${name} does not use the requested exact worker digest.`);
      }
      if (observedDigest && digest !== observedDigest) {
        throw new Error('Rendered Kubernetes worker manifests must all use one exact digest.');
      }
      observedDigest = digest;
      imageCount += 1;
    }
  }
  if (imageCount !== KUBERNETES_WORKER_IMAGE_COUNT) {
    throw new Error(
      `Rendered Kubernetes worker manifests must contain exactly ${KUBERNETES_WORKER_IMAGE_COUNT} image references; found ${imageCount}.`,
    );
  }
  assertZeroPermissionWorkerRbac(directory);
  return {
    digest: observedDigest,
    manifest_count: KUBERNETES_WORKER_RELEASE_MANIFESTS.length,
    image_count: imageCount,
  };
}

export function renderKubernetesWorkerManifests({
  digest,
  outDir,
  sourceDir = DEFAULT_KUBERNETES_WORKER_SOURCE_DIR,
}) {
  const exactDigest = assertExactWorkerDigest(digest);
  if (!String(outDir ?? '').trim()) throw new Error('Kubernetes worker render requires --out-dir.');
  const resolvedSource = path.resolve(sourceDir);
  const resolvedOut = path.resolve(outDir);
  if (resolvedOut === resolvedSource) {
    throw new Error('Kubernetes worker manifests must be rendered out-of-tree.');
  }

  validateKubernetesWorkerManifestSources(resolvedSource);
  mkdirSync(resolvedOut, { recursive: true });
  for (const name of KUBERNETES_WORKER_RELEASE_MANIFESTS) {
    const rendered = readUtf8(path.join(resolvedSource, name)).replaceAll(
      KUBERNETES_WORKER_DIGEST_PLACEHOLDER,
      exactDigest,
    );
    writeFileSync(path.join(resolvedOut, name), rendered, { encoding: 'utf8', mode: 0o600 });
  }
  writeFileSync(
    path.join(resolvedOut, 'kustomization.yaml'),
    readUtf8(path.join(resolvedSource, 'kustomization.yaml')),
    { encoding: 'utf8', mode: 0o600 },
  );
  return validateRenderedKubernetesWorkerManifests(resolvedOut, exactDigest);
}

function parseArgs(argv) {
  const parsed = { checkSource: false, digest: null, outDir: null, validateDir: null };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--check-source') {
      parsed.checkSource = true;
      continue;
    }
    if (['--digest', '--out-dir', '--validate-dir'].includes(arg)) {
      const value = argv[i + 1];
      if (!value || value.startsWith('--')) throw new Error(`${arg} requires a value.`);
      if (arg === '--digest') parsed.digest = value;
      if (arg === '--out-dir') parsed.outDir = value;
      if (arg === '--validate-dir') parsed.validateDir = value;
      i += 1;
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }
  return parsed;
}

export function main(argv = process.argv) {
  const args = parseArgs(argv);
  if (!args.checkSource && !args.digest && !args.validateDir) {
    throw new Error('Use --check-source, --digest with --out-dir, or --validate-dir.');
  }
  if (args.checkSource) validateKubernetesWorkerManifestSources();
  let result = null;
  if (args.digest || args.outDir) {
    if (!args.digest || !args.outDir) throw new Error('--digest and --out-dir must be provided together.');
    result = renderKubernetesWorkerManifests({ digest: args.digest, outDir: args.outDir });
  }
  if (args.validateDir) result = validateRenderedKubernetesWorkerManifests(args.validateDir);
  console.log(`kubernetes-worker-manifests: ok${result?.digest ? ` (${result.digest})` : ''}`);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === __filename;
if (isMain) {
  try {
    main();
  } catch (error) {
    console.error(`kubernetes-worker-manifests: failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
