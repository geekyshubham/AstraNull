#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const GHCR_PREFIX = 'ghcr.io/';
const KUBERNETES_WORKER_IMAGE_NAME = 'astranull-worker';
const GITHUB_OWNER_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const GHCR_IMAGE_NAME_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;

export const KUBERNETES_WORKER_IMAGE_REPOSITORY_PLACEHOLDER = '__ASTRANULL_WORKER_IMAGE_REPOSITORY__';
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

function assertGitHubOwner(owner) {
  if (
    owner.length > 39
    || !GITHUB_OWNER_PATTERN.test(owner)
  ) {
    throw new Error(
      'GitHub repository owner must contain at most 39 alphanumeric characters or single hyphens and cannot begin or end with a hyphen.',
    );
  }
  return owner;
}

export function deriveKubernetesWorkerImageRepository(repositoryOwner) {
  const owner = String(repositoryOwner ?? '').toLowerCase();
  assertGitHubOwner(owner);
  return `${GHCR_PREFIX}${owner}/${KUBERNETES_WORKER_IMAGE_NAME}`;
}

export function assertKubernetesWorkerImageRepository(imageRepository) {
  const repository = String(imageRepository ?? '');
  const segments = repository.startsWith(GHCR_PREFIX)
    ? repository.slice(GHCR_PREFIX.length).split('/')
    : [];
  if (
    repository.length > 255
    || repository !== repository.toLowerCase()
    || segments.length !== 2
    || segments[0].length > 39
    || !GITHUB_OWNER_PATTERN.test(segments[0] ?? '')
    || !GHCR_IMAGE_NAME_PATTERN.test(segments[1] ?? '')
  ) {
    throw new Error(
      'Kubernetes worker image repository must be a strict lowercase ghcr.io/<github-owner>/<image> repository without a tag or digest.',
    );
  }
  return repository;
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

const YAML_MAPPING_ENTRY_PATTERN = /^([A-Za-z_][A-Za-z0-9_./-]*):(?: +(.*))?$/;

function unsupportedYaml(name, documentIndex, lineNumber, detail) {
  throw new Error(
    `${name} document ${documentIndex + 1} line ${lineNumber} has unsupported YAML syntax: ${detail}.`,
  );
}

function yamlSyntaxOutsideQuotes(value, name, documentIndex, lineNumber) {
  let quote = null;
  let syntax = '';
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (quote === '"') {
      syntax += ' ';
      if (character === '\\') {
        index += 1;
        syntax += ' ';
      } else if (character === '"') {
        quote = null;
      }
      continue;
    }
    if (quote === "'") {
      syntax += ' ';
      if (character === "'" && value[index + 1] === "'") {
        index += 1;
        syntax += ' ';
      } else if (character === "'") {
        quote = null;
      }
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      syntax += ' ';
      continue;
    }
    syntax += character;
  }
  if (quote) unsupportedYaml(name, documentIndex, lineNumber, 'unterminated quoted scalar');
  const comment = [...syntax].findIndex(
    (character, index) => character === '#' && (index === 0 || /\s/.test(syntax[index - 1])),
  );
  return (comment === -1 ? syntax : syntax.slice(0, comment)).trim();
}

function assertSupportedYamlValue(value, name, documentIndex, lineNumber) {
  const trimmed = String(value ?? '').trim();
  if (!trimmed || trimmed.startsWith('#')) return false;
  const syntax = yamlSyntaxOutsideQuotes(trimmed, name, documentIndex, lineNumber);
  if (!syntax) return true;
  if (/^[|>]/.test(syntax)) {
    unsupportedYaml(name, documentIndex, lineNumber, 'block scalars are not supported');
  }
  if (/(^|[\s,[\]{}])[&*!]/.test(syntax)) {
    unsupportedYaml(name, documentIndex, lineNumber, 'anchors, aliases, and tags are not supported');
  }
  if (/[{}]/.test(syntax) && syntax !== '{}') {
    unsupportedYaml(name, documentIndex, lineNumber, 'non-empty flow mappings are not supported');
  }
  if (/[\[\]]/.test(syntax) && !/^\[[^\[\]{}:]*\]$/.test(syntax)) {
    unsupportedYaml(name, documentIndex, lineNumber, 'complex flow sequences are not supported');
  }
  return true;
}

function parseYamlMappingEntry(content, token, context) {
  const match = YAML_MAPPING_ENTRY_PATTERN.exec(content);
  if (!match) {
    unsupportedYaml(
      context.name,
      context.documentIndex,
      token.lineNumber,
      'expected an unquoted block-mapping key',
    );
  }
  return {
    key: match[1],
    hasValue: assertSupportedYamlValue(
      match[2],
      context.name,
      context.documentIndex,
      token.lineNumber,
    ),
    token,
  };
}

function assertUniqueYamlKey(keys, entry, indent, context) {
  if (keys.has(entry.key)) {
    const level = indent === 0 ? 'top-level ' : '';
    throw new Error(
      `${context.name} document ${context.documentIndex + 1} has duplicate ${level}YAML key "${entry.key}" at line ${entry.token.lineNumber}.`,
    );
  }
  keys.add(entry.key);
}

function parseYamlBlock(tokens, start, indent, context) {
  const token = tokens[start];
  if (!token || token.indent !== indent) {
    unsupportedYaml(context.name, context.documentIndex, token?.lineNumber ?? 1, 'invalid indentation');
  }
  return token.content === '-' || token.content.startsWith('- ')
    ? parseYamlSequence(tokens, start, indent, context)
    : parseYamlMapping(tokens, start, indent, context);
}

function parseYamlMapping(tokens, start, indent, context, firstEntry = null) {
  const keys = new Set();
  let index = start;
  let entry = firstEntry;
  while (entry || index < tokens.length) {
    if (!entry) {
      const token = tokens[index];
      if (token.indent < indent) break;
      if (token.indent > indent || token.content === '-' || token.content.startsWith('- ')) {
        unsupportedYaml(
          context.name,
          context.documentIndex,
          token.lineNumber,
          'unexpected indentation or sequence entry in a mapping',
        );
      }
      entry = parseYamlMappingEntry(token.content, token, context);
      index += 1;
    }

    assertUniqueYamlKey(keys, entry, indent, context);
    const next = tokens[index];
    if (!entry.hasValue && next?.indent > indent) {
      index = parseYamlBlock(tokens, index, next.indent, context);
    } else if (entry.hasValue && next?.indent > indent) {
      unsupportedYaml(
        context.name,
        context.documentIndex,
        next.lineNumber,
        `nested content under scalar key "${entry.key}"`,
      );
    }
    entry = null;
  }
  return index;
}

function parseYamlSequence(tokens, start, indent, context) {
  let index = start;
  while (index < tokens.length) {
    const token = tokens[index];
    if (token.indent < indent) break;
    if (token.indent > indent) {
      unsupportedYaml(
        context.name,
        context.documentIndex,
        token.lineNumber,
        'unexpected indentation in a sequence',
      );
    }
    const match = /^-(?: +(.*))?$/.exec(token.content);
    if (!match) {
      unsupportedYaml(
        context.name,
        context.documentIndex,
        token.lineNumber,
        'expected a block-sequence entry',
      );
    }
    index += 1;
    const item = String(match[1] ?? '').trim();
    if (!item || item.startsWith('#')) {
      const next = tokens[index];
      if (next?.indent > indent) index = parseYamlBlock(tokens, index, next.indent, context);
      continue;
    }

    const mapping = YAML_MAPPING_ENTRY_PATTERN.exec(item);
    if (mapping) {
      const firstEntry = parseYamlMappingEntry(item, token, context);
      index = parseYamlMapping(tokens, index, indent + 2, context, firstEntry);
      continue;
    }

    const syntax = yamlSyntaxOutsideQuotes(item, context.name, context.documentIndex, token.lineNumber);
    if (/:(?:\s|$)/.test(syntax)) {
      unsupportedYaml(
        context.name,
        context.documentIndex,
        token.lineNumber,
        'unsupported sequence-item mapping key',
      );
    }
    assertSupportedYamlValue(item, context.name, context.documentIndex, token.lineNumber);
    if (tokens[index]?.indent > indent) {
      unsupportedYaml(
        context.name,
        context.documentIndex,
        tokens[index].lineNumber,
        'nested content under a scalar sequence item',
      );
    }
  }
  return index;
}

function assertUniqueYamlMappingKeys(source, name) {
  const documents = String(source).replace(/^\uFEFF/, '').split(/^---(?: +#.*)? *$/m);
  for (const [documentIndex, document] of documents.entries()) {
    const tokens = [];
    let ended = false;
    for (const [lineIndex, line] of document.split(/\r?\n/).entries()) {
      const lineNumber = lineIndex + 1;
      if (line.includes('\t')) unsupportedYaml(name, documentIndex, lineNumber, 'tabs are not supported');
      if (/^ *(?:#.*)?$/.test(line)) continue;
      const indent = /^ */.exec(line)[0].length;
      if (indent % 2 !== 0) unsupportedYaml(name, documentIndex, lineNumber, 'indentation must use two-space levels');
      const content = line.slice(indent).trimEnd();
      if (/^\.\.\.(?: +#.*)?$/.test(content)) {
        if (indent !== 0) unsupportedYaml(name, documentIndex, lineNumber, 'indented document end marker');
        ended = true;
        continue;
      }
      if (ended) unsupportedYaml(name, documentIndex, lineNumber, 'content follows a document end marker');
      tokens.push({ content, indent, lineNumber });
    }
    if (tokens.length === 0) continue;
    if (tokens[0].indent !== 0 || tokens[0].content === '-' || tokens[0].content.startsWith('- ')) {
      unsupportedYaml(name, documentIndex, tokens[0].lineNumber, 'Kubernetes documents must be root mappings');
    }
    const consumed = parseYamlMapping(tokens, 0, 0, { documentIndex, name });
    if (consumed !== tokens.length) {
      unsupportedYaml(name, documentIndex, tokens[consumed].lineNumber, 'unconsumed document content');
    }
  }
}

function assertManifestInventory(directory) {
  for (const name of ['kustomization.yaml', ...KUBERNETES_WORKER_RELEASE_MANIFESTS]) {
    assertUniqueYamlMappingKeys(readUtf8(path.join(directory, name)), name);
  }
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
  const expected = `${KUBERNETES_WORKER_IMAGE_REPOSITORY_PLACEHOLDER}@${KUBERNETES_WORKER_DIGEST_PLACEHOLDER}`;
  let imageCount = 0;
  for (const name of KUBERNETES_WORKER_MANIFESTS) {
    const source = readUtf8(path.join(sourceDir, name));
    assertCronJobRuntimeHardening(source, name);
    const refs = imageReferences(source);
    if (refs.length === 0 || refs.some((ref) => ref !== expected)) {
      throw new Error(`${name} must use only the worker repository and exact-digest release placeholders.`);
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

export function validateRenderedKubernetesWorkerManifests(
  directory,
  expectedDigest = null,
  expectedImageRepository = null,
) {
  assertManifestInventory(directory);
  const requiredDigest = expectedDigest == null ? null : assertExactWorkerDigest(expectedDigest);
  const requiredRepository = expectedImageRepository == null
    ? null
    : assertKubernetesWorkerImageRepository(expectedImageRepository);
  let observedReference = null;
  let observedDigest = null;
  let observedRepository = null;
  let imageCount = 0;
  for (const name of KUBERNETES_WORKER_MANIFESTS) {
    const source = readUtf8(path.join(directory, name));
    assertCronJobRuntimeHardening(source, name);
    const refs = imageReferences(source);
    if (refs.length === 0) throw new Error(`${name} has no worker image reference.`);
    for (const ref of refs) {
      const separator = ref.indexOf('@');
      if (separator < 1 || separator !== ref.lastIndexOf('@')) {
        throw new Error(`${name} contains a mutable or malformed worker image reference.`);
      }
      const repository = assertKubernetesWorkerImageRepository(ref.slice(0, separator));
      const digest = assertExactWorkerDigest(ref.slice(separator + 1));
      if (requiredRepository && repository !== requiredRepository) {
        throw new Error(`${name} does not use the requested concrete worker image repository.`);
      }
      if (requiredDigest && digest !== requiredDigest) {
        throw new Error(`${name} does not use the requested exact worker digest.`);
      }
      if (observedReference && ref !== observedReference) {
        throw new Error(
          'Rendered Kubernetes worker manifests must all use one concrete repository@sha256 digest.',
        );
      }
      observedReference = ref;
      observedRepository = repository;
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
    image: observedReference,
    image_repository: observedRepository,
    digest: observedDigest,
    manifest_count: KUBERNETES_WORKER_RELEASE_MANIFESTS.length,
    image_count: imageCount,
  };
}

export function renderKubernetesWorkerManifests({
  digest,
  imageRepository,
  outDir,
  sourceDir = DEFAULT_KUBERNETES_WORKER_SOURCE_DIR,
}) {
  const exactDigest = assertExactWorkerDigest(digest);
  const exactRepository = assertKubernetesWorkerImageRepository(imageRepository);
  if (!String(outDir ?? '').trim()) throw new Error('Kubernetes worker render requires --out-dir.');
  const resolvedSource = path.resolve(sourceDir);
  const resolvedOut = path.resolve(outDir);
  if (resolvedOut === resolvedSource) {
    throw new Error('Kubernetes worker manifests must be rendered out-of-tree.');
  }

  validateKubernetesWorkerManifestSources(resolvedSource);
  mkdirSync(resolvedOut, { recursive: true });
  for (const name of KUBERNETES_WORKER_RELEASE_MANIFESTS) {
    const rendered = readUtf8(path.join(resolvedSource, name))
      .replaceAll(KUBERNETES_WORKER_IMAGE_REPOSITORY_PLACEHOLDER, exactRepository)
      .replaceAll(KUBERNETES_WORKER_DIGEST_PLACEHOLDER, exactDigest);
    writeFileSync(path.join(resolvedOut, name), rendered, { encoding: 'utf8', mode: 0o600 });
  }
  writeFileSync(
    path.join(resolvedOut, 'kustomization.yaml'),
    readUtf8(path.join(resolvedSource, 'kustomization.yaml')),
    { encoding: 'utf8', mode: 0o600 },
  );
  return validateRenderedKubernetesWorkerManifests(
    resolvedOut,
    exactDigest,
    exactRepository,
  );
}

function parseArgs(argv) {
  const parsed = {
    checkSource: false,
    digest: null,
    imageRepository: null,
    outDir: null,
    validateDir: null,
  };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--check-source') {
      parsed.checkSource = true;
      continue;
    }
    if (['--digest', '--image-repository', '--out-dir', '--validate-dir'].includes(arg)) {
      const value = argv[i + 1];
      if (!value || value.startsWith('--')) throw new Error(`${arg} requires a value.`);
      if (arg === '--digest') parsed.digest = value;
      if (arg === '--image-repository') parsed.imageRepository = value;
      if (arg === '--out-dir') parsed.outDir = value;
      if (arg === '--validate-dir') parsed.validateDir = value;
      i += 1;
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }
  return parsed;
}

function resolveRenderImageRepository(explicitRepository, env) {
  if (explicitRepository) return assertKubernetesWorkerImageRepository(explicitRepository);
  if (env.GITHUB_ACTIONS === 'true' && env.GITHUB_REPOSITORY_OWNER) {
    return deriveKubernetesWorkerImageRepository(env.GITHUB_REPOSITORY_OWNER);
  }
  throw new Error(
    'Kubernetes worker rendering requires --image-repository; the digest-only compatibility path is limited to GitHub Actions with GITHUB_REPOSITORY_OWNER.',
  );
}

export function main(argv = process.argv, env = process.env) {
  const args = parseArgs(argv);
  const renders = Boolean(args.digest || args.outDir);
  if (!args.checkSource && !renders && !args.validateDir) {
    throw new Error('Use --check-source, --digest with --image-repository and --out-dir, or --validate-dir.');
  }
  if (args.imageRepository && !renders && !args.validateDir) {
    throw new Error('--image-repository is valid only with rendering or --validate-dir.');
  }
  if (args.checkSource) validateKubernetesWorkerManifestSources();
  let result = null;
  let imageRepository = args.imageRepository;
  if (renders) {
    if (!args.digest || !args.outDir) throw new Error('--digest and --out-dir must be provided together.');
    imageRepository = resolveRenderImageRepository(imageRepository, env);
    result = renderKubernetesWorkerManifests({
      digest: args.digest,
      imageRepository,
      outDir: args.outDir,
    });
  }
  if (args.validateDir) {
    result = validateRenderedKubernetesWorkerManifests(
      args.validateDir,
      null,
      imageRepository,
    );
  }
  console.log(`kubernetes-worker-manifests: ok${result?.image ? ` (${result.image})` : ''}`);
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
