#!/usr/bin/env node
/** Read-only, fail-closed promotion prerequisite validation; never generates approvals or deploys. */
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { aggregateProductionReadinessGapAudit } from './production-readiness-gap-audit.mjs';

const PROFILES = new Set(['full', 'safe-validation-ga', 'high-scale-ga']);
const SHA256 = /^[a-f0-9]{64}$/;
const CANDIDATE_SHA = /^[a-f0-9]{40}$/;
const IMAGE_DIGEST = /^sha256:[a-f0-9]{64}$/;

export function parseArgs(argv = []) {
  const opts = { profile: 'full', help: false };
  const flags = new Map([
    ['--profile', 'profile'], ['--release-id', 'releaseId'], ['--candidate-sha', 'candidateSha'],
    ['--image-digest', 'imageDigest'], ['--schema-digest', 'schemaDigest'],
    ['--evidence', 'evidence'], ['--manifest', 'manifest'],
    ['--evidence-digest', 'evidenceDigest'], ['--manifest-digest', 'manifestDigest'],
    // Kept for callers migrating from the old live-drill command. This verifier sends no requests.
    ['--base-url', 'baseUrl'],
  ]);
  const seen = new Set();
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') { opts.help = true; continue; }
    const key = flags.get(arg);
    if (!key) throw new Error(`Unknown argument: ${arg}`);
    if (seen.has(key)) throw new Error(`Duplicate argument: ${arg}`);
    seen.add(key);
    const value = argv[++i];
    if (!value || value.startsWith('--')) throw new Error(`Missing value for ${arg}`);
    opts[key] = value;
  }
  return opts;
}

function readPinnedJson(file, expectedDigest, label) {
  if (typeof file !== 'string' || !file.trim() || !SHA256.test(expectedDigest ?? '')) {
    throw new Error(`${label} path and exact SHA-256 digest are required`);
  }
  let fd, bytes;
  try {
    fd = openSync(file, constants.O_RDONLY | constants.O_NONBLOCK);
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw new Error(`${label} must be a regular file`);
    if (stat.size > 16 * 1024 * 1024) throw new Error(`${label} exceeds the 16 MiB input limit`);
    // Bound allocation before reading and detect growth without an unbounded readFile.
    const buffer = Buffer.alloc(stat.size + 1);
    let length = 0, count;
    while (length < buffer.length && (count = readSync(fd, buffer, length, buffer.length - length, null)) > 0) {
      length += count;
    }
    if (length !== stat.size || fstatSync(fd).size !== length) throw new Error(`${label} changed while reading`);
    bytes = buffer.subarray(0, length);
  } catch (error) {
    if (error.code) throw new Error(`${label} is unreadable`);
    throw error;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
  if (createHash('sha256').update(bytes).digest('hex') !== expectedDigest) throw new Error(`${label} digest mismatch`);
  let parsed;
  try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { throw new Error(`${label} must be valid UTF-8 JSON`); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(`${label} must be an object`);
  return parsed;
}

export function validatePromotionCandidateInputs(opts, bundle, manifest) {
  if (typeof opts.releaseId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(opts.releaseId)) {
    throw new Error('An explicit valid --release-id is required; historical releases are never selected');
  }
  if (!PROFILES.has(opts.profile ?? 'full')) throw new Error('Unsupported promotion profile');
  if (!CANDIDATE_SHA.test(opts.candidateSha ?? '') || !IMAGE_DIGEST.test(opts.imageDigest ?? '')
    || !SHA256.test(opts.schemaDigest ?? '')) throw new Error('Exact candidate SHA, image digest and schema SHA-256 are required');
  const binding = { candidate_sha: opts.candidateSha, image_digest: opts.imageDigest, schema_digest: opts.schemaDigest };
  for (const [label, input] of [['Evidence bundle', bundle], ['External verification manifest', manifest]]) {
    if (input.release_id !== opts.releaseId) throw new Error(`${label} release identity mismatch`);
    if (input.rehearsal_only === true || input.rehearsalOnly === true) throw new Error(`${label} is rehearsal-only`);
    if (Object.entries(binding).some(([key, value]) => input.candidate_binding?.[key] !== value)) {
      throw new Error(`${label} candidate binding mismatch`);
    }
  }
  if (!['staging', 'production'].includes(bundle.environment)) throw new Error('Evidence bundle must declare staging or production environment');
  if (!Array.isArray(bundle.records) || !bundle.records.length) throw new Error('Evidence bundle records are required');
  for (const record of bundle.records) {
    if (record?.release_id !== opts.releaseId) throw new Error('Mixed or missing evidence record release identity');
    if (record.status !== 'accepted' || record.rehearsal_only === true || record.evidence?.rehearsal_only === true
      || !['staging', 'production'].includes(record.evidence?.environment ?? record.environment ?? bundle.environment)) {
      throw new Error('Promotion requires accepted non-rehearsal operational records');
    }
  }
  return binding;
}

export async function runProductionPromotionAttest(opts = {}, deps = {}) {
  // Read both exact artifacts once. Never create a pending template, attach markers, close
  // documentation gates, collect fixture-derived signoffs, mutate env, or run live drills.
  const bundle = readPinnedJson(opts.evidence, opts.evidenceDigest, 'Evidence bundle');
  const manifest = readPinnedJson(opts.manifest, opts.manifestDigest, 'External verification manifest');
  const binding = validatePromotionCandidateInputs(opts, bundle, manifest);
  const aggregate = deps.aggregate ?? aggregateProductionReadinessGapAudit;
  const report = aggregate({ ...bundle, releaseId: opts.releaseId }, {
    profile: opts.profile ?? 'full', externalVerificationManifest: manifest,
  });
  if (report.release_id !== opts.releaseId || report.profile !== (opts.profile ?? 'full')) {
    throw new Error('Readiness report identity mismatch');
  }
  if (report.production_ready !== true || report.customer_production_ready !== true
    || report.external_verification?.complete !== true) {
    throw new Error('Promotion blocked: local inventory, documented gates and real external verification must all be complete');
  }
  return { ...report, candidate_binding: binding,
    input_digests: { evidence_sha256: opts.evidenceDigest, manifest_sha256: opts.manifestDigest },
    passive: true, executes_drills: false, grants_deployment: false,
    caveats: [...(report.caveats ?? []),
      'This read-only validator checks retained declarations and pinned input bytes. It does not authenticate a human approver, fetch retained artifacts, perform operational acceptance, or authorize deployment.'],
  };
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log('Usage: node scripts/production-promotion-attest.mjs --release-id ID --candidate-sha SHA --image-digest sha256:DIGEST --schema-digest SHA256 --evidence records.json --evidence-digest SHA256 --manifest external-verification.json --manifest-digest SHA256 [--profile full|safe-validation-ga|high-scale-ga]');
    return;
  }
  const report = await runProductionPromotionAttest(opts);
  console.log(`production-promotion-attest: prerequisites_valid=true release=${report.release_id} candidate=${report.candidate_binding.candidate_sha}; passive validation only, not deployment approval`);
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) main().catch((error) => {
  console.error(`production-promotion-attest: ${error.message}`);
  process.exitCode = 1;
});
