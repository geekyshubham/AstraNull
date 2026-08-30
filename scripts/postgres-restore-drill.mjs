#!/usr/bin/env node
import crypto from 'node:crypto';
import { createReadStream, createWriteStream, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { open, readFile, rm, stat } from 'node:fs/promises';
import { Readable, Transform, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';
import { redactObject } from '../src/lib/redact.mjs';
import {
  ARTIFACT_TYPE,
  BACKUP_AUTH_TAG_BYTES,
  BACKUP_ENCRYPTION_ALGORITHM,
  BACKUP_ENVELOPE_VERSION,
  BACKUP_STREAM_HEADER_BYTES,
  BACKUP_STREAM_MAGIC,
  LEGACY_BACKUP_ENVELOPE_VERSION,
  loadBackupEncryptionKey,
  serializeBackupAad,
  validatePostgresBackupManifestFields,
} from './postgres-backup.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SHA256_HEX_RE = /^[a-fA-F0-9]{64}$/;
const PG_CUSTOM_DUMP_MAGIC = Buffer.from('PGDMP', 'ascii');
const DEFAULT_OUT = 'output/postgres-restore-drill-manifest.json';

export const POSTGRES_RESTORE_DRILL_REQUIRED_FIELDS = Object.freeze([
  'drill_id',
  'environment',
  'started_at',
  'completed_at',
  'backup_manifest',
  'restore_target',
  'verification',
  'operator_signoff',
]);

const FORBIDDEN_DRILL_KEYS = new Set([
  'auth_tag',
  'authorization',
  'body',
  'ciphertext',
  'connection_string',
  'credential',
  'customer_payload',
  'database_dump',
  'database_url',
  'dump',
  'dump_contents',
  'encryption_key',
  'headers',
  'iv',
  'log',
  'logs',
  'password',
  'payload',
  'pg_dump',
  'raw_body',
  'raw_dump',
  'raw_headers',
  'raw_log',
  'secret',
  'sql_dump',
  'token',
]);

const PG_URL_RE = /postgres(?:ql)?:\/\/[^\s'"]+/gi;

function normalizeKey(key) {
  return key
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  if (Array.isArray(value) && value.length === 0) return false;
  return true;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * @param {unknown} value
 * @param {string} [fieldPath]
 */
export function collectDrillForbiddenFields(value, fieldPath = '') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return [];
  }
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectDrillForbiddenFields(entry, `${fieldPath}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = fieldPath ? `${fieldPath}.${key}` : key;
    const normalized = normalizeKey(key);
    if (
      FORBIDDEN_DRILL_KEYS.has(normalized)
      || normalized.startsWith('raw_')
      || normalized.endsWith('_dump')
      || normalized.includes('customer_payload')
    ) {
      findings.push(keyPath);
    }
    findings.push(...collectDrillForbiddenFields(nested, keyPath));
  }
  return findings;
}

function collectForbiddenStringPatterns(value, fieldPath = '') {
  if (value === null || value === undefined) return [];
  if (typeof value === 'string') {
    const findings = [];
    if (PG_URL_RE.test(value)) {
      PG_URL_RE.lastIndex = 0;
      findings.push(`${fieldPath}:database_url_pattern`);
    }
    return findings;
  }
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) =>
      collectForbiddenStringPatterns(entry, `${fieldPath}[${index}]`),
    );
  }
  if (typeof value === 'object') {
    return Object.entries(value).flatMap(([key, nested]) =>
      collectForbiddenStringPatterns(nested, fieldPath ? `${fieldPath}.${key}` : key),
    );
  }
  return [];
}

const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_LEGACY_METADATA_BYTES = 64 * 1024;
const LEGACY_CIPHERTEXT_MARKER = Buffer.from('"ciphertext":"', 'ascii');

async function readManifest(manifestPath) {
  if (!existsSync(manifestPath)) {
    throw new Error(`postgres-restore-drill: manifest not found: ${manifestPath}`);
  }
  let parsed;
  try {
    const metadata = await stat(manifestPath);
    if (!metadata.isFile() || metadata.size > MAX_MANIFEST_BYTES) {
      throw new Error('manifest size is invalid');
    }
    parsed = JSON.parse(await readFile(manifestPath, 'utf8'));
  } catch {
    throw new Error(`postgres-restore-drill: manifest is not valid JSON: ${manifestPath}`);
  }
  validatePostgresBackupManifestFields(parsed);
  return parsed;
}

/** @param {Buffer} plaintext */
export function assertPgCustomDumpFormat(plaintext) {
  if (plaintext.length < PG_CUSTOM_DUMP_MAGIC.length) {
    throw new Error('postgres-restore-drill: decrypted backup is too small to be a pg_dump custom archive');
  }
  if (!plaintext.subarray(0, PG_CUSTOM_DUMP_MAGIC.length).equals(PG_CUSTOM_DUMP_MAGIC)) {
    throw new Error('postgres-restore-drill: decrypted backup does not look like a pg_dump custom archive');
  }
}

async function hashBackupFile(backupPath) {
  const hash = crypto.createHash('sha256');
  let bytes = 0;
  let chunks = 0;
  for await (const rawChunk of createReadStream(backupPath)) {
    const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
    hash.update(chunk);
    bytes += chunk.length;
    chunks += 1;
  }
  return { sha256: hash.digest('hex'), bytes, chunks };
}

async function readExactRange(backupPath, position, length) {
  const handle = await open(backupPath, 'r');
  try {
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buffer, 0, length, position);
    if (bytesRead !== length) {
      throw new Error('postgres-restore-drill: encrypted backup is truncated');
    }
    return buffer;
  } finally {
    await handle.close();
  }
}

function createPlaintextTracker() {
  const hash = crypto.createHash('sha256');
  let bytes = 0;
  let chunks = 0;
  let prefix = Buffer.alloc(0);
  const transform = new Transform({
    transform(chunk, _encoding, callback) {
      const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      hash.update(value);
      bytes += value.length;
      chunks += 1;
      if (prefix.length < PG_CUSTOM_DUMP_MAGIC.length) {
        const needed = PG_CUSTOM_DUMP_MAGIC.length - prefix.length;
        prefix = Buffer.concat([prefix, value.subarray(0, needed)]);
      }
      callback(null, value);
    },
  });
  return {
    transform,
    finish() {
      assertPgCustomDumpFormat(prefix);
      return { sha256: hash.digest('hex'), bytes, chunks };
    },
  };
}

async function decryptToDestination({ source, decipher, extractPath, expectedSha256 }) {
  const tracker = createPlaintextTracker();
  const extractedTo = extractPath ? path.resolve(extractPath) : null;
  let openedExtraction = false;
  let destination;
  if (extractedTo) {
    mkdirSync(path.dirname(extractedTo), { recursive: true, mode: 0o700 });
    destination = createWriteStream(extractedTo, { flags: 'wx', mode: 0o600 });
    destination.once('open', () => { openedExtraction = true; });
  } else {
    destination = new Writable({ write(_chunk, _encoding, callback) { callback(); } });
  }

  try {
    await pipeline(source, decipher, tracker.transform, destination);
    const plaintext = tracker.finish();
    if (expectedSha256 && plaintext.sha256 !== expectedSha256) {
      const error = new Error(
        `postgres-restore-drill: plaintext checksum mismatch (expected ${expectedSha256}, got ${plaintext.sha256})`,
      );
      error.code = 'PLAINTEXT_CHECKSUM_MISMATCH';
      throw error;
    }
    if (extractedTo) {
      const handle = await open(extractedTo, 'r');
      try { await handle.sync(); } finally { await handle.close(); }
    }
    return { ...plaintext, extractedTo };
  } catch (error) {
    if (openedExtraction) await rm(extractedTo, { force: true });
    throw error;
  }
}

async function locateLegacyEnvelope(backupPath) {
  let beforeMarker = Buffer.alloc(0);
  let prefix = null;
  const suffix = [];
  let suffixBytes = 0;
  let ciphertextStart = null;
  let ciphertextEnd = null;
  let offset = 0;

  const appendSuffix = (chunk) => {
    if (chunk.length === 0) return;
    suffixBytes += chunk.length;
    if (suffixBytes > MAX_LEGACY_METADATA_BYTES) {
      throw new Error('postgres-restore-drill: legacy backup metadata exceeds the bounded limit');
    }
    suffix.push(Buffer.from(chunk));
  };

  for await (const rawChunk of createReadStream(backupPath)) {
    const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
    if (ciphertextStart === null) {
      const combined = Buffer.concat([beforeMarker, chunk]);
      const markerIndex = combined.indexOf(LEGACY_CIPHERTEXT_MARKER);
      if (markerIndex < 0) {
        if (combined.length > MAX_LEGACY_METADATA_BYTES) {
          throw new Error('postgres-restore-drill: legacy backup envelope header exceeds the bounded limit');
        }
        beforeMarker = combined;
      } else {
        const localStart = markerIndex + LEGACY_CIPHERTEXT_MARKER.length;
        prefix = Buffer.from(combined.subarray(0, localStart));
        ciphertextStart = localStart;
        const quoteIndex = combined.indexOf(0x22, localStart);
        if (quoteIndex >= 0) {
          ciphertextEnd = quoteIndex;
          appendSuffix(combined.subarray(quoteIndex));
        }
        beforeMarker = Buffer.alloc(0);
      }
    } else if (ciphertextEnd === null) {
      const quoteIndex = chunk.indexOf(0x22);
      if (quoteIndex >= 0) {
        ciphertextEnd = offset + quoteIndex;
        appendSuffix(chunk.subarray(quoteIndex));
      }
    } else {
      appendSuffix(chunk);
    }
    offset += chunk.length;
  }

  if (prefix === null || ciphertextStart === null || ciphertextEnd === null) {
    throw new Error('postgres-restore-drill: backup envelope is not valid legacy JSON');
  }
  let envelope;
  try {
    envelope = JSON.parse(Buffer.concat([prefix, ...suffix]).toString('utf8'));
  } catch {
    throw new Error(`postgres-restore-drill: backup envelope is not valid JSON: ${backupPath}`);
  }
  if (
    envelope.version !== LEGACY_BACKUP_ENVELOPE_VERSION
    || envelope.algorithm !== BACKUP_ENCRYPTION_ALGORITHM
    || typeof envelope.iv !== 'string'
    || typeof envelope.auth_tag !== 'string'
  ) {
    throw new Error('postgres-restore-drill: unsupported or invalid legacy backup envelope');
  }
  return { envelope, ciphertextStart, ciphertextEnd };
}

async function* decodeLegacyBase64Range(backupPath, start, endExclusive) {
  let carry = '';
  let sawPadding = false;
  for await (const rawChunk of createReadStream(backupPath, {
    start,
    end: endExclusive - 1,
  })) {
    const text = carry + Buffer.from(rawChunk).toString('ascii');
    if (!/^[A-Za-z0-9+/=]*$/.test(text)) {
      throw new Error('postgres-restore-drill: legacy ciphertext is not valid base64');
    }
    const readyLength = text.length - (text.length % 4);
    const ready = text.slice(0, readyLength);
    carry = text.slice(readyLength);
    if (ready) {
      if (sawPadding || !/^[A-Za-z0-9+/]*={0,2}$/.test(ready)) {
        throw new Error('postgres-restore-drill: legacy ciphertext has invalid base64 padding');
      }
      sawPadding = ready.includes('=');
      const decoded = Buffer.from(ready, 'base64');
      if (decoded.length > 0) yield decoded;
    }
  }
  if (carry.length === 1 || !/^[A-Za-z0-9+/]*={0,2}$/.test(carry)) {
    throw new Error('postgres-restore-drill: legacy ciphertext is truncated base64');
  }
  if (carry) yield Buffer.from(carry, 'base64');
}

async function decryptV2Backup({ backupPath, backupBytes, encryptionKey, aad, extractPath, expectedSha256 }) {
  if (backupBytes < BACKUP_STREAM_HEADER_BYTES + BACKUP_AUTH_TAG_BYTES + PG_CUSTOM_DUMP_MAGIC.length) {
    throw new Error('postgres-restore-drill: streamed backup is too small');
  }
  const header = await readExactRange(backupPath, 0, BACKUP_STREAM_HEADER_BYTES);
  if (!header.subarray(0, BACKUP_STREAM_MAGIC.length).equals(BACKUP_STREAM_MAGIC)) {
    throw new Error('postgres-restore-drill: streamed backup header is invalid');
  }
  const authTag = await readExactRange(
    backupPath,
    backupBytes - BACKUP_AUTH_TAG_BYTES,
    BACKUP_AUTH_TAG_BYTES,
  );
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    encryptionKey,
    header.subarray(BACKUP_STREAM_MAGIC.length),
  );
  decipher.setAAD(serializeBackupAad(aad));
  decipher.setAuthTag(authTag);
  return decryptToDestination({
    source: createReadStream(backupPath, {
      start: BACKUP_STREAM_HEADER_BYTES,
      end: backupBytes - BACKUP_AUTH_TAG_BYTES - 1,
    }),
    decipher,
    extractPath,
    expectedSha256,
  });
}

async function decryptLegacyBackup({ backupPath, encryptionKey, aad, extractPath, expectedSha256 }) {
  const { envelope, ciphertextStart, ciphertextEnd } = await locateLegacyEnvelope(backupPath);
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    encryptionKey,
    Buffer.from(envelope.iv, 'base64'),
  );
  decipher.setAAD(serializeBackupAad(aad));
  decipher.setAuthTag(Buffer.from(envelope.auth_tag, 'base64'));
  return decryptToDestination({
    source: Readable.from(decodeLegacyBase64Range(backupPath, ciphertextStart, ciphertextEnd)),
    decipher,
    extractPath,
    expectedSha256,
  });
}

/**
 * @param {{
 *   manifestPath: string,
 *   backupPath?: string | null,
 *   encryptionKey: Buffer,
 *   extractPath?: string | null,
 * }} options
 */
export async function verifyEncryptedPostgresBackup(options) {
  const { manifestPath, encryptionKey } = options;
  if (!encryptionKey || encryptionKey.length !== 32) {
    throw new Error('postgres-restore-drill: backup encryption key must be 32 bytes');
  }
  const manifest = await readManifest(manifestPath);
  const manifestDir = path.dirname(manifestPath);
  const backupPath = options.backupPath ?? path.join(manifestDir, manifest.backup_file);
  if (!existsSync(backupPath)) {
    throw new Error(`postgres-restore-drill: backup not found: ${backupPath}`);
  }

  const encrypted = await hashBackupFile(backupPath);
  if (encrypted.bytes !== manifest.bytes) {
    throw new Error(
      `postgres-restore-drill: manifest bytes (${manifest.bytes}) does not match backup length (${encrypted.bytes})`,
    );
  }
  if (encrypted.sha256 !== manifest.sha256) {
    const error = new Error(
      `postgres-restore-drill: checksum mismatch (expected ${manifest.sha256}, got ${encrypted.sha256})`,
    );
    error.code = 'CHECKSUM_MISMATCH';
    throw error;
  }

  const aad = {
    artifact_type: ARTIFACT_TYPE,
    backup_file: manifest.backup_file,
    created_at: manifest.created_at,
    database_reference: manifest.database_reference,
  };
  const envelopeVersion = manifest.encryption.envelope_version ?? LEGACY_BACKUP_ENVELOPE_VERSION;
  const plaintext = envelopeVersion === BACKUP_ENVELOPE_VERSION
    ? await decryptV2Backup({
        backupPath,
        backupBytes: encrypted.bytes,
        encryptionKey,
        aad,
        extractPath: options.extractPath ?? null,
        expectedSha256: manifest.plaintext_sha256,
      })
    : await decryptLegacyBackup({
        backupPath,
        encryptionKey,
        aad,
        extractPath: options.extractPath ?? null,
        expectedSha256: manifest.plaintext_sha256,
      });

  return {
    status: 'verified',
    manifestPath,
    backupPath,
    sha256: encrypted.sha256,
    plaintext_sha256: plaintext.sha256,
    plaintext_bytes: plaintext.bytes,
    database_reference: manifest.database_reference,
    encryption_algorithm: BACKUP_ENCRYPTION_ALGORITHM,
    envelope_version: envelopeVersion,
    extracted_to: plaintext.extractedTo,
    encrypted_chunks: encrypted.chunks,
    plaintext_chunks: plaintext.chunks,
  };
}

function validateBackupManifestReference(reference) {
  const missing = [];
  if (!isObject(reference)) {
    return ['backup_manifest'];
  }
  if (!hasValue(reference.manifest_uri)) missing.push('backup_manifest.manifest_uri');
  if (!hasValue(reference.sha256) || !SHA256_HEX_RE.test(String(reference.sha256))) {
    missing.push('backup_manifest.sha256');
  }
  if (!hasValue(reference.backup_reference)) missing.push('backup_manifest.backup_reference');
  return missing;
}

function validateRestoreTarget(target) {
  const missing = [];
  if (!isObject(target)) {
    return ['restore_target'];
  }
  if (!hasValue(target.cluster_reference)) missing.push('restore_target.cluster_reference');
  if (!hasValue(target.database_reference)) missing.push('restore_target.database_reference');
  if (!hasValue(target.restore_mode)) missing.push('restore_target.restore_mode');
  return missing;
}

function validateVerification(verification) {
  const missing = [];
  if (!isObject(verification)) {
    return { missing: ['verification'], missing_signoff: true };
  }
  if (!hasValue(verification.signoff_reference)) {
    missing.push('verification.signoff_reference');
  }
  const checks = verification.checks;
  if (!Array.isArray(checks) || checks.length === 0) {
    missing.push('verification.checks');
    return { missing, missing_signoff: !hasValue(verification.signoff_reference) };
  }
  checks.forEach((check, index) => {
    if (!isObject(check)) {
      missing.push(`verification.checks[${index}]`);
      return;
    }
    if (!hasValue(check.check_id)) missing.push(`verification.checks[${index}].check_id`);
    if (!hasValue(check.status) || !['passed', 'failed', 'skipped'].includes(check.status)) {
      missing.push(`verification.checks[${index}].status`);
    }
    if (!hasValue(check.evidence_uri)) {
      missing.push(`verification.checks[${index}].evidence_uri`);
    }
  });
  return {
    missing,
    missing_signoff: !hasValue(verification.signoff_reference),
  };
}

function validateOperatorSignoff(signoff) {
  const missing = [];
  if (!isObject(signoff)) {
    return { missing: ['operator_signoff'], missing_signoff: true };
  }
  for (const field of ['operator', 'role', 'signed_at', 'signoff_reference']) {
    if (!hasValue(signoff[field])) {
      missing.push(`operator_signoff.${field}`);
    }
  }
  return {
    missing,
    missing_signoff: !hasValue(signoff.signoff_reference),
  };
}

/**
 * @param {unknown} evidence
 */
export function validatePostgresRestoreDrillEvidence(evidence) {
  const missing_fields = POSTGRES_RESTORE_DRILL_REQUIRED_FIELDS.filter(
    (field) => !hasValue(evidence?.[field]),
  );
  const forbidden_fields = [
    ...new Set([
      ...collectDrillForbiddenFields(evidence),
      ...collectForbiddenStringPatterns(evidence),
    ]),
  ].sort();

  missing_fields.push(...validateBackupManifestReference(evidence?.backup_manifest));
  missing_fields.push(...validateRestoreTarget(evidence?.restore_target));

  const verification = validateVerification(evidence?.verification);
  missing_fields.push(...verification.missing);

  const signoff = validateOperatorSignoff(evidence?.operator_signoff);
  missing_fields.push(...signoff.missing);

  const uniqueMissing = [...new Set(missing_fields)].sort();
  const missing_signoff = verification.missing_signoff || signoff.missing_signoff;
  const ok =
    uniqueMissing.length === 0
    && forbidden_fields.length === 0
    && !missing_signoff;

  return {
    ok,
    missing_fields: uniqueMissing,
    forbidden_fields,
    missing_signoff,
  };
}

export function parsePostgresRestoreDrillArgs(argv = []) {
  const opts = {
    manifest: null,
    backup: null,
    input: null,
    out: DEFAULT_OUT,
    dryRun: false,
    validateOnly: false,
    extract: null,
    yes: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) {
        throw new Error(`postgres-restore-drill: missing value for ${arg}`);
      }
      return argv[i];
    };
    if (arg === '--manifest') opts.manifest = next();
    else if (arg === '--backup') opts.backup = next();
    else if (arg === '--input') opts.input = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--dry-run') opts.dryRun = true;
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--extract') opts.extract = next();
    else if (arg === '--yes') opts.yes = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`postgres-restore-drill: unknown argument ${arg}`);
  }

  if (!opts.help && !opts.manifest) {
    throw new Error('postgres-restore-drill: --manifest is required');
  }
  if (opts.extract && !opts.yes) {
    throw new Error('postgres-restore-drill: --extract requires --yes to confirm plaintext materialization');
  }
  if (opts.extract && (opts.dryRun || opts.validateOnly)) {
    throw new Error('postgres-restore-drill: --extract cannot be combined with --dry-run or --validate-only');
  }
  return opts;
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {{ manifest: string, backup: string | null, input: string | null, dryRun: boolean }} opts
 */
export function resolvePostgresRestoreDrillConfig(env, opts) {
  try {
    loadBackupEncryptionKey(env, { required: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, message: message.replace(/^postgres-backup:/, 'postgres-restore-drill:') };
  }
  return {
    ok: true,
    manifest: path.resolve(opts.manifest),
    backup: opts.backup ? path.resolve(opts.backup) : null,
    input: opts.input ? path.resolve(opts.input) : null,
    dryRun: opts.dryRun,
  };
}

async function readDrillEvidence(inputPath) {
  let parsed;
  try {
    const metadata = await stat(inputPath);
    if (!metadata.isFile() || metadata.size > MAX_MANIFEST_BYTES) {
      throw new Error('drill evidence size is invalid');
    }
    parsed = JSON.parse(await readFile(inputPath, 'utf8'));
  } catch {
    throw new Error(`postgres-restore-drill: input is not valid JSON: ${inputPath}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('postgres-restore-drill: input must be a JSON object');
  }
  return parsed;
}

/**
 * @param {{
 *   verification: ReturnType<typeof verifyEncryptedPostgresBackup>,
 *   drillValidation?: ReturnType<typeof validatePostgresRestoreDrillEvidence> | null,
 *   drillEvidence?: Record<string, unknown> | null,
 *   createdAt?: string,
 * }} input
 */
export function createPostgresRestoreDrillManifest(input) {
  const { verification, drillValidation, drillEvidence, createdAt } = input;
  const redactedEvidence = drillEvidence ? redactObject(drillEvidence) : null;
  return {
    schema_version: 1,
    artifact_type: 'postgres_restore_drill_manifest',
    created_at: createdAt ?? new Date().toISOString(),
    verification: {
      status: verification.status,
      manifest_path: verification.manifestPath,
      backup_path: verification.backupPath,
      sha256: verification.sha256,
      plaintext_sha256: verification.plaintext_sha256,
      plaintext_bytes: verification.plaintext_bytes,
      database_reference: verification.database_reference,
      encryption_algorithm: verification.encryption_algorithm,
    },
    drill_validation: drillValidation
      ? {
          ok: drillValidation.ok,
          missing_fields: drillValidation.missing_fields,
          forbidden_fields: drillValidation.forbidden_fields,
          missing_signoff: drillValidation.missing_signoff,
        }
      : null,
    drill_summary: redactedEvidence
      ? {
          drill_id: redactedEvidence.drill_id ?? null,
          environment: redactedEvidence.environment ?? null,
          restore_mode: redactedEvidence.restore_target?.restore_mode ?? null,
          backup_manifest_sha256: redactedEvidence.backup_manifest?.sha256 ?? null,
        }
      : null,
    caveats: [
      'Metadata-only Postgres restore drill manifest; no database dumps, secrets, tokens, logs, or customer payloads.',
      'Backup verification decrypts locally for integrity checks only; production restore still requires governed operator approval.',
    ],
  };
}

/**
 * @param {{
 *   env: NodeJS.ProcessEnv | Record<string, string | undefined>,
 *   manifest: string,
 *   backup: string | null,
 *   input: string | null,
 *   out: string | null,
 *   dryRun: boolean,
 *   validateOnly: boolean,
 *   extract?: string | null,
 *   yes?: boolean,
 * }} options
 */
export async function runPostgresRestoreDrill(options) {
  const config = resolvePostgresRestoreDrillConfig(options.env, {
    manifest: options.manifest,
    backup: options.backup,
    input: options.input,
    dryRun: options.dryRun,
  });
  if (!config.ok) {
    const err = new Error(config.message);
    err.code = 'CONFIG_INVALID';
    throw err;
  }

  const encryptionKey = loadBackupEncryptionKey(options.env, { required: true });
  const verification = await verifyEncryptedPostgresBackup({
    manifestPath: config.manifest,
    backupPath: config.backup,
    encryptionKey,
    extractPath: options.extract ?? null,
  });

  let drillValidation = null;
  let drillEvidence = null;
  if (config.input) {
    drillEvidence = await readDrillEvidence(config.input);
    drillValidation = validatePostgresRestoreDrillEvidence(drillEvidence);
    if (!drillValidation.ok) {
      const err = new Error('postgres-restore-drill: drill evidence validation failed');
      err.code = 'DRILL_EVIDENCE_INVALID';
      err.validation = drillValidation;
      throw err;
    }
  }

  const manifest = createPostgresRestoreDrillManifest({
    verification,
    drillValidation,
    drillEvidence,
  });

  if (!options.validateOnly && options.out) {
    mkdirSync(path.dirname(path.resolve(options.out)), { recursive: true });
    writeFileSync(options.out, `${JSON.stringify(manifest, null, 2)}\n`);
  }

  return {
    ok: true,
    dryRun: config.dryRun,
    verification,
    drillValidation,
    manifest,
    wrote: !options.validateOnly && Boolean(options.out),
    out: options.out,
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parsePostgresRestoreDrillArgs(argv);
  if (opts.help) {
    console.log(`Usage: node scripts/postgres-restore-drill.mjs --manifest <path> [--backup <path>] [--input drill.json] [--out manifest.json] [--dry-run] [--validate-only] [--extract dump.dump --yes]

Verifies encrypted Postgres backup integrity with bounded streaming (envelope authentication, checksums, and pg_dump custom header) and optional metadata-only restore drill evidence. --extract writes a new mode-0600 plaintext archive only with --yes and never overwrites an existing path.
Requires only ASTRANULL_BACKUP_ENCRYPTION_KEY; no database URL is accepted by this verification process.`);
    return 0;
  }

  try {
    const result = await runPostgresRestoreDrill({
      env: process.env,
      manifest: opts.manifest,
      backup: opts.backup,
      input: opts.input,
      out: opts.validateOnly ? null : opts.out,
      dryRun: opts.dryRun,
      validateOnly: opts.validateOnly,
      extract: opts.extract,
      yes: opts.yes,
    });

    console.log(`postgres-restore-drill: ${result.dryRun ? 'dry-run ok' : 'ok'}`);
    console.log(`  manifest: ${result.verification.manifestPath}`);
    console.log(`  backup: ${result.verification.backupPath}`);
    console.log(`  sha256: ${result.verification.sha256}`);
    console.log(`  plaintext_sha256: ${result.verification.plaintext_sha256}`);
    if (result.verification.extracted_to) {
      console.log(`  extracted: ${result.verification.extracted_to}`);
    }
    if (result.drillValidation) {
      console.log(`  drill_evidence: ok`);
    }
    if (result.wrote && result.out) {
      console.log(`  wrote: ${result.out}`);
    }
    return 0;
  } catch (err) {
    const message = redactDatabaseUrlInMessage(err, process.env);
    console.error(message);
    return 1;
  }
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(redactDatabaseUrlInMessage(err, process.env));
      process.exit(1);
    },
  );
}