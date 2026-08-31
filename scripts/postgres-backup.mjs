#!/usr/bin/env node
import { spawn as defaultSpawn } from 'node:child_process';
import crypto from 'node:crypto';
import {
  closeSync,
  constants as fsConstants,
  createReadStream,
  createWriteStream,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import {
  lstat as lstatPath,
  open as openFile,
  readdir,
} from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');

export const MANIFEST_VERSION = 1;
export const ARTIFACT_TYPE = 'postgres_backup_manifest';
export const BACKUP_ENCRYPTION_ALGORITHM = 'AES-256-GCM';
export const LEGACY_BACKUP_ENVELOPE_VERSION = 1;
export const BACKUP_ENVELOPE_VERSION = 2;
export const BACKUP_STREAM_MAGIC = Buffer.from('ANPGBAK2', 'ascii');
export const BACKUP_STREAM_HEADER_BYTES = BACKUP_STREAM_MAGIC.length + 12;
export const BACKUP_AUTH_TAG_BYTES = 16;

const KEY_BYTES = 32;
const IV_BYTES = 12;
const SAFE_LABEL = /^[a-zA-Z0-9._-]{1,64}$/;
const SAFE_HOST = /^[A-Za-z0-9.-]{1,253}$/;
const SAFE_DATABASE = /^[A-Za-z0-9_-]{1,63}$/;
const SHA256_HEX_RE = /^[a-fA-F0-9]{64}$/;
const PG_CUSTOM_DUMP_MAGIC = Buffer.from('PGDMP', 'ascii');
const DEFAULT_STREAM_HIGH_WATER_MARK = 64 * 1024;
const MAX_PG_DUMP_STDERR_BYTES = 16 * 1024;
const CURRENT_BACKUP_ARTIFACT_RE = /^postgres-([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2})-([0-9]{2})-([0-9]{2})-([0-9]{3})Z-([0-9a-f]{12})\.dump\.enc$/;
const LEGACY_BACKUP_ARTIFACT_RE = /^postgres-([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2})-([0-9]{2})-([0-9]{2})-([0-9]{3})Z\.dump\.enc$/;
const BACKUP_IDENTITY_FIELDS = [
  'dev', 'ino', 'size', 'mtimeNs', 'ctimeNs', 'mode', 'uid', 'gid', 'nlink',
];
const MAX_BACKUP_INVENTORY_ARTIFACTS = 64;
const MAX_BACKUP_MANIFEST_BYTES = 65_536;
const BACKUP_READ_CHUNK_BYTES = 64 * 1024;

const MANIFEST_FORBIDDEN_KEYS = new Set([
  'auth_tag',
  'authorization',
  'ciphertext',
  'connection_string',
  'credential',
  'database_dump',
  'database_url',
  'dump',
  'dump_contents',
  'encryption_key',
  'iv',
  'password',
  'pg_dump',
  'raw_dump',
  'secret',
  'sql_dump',
  'token',
]);

export function sha256Hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function stableStringify(value) {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((entry) => (entry === undefined ? 'null' : stableStringify(entry))).join(',')}]`;
  }
  const keys = Object.keys(value).sort().filter((key) => value[key] !== undefined);
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
}

export function serializeBackupAad(aadObject) {
  return Buffer.from(stableStringify(aadObject ?? {}), 'utf8');
}

/** @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env */
export function resolveDatabaseUrl(env = process.env) {
  const databaseUrl = String(env.ASTRANULL_DATABASE_URL ?? env.DATABASE_URL ?? '').trim();
  if (!databaseUrl) {
    return {
      ok: false,
      message: 'postgres-backup: DATABASE_URL or ASTRANULL_DATABASE_URL must be set.',
    };
  }
  return { ok: true, databaseUrl };
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {{ required?: boolean }} [options]
 */
export function loadBackupEncryptionKey(env = process.env, { required = true } = {}) {
  const raw = String(env.ASTRANULL_BACKUP_ENCRYPTION_KEY ?? '').trim();
  if (!raw) {
    if (required) {
      throw new Error(
        'postgres-backup: ASTRANULL_BACKUP_ENCRYPTION_KEY must be set for encrypted backups.',
      );
    }
    return null;
  }

  const key = /^[0-9a-fA-F]{64}$/.test(raw) ? Buffer.from(raw, 'hex') : Buffer.from(raw, 'base64');
  if (key.length !== KEY_BYTES) {
    throw new Error(
      'postgres-backup: ASTRANULL_BACKUP_ENCRYPTION_KEY must be a 32-byte key encoded as base64 or 64-character hex.',
    );
  }
  return key;
}

/** @param {string} databaseUrl */
export function parseDatabaseReference(databaseUrl) {
  let parsed;
  try {
    parsed = new URL(databaseUrl);
  } catch {
    throw new Error('postgres-backup: database URL is not a valid connection URI.');
  }
  if (!['postgresql:', 'postgres:'].includes(parsed.protocol)) {
    throw new Error('postgres-backup: database URL must use the postgresql:// scheme.');
  }
  return {
    host: parsed.hostname || 'localhost',
    port: parsed.port ? Number(parsed.port) : 5432,
    database: decodeURIComponent(parsed.pathname.replace(/^\//, '') || 'postgres'),
  };
}

function normalizeManifestKey(key) {
  return key
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

/** @param {unknown} value @param {string} [fieldPath] */
export function collectManifestForbiddenFields(value, fieldPath = '') {
  if (value === null || value === undefined || typeof value !== 'object') return [];
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectManifestForbiddenFields(entry, `${fieldPath}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = fieldPath ? `${fieldPath}.${key}` : key;
    const normalized = normalizeManifestKey(key);
    if (
      MANIFEST_FORBIDDEN_KEYS.has(normalized)
      || normalized.startsWith('raw_')
      || normalized.endsWith('_dump')
      || normalized.includes('database_url')
    ) {
      findings.push(keyPath);
    }
    findings.push(...collectManifestForbiddenFields(nested, keyPath));
  }
  return findings;
}

/** @param {RegExpExecArray | null} match */
function hasValidBackupTimestamp(match) {
  if (!match) return false;
  const [year, month, day, hour, minute, second, millisecond] = match
    .slice(1, 8)
    .map((component) => Number(component));
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12
    || day < 1 || day > daysInMonth[month - 1]
    || hour < 0 || hour > 23
    || minute < 0 || minute > 59
    || second < 0 || second > 59
    || millisecond < 0 || millisecond > 999) return false;

  const isoTimestamp = `${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}.${match[7]}Z`;
  const roundTrip = new Date(isoTimestamp);
  return Number.isFinite(roundTrip.getTime()) && roundTrip.toISOString() === isoTimestamp;
}

/** @param {unknown} name @returns {'current' | 'legacy' | 'unknown'} */
export function classifyPostgresBackupArtifactName(name) {
  if (typeof name !== 'string') return 'unknown';
  const currentMatch = CURRENT_BACKUP_ARTIFACT_RE.exec(name);
  if (currentMatch?.[0] === name && hasValidBackupTimestamp(currentMatch)) return 'current';
  const legacyMatch = LEGACY_BACKUP_ARTIFACT_RE.exec(name);
  if (legacyMatch?.[0] === name && hasValidBackupTimestamp(legacyMatch)) return 'legacy';
  return 'unknown';
}

function backupIdentityFromStat(stat) {
  return Object.fromEntries(BACKUP_IDENTITY_FIELDS.map((field) => [field, stat[field]]));
}

function backupIdentityEquals(left, right) {
  return BACKUP_IDENTITY_FIELDS.every((field) => left[field] === right[field]);
}

function assertSafeBackupStat(stat, label, { manifest = false } = {}) {
  if (!stat.isFile() || stat.nlink !== 1n) {
    throw new Error(`unsafe backup ${label}: expected a singly linked regular file`);
  }
  if (manifest && (stat.size < 1n || stat.size > BigInt(MAX_BACKUP_MANIFEST_BYTES))) {
    throw new Error(`unsafe backup ${label}: manifest size is outside the bounded range`);
  }
}

function assertExactBackupIdentity(actualStat, expectedIdentity, label, options) {
  assertSafeBackupStat(actualStat, label, options);
  const actualIdentity = backupIdentityFromStat(actualStat);
  if (!backupIdentityEquals(actualIdentity, expectedIdentity)) {
    throw new Error(`backup ${label} identity changed`);
  }
}

function noFollowReadFlags() {
  if (!Number.isInteger(fsConstants.O_NOFOLLOW)) {
    throw new Error('backup inventory requires O_NOFOLLOW support');
  }
  return fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW;
}

async function closeBackupHandles(handles) {
  let firstError;
  for (const handle of handles.reverse()) {
    if (!handle) continue;
    try {
      await handle.close();
    } catch (error) {
      firstError ??= error;
    }
  }
  if (firstError) throw firstError;
}

async function readBoundedBackupHandle(handle, maximumBytes, label) {
  const chunks = [];
  let position = 0;
  while (position <= maximumBytes) {
    const available = maximumBytes + 1 - position;
    const buffer = Buffer.allocUnsafe(Math.min(BACKUP_READ_CHUNK_BYTES, available));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
    if (bytesRead === 0) return Buffer.concat(chunks, position);
    position += bytesRead;
    if (position > maximumBytes) throw new Error(`backup ${label} exceeded its bounded size while reading`);
    chunks.push(buffer.subarray(0, bytesRead));
  }
  throw new Error(`backup ${label} exceeded its bounded size while reading`);
}

async function hashBackupHandle(handle, expectedBytes, checkpoint, context) {
  if (expectedBytes < 0n || expectedBytes > BigInt(Number.MAX_SAFE_INTEGER - 1)) {
    throw new Error(`backup artifact is too large for exact manifest size validation: ${context.name}`);
  }
  const maximumBytes = Number(expectedBytes) + 1;
  const hash = crypto.createHash('sha256');
  let position = 0;
  let checkpointCalled = false;
  while (position <= maximumBytes) {
    const available = maximumBytes + 1 - position;
    const buffer = Buffer.allocUnsafe(Math.min(BACKUP_READ_CHUNK_BYTES, available));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
    if (bytesRead === 0) break;
    position += bytesRead;
    if (position > maximumBytes) {
      throw new Error(`backup artifact changed size while hashing: ${context.name}`);
    }
    hash.update(buffer.subarray(0, bytesRead));
    if (!checkpointCalled) {
      checkpointCalled = true;
      await checkpoint('artifact_hash_chunk', context);
    }
  }
  if (BigInt(position) !== expectedBytes) {
    throw new Error(`backup artifact changed size while hashing: ${context.name}`);
  }
  return hash.digest('hex');
}

async function inspectCurrentBackupPair(root, name, checkpoint) {
  const artifactPath = path.join(root, name);
  const manifestPath = `${artifactPath}.manifest.json`;
  const context = { name, artifactPath, manifestPath };
  let artifactHandle;
  let manifestHandle;
  try {
    artifactHandle = await openFile(artifactPath, noFollowReadFlags());
    manifestHandle = await openFile(manifestPath, noFollowReadFlags());
    const artifactBefore = await artifactHandle.stat({ bigint: true });
    const manifestBefore = await manifestHandle.stat({ bigint: true });
    assertSafeBackupStat(artifactBefore, `artifact ${name}`);
    assertSafeBackupStat(manifestBefore, `manifest ${name}`, { manifest: true });
    const artifactIdentity = backupIdentityFromStat(artifactBefore);
    const manifestIdentity = backupIdentityFromStat(manifestBefore);

    await checkpoint('pair_handles_opened', context);
    const manifestBytes = await readBoundedBackupHandle(
      manifestHandle,
      MAX_BACKUP_MANIFEST_BYTES,
      `manifest ${name}`,
    );
    const manifestAfterRead = await manifestHandle.stat({ bigint: true });
    assertExactBackupIdentity(
      manifestAfterRead,
      manifestIdentity,
      `manifest ${name} during read`,
      { manifest: true },
    );

    const manifest = JSON.parse(manifestBytes.toString('utf8'));
    validatePostgresBackupManifestFields(manifest);
    if (!Number.isSafeInteger(manifest.bytes)
      || manifest.backup_file !== name
      || BigInt(manifest.bytes) !== artifactBefore.size) {
      throw new Error(`backup manifest identity/size mismatch: ${name}`);
    }

    const encryptedSha256 = await hashBackupHandle(
      artifactHandle,
      artifactBefore.size,
      checkpoint,
      context,
    );
    const artifactAfterRead = await artifactHandle.stat({ bigint: true });
    const manifestAfterArtifactRead = await manifestHandle.stat({ bigint: true });
    assertExactBackupIdentity(
      artifactAfterRead,
      artifactIdentity,
      `artifact ${name} during hash`,
    );
    assertExactBackupIdentity(
      manifestAfterArtifactRead,
      manifestIdentity,
      `manifest ${name} during artifact hash`,
      { manifest: true },
    );
    if (encryptedSha256 !== manifest.sha256) {
      throw new Error(`backup encrypted digest mismatch: ${name}`);
    }

    await checkpoint('before_final_path_check', context);
    const artifactAtPath = await lstatPath(artifactPath, { bigint: true });
    const manifestAtPath = await lstatPath(manifestPath, { bigint: true });
    assertExactBackupIdentity(artifactAtPath, artifactIdentity, `artifact path ${name}`);
    assertExactBackupIdentity(
      manifestAtPath,
      manifestIdentity,
      `manifest path ${name}`,
      { manifest: true },
    );
    return { name, artifactIdentity, manifestIdentity };
  } finally {
    await closeBackupHandles([artifactHandle, manifestHandle]);
  }
}

function serializeBackupIdentity(identity) {
  return BACKUP_IDENTITY_FIELDS.map((field) => identity[field].toString());
}

function serializeBackupIdentityRecord({ name, artifactIdentity, manifestIdentity }) {
  return [
    name,
    ...serializeBackupIdentity(artifactIdentity),
    ...serializeBackupIdentity(manifestIdentity),
  ].join('\t');
}

function parseCanonicalIdentityInteger(value, { signed = false } = {}) {
  const pattern = signed ? /^(?:0|-[1-9][0-9]*|[1-9][0-9]*)$/ : /^(?:0|[1-9][0-9]*)$/;
  if (!pattern.test(value)) throw new Error('backup identity record contains a non-canonical integer');
  return BigInt(value);
}

/** Parse a line-safe current-backup identity record emitted by secure inventory. */
export function parsePostgresBackupIdentityRecord(record) {
  if (typeof record !== 'string' || record.length === 0 || record.length > 2048
    || record.includes('\n') || record.includes('\r')) {
    throw new Error('backup identity record must be one bounded line');
  }
  const fields = record.split('\t');
  if (fields.length !== 1 + (BACKUP_IDENTITY_FIELDS.length * 2)
    || classifyPostgresBackupArtifactName(fields[0]) !== 'current') {
    throw new Error('backup identity record has an unsafe artifact name or field count');
  }
  const parseIdentity = (offset) => Object.fromEntries(BACKUP_IDENTITY_FIELDS.map((field, index) => [
    field,
    parseCanonicalIdentityInteger(fields[offset + index], {
      signed: field === 'mtimeNs' || field === 'ctimeNs',
    }),
  ]));
  const parsed = {
    name: fields[0],
    artifactIdentity: parseIdentity(1),
    manifestIdentity: parseIdentity(1 + BACKUP_IDENTITY_FIELDS.length),
  };
  if (parsed.artifactIdentity.nlink !== 1n || parsed.manifestIdentity.nlink !== 1n) {
    throw new Error('backup identity record must describe singly linked files');
  }
  return parsed;
}

/**
 * Inventory only exact current backup pairs. Every byte is read through O_NOFOLLOW
 * handles and the handle/path identities must remain exact through final lstat.
 */
export async function inventoryPostgresBackupArtifacts(root, options = {}) {
  const checkpoint = options.checkpoint ?? (async () => {});
  const artifacts = (await readdir(root))
    .filter((name) => name.endsWith('.dump.enc'))
    .sort();
  if (artifacts.length > MAX_BACKUP_INVENTORY_ARTIFACTS) {
    throw new Error(`backup inventory exceeds bounded maximum ${MAX_BACKUP_INVENTORY_ARTIFACTS}`);
  }
  const validated = [];
  for (const name of artifacts) {
    const classification = classifyPostgresBackupArtifactName(name);
    if (classification === 'legacy') continue;
    if (classification !== 'current') {
      throw new Error(`unsafe backup artifact name: ${JSON.stringify(name)}`);
    }
    validated.push(serializeBackupIdentityRecord(
      await inspectCurrentBackupPair(root, name, checkpoint),
    ));
  }
  return validated;
}

export const MAX_RETENTION_TOMBSTONE_DIRECTORIES = 4_096;
const POSTGRES_RETENTION_HELPER = path.join(__dirname, 'postgres-retention-helper.py');
const MAX_RETENTION_HELPER_STDERR_BYTES = 16 * 1024;

function retentionHelperError(message, code) {
  const error = new Error(message || 'postgres retention helper failed');
  if (typeof code === 'string' && code) error.code = code;
  return error;
}

/**
 * Node 22 exposes neither renameat2 nor openat/unlinkat. The production AWS host
 * already requires Python 3 for deploy locking, so retention runs the adjacent
 * stdlib-only helper there instead of adding a runtime dependency to node:22-alpine.
 * The helper uses directory-fd-anchored renameat2(RENAME_NOREPLACE) on Linux.
 *
 * Linux has no compare-and-unlink-by-inode primitive. The helper therefore
 * ftruncates only the two held O_NOFOLLOW descriptors after one pair-wide final
 * barrier and leaves bounded zero-byte tombstones rather than unlinking a raced
 * pathname. It fails before capture at MAX_RETENTION_TOMBSTONE_DIRECTORIES.
 */
async function runPostgresRetentionHelper(root, identityRecords, options) {
  const checkpoint = options.checkpoint ?? (async () => {});
  const spawnFn = options.spawnFn ?? defaultSpawn;
  const pythonCommand = options.pythonCommand ?? 'python3';
  const child = spawnFn(
    pythonCommand,
    [POSTGRES_RETENTION_HELPER, '--protocol'],
    { stdio: ['pipe', 'pipe', 'pipe'] },
  );
  if (!child?.stdin || !child?.stdout || !child?.stderr) {
    throw new Error('postgres retention helper did not expose protocol streams');
  }
  child.stdin.on('error', () => {});

  let stderr = '';
  child.stderr.on('data', (chunk) => {
    if (stderr.length >= MAX_RETENTION_HELPER_STDERR_BYTES) return;
    stderr += Buffer.from(chunk).toString('utf8')
      .slice(0, MAX_RETENTION_HELPER_STDERR_BYTES - stderr.length);
  });
  const completion = new Promise((resolve) => {
    let settled = false;
    const settle = (outcome) => {
      if (settled) return;
      settled = true;
      resolve(outcome);
    };
    child.once('error', (error) => settle({ error }));
    child.once('close', (code, signal) => settle({ code, signal }));
  });
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  let helperResult;
  let helperFailure;

  child.stdin.write(`${JSON.stringify({
    root: path.resolve(root),
    identityRecords,
    maxTombstoneDirectories: MAX_RETENTION_TOMBSTONE_DIRECTORIES,
  })}\n`);

  try {
    for await (const line of lines) {
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        throw new Error('postgres retention helper emitted invalid protocol JSON');
      }
      if (message?.type === 'checkpoint') {
        try {
          await checkpoint(message.step, message.context);
        } catch (error) {
          child.stdin.write('{"abort":true}\n');
          child.stdin.end();
          await completion;
          throw error;
        }
        child.stdin.write('{"continue":true}\n');
      } else if (message?.type === 'result') {
        helperResult = message;
      } else if (message?.type === 'error') {
        helperFailure = retentionHelperError(message.message, message.code);
      } else {
        throw new Error('postgres retention helper emitted an unknown protocol message');
      }
    }
  } catch (error) {
    if (!child.killed) child.kill('SIGKILL');
    await completion;
    throw error;
  }

  const outcome = await completion;
  if (helperFailure) throw helperFailure;
  if (outcome.error) throw outcome.error;
  if (outcome.code !== 0 || !helperResult?.ok) {
    const detail = stderr.trim();
    throw new Error(
      `postgres retention helper exited ${outcome.code ?? `signal ${outcome.signal ?? 'unknown'}`}`
      + (detail ? `: ${detail}` : ''),
    );
  }
  if (helperResult.maxTombstoneDirectories !== MAX_RETENTION_TOMBSTONE_DIRECTORIES) {
    throw new Error('postgres retention helper returned a mismatched tombstone bound');
  }
  return helperResult;
}

/**
 * Revalidate every identity, atomically capture completion-marker first, then
 * reclaim only held inodes. Production AWS invokes the same helper directly on
 * the host because the pinned Node Alpine release image intentionally has no
 * Python interpreter.
 */
export async function pruneInventoriedPostgresBackups(root, identityRecords, options = {}) {
  if (!Array.isArray(identityRecords) || identityRecords.length > MAX_BACKUP_INVENTORY_ARTIFACTS) {
    throw new Error('backup retention identity record set is invalid or unbounded');
  }
  const parsed = identityRecords.map(parsePostgresBackupIdentityRecord);
  if (new Set(parsed.map(({ name }) => name)).size !== parsed.length) {
    throw new Error('backup retention identity record set contains duplicate names');
  }
  return runPostgresRetentionHelper(root, identityRecords, options);
}

/** @param {unknown} name */
export function isSimpleBackupFilename(name) {
  if (typeof name !== 'string' || name.length === 0) return false;
  if (name.includes('..') || name.includes('/') || name.includes('\\')) return false;
  if (path.isAbsolute(name)) return false;
  return path.basename(name) === name;
}

/** @param {Record<string, unknown>} manifest */
export function validatePostgresBackupManifestFields(manifest) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new Error('postgres-backup: manifest must be a JSON object');
  }
  if (manifest.version !== MANIFEST_VERSION) {
    throw new Error(`postgres-backup: manifest version must be ${MANIFEST_VERSION}`);
  }
  if (manifest.artifact_type !== ARTIFACT_TYPE) {
    throw new Error(`postgres-backup: manifest artifact_type must be ${ARTIFACT_TYPE}`);
  }
  if (!isSimpleBackupFilename(manifest.backup_file)) {
    throw new Error(
      'postgres-backup: manifest backup_file must be a simple filename (no path separators or ..)',
    );
  }
  if (typeof manifest.sha256 !== 'string' || !SHA256_HEX_RE.test(manifest.sha256)) {
    throw new Error('postgres-backup: manifest sha256 must be a 64-character hex digest');
  }
  if (!Number.isInteger(manifest.bytes) || manifest.bytes < 0) {
    throw new Error('postgres-backup: manifest bytes must be a nonnegative integer');
  }
  if (
    manifest.plaintext_sha256 !== undefined
    && manifest.plaintext_sha256 !== null
    && (typeof manifest.plaintext_sha256 !== 'string' || !SHA256_HEX_RE.test(manifest.plaintext_sha256))
  ) {
    throw new Error('postgres-backup: manifest plaintext_sha256 must be a 64-character hex digest');
  }
  if (!manifest.database_reference || typeof manifest.database_reference !== 'object') {
    throw new Error('postgres-backup: manifest database_reference is required');
  }
  const ref = manifest.database_reference;
  if (typeof ref.host !== 'string' || !ref.host) {
    throw new Error('postgres-backup: manifest database_reference.host is required');
  }
  if (typeof ref.database !== 'string' || !ref.database) {
    throw new Error('postgres-backup: manifest database_reference.database is required');
  }
  if (!Number.isInteger(ref.port) || ref.port <= 0) {
    throw new Error('postgres-backup: manifest database_reference.port must be a positive integer');
  }
  if (!manifest.encryption || typeof manifest.encryption !== 'object') {
    throw new Error('postgres-backup: manifest encryption metadata is required');
  }
  if (manifest.encryption.algorithm !== BACKUP_ENCRYPTION_ALGORITHM) {
    throw new Error(`postgres-backup: manifest encryption.algorithm must be ${BACKUP_ENCRYPTION_ALGORITHM}`);
  }
  if (manifest.encryption.key_reference !== 'env:ASTRANULL_BACKUP_ENCRYPTION_KEY') {
    throw new Error(
      'postgres-backup: manifest encryption.key_reference must be env:ASTRANULL_BACKUP_ENCRYPTION_KEY',
    );
  }
  const envelopeVersion = manifest.encryption.envelope_version ?? LEGACY_BACKUP_ENVELOPE_VERSION;
  if (![LEGACY_BACKUP_ENVELOPE_VERSION, BACKUP_ENVELOPE_VERSION].includes(envelopeVersion)) {
    throw new Error('postgres-backup: manifest encryption.envelope_version is unsupported');
  }
  const forbidden = [...new Set(collectManifestForbiddenFields(manifest))].sort();
  if (forbidden.length > 0) {
    throw new Error(`postgres-backup: manifest contains forbidden fields: ${forbidden.join(', ')}`);
  }
}

/**
 * Legacy v1 compatibility helper. The production writer below never uses this
 * whole-buffer JSON/base64 representation.
 */
export function encryptBackupPayload(plaintext, key, aadObject) {
  if (!key || key.length !== KEY_BYTES) {
    throw new Error('postgres-backup: backup encryption key must be 32 bytes.');
  }
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(serializeBackupAad(aadObject));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    version: LEGACY_BACKUP_ENVELOPE_VERSION,
    algorithm: BACKUP_ENCRYPTION_ALGORITHM,
    iv: iv.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    auth_tag: cipher.getAuthTag().toString('base64'),
    created_at: new Date().toISOString(),
  };
}

/** Legacy v1 compatibility helper; production restore uses bounded streaming. */
export function decryptBackupPayload(envelope, key, aadObject) {
  if (
    !envelope
    || envelope.version !== LEGACY_BACKUP_ENVELOPE_VERSION
    || envelope.algorithm !== BACKUP_ENCRYPTION_ALGORITHM
  ) {
    throw new Error('postgres-backup: unsupported or invalid backup envelope.');
  }
  if (!key || key.length !== KEY_BYTES) {
    throw new Error('postgres-backup: backup encryption key must be 32 bytes.');
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
  decipher.setAAD(serializeBackupAad(aadObject));
  decipher.setAuthTag(Buffer.from(envelope.auth_tag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
    decipher.final(),
  ]);
}

export function parsePostgresBackupCliArgs(argv) {
  let out = path.join(ROOT, '.data', 'backups', 'postgres');
  let label = null;
  let input = null;
  let databaseHost = null;
  let databasePort = null;
  let databaseName = null;

  for (let index = 2; index < argv.length; index += 1) {
    const arg = argv[index];
    const next = () => {
      index += 1;
      if (index >= argv.length || String(argv[index]).startsWith('--')) {
        throw new Error(`postgres-backup: ${arg} requires a value`);
      }
      return argv[index];
    };
    if (arg === '--out') out = next();
    else if (arg === '--label') label = next();
    else if (arg === '--input') input = next();
    else if (arg === '--database-host') databaseHost = next();
    else if (arg === '--database-port') databasePort = Number(next());
    else if (arg === '--database-name') databaseName = next();
    else if (arg === '-h' || arg === '--help') {
      console.log(`Usage: node scripts/postgres-backup.mjs [--out <dir>] [--label <safe-label>] [--input <custom-dump> --database-host <host> --database-port <port> --database-name <name>]

Creates a streamed encrypted pg_dump custom-format backup and metadata-only integrity manifest.
Input mode receives no database credential; all three non-secret database-reference flags are required.
Direct pg_dump mode requires DATABASE_URL or ASTRANULL_DATABASE_URL and uses astranull_backup in production.
Both modes require ASTRANULL_BACKUP_ENCRYPTION_KEY.`);
      process.exit(0);
    } else {
      throw new Error(`postgres-backup: unknown argument ${arg}`);
    }
  }

  if (!out) throw new Error('postgres-backup: --out requires a value');
  if (label !== null && !SAFE_LABEL.test(label)) {
    throw new Error('postgres-backup: --label must match [a-zA-Z0-9._-] (max 64 chars)');
  }
  return {
    out: path.resolve(out),
    label,
    input: input === null ? null : path.resolve(input),
    databaseHost,
    databasePort,
    databaseName,
  };
}

function timestampForFilename(date = new Date()) {
  return date.toISOString().replace(/[:.]/g, '-');
}

function fsyncPathSync(target, { directory = false } = {}) {
  let descriptor;
  try {
    descriptor = openSync(target, 'r');
    fsyncSync(descriptor);
  } catch (error) {
    // Some supported filesystems reject directory fsync. File fsync is never optional.
    if (!directory || !['EINVAL', 'ENOTSUP', 'EISDIR', 'EPERM'].includes(error?.code)) throw error;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function fsyncParentSync(target) {
  fsyncPathSync(path.dirname(target), { directory: true });
}

function durableRenameSync(source, destination) {
  fsyncPathSync(source);
  fsyncParentSync(source);
  renameSync(source, destination);
  fsyncParentSync(destination);
}

function durableUnlinkIfPresent(target) {
  try {
    unlinkSync(target);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    return;
  }
  fsyncParentSync(target);
}

async function verifyPublishedBackupPair({
  backupPath,
  manifestPath,
  expectedSha256,
  expectedBytes,
  expectedManifestText,
}) {
  const before = lstatSync(backupPath);
  const manifestBefore = lstatSync(manifestPath);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
    || (before.mode & 0o777) !== 0o600 || before.size !== expectedBytes) {
    throw new Error('postgres-backup: published backup artifact is unsafe or incomplete');
  }
  if (!manifestBefore.isFile() || manifestBefore.isSymbolicLink() || manifestBefore.nlink !== 1
    || (manifestBefore.mode & 0o777) !== 0o600 || manifestBefore.size < 1
    || manifestBefore.size !== Buffer.byteLength(expectedManifestText)) {
    throw new Error('postgres-backup: published manifest completion marker is unsafe or incomplete');
  }
  const hash = crypto.createHash('sha256');
  for await (const chunk of createReadStream(backupPath)) hash.update(chunk);
  const manifestChunks = [];
  let manifestBytes = 0;
  for await (const chunk of createReadStream(manifestPath)) {
    manifestBytes += chunk.length;
    if (manifestBytes > Buffer.byteLength(expectedManifestText)) {
      throw new Error('postgres-backup: published manifest exceeds expected content');
    }
    manifestChunks.push(chunk);
  }
  const after = lstatSync(backupPath);
  const manifestAfter = lstatSync(manifestPath);
  if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
    || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs
    || hash.digest('hex') !== expectedSha256) {
    throw new Error('postgres-backup: published backup artifact changed during final verification');
  }
  if (manifestBefore.dev !== manifestAfter.dev || manifestBefore.ino !== manifestAfter.ino
    || manifestBefore.size !== manifestAfter.size || manifestBefore.mtimeMs !== manifestAfter.mtimeMs
    || manifestBefore.ctimeMs !== manifestAfter.ctimeMs
    || !Buffer.concat(manifestChunks).equals(Buffer.from(expectedManifestText))) {
    throw new Error('postgres-backup: published manifest changed or differs from generated content');
  }
}

function privatePartialPath(out, backupName, purpose) {
  const nonce = crypto.randomBytes(12).toString('hex');
  return path.join(out, `.${backupName}.partial-${purpose}-${nonce}`);
}

async function publicationCheckpoint(options, step, paths) {
  if (typeof options.publicationHook === 'function') {
    await options.publicationHook(step, paths);
  }
}

function databaseReferenceFromInputCli(cli) {
  if (!SAFE_HOST.test(String(cli.databaseHost ?? ''))) {
    throw new Error('postgres-backup: --database-host is required and must be a safe hostname in input mode.');
  }
  if (!Number.isInteger(cli.databasePort) || cli.databasePort < 1 || cli.databasePort > 65535) {
    throw new Error('postgres-backup: --database-port must be an integer between 1 and 65535 in input mode.');
  }
  if (!SAFE_DATABASE.test(String(cli.databaseName ?? ''))) {
    throw new Error('postgres-backup: --database-name is required and must be a safe database name in input mode.');
  }
  return { host: cli.databaseHost, port: cli.databasePort, database: cli.databaseName };
}

export function assertProductionBackupDatabaseRole(databaseUrl, env = process.env) {
  if (String(env.NODE_ENV ?? '').trim() !== 'production') return;
  let username;
  try {
    username = decodeURIComponent(new URL(databaseUrl).username);
  } catch {
    throw new Error('postgres-backup: database URL is not a valid connection URI.');
  }
  if (username !== 'astranull_backup') {
    throw new Error('postgres-backup: production pg_dump must authenticate as astranull_backup.');
  }
}

/**
 * Streams pg_dump stdout and keeps credentials out of argv by moving only the password
 * into the child environment. stderr is capped so a failing child cannot grow memory.
 */
export function createPgDumpSource(databaseUrl, options = {}) {
  const spawnFn = options.spawnFn ?? defaultSpawn;
  let parsed;
  try {
    parsed = new URL(databaseUrl);
  } catch {
    throw new Error('postgres-backup: database URL is not a valid connection URI.');
  }
  if (!['postgresql:', 'postgres:'].includes(parsed.protocol)) {
    throw new Error('postgres-backup: database URL must use the postgresql:// scheme.');
  }
  const password = decodeURIComponent(parsed.password);
  parsed.password = '';
  const child = spawnFn(
    'pg_dump',
    ['--format=custom', '--no-owner', '--no-acl', `--dbname=${parsed.toString()}`],
    {
      env: { ...(options.env ?? process.env), PGPASSWORD: password },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  if (!child?.stdout) throw new Error('postgres-backup: pg_dump did not expose stdout.');
  let stderr = '';
  child.stderr?.on('data', (chunk) => {
    if (stderr.length >= MAX_PG_DUMP_STDERR_BYTES) return;
    stderr += Buffer.from(chunk).toString('utf8').slice(0, MAX_PG_DUMP_STDERR_BYTES - stderr.length);
  });
  const completion = new Promise((resolve) => {
    let settled = false;
    const settle = (outcome) => {
      if (settled) return;
      settled = true;
      resolve(outcome);
    };
    child.once('error', (error) => settle({ error }));
    child.once('close', (code, signal) => settle({ code, signal }));
  });
  const stream = Readable.from((async function* pgDumpChunks() {
    for await (const chunk of child.stdout) yield chunk;
    const outcome = await completion;
    if (outcome.error) throw outcome.error;
    if (outcome.code !== 0) {
      throw new Error(
        `postgres-backup: pg_dump exited ${outcome.code ?? `signal ${outcome.signal ?? 'unknown'}`}: ${stderr.trim()}`,
      );
    }
  })());
  return { stream, cancel: () => child.kill('SIGTERM') };
}

async function sourceForBackup(options) {
  if (options.inputStream) {
    return {
      stream: typeof options.inputStream.pipe === 'function'
        ? options.inputStream
        : Readable.from(options.inputStream),
      cancel() {},
    };
  }
  if (options.inputPath) {
    return {
      stream: createReadStream(options.inputPath, {
        highWaterMark: options.highWaterMark ?? DEFAULT_STREAM_HIGH_WATER_MARK,
      }),
      cancel() {},
    };
  }
  if (options.dumpFn) {
    const value = await options.dumpFn(options.databaseUrl);
    return {
      stream: Buffer.isBuffer(value) ? Readable.from([value]) : Readable.from(value),
      cancel() {},
    };
  }
  return createPgDumpSource(options.databaseUrl, {
    spawnFn: options.spawnFn,
    env: options.env,
  });
}

async function encryptSourceToFile({ source, destinationPath, encryptionKey, aad }) {
  if (!encryptionKey || encryptionKey.length !== KEY_BYTES) {
    throw new Error('postgres-backup: backup encryption key must be 32 bytes.');
  }
  const iv = crypto.randomBytes(IV_BYTES);
  const header = Buffer.concat([BACKUP_STREAM_MAGIC, iv]);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
  cipher.setAAD(serializeBackupAad(aad));
  const plaintextHash = crypto.createHash('sha256');
  const encryptedHash = crypto.createHash('sha256');
  let plaintextBytes = 0;
  let encryptedBytes = 0;
  let sourceChunks = 0;
  let prefix = Buffer.alloc(0);

  const trackedEncryptedChunk = (chunk) => {
    if (chunk.length === 0) return null;
    encryptedHash.update(chunk);
    encryptedBytes += chunk.length;
    return chunk;
  };

  const encrypted = Readable.from((async function* encryptedChunks() {
    yield trackedEncryptedChunk(header);
    for await (const rawChunk of source) {
      const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
      if (chunk.length === 0) continue;
      sourceChunks += 1;
      plaintextBytes += chunk.length;
      plaintextHash.update(chunk);
      if (prefix.length < PG_CUSTOM_DUMP_MAGIC.length) {
        const needed = PG_CUSTOM_DUMP_MAGIC.length - prefix.length;
        prefix = Buffer.concat([prefix, chunk.subarray(0, needed)]);
      }
      const ciphertext = cipher.update(chunk);
      if (ciphertext.length > 0) yield trackedEncryptedChunk(ciphertext);
    }
    if (!prefix.equals(PG_CUSTOM_DUMP_MAGIC)) {
      throw new Error('postgres-backup: pg_dump output is not PostgreSQL custom format');
    }
    const finalCiphertext = cipher.final();
    if (finalCiphertext.length > 0) yield trackedEncryptedChunk(finalCiphertext);
    yield trackedEncryptedChunk(cipher.getAuthTag());
  })());

  await pipeline(
    encrypted,
    createWriteStream(destinationPath, { flags: 'wx', mode: 0o600 }),
  );
  return {
    plaintextSha256: plaintextHash.digest('hex'),
    plaintextBytes,
    encryptedSha256: encryptedHash.digest('hex'),
    encryptedBytes,
    sourceChunks,
  };
}

/**
 * @param {{
 *   databaseUrl?: string | null,
 *   databaseReference?: {host: string, port: number, database: string},
 *   encryptionKey: Buffer,
 *   out: string,
 *   label: string | null,
 *   now?: Date,
 *   inputPath?: string | null,
 *   inputStream?: NodeJS.ReadableStream | AsyncIterable<Buffer>,
 *   highWaterMark?: number,
 *   spawnFn?: typeof defaultSpawn,
 *   dumpFn?: (databaseUrl?: string | null) => Buffer | AsyncIterable<Buffer> | Promise<Buffer | AsyncIterable<Buffer>>,
 *   env?: NodeJS.ProcessEnv | Record<string, string | undefined>,
 * }} options
 */
export async function backupPostgres(options) {
  const {
    databaseUrl = null,
    encryptionKey,
    out,
    label,
    now = new Date(),
  } = options;
  const databaseReference = options.databaseReference
    ?? (databaseUrl ? parseDatabaseReference(databaseUrl) : null);
  if (!databaseReference) {
    throw new Error('postgres-backup: a non-secret database reference is required.');
  }

  mkdirSync(out, { recursive: true, mode: 0o700 });
  const filenameNonce = options.filenameNonce ?? crypto.randomBytes(6).toString('hex');
  if (!/^[0-9a-f]{12}$/.test(filenameNonce)) {
    throw new Error('postgres-backup: filename nonce must be 12 lowercase hexadecimal characters.');
  }
  const backupName = `postgres-${timestampForFilename(now)}-${filenameNonce}.dump.enc`;
  if (classifyPostgresBackupArtifactName(backupName) !== 'current') {
    throw new Error('postgres-backup: generated backup filename is not exact current format.');
  }
  const backupPath = path.join(out, backupName);
  const manifestPath = `${backupPath}.manifest.json`;
  const backupPartialPath = privatePartialPath(out, backupName, 'artifact');
  const manifestPartialPath = privatePartialPath(out, backupName, 'manifest');
  const publicationPaths = {
    backupPath,
    manifestPath,
    backupPartialPath,
    manifestPartialPath,
  };
  const aad = {
    artifact_type: ARTIFACT_TYPE,
    backup_file: backupName,
    created_at: now.toISOString(),
    database_reference: databaseReference,
  };
  const sourceControl = await sourceForBackup({ ...options, databaseUrl });
  let streamed;
  let artifactPublished = false;
  let manifestPublished = false;
  try {
    streamed = await encryptSourceToFile({
      source: sourceControl.stream,
      destinationPath: backupPartialPath,
      encryptionKey,
      aad,
    });
    fsyncPathSync(backupPartialPath);
    fsyncParentSync(backupPartialPath);
    await publicationCheckpoint(options, 'artifact_partial_ready', publicationPaths);

    const manifest = {
      version: MANIFEST_VERSION,
      artifact_type: ARTIFACT_TYPE,
      created_at: now.toISOString(),
      backup_file: backupName,
      sha256: streamed.encryptedSha256,
      plaintext_sha256: streamed.plaintextSha256,
      bytes: streamed.encryptedBytes,
      label,
      database_reference: databaseReference,
      dump_format: 'pg_custom',
      encryption: {
        algorithm: BACKUP_ENCRYPTION_ALGORITHM,
        key_reference: 'env:ASTRANULL_BACKUP_ENCRYPTION_KEY',
        envelope_version: BACKUP_ENVELOPE_VERSION,
        encoding: 'binary_stream',
      },
    };
    validatePostgresBackupManifestFields(manifest);
    const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
    writeFileSync(manifestPartialPath, manifestText, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
    fsyncPathSync(manifestPartialPath);
    fsyncParentSync(manifestPartialPath);
    await publicationCheckpoint(options, 'manifest_partial_ready', publicationPaths);

    // The artifact becomes visible first. Only the subsequent manifest rename advertises
    // a complete restore point; a crash in between leaves an unadvertised orphan.
    durableRenameSync(backupPartialPath, backupPath);
    artifactPublished = true;
    await publicationCheckpoint(options, 'artifact_published', publicationPaths);
    durableRenameSync(manifestPartialPath, manifestPath);
    manifestPublished = true;
    await publicationCheckpoint(options, 'manifest_published', publicationPaths);
    await verifyPublishedBackupPair({
      backupPath,
      manifestPath,
      expectedSha256: streamed.encryptedSha256,
      expectedBytes: streamed.encryptedBytes,
      expectedManifestText: manifestText,
    });
    await publicationCheckpoint(options, 'pair_verified', publicationPaths);

    return {
      backupPath,
      manifestPath,
      manifest,
      plaintextBytes: streamed.plaintextBytes,
      sourceChunks: streamed.sourceChunks,
    };
  } catch (error) {
    sourceControl.cancel();
    try { durableUnlinkIfPresent(backupPartialPath); } catch {}
    try { durableUnlinkIfPresent(manifestPartialPath); } catch {}
    if (manifestPublished) {
      try { durableUnlinkIfPresent(manifestPath); } catch {}
    }
    if (artifactPublished) {
      try { durableUnlinkIfPresent(backupPath); } catch {}
    }
    throw error;
  }
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {ReturnType<typeof parsePostgresBackupCliArgs>} cli
 */
export function resolvePostgresBackupConfig(env, cli) {
  try {
    loadBackupEncryptionKey(env, { required: true });
  } catch (error) {
    return { ok: false, message: error instanceof Error ? error.message : String(error) };
  }

  if (cli.input) {
    try {
      return {
        ok: true,
        databaseUrl: null,
        databaseReference: databaseReferenceFromInputCli(cli),
        inputPath: cli.input,
        out: cli.out,
        label: cli.label,
      };
    } catch (error) {
      return { ok: false, message: error instanceof Error ? error.message : String(error) };
    }
  }

  const database = resolveDatabaseUrl(env);
  if (!database.ok) return database;
  try {
    assertProductionBackupDatabaseRole(database.databaseUrl, env);
    return {
      ok: true,
      databaseUrl: database.databaseUrl,
      databaseReference: parseDatabaseReference(database.databaseUrl),
      inputPath: null,
      out: cli.out,
      label: cli.label,
    };
  } catch (error) {
    return { ok: false, message: error instanceof Error ? error.message : String(error) };
  }
}

async function main() {
  try {
    const cli = parsePostgresBackupCliArgs(process.argv);
    const config = resolvePostgresBackupConfig(process.env, cli);
    if (!config.ok) {
      console.error(config.message);
      process.exitCode = 1;
      return;
    }
    const encryptionKey = loadBackupEncryptionKey(process.env, { required: true });
    const { backupPath, manifestPath, manifest } = await backupPostgres({
      databaseUrl: config.databaseUrl,
      databaseReference: config.databaseReference,
      inputPath: config.inputPath,
      encryptionKey,
      out: config.out,
      label: config.label,
      env: process.env,
    });

    console.log('postgres-backup: ok');
    console.log(`  backup: ${backupPath}`);
    console.log(`  manifest: ${manifestPath}`);
    console.log(`  sha256: ${manifest.sha256}`);
    console.log(`  plaintext_sha256: ${manifest.plaintext_sha256}`);
    console.log(`  bytes: ${manifest.bytes}`);
    console.log(`  database: ${manifest.database_reference.host}/${manifest.database_reference.database}`);
  } catch (error) {
    console.error(redactDatabaseUrlInMessage(error, process.env));
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) main();
