import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { Readable } from 'node:stream';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, it } from 'node:test';
import {
  ARTIFACT_TYPE,
  BACKUP_ENVELOPE_VERSION,
  BACKUP_STREAM_MAGIC,
  LEGACY_BACKUP_ENVELOPE_VERSION,
  MANIFEST_VERSION,
  backupPostgres,
  collectManifestForbiddenFields,
  decryptBackupPayload,
  encryptBackupPayload,
  parsePostgresBackupCliArgs,
  resolveDatabaseUrl,
  resolvePostgresBackupConfig,
  sha256Hex,
  validatePostgresBackupManifestFields,
} from '../../scripts/postgres-backup.mjs';
import {
  createPostgresRestoreDrillManifest,
  parsePostgresRestoreDrillArgs,
  resolvePostgresRestoreDrillConfig,
  runPostgresRestoreDrill,
  validatePostgresRestoreDrillEvidence,
  verifyEncryptedPostgresBackup,
} from '../../scripts/postgres-restore-drill.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const TEST_KEY_HEX = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const PG_CUSTOM_DUMP = Buffer.concat([
  Buffer.from('PGDMP', 'ascii'),
  Buffer.from([1, 0, 0, 0]),
  Buffer.from('test-dump-body'),
]);
const DATABASE_REFERENCE = { host: 'db.example', port: 5432, database: 'astranull' };

const VALID_DRILL = {
  drill_id: 'pg_dr_2026_07_03_staging_restore',
  environment: 'staging',
  started_at: '2026-07-03T00:00:00.000Z',
  completed_at: '2026-07-03T01:00:00.000Z',
  backup_manifest: {
    manifest_uri: 'evidence://postgres/backup-manifest/staging-2026-07-03',
    sha256: 'a'.repeat(64),
    backup_reference: 's3://backups/staging/postgres-2026-07-03.dump.enc',
  },
  restore_target: {
    cluster_reference: 'db-cluster/staging/astranull-restore-clone',
    database_reference: 'postgres/staging/astranull',
    restore_mode: 'non_production_clone',
  },
  verification: {
    signoff_reference: 'signoff://ops/postgres-restore-verification',
    checks: [
      { check_id: 'tenant_rls_smoke', status: 'passed', evidence_uri: 'evidence://postgres/checks/tenant-rls' },
      { check_id: 'migration_head', status: 'passed', evidence_uri: 'evidence://postgres/checks/migration-head' },
    ],
  },
  operator_signoff: {
    operator: 'db-oncall',
    role: 'database-operator',
    signed_at: '2026-07-03T01:00:00.000Z',
    signoff_reference: 'signoff://ops/postgres-drill',
  },
};

const tempDirs = [];
function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-pg-backup-'));
  tempDirs.push(dir);
  return dir;
}
function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}
function testEnv(overrides = {}) {
  return {
    ASTRANULL_DATABASE_URL: 'postgresql://astranull_backup:secret@db.example:5432/astranull',
    ASTRANULL_BACKUP_ENCRYPTION_KEY: TEST_KEY_HEX,
    ...overrides,
  };
}

async function createV2Backup(root, overrides = {}) {
  return backupPostgres({
    databaseReference: DATABASE_REFERENCE,
    encryptionKey: Buffer.from(TEST_KEY_HEX, 'hex'),
    out: path.join(root, 'backups'),
    label: null,
    dumpFn: () => PG_CUSTOM_DUMP,
    ...overrides,
  });
}

afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop(), { recursive: true, force: true });
});

describe('postgres backup config', () => {
  it('parses input mode with a non-secret database reference', () => {
    const parsed = parsePostgresBackupCliArgs([
      'node', 'script.mjs', '--out', '/tmp/backups', '--label', 'nightly',
      '--input', '/tmp/predeploy.dump', '--database-host', 'postgres',
      '--database-port', '5432', '--database-name', 'astranull',
    ]);
    assert.equal(parsed.out, '/tmp/backups');
    assert.equal(parsed.label, 'nightly');
    assert.equal(parsed.input, '/tmp/predeploy.dump');
    assert.deepEqual(
      [parsed.databaseHost, parsed.databasePort, parsed.databaseName],
      ['postgres', 5432, 'astranull'],
    );
  });

  it('fails closed without DATABASE_URL in direct mode', () => {
    const resolved = resolveDatabaseUrl({});
    assert.equal(resolved.ok, false);
    assert.match(resolved.message ?? '', /DATABASE_URL/);
  });

  it('accepts ASTRANULL_DATABASE_URL', () => {
    const resolved = resolveDatabaseUrl({ ASTRANULL_DATABASE_URL: 'postgresql://localhost/astranull' });
    assert.equal(resolved.ok, true);
  });

  it('fails closed without backup encryption key', () => {
    const config = resolvePostgresBackupConfig(
      { DATABASE_URL: 'postgresql://astranull_backup@localhost/astranull' },
      { out: '/tmp/out', label: null, input: null },
    );
    assert.equal(config.ok, false);
    assert.match(config.message ?? '', /ASTRANULL_BACKUP_ENCRYPTION_KEY/);
  });

  it('requires astranull_backup only for production direct pg_dump', () => {
    const base = {
      NODE_ENV: 'production',
      ASTRANULL_BACKUP_ENCRYPTION_KEY: TEST_KEY_HEX,
      ASTRANULL_DATABASE_URL: 'postgresql://astranull:owner@localhost/astranull',
    };
    const rejected = resolvePostgresBackupConfig(base, { out: '/tmp/out', label: null, input: null });
    assert.equal(rejected.ok, false);
    assert.match(rejected.message, /must authenticate as astranull_backup/);
    const accepted = resolvePostgresBackupConfig({
      ...base,
      ASTRANULL_DATABASE_URL: 'postgresql://astranull_backup:reader@localhost/astranull',
    }, { out: '/tmp/out', label: null, input: null });
    assert.equal(accepted.ok, true);
  });

  it('input encryption requires no database URL but does require reference fields', () => {
    const parsed = parsePostgresBackupCliArgs([
      'node', 'script', '--input', '/tmp/dump', '--database-host', 'postgres',
      '--database-port', '5432', '--database-name', 'astranull',
    ]);
    const config = resolvePostgresBackupConfig(
      { NODE_ENV: 'production', ASTRANULL_BACKUP_ENCRYPTION_KEY: TEST_KEY_HEX },
      parsed,
    );
    assert.equal(config.ok, true);
    assert.equal(config.databaseUrl, null);
    assert.deepEqual(config.databaseReference, { host: 'postgres', port: 5432, database: 'astranull' });
  });
});

describe('postgres backup manifest safety', () => {
  it('rejects forbidden secret-like manifest fields', () => {
    const manifest = {
      version: MANIFEST_VERSION,
      artifact_type: ARTIFACT_TYPE,
      created_at: '2026-07-03T12:00:00.000Z',
      backup_file: 'postgres-2026-07-03.dump.enc',
      sha256: sha256Hex(Buffer.from('x')),
      plaintext_sha256: sha256Hex(PG_CUSTOM_DUMP),
      bytes: 10,
      label: null,
      database_reference: DATABASE_REFERENCE,
      dump_format: 'pg_custom',
      encryption: {
        algorithm: 'AES-256-GCM',
        key_reference: 'env:ASTRANULL_BACKUP_ENCRYPTION_KEY',
        envelope_version: BACKUP_ENVELOPE_VERSION,
      },
      database_url: 'postgresql://secret@db.example/astranull',
    };
    assert.ok(collectManifestForbiddenFields(manifest).includes('database_url'));
    assert.throws(() => validatePostgresBackupManifestFields(manifest), /forbidden fields/);
  });
});

describe('postgres streaming backup and restore', () => {
  it('creates a binary v2 backup with a metadata-only manifest', async () => {
    const root = tempDir();
    const fixedNow = new Date('2026-07-03T12:00:00.000Z');
    const { backupPath, manifestPath, manifest } = await createV2Backup(root, {
      label: 'drill',
      now: fixedNow,
    });
    const backupBytes = readFileSync(backupPath);
    assert.ok(backupBytes.subarray(0, BACKUP_STREAM_MAGIC.length).equals(BACKUP_STREAM_MAGIC));
    assert.equal(backupBytes.includes(PG_CUSTOM_DUMP), false);
    assert.equal(manifest.encryption.envelope_version, BACKUP_ENVELOPE_VERSION);
    assert.equal(manifest.sha256, sha256Hex(backupBytes));
    assert.equal(manifest.plaintext_sha256, sha256Hex(PG_CUSTOM_DUMP));
    assert.equal(manifest.label, 'drill');
    assert.deepEqual(manifest.database_reference, DATABASE_REFERENCE);
    assert.doesNotMatch(readFileSync(manifestPath, 'utf8'), /postgresql:\/\//);
    validatePostgresBackupManifestFields(manifest);
  });

  it('streams many input and output chunks without synchronous production input reads', async () => {
    const root = tempDir();
    const largeDump = Buffer.concat([PG_CUSTOM_DUMP, Buffer.alloc(512 * 1024, 0x5a)]);
    const chunks = [];
    for (let offset = 0; offset < largeDump.length; offset += 4093) {
      chunks.push(largeDump.subarray(offset, offset + 4093));
    }
    const created = await createV2Backup(root, { inputStream: Readable.from(chunks), dumpFn: undefined });
    assert.ok(created.sourceChunks > 100);
    const verification = await verifyEncryptedPostgresBackup({
      manifestPath: created.manifestPath,
      encryptionKey: Buffer.from(TEST_KEY_HEX, 'hex'),
    });
    assert.ok(verification.encrypted_chunks > 1);
    assert.ok(verification.plaintext_chunks > 1);
    assert.equal(verification.plaintext_bytes, largeDump.length);
    assert.equal(verification.plaintext_sha256, sha256Hex(largeDump));

    const backupSource = readFileSync(path.join(ROOT, 'scripts/postgres-backup.mjs'), 'utf8');
    const restoreSource = readFileSync(path.join(ROOT, 'scripts/postgres-restore-drill.mjs'), 'utf8');
    assert.doesNotMatch(backupSource, /readFileSync/);
    assert.doesNotMatch(restoreSource, /readFileSync/);
    assert.match(backupSource, /createReadStream\(options\.inputPath/);
    assert.match(restoreSource, /for await \(const rawChunk of createReadStream\(backupPath\)\)/);
  });

  it('rejects checksum mismatch before decryption', async () => {
    const root = tempDir();
    const { backupPath, manifestPath } = await createV2Backup(root);
    const tampered = Buffer.from(readFileSync(backupPath));
    tampered[20] ^= 0xff;
    writeFileSync(backupPath, tampered);
    await assert.rejects(
      () => verifyEncryptedPostgresBackup({ manifestPath, encryptionKey: Buffer.from(TEST_KEY_HEX, 'hex') }),
      (error) => error?.code === 'CHECKSUM_MISMATCH',
    );
  });

  it('retains bounded restore compatibility with legacy v1 JSON/base64 backups', async () => {
    const root = tempDir();
    const key = Buffer.from(TEST_KEY_HEX, 'hex');
    const backupName = 'postgres-legacy.dump.enc';
    const createdAt = '2026-07-03T12:00:00.000Z';
    const aad = {
      artifact_type: ARTIFACT_TYPE,
      backup_file: backupName,
      created_at: createdAt,
      database_reference: DATABASE_REFERENCE,
    };
    const envelope = encryptBackupPayload(PG_CUSTOM_DUMP, key, aad);
    const backupBytes = Buffer.from(`${JSON.stringify(envelope)}\n`);
    const backupPath = path.join(root, backupName);
    const manifestPath = `${backupPath}.manifest.json`;
    writeFileSync(backupPath, backupBytes);
    writeJson(manifestPath, {
      version: MANIFEST_VERSION,
      artifact_type: ARTIFACT_TYPE,
      created_at: createdAt,
      backup_file: backupName,
      sha256: sha256Hex(backupBytes),
      plaintext_sha256: sha256Hex(PG_CUSTOM_DUMP),
      bytes: backupBytes.length,
      label: 'legacy',
      database_reference: DATABASE_REFERENCE,
      dump_format: 'pg_custom',
      encryption: {
        algorithm: 'AES-256-GCM',
        key_reference: 'env:ASTRANULL_BACKUP_ENCRYPTION_KEY',
        envelope_version: LEGACY_BACKUP_ENVELOPE_VERSION,
      },
    });
    const verification = await verifyEncryptedPostgresBackup({ manifestPath, encryptionKey: key });
    assert.equal(verification.envelope_version, LEGACY_BACKUP_ENVELOPE_VERSION);
    assert.equal(verification.plaintext_sha256, sha256Hex(PG_CUSTOM_DUMP));
  });

  it('keeps the explicit legacy v1 helper round trip', () => {
    const key = Buffer.from(TEST_KEY_HEX, 'hex');
    const aad = {
      artifact_type: ARTIFACT_TYPE,
      backup_file: 'postgres-test.dump.enc',
      created_at: '2026-07-03T12:00:00.000Z',
      database_reference: DATABASE_REFERENCE,
    };
    const envelope = encryptBackupPayload(PG_CUSTOM_DUMP, key, aad);
    assert.equal(envelope.version, LEGACY_BACKUP_ENVELOPE_VERSION);
    assert.deepEqual(decryptBackupPayload(envelope, key, aad), PG_CUSTOM_DUMP);
  });
});

describe('postgres restore drill evidence', () => {
  it('parses guarded extraction arguments', () => {
    assert.deepEqual(
      parsePostgresRestoreDrillArgs(['--manifest', 'backup.manifest.json', '--input', 'drill.json']),
      {
        manifest: 'backup.manifest.json', backup: null, input: 'drill.json',
        out: 'output/postgres-restore-drill-manifest.json', dryRun: false,
        validateOnly: false, extract: null, yes: false, help: false,
      },
    );
    assert.throws(() => parsePostgresRestoreDrillArgs([]), /--manifest is required/);
    assert.throws(
      () => parsePostgresRestoreDrillArgs(['--manifest', 'backup.manifest.json', '--extract', 'plain.dump']),
      /--extract requires --yes/,
    );
  });

  it('extracts an authenticated custom dump with mode 0600 and refuses overwrite', async () => {
    const root = tempDir();
    const key = Buffer.from(TEST_KEY_HEX, 'hex');
    const { manifestPath } = await createV2Backup(root, { label: 'restore' });
    const extractPath = path.join(root, 'plaintext', 'restore.dump');
    const verification = await verifyEncryptedPostgresBackup({ manifestPath, encryptionKey: key, extractPath });
    assert.equal(verification.extracted_to, path.resolve(extractPath));
    assert.deepEqual(readFileSync(extractPath), PG_CUSTOM_DUMP);
    assert.equal(statSync(extractPath).mode & 0o777, 0o600);
    await assert.rejects(
      () => verifyEncryptedPostgresBackup({ manifestPath, encryptionKey: key, extractPath }),
      /EEXIST/,
    );
    assert.deepEqual(readFileSync(extractPath), PG_CUSTOM_DUMP);
  });

  it('requires only the encryption key for restore verification', () => {
    const config = resolvePostgresRestoreDrillConfig(
      { ASTRANULL_BACKUP_ENCRYPTION_KEY: TEST_KEY_HEX },
      { manifest: '/tmp/manifest.json', backup: null, input: null, dryRun: true },
    );
    assert.equal(config.ok, true);
    assert.equal('databaseUrl' in config, false);
  });

  it('accepts valid metadata-only drill evidence', () => {
    const result = validatePostgresRestoreDrillEvidence(VALID_DRILL);
    assert.deepEqual(result, { ok: true, missing_fields: [], forbidden_fields: [], missing_signoff: false });
  });

  it('rejects drill evidence containing database URLs', () => {
    const result = validatePostgresRestoreDrillEvidence({
      ...VALID_DRILL,
      notes: 'connected using postgresql://user:secret@db.example:5432/astranull',
    });
    assert.equal(result.ok, false);
    assert.ok(result.forbidden_fields.some((field) => field.includes('database_url_pattern')));
  });

  it('runs end-to-end restore drill with evidence manifest output', async () => {
    const root = tempDir();
    const { manifestPath } = await createV2Backup(root, { label: 'drill' });
    const drillPath = path.join(root, 'drill.json');
    writeJson(drillPath, VALID_DRILL);
    const outPath = path.join(root, 'output', 'postgres-restore-drill-manifest.json');
    const result = await runPostgresRestoreDrill({
      env: { ASTRANULL_BACKUP_ENCRYPTION_KEY: TEST_KEY_HEX },
      manifest: manifestPath,
      backup: null,
      input: drillPath,
      out: outPath,
      dryRun: true,
      validateOnly: false,
    });
    assert.equal(result.ok, true);
    assert.equal(result.drillValidation?.ok, true);
    assert.ok(existsSync(outPath));
    const written = JSON.parse(readFileSync(outPath, 'utf8'));
    assert.equal(written.artifact_type, 'postgres_restore_drill_manifest');
    assert.equal(written.verification.status, 'verified');
    assert.equal(written.drill_validation.ok, true);
    assert.doesNotMatch(readFileSync(outPath, 'utf8'), /postgresql:\/\//);
  });

  it('creates metadata-only restore drill manifest helper output', () => {
    const manifest = createPostgresRestoreDrillManifest({
      verification: {
        status: 'verified', manifestPath: '/tmp/backup.manifest.json',
        backupPath: '/tmp/backup.dump.enc', sha256: 'b'.repeat(64),
        plaintext_sha256: 'c'.repeat(64), plaintext_bytes: 128,
        database_reference: DATABASE_REFERENCE, encryption_algorithm: 'AES-256-GCM',
      },
      drillValidation: { ok: true, missing_fields: [], forbidden_fields: [], missing_signoff: false },
      drillEvidence: VALID_DRILL,
    });
    const serialized = JSON.stringify(manifest);
    assert.doesNotMatch(serialized, /postgresql:\/\//);
    assert.equal(manifest.drill_summary.drill_id, VALID_DRILL.drill_id);
  });
});
