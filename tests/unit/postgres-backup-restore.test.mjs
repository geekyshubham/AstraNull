import assert from 'node:assert/strict';
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
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
  MAX_RETENTION_TOMBSTONE_DIRECTORIES,
  backupPostgres,
  classifyPostgresBackupArtifactName,
  collectManifestForbiddenFields,
  decryptBackupPayload,
  encryptBackupPayload,
  inventoryPostgresBackupArtifacts,
  parsePostgresBackupCliArgs,
  parsePostgresBackupIdentityRecord,
  pruneInventoriedPostgresBackups,
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
function writeInventoryBackupPair(directory, name, bytes = Buffer.from(`encrypted-${name}`)) {
  const artifactPath = path.join(directory, name);
  const manifestPath = `${artifactPath}.manifest.json`;
  writeFileSync(artifactPath, bytes, { mode: 0o600 });
  writeFileSync(manifestPath, `${JSON.stringify({
    version: MANIFEST_VERSION,
    artifact_type: ARTIFACT_TYPE,
    created_at: '2026-08-31T12:00:00.000Z',
    backup_file: name,
    sha256: sha256Hex(bytes),
    bytes: bytes.length,
    label: null,
    database_reference: DATABASE_REFERENCE,
    dump_format: 'pg_custom',
    encryption: {
      algorithm: 'AES-256-GCM',
      key_reference: 'env:ASTRANULL_BACKUP_ENCRYPTION_KEY',
      envelope_version: BACKUP_ENVELOPE_VERSION,
    },
  }, null, 2)}\n`, { mode: 0o600 });
  chmodSync(artifactPath, 0o600);
  chmodSync(manifestPath, 0o600);
  return { artifactPath, manifestPath, bytes };
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

describe('postgres backup artifact filename classification', () => {
  it('recognizes only exact calendar-valid current and pre-nonce legacy generated names', () => {
    const current = 'postgres-2026-08-30T16-47-04-492Z-abcdef123456.dump.enc';
    const productionLegacy = 'postgres-2026-08-30T16-47-04-492Z.dump.enc';
    const leapCurrent = 'postgres-2024-02-29T23-59-59-999Z-012345abcdef.dump.enc';
    const leapLegacy = 'postgres-2000-02-29T00-00-00-000Z.dump.enc';
    assert.equal(classifyPostgresBackupArtifactName(current), 'current');
    assert.equal(classifyPostgresBackupArtifactName(productionLegacy), 'legacy');
    assert.equal(classifyPostgresBackupArtifactName(leapCurrent), 'current');
    assert.equal(classifyPostgresBackupArtifactName(leapLegacy), 'legacy');

    const impossibleTimestamps = [
      '2026-00-15T12-00-00-000Z',
      '2026-13-15T12-00-00-000Z',
      '2026-01-00T12-00-00-000Z',
      '2026-04-31T12-00-00-000Z',
      '2025-02-29T12-00-00-000Z',
      '2024-02-30T12-00-00-000Z',
      '2026-08-30T24-00-00-000Z',
      '2026-08-30T16-60-00-000Z',
      '2026-08-30T16-47-60-000Z',
    ];
    for (const timestamp of impossibleTimestamps) {
      assert.equal(
        classifyPostgresBackupArtifactName(`postgres-${timestamp}-abcdef123456.dump.enc`),
        'unknown',
        timestamp,
      );
      assert.equal(
        classifyPostgresBackupArtifactName(`postgres-${timestamp}.dump.enc`),
        'unknown',
        `legacy ${timestamp}`,
      );
    }

    for (const unsafe of [
      'postgres-2026-08-30T16-47-04-492Z-ABCDEF123456.dump.enc',
      'postgres-2026-08-30T16-47-04-492Z-abcdef12345.dump.enc',
      'postgres-2026-08-30T16-47-04-492Z-abcdef1234567.dump.enc',
      'postgres-2026-08-30T16-47-04Z.dump.enc',
      'postgres-2026-08-30T16-47-04-492Z-manual.dump.enc',
      `${current}\n`,
      `postgres-2026-08-30T16-47-04-492Z-abc\ndef123456.dump.enc`,
      `postgres-2026-08-30T16-47-04-492Z-abc\u0001def123456.dump.enc`,
      `../${current}`,
      `/backup/${current}`,
      `backup\\${current}`,
    ]) {
      assert.equal(classifyPostgresBackupArtifactName(unsafe), 'unknown', JSON.stringify(unsafe));
    }
    assert.equal(classifyPostgresBackupArtifactName(null), 'unknown');
  });
});

describe('postgres backup secure inventory and retention', () => {
  it('emits one line-safe exact identity record for an unchanged current pair', async () => {
    const root = tempDir();
    const name = 'postgres-2026-08-31T12-00-00-000Z-abcdef123456.dump.enc';
    writeInventoryBackupPair(root, name);
    const records = await inventoryPostgresBackupArtifacts(root);
    assert.equal(records.length, 1);
    assert.doesNotMatch(records[0], /[\r\n]/);
    const parsed = parsePostgresBackupIdentityRecord(records[0]);
    assert.equal(parsed.name, name);
    assert.equal(parsed.artifactIdentity.nlink, 1n);
    assert.equal(parsed.manifestIdentity.nlink, 1n);
  });

  it('rejects a hard link created deterministically during artifact hashing', async () => {
    const root = tempDir();
    const name = 'postgres-2026-08-31T12-00-01-000Z-abcdef123456.dump.enc';
    const { artifactPath, manifestPath } = writeInventoryBackupPair(root, name);
    const linkedPath = path.join(root, 'attacker-hard-link');
    let linked = false;
    await assert.rejects(
      () => inventoryPostgresBackupArtifacts(root, {
        checkpoint(step) {
          if (step === 'artifact_hash_chunk' && !linked) {
            linked = true;
            linkSync(artifactPath, linkedPath);
          }
        },
      }),
      /singly linked|identity changed/,
    );
    assert.equal(linked, true);
    assert.equal(existsSync(artifactPath), true);
    assert.equal(existsSync(manifestPath), true);
    assert.equal(existsSync(linkedPath), true);
  });

  it('rejects a deterministic final-path swap after reading through open handles', async () => {
    const root = tempDir();
    const name = 'postgres-2026-08-31T12-00-02-000Z-abcdef123456.dump.enc';
    const { artifactPath, manifestPath, bytes } = writeInventoryBackupPair(root, name);
    const displacedPath = `${artifactPath}.displaced`;
    let swapped = false;
    await assert.rejects(
      () => inventoryPostgresBackupArtifacts(root, {
        checkpoint(step) {
          if (step === 'before_final_path_check' && !swapped) {
            swapped = true;
            renameSync(artifactPath, displacedPath);
            writeFileSync(artifactPath, bytes, { mode: 0o600 });
          }
        },
      }),
      /artifact path .* identity changed/,
    );
    assert.equal(swapped, true);
    assert.equal(existsSync(artifactPath), true);
    assert.equal(existsSync(displacedPath), true);
    assert.equal(existsSync(manifestPath), true);
  });

  it('rejects deterministic manifest metadata drift while hashing the artifact', async () => {
    const root = tempDir();
    const name = 'postgres-2026-08-31T12-00-03-000Z-abcdef123456.dump.enc';
    const { artifactPath, manifestPath } = writeInventoryBackupPair(root, name);
    let drifted = false;
    await assert.rejects(
      () => inventoryPostgresBackupArtifacts(root, {
        checkpoint(step) {
          if (step === 'artifact_hash_chunk' && !drifted) {
            drifted = true;
            chmodSync(manifestPath, 0o640);
          }
        },
      }),
      /manifest .* during artifact hash/,
    );
    assert.equal(drifted, true);
    assert.equal(existsSync(artifactPath), true);
    assert.equal(existsSync(manifestPath), true);
  });

  it('fails an inventory-to-prune identity drift before deleting any pair', async () => {
    const root = tempDir();
    const names = Array.from({ length: 11 }, (_, index) => (
      `postgres-2026-08-${String(index + 1).padStart(2, '0')}T12-00-00-000Z-${String(index).padStart(12, '0')}.dump.enc`
    ));
    for (const name of names) writeInventoryBackupPair(root, name);
    const records = await inventoryPostgresBackupArtifacts(root);
    chmodSync(path.join(root, `${names[0]}.manifest.json`), 0o640);
    await assert.rejects(
      () => pruneInventoriedPostgresBackups(root, [records[0]]),
      /identity changed/,
    );
    assert.equal(readdirSync(root).length, names.length * 2);
    for (const name of names) {
      assert.equal(existsSync(path.join(root, name)), true, name);
      assert.equal(existsSync(path.join(root, `${name}.manifest.json`)), true, `${name} manifest`);
    }
  });

  it('atomically refuses a pre-existing manifest capture without changing source or destination', async () => {
    const root = tempDir();
    const name = 'postgres-2026-08-31T12-00-03-100Z-abcdef123456.dump.enc';
    const { artifactPath, manifestPath, bytes } = writeInventoryBackupPair(root, name);
    const originalManifest = readFileSync(manifestPath);
    const replacement = Buffer.from('pre-existing-quarantine-destination');
    const [record] = await inventoryPostgresBackupArtifacts(root);
    let capturedManifestPath;

    await assert.rejects(
      () => pruneInventoriedPostgresBackups(root, [record], {
        checkpoint(step, context) {
          if (step === 'retention_quarantine_created') {
            capturedManifestPath = context.capturedManifestPath;
            writeFileSync(capturedManifestPath, replacement, { mode: 0o600 });
          }
        },
      }),
      (error) => error?.code === 'EEXIST',
    );

    assert.ok(capturedManifestPath);
    assert.deepEqual(readFileSync(capturedManifestPath), replacement);
    assert.deepEqual(readFileSync(artifactPath), bytes);
    assert.deepEqual(readFileSync(manifestPath), originalManifest);
    assert.equal(existsSync(path.join(path.dirname(capturedManifestPath), 'artifact')), false);
  });

  it('atomically refuses a pre-existing artifact capture without clobbering either entry', async () => {
    const root = tempDir();
    const name = 'postgres-2026-08-31T12-00-03-150Z-abcdef123456.dump.enc';
    const { artifactPath, manifestPath, bytes } = writeInventoryBackupPair(root, name);
    const originalManifest = readFileSync(manifestPath);
    const replacement = Buffer.from('pre-existing-artifact-destination');
    const [record] = await inventoryPostgresBackupArtifacts(root);
    let context;

    await assert.rejects(
      () => pruneInventoriedPostgresBackups(root, [record], {
        checkpoint(step, current) {
          if (step === 'retention_manifest_public_removal_durable') {
            context = current;
            writeFileSync(current.capturedArtifactPath, replacement, { mode: 0o600 });
          }
        },
      }),
      (error) => error?.code === 'EEXIST',
    );

    assert.ok(context);
    assert.deepEqual(readFileSync(context.capturedArtifactPath), replacement);
    assert.deepEqual(readFileSync(context.capturedManifestPath), originalManifest);
    assert.deepEqual(readFileSync(artifactPath), bytes);
    assert.equal(existsSync(manifestPath), false);
  });

  it('validates both captured members before reclaiming either one', async () => {
    const root = tempDir();
    const name = 'postgres-2026-08-31T12-00-03-200Z-abcdef123456.dump.enc';
    const { artifactPath, manifestPath, bytes } = writeInventoryBackupPair(root, name);
    const originalManifest = readFileSync(manifestPath);
    const mutatedArtifact = Buffer.concat([bytes, Buffer.from('-mutated-before-final-barrier')]);
    const [record] = await inventoryPostgresBackupArtifacts(root);
    let context;

    await assert.rejects(
      () => pruneInventoriedPostgresBackups(root, [record], {
        checkpoint(step, current) {
          if (step === 'retention_artifact_public_removal_durable') {
            context = current;
            writeFileSync(current.capturedArtifactPath, mutatedArtifact);
          }
        },
      }),
      /captured artifact held handle at final capture barrier identity changed/,
    );

    assert.ok(context);
    assert.equal(existsSync(artifactPath), false);
    assert.equal(existsSync(manifestPath), false);
    assert.deepEqual(readFileSync(context.capturedManifestPath), originalManifest);
    assert.deepEqual(readFileSync(context.capturedArtifactPath), mutatedArtifact);
  });

  it('never deletes a replacement injected after the pair-wide final lstat barrier', async () => {
    const root = tempDir();
    const name = 'postgres-2026-08-31T12-00-03-300Z-abcdef123456.dump.enc';
    const { artifactPath, manifestPath } = writeInventoryBackupPair(root, name);
    const replacement = Buffer.from('post-final-lstat-replacement-must-survive');
    const [record] = await inventoryPostgresBackupArtifacts(root);
    let context;
    let displacedArtifactPath;

    await assert.rejects(
      () => pruneInventoriedPostgresBackups(root, [record], {
        checkpoint(step, current) {
          if (step === 'retention_final_capture_barrier_complete') {
            context = current;
            displacedArtifactPath = `${current.capturedArtifactPath}.displaced`;
            renameSync(current.capturedArtifactPath, displacedArtifactPath);
            writeFileSync(current.capturedArtifactPath, replacement, { mode: 0o600 });
          }
        },
      }),
      /captured artifact live tombstone/,
    );

    assert.ok(context);
    assert.deepEqual(readFileSync(context.capturedArtifactPath), replacement);
    assert.equal(existsSync(context.capturedManifestPath), true);
    assert.equal(existsSync(displacedArtifactPath), true);
    assert.equal(statSync(context.capturedManifestPath).size, 0);
    assert.equal(statSync(displacedArtifactPath).size, 0);
    assert.equal(existsSync(artifactPath), false);
    assert.equal(existsSync(manifestPath), false);
  });

  it('quarantines and preserves a manifest replacement swapped after the last source-path check', async () => {
    const root = tempDir();
    const name = 'postgres-2026-08-31T12-00-04-000Z-abcdef123456.dump.enc';
    const { artifactPath, manifestPath } = writeInventoryBackupPair(root, name);
    const displacedPath = `${manifestPath}.retention-displaced`;
    const replacement = Buffer.from('replacement-manifest');
    const [record] = await inventoryPostgresBackupArtifacts(root);
    const checkpoints = [];
    let swapped = false;
    await assert.rejects(
      () => pruneInventoriedPostgresBackups(root, [record], {
        checkpoint(step) {
          checkpoints.push(step);
          if (step === 'before_retention_manifest_capture' && !swapped) {
            swapped = true;
            renameSync(manifestPath, displacedPath);
            writeFileSync(manifestPath, replacement, { mode: 0o600 });
          }
        },
      }),
      /captured manifest identity changed/,
    );
    const quarantines = readdirSync(root).filter((entry) => entry.startsWith('.postgres-retention-quarantine-'));
    assert.equal(swapped, true);
    assert.equal(quarantines.length, 1);
    const quarantine = path.join(root, quarantines[0]);
    assert.deepEqual(readFileSync(path.join(quarantine, 'manifest')), replacement);
    assert.equal(statSync(quarantine).mode & 0o777, 0o700);
    assert.equal(existsSync(manifestPath), false);
    assert.equal(existsSync(displacedPath), true);
    assert.equal(existsSync(artifactPath), true);
    assert.equal(existsSync(path.join(quarantine, 'artifact')), false);
    assert.equal(checkpoints.includes('before_retention_artifact_capture'), false);
    assert.equal(checkpoints.some((step) => step.startsWith('retention_captured_')), false);
  });

  it('quarantines and preserves an artifact replacement swapped after the last source-path check', async () => {
    const root = tempDir();
    const name = 'postgres-2026-08-31T12-00-05-000Z-abcdef123456.dump.enc';
    const { artifactPath, manifestPath, bytes } = writeInventoryBackupPair(root, name);
    const originalManifest = readFileSync(manifestPath);
    const displacedPath = `${artifactPath}.retention-displaced`;
    const replacement = Buffer.from(bytes);
    const [record] = await inventoryPostgresBackupArtifacts(root);
    const checkpoints = [];
    let swapped = false;
    await assert.rejects(
      () => pruneInventoriedPostgresBackups(root, [record], {
        checkpoint(step) {
          checkpoints.push(step);
          if (step === 'before_retention_artifact_capture' && !swapped) {
            swapped = true;
            renameSync(artifactPath, displacedPath);
            writeFileSync(artifactPath, replacement, { mode: 0o600 });
          }
        },
      }),
      /captured artifact identity changed/,
    );
    const quarantines = readdirSync(root).filter((entry) => entry.startsWith('.postgres-retention-quarantine-'));
    assert.equal(swapped, true);
    assert.equal(quarantines.length, 1);
    const quarantine = path.join(root, quarantines[0]);
    assert.deepEqual(readFileSync(path.join(quarantine, 'artifact')), replacement);
    assert.deepEqual(readFileSync(path.join(quarantine, 'manifest')), originalManifest);
    assert.equal(existsSync(artifactPath), false);
    assert.equal(existsSync(displacedPath), true);
    assert.equal(existsSync(manifestPath), false);
    assert.equal(checkpoints.some((step) => step.startsWith('retention_captured_')), false);
  });

  it('fails immediately after manifest capture when the quarantine pathname is swapped', async () => {
    const root = tempDir();
    const name = 'postgres-2026-08-31T12-00-07-000Z-abcdef123456.dump.enc';
    const { artifactPath, manifestPath } = writeInventoryBackupPair(root, name);
    const originalManifest = readFileSync(manifestPath);
    const [record] = await inventoryPostgresBackupArtifacts(root);
    const checkpoints = [];
    const syncPhases = [];
    let swapped = false;
    let quarantinePath;
    let displacedQuarantinePath;
    let replacementSentinelPath;

    await assert.rejects(
      () => pruneInventoriedPostgresBackups(root, [record], {
        checkpoint(step, context) {
          checkpoints.push(step);
          if (step === 'retention_sync') syncPhases.push(context.phase);
          if (step === 'before_retention_manifest_capture' && !swapped) {
            const preparedReplacement = mkdtempSync(path.join(root, '.attacker-quarantine-'));
            replacementSentinelPath = path.join(preparedReplacement, 'replacement-sentinel');
            writeFileSync(replacementSentinelPath, 'do-not-delete', { mode: 0o600 });
            quarantinePath = context.quarantinePath;
            displacedQuarantinePath = `${quarantinePath}.displaced`;
            renameSync(quarantinePath, displacedQuarantinePath);
            renameSync(preparedReplacement, quarantinePath);
            replacementSentinelPath = path.join(quarantinePath, 'replacement-sentinel');
            swapped = true;
          }
        },
      }),
      /retention quarantine .* after manifest capture identity changed/,
    );

    assert.equal(swapped, true);
    assert.equal(checkpoints.at(-1), 'retention_manifest_captured');
    assert.equal(checkpoints.includes('before_retention_artifact_capture'), false);
    assert.equal(checkpoints.some((step) => step.startsWith('retention_captured_')), false);
    assert.equal(syncPhases.includes('manifest_quarantine'), false);
    assert.equal(syncPhases.includes('manifest_root'), false);
    assert.equal(existsSync(artifactPath), true, 'artifact capture must not start');
    assert.equal(existsSync(manifestPath), false, 'manifest was captured before the barrier');
    assert.equal(readFileSync(replacementSentinelPath, 'utf8'), 'do-not-delete');
    assert.deepEqual(readdirSync(quarantinePath), ['replacement-sentinel']);
    assert.deepEqual(readFileSync(path.join(displacedQuarantinePath, 'manifest')), originalManifest);
  });

  it('fails immediately after artifact capture when the quarantine pathname is swapped', async () => {
    const root = tempDir();
    const name = 'postgres-2026-08-31T12-00-08-000Z-abcdef123456.dump.enc';
    const { artifactPath, manifestPath, bytes } = writeInventoryBackupPair(root, name);
    const originalManifest = readFileSync(manifestPath);
    const [record] = await inventoryPostgresBackupArtifacts(root);
    const checkpoints = [];
    const syncPhases = [];
    let swapped = false;
    let quarantinePath;
    let displacedQuarantinePath;
    let replacementSentinelPath;

    await assert.rejects(
      () => pruneInventoriedPostgresBackups(root, [record], {
        checkpoint(step, context) {
          checkpoints.push(step);
          if (step === 'retention_sync') syncPhases.push(context.phase);
          if (step === 'before_retention_artifact_capture' && !swapped) {
            const preparedReplacement = mkdtempSync(path.join(root, '.attacker-quarantine-'));
            replacementSentinelPath = path.join(preparedReplacement, 'replacement-sentinel');
            writeFileSync(replacementSentinelPath, 'do-not-delete', { mode: 0o600 });
            quarantinePath = context.quarantinePath;
            displacedQuarantinePath = `${quarantinePath}.displaced`;
            renameSync(quarantinePath, displacedQuarantinePath);
            renameSync(preparedReplacement, quarantinePath);
            replacementSentinelPath = path.join(quarantinePath, 'replacement-sentinel');
            swapped = true;
          }
        },
      }),
      /retention quarantine .* after artifact capture identity changed/,
    );

    assert.equal(swapped, true);
    assert.equal(checkpoints.at(-1), 'retention_artifact_captured');
    assert.equal(checkpoints.some((step) => step.startsWith('retention_captured_')), false);
    assert.equal(syncPhases.includes('artifact_quarantine'), false);
    assert.equal(syncPhases.includes('artifact_root'), false);
    assert.equal(existsSync(artifactPath), false, 'artifact was captured before the barrier');
    assert.equal(existsSync(manifestPath), false, 'manifest was already durably captured');
    assert.equal(readFileSync(replacementSentinelPath, 'utf8'), 'do-not-delete');
    assert.deepEqual(readdirSync(quarantinePath), ['replacement-sentinel']);
    assert.deepEqual(readFileSync(path.join(displacedQuarantinePath, 'manifest')), originalManifest);
    assert.deepEqual(readFileSync(path.join(displacedQuarantinePath, 'artifact')), bytes);
  });

  it('never starts artifact capture when durable public manifest removal fsync fails', async () => {
    const root = tempDir();
    const name = 'postgres-2026-08-31T12-00-06-000Z-abcdef123456.dump.enc';
    const { artifactPath, manifestPath } = writeInventoryBackupPair(root, name);
    const originalManifest = readFileSync(manifestPath);
    const [record] = await inventoryPostgresBackupArtifacts(root);
    const events = [];
    await assert.rejects(
      () => pruneInventoriedPostgresBackups(root, [record], {
        checkpoint(step, context) {
          if (step === 'before_retention_sync') {
            events.push(`sync:${context.phase}`);
            if (context.phase === 'manifest_root') {
              throw new Error('injected manifest root fsync failure');
            }
            return;
          }
          if (step !== 'retention_sync') events.push(`checkpoint:${step}`);
        },
      }),
      /injected manifest root fsync failure/,
    );
    const quarantines = readdirSync(root).filter((entry) => entry.startsWith('.postgres-retention-quarantine-'));
    assert.equal(quarantines.length, 1);
    assert.deepEqual(readFileSync(path.join(root, quarantines[0], 'manifest')), originalManifest);
    assert.equal(existsSync(manifestPath), false);
    assert.equal(existsSync(artifactPath), true);
    assert.ok(events.includes('checkpoint:retention_manifest_captured'));
    assert.ok(events.includes('sync:manifest_quarantine'));
    assert.ok(events.includes('sync:manifest_root'));
    assert.equal(events.includes('checkpoint:retention_manifest_public_removal_durable'), false);
    assert.equal(events.includes('checkpoint:before_retention_artifact_capture'), false);
    assert.equal(events.some((event) => event.includes('artifact_captured')), false);
    assert.equal(events.some((event) => event.includes('captured_manifest_deleted')), false);
  });

  it('preserves a bounded private pair when interrupted between held-inode reclaims', async () => {
    const root = tempDir();
    const name = 'postgres-2026-08-31T12-00-09-000Z-abcdef123456.dump.enc';
    const { artifactPath, manifestPath, bytes } = writeInventoryBackupPair(root, name);
    const [record] = await inventoryPostgresBackupArtifacts(root);
    let context;

    await assert.rejects(
      () => pruneInventoriedPostgresBackups(root, [record], {
        checkpoint(step, current) {
          if (step === 'retention_captured_manifest_reclaimed') {
            context = current;
            throw new Error('injected interruption after manifest inode reclaim');
          }
        },
      }),
      /injected interruption after manifest inode reclaim/,
    );

    assert.ok(context);
    assert.equal(existsSync(artifactPath), false);
    assert.equal(existsSync(manifestPath), false);
    assert.equal(existsSync(context.capturedManifestPath), true);
    assert.equal(existsSync(context.capturedArtifactPath), true);
    assert.equal(statSync(context.capturedManifestPath).size, 0);
    assert.deepEqual(readFileSync(context.capturedArtifactPath), bytes);
    assert.ok(
      readdirSync(root).filter((entry) => entry.startsWith('.postgres-retention-quarantine-')).length
      <= MAX_RETENTION_TOMBSTONE_DIRECTORIES,
    );
  });

  it('orders durable manifest capture before artifact capture and held-inode reclamation', async () => {
    const root = tempDir();
    const names = Array.from({ length: 11 }, (_, index) => (
      `postgres-2026-07-${String(index + 1).padStart(2, '0')}T12-00-00-000Z-${String(index).padStart(12, '0')}.dump.enc`
    ));
    for (const name of names) writeInventoryBackupPair(root, name);
    const records = await inventoryPostgresBackupArtifacts(root);
    const events = [];
    await pruneInventoriedPostgresBackups(root, [records[0]], {
      checkpoint(step, context) {
        if (step === 'retention_sync') events.push(`sync:${context.phase}`);
        else if (step !== 'before_retention_sync') events.push(`checkpoint:${step}`);
      },
    });
    assert.equal(existsSync(path.join(root, names[0])), false);
    assert.equal(existsSync(path.join(root, `${names[0]}.manifest.json`)), false);
    const quarantines = readdirSync(root)
      .filter((entry) => entry.startsWith('.postgres-retention-quarantine-'));
    assert.equal(quarantines.length, 1);
    assert.ok(quarantines.length <= MAX_RETENTION_TOMBSTONE_DIRECTORIES);
    const tombstoneDirectory = path.join(root, quarantines[0]);
    assert.deepEqual(readdirSync(tombstoneDirectory).sort(), ['artifact', 'manifest']);
    assert.equal(statSync(path.join(tombstoneDirectory, 'artifact')).size, 0);
    assert.equal(statSync(path.join(tombstoneDirectory, 'manifest')).size, 0);
    for (const name of names.slice(1)) {
      assert.equal(existsSync(path.join(root, name)), true, name);
      assert.equal(existsSync(path.join(root, `${name}.manifest.json`)), true, `${name} manifest`);
    }
    const ordered = new Set([
      'checkpoint:retention_manifest_captured',
      'sync:manifest_quarantine',
      'sync:manifest_root',
      'checkpoint:retention_manifest_public_removal_durable',
      'checkpoint:retention_artifact_captured',
      'sync:artifact_quarantine',
      'sync:artifact_root',
      'checkpoint:retention_artifact_public_removal_durable',
      'checkpoint:retention_final_capture_barrier_complete',
      'checkpoint:retention_captured_manifest_reclaimed',
      'checkpoint:retention_captured_artifact_reclaimed',
      'sync:retained_tombstones_quarantine',
      'sync:retained_tombstones_root',
      'checkpoint:retention_tombstones_durable',
    ]);
    assert.deepEqual(events.filter((event) => ordered.has(event)), [...ordered]);
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
      filenameNonce: 'abcdef123456',
    });
    assert.equal(
      path.basename(backupPath),
      'postgres-2026-07-03T12-00-00-000Z-abcdef123456.dump.enc',
    );
    assert.equal(classifyPostgresBackupArtifactName(path.basename(backupPath)), 'current');
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

  it('publishes through private partials and advertises completion only with the manifest', async () => {
    const root = tempDir();
    const out = path.join(root, 'backups');
    const steps = [];
    const created = await createV2Backup(root, {
      filenameNonce: 'abcdef123456',
      publicationHook(step, paths) {
        steps.push({ step, ...paths });
        if (step.endsWith('_partial_ready')) {
          assert.match(path.basename(paths.backupPartialPath), /^\.postgres-.*\.partial-artifact-[0-9a-f]{24}$/);
          assert.match(path.basename(paths.manifestPartialPath), /^\.postgres-.*\.partial-manifest-[0-9a-f]{24}$/);
        }
      },
    });
    assert.deepEqual(steps.map(({ step }) => step), [
      'artifact_partial_ready',
      'manifest_partial_ready',
      'artifact_published',
      'manifest_published',
      'pair_verified',
    ]);
    assert.deepEqual(readdirSync(out).sort(), [
      path.basename(created.backupPath),
      path.basename(created.manifestPath),
    ].sort());

    const racedRoot = tempDir();
    const racedOut = path.join(racedRoot, 'backups');
    await assert.rejects(
      () => createV2Backup(racedRoot, {
        filenameNonce: 'fedcba654321',
        publicationHook(step, paths) {
          if (step === 'manifest_published') rmSync(paths.backupPath);
        },
      }),
      /published backup artifact|ENOENT/,
    );
    assert.deepEqual(readdirSync(racedOut), [], 'failed pair verification must remove the completion marker');

    const tamperedRoot = tempDir();
    const tamperedOut = path.join(tamperedRoot, 'backups');
    await assert.rejects(
      () => createV2Backup(tamperedRoot, {
        filenameNonce: '012345abcdef',
        publicationHook(step, paths) {
          if (step === 'manifest_published') writeFileSync(paths.manifestPath, '{}\n', { mode: 0o600 });
        },
      }),
      /published manifest/,
    );
    assert.deepEqual(readdirSync(tamperedOut), [], 'tampered completion manifest must be removed with its artifact');

    const killedRoot = tempDir();
    const killedOut = path.join(killedRoot, 'backups');
    const input = path.join(killedRoot, 'input.dump');
    const child = path.join(killedRoot, 'kill-writer.mjs');
    writeFileSync(input, PG_CUSTOM_DUMP);
    writeFileSync(child, `
      import { backupPostgres } from ${JSON.stringify(new URL('../../scripts/postgres-backup.mjs', import.meta.url).href)};
      await backupPostgres({
        databaseReference: ${JSON.stringify(DATABASE_REFERENCE)},
        encryptionKey: Buffer.from(${JSON.stringify(TEST_KEY_HEX)}, 'hex'),
        out: ${JSON.stringify(killedOut)},
        label: null,
        filenameNonce: '123456abcdef',
        inputPath: ${JSON.stringify(input)},
        publicationHook(step) {
          if (step === 'artifact_published') process.kill(process.pid, 'SIGKILL');
        },
      });
    `);
    const killed = spawnSync(process.execPath, [child], { encoding: 'utf8' });
    assert.equal(killed.signal, 'SIGKILL', killed.stderr);
    const leftovers = readdirSync(killedOut);
    const finalArtifacts = leftovers.filter((name) => name.endsWith('.dump.enc'));
    const finalManifests = leftovers.filter((name) => name.endsWith('.dump.enc.manifest.json'));
    assert.equal(finalArtifacts.length, 1, 'artifact rename happened before the injected SIGKILL');
    assert.deepEqual(finalManifests, [], 'manifest completion marker must not be published');
    assert.ok(leftovers.some((name) => name.startsWith('.') && name.includes('.partial-manifest-')));
    assert.equal(
      leftovers.some((name) => name.endsWith('.manifest.json') && !name.startsWith('.')),
      false,
      'no complete restore point is advertised after interruption',
    );
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
