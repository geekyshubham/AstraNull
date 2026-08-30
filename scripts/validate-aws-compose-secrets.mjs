#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HEX_32_BYTES = /^[a-fA-F0-9]{64}$/;

function databaseCredential(value, label, expectedUser) {
  let parsed;
  try {
    parsed = new URL(String(value));
  } catch {
    throw new Error(`aws-compose-secrets: ${label} is not a valid database URL.`);
  }
  if (!['postgres:', 'postgresql:'].includes(parsed.protocol)) {
    throw new Error(`aws-compose-secrets: ${label} must use the PostgreSQL scheme.`);
  }
  const username = decodeURIComponent(parsed.username);
  const password = decodeURIComponent(parsed.password);
  if (username !== expectedUser) {
    throw new Error(`aws-compose-secrets: ${label} must authenticate as ${expectedUser}.`);
  }
  return { username, password };
}

export function validateAwsComposeSecretModel(model) {
  const services = model?.services ?? {};
  const environment = (name) => services[name]?.environment ?? {};
  for (const required of ['postgres', 'migrate', 'backup-dump', 'backup', 'control-plane']) {
    if (!services[required]) throw new Error(`aws-compose-secrets: missing ${required} service.`);
  }

  const postgres = environment('postgres');
  const migrate = environment('migrate');
  const dump = environment('backup-dump');
  const encryption = environment('backup');
  const control = environment('control-plane');

  const owner = databaseCredential(
    migrate.ASTRANULL_ADMIN_DATABASE_URL,
    'admin URL',
    'astranull',
  );
  const migrationOwner = databaseCredential(
    migrate.ASTRANULL_DATABASE_URL,
    'migration URL',
    'astranull',
  );
  const postgresPassword = String(postgres.POSTGRES_PASSWORD ?? '');
  const appPassword = String(migrate.ASTRANULL_DATABASE_APP_PASSWORD ?? '');
  const backupDbPassword = String(migrate.ASTRANULL_DATABASE_BACKUP_PASSWORD ?? '');
  const runtime = databaseCredential(
    control.ASTRANULL_DATABASE_URL,
    'runtime URL',
    'astranull_app',
  );
  const backupDump = databaseCredential(
    dump.ASTRANULL_BACKUP_DATABASE_URL,
    'backup dump URL',
    'astranull_backup',
  );
  const backupEncryptionKey = String(encryption.ASTRANULL_BACKUP_ENCRYPTION_KEY ?? '');
  const envelopeEncryptionKey = String(control.ASTRANULL_SECRET_ENCRYPTION_KEY ?? '');

  const fiveSecrets = {
    ownerPassword: owner.password,
    appPassword,
    backupDbPassword,
    backupEncryptionKey,
    envelopeEncryptionKey,
  };
  for (const [name, value] of Object.entries(fiveSecrets)) {
    if (!HEX_32_BYTES.test(value)) {
      throw new Error(`aws-compose-secrets: ${name} must be exactly 64 hexadecimal characters.`);
    }
  }
  if (migrationOwner.password !== owner.password || postgresPassword !== owner.password) {
    throw new Error(
      'aws-compose-secrets: Postgres initialization, migration, and admin owner passwords must match.',
    );
  }
  if (runtime.password !== appPassword) {
    throw new Error('aws-compose-secrets: runtime URL does not use the configured app password.');
  }
  if (backupDump.password !== backupDbPassword) {
    throw new Error('aws-compose-secrets: backup dump URL does not use the configured backup password.');
  }
  if (new Set(Object.values(fiveSecrets)).size !== 5) {
    throw new Error(
      'aws-compose-secrets: owner DB, app DB, backup DB, backup encryption, and envelope encryption secrets must all be distinct.',
    );
  }

  const dumpKeys = Object.keys(dump).sort();
  if (dumpKeys.length !== 1 || dumpKeys[0] !== 'ASTRANULL_BACKUP_DATABASE_URL') {
    throw new Error('aws-compose-secrets: backup-dump may receive only its backup database URL.');
  }
  const encryptionCredentialKeys = Object.keys(encryption).filter((key) =>
    /DATABASE|POSTGRES|PASSWORD|SECRET_ENCRYPTION/i.test(key),
  );
  if (encryptionCredentialKeys.length > 0) {
    throw new Error('aws-compose-secrets: backup encryption service must not receive a database or envelope credential.');
  }
  const allowedEncryptionKeys = new Set(['NODE_ENV', 'ASTRANULL_BACKUP_ENCRYPTION_KEY']);
  if (Object.keys(encryption).some((key) => !allowedEncryptionKeys.has(key))) {
    throw new Error('aws-compose-secrets: backup encryption service has an unexpected environment field.');
  }

  const operatorOnlyKeys = new Set([
    'POSTGRES_PASSWORD',
    'ASTRANULL_ADMIN_DATABASE_URL',
    'ASTRANULL_DATABASE_BACKUP_PASSWORD',
    'ASTRANULL_BACKUP_DATABASE_URL',
    'ASTRANULL_BACKUP_ENCRYPTION_KEY',
  ]);
  for (const name of ['control-plane', 'probe-worker', 'password-recovery-worker', 'test-policy-runner']) {
    const env = environment(name);
    if (Object.keys(env).some((key) => operatorOnlyKeys.has(key))) {
      throw new Error(`aws-compose-secrets: ${name} receives an operator-only credential.`);
    }
  }
  if ('ASTRANULL_BACKUP_ENCRYPTION_KEY' in migrate || 'ASTRANULL_SECRET_ENCRYPTION_KEY' in migrate) {
    throw new Error('aws-compose-secrets: migration service receives an encryption credential.');
  }
  const recoveryEnvelope = environment('password-recovery-worker').ASTRANULL_SECRET_ENCRYPTION_KEY;
  if (recoveryEnvelope !== undefined && recoveryEnvelope !== envelopeEncryptionKey) {
    throw new Error('aws-compose-secrets: recovery worker envelope key differs from the control-plane key.');
  }
  return true;
}

export async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  let model;
  try {
    model = JSON.parse(input);
  } catch {
    throw new Error('aws-compose-secrets: expected rendered Compose JSON on stdin.');
  }
  validateAwsComposeSecretModel(model);
  console.log('aws-compose-secrets: ok');
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
