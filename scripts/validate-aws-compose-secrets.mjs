#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  connectorJobPublicKeyFromPrivate,
  isConnectorJobPrivateKeyValid,
  isConnectorJobPublicKeyValid,
} from '../src/lib/connectorPollJobs.mjs';

function parseOptionalBoolean(raw, name) {
  if (raw === undefined || raw === null || String(raw).trim() === '') return false;
  const value = String(raw).trim();
  if (value === '1') return true;
  if (value === '0') return false;
  throw new Error(`aws-compose-secrets: ${name} must be 1 or 0 (got "${raw}").`);
}

function parseConnectorTenantBooleanMap(raw, name) {
  if (raw === undefined || raw === null || String(raw).trim() === '') return {};
  let parsed;
  try {
    parsed = JSON.parse(String(raw));
  } catch {
    throw new Error(
      `aws-compose-secrets: ${name} must be valid JSON object mapping tenant_id to 0/1 or boolean.`,
    );
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(
      `aws-compose-secrets: ${name} must be a JSON object mapping tenant_id to 0/1 or boolean.`,
    );
  }
  const out = {};
  for (const [tenantId, value] of Object.entries(parsed)) {
    const key = String(tenantId ?? '').trim();
    if (!key) {
      throw new Error(`aws-compose-secrets: ${name} keys must be non-empty tenant ids.`);
    }
    if (value === true || value === 1 || value === '1') {
      out[key] = true;
      continue;
    }
    if (value === false || value === 0 || value === '0') {
      out[key] = false;
      continue;
    }
    throw new Error(
      `aws-compose-secrets: ${name} value for tenant "${key}" must be boolean or 0/1.`,
    );
  }
  return out;
}

export function connectorWorkloadsEnabled(environment) {
  const defaultEnabled = parseOptionalBoolean(
    environment.ASTRANULL_CONNECTORS_ENABLED,
    'ASTRANULL_CONNECTORS_ENABLED',
  );
  const tenantOverrides = parseConnectorTenantBooleanMap(
    environment.ASTRANULL_CONNECTORS_ENABLED_TENANTS,
    'ASTRANULL_CONNECTORS_ENABLED_TENANTS',
  );
  return defaultEnabled || Object.values(tenantOverrides).some((enabled) => enabled === true);
}

export function wafPostureEnabled(environment) {
  return parseOptionalBoolean(
    environment.ASTRANULL_WAF_POSTURE_ENABLED,
    'ASTRANULL_WAF_POSTURE_ENABLED',
  );
}

const HEX_32_BYTES = /^[a-fA-F0-9]{64}$/;
const FULL_LOCAL_IMAGE_ID = /^sha256:[0-9a-f]{64}$/;
const APP_IMAGE_GROUPS = {
  control: ['control-plane'],
  core: [
    'migrate',
    'backup-role-bootstrap',
    'backup',
    'probe-worker',
    'password-recovery-worker',
    'test-policy-runner',
  ],
  connector: ['connector-poll-scheduler', 'connector-poll-runner'],
};

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
  return { parsed, username, password };
}

function exactOwnerRestoreCredential(value, label, databaseName, ownerPassword) {
  const credential = databaseCredential(value, label, 'astranull');
  const { parsed } = credential;
  if (credential.password !== ownerPassword
    || parsed.protocol !== 'postgresql:'
    || parsed.hostname !== 'postgres'
    || parsed.port !== '5432'
    || parsed.pathname !== `/${databaseName}`
    || parsed.search !== ''
    || parsed.hash !== '') {
    throw new Error(
      `aws-compose-secrets: ${label} must be the exact owner URL for postgres:5432/${databaseName}.`,
    );
  }
  return credential;
}

export function validateAwsComposeSecretModel(model) {
  const services = model?.services ?? {};
  const environment = (name) => services[name]?.environment ?? {};
  for (const required of [
    'postgres', 'migrate', 'backup-role-bootstrap', 'backup-dump', 'restore-db', 'backup',
    'control-plane', 'probe-worker', 'password-recovery-worker', 'test-policy-runner',
    'connector-poll-scheduler', 'connector-poll-runner',
  ]) {
    if (!services[required]) throw new Error(`aws-compose-secrets: missing ${required} service.`);
  }
  for (const [group, names] of Object.entries(APP_IMAGE_GROUPS)) {
    const imageIds = names.map((name) => services[name].image);
    for (const [index, imageId] of imageIds.entries()) {
      if (!FULL_LOCAL_IMAGE_ID.test(String(imageId ?? ''))) {
        throw new Error(
          `aws-compose-secrets: ${names[index]} must use a full local sha256 image ID.`,
        );
      }
    }
    if (new Set(imageIds).size !== 1) {
      throw new Error(`aws-compose-secrets: ${group} image group must use one exact image ID.`);
    }
  }

  const postgres = environment('postgres');
  const migrate = environment('migrate');
  const bootstrap = environment('backup-role-bootstrap');
  const dump = environment('backup-dump');
  const restoreDatabase = environment('restore-db');
  const encryption = environment('backup');
  const control = environment('control-plane');
  const connectorScheduler = environment('connector-poll-scheduler');
  const connectorWorker = environment('connector-poll-runner');
  const connectorsEnabled = connectorWorkloadsEnabled(control);
  const controlWafEnabled = wafPostureEnabled(control);
  const schedulerWafEnabled = wafPostureEnabled(connectorScheduler);
  const workerWafEnabled = wafPostureEnabled(connectorWorker);

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
  exactOwnerRestoreCredential(
    restoreDatabase.ASTRANULL_MAINTENANCE_DATABASE_URL,
    'restore maintenance URL',
    'postgres',
    owner.password,
  );
  exactOwnerRestoreCredential(
    restoreDatabase.ASTRANULL_RESTORE_DATABASE_URL,
    'restore target URL',
    'astranull',
    owner.password,
  );
  const appPassword = String(migrate.ASTRANULL_DATABASE_APP_PASSWORD ?? '');
  const backupDbPassword = String(migrate.ASTRANULL_DATABASE_BACKUP_PASSWORD ?? '');
  const runtime = databaseCredential(
    control.ASTRANULL_DATABASE_URL,
    'runtime URL',
    'astranull_app',
  );
  const bootstrapOwner = databaseCredential(
    bootstrap.ASTRANULL_ADMIN_DATABASE_URL,
    'backup bootstrap admin URL',
    'astranull',
  );
  const backupDump = databaseCredential(
    dump.ASTRANULL_BACKUP_DATABASE_URL,
    'backup dump URL',
    'astranull_backup',
  );
  const backupEncryptionKey = String(encryption.ASTRANULL_BACKUP_ENCRYPTION_KEY ?? '');
  const envelopeEncryptionKey = String(control.ASTRANULL_SECRET_ENCRYPTION_KEY ?? '');
  const connectorEncryptionKey = String(control.ASTRANULL_CONNECTOR_SECRET_ENCRYPTION_KEY ?? '');
  const connectorJobPrivateKey = String(control.ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY ?? '');
  const connectorJobPublicKey = String(connectorWorker.ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY ?? '');
  const connectorSchedulerPassword = String(
    migrate.ASTRANULL_DATABASE_CONNECTOR_SCHEDULER_PASSWORD ?? '',
  );
  const connectorWorkerPassword = String(
    migrate.ASTRANULL_DATABASE_CONNECTOR_WORKER_PASSWORD ?? '',
  );
  const schedulerDatabase = databaseCredential(
    connectorScheduler.ASTRANULL_DATABASE_URL,
    'connector scheduler runtime URL',
    'astranull_connector_scheduler',
  );
  const workerDatabase = databaseCredential(
    connectorWorker.ASTRANULL_DATABASE_URL,
    'connector worker runtime URL',
    'astranull_connector_worker',
  );

  if (controlWafEnabled !== schedulerWafEnabled || controlWafEnabled !== workerWafEnabled) {
    throw new Error(
      'aws-compose-secrets: ASTRANULL_WAF_POSTURE_ENABLED must match across control-plane and connector services.',
    );
  }
  if (connectorsEnabled && !controlWafEnabled) {
    throw new Error(
      'aws-compose-secrets: connectors cannot be enabled while WAF posture is disabled.',
    );
  }
  const restoreDatabaseKeys = Object.keys(restoreDatabase).sort();
  if (restoreDatabaseKeys.length !== 2
    || restoreDatabaseKeys[0] !== 'ASTRANULL_MAINTENANCE_DATABASE_URL'
    || restoreDatabaseKeys[1] !== 'ASTRANULL_RESTORE_DATABASE_URL') {
    throw new Error(
      'aws-compose-secrets: restore-db may receive only exact owner maintenance and restore URLs.',
    );
  }

  const coreSecrets = {
    ownerPassword: owner.password,
    appPassword,
    backupDbPassword,
    backupEncryptionKey,
    envelopeEncryptionKey,
  };
  const connectorSecrets = {
    connectorSchedulerPassword,
    connectorWorkerPassword,
    connectorEncryptionKey,
  };
  const requiredSecrets = connectorsEnabled
    ? { ...coreSecrets, ...connectorSecrets }
    : coreSecrets;
  for (const [name, value] of Object.entries(requiredSecrets)) {
    if (!HEX_32_BYTES.test(value)) {
      throw new Error(`aws-compose-secrets: ${name} must be exactly 64 hexadecimal characters.`);
    }
  }
  if (connectorsEnabled && !isConnectorJobPrivateKeyValid(connectorJobPrivateKey)) {
    throw new Error('aws-compose-secrets: connector control plane must receive a base64 DER Ed25519 PKCS8 private key.');
  }
  if (connectorsEnabled && !isConnectorJobPublicKeyValid(connectorJobPublicKey)) {
    throw new Error('aws-compose-secrets: connector worker must receive a base64 DER Ed25519 SPKI public key.');
  }
  if (connectorsEnabled
    && connectorJobPublicKeyFromPrivate(connectorJobPrivateKey) !== connectorJobPublicKey) {
    throw new Error('aws-compose-secrets: connector signer and verifier keys must be one matching Ed25519 keypair.');
  }
  if (connectorScheduler.ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY !== connectorJobPrivateKey
    || 'ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY' in connectorScheduler
    || 'ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY' in connectorWorker
    || 'ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY' in control) {
    throw new Error('aws-compose-secrets: connector private key must be signer-only and public key verifier-only.');
  }
  if (connectorsEnabled && (
    schedulerDatabase.password !== connectorSchedulerPassword
    || workerDatabase.password !== connectorWorkerPassword
  )) {
    throw new Error('aws-compose-secrets: connector services must use their configured dedicated role passwords.');
  }
  if (!connectorsEnabled && (
    connectorSchedulerPassword || connectorWorkerPassword || schedulerDatabase.password
    || workerDatabase.password || connectorEncryptionKey || connectorJobPrivateKey
    || connectorJobPublicKey
  )) {
    throw new Error('aws-compose-secrets: disabled connector deployment must not project connector credentials.');
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
  if (
    bootstrapOwner.password !== owner.password
    || bootstrap.ASTRANULL_DATABASE_BACKUP_PASSWORD !== backupDbPassword
  ) {
    throw new Error('aws-compose-secrets: backup role bootstrap credentials do not match owner and backup role secrets.');
  }
  const allowedBootstrapKeys = new Set([
    'NODE_ENV',
    'ASTRANULL_ADMIN_DATABASE_URL',
    'ASTRANULL_DATABASE_BACKUP_PASSWORD',
  ]);
  if (Object.keys(bootstrap).some((key) => !allowedBootstrapKeys.has(key))) {
    throw new Error('aws-compose-secrets: backup role bootstrap has an unexpected environment field.');
  }
  if (new Set(Object.values(requiredSecrets)).size !== Object.keys(requiredSecrets).length) {
    throw new Error(
      'aws-compose-secrets: every configured database and encryption purpose must use a distinct secret.',
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
    'ASTRANULL_DATABASE_CONNECTOR_SCHEDULER_PASSWORD',
    'ASTRANULL_DATABASE_CONNECTOR_WORKER_PASSWORD',
    'ASTRANULL_BACKUP_DATABASE_URL',
    'ASTRANULL_BACKUP_ENCRYPTION_KEY',
  ]);
  for (const name of [
    'control-plane', 'probe-worker', 'password-recovery-worker', 'test-policy-runner',
    'connector-poll-scheduler', 'connector-poll-runner',
  ]) {
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

  const connectorCommonKeys = [
    'NODE_ENV',
    'ASTRANULL_PERSISTENCE_MODE',
    'ASTRANULL_DATABASE_URL',
    'ASTRANULL_ENFORCE_DATABASE_ROLE',
    'ASTRANULL_WAF_POSTURE_ENABLED',
    'ASTRANULL_CONNECTORS_ENABLED',
    'ASTRANULL_CONNECTORS_ENABLED_TENANTS',
    'ASTRANULL_CONNECTOR_POLL_TENANT_IDS',
    'ASTRANULL_CONNECTOR_POLL_CONCURRENCY',
  ];
  const schedulerKeys = new Set([
    ...connectorCommonKeys,
    'ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY',
    'ASTRANULL_CONNECTOR_SCHEDULER_INTERVAL_SECONDS',
  ]);
  const workerKeys = new Set([
    ...connectorCommonKeys,
    'ASTRANULL_CONNECTOR_SECRET_ENCRYPTION_KEY',
    'ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY',
    'ASTRANULL_CONNECTOR_WORKER_ID',
    'ASTRANULL_CONNECTOR_POLL_INTERVAL_SECONDS',
  ]);
  if (Object.keys(connectorScheduler).some((key) => !schedulerKeys.has(key))) {
    throw new Error('aws-compose-secrets: connector scheduler has an unexpected environment field.');
  }
  if (Object.keys(connectorWorker).some((key) => !workerKeys.has(key))) {
    throw new Error('aws-compose-secrets: connector worker has an unexpected environment field.');
  }
  if ('ASTRANULL_SECRET_ENCRYPTION_KEY' in connectorScheduler) {
    throw new Error('aws-compose-secrets: connector scheduler must not receive the envelope encryption key.');
  }
  if ('ASTRANULL_SECRET_ENCRYPTION_KEY' in connectorWorker) {
    throw new Error('aws-compose-secrets: connector worker must not receive the global envelope key.');
  }
  if (connectorWorker.ASTRANULL_CONNECTOR_SECRET_ENCRYPTION_KEY !== connectorEncryptionKey) {
    throw new Error('aws-compose-secrets: connector worker key differs from the control-plane connector encryption key.');
  }
  return true;
}

export function validatedAwsComposeConnectorMode(model) {
  validateAwsComposeSecretModel(model);
  const controlEnvironment = model.services['control-plane'].environment ?? {};
  return connectorWorkloadsEnabled(controlEnvironment) ? 'enabled' : 'disabled';
}

export async function main(argv = process.argv.slice(2)) {
  const printConnectorMode = argv.length === 1 && argv[0] === '--print-connector-mode';
  if (argv.length > 0 && !printConnectorMode) {
    throw new Error('aws-compose-secrets: usage: validate-aws-compose-secrets.mjs [--print-connector-mode]');
  }

  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  let model;
  try {
    model = JSON.parse(input);
  } catch {
    throw new Error('aws-compose-secrets: expected rendered Compose JSON on stdin.');
  }
  if (printConnectorMode) {
    console.log(validatedAwsComposeConnectorMode(model));
  } else {
    validateAwsComposeSecretModel(model);
    console.log('aws-compose-secrets: ok');
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
