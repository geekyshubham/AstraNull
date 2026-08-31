#!/usr/bin/env node
/**
 * Provision purpose-specific non-owner roles after owner-run migrations.
 * This command receives the admin URL only inside the one-shot migration service;
 * runtime and backup-encryption services never receive it.
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';
import { closePgPool, createPgPool } from '../src/persistence/postgres/pool.mjs';

export const DEFAULT_APP_ROLE = 'astranull_app';
export const DEFAULT_BACKUP_ROLE = 'astranull_backup';
export const DEFAULT_CONNECTOR_SCHEDULER_ROLE = 'astranull_connector_scheduler';
export const DEFAULT_CONNECTOR_WORKER_ROLE = 'astranull_connector_worker';

function validateDeploymentPassword(value, variableName) {
  const password = String(value ?? '').trim();
  if (!/^[A-Fa-f0-9]{64}$/.test(password)) {
    throw new Error(
      `postgres-grant-app-role: ${variableName} must be exactly 32 bytes encoded as 64 hex characters.`,
    );
  }
  return password;
}

export function validatePostgresAppRolePassword(value) {
  return validateDeploymentPassword(value, 'ASTRANULL_DATABASE_APP_PASSWORD');
}

export function validatePostgresBackupRolePassword(value) {
  return validateDeploymentPassword(value, 'ASTRANULL_DATABASE_BACKUP_PASSWORD');
}

export function validatePostgresConnectorSchedulerRolePassword(value) {
  return validateDeploymentPassword(value, 'ASTRANULL_DATABASE_CONNECTOR_SCHEDULER_PASSWORD');
}

export function validatePostgresConnectorWorkerRolePassword(value) {
  return validateDeploymentPassword(value, 'ASTRANULL_DATABASE_CONNECTOR_WORKER_PASSWORD');
}

function validateRoleName(roleName, label) {
  const normalized = String(roleName ?? '').trim();
  if (!/^[a-z_][a-z0-9_]*$/.test(normalized)) {
    throw new Error(`Invalid ${label} role name: ${roleName}`);
  }
  return normalized;
}

/**
 * @param {import('pg').Pool | import('pg').PoolClient} db
 * @param {string} [roleName]
 */
export async function grantPostgresAppRolePrivileges(db, roleName = DEFAULT_APP_ROLE) {
  const normalized = validateRoleName(roleName, 'application');
  const statements = [
    'GRANT USAGE ON SCHEMA public TO astranull_app',
    'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO astranull_app',
    'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO astranull_app',
    'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO astranull_app',
    'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO astranull_app',
  ].map((sql) => sql.replaceAll('astranull_app', normalized));

  for (const sql of statements) await db.query(sql);
}

/**
 * `pg_dump` must see all FORCE-RLS rows, so this narrowly scoped role has BYPASSRLS.
 * Its object ACLs are reset before SELECT is granted; it receives no mutation, schema
 * creation, ownership, superuser, role-management, or database-management authority.
 * @param {import('pg').Pool | import('pg').PoolClient} db
 * @param {string} [roleName]
 */
export async function grantPostgresBackupRolePrivileges(db, roleName = DEFAULT_BACKUP_ROLE) {
  const normalized = validateRoleName(roleName, 'backup');
  const statements = [
    'REVOKE CREATE ON SCHEMA public FROM astranull_backup',
    'GRANT USAGE ON SCHEMA public TO astranull_backup',
    'REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM astranull_backup',
    'GRANT SELECT ON ALL TABLES IN SCHEMA public TO astranull_backup',
    'REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM astranull_backup',
    'GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO astranull_backup',
    'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO astranull_backup',
    'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO astranull_backup',
  ].map((sql) => sql.replaceAll('astranull_backup', normalized));

  for (const sql of statements) await db.query(sql);
}

async function resetPurposeRolePrivileges(db, roleName) {
  const normalized = validateRoleName(roleName, 'connector runtime');
  await db.query(`REVOKE CREATE ON SCHEMA public FROM ${normalized}`);
  await db.query(`GRANT USAGE ON SCHEMA public TO ${normalized}`);
  await db.query(`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM ${normalized}`);
  await db.query(`REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM ${normalized}`);
  return normalized;
}

export async function grantPostgresConnectorSchedulerRolePrivileges(
  db,
  roleName = DEFAULT_CONNECTOR_SCHEDULER_ROLE,
) {
  const role = await resetPurposeRolePrivileges(db, roleName);
  await db.query(`GRANT SELECT, INSERT, UPDATE ON tenant_connector_features TO ${role}`);
  await db.query(`GRANT SELECT, UPDATE ON waf_connectors TO ${role}`);
  await db.query(`GRANT SELECT, INSERT, UPDATE ON connector_poll_jobs TO ${role}`);
  await db.query(`GRANT UPDATE ON probe_jobs TO ${role}`);
  await db.query(`GRANT SELECT ON encrypted_secrets TO ${role}`);
  await db.query(`GRANT SELECT, INSERT ON audit_logs TO ${role}`);
  await db.query(`GRANT SELECT, INSERT, UPDATE ON connector_provider_rate_limits TO ${role}`);
}

export async function grantPostgresConnectorWorkerRolePrivileges(
  db,
  roleName = DEFAULT_CONNECTOR_WORKER_ROLE,
) {
  const role = await resetPurposeRolePrivileges(db, roleName);
  await db.query(`GRANT SELECT ON tenant_connector_features TO ${role}`);
  await db.query(`GRANT SELECT, UPDATE ON waf_connectors TO ${role}`);
  await db.query(`GRANT SELECT, UPDATE ON connector_poll_jobs TO ${role}`);
  await db.query(`GRANT UPDATE ON probe_jobs TO ${role}`);
  await db.query(`GRANT SELECT ON encrypted_secrets TO ${role}`);
  await db.query(`GRANT SELECT, INSERT ON waf_connector_snapshots TO ${role}`);
  await db.query(`GRANT SELECT, INSERT ON audit_logs TO ${role}`);
}

async function provisionRolesTransaction(db, specs) {
  const client = typeof db.connect === 'function' ? await db.connect() : db;
  const ownsClient = client !== db && typeof client.release === 'function';
  let releaseError;
  let transactionStarted = false;

  try {
    await client.query('BEGIN');
    transactionStarted = true;
    const results = [];
    for (const spec of specs) {
      const exists = await client.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [spec.roleName]);
      if (exists.rows.length === 0) {
        await client.query(`CREATE ROLE ${spec.roleName} ${spec.attributes}`);
      }
      // Deployment passwords are exact hex before interpolation; PostgreSQL role DDL does
      // not accept a bind parameter. Role DDL and grants remain in this transaction.
      await client.query(
        `ALTER ROLE ${spec.roleName} WITH LOGIN PASSWORD '${spec.password}' ${spec.attributes}`,
      );
      await spec.grantPrivileges(client, spec.roleName);
      results.push({ role: spec.roleName, created: exists.rows.length === 0 });
    }
    await client.query('COMMIT');
    transactionStarted = false;
    return results;
  } catch (error) {
    if (transactionStarted) {
      try {
        await client.query('ROLLBACK');
      } catch (rollbackError) {
        releaseError = rollbackError instanceof Error
          ? rollbackError
          : new Error('postgres-grant-app-role: rollback failed');
      }
    }
    throw error;
  } finally {
    if (ownsClient) client.release(releaseError);
  }
}

function appRoleSpec(options) {
  return {
    roleName: validateRoleName(options.roleName ?? DEFAULT_APP_ROLE, 'application'),
    password: validatePostgresAppRolePassword(options.password),
    attributes: 'NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS',
    grantPrivileges: grantPostgresAppRolePrivileges,
  };
}

function backupRoleSpec(options) {
  return {
    roleName: validateRoleName(options.roleName ?? DEFAULT_BACKUP_ROLE, 'backup'),
    password: validatePostgresBackupRolePassword(options.password),
    attributes: 'NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS',
    grantPrivileges: grantPostgresBackupRolePrivileges,
  };
}

function connectorSchedulerRoleSpec(options) {
  return {
    roleName: validateRoleName(
      options.roleName ?? DEFAULT_CONNECTOR_SCHEDULER_ROLE,
      'connector scheduler',
    ),
    password: validatePostgresConnectorSchedulerRolePassword(options.password),
    attributes: 'NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS',
    grantPrivileges: grantPostgresConnectorSchedulerRolePrivileges,
  };
}

function connectorWorkerRoleSpec(options) {
  return {
    roleName: validateRoleName(
      options.roleName ?? DEFAULT_CONNECTOR_WORKER_ROLE,
      'connector worker',
    ),
    password: validatePostgresConnectorWorkerRolePassword(options.password),
    attributes: 'NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS',
    grantPrivileges: grantPostgresConnectorWorkerRolePrivileges,
  };
}

/** @param {import('pg').Pool | import('pg').PoolClient} db */
export async function provisionPostgresAppRole(db, options) {
  const [result] = await provisionRolesTransaction(db, [appRoleSpec(options)]);
  return result;
}

/** @param {import('pg').Pool | import('pg').PoolClient} db */
export async function provisionPostgresBackupRole(db, options) {
  const [result] = await provisionRolesTransaction(db, [backupRoleSpec(options)]);
  return result;
}

/** @param {import('pg').Pool | import('pg').PoolClient} db */
export async function provisionPostgresConnectorSchedulerRole(db, options) {
  const [result] = await provisionRolesTransaction(db, [connectorSchedulerRoleSpec(options)]);
  return result;
}

/** @param {import('pg').Pool | import('pg').PoolClient} db */
export async function provisionPostgresConnectorWorkerRole(db, options) {
  const [result] = await provisionRolesTransaction(db, [connectorWorkerRoleSpec(options)]);
  return result;
}

/** @param {import('pg').Pool | import('pg').PoolClient} db */
export async function provisionPostgresDatabaseRoles(db, options) {
  const specs = [
    appRoleSpec({ password: options.appPassword, roleName: options.appRoleName }),
    backupRoleSpec({ password: options.backupPassword, roleName: options.backupRoleName }),
  ];
  if (options.connectorSchedulerPassword || options.connectorWorkerPassword) {
    specs.push(
      connectorSchedulerRoleSpec({
        password: options.connectorSchedulerPassword,
        roleName: options.connectorSchedulerRoleName,
      }),
      connectorWorkerRoleSpec({
        password: options.connectorWorkerPassword,
        roleName: options.connectorWorkerRoleName,
      }),
    );
  }
  const [app, backup, connectorScheduler = null, connectorWorker = null] =
    await provisionRolesTransaction(db, specs);
  return { app, backup, connectorScheduler, connectorWorker };
}

export function resolvePostgresAppRoleConfig(env = process.env) {
  const adminUrl = String(env.ASTRANULL_ADMIN_DATABASE_URL ?? '').trim();
  if (!adminUrl) throw new Error('postgres-grant-app-role: ASTRANULL_ADMIN_DATABASE_URL is required.');
  const appPassword = validatePostgresAppRolePassword(env.ASTRANULL_DATABASE_APP_PASSWORD);
  const backupPassword = validatePostgresBackupRolePassword(env.ASTRANULL_DATABASE_BACKUP_PASSWORD);
  const rawConnectorSchedulerPassword = String(
    env.ASTRANULL_DATABASE_CONNECTOR_SCHEDULER_PASSWORD ?? '',
  ).trim();
  const rawConnectorWorkerPassword = String(
    env.ASTRANULL_DATABASE_CONNECTOR_WORKER_PASSWORD ?? '',
  ).trim();
  if (Boolean(rawConnectorSchedulerPassword) !== Boolean(rawConnectorWorkerPassword)) {
    throw new Error(
      'postgres-grant-app-role: connector scheduler and worker database passwords must be configured together.',
    );
  }
  const connectorSchedulerPassword = rawConnectorSchedulerPassword
    ? validatePostgresConnectorSchedulerRolePassword(rawConnectorSchedulerPassword)
    : null;
  const connectorWorkerPassword = rawConnectorWorkerPassword
    ? validatePostgresConnectorWorkerRolePassword(rawConnectorWorkerPassword)
    : null;
  let parsed;
  try {
    parsed = new URL(adminUrl);
  } catch {
    throw new Error('postgres-grant-app-role: ASTRANULL_ADMIN_DATABASE_URL must be a valid PostgreSQL URL.');
  }
  if (!['postgres:', 'postgresql:'].includes(parsed.protocol)) {
    throw new Error('postgres-grant-app-role: ASTRANULL_ADMIN_DATABASE_URL must be a valid PostgreSQL URL.');
  }
  const adminPassword = decodeURIComponent(parsed.password);
  const configuredPasswords = [
    adminPassword,
    appPassword,
    backupPassword,
    connectorSchedulerPassword,
    connectorWorkerPassword,
  ].filter(Boolean);
  if (!adminPassword || new Set(configuredPasswords).size !== configuredPasswords.length) {
    throw new Error(
      'postgres-grant-app-role: admin, application, backup, connector scheduler, and connector worker database passwords must be distinct.',
    );
  }
  return {
    adminUrl,
    appPassword,
    backupPassword,
    connectorSchedulerPassword,
    connectorWorkerPassword,
    password: appPassword,
  };
}

export function resolvePostgresBackupRoleConfig(env = process.env) {
  const adminUrl = String(env.ASTRANULL_ADMIN_DATABASE_URL ?? '').trim();
  if (!adminUrl) throw new Error('postgres-grant-app-role: ASTRANULL_ADMIN_DATABASE_URL is required.');
  const backupPassword = validatePostgresBackupRolePassword(env.ASTRANULL_DATABASE_BACKUP_PASSWORD);
  let parsed;
  try {
    parsed = new URL(adminUrl);
  } catch {
    throw new Error('postgres-grant-app-role: ASTRANULL_ADMIN_DATABASE_URL must be a valid PostgreSQL URL.');
  }
  if (!['postgres:', 'postgresql:'].includes(parsed.protocol)) {
    throw new Error('postgres-grant-app-role: ASTRANULL_ADMIN_DATABASE_URL must be a valid PostgreSQL URL.');
  }
  const adminPassword = decodeURIComponent(parsed.password);
  if (!adminPassword || adminPassword === backupPassword) {
    throw new Error('postgres-grant-app-role: admin and backup database passwords must be distinct.');
  }
  return { adminUrl, backupPassword };
}

export async function main(env = process.env, { backupOnly = false } = {}) {
  const config = backupOnly
    ? resolvePostgresBackupRoleConfig(env)
    : resolvePostgresAppRoleConfig(env);
  const pool = createPgPool({ ...env, ASTRANULL_DATABASE_URL: config.adminUrl });
  try {
    if (backupOnly) {
      const result = await provisionPostgresBackupRole(pool, { password: config.backupPassword });
      console.log(`postgres-grant-app-role: ok backup_role=${result.role} backup_created=${result.created}`);
      return;
    }
    const result = await provisionPostgresDatabaseRoles(pool, {
      appPassword: config.appPassword,
      backupPassword: config.backupPassword,
      connectorSchedulerPassword: config.connectorSchedulerPassword,
      connectorWorkerPassword: config.connectorWorkerPassword,
    });
    const connectorRoleSummary = result.connectorScheduler && result.connectorWorker
      ? ` connector_scheduler_role=${result.connectorScheduler.role}`
        + ` connector_scheduler_created=${result.connectorScheduler.created}`
        + ` connector_worker_role=${result.connectorWorker.role}`
        + ` connector_worker_created=${result.connectorWorker.created}`
      : ' connector_roles=disabled';
    console.log(
      `postgres-grant-app-role: ok app_role=${result.app.role} app_created=${result.app.created} `
      + `backup_role=${result.backup.role} backup_created=${result.backup.created}`
      + connectorRoleSummary,
    );
  } finally {
    await closePgPool(pool);
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  const args = process.argv.slice(2);
  const backupOnly = args.length === 1 && args[0] === '--backup-only';
  if (args.length > (backupOnly ? 1 : 0)) {
    console.error('postgres-grant-app-role: only --backup-only is supported.');
    process.exitCode = 2;
  } else {
    main(process.env, { backupOnly }).catch((error) => {
      console.error(redactDatabaseUrlInMessage(error, process.env));
      process.exitCode = 1;
    });
  }
}
