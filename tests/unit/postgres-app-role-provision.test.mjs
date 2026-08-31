import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  provisionPostgresAppRole,
  provisionPostgresBackupRole,
  provisionPostgresConnectorSchedulerRole,
  provisionPostgresConnectorWorkerRole,
  provisionPostgresDatabaseRoles,
  resolvePostgresAppRoleConfig,
  resolvePostgresBackupRoleConfig,
  validatePostgresAppRolePassword,
  validatePostgresBackupRolePassword,
  validatePostgresConnectorSchedulerRolePassword,
  validatePostgresConnectorWorkerRolePassword,
} from '../../scripts/postgres-grant-app-role.mjs';

const APP_PASSWORD = 'a'.repeat(64);
const BACKUP_PASSWORD = 'b'.repeat(64);
const OWNER_PASSWORD = 'c'.repeat(64);
const SCHEDULER_PASSWORD = 'd'.repeat(64);
const WORKER_PASSWORD = 'e'.repeat(64);

function fakePool({ existingRoles = [], failOn = null, rollbackFails = false } = {}) {
  const calls = [];
  const releases = [];
  let connectCount = 0;
  const client = {
    async query(text, params) {
      calls.push({ text, params });
      if (text === 'ROLLBACK' && rollbackFails) throw new Error('rollback connection failure');
      if (failOn?.test(text)) throw new Error('injected grant failure');
      if (text.startsWith('SELECT 1 FROM pg_roles')) {
        return { rows: existingRoles.includes(params[0]) ? [{ '?column?': 1 }] : [] };
      }
      return { rows: [] };
    },
    release(error) { releases.push(error); },
  };
  return {
    calls,
    releases,
    connectCount: () => connectCount,
    async query() { throw new Error('pool.query must not be used for transactional provisioning'); },
    async connect() { connectCount += 1; return client; },
  };
}

describe('Postgres purpose-specific role provisioning', () => {
  it('creates, rotates, and grants the app role on one transaction/client', async () => {
    const db = fakePool();
    const result = await provisionPostgresAppRole(db, { password: APP_PASSWORD });
    const statements = db.calls.map((call) => call.text);
    assert.deepEqual(result, { role: 'astranull_app', created: true });
    assert.equal(db.connectCount(), 1);
    assert.equal(statements[0], 'BEGIN');
    assert.match(statements.find((text) => text.startsWith('CREATE ROLE')), /astranull_app[\s\S]*NOBYPASSRLS/);
    assert.match(statements.find((text) => text.startsWith('ALTER ROLE')), /astranull_app[\s\S]*NOBYPASSRLS/);
    assert.ok(statements.some((text) => /GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES/.test(text)));
    assert.equal(statements.at(-1), 'COMMIT');
    assert.deepEqual(db.releases, [undefined]);
  });

  it('provisions astranull_backup with BYPASSRLS and reset SELECT-only object ACLs', async () => {
    const db = fakePool();
    const result = await provisionPostgresBackupRole(db, { password: BACKUP_PASSWORD });
    const statements = db.calls.map((call) => call.text);
    assert.deepEqual(result, { role: 'astranull_backup', created: true });
    assert.match(
      statements.find((text) => text.startsWith('CREATE ROLE')),
      /astranull_backup NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS/,
    );
    assert.match(
      statements.find((text) => text.startsWith('ALTER ROLE')),
      /astranull_backup[\s\S]*NOSUPERUSER[\s\S]*BYPASSRLS/,
    );
    const revokeTables = statements.indexOf(
      'REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM astranull_backup',
    );
    const grantTables = statements.indexOf(
      'GRANT SELECT ON ALL TABLES IN SCHEMA public TO astranull_backup',
    );
    assert.ok(revokeTables > 0 && grantTables > revokeTables);
    assert.ok(statements.includes('REVOKE CREATE ON SCHEMA public FROM astranull_backup'));
    assert.equal(
      statements.some((text) => /^GRANT\s+.*(?:INSERT|UPDATE|DELETE|TRUNCATE|TRIGGER)/.test(text)),
      false,
    );
  });

  it('provisions connector scheduler and worker with disjoint least-privilege ACLs', async () => {
    const schedulerDb = fakePool();
    const workerDb = fakePool();
    await provisionPostgresConnectorSchedulerRole(schedulerDb, { password: SCHEDULER_PASSWORD });
    await provisionPostgresConnectorWorkerRole(workerDb, { password: WORKER_PASSWORD });
    const scheduler = schedulerDb.calls.map((call) => call.text);
    const worker = workerDb.calls.map((call) => call.text);

    assert.match(scheduler.find((text) => text.startsWith('CREATE ROLE')), /astranull_connector_scheduler[\s\S]*NOBYPASSRLS/);
    assert.ok(scheduler.includes(
      'GRANT SELECT, INSERT, UPDATE ON connector_provider_rate_limits TO astranull_connector_scheduler',
    ));
    assert.ok(scheduler.includes(
      'GRANT SELECT, INSERT, UPDATE ON connector_poll_jobs TO astranull_connector_scheduler',
    ));
    assert.equal(scheduler.some((text) => /waf_connector_snapshots TO astranull_connector_scheduler/.test(text)), false);

    assert.match(worker.find((text) => text.startsWith('CREATE ROLE')), /astranull_connector_worker[\s\S]*NOBYPASSRLS/);
    assert.ok(worker.includes(
      'GRANT SELECT, INSERT ON waf_connector_snapshots TO astranull_connector_worker',
    ));
    assert.ok(worker.includes(
      'GRANT SELECT, UPDATE ON connector_poll_jobs TO astranull_connector_worker',
    ));
    assert.equal(worker.some((text) => /connector_provider_rate_limits TO astranull_connector_worker/.test(text)), false);
    assert.equal(worker.some((text) => /INSERT, UPDATE ON tenant_connector_features/.test(text)), false);
  });

  it('provisions app and backup roles atomically in one transaction', async () => {
    const db = fakePool({ existingRoles: ['astranull_app'] });
    const result = await provisionPostgresDatabaseRoles(db, {
      appPassword: APP_PASSWORD,
      backupPassword: BACKUP_PASSWORD,
    });
    const statements = db.calls.map((call) => call.text);
    assert.deepEqual(result, {
      app: { role: 'astranull_app', created: false },
      backup: { role: 'astranull_backup', created: true },
      connectorScheduler: null,
      connectorWorker: null,
    });
    assert.equal(statements.filter((text) => text === 'BEGIN').length, 1);
    assert.equal(statements.filter((text) => text === 'COMMIT').length, 1);
    assert.equal(statements.at(-1), 'COMMIT');
    assert.equal(db.connectCount(), 1);
  });

  it('rolls both role changes back when any grant fails', async () => {
    const db = fakePool({ failOn: /GRANT SELECT ON ALL TABLES.*astranull_backup/ });
    await assert.rejects(
      () => provisionPostgresDatabaseRoles(db, {
        appPassword: APP_PASSWORD,
        backupPassword: BACKUP_PASSWORD,
      }),
      /injected grant failure/,
    );
    const statements = db.calls.map((call) => call.text);
    assert.equal(statements.includes('COMMIT'), false);
    assert.equal(statements.at(-1), 'ROLLBACK');
    assert.deepEqual(db.releases, [undefined]);
  });

  it('destroys a client that cannot roll back', async () => {
    const db = fakePool({ failOn: /^GRANT SELECT, INSERT/, rollbackFails: true });
    await assert.rejects(
      () => provisionPostgresAppRole(db, { password: APP_PASSWORD }),
      /injected grant failure/,
    );
    assert.equal(db.releases.length, 1);
    assert.match(db.releases[0]?.message ?? '', /rollback connection failure/);
  });

  it('requires three distinct database credentials', () => {
    const config = resolvePostgresAppRoleConfig({
      ASTRANULL_ADMIN_DATABASE_URL: `postgresql://astranull:${OWNER_PASSWORD}@postgres/astranull`,
      ASTRANULL_DATABASE_APP_PASSWORD: APP_PASSWORD,
      ASTRANULL_DATABASE_BACKUP_PASSWORD: BACKUP_PASSWORD,
    });
    assert.equal(config.appPassword, APP_PASSWORD);
    assert.equal(config.backupPassword, BACKUP_PASSWORD);
    assert.equal(config.connectorSchedulerPassword, null);
    assert.equal(config.connectorWorkerPassword, null);
    const connectorConfig = resolvePostgresAppRoleConfig({
      ASTRANULL_ADMIN_DATABASE_URL: `postgresql://astranull:${OWNER_PASSWORD}@postgres/astranull`,
      ASTRANULL_DATABASE_APP_PASSWORD: APP_PASSWORD,
      ASTRANULL_DATABASE_BACKUP_PASSWORD: BACKUP_PASSWORD,
      ASTRANULL_DATABASE_CONNECTOR_SCHEDULER_PASSWORD: SCHEDULER_PASSWORD,
      ASTRANULL_DATABASE_CONNECTOR_WORKER_PASSWORD: WORKER_PASSWORD,
    });
    assert.equal(connectorConfig.connectorSchedulerPassword, SCHEDULER_PASSWORD);
    assert.equal(connectorConfig.connectorWorkerPassword, WORKER_PASSWORD);
    assert.throws(() => resolvePostgresAppRoleConfig({
      ASTRANULL_ADMIN_DATABASE_URL: `postgresql://astranull:${OWNER_PASSWORD}@postgres/astranull`,
      ASTRANULL_DATABASE_APP_PASSWORD: APP_PASSWORD,
      ASTRANULL_DATABASE_BACKUP_PASSWORD: BACKUP_PASSWORD,
      ASTRANULL_DATABASE_CONNECTOR_SCHEDULER_PASSWORD: SCHEDULER_PASSWORD,
    }), /configured together/);
    assert.throws(() => resolvePostgresAppRoleConfig({
      ASTRANULL_ADMIN_DATABASE_URL: `postgresql://astranull:${OWNER_PASSWORD}@postgres/astranull`,
      ASTRANULL_DATABASE_APP_PASSWORD: APP_PASSWORD,
      ASTRANULL_DATABASE_BACKUP_PASSWORD: BACKUP_PASSWORD,
      ASTRANULL_DATABASE_CONNECTOR_SCHEDULER_PASSWORD: APP_PASSWORD,
      ASTRANULL_DATABASE_CONNECTOR_WORKER_PASSWORD: WORKER_PASSWORD,
    }), /must be distinct/);
    for (const [appPassword, backupPassword] of [
      [OWNER_PASSWORD, BACKUP_PASSWORD],
      [APP_PASSWORD, OWNER_PASSWORD],
      [APP_PASSWORD, APP_PASSWORD],
    ]) {
      assert.throws(() => resolvePostgresAppRoleConfig({
        ASTRANULL_ADMIN_DATABASE_URL: `postgresql://astranull:${OWNER_PASSWORD}@postgres/astranull`,
        ASTRANULL_DATABASE_APP_PASSWORD: appPassword,
        ASTRANULL_DATABASE_BACKUP_PASSWORD: backupPassword,
      }), /must be distinct/);
    }
  });

  it('resolves backup-only bootstrap without an application credential', () => {
    const config = resolvePostgresBackupRoleConfig({
      ASTRANULL_ADMIN_DATABASE_URL: `postgresql://astranull:${OWNER_PASSWORD}@postgres/astranull`,
      ASTRANULL_DATABASE_BACKUP_PASSWORD: BACKUP_PASSWORD,
    });
    assert.equal(config.backupPassword, BACKUP_PASSWORD);
    assert.equal('appPassword' in config, false);
    assert.throws(() => resolvePostgresBackupRoleConfig({
      ASTRANULL_ADMIN_DATABASE_URL: `postgresql://astranull:${OWNER_PASSWORD}@postgres/astranull`,
      ASTRANULL_DATABASE_BACKUP_PASSWORD: OWNER_PASSWORD,
    }), /must be distinct/);
  });

  it('accepts only exact 32-byte hex deployment passwords', () => {
    assert.equal(validatePostgresAppRolePassword(APP_PASSWORD), APP_PASSWORD);
    assert.equal(validatePostgresBackupRolePassword(BACKUP_PASSWORD), BACKUP_PASSWORD);
    assert.equal(
      validatePostgresConnectorSchedulerRolePassword(SCHEDULER_PASSWORD),
      SCHEDULER_PASSWORD,
    );
    assert.equal(validatePostgresConnectorWorkerRolePassword(WORKER_PASSWORD), WORKER_PASSWORD);
    for (const invalid of ['', 'a'.repeat(63), 'z'.repeat(64), "a'.repeat(64)"]) {
      assert.throws(() => validatePostgresAppRolePassword(invalid), /64 hex/);
      assert.throws(() => validatePostgresBackupRolePassword(invalid), /64 hex/);
      assert.throws(() => validatePostgresConnectorSchedulerRolePassword(invalid), /64 hex/);
      assert.throws(() => validatePostgresConnectorWorkerRolePassword(invalid), /64 hex/);
    }
  });
});
