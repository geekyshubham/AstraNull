import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { provisionPostgresDatabaseRoles } from '../../scripts/postgres-grant-app-role.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const APP_PASSWORD = '1'.repeat(64);
const BACKUP_PASSWORD = '2'.repeat(64);

describe('postgres backup role privileges', () => {
  it('reads complete FORCE-RLS data but cannot mutate it', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      const suffix = Math.random().toString(36).slice(2, 10);
      const appRole = `astranull_app_test_${suffix}`;
      const backupRole = `astranull_backup_test_${suffix}`;
      let rolesCreated = false;
      try {
        await provisionPostgresDatabaseRoles(pool, {
          appPassword: APP_PASSWORD,
          backupPassword: BACKUP_PASSWORD,
          appRoleName: appRole,
          backupRoleName: backupRole,
        });
        rolesCreated = true;

        const roleRows = await pool.query(
          `SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolinherit, rolbypassrls
           FROM pg_roles WHERE rolname = ANY($1::text[]) ORDER BY rolname`,
          [[appRole, backupRole]],
        );
        assert.equal(roleRows.rows.length, 2);
        const app = roleRows.rows.find((row) => row.rolname === appRole);
        const backup = roleRows.rows.find((row) => row.rolname === backupRole);
        assert.deepEqual(
          [app.rolsuper, app.rolcreatedb, app.rolcreaterole, app.rolinherit, app.rolbypassrls],
          [false, false, false, false, false],
        );
        assert.deepEqual(
          [backup.rolsuper, backup.rolcreatedb, backup.rolcreaterole, backup.rolinherit, backup.rolbypassrls],
          [false, false, false, false, true],
        );

        const grants = await pool.query(
          `SELECT DISTINCT privilege_type
           FROM information_schema.role_table_grants
           WHERE grantee = $1 ORDER BY privilege_type`,
          [backupRole],
        );
        assert.deepEqual(grants.rows.map((row) => row.privilege_type), ['SELECT']);

        await pool.query(
          `INSERT INTO tenants (id, name) VALUES ('ten_backup_role', 'backup role proof')`,
        );
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          await client.query(`SET LOCAL ROLE ${backupRole}`);
          const visible = await client.query(
            `SELECT count(*)::int AS count FROM tenants WHERE id = 'ten_backup_role'`,
          );
          assert.equal(visible.rows[0].count, 1, 'BYPASSRLS must expose all backed-up tenant rows');
          await assert.rejects(
            client.query(`DELETE FROM tenants WHERE id = 'ten_backup_role'`),
            (error) => error?.code === '42501',
          );
          await client.query('ROLLBACK');
        } finally {
          client.release();
        }
      } finally {
        if (rolesCreated) {
          await pool.query(`DROP OWNED BY ${appRole}, ${backupRole}`);
          await pool.query(`DROP ROLE ${appRole}, ${backupRole}`);
        }
      }
    }, availability.env ?? process.env);
  });
});
