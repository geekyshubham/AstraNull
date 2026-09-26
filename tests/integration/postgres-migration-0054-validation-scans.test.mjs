import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  assertRlsPoliciesExist,
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
  withTenantContextAsAppRole,
} from '../helpers/pg-harness.mjs';

const IDS = Object.freeze({
  tenantA: 'ten_scan_mig_a',
  tenantB: 'ten_scan_mig_b',
  environmentA: 'env_scan_mig_a',
  environmentB: 'env_scan_mig_b',
  groupA: 'tg_scan_mig_a',
  groupB: 'tg_scan_mig_b',
  targetA: 'tgt_scan_mig_a',
  targetB: 'tgt_scan_mig_b',
});

const REQUIRED_INDEXES = [
  'uniq_validation_scans_occurrence',
  'idx_validation_scans_due',
  'idx_validation_scans_runnable',
  'idx_validation_scans_tenant_group_created',
  'uniq_active_validation_scan_per_group',
  'uniq_validation_scan_steps_run',
  'idx_validation_scan_steps_scan',
  'uniq_test_runs_scan_step',
  'idx_audit_tenant_resource',
];

const REQUIRED_CONSTRAINTS = [
  'validation_scans_tenant_id_id_key',
  'validation_scan_steps_tenant_id_id_key',
  'fk_validation_scans_target_group_tenant',
  'fk_validation_scan_steps_scan_tenant',
  'fk_validation_scan_steps_test_run_tenant',
  'fk_test_runs_scan_tenant',
  'validation_scans_status_check',
  'validation_scans_scheduled_for_check',
  'validation_scans_lease_check',
  'validation_scans_recurrence_check',
  'validation_scans_cancelled_check',
  'validation_scan_steps_status_check',
];

async function seedFixtures(pool) {
  await pool.query(`INSERT INTO tenants (id, name) VALUES ($1, 'scan tenant A'), ($2, 'scan tenant B')`, [IDS.tenantA, IDS.tenantB]);
  await pool.query(
    `INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, 'prod A'), ($3, $4, 'prod B')`,
    [IDS.environmentA, IDS.tenantA, IDS.environmentB, IDS.tenantB],
  );
  await pool.query(
    `INSERT INTO target_groups (id, tenant_id, environment_id, name) VALUES ($1, $2, $3, 'group A'), ($4, $5, $6, 'group B')`,
    [IDS.groupA, IDS.tenantA, IDS.environmentA, IDS.groupB, IDS.tenantB, IDS.environmentB],
  );
  await pool.query(
    `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
     VALUES ($1, $2, $3, 'fqdn', 'a.scan.test', 'a.scan.test'), ($4, $5, $6, 'fqdn', 'b.scan.test', 'b.scan.test')`,
    [IDS.targetA, IDS.tenantA, IDS.groupA, IDS.targetB, IDS.tenantB, IDS.groupB],
  );
}

function scanInsert(id, tenantId, groupId, overrides = {}) {
  const row = {
    status: 'pending',
    scheduled_for: null,
    recurrence: null,
    lease_token: null,
    lease_owner: null,
    lease_expires_at: null,
    cancelled_at: null,
    occurrence_key: null,
    ...overrides,
  };
  return {
    text: `INSERT INTO validation_scans (
             id, tenant_id, target_group_id, status, check_ids, scheduled_for, recurrence,
             lease_token, lease_owner, lease_expires_at, cancelled_at, occurrence_key, created_by
           ) VALUES ($1, $2, $3, $4, '["waf.fingerprint.safe"]'::jsonb, $5::timestamptz, $6::jsonb,
             $7, $8, $9::timestamptz, $10::timestamptz, $11, 'usr_scan')
           RETURNING id, status`,
    values: [
      id, tenantId, groupId, row.status, row.scheduled_for,
      row.recurrence == null ? null : JSON.stringify(row.recurrence),
      row.lease_token, row.lease_owner, row.lease_expires_at, row.cancelled_at, row.occurrence_key,
    ],
  };
}

function rejectsWith(code, constraint) {
  return (error) => {
    assert.equal(error?.code, code, error?.message);
    if (constraint) assert.equal(error?.constraint, constraint);
    return true;
  };
}

describe('postgres migration 0054 validation scans', () => {
  it('creates tables, indexes, constraints, and RLS policies', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }
    await withEphemeralPostgres(async (pool) => {
      const tables = await pool.query(
        `SELECT table_name FROM information_schema.tables
         WHERE table_schema = 'public' AND table_name = ANY($1::text[]) ORDER BY table_name`,
        [['validation_scans', 'validation_scan_steps']],
      );
      assert.deepEqual(tables.rows.map((row) => row.table_name), ['validation_scan_steps', 'validation_scans']);

      const columns = await pool.query(
        `SELECT column_name FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'test_runs' AND column_name IN ('scan_id', 'scan_step_id')
         ORDER BY column_name`,
      );
      assert.deepEqual(columns.rows.map((row) => row.column_name), ['scan_id', 'scan_step_id']);

      const indexes = await pool.query(
        `SELECT indexname FROM pg_indexes WHERE schemaname = 'public' AND indexname = ANY($1::text[])`,
        [REQUIRED_INDEXES],
      );
      assert.deepEqual(indexes.rows.map((row) => row.indexname).sort(), [...REQUIRED_INDEXES].sort());

      const constraints = await pool.query(
        `SELECT conname FROM pg_constraint WHERE conname = ANY($1::text[])`,
        [REQUIRED_CONSTRAINTS],
      );
      assert.deepEqual(constraints.rows.map((row) => row.conname).sort(), [...REQUIRED_CONSTRAINTS].sort());

      const rls = await pool.query(
        `SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class
         WHERE relname IN ('validation_scans', 'validation_scan_steps') ORDER BY relname`,
      );
      assert.deepEqual(rls.rows, [
        { relname: 'validation_scan_steps', relrowsecurity: true, relforcerowsecurity: true },
        { relname: 'validation_scans', relrowsecurity: true, relforcerowsecurity: true },
      ]);
      await assertRlsPoliciesExist(pool, ['validation_scans_tenant_isolation', 'validation_scan_steps_tenant_isolation']);
    }, availability.env ?? process.env);
  });

  it('rejects malformed rows and enforces single active scan and single run per step', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }
    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedFixtures(pool);
      const run = (statement) => withTenantContextAsAppRole(pool, IDS.tenantA, (client) => client.query(statement.text, statement.values));

      await assert.rejects(() => run(scanInsert('scan_bad_status', IDS.tenantA, IDS.groupA, { status: 'paused' })), rejectsWith('23514', 'validation_scans_status_check'));
      await assert.rejects(() => run(scanInsert('scan_no_schedule', IDS.tenantA, IDS.groupA, { status: 'scheduled' })), rejectsWith('23514', 'validation_scans_scheduled_for_check'));
      await assert.rejects(() => run(scanInsert('scan_half_lease', IDS.tenantA, IDS.groupA, { lease_token: 'tok' })), rejectsWith('23514', 'validation_scans_lease_check'));
      await assert.rejects(() => run(scanInsert('scan_bad_cadence', IDS.tenantA, IDS.groupA, {
        status: 'scheduled', scheduled_for: '2030-01-01T00:00:00.000Z', recurrence: { cadence: 'hourly' },
      })), rejectsWith('23514', 'validation_scans_recurrence_check'));
      await assert.rejects(() => run(scanInsert('scan_cancel_mismatch', IDS.tenantA, IDS.groupA, { status: 'cancelled' })), rejectsWith('23514', 'validation_scans_cancelled_check'));
      await assert.rejects(() => run(scanInsert('scan_wrong_group', IDS.tenantA, IDS.groupB)), rejectsWith('23503', 'fk_validation_scans_target_group_tenant'));

      const first = await run(scanInsert('scan_active_1', IDS.tenantA, IDS.groupA));
      assert.equal(first.rows[0].status, 'pending');
      await assert.rejects(() => run(scanInsert('scan_active_2', IDS.tenantA, IDS.groupA, { status: 'running' })), rejectsWith('23505', 'uniq_active_validation_scan_per_group'));
      const scheduled = await run(scanInsert('scan_scheduled_ok', IDS.tenantA, IDS.groupA, {
        status: 'scheduled', scheduled_for: '2030-01-01T00:00:00.000Z', recurrence: { cadence: 'daily', timezone: 'UTC' }, occurrence_key: 'occ_1',
      }));
      assert.equal(scheduled.rows[0].status, 'scheduled');
      await assert.rejects(() => run(scanInsert('scan_dup_occurrence', IDS.tenantA, IDS.groupA, {
        status: 'scheduled', scheduled_for: '2030-01-02T00:00:00.000Z', occurrence_key: 'occ_1',
      })), rejectsWith('23505', 'uniq_validation_scans_occurrence'));

      await run({
        text: `INSERT INTO validation_scan_steps (id, tenant_id, scan_id, position, check_id, target_id, status, created_at, updated_at)
               VALUES ('step_1', $1, 'scan_active_1', 0, 'waf.fingerprint.safe', $2, 'starting', now(), now())`,
        values: [IDS.tenantA, IDS.targetA],
      });
      await assert.rejects(() => run({
        text: `INSERT INTO validation_scan_steps (id, tenant_id, scan_id, position, check_id, target_id, status, created_at, updated_at)
               VALUES ('step_bad_status', $1, 'scan_active_1', 1, 'waf.fingerprint.safe', $2, 'exploded', now(), now())`,
        values: [IDS.tenantA, IDS.targetA],
      }), rejectsWith('23514', 'validation_scan_steps_status_check'));
      await assert.rejects(() => run({
        text: `INSERT INTO validation_scan_steps (id, tenant_id, scan_id, position, check_id, target_id, created_at, updated_at)
               VALUES ('step_dup_position', $1, 'scan_active_1', 0, 'waf.fingerprint.safe', $2, now(), now())`,
        values: [IDS.tenantA, IDS.targetA],
      }), rejectsWith('23505', 'validation_scan_steps_tenant_scan_position_key'));

      const runInsert = (id, stepId) => ({
        text: `INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status, scan_id, scan_step_id)
               VALUES ($1, $2, $3, $4, 'waf.fingerprint.safe', 'verdicted', 'scan_active_1', $5)`,
        values: [id, IDS.tenantA, IDS.groupA, IDS.targetA, stepId],
      });
      await run(runInsert('run_step_1', 'step_1'));
      await assert.rejects(() => run(runInsert('run_step_1_dup', 'step_1')), rejectsWith('23505', 'uniq_test_runs_scan_step'));
      await assert.rejects(() => run({
        text: `INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status, scan_id)
               VALUES ('run_bad_scan', $1, $2, $3, 'waf.fingerprint.safe', 'verdicted', 'scan_missing')`,
        values: [IDS.tenantA, IDS.groupA, IDS.targetA],
      }), rejectsWith('23503', 'fk_test_runs_scan_tenant'));

      await run({ text: `UPDATE validation_scan_steps SET test_run_id = 'run_step_1' WHERE id = 'step_1'`, values: [] });
      await run({
        text: `INSERT INTO validation_scan_steps (id, tenant_id, scan_id, position, check_id, target_id, created_at, updated_at)
               VALUES ('step_2', $1, 'scan_active_1', 1, 'waf.fingerprint.safe', $2, now(), now())`,
        values: [IDS.tenantA, IDS.targetA],
      });
      await assert.rejects(() => run({
        text: `UPDATE validation_scan_steps SET test_run_id = 'run_step_1' WHERE id = 'step_2'`,
        values: [],
      }), rejectsWith('23505', 'uniq_validation_scan_steps_run'));
      await assert.rejects(() => run({
        text: `UPDATE validation_scan_steps SET test_run_id = 'run_missing' WHERE id = 'step_2'`,
        values: [],
      }), rejectsWith('23503', 'fk_validation_scan_steps_test_run_tenant'));

      await run({ text: `UPDATE test_runs SET scan_id = NULL, scan_step_id = NULL WHERE id = 'run_step_1'`, values: [] });
      await run({ text: `UPDATE validation_scan_steps SET test_run_id = NULL WHERE id = 'step_1'`, values: [] });
      await run({ text: `DELETE FROM validation_scans WHERE id = 'scan_active_1'`, values: [] });
      const remainingSteps = await run({ text: `SELECT id FROM validation_scan_steps WHERE scan_id = 'scan_active_1'`, values: [] });
      assert.deepEqual(remainingSteps.rows, [], 'steps cascade with their scan');
    }, availability.env ?? process.env);
  });

  it('isolates tenants under the app role', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }
    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedFixtures(pool);
      const insert = scanInsert('scan_rls_a', IDS.tenantA, IDS.groupA);
      await withTenantContextAsAppRole(pool, IDS.tenantA, (client) => client.query(insert.text, insert.values));
      await withTenantContextAsAppRole(pool, IDS.tenantA, (client) => client.query(
        `INSERT INTO validation_scan_steps (id, tenant_id, scan_id, position, check_id, target_id, created_at, updated_at)
         VALUES ('step_rls_a', $1, 'scan_rls_a', 0, 'waf.fingerprint.safe', $2, now(), now())`,
        [IDS.tenantA, IDS.targetA],
      ));

      await withTenantContextAsAppRole(pool, IDS.tenantB, async (client) => {
        const scans = await client.query(`SELECT id FROM validation_scans WHERE id = 'scan_rls_a'`);
        assert.deepEqual(scans.rows, []);
        const steps = await client.query(`SELECT id FROM validation_scan_steps WHERE id = 'step_rls_a'`);
        assert.deepEqual(steps.rows, []);
        const update = await client.query(`UPDATE validation_scans SET name = 'cross tenant' WHERE id = 'scan_rls_a'`);
        assert.equal(update.rowCount, 0);
      });
      const foreign = scanInsert('scan_rls_forged', IDS.tenantA, IDS.groupA);
      await assert.rejects(
        () => withTenantContextAsAppRole(pool, IDS.tenantB, (client) => client.query(foreign.text, foreign.values)),
        rejectsWith('42501'),
      );
      const own = await withTenantContextAsAppRole(pool, IDS.tenantA, (client) =>
        client.query(`SELECT id FROM validation_scans WHERE id = 'scan_rls_a'`));
      assert.equal(own.rows.length, 1);
    }, availability.env ?? process.env);
  });
});
