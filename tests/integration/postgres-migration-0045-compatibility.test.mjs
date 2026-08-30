import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { POLICY_CADENCES } from '../../src/contracts/testPolicyManagement.mjs';
import { createPostgresTestPolicyRepository } from '../../src/persistence/postgres/testPolicyRepository.mjs';
import {
  listMigrationFiles,
  runMigrations,
} from '../../src/persistence/postgres/migrations.mjs';
import {
  MIGRATIONS_DIR,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const MIGRATION_0045 = '0045_ownership_and_policy_dispatch_hardening';

function assertInertEventPolicy(row) {
  assert.equal(row.cadence, 'event_driven');
  assert.equal(row.state, 'paused');
  assert.equal(row.enabled, false);
  assert.equal(row.next_run_at, null);
  assert.equal(row.lease_token, null);
  assert.equal(row.lease_owner, null);
  assert.equal(row.lease_expires_at, null);
  assert.equal(row.event_trigger?.migrated_disabled, true);
}

describe('postgres migration 0045 rollback compatibility', () => {
  it('accepts previous-release event-driven writes only as inert policies', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(
      async (pool) => {
        const files = listMigrationFiles(MIGRATIONS_DIR);
        const before0045 = files.filter((file) => file.version < MIGRATION_0045);
        const migration0045 = files.filter((file) => file.version === MIGRATION_0045);
        assert.equal(migration0045.length, 1);
        await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files: before0045 });

        await pool.query(`INSERT INTO tenants (id, name) VALUES ('ten_0045', 'migration 0045')`);
        await pool.query(
          `INSERT INTO target_groups (id, tenant_id, name)
           VALUES ('tg_0045', 'ten_0045', 'rollback policies')`,
        );
        await pool.query(
          `INSERT INTO test_policies (
             id, tenant_id, target_group_id, check_id, cadence, event_trigger,
             state, enabled, next_run_at, lease_token, lease_owner, lease_expires_at
           ) VALUES (
             'policy_0045_existing', 'ten_0045', 'tg_0045', 'check.existing',
             'event_driven', '{"event_type":"target.changed","filters":{}}'::jsonb,
             'active', TRUE, now(), 'legacy-lease', 'legacy-worker', now() + interval '5 minutes'
           )`,
        );

        const applied = await runMigrations(pool, {
          migrationsDir: MIGRATIONS_DIR,
          files: migration0045,
        });
        assert.deepEqual(applied.results.map(({ version, status }) => [version, status]), [
          [MIGRATION_0045, 'applied'],
        ]);

        const existing = await pool.query(
          `SELECT cadence, event_trigger, state, enabled, next_run_at,
                  lease_token, lease_owner, lease_expires_at
           FROM test_policies WHERE id = 'policy_0045_existing'`,
        );
        assertInertEventPolicy(existing.rows[0]);
        assert.equal(existing.rows[0].event_trigger.event_type, 'target.changed');

        // This is the previous release's write shape: it still sends event_driven and may
        // attempt to arm the row. The compatibility trigger must accept but neutralize it.
        const inserted = await pool.query(
          `INSERT INTO test_policies (
             id, tenant_id, target_group_id, check_id, cadence, event_trigger,
             state, enabled, next_run_at, lease_token, lease_owner, lease_expires_at
           ) VALUES (
             'policy_0045_rollback', 'ten_0045', 'tg_0045', 'check.rollback',
             'event_driven', NULL, 'active', TRUE, now(),
             'rollback-lease', 'rollback-worker', now() + interval '5 minutes'
           )
           RETURNING cadence, event_trigger, state, enabled, next_run_at,
                     lease_token, lease_owner, lease_expires_at`,
        );
        assertInertEventPolicy(inserted.rows[0]);

        const updated = await pool.query(
          `UPDATE test_policies
           SET state = 'active', enabled = TRUE, next_run_at = now(),
               lease_token = 'retry-lease', lease_owner = 'retry-worker',
               lease_expires_at = now() + interval '5 minutes'
           WHERE id = 'policy_0045_rollback'
           RETURNING cadence, event_trigger, state, enabled, next_run_at,
                     lease_token, lease_owner, lease_expires_at`,
        );
        assertInertEventPolicy(updated.rows[0]);

        // The prior release changed cadence without mentioning event_trigger. Exercise the
        // actual SQL shape against every currently supported non-event cadence: the trigger
        // must clear the inherited compatibility payload rather than letting the CHECK reject.
        for (const cadence of ['daily', 'weekly', 'monthly', 'manual']) {
          const policyId = `policy_0045_transition_${cadence}`;
          await pool.query(
            `INSERT INTO test_policies (
               id, tenant_id, target_group_id, check_id, cadence, event_trigger,
               state, enabled, next_run_at
             ) VALUES ($1, 'ten_0045', 'tg_0045', $2, 'event_driven',
                       '{"event_type":"target.changed"}'::jsonb, 'active', TRUE, now())`,
            [policyId, `check.transition.${cadence}`],
          );
          const transitioned = await pool.query(
            `UPDATE test_policies SET cadence = $1 WHERE id = $2
             RETURNING cadence, event_trigger`,
            [cadence, policyId],
          );
          assert.deepEqual(transitioned.rows[0], { cadence, event_trigger: null });
        }

        // The CHECK remains a fail-closed backstop if the compatibility trigger is absent.
        await pool.query('ALTER TABLE test_policies DISABLE TRIGGER test_policies_event_driven_compat');
        await assert.rejects(
          pool.query(
            `UPDATE test_policies SET state = 'active', enabled = TRUE
             WHERE id = 'policy_0045_rollback'`,
          ),
          (error) => error?.code === '23514'
            && error?.constraint === 'test_policies_event_driven_inert_check',
        );
        await pool.query('ALTER TABLE test_policies ENABLE TRIGGER test_policies_event_driven_compat');

        const repository = createPostgresTestPolicyRepository(pool);
        const context = { tenantId: 'ten_0045', userId: 'usr_0045', role: 'engineer' };
        const due = await repository.listDueTestPolicies(context, { now: new Date() });
        const leased = await repository.leaseDueTestPolicies(context, {
          workerId: 'migration-0045-test',
          now: new Date(),
        });
        assert.deepEqual(due, []);
        assert.deepEqual(leased, []);
        assert.equal(POLICY_CADENCES.includes('event_driven'), false);
      },
      availability.env ?? process.env,
      { applyMigrations: false },
    );
  });
});
