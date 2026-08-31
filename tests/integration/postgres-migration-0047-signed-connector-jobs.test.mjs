import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  MIGRATIONS_DIR,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';
import { createWafPostureRepository } from '../../src/persistence/postgres/wafPostureRepository.mjs';
import { listMigrationFiles, runMigrations } from '../../src/persistence/postgres/migrations.mjs';

const MIGRATION_0050 = '0050_connector_poll_governance';

function envelope({ tenantId, connectorId, provider = 'cloudflare', revision = 1 }) {
  return {
    version: 1,
    job_id: `connector_poll_${connectorId}_${revision}`,
    tenant_id: tenantId,
    connector_id: connectorId,
    provider,
    poll_revision: revision,
    operation: 'read_only_provider_inventory',
  };
}

describe('postgres migrations 0047-0049 connector authority', () => {
  it('enforces exact envelope binding, generation uniqueness, and forced tenant RLS', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      const files = listMigrationFiles(MIGRATIONS_DIR);
      await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files });
      assert.equal(files.at(-1)?.version, MIGRATION_0050);

      await pool.query(`
        INSERT INTO tenants (id, name) VALUES
          ('ten_0047_a', 'tenant a'),
          ('ten_0047_b', 'tenant b');
        INSERT INTO tenant_connector_features (
          tenant_id, enabled, updated_by
        ) VALUES
          ('ten_0047_a', TRUE, 'integration-test'),
          ('ten_0047_b', TRUE, 'integration-test');
        INSERT INTO waf_connectors (
          id, tenant_id, provider, name, config_json, status, poll_revision
        ) VALUES
          ('conn_0047_a', 'ten_0047_a', 'cloudflare', 'tenant a connector',
           '{"read_only":true}'::jsonb, 'validating', 1),
          ('conn_0047_b', 'ten_0047_b', 'cloudflare', 'tenant b connector',
           '{"read_only":true}'::jsonb, 'validating', 1);
      `);

      const validEnvelopeA = envelope({ tenantId: 'ten_0047_a', connectorId: 'conn_0047_a' });
      const validEnvelopeB = envelope({ tenantId: 'ten_0047_b', connectorId: 'conn_0047_b' });
      await pool.query(
        `INSERT INTO connector_poll_jobs (
           id, tenant_id, connector_id, provider, poll_revision, envelope_json,
           job_signature, expires_at, created_at, updated_at
         ) VALUES
           ($1, 'ten_0047_a', 'conn_0047_a', 'cloudflare', 1, $2::jsonb,
            'sig-a', '2099-01-01T00:10:00Z', '2099-01-01T00:00:00Z', '2099-01-01T00:00:00Z'),
           ($3, 'ten_0047_b', 'conn_0047_b', 'cloudflare', 1, $4::jsonb,
            'sig-b', '2099-01-01T00:10:00Z', '2099-01-01T00:00:00Z', '2099-01-01T00:00:00Z')`,
        [validEnvelopeA.job_id, JSON.stringify(validEnvelopeA), validEnvelopeB.job_id, JSON.stringify(validEnvelopeB)],
      );

      await assert.rejects(
        pool.query(
          `INSERT INTO connector_poll_jobs (
             id, tenant_id, connector_id, provider, poll_revision, envelope_json,
             job_signature, expires_at
           ) VALUES ('connector_poll_conn_0047_a_2', 'ten_0047_a', 'conn_0047_a',
             'cloudflare', 2, $1::jsonb, 'sig-tampered', '2099-01-01T00:10:00Z')`,
          [JSON.stringify(envelope({
            tenantId: 'ten_0047_b', connectorId: 'conn_0047_a', revision: 2,
          }))],
        ),
        /connector_poll_jobs_envelope_binding/,
      );

      await assert.rejects(
        pool.query(
          `INSERT INTO connector_poll_jobs (
             id, tenant_id, connector_id, provider, poll_revision, envelope_json,
             job_signature, expires_at
           ) VALUES ('connector_poll_conn_0047_a_duplicate', 'ten_0047_a', 'conn_0047_a',
             'cloudflare', 1, $1::jsonb, 'sig-duplicate', '2099-01-01T00:10:00Z')`,
          [JSON.stringify({ ...validEnvelopeA, job_id: 'connector_poll_conn_0047_a_duplicate' })],
        ),
        /uniq_connector_poll_jobs_generation/,
      );

      const repository = createWafPostureRepository(pool);
      const repoCtx = { tenantId: 'ten_0047_a' };
      const claimed = await repository.claimConnectorPollJob(repoCtx, 'conn_0047_a', {
        worker_id: 'worker-microsecond-regression',
      });
      assert.ok(claimed?.lease_token);
      assert.match(claimed.lease_token, /^[0-9a-f-]{36}$/i);
      const completed = await repository.completeConnectorPoll(repoCtx, 'conn_0047_a', {
        job_id: claimed.id,
        worker_id: 'worker-microsecond-regression',
        lease_token: claimed.lease_token,
        poll_revision: claimed.poll_revision,
        completed_at: new Date().toISOString(),
        updates: { status: 'active', last_error_at: null },
        records: [],
        error_code: null,
      });
      assert.equal(completed?.job.status, 'completed');
      assert.equal(completed?.job.lease_token, null);

      await pool.query('DROP ROLE IF EXISTS astranull_0047_app');
      await pool.query(`
        CREATE ROLE astranull_0047_app NOLOGIN NOBYPASSRLS;
        GRANT USAGE ON SCHEMA public TO astranull_0047_app;

        GRANT SELECT, INSERT, UPDATE ON connector_poll_jobs TO astranull_0047_app;
      `);
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query('SET LOCAL ROLE astranull_0047_app');
        await client.query("SELECT set_config('app.tenant_id', 'ten_0047_a', true)");
        const visible = await client.query('SELECT tenant_id, id FROM connector_poll_jobs ORDER BY id');
        assert.deepEqual(visible.rows, [{ tenant_id: 'ten_0047_a', id: validEnvelopeA.job_id }]);
        const crossTenantClaim = await client.query(
          `UPDATE connector_poll_jobs
           SET status = 'leased', leased_by = 'worker-a', leased_at = NOW(),
               lease_token = gen_random_uuid()::text
           WHERE tenant_id = 'ten_0047_b' AND id = $1
           RETURNING id`,
          [validEnvelopeB.job_id],
        );
        assert.equal(crossTenantClaim.rowCount, 0);
        await client.query('ROLLBACK');
      } finally {
        client.release();
      }

      const rls = await pool.query(
        `SELECT relrowsecurity, relforcerowsecurity
         FROM pg_class WHERE oid = 'connector_poll_jobs'::regclass`,
      );
      assert.deepEqual(rls.rows[0], { relrowsecurity: true, relforcerowsecurity: true });
    }, { label: 'migration-0047-signed-jobs' });
  });
});
