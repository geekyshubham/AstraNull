import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  provisionPostgresConnectorSchedulerRole,
  provisionPostgresConnectorWorkerRole,
} from '../../scripts/postgres-grant-app-role.mjs';
import { createWafPostureRepository } from '../../src/persistence/postgres/wafPostureRepository.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const TENANT_A = 'ten_0050_a';
const TENANT_B = 'ten_0050_b';
const CTX_A = { tenantId: TENANT_A, userId: 'scheduler', role: 'system' };
const T0 = '2026-08-31T12:00:00.000Z';

async function seed(pool) {
  await pool.query(`
    INSERT INTO tenants (id, name) VALUES
      ('ten_0050_a', '0050 tenant a'),
      ('ten_0050_b', '0050 tenant b');
    INSERT INTO encrypted_secrets (id, tenant_id, purpose, name, rotation) VALUES
      ('sec_0050_a_1', 'ten_0050_a', 'waf_provider_credential', 'a1', 1),
      ('sec_0050_a_2', 'ten_0050_a', 'waf_provider_credential', 'a2', 1),
      ('sec_0050_b_1', 'ten_0050_b', 'waf_provider_credential', 'b1', 1);
    INSERT INTO tenant_connector_features (tenant_id, enabled, updated_by) VALUES
      ('ten_0050_a', TRUE, 'seed'),
      ('ten_0050_b', TRUE, 'seed');
    INSERT INTO waf_connectors (
      id, tenant_id, provider, name, secret_id, config_json, status, next_poll_at
    ) VALUES
      ('conn_0050_a_1', 'ten_0050_a', 'cloudflare', 'a1', 'sec_0050_a_1',
       '{"read_only":true}'::jsonb, 'active', '2026-08-31T11:00:00Z'),
      ('conn_0050_a_2', 'ten_0050_a', 'cloudflare', 'a2', 'sec_0050_a_2',
       '{"read_only":true}'::jsonb, 'active', '2026-08-31T11:00:00Z'),
      ('conn_0050_b_1', 'ten_0050_b', 'cloudflare', 'b1', 'sec_0050_b_1',
       '{"read_only":true}'::jsonb, 'active', '2026-08-31T11:00:00Z');
  `);
}

async function asRole(pool, role, tenantId, callback) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL ROLE ${role}`);
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
    const result = await callback(client);
    await client.query('ROLLBACK');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

describe('postgres migration 0050 connector poll governance', () => {
  it('enforces durable cadence, sustained provider limits, role ACLs, and tenant RLS', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool, { latestVersion }) => {
      assert.equal(latestVersion, '0050_connector_poll_governance');
      await seed(pool);
      const repo = createWafPostureRepository(pool);

      assert.equal(await repo.beginConnectorPoll(CTX_A, 'conn_0050_a_1', {
        scheduled: true,
        updated_at: T0,
      }), 1);
      assert.equal(await repo.beginConnectorPoll(CTX_A, 'conn_0050_a_2', {
        scheduled: true,
        updated_at: T0,
      }), null, 'same provider must be spaced by the durable 30-second gate');
      assert.equal(await repo.beginConnectorPoll(CTX_A, 'conn_0050_a_2', {
        scheduled: true,
        updated_at: '2026-08-31T12:00:31.000Z',
      }), 1);

      await pool.query(
        `UPDATE waf_connectors SET status = 'active'
         WHERE tenant_id = $1 AND id = 'conn_0050_a_1'`,
        [TENANT_A],
      );
      assert.equal(await repo.beginConnectorPoll(CTX_A, 'conn_0050_a_1', {
        scheduled: false,
        updated_at: '2026-08-31T12:01:00.000Z',
      }), null, 'manual polling must honor the five-minute cooldown');
      assert.equal(await repo.beginConnectorPoll(CTX_A, 'conn_0050_a_1', {
        scheduled: false,
        updated_at: '2026-08-31T12:05:01.000Z',
      }), 2);

      const governance = await pool.query(
        `SELECT request_count, next_allowed_at
         FROM connector_provider_rate_limits
         WHERE tenant_id = $1 AND provider = 'cloudflare'`,
        [TENANT_A],
      );
      assert.equal(governance.rows[0]?.request_count, 3);
      assert.equal(governance.rows[0]?.next_allowed_at.toISOString(), '2026-08-31T12:05:31.000Z');
      const connector = await pool.query(
        `SELECT poll_revision, last_poll_requested_at, next_poll_at
         FROM waf_connectors WHERE tenant_id = $1 AND id = 'conn_0050_a_1'`,
        [TENANT_A],
      );
      assert.equal(Number(connector.rows[0]?.poll_revision), 2);
      assert.equal(connector.rows[0]?.last_poll_requested_at.toISOString(), '2026-08-31T12:05:01.000Z');
      assert.equal(connector.rows[0]?.next_poll_at.toISOString(), '2026-08-31T12:20:01.000Z');

      await provisionPostgresConnectorSchedulerRole(pool, { password: 'd'.repeat(64) });
      await provisionPostgresConnectorWorkerRole(pool, { password: 'e'.repeat(64) });

      const schedulerVisible = await asRole(
        pool,
        'astranull_connector_scheduler',
        TENANT_A,
        (client) => client.query('SELECT id, tenant_id FROM waf_connectors ORDER BY id'),
      );
      assert.deepEqual(schedulerVisible.rows.map((row) => row.tenant_id), [TENANT_A, TENANT_A]);
      const schedulerCrossTenant = await asRole(
        pool,
        'astranull_connector_scheduler',
        TENANT_A,
        (client) => client.query(
          `UPDATE waf_connectors SET status = 'disabled'
           WHERE tenant_id = $1 RETURNING id`,
          [TENANT_B],
        ),
      );
      assert.equal(schedulerCrossTenant.rowCount, 0);
      await assert.rejects(
        asRole(pool, 'astranull_connector_scheduler', TENANT_A, (client) =>
          client.query('SELECT id FROM waf_connector_snapshots')),
        /permission denied/,
      );

      const workerVisible = await asRole(
        pool,
        'astranull_connector_worker',
        TENANT_A,
        (client) => client.query('SELECT id, tenant_id FROM waf_connectors ORDER BY id'),
      );
      assert.deepEqual(workerVisible.rows.map((row) => row.tenant_id), [TENANT_A, TENANT_A]);
      await asRole(pool, 'astranull_connector_worker', TENANT_A, (client) => client.query(
        `INSERT INTO waf_connector_snapshots (
           id, tenant_id, connector_id, provider, snapshot_kind, resource_ref_hash,
           summary_json, evidence_source, poll_revision, observed_at
         ) VALUES (
           'snap_0050_worker', $1, 'conn_0050_a_1', 'cloudflare', 'dns_zone',
           'zone_hash_0050', '{}'::jsonb, 'provider_api', 2, $2::timestamptz
         )`,
        [TENANT_A, T0],
      ));
      await assert.rejects(
        asRole(pool, 'astranull_connector_worker', TENANT_A, (client) => client.query(
          'UPDATE tenant_connector_features SET enabled = FALSE WHERE tenant_id = $1',
          [TENANT_A],
        )),
        /permission denied/,
      );
      await assert.rejects(
        asRole(pool, 'astranull_connector_worker', TENANT_A, (client) =>
          client.query('SELECT * FROM connector_provider_rate_limits')),
        /permission denied/,
      );
    });
  });
});
