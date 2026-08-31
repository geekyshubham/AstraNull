import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const TENANT_A = 'ten_0049_a';
const TENANT_B = 'ten_0049_b';
const CTX_A = { tenantId: TENANT_A, userId: 'usr_0049', role: 'admin' };
const TARGET_A = 'tgt_0049_a';
const TRANSITIONED_AT = new Date(Date.now() - 60 * 60 * 1000).toISOString();
const GENERATION_7 = new Date(Date.now() - 30 * 60 * 1000).toISOString();
const GENERATION_8 = new Date(Date.now() - 20 * 60 * 1000).toISOString();

function ownershipBinding({
  featureRevision = 5,
  connectorSecretId = 'sec_0049_a_1',
  connectorRevision = 7,
  connectorGeneration = GENERATION_7,
  snapshotId = 'snap_0049_a_7',
} = {}) {
  return {
    kind: 'provider_account',
    state: 'provider_verified',
    target_id: TARGET_A,
    transitioned_at: TRANSITIONED_AT,
    provider_provenance: {
      feature_revision: featureRevision,
      connector_id: 'conn_0049_a',
      connector_provider: 'cloudflare',
      connector_secret_id: connectorSecretId,
      connector_revision: connectorRevision,
      connector_generation: connectorGeneration,
      snapshot_id: snapshotId,
      snapshot_resource_ref_hash: 'zone_hash_0049',
      snapshot_revision: connectorRevision,
      snapshot_observed_at: connectorGeneration,
    },
  };
}

async function insertProbeJob(pool, suffix, binding) {
  const runId = `run_0049_${suffix}`;
  const jobId = `pjob_0049_${suffix}`;
  await pool.query(
    `INSERT INTO test_runs (
       id, tenant_id, target_group_id, target_id, check_id, status, started_at
     ) VALUES ($1, $2, 'tg_0049_a', $3, 'path.protected_canary.safe', 'running', now())`,
    [runId, TENANT_A, TARGET_A],
  );
  await pool.query(
    `INSERT INTO probe_jobs (
       id, tenant_id, test_run_id, target_id, check_id, vector_family, status,
       nonce_hash, nonce_for_worker, probe_profile, constraints_json,
       target_descriptor_json, worker_metadata_json, job_signature, created_at
     ) VALUES (
       $1, $2, $3, $4, 'path.protected_canary.safe', 'l7', 'pending',
       $5, 'nonce', '{"kind":"http_head"}'::jsonb, $6::jsonb,
       '{"id":"tgt_0049_a","kind":"fqdn","value":"app.example.com"}'::jsonb,
       '{}'::jsonb, 'test-signature', now()
     )`,
    [
      jobId,
      TENANT_A,
      runId,
      TARGET_A,
      `nonce_hash_${suffix}`,
      JSON.stringify({ max_requests: 1, ownership_binding: binding }),
    ],
  );
  return jobId;
}

async function currentState(pool) {
  return withTenantContext(pool, TENANT_A, async (client) => {
    const result = await client.query(
      'SELECT state FROM target_verification_current WHERE tenant_id = $1 AND target_id = $2',
      [TENANT_A, TARGET_A],
    );
    return result.rows[0]?.state ?? null;
  });
}

async function cancelFixtureRun(pool, suffix) {
  await pool.query(
    `UPDATE test_runs SET status = 'cancelled', completed_at = now()
     WHERE tenant_id = $1 AND id = $2`,
    [TENANT_A, `run_0049_${suffix}`],
  );
}

async function seed(pool) {
  await pool.query(
    `INSERT INTO tenants (id, name) VALUES
       ('ten_0049_a', '0049 tenant a'),
       ('ten_0049_b', '0049 tenant b');
     INSERT INTO environments (id, tenant_id, name) VALUES
       ('env_0049_a', 'ten_0049_a', 'prod'),
       ('env_0049_b', 'ten_0049_b', 'prod');
     INSERT INTO target_groups (
       id, tenant_id, environment_id, name, ownership_status, validation_mode
     ) VALUES
       ('tg_0049_a', 'ten_0049_a', 'env_0049_a', 'group a', 'verified', 'external_only'),
       ('tg_0049_b', 'ten_0049_b', 'env_0049_b', 'group b', 'verified', 'external_only');
     INSERT INTO targets (
       id, tenant_id, target_group_id, kind, value, normalized_value
     ) VALUES
       ('tgt_0049_a', 'ten_0049_a', 'tg_0049_a', 'fqdn', 'app.example.com', 'app.example.com'),
       ('tgt_0049_b', 'ten_0049_b', 'tg_0049_b', 'fqdn', 'other.example.com', 'other.example.com');
     INSERT INTO encrypted_secrets (
       id, tenant_id, purpose, name, rotation, envelope_json, created_by
     ) VALUES
       ('sec_0049_a_1', 'ten_0049_a', 'waf_provider_credential', 'provider one', 1, '{}'::jsonb, 'seed'),
       ('sec_0049_a_2', 'ten_0049_a', 'waf_provider_credential', 'provider two', 2, '{}'::jsonb, 'seed');
     INSERT INTO tenant_connector_features (
       tenant_id, enabled, updated_by, revision
     ) VALUES
       ('ten_0049_a', TRUE, 'seed', 5),
       ('ten_0049_b', TRUE, 'seed', 3);`,
  );
  await pool.query(
    `INSERT INTO waf_connectors (
       id, tenant_id, provider, name, secret_id, config_json, status,
       last_success_at, poll_revision, last_success_revision
     ) VALUES (
       'conn_0049_a', $1, 'cloudflare', 'Cloudflare DNS', 'sec_0049_a_1',
       '{"read_only":true}'::jsonb, 'active', $2::timestamptz, 7, 7
     )`,
    [TENANT_A, GENERATION_7],
  );
  await pool.query(
    `INSERT INTO waf_connector_snapshots (
       id, tenant_id, connector_id, provider, snapshot_kind, resource_ref_hash,
       display_ref, summary_json, observed_at, evidence_source, inventory_complete,
       inventory_truncated, poll_revision
     ) VALUES (
       'snap_0049_a_7', $1, 'conn_0049_a', 'cloudflare', 'dns_zone', 'zone_hash_0049',
       'app.example.com',
       '{"hostnames":["app.example.com"],"tags":["ownership_eligible:true","resource_status:active"]}'::jsonb,
       $2::timestamptz, 'provider_api', TRUE, FALSE, 7
     )`,
    [TENANT_A, GENERATION_7],
  );
  await pool.query(
    `INSERT INTO target_verifications (
       id, tenant_id, target_id, state, source_kind, source_ref,
       transitioned_at, transitioned_by, audit_entry_id
     ) VALUES
       ('tv_0049_a', $1, 'tgt_0049_a', 'provider_verified', 'provider_account',
        '{"connector_id":"conn_0049_a","provider":"cloudflare","resource_ref_hash":"zone_hash_0049"}'::jsonb,
        $2::timestamptz, 'seed', 'audit_0049_a'),
       ('tv_0049_b', 'ten_0049_b', 'tgt_0049_b', 'dns_verified', 'dns_txt',
        '{"record":"_astranull.other.example.com"}'::jsonb,
        $2::timestamptz, 'seed', 'audit_0049_b')`,
    [TENANT_A, TRANSITIONED_AT],
  );
}

describe('postgres migration 0049 feature authority', () => {
  it('enforces security-invoker tenant reads and exact lease-time authority generations', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool, { latestVersion }) => {
      assert.equal(latestVersion, '0050_connector_poll_governance');
      await seed(pool);

      const view = await pool.query(
        `SELECT reloptions FROM pg_class
         WHERE oid = 'target_verification_current'::regclass`,
      );
      assert.ok(view.rows[0]?.reloptions?.includes('security_invoker=true'));
      const rls = await pool.query(
        `SELECT relrowsecurity, relforcerowsecurity
         FROM pg_class WHERE oid = 'tenant_connector_features'::regclass`,
      );
      assert.deepEqual(rls.rows[0], { relrowsecurity: true, relforcerowsecurity: true });
      assert.equal(await currentState(pool), 'provider_verified');

      await pool.query('DROP ROLE IF EXISTS astranull_0049_app');
      await pool.query(`
        CREATE ROLE astranull_0049_app NOLOGIN NOBYPASSRLS;
        GRANT USAGE ON SCHEMA public TO astranull_0049_app;
        GRANT SELECT ON target_verification_current, target_verifications, targets,
          waf_connectors, waf_connector_snapshots, tenant_connector_features
          TO astranull_0049_app;
        GRANT UPDATE ON tenant_connector_features TO astranull_0049_app;
      `);
      const app = await pool.connect();
      try {
        await app.query('BEGIN');
        await app.query('SET LOCAL ROLE astranull_0049_app');
        await app.query("SELECT set_config('app.tenant_id', 'ten_0049_a', true)");
        const visible = await app.query(
          'SELECT tenant_id, target_id, state FROM target_verification_current ORDER BY target_id',
        );
        assert.deepEqual(visible.rows, [{
          tenant_id: TENANT_A,
          target_id: TARGET_A,
          state: 'provider_verified',
        }]);
        const features = await app.query(
          'SELECT tenant_id FROM tenant_connector_features ORDER BY tenant_id',
        );
        assert.deepEqual(features.rows, [{ tenant_id: TENANT_A }]);
        const crossTenantUpdate = await app.query(
          `UPDATE tenant_connector_features SET enabled = FALSE
           WHERE tenant_id = 'ten_0049_b' RETURNING tenant_id`,
        );
        assert.equal(crossTenantUpdate.rowCount, 0);
        await app.query('ROLLBACK');
      } finally {
        app.release();
      }

      const probeJobs = createProbeJobRepository(pool);
      const featureJob = await insertProbeJob(pool, 'feature', ownershipBinding());
      await pool.query(
        `UPDATE tenant_connector_features SET enabled = FALSE, revision = 6
         WHERE tenant_id = $1`,
        [TENANT_A],
      );
      assert.equal(await currentState(pool), 'pending');
      assert.equal(await probeJobs.claimPendingJobForWorker(CTX_A, featureJob, 'worker-feature', new Date().toISOString()), null);
      await cancelFixtureRun(pool, 'feature');

      await pool.query(
        `UPDATE tenant_connector_features SET enabled = TRUE WHERE tenant_id = $1`,
        [TENANT_A],
      );
      assert.equal(await currentState(pool), 'provider_verified');
      const revisionJob = await insertProbeJob(pool, 'revision', ownershipBinding({ featureRevision: 6 }));
      await pool.query(
        `UPDATE waf_connectors SET last_success_revision = 8, poll_revision = 8
         WHERE tenant_id = $1 AND id = 'conn_0049_a'`,
        [TENANT_A],
      );
      assert.equal(await probeJobs.claimPendingJobForWorker(CTX_A, revisionJob, 'worker-revision', new Date().toISOString()), null);
      await cancelFixtureRun(pool, 'revision');

      await pool.query(
        `UPDATE waf_connectors SET last_success_revision = 7, poll_revision = 7
         WHERE tenant_id = $1 AND id = 'conn_0049_a'`,
        [TENANT_A],
      );
      const secretJob = await insertProbeJob(pool, 'secret', ownershipBinding({ featureRevision: 6 }));
      await pool.query(
        `UPDATE waf_connectors SET secret_id = 'sec_0049_a_2'
         WHERE tenant_id = $1 AND id = 'conn_0049_a'`,
        [TENANT_A],
      );
      assert.equal(await currentState(pool), 'provider_verified');
      assert.equal(await probeJobs.claimPendingJobForWorker(CTX_A, secretJob, 'worker-secret', new Date().toISOString()), null);
      await cancelFixtureRun(pool, 'secret');

      await pool.query(
        `UPDATE waf_connectors
         SET secret_id = 'sec_0049_a_1', last_success_at = $2::timestamptz,
             last_success_revision = 8, poll_revision = 8
         WHERE tenant_id = $1 AND id = 'conn_0049_a'`,
        [TENANT_A, GENERATION_8],
      );
      await pool.query(
        `INSERT INTO waf_connector_snapshots (
           id, tenant_id, connector_id, provider, snapshot_kind, resource_ref_hash,
           display_ref, summary_json, observed_at, evidence_source, inventory_complete,
           inventory_truncated, poll_revision
         ) VALUES (
           'snap_0049_a_8', $1, 'conn_0049_a', 'cloudflare', 'dns_zone', 'zone_hash_0049',
           'app.example.com',
           '{"hostnames":["app.example.com"],"tags":["ownership_eligible:true","resource_status:active"]}'::jsonb,
           $2::timestamptz, 'provider_api', TRUE, FALSE, 8
         )`,
        [TENANT_A, GENERATION_8],
      );
      assert.equal(await currentState(pool), 'provider_verified');
      const staleSnapshotJob = await insertProbeJob(
        pool,
        'snapshot',
        ownershipBinding({ featureRevision: 6 }),
      );
      assert.equal(await probeJobs.claimPendingJobForWorker(
        CTX_A,
        staleSnapshotJob,
        'worker-snapshot',
        new Date().toISOString(),
      ), null);
      await cancelFixtureRun(pool, 'snapshot');

      const validJob = await insertProbeJob(pool, 'valid', ownershipBinding({
        featureRevision: 6,
        connectorRevision: 8,
        connectorGeneration: GENERATION_8,
        snapshotId: 'snap_0049_a_8',
      }));
      const claimed = await probeJobs.claimPendingJobForWorker(
        CTX_A,
        validJob,
        'worker-valid',
        new Date().toISOString(),
      );
      assert.equal(claimed?.id, validJob);
      assert.equal(claimed?.status, 'leased');
    }, { databaseName: undefined });
  });
});
