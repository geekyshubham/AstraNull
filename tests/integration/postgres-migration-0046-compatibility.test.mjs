import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  listMigrationFiles,
  runMigrations,
} from '../../src/persistence/postgres/migrations.mjs';
import { createWafPostureRepository } from '../../src/persistence/postgres/wafPostureRepository.mjs';
import {
  MIGRATIONS_DIR,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const MIGRATION_0046 = '0046_exact_target_provider_onboarding';

describe('postgres migration 0046 exact-target compatibility', () => {
  it('backfills only unambiguous policies and adds provider ownership contracts', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(
      async (pool) => {
        const files = listMigrationFiles(MIGRATIONS_DIR);
        const before0046 = files.filter((file) => file.version < MIGRATION_0046);
        const migration0046 = files.filter((file) => file.version === MIGRATION_0046);
        assert.equal(migration0046.length, 1);
        await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files: before0046 });

        await pool.query(
          `INSERT INTO tenants (id, name, dashboard_rollup)
           VALUES ('ten_0046', 'migration 0046', '{"readiness":{"score":100}}'::jsonb)`,
        );
        await pool.query(
          `INSERT INTO target_groups (id, tenant_id, name, validation_mode)
           VALUES
             ('tg_0046_single', 'ten_0046', 'single target', 'agent_assisted'),
             ('tg_0046_multi', 'ten_0046', 'multiple targets', 'agent_assisted'),
             ('tg_0046_empty', 'ten_0046', 'empty group', 'agent_assisted')`,
        );
        await pool.query(
          `INSERT INTO targets (id, tenant_id, target_group_id, kind, value)
           VALUES
             ('tgt_0046_single', 'ten_0046', 'tg_0046_single', 'domain', 'single.example.com'),
             ('tgt_0046_a', 'ten_0046', 'tg_0046_multi', 'domain', 'a.example.com'),
             ('tgt_0046_b', 'ten_0046', 'tg_0046_multi', 'domain', 'b.example.com')`,
        );
        await pool.query(
          `INSERT INTO waf_assets (id, tenant_id, target_group_id, canonical_url)
           VALUES ('waf_0046', 'ten_0046', 'tg_0046_single', 'https://single.example.com')`,
        );
        await pool.query(
          `INSERT INTO waf_drift_events (
             id, tenant_id, waf_asset_id, drift_type, severity, created_at
           ) VALUES
             ('drift_0046_critical', 'ten_0046', 'waf_0046', 'mode_change', 'critical',
              '2026-02-01T00:00:00.000Z'),
             ('drift_0046_older_high', 'ten_0046', 'waf_0046', 'mode_change', 'high',
              '2026-01-01T00:00:00.000Z')`,
        );
        await pool.query(
          `INSERT INTO waf_retest_requests (
             id, tenant_id, drift_event_id, waf_asset_id, requested_by
           ) VALUES (
             'retest_0046_loser', 'ten_0046', 'drift_0046_older_high',
             'waf_0046', 'usr_0046'
           )`,
        );
        await pool.query(
          `INSERT INTO test_policies (
             id, tenant_id, target_group_id, check_id, cadence,
             state, enabled, next_run_at, lease_token, lease_owner, lease_expires_at,
             archived_at

           ) VALUES
             ('policy_0046_single', 'ten_0046', 'tg_0046_single', 'check.single', 'daily',
              'active', TRUE, now(), 'single-lease', 'worker', now() + interval '5 minutes', NULL),
             ('policy_0046_multi', 'ten_0046', 'tg_0046_multi', 'check.multi', 'daily',
              'active', TRUE, now(), 'multi-lease', 'worker', now() + interval '5 minutes', NULL),
             ('policy_0046_archived', 'ten_0046', 'tg_0046_empty', 'check.archived', 'manual',
              'archived', FALSE, NULL, NULL, NULL, NULL, now()),
             ('policy_0046_archived_single', 'ten_0046', 'tg_0046_single', 'check.archived-single', 'manual',
              'archived', FALSE, NULL, NULL, NULL, NULL, now())`,
        );

        const applied = await runMigrations(pool, {
          migrationsDir: MIGRATIONS_DIR,
          files: migration0046,
        });
        assert.deepEqual(applied.results.map(({ version, status }) => [version, status]), [
          [MIGRATION_0046, 'applied'],
        ]);

        const readinessCache = await pool.query(
          `SELECT dashboard_rollup FROM tenants WHERE id = 'ten_0046'`,
        );
        assert.equal(readinessCache.rows[0].dashboard_rollup, null);
        const dedupedDrift = await pool.query(
          `SELECT id, severity, created_at
           FROM waf_drift_events
           WHERE tenant_id = 'ten_0046' AND waf_asset_id = 'waf_0046'
             AND drift_type = 'mode_change' AND status = 'open'`,
        );
        assert.equal(dedupedDrift.rows.length, 1);
        assert.equal(dedupedDrift.rows[0].id, 'drift_0046_critical');
        assert.equal(dedupedDrift.rows[0].severity, 'critical');
        assert.equal(
          new Date(dedupedDrift.rows[0].created_at).toISOString(),
          '2026-01-01T00:00:00.000Z',
        );

        const repointedRetest = await pool.query(
          `SELECT drift_event_id
           FROM waf_retest_requests
           WHERE tenant_id = 'ten_0046' AND id = 'retest_0046_loser'`,
        );
        assert.equal(repointedRetest.rows[0].drift_event_id, 'drift_0046_critical');
        const driftIndex = await pool.query(
          `SELECT indexdef FROM pg_indexes
           WHERE schemaname = 'public'
             AND indexname = 'uniq_waf_drift_events_open_asset_type'`,
        );
        assert.equal(driftIndex.rows.length, 1);
        assert.match(driftIndex.rows[0].indexdef, /WHERE \(status = 'open'/i);

        const driftRepository = createWafPostureRepository(pool);
        const driftContext = { tenantId: 'ten_0046', userId: 'usr_0046', role: 'system' };
        await Promise.all([
          driftRepository.upsertWafDriftEvent(driftContext, {
            id: 'drift_0046_concurrent_high',
            waf_asset_id: 'waf_0046',
            drift_type: 'concurrent_mode_change',
            severity: 'high',
            before_summary: { posture_status: 'protected' },
            after_summary: { posture_status: 'underprotected' },
            status: 'open',
            created_at: '2026-03-01T00:00:00.000Z',
          }),
          driftRepository.upsertWafDriftEvent(driftContext, {
            id: 'drift_0046_concurrent_critical',
            waf_asset_id: 'waf_0046',
            drift_type: 'concurrent_mode_change',
            severity: 'critical',
            before_summary: { posture_status: 'protected' },
            after_summary: { posture_status: 'unprotected' },
            status: 'open',
            created_at: '2026-03-01T00:00:01.000Z',
          }),
        ]);
        const concurrentDrift = await pool.query(
          `SELECT severity, count(*)::int AS count
           FROM waf_drift_events
           WHERE tenant_id = 'ten_0046' AND waf_asset_id = 'waf_0046'
             AND drift_type = 'concurrent_mode_change' AND status = 'open'
           GROUP BY severity`,
        );
        assert.deepEqual(concurrentDrift.rows, [{ severity: 'critical', count: 1 }]);

        const policies = await pool.query(
          `SELECT id, target_id, state, enabled, next_run_at,
                  lease_token, lease_owner, lease_expires_at
           FROM test_policies
           WHERE tenant_id = 'ten_0046'
           ORDER BY id`,
        );
        const byId = new Map(policies.rows.map((row) => [row.id, row]));
        assert.equal(byId.get('policy_0046_single').target_id, 'tgt_0046_single');
        assert.equal(byId.get('policy_0046_single').state, 'active');
        assert.equal(byId.get('policy_0046_archived_single').target_id, 'tgt_0046_single');
        assert.equal(byId.get('policy_0046_archived_single').state, 'archived');
        assert.equal(byId.get('policy_0046_archived_single').enabled, false);
        assert.equal(byId.get('policy_0046_archived_single').next_run_at, null);
        for (const id of ['policy_0046_multi', 'policy_0046_archived']) {
          const row = byId.get(id);
          assert.equal(row.target_id, null);
          assert.equal(row.enabled, false);
          assert.equal(row.next_run_at, null);
          assert.equal(row.lease_token, null);
          assert.equal(row.lease_owner, null);
          assert.equal(row.lease_expires_at, null);
        }
        assert.equal(byId.get('policy_0046_multi').state, 'paused');
        assert.equal(byId.get('policy_0046_archived').state, 'archived');

        // Simulate the previous release after 0046 is live: this is its exact column list,
        // which does not know target_id. The trigger may bind only the single-target group.
        const oldWriterInserts = await pool.query(
          `INSERT INTO test_policies (
             id, tenant_id, target_group_id, check_id, cadence,
             state, enabled, next_run_at, lease_token, lease_owner, lease_expires_at,
             archived_at
           ) VALUES
             ('policy_0046_old_single', 'ten_0046', 'tg_0046_single', 'check.old-single', 'daily',
              'active', TRUE, now(), 'old-single-lease', 'old-worker', now() + interval '5 minutes', NULL),
             ('policy_0046_old_multi', 'ten_0046', 'tg_0046_multi', 'check.old-multi', 'daily',
              'active', TRUE, now(), 'old-multi-lease', 'old-worker', now() + interval '5 minutes', NULL),
             ('policy_0046_old_empty_archived', 'ten_0046', 'tg_0046_empty', 'check.old-archived', 'manual',
              'archived', TRUE, now(), 'old-archived-lease', 'old-worker', now() + interval '5 minutes', now())
           RETURNING id, target_id, state, enabled, next_run_at,
                     lease_token, lease_owner, lease_expires_at`,
        );
        const oldInsertById = new Map(oldWriterInserts.rows.map((row) => [row.id, row]));
        assert.equal(oldInsertById.get('policy_0046_old_single').target_id, 'tgt_0046_single');
        assert.equal(oldInsertById.get('policy_0046_old_single').state, 'active');
        assert.equal(oldInsertById.get('policy_0046_old_single').enabled, true);
        for (const id of ['policy_0046_old_multi', 'policy_0046_old_empty_archived']) {
          const row = oldInsertById.get(id);
          assert.equal(row.target_id, null);
          assert.equal(row.enabled, false);
          assert.equal(row.next_run_at, null);
          assert.equal(row.lease_token, null);
          assert.equal(row.lease_owner, null);
          assert.equal(row.lease_expires_at, null);
        }
        assert.equal(oldInsertById.get('policy_0046_old_multi').state, 'paused');
        assert.equal(oldInsertById.get('policy_0046_old_empty_archived').state, 'archived');

        const oldWriterUpdates = await pool.query(
          `UPDATE test_policies
           SET state = 'active', enabled = TRUE, next_run_at = now(),
               lease_token = 'old-update-lease', lease_owner = 'old-worker',
               lease_expires_at = now() + interval '5 minutes'
           WHERE id IN ('policy_0046_multi', 'policy_0046_archived')
           RETURNING id, target_id, state, enabled, next_run_at,
                     lease_token, lease_owner, lease_expires_at`,
        );
        const oldUpdateById = new Map(oldWriterUpdates.rows.map((row) => [row.id, row]));
        for (const id of ['policy_0046_multi', 'policy_0046_archived']) {
          const row = oldUpdateById.get(id);
          assert.equal(row.target_id, null);
          assert.equal(row.enabled, false);
          assert.equal(row.next_run_at, null);
          assert.equal(row.lease_token, null);
          assert.equal(row.lease_owner, null);
          assert.equal(row.lease_expires_at, null);
        }
        assert.equal(oldUpdateById.get('policy_0046_multi').state, 'paused');
        assert.equal(oldUpdateById.get('policy_0046_archived').state, 'archived');

        await assert.rejects(
          pool.query(
            `INSERT INTO test_policies (
               id, tenant_id, target_group_id, target_id, check_id, cadence,
               state, enabled, next_run_at
             ) VALUES (
               'policy_0046_wrong_group', 'ten_0046', 'tg_0046_single', 'tgt_0046_a',
               'check.wrong-group', 'daily', 'active', TRUE, now()
             )`,
          ),
          (error) => error?.code === '23503'
            && error?.constraint === 'fk_test_policies_target_binding',
        );

        await pool.query(
          `INSERT INTO targets (id, tenant_id, target_group_id, kind, value)
           VALUES ('tgt_0046_single_other', 'ten_0046', 'tg_0046_single', 'domain', 'other.example.com')`,
        );
        await assert.rejects(
          pool.query(
            `UPDATE test_policies
             SET target_id = 'tgt_0046_single_other'
             WHERE id = 'policy_0046_single'`,
          ),
          (error) => error?.code === '23514'
            && error?.constraint === 'test_policies_target_identity_immutable',
        );

        for (const targetId of ['tgt_0046_a', 'tgt_0046_b']) {
          await pool.query(
            `INSERT INTO test_policies (
               id, tenant_id, target_group_id, target_id, check_id, cadence,
               state, enabled, next_run_at
             ) VALUES ($1, 'ten_0046', 'tg_0046_multi', $2,
                       'check.same', 'daily', 'active', TRUE, now())`,
            [`policy_0046_${targetId}`, targetId],
          );
        }
        await assert.rejects(
          pool.query(
            `INSERT INTO test_policies (
               id, tenant_id, target_group_id, target_id, check_id, cadence,
               state, enabled, next_run_at
             ) VALUES (
               'policy_0046_duplicate', 'ten_0046', 'tg_0046_multi', 'tgt_0046_a',
               'check.same', 'daily', 'active', TRUE, now()
             )`,
          ),
          (error) => error?.code === '23505'
            && error?.constraint === 'uniq_test_policies_active_group_target_check',
        );

        await pool.query(
          `INSERT INTO target_verifications (
             id, tenant_id, target_id, state, source_kind, source_ref,
             transitioned_at, transitioned_by, audit_entry_id
           ) VALUES (
             'tv_0046_provider', 'ten_0046', 'tgt_0046_single',
             'provider_verified', 'provider_account',
             '{"connector_id":"conn_0046","snapshot_id":"snap_0046"}'::jsonb,
             now(), 'usr_0046', 'audit_0046'
           )`,
        );

        const existingMode = await pool.query(
          `SELECT validation_mode FROM target_groups WHERE id = 'tg_0046_single'`,
        );
        assert.equal(existingMode.rows[0].validation_mode, 'agent_assisted');
        const newMode = await pool.query(
          `INSERT INTO target_groups (id, tenant_id, name)
           VALUES ('tg_0046_new', 'ten_0046', 'new default')
           RETURNING validation_mode`,
        );
        assert.equal(newMode.rows[0].validation_mode, 'external_only');

        const columns = await pool.query(
          `SELECT column_name, column_default
           FROM information_schema.columns
           WHERE table_schema = 'public'
             AND (
               (table_name = 'waf_connector_snapshots'
                 AND column_name IN ('evidence_source', 'inventory_complete', 'inventory_truncated'))
               OR (table_name = 'waf_coverage_daily_rollups' AND column_name = 'edge_protected')
               OR (table_name = 'events' AND column_name = 'producer_kind')
             )`,
        );
        assert.deepEqual(
          new Set(columns.rows.map((row) => row.column_name)),
          new Set(['evidence_source', 'inventory_complete', 'inventory_truncated', 'edge_protected', 'producer_kind']),
        );

        await assert.rejects(
          pool.query(
            `INSERT INTO test_runs (
               id, tenant_id, target_group_id, target_id, policy_id, check_id, status
             ) VALUES (
               'run_0046_wrong_policy_target', 'ten_0046', 'tg_0046_multi', 'tgt_0046_b',
               'policy_0046_tgt_0046_a', 'check.same', 'running'
             )`,
          ),
          (error) => error?.code === '23514'
            && error?.constraint === 'test_runs_policy_target_binding',
        );

        await pool.query(
          `INSERT INTO test_runs (

             id, tenant_id, target_group_id, target_id, policy_id, check_id, status
           ) VALUES (
             'run_0046_exact', 'ten_0046', 'tg_0046_multi', 'tgt_0046_a',
             'policy_0046_tgt_0046_a', 'check.same', 'running'
           )`,
        );
        await pool.query(
          `INSERT INTO agents (id, tenant_id, target_group_id, status, last_token_validation_status)
           VALUES ('agent_0046_owner', 'ten_0046', 'tg_0046_multi', 'online', 'valid')`,
        );
        await pool.query(
          `INSERT INTO ownership_verifications (
             id, tenant_id, target_group_id, agent_id, declared_fqdn, status,
             challenge_nonce_hash, probe_job_id, created_by
           ) VALUES (
             'own_0046_signed', 'ten_0046', 'tg_0046_multi', 'agent_0046_owner',
             'a.example.com', 'challenge_sent', 'nonce_0046_owner',
             'probe_0046_owner', 'usr_0046'
           )`,
        );
        const ownershipProbe = await pool.query(
          `INSERT INTO probe_jobs (
             id, tenant_id, test_run_id, target_id, check_id, nonce_hash,
             target_descriptor_json, ownership_verification_id
           ) VALUES (
             'probe_0046_owner', 'ten_0046', 'own_0046_signed', 'agent_0046_owner',
             'ownership.challenge', 'nonce_0046_owner',
             '{"id":"agent_0046_owner","kind":"fqdn","value":"a.example.com"}'::jsonb,
             'own_0046_signed'
           )
           RETURNING id`,
        );
        assert.equal(ownershipProbe.rows[0].id, 'probe_0046_owner');
        await assert.rejects(
          pool.query(
            `INSERT INTO probe_jobs (
               id, tenant_id, test_run_id, target_id, check_id, nonce_hash
             ) VALUES (
               'probe_0046_wrong_target', 'ten_0046', 'run_0046_exact', 'tgt_0046_b',
               'check.same', 'nonce_0046_wrong'
             )`,
          ),
          (error) => error?.code === '23514'
            && error?.constraint === 'probe_jobs_test_run_target_binding',
        );

        await pool.query(
          `UPDATE targets SET deleted_at = now()
           WHERE id = 'tgt_0046_single_other'`,
        );
        await assert.rejects(
          pool.query(
            `INSERT INTO test_runs (
               id, tenant_id, target_group_id, target_id, check_id, status
             ) VALUES (
               'run_0046_archived_target', 'ten_0046', 'tg_0046_single',
               'tgt_0046_single_other', 'check.archived-target', 'running'
             )`,
          ),
          (error) => error?.code === '23514'
            && error?.constraint === 'test_runs_exact_active_target',
        );

        const providerProofDefinition = await pool.query(
          `SELECT pg_get_functiondef(
             'target_provider_verification_is_current(text,text,jsonb)'::regprocedure
           ) AS definition`,
        );
        assert.match(providerProofDefinition.rows[0].definition, /last_success_at <= CURRENT_TIMESTAMP/i);
        assert.match(
          providerProofDefinition.rows[0].definition,
          /last_success_at >= CURRENT_TIMESTAMP\s*-\s*INTERVAL '24 hours'/i,
        );

        const pollRevisionColumns = await pool.query(
          `SELECT table_name, column_name
           FROM information_schema.columns
           WHERE table_schema = 'public'
             AND (
               (table_name = 'waf_connectors'
                 AND column_name IN ('poll_revision', 'last_success_revision'))
               OR (table_name = 'waf_connector_snapshots' AND column_name = 'poll_revision')
             )`,
        );
        assert.deepEqual(
          new Set(pollRevisionColumns.rows.map((row) => `${row.table_name}.${row.column_name}`)),
          new Set([
            'waf_connectors.poll_revision',
            'waf_connectors.last_success_revision',
            'waf_connector_snapshots.poll_revision',
          ]),
        );

        // Previous-release event writers do not know producer_kind. During the rolling
        // window those rows remain stored but quarantined from every trusted correlation.
        const legacyReserved = await pool.query(
          `INSERT INTO events (id, tenant_id, signal_type, timestamp)
           VALUES
             ('event_0046_old_probe', 'ten_0046', 'probe_result', now()),
             ('event_0046_old_agent', 'ten_0046', 'agent_observation', now())
           RETURNING producer_kind`,
        );
        assert.deepEqual(
          legacyReserved.rows.map((row) => row.producer_kind),
          ['legacy_untrusted', 'legacy_untrusted'],
        );

        await assert.rejects(
          pool.query(
            `INSERT INTO events (
               id, tenant_id, signal_type, producer_kind, timestamp
             ) VALUES (
               'event_0046_forged_probe', 'ten_0046', 'probe_result', 'public_api', now()
             )`,
          ),
          (error) => error?.code === '23514'
            && error?.constraint === 'events_reserved_producer_check',
        );
        await pool.query('SELECT edge_protected FROM waf_coverage_summary LIMIT 0');
      },
      availability.env ?? process.env,
      { applyMigrations: false },
    );
  });
});
