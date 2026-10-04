import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { it } from 'node:test';
import { createTargetHistoryRepository, writeObservation } from '../../src/persistence/postgres/targetHistoryRepository.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import {
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
  withTenantContextAsAppRole,
} from '../helpers/pg-harness.mjs';

const TENANT = 'ten_observation_race';

function observation(id, nonce, digest) {
  return {
    id, tenant_id: TENANT, target_id: 'tgt_observation_race',
    target_group_id: 'tg_observation_race', family: 'waf',
    check_id: 'waf.fingerprint.safe', test_run_id: null,
    source_kind: 'explicit_record', source_id: null, corpus_version: null,
    scenario_version: null, check_version: null,
    observed_at: '2026-10-04T00:00:00.000000Z', source_completed_at: null,
    outcome: 'detected', attempt_class: 'successful', producer_kind: 'manual',
    provenance: {}, origin_binding_id: null, nonce, event_id: null, digest,
    created_at: '2026-10-04T00:00:01.000000Z',
  };
}

// Both transactions must see an empty preflight lookup before either INSERT.
// This exercises the race deterministically rather than relying on timing.
async function race(pool, records) {
  let release;
  const barrier = new Promise((resolve) => { release = resolve; });
  let initialReads = 0;
  return Promise.all(records.map((record) => withTenantContextAsAppRole(pool, TENANT, async (client) => {
    const wrapped = {
      async query(sql, values) {
        const result = await client.query(sql, values);
        if (sql.includes('FROM target_observations') && sql.includes('digest = $4') && initialReads < 2) {
          if (++initialReads === 2) release();
          await barrier;
        }
        return result;
      },
    };
    const result = await writeObservation(wrapped, record);
    // A replay or a 409 must leave the outer ingest transaction usable.
    await client.query('SELECT 1');
    return result;
  })));
}

function racingAppPool(pool, table) {
  let release;
  const barrier = new Promise((resolve) => { release = resolve; });
  let arrivals = 0;
  return {
    async connect() {
      const client = await pool.connect();
      return {
        async query(sql, values) {
          if (sql.includes(`INSERT INTO ${table}`)) {
            if (++arrivals === 2) release();
            await barrier;
          }
          const result = await client.query(sql, values);
          if (sql === 'BEGIN') await client.query('SET LOCAL ROLE astranull_app');
          return result;
        },
        release() { client.release(); },
      };
    },
  };
}

it('keeps concurrent observation replay and conflicts inside usable RLS transactions', { timeout: 180_000 }, async (t) => {
  const availability = await resolvePostgresHarnessAvailability(process.env, { tryDocker: false });
  if (!availability.available) return t.skip(availability.reason);
  await withEphemeralPostgres(async (pool) => {
    await pool.query(`INSERT INTO tenants (id, name) VALUES ($1, 'Observation race')`, [TENANT]);
    await pool.query(`INSERT INTO target_groups (id, tenant_id, name) VALUES ('tg_observation_race', $1, 'Race')`, [TENANT]);
    await pool.query(`INSERT INTO targets (id, tenant_id, target_group_id, kind, value)
      VALUES ('tgt_observation_race', $1, 'tg_observation_race', 'fqdn', 'example.test'),
        ('tgt_origin_race', $1, 'tg_observation_race', 'ip', '203.0.113.10')`, [TENANT]);
    await pool.query(`INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status)
      VALUES ('run_lineage_race', $1, 'tg_observation_race', 'tgt_observation_race', 'waf.fingerprint.safe', 'planned')`, [TENANT]);
    await pool.query(`INSERT INTO findings (id, tenant_id, target_group_id, target_id, test_run_id, check_id, title, severity, status)
      VALUES ('fnd_lineage_race', $1, 'tg_observation_race', 'tgt_observation_race', 'run_lineage_race',
        'waf.fingerprint.safe', 'Race', 'high', 'open')`, [TENANT]);
    await ensureHarnessAppRole(pool);

    await t.test('identical simultaneous observations return the same row and one replay', async () => {
      const results = await race(pool, [
        observation('obs_race_a', 'replay-nonce', 'replay-digest'),
        observation('obs_race_b', 'replay-nonce', 'replay-digest'),
      ]);
      assert.equal(results[0].id, results[1].id);
      assert.deepEqual(results.map((row) => row.replayed).sort(), [false, true]);
      const count = await pool.query(`SELECT count(*)::int AS n FROM target_observations WHERE nonce = 'replay-nonce'`);
      assert.equal(count.rows[0].n, 1);
    });

    await t.test('different simultaneous observations sharing a nonce return one 409', async () => {
      const results = await race(pool, [
        observation('obs_conflict_a', 'conflict-nonce', 'digest-a'),
        observation('obs_conflict_b', 'conflict-nonce', 'digest-b'),
      ]);
      const conflict = results.find((row) => row.error);
      assert.equal(conflict?.error, 'idempotency_conflict');
      assert.equal(conflict?.status, 409);
      assert.equal(results.filter((row) => !row.error).length, 1);
      const count = await pool.query(`SELECT count(*)::int AS n FROM target_observations WHERE nonce = 'conflict-nonce'`);
      assert.equal(count.rows[0].n, 1);
    });

    await t.test('simultaneous binding creates replay once, audit once, and reject a different scope', async () => {
      const repository = createTargetHistoryRepository(racingAppPool(pool, 'origin_bindings'));
      const ctx = { tenantId: TENANT, userId: null, role: 'admin' };
      const record = {
        tenant_id: TENANT, protected_target_id: 'tgt_observation_race',
        protected_target_group_id: 'tg_observation_race', origin_target_id: 'tgt_origin_race',
        origin_target_group_id: 'tg_observation_race', host: 'example.test', sni: 'example.test',
        port: 443, path: '/', created_by: null, created_at: '2026-10-04T00:00:00.123456Z',
      };
      const audit = createAuditRepository(pool);
      const results = await Promise.all(['binding_race_a', 'binding_race_b'].map((id) => repository.insertBinding(ctx,
        { ...record, id }, { tenant_id: TENANT, action: 'origin_binding.created', resource_type: 'origin_binding', resource_id: id }, audit)));
      assert.equal(results[0].id, results[1].id);
      assert.deepEqual(results.map((row) => row.replayed).sort(), [false, true]);
      assert.equal(results[0].created_at, record.created_at);
      assert.equal(results[1].created_at, record.created_at);
      const auditCount = await pool.query(`SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1 AND action = 'origin_binding.created'`, [TENANT]);
      assert.equal(auditCount.rows[0].n, 1);
      const mismatch = await repository.insertBinding(ctx, { ...record, id: 'binding_other_scope', path: '/different' });
      assert.equal(mismatch.error, 'scope_conflict');
      assert.equal(mismatch.status, 409);
    });

    await t.test('simultaneous retest registrations retain one immutable intent', async () => {
      const repository = createTargetHistoryRepository(racingAppPool(pool, 'finding_retest_lineage'));
      const record = {
        tenant_id: TENANT, finding_id: 'fnd_lineage_race', test_run_id: 'run_lineage_race',
        target_id: 'tgt_observation_race', check_id: 'waf.fingerprint.safe',
        created_by: null, created_at: '2026-10-04T00:00:00Z',
      };
      const results = await Promise.all(['lineage_race_a', 'lineage_race_b'].map((id) => repository.insertLineage({ tenantId: TENANT }, { ...record, id })));
      assert.equal(results[0].id, results[1].id);
      assert.deepEqual(results.map((row) => row.replayed).sort(), [false, true]);
      const count = await pool.query(`SELECT count(*)::int AS n FROM finding_retest_lineage WHERE tenant_id = $1`, [TENANT]);
      assert.equal(count.rows[0].n, 1);
    });
  }, availability.env);
});
