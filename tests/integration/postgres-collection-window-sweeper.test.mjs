import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createAgentControlRepository } from '../../src/persistence/postgres/agentControlRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import {
  createValidationEvidenceRepository,
  verdictWasInserted,
} from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createPostgresValidationServices } from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { sweepExpiredCollectionWindows } from '../../scripts/collection-window-sweeper.mjs';
import {
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const TENANT = 'ten_sweep_a';
const OTHER_TENANT = 'ten_sweep_b';
const ENVIRONMENT = 'env_sweep_a';
const TARGET_GROUP = 'tg_sweep_a';
const TARGET = 'tgt_sweep_a';
const RUN = 'run_sweep_a';
const CHECK_ID = 'origin.direct_bypass.safe';

const CTX = { tenantId: TENANT, userId: 'collection-window-sweeper', role: 'system' };

/**
 * Build a full validation service instance over a live pool. Each call creates its own
 * repository instances so two instances model two independent sweeper processes.
 *
 * @param {import('pg').Pool} pool
 */
function buildValidationServices(pool) {
  return createPostgresValidationServices({
    validationEvidence: createValidationEvidenceRepository(pool),
    audit: createAuditRepository(pool),
    coreCatalog: createCoreCatalogRepository(pool),
    agentControl: createAgentControlRepository(pool),
    probeJobs: createProbeJobRepository(pool),
    killSwitch: createKillSwitchRepository(pool),
  });
}

/**
 * Seed a run that reached `collecting` with external probe evidence and a collection
 * deadline that has already elapsed, and no agent observation. This is exactly the
 * state that stays stuck forever in Postgres mode without a client-independent sweeper.
 *
 * @param {import('pg').Pool} pool
 */
async function seedExpiredCollectingRun(pool) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(
      `INSERT INTO tenants (id, name) VALUES ($1, 'sweep tenant A'), ($2, 'sweep tenant B')`,
      [TENANT, OTHER_TENANT],
    );
    await client.query(`INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, 'env')`, [
      ENVIRONMENT,
      TENANT,
    ]);
    await client.query(
      `INSERT INTO target_groups (id, tenant_id, environment_id, name, validation_mode)
       VALUES ($1, $2, $3, 'sweep group', 'agent_assisted')`,
      [TARGET_GROUP, TENANT, ENVIRONMENT],
    );
    await client.query(
      `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, expected_behavior)
       VALUES ($1, $2, $3, 'ip', '203.0.113.10', '203.0.113.10', 'must_block_before_origin')`,
      [TARGET, TENANT, TARGET_GROUP],
    );
    await client.query(
      `INSERT INTO test_runs (
         id, tenant_id, target_group_id, target_id, check_id, status,
         probe_external_result, awaiting_external_probe, remediation_template,
         safety_constraints, correlation_json, collection_deadline_at, started_at
       ) VALUES (
         $1, $2, $3, $4, $5, 'collecting',
         'connected', FALSE, 'block_origin',
         '{"max_events": 50}'::jsonb, '{"nonce_hash": "nh_sweep", "window_ms": 120000}'::jsonb,
         now() - interval '10 minutes', now() - interval '20 minutes'
       )`,
      [RUN, TENANT, TARGET_GROUP, TARGET, CHECK_ID],
    );
    // External probe evidence; no agent_observation, so the window closes unobserved.
    await client.query(
      `INSERT INTO events (
         id, tenant_id, test_run_id, target_id, check_id, source, signal_type,
         nonce_hash, timestamp, metadata_json
       ) VALUES (
         'evt_sweep_probe', $1, $2, $3, $4, 'probe_worker', 'probe_result',
         'nh_sweep', now() - interval '19 minutes', '{"external_result": "connected"}'::jsonb
       )`,
      [TENANT, RUN, TARGET, CHECK_ID],
    );
  });
}

/**
 * @param {import('pg').Pool} pool
 * @param {string} status
 */
async function tryInsertActiveRun(pool, runId, status) {
  try {
    await withTenantContext(pool, TENANT, async (client) => {
      await client.query(
        `INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [runId, TENANT, TARGET_GROUP, TARGET, CHECK_ID, status],
      );
    });
    return { ok: true };
  } catch (err) {
    return { ok: false, code: err?.code, constraint: err?.constraint, message: err?.message };
  }
}

/**
 * @param {import('pg').Pool} pool
 */
async function readRunState(pool) {
  return withTenantContext(pool, TENANT, async (client) => {
    const verdicts = await client.query(
      `SELECT id, verdict, confidence FROM verdicts WHERE tenant_id = $1 AND test_run_id = $2`,
      [TENANT, RUN],
    );
    const run = await client.query(
      `SELECT status, completed_at FROM test_runs WHERE tenant_id = $1 AND id = $2`,
      [TENANT, RUN],
    );
    const noObservation = await client.query(
      `SELECT id, metadata_json FROM events
        WHERE tenant_id = $1 AND test_run_id = $2 AND signal_type = 'agent_no_observation'`,
      [TENANT, RUN],
    );
    const audits = await client.query(
      `SELECT action, metadata_json FROM audit_logs
        WHERE tenant_id = $1 AND resource_id = $2 AND action LIKE 'verdict.%'
        ORDER BY sequence`,
      [TENANT, RUN],
    );
    return {
      verdicts: verdicts.rows,
      run: run.rows[0] ?? null,
      noObservationEvents: noObservation.rows,
      verdictAudits: audits.rows,
    };
  });
}

describe('postgres collection-window sweeper (expired collecting runs)', () => {
  it('finalizes an expired run with no client call and frees the uniq_active_test_run slot', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedExpiredCollectingRun(pool);

      // Precondition: the stuck run holds the active slot, so no new run can start.
      const blocked = await tryInsertActiveRun(pool, 'run_sweep_blocked', 'collecting');
      assert.equal(blocked.ok, false, 'expected the stuck collecting run to hold the active slot');
      assert.equal(blocked.code, '23505', 'expected a unique violation');

      const services = buildValidationServices(pool);
      const summary = await services.testRuns.sweepExpiredCollectingRuns(CTX, {});

      assert.equal(summary.examined, 1);
      assert.equal(summary.finalized, 1);
      assert.deepEqual(summary.errors, []);

      const state = await readRunState(pool);

      // A verdict was written without any client call.
      assert.equal(state.verdicts.length, 1);
      // No agent is bound, so correlation yields an evidence-honest inconclusive verdict.
      assert.equal(state.verdicts[0].verdict, 'inconclusive');

      // The bounded-window closure is recorded as evidence.
      assert.equal(state.noObservationEvents.length, 1);
      assert.equal(
        state.noObservationEvents[0].metadata_json.reason,
        'bounded_observation_window_elapsed',
      );

      // Exactly one verdict audit event, matching the stored verdict.
      assert.equal(state.verdictAudits.length, 1);
      assert.equal(state.verdictAudits[0].action, 'verdict.finalized_no_observation');
      assert.equal(state.verdictAudits[0].metadata_json.verdict, 'inconclusive');

      // The run left the active statuses, so the slot is free.
      assert.equal(state.run.status, 'verdicted');
      assert.ok(state.run.completed_at);

      const afterSweep = await tryInsertActiveRun(pool, 'run_sweep_next', 'collecting');
      assert.equal(
        afterSweep.ok,
        true,
        `expected a subsequent run to start after the sweep: ${afterSweep.message ?? ''}`,
      );
    });
  });

  it('two concurrent sweeper instances produce exactly one verdict and one audit event', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedExpiredCollectingRun(pool);

      // Two independent service instances over the same database = two sweeper processes.
      const sweeperA = buildValidationServices(pool);
      const sweeperB = buildValidationServices(pool);

      const [resultA, resultB] = await Promise.all([
        sweeperA.testRuns.sweepExpiredCollectingRuns(CTX, {}),
        sweeperB.testRuns.sweepExpiredCollectingRuns(CTX, {}),
      ]);

      assert.deepEqual(resultA.errors, []);
      assert.deepEqual(resultB.errors, []);

      // Exactly one sweeper did the finalization work.
      assert.equal(
        resultA.finalized + resultB.finalized,
        1,
        'exactly one sweeper instance should finalize the run',
      );

      const state = await readRunState(pool);

      // uniq_verdict_per_test_run + ON CONFLICT DO NOTHING guarantee a single verdict.
      assert.equal(state.verdicts.length, 1);
      // The side effects ran exactly once, for the verdict that was actually stored.
      assert.equal(state.verdictAudits.length, 1);
      assert.equal(state.verdictAudits[0].metadata_json.verdict, state.verdicts[0].verdict);
      assert.equal(state.noObservationEvents.length, 1);
      assert.equal(state.run.status, 'verdicted');
    });
  });

  it('createVerdictIfAbsent DO NOTHING path returns the live incumbent instead of null', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedExpiredCollectingRun(pool);

      const repo = createValidationEvidenceRepository(pool);
      const baseRecord = {
        test_run_id: RUN,
        target_id: TARGET,
        check_id: CHECK_ID,
        evidence_ids: [],
        placement_confidence: { level: 'low' },
        created_at: new Date().toISOString(),
      };

      const first = await repo.createVerdictIfAbsent(CTX, {
        ...baseRecord,
        id: 'ver_first',
        verdict: 'bypassable',
        confidence: 'high',
        explanation: 'first writer wins',
      });
      assert.equal(first.verdict, 'bypassable');
      assert.equal(verdictWasInserted(first), true);

      // Second writer with an OPPOSITE verdict. This is the branch that previously
      // ran DO UPDATE and silently rewrote a published verdict; it now hits
      // DO NOTHING, whose RETURNING is empty, and must resolve to the incumbent
      // rather than null (every caller dereferences the result).
      const second = await repo.createVerdictIfAbsent(CTX, {
        ...baseRecord,
        id: 'ver_second',
        verdict: 'protected',
        confidence: 'low',
        explanation: 'second writer must not overwrite',
      });

      assert.notEqual(second, null, 'DO NOTHING path must not return null');
      assert.equal(verdictWasInserted(second), false);
      // The incumbent is returned verbatim: id, verdict and explanation are the first writer's.
      assert.equal(second.id, 'ver_first');
      assert.equal(second.verdict, 'bypassable');
      assert.equal(second.confidence, 'high');
      assert.equal(second.explanation, 'first writer wins');

      const stored = await withTenantContext(pool, TENANT, async (client) =>
        client.query(
          `SELECT id, verdict FROM verdicts WHERE tenant_id = $1 AND test_run_id = $2`,
          [TENANT, RUN],
        ),
      );
      assert.equal(stored.rows.length, 1, 'uniq_verdict_per_test_run must keep exactly one row');
      assert.equal(stored.rows[0].id, 'ver_first');
      assert.equal(stored.rows[0].verdict, 'bypassable');
    });
  });

  it('concurrent createVerdictIfAbsent writers converge on one verdict with no lost dereference', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedExpiredCollectingRun(pool);

      const repo = createValidationEvidenceRepository(pool);
      const record = (id, verdict) => ({
        id,
        test_run_id: RUN,
        target_id: TARGET,
        check_id: CHECK_ID,
        verdict,
        confidence: 'medium',
        explanation: `${id} explanation`,
        evidence_ids: [],
        placement_confidence: {},
        created_at: new Date().toISOString(),
      });

      // Genuine concurrency: both transactions race on the unique index.
      const results = await Promise.all([
        repo.createVerdictIfAbsent(CTX, record('ver_race_a', 'bypassable')),
        repo.createVerdictIfAbsent(CTX, record('ver_race_b', 'protected')),
        repo.createVerdictIfAbsent(CTX, record('ver_race_c', 'inconclusive')),
      ]);

      // No caller got null, so no caller can crash on dereference.
      for (const result of results) {
        assert.notEqual(result, null);
        assert.ok(result.verdict);
      }

      // Exactly one insert won; the rest observed the incumbent.
      const inserted = results.filter((r) => verdictWasInserted(r));
      assert.equal(inserted.length, 1, 'exactly one writer should insert');

      const stored = await withTenantContext(pool, TENANT, async (client) =>
        client.query(
          `SELECT id, verdict FROM verdicts WHERE tenant_id = $1 AND test_run_id = $2`,
          [TENANT, RUN],
        ),
      );
      assert.equal(stored.rows.length, 1);

      // Every caller's view agrees with the single stored row.
      for (const result of results) {
        assert.equal(result.id, stored.rows[0].id);
        assert.equal(result.verdict, stored.rows[0].verdict);
      }
    });
  });

  it('sweeper runner refuses implicit cross-tenant enumeration and is tenant-scoped', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedExpiredCollectingRun(pool);

      const services = buildValidationServices(pool);

      // Sweeping an unrelated tenant must not touch this tenant's run.
      const results = await sweepExpiredCollectionWindows({
        services,
        tenantIds: [OTHER_TENANT],
      });
      assert.equal(results.length, 1);
      assert.equal(results[0].tenant_id, OTHER_TENANT);
      assert.equal(results[0].examined, 0);
      assert.equal(results[0].finalized, 0);

      const untouched = await readRunState(pool);
      assert.equal(untouched.verdicts.length, 0);
      assert.equal(untouched.run.status, 'collecting');

      // Scoped to the owning tenant, the same runner finalizes it.
      const scoped = await sweepExpiredCollectionWindows({ services, tenantIds: [TENANT] });
      assert.equal(scoped[0].finalized, 1);

      const swept = await readRunState(pool);
      assert.equal(swept.verdicts.length, 1);
      assert.equal(swept.run.status, 'verdicted');
    });
  });
});
