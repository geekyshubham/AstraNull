import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import {
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
  withTenantContextAsAppRole,
} from '../helpers/pg-harness.mjs';

const IDS = Object.freeze({
  tenantA: 'ten_state_batch_a',
  tenantB: 'ten_state_batch_b',
  environmentA: 'env_state_batch_a',
  environmentB: 'env_state_batch_b',
  groupA: 'tg_state_batch_a',
  groupB: 'tg_state_batch_b',
  targetA: 'tgt_state_batch_a',
  targetB: 'tgt_state_batch_b',
  runA: 'run_state_batch_a',
  runB: 'run_state_batch_b',
  verdictA: 'verdict_state_batch_a',
  verdictB: 'verdict_state_batch_b',
  eventA: 'event_state_batch_a',
  eventB: 'event_state_batch_b',
});

async function seed(pool) {
  await pool.query(
    `INSERT INTO tenants (id, name) VALUES ($1, 'state A'), ($2, 'state B')`,
    [IDS.tenantA, IDS.tenantB],
  );
  await pool.query(
    `INSERT INTO environments (id, tenant_id, name) VALUES
       ($1, $2, 'prod A'), ($3, $4, 'prod B')`,
    [IDS.environmentA, IDS.tenantA, IDS.environmentB, IDS.tenantB],
  );
  await pool.query(
    `INSERT INTO target_groups (id, tenant_id, environment_id, name) VALUES
       ($1, $2, $3, 'group A'), ($4, $5, $6, 'group B')`,
    [IDS.groupA, IDS.tenantA, IDS.environmentA, IDS.groupB, IDS.tenantB, IDS.environmentB],
  );
  await pool.query(
    `INSERT INTO targets (
       id, tenant_id, target_group_id, kind, value, normalized_value
     ) VALUES
       ($1, $2, $3, 'fqdn', 'state-a.test', 'state-a.test'),
       ($4, $5, $6, 'fqdn', 'state-b.test', 'state-b.test')`,
    [IDS.targetA, IDS.tenantA, IDS.groupA, IDS.targetB, IDS.tenantB, IDS.groupB],
  );
  await pool.query(
    `INSERT INTO test_runs (
       id, tenant_id, target_group_id, target_id, check_id, status, created_at
     ) VALUES
       ($1, $2, $3, $4, 'origin.direct_reachability.safe', 'verdicted', now()),
       ($5, $6, $7, $8, 'origin.direct_reachability.safe', 'verdicted', now())`,
    [
      IDS.runA,
      IDS.tenantA,
      IDS.groupA,
      IDS.targetA,
      IDS.runB,
      IDS.tenantB,
      IDS.groupB,
      IDS.targetB,
    ],
  );
  await pool.query(
    `INSERT INTO events (
       id, tenant_id, test_run_id, target_id, check_id, source,
       signal_type, producer_kind, nonce_hash, timestamp, metadata_json
     ) VALUES
       ($1, $2, $3, $4, 'origin.direct_reachability.safe', 'probe_worker',
        'probe_result', 'signed_probe', 'nonce_state_a', now(), '{}'::jsonb),
       ($5, $6, $7, $8, 'origin.direct_reachability.safe', 'probe_worker',
        'probe_result', 'signed_probe', 'nonce_state_b', now(), '{}'::jsonb)`,
    [
      IDS.eventA,
      IDS.tenantA,
      IDS.runA,
      IDS.targetA,
      IDS.eventB,
      IDS.tenantB,
      IDS.runB,
      IDS.targetB,
    ],
  );
  await pool.query(
    `INSERT INTO verdicts (
       id, tenant_id, test_run_id, target_id, check_id, verdict, evidence_ids, created_at
     ) VALUES
       ($1, $2, $3, $4, 'origin.direct_reachability.safe', 'protected', ARRAY[$5], now()),
       ($6, $7, $8, $9, 'origin.direct_reachability.safe', 'protected', ARRAY[$10], now())`,
    [
      IDS.verdictA,
      IDS.tenantA,
      IDS.runA,
      IDS.targetA,
      IDS.eventA,
      IDS.verdictB,
      IDS.tenantB,
      IDS.runB,
      IDS.targetB,
      IDS.eventB,
    ],
  );
}

describe('postgres state evidence batch app-role RLS', () => {
  it('returns only the app-role tenant when the requested run array mixes tenants', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seed(pool);
      const repository = createValidationEvidenceRepository(pool);
      const mixedRunIds = [IDS.runB, IDS.runA];

      const tenantAResult = await withTenantContextAsAppRole(pool, IDS.tenantA, (client) =>
        repository.loadRunEvidenceBatch(
          { tenantId: IDS.tenantA },
          {
            runIds: mixedRunIds,
            eventRunIds: mixedRunIds,
            eventLimitPerRun: 1000,
          },
          { client },
        ));
      assert.deepEqual(tenantAResult.verdicts.map((row) => row.id), [IDS.verdictA]);
      assert.deepEqual(tenantAResult.events.map((row) => row.id), [IDS.eventA]);

      const tenantBResult = await withTenantContextAsAppRole(pool, IDS.tenantB, (client) =>
        repository.loadRunEvidenceBatch(
          { tenantId: IDS.tenantB },
          {
            runIds: mixedRunIds,
            eventRunIds: mixedRunIds,
            eventLimitPerRun: 1000,
          },
          { client },
        ));
      assert.deepEqual(tenantBResult.verdicts.map((row) => row.id), [IDS.verdictB]);
      assert.deepEqual(tenantBResult.events.map((row) => row.id), [IDS.eventB]);
    }, availability.env ?? process.env);
  });
});
