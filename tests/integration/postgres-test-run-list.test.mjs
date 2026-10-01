import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createPostgresValidationServices } from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { listTestRuns as listDevTestRuns } from '../../src/services/testRuns.mjs';
import { resetStoreForTests } from '../../src/store.mjs';
import { resolvePostgresHarnessAvailability, withEphemeralPostgres } from '../helpers/pg-harness.mjs';

const TENANT = 'ten_run_list';
const OTHER = 'ten_run_list_other';
const CTX = { tenantId: TENANT, userId: 'run-list-test', role: 'viewer' };

async function seedTenant(pool, tenantId, groups) {
  await withTenantContext(pool, tenantId, async (client) => {
    await client.query('INSERT INTO tenants (id, name) VALUES ($1, $1)', [tenantId]);
    await client.query("INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, 'prod')", [`env_${tenantId}`, tenantId]);
    let octet = 10;
    for (const [group, targets] of Object.entries(groups)) {
      await client.query(
        "INSERT INTO target_groups (id, tenant_id, environment_id, name, validation_mode) VALUES ($1, $2, $3, $1, 'external_only')",
        [group, tenantId, `env_${tenantId}`],
      );
      for (const [target, runCount] of Object.entries(targets)) {
        const value = `203.0.113.${octet}`;
        octet += 1;
        await client.query(
          `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, expected_behavior)
           VALUES ($1, $2, $3, 'ip', $4, $4, 'must_block_before_origin')`,
          [target, tenantId, group, value],
        );
        for (let index = 0; index < runCount; index += 1) {
          const runId = `run_${target}_${index}`;
          const at = new Date(Date.UTC(2026, 0, 1, 0, octet, index)).toISOString();
          await client.query(
            `INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status,
               probe_external_result, awaiting_external_probe, remediation_template, safety_constraints,
               correlation_json, started_at, completed_at, created_at)
             VALUES ($1, $2, $3, $4, 'origin.direct_bypass.safe', 'verdicted', 'blocked', FALSE, 'block_origin',
               '{}'::jsonb, '{}'::jsonb, $5::timestamptz, $5::timestamptz, $5::timestamptz)`,
            [runId, tenantId, group, target, at],
          );
          if (index === 0) {
            await client.query(
              `INSERT INTO verdicts (id, tenant_id, test_run_id, target_id, check_id, verdict, confidence,
                 placement_confidence_json, explanation, evidence_ids, created_at)
               VALUES ($1, $2, $3, $4, 'origin.direct_bypass.safe', 'edge_protected', 'external_only',
                 '{}'::jsonb, 'blocked at edge', ARRAY['evt_x']::text[], $5::timestamptz)`,
              [`vrd_${runId}`, tenantId, runId, target, at],
            );
          }
        }
      }
    }
  });
}

describe('postgres test-run list parity', () => {
  it('honours target, group, and limit filters and attaches verdicts', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }
    await withEphemeralPostgres(async (pool) => {
      await seedTenant(pool, TENANT, { tg_a: { tgt_a1: 3, tgt_a2: 2 }, tg_b: { tgt_b1: 2 } });
      await seedTenant(pool, OTHER, { tg_other: { tgt_other: 2 } });
      await withTenantContext(pool, TENANT, (client) => client.query(
        "UPDATE test_runs SET started_at = '2027-01-01T00:00:00.000Z' WHERE tenant_id = $1 AND id = 'run_tgt_a1_0'",
        [TENANT],
      ));
      const { testRuns } = createPostgresValidationServices({
        validationEvidence: createValidationEvidenceRepository(pool),
        audit: createAuditRepository(pool),
        coreCatalog: createCoreCatalogRepository(pool),
        probeJobs: createProbeJobRepository(pool),
        killSwitch: createKillSwitchRepository(pool),
      });

      const all = await testRuns.listTestRuns(CTX, {});
      assert.equal(all.length, 7, 'tenant-scoped: other tenant runs never appear');
      assert.equal(all[0].id, 'run_tgt_a1_0', 'newest started run sorts first even when created earlier');

      const byTarget = await testRuns.listTestRuns(CTX, { target_id: 'tgt_a1' });
      assert.deepEqual([...new Set(byTarget.map((run) => run.target_id))], ['tgt_a1']);
      assert.equal(byTarget.length, 3);

      const byGroup = await testRuns.listTestRuns(CTX, { target_group_id: 'tg_b' });
      assert.deepEqual([...new Set(byGroup.map((run) => run.target_group_id))], ['tg_b']);

      const byCheck = await testRuns.listTestRuns(CTX, { check_id: 'origin.direct_bypass.safe', limit: '3' });
      assert.equal(byCheck.length, 3);
      assert.deepEqual(await testRuns.listTestRuns(CTX, { check_id: 'waf.fingerprint.safe' }), []);

      const limited = await testRuns.listTestRuns(CTX, { target_group_id: 'tg_a', limit: '2' });
      assert.equal(limited.length, 2);

      const verdicted = byTarget.find((run) => run.id === 'run_tgt_a1_0');
      assert.equal(verdicted.verdict?.verdict, 'edge_protected');
      assert.equal(byTarget.find((run) => run.id === 'run_tgt_a1_1').verdict, null);

      const empty = await testRuns.listTestRunsEnvelope(CTX, { target_id: 'tgt_other' });
      assert.equal(empty.count, 0, 'another tenant target id returns nothing');
      assert.equal(empty.meta.empty_reason, 'No test runs match this target filter.');

      await withTenantContext(pool, TENANT, (client) => client.query(
        `INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status, started_at, created_at)
         SELECT 'run_cap_' || lpad(n::text, 3, '0'), $1, 'tg_a', 'tgt_a1',
                'origin.direct_bypass.safe', 'completed',
                '2025-01-01T00:00:00.000Z'::timestamptz + n * interval '1 second',
                '2025-01-01T00:00:00.000Z'::timestamptz + n * interval '1 second'
         FROM generate_series(1, 500) AS n`,
        [TENANT],
      ));
      assert.equal((await testRuns.listTestRuns(CTX)).length, 100, 'Postgres default is bounded');
      assert.equal((await testRuns.listTestRuns(CTX, { limit: '9999' })).length, 100, 'Postgres max is clamped to documented 100');

      const devRuns = Array.from({ length: 507 }, (_, index) => ({
        id: `run_dev_cap_${index}`,
        tenant_id: TENANT,
        target_group_id: 'tg_a',
        target_id: 'tgt_a1',
        check_id: 'origin.direct_bypass.safe',
        status: 'completed',
        started_at: new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
        created_at: new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
      }));
      resetStoreForTests({ testRuns: devRuns, verdicts: [] });
      assert.equal(listDevTestRuns(CTX).length, 100, 'dev-json uses the same default');
      assert.equal(listDevTestRuns(CTX, { limit: '9999' }).length, 100, 'dev-json clamps to documented max 100');
      assert.equal(listDevTestRuns(CTX, { limit: 'abc' }).length, 100, 'dev-json falls back to default for non-numeric limit');
      assert.equal(listDevTestRuns(CTX, { limit: '-5' }).length, 100, 'dev-json falls back to default for negative limit');
      assert.equal(listDevTestRuns(CTX, { limit: '0' }).length, 100, 'dev-json falls back to default for zero limit');
    });
  });
});
