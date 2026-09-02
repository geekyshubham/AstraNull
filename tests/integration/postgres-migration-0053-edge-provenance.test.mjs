import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import {
  listMigrationFiles,
  runMigrations,
} from '../../src/persistence/postgres/migrations.mjs';
import {
  ensureHarnessAppRole,
  MIGRATIONS_DIR,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
  withTenantContextAsAppRole,
} from '../helpers/pg-harness.mjs';

const MIGRATION_0052 = '0052_target_edge_detections';
const MIGRATION_0053 = '0053_target_edge_detection_provenance';

const IDS = Object.freeze({
  tenantA: 'ten_edge_prov_a',
  tenantB: 'ten_edge_prov_b',
  environmentA: 'env_edge_prov_a',
  environmentB: 'env_edge_prov_b',
  groupA: 'tg_edge_prov_a',
  groupAOther: 'tg_edge_prov_a_other',
  groupB: 'tg_edge_prov_b',
  targetA: 'tgt_edge_prov_a',
  targetASibling: 'tgt_edge_prov_a_sibling',
  targetAOther: 'tgt_edge_prov_a_other',
  targetB: 'tgt_edge_prov_b',
  runA: 'run_edge_prov_a',
  runASecond: 'run_edge_prov_a_second',
  runAOther: 'run_edge_prov_a_other',
  runB: 'run_edge_prov_b',
});

const CTX_A = { tenantId: IDS.tenantA, userId: 'usr_edge_a', role: 'admin' };

async function seedFixtures(pool) {
  await pool.query(
    `INSERT INTO tenants (id, name) VALUES
       ($1, 'edge tenant A'),
       ($2, 'edge tenant B')`,
    [IDS.tenantA, IDS.tenantB],
  );
  await pool.query(
    `INSERT INTO environments (id, tenant_id, name) VALUES
       ($1, $2, 'prod A'),
       ($3, $4, 'prod B')`,
    [IDS.environmentA, IDS.tenantA, IDS.environmentB, IDS.tenantB],
  );
  await pool.query(
    `INSERT INTO target_groups (id, tenant_id, environment_id, name) VALUES
       ($1, $2, $3, 'group A'),
       ($4, $2, $3, 'group A other'),
       ($5, $6, $7, 'group B')`,
    [
      IDS.groupA,
      IDS.tenantA,
      IDS.environmentA,
      IDS.groupAOther,
      IDS.groupB,
      IDS.tenantB,
      IDS.environmentB,
    ],
  );
  await pool.query(
    `INSERT INTO targets (
       id, tenant_id, target_group_id, kind, value, normalized_value
     ) VALUES
       ($1, $2, $3, 'fqdn', 'a.edge.test', 'a.edge.test'),
       ($4, $2, $3, 'fqdn', 'a-sibling.edge.test', 'a-sibling.edge.test'),
       ($5, $2, $6, 'fqdn', 'a-other.edge.test', 'a-other.edge.test'),
       ($7, $8, $9, 'fqdn', 'b.edge.test', 'b.edge.test')`,
    [
      IDS.targetA,
      IDS.tenantA,
      IDS.groupA,
      IDS.targetASibling,
      IDS.targetAOther,
      IDS.groupAOther,
      IDS.targetB,
      IDS.tenantB,
      IDS.groupB,
    ],
  );
  await pool.query(
    `INSERT INTO test_runs (
       id, tenant_id, target_group_id, target_id, check_id, status
     ) VALUES
       ($1, $2, $3, $4, 'waf.fingerprint.safe', 'verdicted'),
       ($5, $2, $3, $4, 'waf.fingerprint.safe', 'verdicted'),
       ($6, $2, $7, $8, 'waf.fingerprint.safe', 'verdicted'),
       ($9, $10, $11, $12, 'waf.fingerprint.safe', 'verdicted')`,
    [
      IDS.runA,
      IDS.tenantA,
      IDS.groupA,
      IDS.targetA,
      IDS.runASecond,
      IDS.runAOther,
      IDS.groupAOther,
      IDS.targetAOther,
      IDS.runB,
      IDS.tenantB,
      IDS.groupB,
      IDS.targetB,
    ],
  );
}

function edgeInsert(id, { tenantId, groupId, targetId, runId }) {
  return {
    text: `INSERT INTO target_edge_detections (
             id, tenant_id, target_group_id, target_id, test_run_id,
             status, waf_status, cdn_status
           ) VALUES ($1, $2, $3, $4, $5, 'detected', 'detected', 'not_detected')
           RETURNING id, tenant_id, target_group_id, target_id, test_run_id`,
    values: [id, tenantId, groupId, targetId, runId],
  };
}

function assertForeignKey(constraint) {
  return (error) => {
    assert.equal(error?.code, '23503');
    assert.equal(error?.constraint, constraint);
    return true;
  };
}

function legacy0052Sql() {
  const source = readFileSync(
    new URL('../../db/migrations/0052_target_edge_detections.sql', import.meta.url),
    'utf8',
  );
  const withoutParentKeys = source.replace(
    /-- Parent keys for the exact target\/group[\s\S]*?\n\nCREATE TABLE IF NOT EXISTS target_edge_detections \(/,
    'CREATE TABLE IF NOT EXISTS target_edge_detections (',
  );
  const nullableRun = withoutParentKeys.replace(
    '  test_run_id TEXT NOT NULL,',
    '  test_run_id TEXT,',
  );
  const legacy = nullableRun.replace(
    /\n-- Coherent provenance: independent existence is insufficient\.[\s\S]*?REFERENCES test_runs \(tenant_id, id, target_group_id, target_id\);\n/,
    '\n',
  );
  assert.notEqual(legacy, source, 'legacy 0052 fixture must remove current hardening');
  assert.doesNotMatch(legacy, /test_runs_tenant_run_group_target_key/);
  assert.doesNotMatch(legacy, /fk_target_edge_detections_(?:target|run)_binding/);
  assert.match(legacy, /test_run_id TEXT,/);
  return legacy;
}

describe('postgres migration 0053 target edge provenance', () => {
  it('enforces exact tuples and app-role RLS while repository refreshes cannot retarget', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedFixtures(pool);

      const wrongTargetGroup = edgeInsert('edge_wrong_target_group', {
        tenantId: IDS.tenantA,
        groupId: IDS.groupAOther,
        targetId: IDS.targetA,
        runId: IDS.runAOther,
      });
      await assert.rejects(
        () => withTenantContextAsAppRole(pool, IDS.tenantA, (client) =>
          client.query(wrongTargetGroup.text, wrongTargetGroup.values)),
        assertForeignKey('fk_target_edge_detections_target_binding'),
      );

      const wrongTarget = edgeInsert('edge_wrong_target', {
        tenantId: IDS.tenantA,
        groupId: IDS.groupA,
        targetId: IDS.targetASibling,
        runId: IDS.runA,
      });
      await assert.rejects(
        () => withTenantContextAsAppRole(pool, IDS.tenantA, (client) =>
          client.query(wrongTarget.text, wrongTarget.values)),
        assertForeignKey('fk_target_edge_detections_run_binding'),
      );

      const wrongRun = edgeInsert('edge_wrong_run', {
        tenantId: IDS.tenantA,
        groupId: IDS.groupA,
        targetId: IDS.targetA,
        runId: IDS.runAOther,
      });
      await assert.rejects(
        () => withTenantContextAsAppRole(pool, IDS.tenantA, (client) =>
          client.query(wrongRun.text, wrongRun.values)),
        assertForeignKey('fk_target_edge_detections_run_binding'),
      );

      const exact = edgeInsert('edge_exact', {
        tenantId: IDS.tenantA,
        groupId: IDS.groupA,
        targetId: IDS.targetA,
        runId: IDS.runA,
      });
      const inserted = await withTenantContextAsAppRole(pool, IDS.tenantA, (client) =>
        client.query(exact.text, exact.values));
      assert.deepEqual(inserted.rows[0], {
        id: 'edge_exact',
        tenant_id: IDS.tenantA,
        target_group_id: IDS.groupA,
        target_id: IDS.targetA,
        test_run_id: IDS.runA,
      });

      await assert.rejects(
        () => withTenantContextAsAppRole(pool, IDS.tenantA, (client) => client.query(
          `UPDATE target_edge_detections
           SET test_run_id = $3
           WHERE tenant_id = $1 AND id = $2`,
          [IDS.tenantA, 'edge_exact', IDS.runAOther],
        )),
        assertForeignKey('fk_target_edge_detections_run_binding'),
      );
      await assert.rejects(
        () => withTenantContextAsAppRole(pool, IDS.tenantA, (client) => client.query(
          `UPDATE target_edge_detections
           SET target_group_id = $3
           WHERE tenant_id = $1 AND id = $2`,
          [IDS.tenantA, 'edge_exact', IDS.groupAOther],
        )),
        assertForeignKey('fk_target_edge_detections_target_binding'),
      );
      await assert.rejects(
        () => withTenantContextAsAppRole(pool, IDS.tenantA, (client) => client.query(
          `UPDATE target_edge_detections
           SET target_id = $3
           WHERE tenant_id = $1 AND id = $2`,
          [IDS.tenantA, 'edge_exact', IDS.targetAOther],
        )),
        assertForeignKey('fk_target_edge_detections_target_binding'),
      );

      const exactUpdate = await withTenantContextAsAppRole(pool, IDS.tenantA, (client) =>
        client.query(
          `UPDATE target_edge_detections
           SET reason = 'exact tuple retained'
           WHERE tenant_id = $1 AND id = $2
           RETURNING reason`,
          [IDS.tenantA, 'edge_exact'],
        ));
      assert.equal(exactUpdate.rows[0].reason, 'exact tuple retained');

      await withTenantContextAsAppRole(pool, IDS.tenantB, async (client) => {
        const hidden = await client.query(
          `SELECT id FROM target_edge_detections WHERE id = 'edge_exact'`,
        );
        assert.equal(hidden.rows.length, 0);
        const deniedUpdate = await client.query(
          `UPDATE target_edge_detections SET reason = 'cross tenant' WHERE id = 'edge_exact'`,
        );
        assert.equal(deniedUpdate.rowCount, 0);
      });
      await assert.rejects(
        () => withTenantContextAsAppRole(pool, IDS.tenantB, (client) =>
          client.query(exact.text, [
            'edge_cross_tenant',
            IDS.tenantA,
            IDS.groupA,
            IDS.targetA,
            IDS.runA,
          ])),
        (error) => {
          assert.equal(error?.code, '42501');
          return true;
        },
      );

      const repository = createValidationEvidenceRepository(pool);
      const mismatched = await withTenantContextAsAppRole(pool, IDS.tenantA, (client) =>
        repository.upsertTargetEdgeDetection(CTX_A, {
          id: 'edge_attacker_retarget',
          target_group_id: IDS.groupAOther,
          target_id: IDS.targetAOther,
          test_run_id: IDS.runA,
          status: 'detected',
          evidence_json: {},
        }, { client }));
      assert.equal(mismatched, null, 'caller tuple cannot override authoritative run binding');

      const refreshed = await withTenantContextAsAppRole(pool, IDS.tenantA, (client) =>
        repository.upsertTargetEdgeDetection(CTX_A, {
          id: 'edge_replay_id_is_not_provenance',
          target_group_id: IDS.groupA,
          target_id: IDS.targetA,
          test_run_id: IDS.runASecond,
          status: 'not_detected',
          evidence_json: {},
        }, { client }));
      assert.equal(refreshed.id, 'edge_exact');
      const stored = await pool.query(
        `SELECT id, tenant_id, target_group_id, target_id, test_run_id, status
         FROM target_edge_detections WHERE id = 'edge_exact'`,
      );
      assert.deepEqual(stored.rows[0], {
        id: 'edge_exact',
        tenant_id: IDS.tenantA,
        target_group_id: IDS.groupA,
        target_id: IDS.targetA,
        test_run_id: IDS.runASecond,
        status: 'not_detected',
      });
    }, availability.env ?? process.env);
  });

  it('upgrades coherent legacy 0052 rows before enforcing exact app-role tuples', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(
      async (pool) => {
        const files = listMigrationFiles(MIGRATIONS_DIR);
        const before0052 = files.filter((file) => file.version < MIGRATION_0052);
        const migration0052 = files.find((file) => file.version === MIGRATION_0052);
        const migration0053 = files.filter((file) => file.version === MIGRATION_0053);
        assert.ok(migration0052);
        assert.equal(migration0053.length, 1);

        await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files: before0052 });
        await runMigrations(pool, {
          migrationsDir: MIGRATIONS_DIR,
          files: [{ ...migration0052, sql: legacy0052Sql() }],
        });
        await seedFixtures(pool);

        const coherent = edgeInsert('edge_coherent_legacy', {
          tenantId: IDS.tenantA,
          groupId: IDS.groupA,
          targetId: IDS.targetA,
          runId: IDS.runA,
        });
        await pool.query(coherent.text, coherent.values);
        const { results } = await runMigrations(pool, {
          migrationsDir: MIGRATIONS_DIR,
          files: migration0053,
        });
        assert.deepEqual(results, [{ version: MIGRATION_0053, status: 'applied' }]);

        const { rows: constraints } = await pool.query(
          `SELECT conname, contype, convalidated
           FROM pg_constraint
           WHERE conname = ANY($1::text[])
           ORDER BY conname`,
          [[
            'targets_tenant_group_id_key',
            'test_runs_tenant_run_group_target_key',
            'fk_target_edge_detections_target_binding',
            'fk_target_edge_detections_run_binding',
          ]],
        );
        assert.deepEqual(constraints, [
          { conname: 'fk_target_edge_detections_run_binding', contype: 'f', convalidated: true },
          { conname: 'fk_target_edge_detections_target_binding', contype: 'f', convalidated: true },
          { conname: 'targets_tenant_group_id_key', contype: 'u', convalidated: true },
          { conname: 'test_runs_tenant_run_group_target_key', contype: 'u', convalidated: true },
        ]);
        const { rows: columns } = await pool.query(
          `SELECT attnotnull
           FROM pg_attribute
           WHERE attrelid = 'target_edge_detections'::regclass
             AND attname = 'test_run_id'`,
        );
        assert.deepEqual(columns, [{ attnotnull: true }]);

        await ensureHarnessAppRole(pool);
        const visible = await withTenantContextAsAppRole(pool, IDS.tenantA, (client) =>
          client.query(
            `SELECT id, target_group_id, target_id, test_run_id
             FROM target_edge_detections WHERE id = $1`,
            ['edge_coherent_legacy'],
          ));
        assert.deepEqual(visible.rows, [{
          id: 'edge_coherent_legacy',
          target_group_id: IDS.groupA,
          target_id: IDS.targetA,
          test_run_id: IDS.runA,
        }]);

        const wrongTarget = edgeInsert('edge_legacy_wrong_target', {
          tenantId: IDS.tenantA,
          groupId: IDS.groupA,
          targetId: IDS.targetASibling,
          runId: IDS.runA,
        });
        await assert.rejects(
          () => withTenantContextAsAppRole(pool, IDS.tenantA, (client) =>
            client.query(wrongTarget.text, wrongTarget.values)),
          assertForeignKey('fk_target_edge_detections_run_binding'),
        );
      },
      availability.env ?? process.env,
      { applyMigrations: false },
    );
  });

  it('fails a legacy 0052 upgrade before trusting malformed rows', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(
      async (pool) => {
        const files = listMigrationFiles(MIGRATIONS_DIR);
        const before0052 = files.filter((file) => file.version < MIGRATION_0052);
        const migration0052 = files.find((file) => file.version === MIGRATION_0052);
        const migration0053 = files.filter((file) => file.version === MIGRATION_0053);
        assert.ok(migration0052);
        assert.equal(migration0053.length, 1);

        await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files: before0052 });
        await runMigrations(pool, {
          migrationsDir: MIGRATIONS_DIR,
          files: [{ ...migration0052, sql: legacy0052Sql() }],
        });
        await seedFixtures(pool);

        const malformed = edgeInsert('edge_malformed_legacy', {
          tenantId: IDS.tenantA,
          groupId: IDS.groupAOther,
          targetId: IDS.targetA,
          runId: IDS.runAOther,
        });
        await pool.query(malformed.text, malformed.values);

        await assert.rejects(
          () => runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files: migration0053 }),
          (error) => {
            assert.equal(error?.code, '23514');
            assert.equal(error?.constraint, 'target_edge_detections_provenance_binding');
            assert.match(error?.message ?? '', /preexisting target edge detection provenance is malformed/);
            return true;
          },
        );

        const applied = await pool.query(
          `SELECT 1 FROM schema_migrations WHERE version = $1`,
          [MIGRATION_0053],
        );
        assert.equal(applied.rows.length, 0);
        const constraints = await pool.query(
          `SELECT conname
           FROM pg_constraint
           WHERE conname = ANY($1::text[])
           ORDER BY conname`,
          [[
            'test_runs_tenant_run_group_target_key',
            'fk_target_edge_detections_target_binding',
            'fk_target_edge_detections_run_binding',
          ]],
        );
        assert.deepEqual(constraints.rows, []);
        const preserved = await pool.query(
          `SELECT test_run_id IS NOT NULL AS has_run
           FROM target_edge_detections WHERE id = 'edge_malformed_legacy'`,
        );
        assert.deepEqual(preserved.rows, [{ has_run: true }]);
        const column = await pool.query(
          `SELECT attnotnull
           FROM pg_attribute
           WHERE attrelid = 'target_edge_detections'::regclass
             AND attname = 'test_run_id'`,
        );
        assert.equal(column.rows[0].attnotnull, false);
      },
      availability.env ?? process.env,
      { applyMigrations: false },
    );
  });
});
