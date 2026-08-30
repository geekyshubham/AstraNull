import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  listMigrationFiles,
  runMigrations,
} from '../../src/persistence/postgres/migrations.mjs';
import {
  MIGRATIONS_DIR,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const MIGRATION_0044 = '0044_target_management_rules_and_schedules';

describe('postgres migration 0044 target compatibility', () => {
  it('backfills legacy URL/TCP/canary rows and accepts previous-release writes', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(
      async (pool) => {
        const files = listMigrationFiles(MIGRATIONS_DIR);
        const before0044 = files.filter((file) => file.version < MIGRATION_0044);
        const migration0044 = files.filter((file) => file.version === MIGRATION_0044);
        assert.equal(migration0044.length, 1);
        await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files: before0044 });

        await pool.query(`INSERT INTO tenants (id, name) VALUES ('ten_0044', 'migration 0044')`);
        await pool.query(
          `INSERT INTO target_groups (id, tenant_id, name)
           VALUES ('tg_0044', 'ten_0044', 'legacy targets')`,
        );
        await pool.query(
          `INSERT INTO targets (id, tenant_id, target_group_id, kind, value)
           VALUES
             ('tgt_0044_url', 'ten_0044', 'tg_0044', 'URL', '  https://EXAMPLE.com/Case?q=1#Fragment  '),
             ('tgt_0044_tcp', 'ten_0044', 'tg_0044', 'tcp', '  EXAMPLE.com:443  '),
             ('tgt_0044_canary', 'ten_0044', 'tg_0044', 'canary', '  Canary.EXAMPLE.com.  '),
             ('tgt_0044_domain', 'ten_0044', 'tg_0044', 'domain', '  WWW.Example.COM.  ')`,
        );

        const applied = await runMigrations(pool, {
          migrationsDir: MIGRATIONS_DIR,
          files: migration0044,
        });
        assert.deepEqual(applied.results.map(({ version, status }) => [version, status]), [
          [MIGRATION_0044, 'applied'],
        ]);

        const legacy = await pool.query(
          `SELECT id, kind, value, normalized_value
           FROM targets
           WHERE tenant_id = 'ten_0044'
           ORDER BY id`,
        );
        const byId = new Map(legacy.rows.map((row) => [row.id, row]));
        assert.deepEqual(
          [byId.get('tgt_0044_url').kind, byId.get('tgt_0044_url').normalized_value],
          ['url', 'https://EXAMPLE.com/Case?q=1#Fragment'],
        );
        assert.equal(byId.get('tgt_0044_tcp').normalized_value, 'EXAMPLE.com:443');
        assert.equal(byId.get('tgt_0044_canary').normalized_value, 'Canary.EXAMPLE.com.');
        assert.deepEqual(
          [byId.get('tgt_0044_domain').kind, byId.get('tgt_0044_domain').normalized_value],
          ['fqdn', 'www.example.com'],
        );

        const previousReleaseInsert = await pool.query(
          `INSERT INTO targets (id, tenant_id, target_group_id, kind, value)
           VALUES ('tgt_0044_rollback', 'ten_0044', 'tg_0044', 'URL', '  https://Rollback.EXAMPLE/path  ')
           RETURNING kind, normalized_value`,
        );
        assert.deepEqual(previousReleaseInsert.rows[0], {
          kind: 'url',
          normalized_value: 'https://Rollback.EXAMPLE/path',
        });

        const previousReleaseUpdate = await pool.query(
          `UPDATE targets
           SET value = '  https://Rollback.EXAMPLE/changed  '
           WHERE id = 'tgt_0044_rollback'
           RETURNING normalized_value`,
        );
        assert.equal(
          previousReleaseUpdate.rows[0].normalized_value,
          'https://Rollback.EXAMPLE/changed',
        );

        const currentReleaseInsert = await pool.query(
          `INSERT INTO targets (
             id, tenant_id, target_group_id, kind, value, normalized_value
           ) VALUES (
             'tgt_0044_current', 'ten_0044', 'tg_0044', 'url',
             'https://EXAMPLE.com/current#ignored', 'https://example.com/current'
           ) RETURNING normalized_value`,
        );
        assert.equal(currentReleaseInsert.rows[0].normalized_value, 'https://example.com/current');

        const contract = await pool.query(
          `SELECT a.attnotnull,
                  EXISTS (
                    SELECT 1 FROM pg_trigger t
                    WHERE t.tgrelid = 'targets'::regclass
                      AND t.tgname = 'targets_normalized_value_compat'
                      AND NOT t.tgisinternal
                  ) AS compatibility_trigger
           FROM pg_attribute a
           WHERE a.attrelid = 'targets'::regclass
             AND a.attname = 'normalized_value'`,
        );
        assert.deepEqual(contract.rows[0], { attnotnull: true, compatibility_trigger: true });
      },
      process.env,
      { applyMigrations: false },
    );
  });
});
