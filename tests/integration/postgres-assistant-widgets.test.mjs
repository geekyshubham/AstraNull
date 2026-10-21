import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAssistantWidgetRepository } from '../../src/persistence/postgres/assistantWidgetRepository.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createPgPool, closePgPool } from '../../src/persistence/postgres/pool.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { assertLatestMigrationApplied, listMigrationFiles, runMigrations } from '../../src/persistence/postgres/migrations.mjs';
import { grantPostgresAppRolePrivileges } from '../../scripts/postgres-grant-app-role.mjs';
import { databaseUrlWithDatabase, resolvePostgresHarnessAvailability, withEphemeralPostgres, ensureHarnessAppRole, MIGRATIONS_DIR } from '../helpers/pg-harness.mjs';

const TENANT = 'ten_widgets', OTHER = 'ten_widgets_other';
const ctx = { tenantId: TENANT, userId: 'usr_widget', role: 'viewer', persistenceMode: 'postgres' };
const teammate = { ...ctx, userId: 'usr_teammate' }, foreign = { ...ctx, tenantId: OTHER, userId: 'usr_foreign' };
const config = { name: 'Observed gaps', question: 'What was observed?', template: 'summary' };
function localEnv() {
  const env = { ...process.env, ASTRANULL_RUN_PUBLIC_DNS: '0' };
  for (const key of ['ASTRANULL_DATABASE_URL', 'ASTRANULL_ADMIN_DATABASE_URL']) {
    if (!env[key]) continue;
    const url = new URL(env[key]);
    assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname), 'test database must be loopback');
    assert.ok(!url.searchParams.has('host') && !url.searchParams.has('hostaddr'), 'no host override');
  }
  return env;
}

test('real local PostgreSQL personal widgets: migration, RLS, bounds, races and atomic audit', { timeout: 120_000 }, async (t) => {
  const availability = await resolvePostgresHarnessAvailability(localEnv(), { tryDocker: false });
  if (!availability.available) return t.skip(availability.reason);
  await withEphemeralPostgres(async (owner, { databaseName }) => {
    await owner.query(`INSERT INTO tenants (id,name) VALUES ($1,'Widgets'),($2,'Other widgets')`, [TENANT, OTHER]);
    await owner.query(`INSERT INTO users (id,tenant_id,email,role) VALUES ($1,$2,'widget@example.test','viewer'),
      ($3,$2,'teammate@example.test','viewer'),($4,$5,'foreign@example.test','viewer')`,
    [ctx.userId, TENANT, teammate.userId, foreign.userId, OTHER]);
    await owner.query(`INSERT INTO target_groups (id,tenant_id,name) VALUES ('tg_widget_other',$1,'Other historical')`, [OTHER]);
    await owner.query(`INSERT INTO targets (id,tenant_id,target_group_id,kind,value,normalized_value,protocol,port,expected_behavior)
      VALUES ('tgt_widget_other',$1,'tg_widget_other','fqdn','other.example.test','other.example.test','https',443,'intentionally_public')`, [OTHER]);
    const url = new URL(databaseUrlWithDatabase(owner.options.connectionString, databaseName));
    url.username = 'astranull_app'; url.password = 'astranull_app_local_dev';
    const pool = createPgPool({ ASTRANULL_DATABASE_URL: url.toString() });
    const audit = createAuditRepository(pool), repository = createAssistantWidgetRepository(pool, { auditRepository: audit });
    const sql = (actor, statement, params = []) => withTenantContext(pool, actor.tenantId, async (client) => {
      await client.query("SELECT set_config('app.user_id',$1,true)", [actor.userId]);
      return client.query(statement, params);
    });
    const count = async () => ({ widgets: (await repository.list(ctx)).length,
      audits: (await audit.listAuditEntries(ctx)).filter((entry) => entry.resource_type === 'assistant_widget').length });
    try {
      await t.test('application role cannot bypass forced tenant AND user RLS; missing settings return no rows', async () => {
        assert.deepEqual((await pool.query(`SELECT current_user AS role, rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user`)).rows[0],
          { role: 'astranull_app', rolsuper: false, rolbypassrls: false });
        assert.deepEqual((await pool.query(`SELECT relrowsecurity, relforcerowsecurity, pg_get_userbyid(relowner)=current_user AS is_owner
          FROM pg_class WHERE oid='assistant_widgets'::regclass`)).rows[0], { relrowsecurity: true, relforcerowsecurity: true, is_owner: false });
        const mine = await repository.create(ctx, config), theirs = await repository.create(teammate, config);
        assert.deepEqual((await sql(teammate, 'SELECT id FROM assistant_widgets WHERE id=$1', [mine.id])).rows, []);
        assert.deepEqual((await sql(foreign, 'SELECT id FROM assistant_widgets WHERE id=$1', [mine.id])).rows, []);
        assert.deepEqual((await pool.query('SELECT id FROM assistant_widgets')).rows, []);
        assert.deepEqual((await withTenantContext(pool, TENANT, (client) => client.query('SELECT id FROM assistant_widgets'))).rows, []);
        assert.equal((await sql(teammate, `UPDATE assistant_widgets SET version=2 WHERE id=$1`, [mine.id])).rowCount, 0);
        assert.equal((await sql(teammate, `DELETE FROM assistant_widgets WHERE id=$1`, [mine.id])).rowCount, 0);
        await assert.rejects(repository.remove(teammate, mine.id, 1), (error) => error.code === 'widget_not_found');
        assert.equal((await repository.list(teammate))[0].id, theirs.id);
        await repository.remove(ctx, mine.id, 1); await repository.remove(teammate, theirs.id, 1);
      });
      await t.test('concurrent creates enforce hard12 slots per user and every success has one chained audit', async () => {
        const before = await count();
        const results = await Promise.allSettled(Array.from({ length: 16 }, () => repository.create(ctx, config)));
        assert.equal(results.filter((result) => result.status === 'fulfilled').length, 12);
        assert.equal(results.filter((result) => result.status === 'rejected' && result.reason.code === 'widget_limit_reached').length, 4);
        assert.deepEqual(await count(), { widgets: 12, audits: before.audits + 12 });
        assert.equal((await repository.list(teammate)).length, 0);
      });
      await t.test('one concurrent update wins; stale versions cannot update/delete or append mutation audit', async () => {
        const widget = (await repository.list(ctx))[0], before = await count();
        const results = await Promise.allSettled(Array.from({ length: 4 }, () => repository.update(ctx, widget.id, { ...config, name: 'Updated' }, 1)));
        assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
        assert.equal(results.filter((result) => result.status === 'rejected' && result.reason.code === 'widget_version_conflict').length, 3);
        await assert.rejects(repository.remove(ctx, widget.id, 1), (error) => error.code === 'widget_version_conflict' && error.extra.current_version === 2);
        assert.deepEqual(await count(), { ...before, audits: before.audits + 1 });
        await repository.remove(ctx, widget.id, 2);
      });
      await t.test('audit failures roll back create, update AND delete on the real app-role transaction', async () => {
        const failing = createAssistantWidgetRepository(pool, { auditRepository: { appendAuditEvent: async () => { throw new Error('injected audit failure'); } } });
        const widget = (await repository.list(ctx))[0], before = await count();
        const stored = (await repository.list(ctx)).find((row) => row.id === widget.id);
        await assert.rejects(failing.create(ctx, config), /injected audit failure/);
        await assert.rejects(failing.update(ctx, widget.id, { ...config, name: 'Rollback' }, 1), /injected audit failure/);
        await assert.rejects(failing.remove(ctx, widget.id, 1), /injected audit failure/);
        assert.deepEqual(await count(), before);
        assert.deepEqual((await repository.list(ctx)).find((row) => row.id === widget.id), stored);
      });
      await t.test('database rejects unknown renderer/code/results, foreign owner/target, slot overflow and invalid JSON field types', async () => {
        for (const widget of await repository.list(ctx)) await repository.remove(ctx, widget.id, widget.version);
        const insert = `INSERT INTO assistant_widgets (id,tenant_id,user_id,slot,config_json) VALUES ($1,$2,$3,$4,$5::jsonb)`;
        const params = (changes = {}) => ['aw_ffffffffffffffffffffffff', TENANT, ctx.userId, 12, JSON.stringify({ ...config, ...changes })];
        for (const change of [{ html: '<script>bad</script>' }, { result: { count: 100 } }, { template: 'sql' }, { question: null }, { name: ['array'] }, { name: '' }, { question: 'x'.repeat(501) }, { severity: 'S2' }, { target_id: null }]) {
          await assert.rejects(sql(ctx, insert, params(change)), (error) => error.code === '23514');
        }
        await assert.rejects(sql(ctx, insert, ['aw_ffffffffffffffffffffffff', TENANT, foreign.userId, 12, JSON.stringify(config)]), (error) => ['42501', '23503'].includes(error.code));
        await assert.rejects(sql(ctx, insert, ['aw_ffffffffffffffffffffffff', TENANT, ctx.userId, 13, JSON.stringify(config)]), (error) => error.code === '23514');
        await assert.rejects(sql(ctx, insert, params({ target_id: 'tgt_missing' })), (error) => error.code === '23503');
        await assert.rejects(sql(ctx, insert, params({ target_id: 'tgt_widget_other' })), (error) => error.code === '23503');
      });
      await t.test('reconstructed repository sees definitions but neither persisted model commentary nor computed results', async () => {
        await repository.create(ctx, config);
        const restored = createAssistantWidgetRepository(pool, { auditRepository: createAuditRepository(pool) });
        assert.deepEqual(await restored.list(ctx), await repository.list(ctx));
        const raw = (await sql(ctx, 'SELECT * FROM assistant_widgets LIMIT 1')).rows[0];
        assert.deepEqual(raw.config_json, config);
        assert.equal(Object.hasOwn(raw, 'result'), false); assert.equal(Object.hasOwn(raw, 'commentary'), false);
      });
    } finally { await closePgPool(pool); }
  }, availability.env);
});

test('additive 0084 to 0085 preserves legacy catalog writes and widget definitions across simulated code rollback', { timeout: 120_000 }, async (t) => {
  const availability = await resolvePostgresHarnessAvailability(localEnv(), { tryDocker: false });
  if (!availability.available) return t.skip(availability.reason);
  await withEphemeralPostgres(async (owner, { databaseName }) => {
    const files = listMigrationFiles(MIGRATIONS_DIR).filter((file) => file.version <= '0085_assistant_widgets');
    const oldFiles = files.filter((file) => file.version <= '0084_origin_clue_retention');
    assert.equal(oldFiles.at(-1).version, '0084_origin_clue_retention');
    assert.equal(files.at(-1).version, '0085_assistant_widgets');
    await runMigrations(owner, { migrationsDir: MIGRATIONS_DIR, files: oldFiles });
    await ensureHarnessAppRole(owner);
    assert.equal((await owner.query("SELECT to_regclass('public.assistant_widgets') AS widgets")).rows[0].widgets, null);
    await owner.query(`INSERT INTO tenants (id,name) VALUES ($1,'Upgrade widgets'),($2,'Other upgrade widgets')`, [TENANT, OTHER]);
    await owner.query(`INSERT INTO users (id,tenant_id,email,role) VALUES ($1,$2,'upgrade-widget@example.test','admin')`, [ctx.userId, TENANT]);
    await owner.query(`INSERT INTO target_groups (id,tenant_id,name) VALUES ('tg_widget_upgrade',$1,'Declared')`, [TENANT]);
    await owner.query(`INSERT INTO targets (id,tenant_id,target_group_id,kind,value,normalized_value,protocol,port,expected_behavior)
      VALUES ('tgt_widget_upgrade',$1,'tg_widget_upgrade','fqdn','upgrade.example.test','upgrade.example.test','https',443,'intentionally_public')`, [TENANT]);
    const url = new URL(databaseUrlWithDatabase(owner.options.connectionString, databaseName));
    url.username = 'astranull_app'; url.password = 'astranull_app_local_dev';
    const pool = createPgPool({ ASTRANULL_DATABASE_URL: url.toString() });
    const actor = { ...ctx, role: 'admin' };
    const audit = createAuditRepository(pool);
    // These catalog and audit implementations are unchanged from the pre-feature release.
    const catalog = createCoreCatalogRepository(pool, { auditRepository: audit });
    const snapshot = () => withTenantContext(pool, TENANT, async (client) => ({
      tenants: (await client.query('SELECT * FROM tenants ORDER BY id')).rows,
      users: (await client.query('SELECT * FROM users ORDER BY id')).rows,
      targets: (await client.query('SELECT * FROM targets ORDER BY id')).rows,
      audits: (await client.query('SELECT * FROM audit_logs ORDER BY id')).rows,
    }));
    const legacySchema = async () => ({
      rls: (await owner.query(`SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class
        WHERE oid IN ('tenants'::regclass,'users'::regclass,'targets'::regclass,'audit_logs'::regclass) ORDER BY relname`)).rows,
      constraints: (await owner.query(`SELECT conname,pg_get_constraintdef(oid) AS definition FROM pg_constraint
        WHERE conrelid IN ('tenants'::regclass,'users'::regclass,'targets'::regclass,'audit_logs'::regclass) ORDER BY conname`)).rows,
    });
    try {
      assert.deepEqual((await pool.query('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user')).rows[0],
        { rolsuper: false, rolbypassrls: false });
      assert.deepEqual((await pool.query(`SELECT relrowsecurity,relforcerowsecurity,pg_get_userbyid(relowner)=current_user AS is_owner
        FROM pg_class WHERE oid='targets'::regclass`)).rows[0], { relrowsecurity: true, relforcerowsecurity: true, is_owner: false });
      assert.equal((await catalog.patchTargetById(actor, 'tgt_widget_upgrade', { tags: ['before-upgrade'] })).id, 'tgt_widget_upgrade');
      const before = await snapshot(), schema = await legacySchema();
      const target = await catalog.getTarget(actor, 'tgt_widget_upgrade');
      const upgraded = await runMigrations(owner, { migrationsDir: MIGRATIONS_DIR, files });
      assert.deepEqual(upgraded.results.filter((result) => result.status === 'applied'), [{ version: '0085_assistant_widgets', status: 'applied' }]);
      assert.deepEqual(await snapshot(), before);
      assert.deepEqual(await legacySchema(), schema);
      await grantPostgresAppRolePrivileges(owner);
      await assertLatestMigrationApplied(pool, '0084_origin_clue_retention');
      assert.deepEqual(await catalog.getTarget(actor, target.id), target);
      assert.equal(await catalog.getTarget({ ...actor, tenantId: OTHER }, target.id), null);
      const repository = createAssistantWidgetRepository(pool, { auditRepository: audit });
      const widget = await repository.create(actor, { ...config, target_id: target.id });
      // Simulate the old application using only its existing catalog, retaining 0085 in place.
      assert.equal((await catalog.patchTargetById(actor, target.id, { tags: ['old-code-active'] })).id, target.id);
      assert.deepEqual((await snapshot()).targets[0].metadata_json.tags, ['old-code-active']);
      assert.deepEqual(await catalog.getTarget(actor, target.id), target);
      const restored = createAssistantWidgetRepository(pool, { auditRepository: createAuditRepository(pool) });
      assert.deepEqual(await restored.list(actor), [widget]);
      const beforeRerun = await snapshot();
      const rerun = await runMigrations(owner, { migrationsDir: MIGRATIONS_DIR, files });
      assert.ok(rerun.results.every((result) => result.status === 'skipped'));
      assert.deepEqual(await snapshot(), beforeRerun);
      assert.deepEqual(await restored.list(actor), [widget]);
    } finally { await closePgPool(pool); }
  }, availability.env, { applyMigrations: false });
});
