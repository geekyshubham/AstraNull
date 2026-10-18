import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createOriginClueService } from '../../src/services/originClues.mjs';
import { createPostgresOriginClueRepository } from '../../src/persistence/postgres/originClueRepository.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createRetentionRepository } from '../../src/persistence/postgres/retentionRepository.mjs';
import { createPostgresRetentionServices } from '../../src/persistence/postgres/retentionServiceAdapters.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createPostgresRuntime } from '../../src/persistence/postgres/runtime.mjs';
import { createServer } from '../../src/server.mjs';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { request, demoHeaders, closeServer } from '../helpers/http.mjs';
import { runMigrations, listMigrationFiles } from '../../src/persistence/postgres/migrations.mjs';
import { grantPostgresAppRolePrivileges } from '../../scripts/postgres-grant-app-role.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { databaseUrlWithDatabase, resolvePostgresHarnessAvailability, withEphemeralPostgres, ensureHarnessAppRole, MIGRATIONS_DIR } from '../helpers/pg-harness.mjs';
import { verifyAuditChain } from '../../src/audit.mjs';

const tenant = 'ten_origin_retention';
const other = 'ten_origin_retention_other';
const ctx = { tenantId: tenant, userId: 'usr_origin_retention', role: 'admin', persistenceMode: 'postgres' };
const config = { featureFlags: { originCluesEnabledTenants: { [tenant]: true, [other]: true } } };
const options = (key) => ({ runtimeConfig: config, idempotencyKey: key });
const input = (records = [{ candidate_ip: '8.8.8.8', associated_hostname: 'origin.test' }]) => ({ source_kind: 'historical_dns', source_ref: 'supplied:archive', records });
const erase = (extra = {}) => ({ confirmation_tenant_id: tenant, reason: 'Explicit customer source metadata deletion', dry_run: false, ...extra });
function localEnv() {
  const env = { ...process.env, ASTRANULL_RUN_PUBLIC_DNS: '0' };
  for (const key of ['ASTRANULL_DATABASE_URL', 'ASTRANULL_ADMIN_DATABASE_URL']) {
    if (!env[key]) continue;
    const url = new URL(env[key]);
    assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname), `${key} must be loopback`);
    assert.ok(!url.searchParams.has('host') && !url.searchParams.has('hostaddr'));
  }
  return env;
}

test('additive 0083 to 0084 upgrade preserves stored responses, reprovisions least privilege and reruns idempotently', { timeout: 120000 }, async (t) => {
  const availability = await resolvePostgresHarnessAvailability(localEnv(), { tryDocker: false });
  if (!availability.available) return t.skip(availability.reason);
  await withEphemeralPostgres(async (owner, { databaseName }) => {
    const files = listMigrationFiles(MIGRATIONS_DIR);
    const oldFiles = files.filter((file) => file.version <= '0083_origin_clues');
    assert.equal(oldFiles.at(-1).version, '0083_origin_clues');
    await runMigrations(owner, { migrationsDir: MIGRATIONS_DIR, files: oldFiles });
    await ensureHarnessAppRole(owner);
    await owner.query(`INSERT INTO tenants (id, name, privacy_settings) VALUES ($1, 'Upgrade fixture', '{"metadata_retention_days":30}')`, [tenant]);
    await owner.query(`INSERT INTO target_groups (id, tenant_id, name) VALUES ('tg_upgrade', $1, 'Declared')`, [tenant]);
    await owner.query(`INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
      VALUES ('tgt_upgrade', $1, 'tg_upgrade', 'fqdn', 'origin.test', 'origin.test')`, [tenant]);
    const url = new URL(databaseUrlWithDatabase(owner.options.connectionString, databaseName));
    url.username = 'astranull_app'; url.password = 'astranull_app_local_dev';
    const pool = createPgPool({ ASTRANULL_DATABASE_URL: url.toString() });
    try {
      const audit = createAuditRepository(pool);
      const service = createOriginClueService({ repository: createPostgresOriginClueRepository(pool, audit) });
      const original = await service.import(ctx, 'tgt_upgrade', input(), options('before-upgrade'));
      assert.equal(original.items.length, 1);
      const snapshot = () => withTenantContext(pool, tenant, async (client) => ({
        clues: (await client.query('SELECT * FROM origin_clues ORDER BY id')).rows,
        batches: (await client.query('SELECT * FROM origin_clue_batches ORDER BY id')).rows,
        privacy: (await client.query('SELECT privacy_settings FROM tenants WHERE id = $1', [tenant])).rows,
      }));
      const before = await snapshot();
      const upgraded = await runMigrations(owner, { migrationsDir: MIGRATIONS_DIR, files });
      assert.deepEqual(upgraded.results.filter((result) => result.status === 'applied'), [{ version: '0084_origin_clue_retention', status: 'applied' }]);
      assert.deepEqual(await snapshot(), before);
      const signature = 'public.astranull_apply_origin_clue_lifecycle(text,text,text,timestamptz)';
      assert.equal((await pool.query('SELECT has_function_privilege(current_user, $1, \'EXECUTE\') AS allowed', [signature])).rows[0].allowed, false);
      await grantPostgresAppRolePrivileges(owner);
      assert.equal((await pool.query('SELECT has_function_privilege(current_user, $1, \'EXECUTE\') AS allowed', [signature])).rows[0].allowed, true);
      assert.equal((await pool.query(`SELECT pg_has_role(current_user, 'astranull_origin_lifecycle', 'MEMBER') AS member`)).rows[0].member, false);
      const rerun = await runMigrations(owner, { migrationsDir: MIGRATIONS_DIR, files });
      assert.ok(rerun.results.every((result) => result.status === 'skipped'));
      assert.deepEqual(await snapshot(), before);
      const replay = await service.import(ctx, 'tgt_upgrade', input(), options('before-upgrade'));
      assert.deepEqual(replay, original);
      const lifecycle = createPostgresRetentionServices({ retention: createRetentionRepository(pool) });
      const erased = await lifecycle.eraseOriginCluesForCurrentTenant(ctx, erase());
      assert.equal(erased.deleted.originClues, 1); assert.equal(erased.deleted.originClueBatches, 1);
      assert.ok(erased.audit_entry_id);
      assert.equal((await snapshot()).clues.length, 0);
    } finally { await closePgPool(pool); }
  }, availability.env, { applyMigrations: false });
});

test('owned PostgreSQL app-role origin metadata lifecycle and append-only security', { timeout: 120000 }, async (t) => {
  const availability = await resolvePostgresHarnessAvailability(localEnv(), { tryDocker: false });
  if (!availability.available) return t.skip(availability.reason);
  await withEphemeralPostgres(async (owner, { databaseName }) => {
    await owner.query(`INSERT INTO tenants (id, name, privacy_settings) VALUES ($1, 'Origin retention', '{"metadata_retention_days":30}'), ($2, 'Other', '{}')`, [tenant, other]);
    await owner.query(`INSERT INTO target_groups (id, tenant_id, name) VALUES ('tg_retention', $1, 'Declared'), ('tg_retention_other', $2, 'Other')`, [tenant, other]);
    await owner.query(`INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value) VALUES
      ('tgt_retention', $1, 'tg_retention', 'fqdn', 'origin.test', 'origin.test'),
      ('tgt_retention_other', $2, 'tg_retention_other', 'fqdn', 'origin.test', 'origin.test')`, [tenant, other]);
    const url = new URL(databaseUrlWithDatabase(owner.options.connectionString, databaseName));
    url.username = 'astranull_app'; url.password = 'astranull_app_local_dev';
    url.searchParams.set('options', '-c timezone=UTC -c statement_timeout=15000');
    const pool = createPgPool({ ASTRANULL_DATABASE_URL: url.toString() });
    const sql = (id, statement, params = []) => withTenantContext(pool, id, (client) => client.query(statement, params));
    const audit = createAuditRepository(pool);
    const repository = createRetentionRepository(pool);
    const lifecycle = createPostgresRetentionServices({ retention: repository });
    const catalog = createCoreCatalogRepository(pool, { auditRepository: audit });
    const now = new Date();
    const old = new Date(now.getTime() - 400 * 86400000);
    const service = (at = now, extra = {}) => createOriginClueService({ repository: createPostgresOriginClueRepository(pool, audit), now: () => at, ...extra });
    const counts = async (id = tenant) => (await sql(id, `SELECT (SELECT count(*)::int FROM origin_clues) AS clues,
      (SELECT count(*)::int FROM origin_clue_batches) AS batches, (SELECT count(*)::int FROM audit_logs) AS audits`)).rows[0];
    try {
      await t.test('real runtime HTTP wiring previews, holds and erases with collection disabled and no dev fallback', async () => {
        const env = { ...process.env, NODE_ENV: 'test', ASTRANULL_AUTH_MODE: 'dev-headers',
          ASTRANULL_PERSISTENCE_MODE: 'postgres', ASTRANULL_DATABASE_URL: url.toString(),
          ASTRANULL_ENFORCE_DATABASE_ROLE: '1', ASTRANULL_ORIGIN_CLUES_ENABLED_TENANTS: '',
          ASTRANULL_RATE_LIMIT_DISABLED: '1' };
        const runtime = await createPostgresRuntime(env, { createPool: () => pool, closePool: async () => {} });
        const server = createServer({ runtimeConfig: loadRuntimeConfig(env), env, services: runtime.services, runtimeHealth: runtime.health });
        await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
        const baseUrl = `http://127.0.0.1:${server.address().port}`;
        const endpoint = '/v1/tenants/current/origin-clues/erase';
        const headers = demoHeaders('admin', tenant, ctx.userId);
        try {
          await runtime.services.originClues.import(ctx, 'tgt_retention', input(), options('api-seed'));
          const disabled = await request(baseUrl, 'GET', '/v1/targets/tgt_retention/origin-clues', { headers });
          assert.equal(disabled.status, 404);
          const preview = await request(baseUrl, 'POST', endpoint, { headers, body: erase({ dry_run: true }) });
          assert.equal(preview.status, 200); assert.equal(preview.json.would_delete.originClues, 1); assert.equal(preview.json.audit_entry_id, null);
          const denied = await request(baseUrl, 'POST', endpoint, { headers: demoHeaders('engineer', tenant, ctx.userId), body: erase() });
          assert.equal(denied.status, 403);
          const changed = await request(baseUrl, 'PATCH', '/v1/tenants/current', { headers,
            body: { privacy_settings: { evidence_retention: { legal_hold: true } } } });
          assert.equal(changed.status, 200);
          const held = await request(baseUrl, 'POST', endpoint, { headers, body: erase() });
          assert.equal(held.status, 409); assert.ok(held.json.audit_entry_id); assert.equal(held.json.deleted.originClues, 0);
          await request(baseUrl, 'PATCH', '/v1/tenants/current', { headers,
            body: { privacy_settings: { evidence_retention: { legal_hold: false } } } });
          const erased = await request(baseUrl, 'POST', endpoint, { headers, body: erase() });
          assert.equal(erased.status, 200); assert.equal(erased.json.deleted.originClues, 1); assert.ok(erased.json.audit_entry_id);
          assert.equal((await counts()).clues, 0);
          assert.equal((await sql(tenant, 'SELECT action FROM audit_logs WHERE id = $1', [erased.json.audit_entry_id])).rows[0].action, 'privacy.origin_clues_erased');
          await service(old).import(ctx, 'tgt_retention', input(), options('api-expiry'));
          assert.equal((await counts()).clues, 1);
          const expired = await request(baseUrl, 'PATCH', '/v1/tenants/current', { headers,
            body: { privacy_settings: { metadata_retention_days: 30 } } });
          assert.equal(expired.status, 200); assert.equal((await counts()).clues, 0);
          const expiryAudit = (await audit.listAuditEntries(ctx)).find((entry) =>
            entry.action === 'privacy.retention_purged' && entry.metadata.deleted.originClues === 1);
          assert.ok(expiryAudit, 'runtime tenant privacy PATCH immediately expires PostgreSQL origin rows with audit');
        } finally { await closeServer(server); await runtime.close(); }
      });
      await t.test('role is non-owner/NOBYPASSRLS, lifecycle cannot be assumed and PUBLIC cannot execute', async () => {
        assert.deepEqual((await pool.query('SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user')).rows[0], { rolsuper: false, rolbypassrls: false });
        assert.equal((await pool.query(`SELECT pg_has_role(current_user, 'astranull_origin_lifecycle', 'MEMBER') AS member`)).rows[0].member, false);
        await assert.rejects(pool.query('SET ROLE astranull_origin_lifecycle'), (error) => error.code === '42501');
        const definition = (await owner.query(`SELECT prosecdef, proconfig, pg_get_userbyid(proowner) AS owner FROM pg_proc WHERE oid = 'public.astranull_apply_origin_clue_lifecycle(text,text,text,timestamptz)'::regprocedure`)).rows[0];
        assert.equal(definition.prosecdef, true); assert.equal(definition.owner, 'astranull_origin_lifecycle');
        assert.ok(definition.proconfig.includes('search_path=pg_catalog')); assert.ok(definition.proconfig.includes('row_security=on'));
        const role = (await owner.query(`SELECT rolcanlogin, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'astranull_origin_lifecycle'`)).rows[0];
        assert.deepEqual(role, { rolcanlogin: false, rolsuper: false, rolbypassrls: false });
        const publicGrants = (await owner.query(`SELECT count(*)::int AS count FROM pg_proc p,
          LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
          WHERE p.oid = 'public.astranull_apply_origin_clue_lifecycle(text,text,text,timestamptz)'::regprocedure
          AND a.grantee = 0 AND a.privilege_type = 'EXECUTE'`)).rows[0];
        assert.equal(publicGrants.count, 0);
        for (const table of ['origin_clues', 'origin_clue_batches']) {
          const state = (await pool.query(`SELECT relrowsecurity, relforcerowsecurity,
            pg_get_userbyid(relowner) = current_user AS owner FROM pg_class WHERE oid = $1::regclass`, [table])).rows[0];
          assert.deepEqual(state, { relrowsecurity: true, relforcerowsecurity: true, owner: false });
        }
      });
      let first; let mixed;
      const records = [...input().records, { candidate_ip: '1.1.1.1', associated_hostname: 'origin.test' }];
      await t.test('expiry removes rows and newer response copies but preserves fresh child FK and terminal replay', async () => {
        first = await service(old).import(ctx, 'tgt_retention', input(), options('old'));
        mixed = await service().import(ctx, 'tgt_retention', input(records), options('mixed'));
        assert.equal(mixed.deduplicated, 1);
        assert.equal(mixed.items.find((item) => item.id === first.items[0].id).retrieved_at, old.toISOString());
        await service(old).import({ ...ctx, tenantId: other }, 'tgt_retention_other', input(), options('foreign'));
        const before = await counts();
        const preview = await lifecycle.previewMetadataRetentionForTenant(ctx, tenant, { now });
        assert.equal(preview.would_delete.originClues, 1); assert.equal(preview.would_delete.originClueResponses, 1);
        assert.deepEqual(await counts(), before);
        const result = await lifecycle.enforceMetadataRetentionForTenant(ctx, tenant, { now });
        assert.equal(result.deleted.originClues, 1); assert.equal(result.deleted.originClueBatches, 1); assert.equal(result.deleted.originClueResponses, 1);
        assert.equal((await counts()).clues, 1);
        const batches = (await sql(tenant, 'SELECT response_json FROM origin_clue_batches')).rows;
        assert.deepEqual(batches[0].response_json, { error: 'origin_clue_response_expired', expired: true });
        assert.equal((await service().import(ctx, 'tgt_retention', input(records), options('mixed'))).status, 410);
        assert.equal((await service().list(ctx, 'tgt_retention', {}, { runtimeConfig: config })).coverage.sources, undefined);
        assert.equal((await counts(other)).clues, 1);
      });
      await t.test('direct mutations, caller GUCs, absent/stale/foreign audit and invalid mode cannot authorize deletion', async () => {
        const before = await counts();
        for (const table of ['origin_clues', 'origin_clue_batches']) {
          await assert.rejects(sql(tenant, `DELETE FROM ${table} WHERE tenant_id = $1`, [tenant]), (error) => error.code === '23514');
          await assert.rejects(sql(tenant, `UPDATE ${table} SET target_id = target_id WHERE tenant_id = $1`, [tenant]), (error) => error.code === '23514');
        }
        await assert.rejects(withTenantContext(pool, tenant, async (client) => {
          await client.query(`SELECT set_config('app.origin_lifecycle_authorized', 'true', true)`);
          await client.query('DELETE FROM origin_clues WHERE tenant_id = $1', [tenant]);
        }), (error) => error.code === '23514');
        for (const [id, auditId, mode] of [[tenant, 'missing', 'erase'], [other, 'missing', 'erase'], [tenant, 'missing', 'force']]) {
          await assert.rejects(sql(tenant, 'SELECT public.astranull_apply_origin_clue_lifecycle($1,$2,$3,$4::timestamptz)', [id, auditId, mode, now.toISOString()]), (error) => error.code === '42501');
        }
        const prior = (await audit.listAuditEntries(ctx)).find((entry) => entry.action === 'privacy.retention_purged');
        await assert.rejects(sql(tenant, 'SELECT public.astranull_apply_origin_clue_lifecycle($1,$2,$3,$4::timestamptz)', [tenant, prior.id, 'expiry', now.toISOString()]), (error) => error.code === '42501');
        // App/DB clock skew: a small positive skew clears the authority guard (then fails later on audit match), but a far-future authority value is still rejected at the guard.
        const skewValid = new Date(now.getTime() + 2 * 60000).toISOString();
        const skewTooFar = new Date(now.getTime() + 60 * 60000).toISOString();
        await assert.rejects(sql(tenant, 'SELECT public.astranull_apply_origin_clue_lifecycle($1,$2,$3,$4::timestamptz)', [tenant, 'missing', 'expiry', skewValid]), (error) => error.code === '42501' && /requires exact same-transaction audit/.test(error.message));
        await assert.rejects(sql(tenant, 'SELECT public.astranull_apply_origin_clue_lifecycle($1,$2,$3,$4::timestamptz)', [tenant, 'missing', 'expiry', skewTooFar]), (error) => error.code === '42501' && /invalid origin lifecycle authority/.test(error.message));
        assert.deepEqual(await counts(), before);
      });
      await t.test('legal hold blocks expiry and erasure while preview remains read-only and reports blocked counts', async () => {
        await catalog.patchCurrentTenant(ctx, { privacy_settings: { evidence_retention: { legal_hold: true } } });
        const before = await counts();
        const preview = await lifecycle.eraseOriginCluesForCurrentTenant(ctx, erase({ dry_run: true }), { now });
        assert.equal(preview.legal_hold, true); assert.equal(preview.blocked_deletions.originClues, 1);
        assert.deepEqual(await counts(), before);
        const blocked = await lifecycle.eraseOriginCluesForCurrentTenant(ctx, erase(), { now });
        assert.equal(blocked.status, 409); assert.ok(blocked.audit_entry_id);
        assert.equal((await counts()).clues, before.clues);
        await catalog.patchCurrentTenant(ctx, { privacy_settings: { evidence_retention: { legal_hold: false } } });
      });
      await t.test('same-transaction audit deletion cannot silently erase data and rolls back entire operation', async () => {
        const before = await counts();
        await assert.rejects(withTenantContext(pool, tenant, async (client) => {
          const erased = await lifecycle.eraseOriginCluesForCurrentTenant(ctx, erase(), { now });
          await client.query('DELETE FROM audit_logs WHERE tenant_id = $1 AND id = $2', [tenant, erased.audit_entry_id]);
        }), (error) => error.code === '23514');
        assert.deepEqual(await counts(), before);
      });
      await t.test('a fresh wrong-plan audit is rejected and rolled back with no lifecycle change', async () => {
        const before = await counts();
        const preview = await lifecycle.eraseOriginCluesForCurrentTenant(ctx, erase({ dry_run: true }), { now });
        await assert.rejects(withTenantContext(pool, tenant, async (client) => {
          await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [tenant]);
          const { rows } = await client.query('SELECT public.astranull_origin_clue_lifecycle_plan($1,$2::timestamptz,true) AS plan', [tenant, now.toISOString()]);
          const entry = await audit.appendAuditEvent({ tenant_id: tenant, actor_user_id: ctx.userId, actor_role: 'admin',
            action: 'privacy.origin_clues_erased', resource_type: 'tenant', resource_id: tenant,
            metadata: { confirmation_tenant_id: tenant, reason: 'Forged plan fixture', deleted: preview.would_delete,
              policy_snapshot: preview.policy_snapshot, origin_lifecycle: { mode: 'erase', at: now.toISOString(),
                counts: rows[0].plan.counts, plan_digest: 'incorrect-plan' } } }, { client, auditLockHeld: true });
          await client.query('SELECT public.astranull_apply_origin_clue_lifecycle($1,$2,$3,$4::timestamptz)', [tenant, entry.id, 'erase', now.toISOString()]);
        }), (error) => error.code === '42501');
        assert.deepEqual(await counts(), before);
      });
      await t.test('audit insertion failure leaves rows, response copies and privacy normalization unchanged', async () => {
        const before = await counts();
        await owner.query(`CREATE FUNCTION test_origin_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
          IF NEW.action = 'privacy.origin_clues_erased' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END; $$;
          CREATE TRIGGER test_origin_audit_failure BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION test_origin_audit_failure()`);
        try { await assert.rejects(lifecycle.eraseOriginCluesForCurrentTenant(ctx, erase(), { now }), /fixture audit failure/); }
        finally { await owner.query('DROP TRIGGER test_origin_audit_failure ON audit_logs; DROP FUNCTION test_origin_audit_failure()'); }
        assert.deepEqual(await counts(), before);
      });
      await t.test('a delete failure rolls back response scrubbing, clue deletion and chained audit', async () => {
        const oldInput = input([{ candidate_ip: '9.9.9.9', associated_hostname: 'origin.test' }]);
        await service(old).import(ctx, 'tgt_retention', oldInput, options('rollback-old'));
        await service().import(ctx, 'tgt_retention', oldInput, options('rollback-copy'));
        const before = await counts();
        const responses = (await sql(tenant, 'SELECT id, response_json FROM origin_clue_batches ORDER BY id')).rows;
        await owner.query(`CREATE FUNCTION test_origin_delete_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
          RAISE EXCEPTION 'fixture delete failure'; END; $$;
          CREATE TRIGGER zz_test_origin_delete_failure BEFORE DELETE ON origin_clues FOR EACH ROW EXECUTE FUNCTION test_origin_delete_failure()`);
        try { await assert.rejects(lifecycle.enforceMetadataRetentionForTenant(ctx, tenant, { now }), /fixture delete failure/); }
        finally { await owner.query('DROP TRIGGER zz_test_origin_delete_failure ON origin_clues; DROP FUNCTION test_origin_delete_failure()'); }
        assert.deepEqual(await counts(), before);
        assert.deepEqual((await sql(tenant, 'SELECT id, response_json FROM origin_clue_batches ORDER BY id')).rows, responses);
        await lifecycle.enforceMetadataRetentionForTenant(ctx, tenant, { now });
      });
      await t.test('concurrent hold update commits before waiting erasure and denies deletion', async () => {
        let entered; let release;
        const ready = new Promise((resolve) => { entered = resolve; });
        const held = new Promise((resolve) => { release = resolve; });
        const update = withTenantContext(pool, tenant, async () => {
          await catalog.patchCurrentTenant(ctx, { privacy_settings: { evidence_retention: { legal_hold: true } } });
          entered(); await held;
        });
        await ready;
        const deletion = lifecycle.eraseOriginCluesForCurrentTenant(ctx, erase(), { now });
        release(); await update;
        assert.equal((await deletion).status, 409);
        assert.ok((await counts()).clues > 0);
        await catalog.patchCurrentTenant(ctx, { privacy_settings: { evidence_retention: { legal_hold: false } } });
      });
      await t.test('concurrent collection and erasure serialize without refetch or resurrected batches', async () => {
        let entered; let release; let calls = 0;
        const ready = new Promise((resolve) => { entered = resolve; });
        const waiting = new Promise((resolve) => { release = resolve; });
        const collecting = service(now, { collectDns: async () => { calls += 1; entered(); await waiting;
          return { records: [], sources: [], query_count: 0 }; } }).collect(ctx, 'tgt_retention', {}, options('concurrent'));
        await ready;
        const deleting = lifecycle.eraseOriginCluesForCurrentTenant(ctx, erase(), { now });
        release();
        const [collection, deletion] = await Promise.all([collecting, deleting]);
        assert.equal(collection.error, undefined); assert.equal(deletion.error, undefined); assert.equal(calls, 1);
        assert.equal((await counts()).clues, 0); assert.equal((await counts()).batches, 0);
        await service().import(ctx, 'tgt_retention', input(), options('after-erase-new-work'));
      });
      await t.test('tenant:write/scopes/confirmation gate erasure; archived targets and repeated erasure are supported', async () => {
        assert.equal((await lifecycle.eraseOriginCluesForCurrentTenant({ ...ctx, role: 'engineer' }, erase())).status, 403);
        assert.equal((await lifecycle.eraseOriginCluesForCurrentTenant({ ...ctx, scopes: ['tenant:read'] }, erase())).status, 403);
        assert.equal((await lifecycle.eraseOriginCluesForCurrentTenant(ctx, erase({ confirmation_tenant_id: other }))).status, 400);
        await sql(tenant, `UPDATE target_groups SET archived_at = now() WHERE id = 'tg_retention'`);
        const erased = await lifecycle.eraseOriginCluesForCurrentTenant(ctx, erase(), { now });
        assert.equal(erased.deleted.originClues, 1); assert.equal(erased.deleted.originClueBatches, 1); assert.ok(erased.audit_entry_id);
        const repeated = await lifecycle.eraseOriginCluesForCurrentTenant(ctx, erase(), { now });
        assert.equal(repeated.deleted.originClues, 0); assert.ok(repeated.audit_entry_id);
        assert.equal((await counts(other)).clues, 1);
        assert.equal(verifyAuditChain(await audit.listAuditEntries(ctx)).valid, true);
        await assert.rejects(sql(tenant, `UPDATE audit_logs SET action = 'renamed' WHERE id = $1`, [erased.audit_entry_id]), (error) => error.code === '23514');
      });
    } finally { await closePgPool(pool); }
  }, availability.env);
});
