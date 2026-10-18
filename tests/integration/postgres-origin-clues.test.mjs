import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { createOriginClueService } from '../../src/services/originClues.mjs';
import { createPostgresOriginClueRepository } from '../../src/persistence/postgres/originClueRepository.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { databaseUrlWithDatabase, resolvePostgresHarnessAvailability, withEphemeralPostgres } from '../helpers/pg-harness.mjs';

const tenant = 'ten_origin_clues', other = 'ten_origin_other';
const ctx = { tenantId: tenant, userId: 'usr_origin', role: 'admin', persistenceMode: 'postgres' };
const config = { featureFlags: { originCluesEnabledTenants: { [tenant]: true, [other]: true } } };
const options = (key = 'key-1') => ({ runtimeConfig: config, idempotencyKey: key });
const body = (extra = {}) => ({ source_kind: 'historical_dns', source_ref: 'supplied:history', records: [
  { associated_hostname: 'origin.test', candidate_ip: '8.8.8.8' }, { associated_hostname: 'origin.test', candidate_ip: '1.1.1.1' },
], ...extra });
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

test('origin clue migration and fresh schema remain exactly synchronized', () => {
  const migration = readFileSync(new URL('../../db/migrations/0083_origin_clues.sql', import.meta.url), 'utf8').trim();
  const schema = readFileSync(new URL('../../db/schema.sql', import.meta.url), 'utf8');
  assert.ok(schema.includes(migration));
  for (const table of ['origin_clues', 'origin_clue_batches']) {
    assert.ok(migration.includes(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY`));
    assert.ok(migration.includes(`BEFORE UPDATE OR DELETE ON ${table}`));
  }
});

test('real local PostgreSQL origin clue persistence, tenant constraints, audit, replay and append-only history', { timeout: 120000 }, async (t) => {
  const availability = await resolvePostgresHarnessAvailability(localEnv(), { tryDocker: false });
  if (!availability.available) return t.skip(availability.reason);
  if (process.env.ASTRANULL_ADMIN_DATABASE_URL) {
    assert.equal(availability.env.ASTRANULL_ADMIN_DATABASE_URL, process.env.ASTRANULL_ADMIN_DATABASE_URL,
      'a reachable application role must not replace the explicit database administrator');
  }
  await withEphemeralPostgres(async (owner, { databaseName }) => {
    await owner.query(`INSERT INTO tenants (id, name) VALUES ($1, 'Origin clues'), ($2, 'Other origin clues')`, [tenant, other]);
    await owner.query(`INSERT INTO target_groups (id, tenant_id, name) VALUES ('tg_origin', $1, 'Declared'), ('tg_origin_other', $2, 'Foreign')`, [tenant, other]);
    await owner.query(`INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value) VALUES
      ('tgt_origin', $1, 'tg_origin', 'fqdn', 'origin.test', 'origin.test'),
      ('tgt_other', $2, 'tg_origin_other', 'fqdn', 'other.test', 'other.test')`, [tenant, other]);
    const url = new URL(databaseUrlWithDatabase(owner.options.connectionString, databaseName));
    url.username = 'astranull_app'; url.password = 'astranull_app_local_dev';
    url.searchParams.set('options', '-c timezone=UTC -c statement_timeout=15000');
    const pool = createPgPool({ ASTRANULL_DATABASE_URL: url.toString() });
    const audit = createAuditRepository(pool);
    const repo = createPostgresOriginClueRepository(pool, audit);
    const service = createOriginClueService({ repository: repo, now: () => new Date('2026-10-16T12:00:00.000Z') });
    const sql = (id, statement, params = []) => withTenantContext(pool, id, (client) => client.query(statement, params));
    const count = async () => (await sql(tenant, `SELECT (SELECT count(*)::int FROM origin_clues) AS clues,
      (SELECT count(*)::int FROM origin_clue_batches) AS batches, (SELECT count(*)::int FROM audit_logs) AS audits,
      (SELECT count(*)::int FROM targets) AS targets, (SELECT count(*)::int FROM origin_bindings) AS bindings,
      (SELECT count(*)::int FROM test_runs) AS runs, (SELECT count(*)::int FROM probe_jobs) AS jobs`)).rows[0];
    try {
      await t.test('non-owner non-BYPASSRLS role enforces forced RLS and tenant FK', async () => {
        assert.deepEqual((await pool.query(`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`)).rows[0], { rolsuper: false, rolbypassrls: false });
        for (const table of ['origin_clues', 'origin_clue_batches']) {
          const row = (await pool.query(`SELECT relrowsecurity, relforcerowsecurity, pg_get_userbyid(relowner) = current_user AS is_owner FROM pg_class WHERE oid = $1::regclass`, [table])).rows[0];
          assert.deepEqual(row, { relrowsecurity: true, relforcerowsecurity: true, is_owner: false });
        }
        await assert.rejects(sql(tenant, `INSERT INTO origin_clue_batches (id, tenant_id, target_id, idempotency_key, request_digest, action, created_at, response_json)
          VALUES ('bad_fk', $1, 'tgt_other', 'x', $2, 'import', now(), '{}')`, [tenant, 'a'.repeat(64)]), (error) => error.code === '23503');
        await assert.rejects(sql(tenant, `INSERT INTO origin_clue_batches (id, tenant_id, target_id, idempotency_key, request_digest, action, created_at, response_json)
          VALUES ('bad_rls', $1, 'tgt_other', 'x', $2, 'import', now(), '{}')`, [other, 'a'.repeat(64)]), (error) => error.code === '42501');
      });
      let first;
      await t.test('concurrent exact replay appends once with transactional audit and no execution/inventory mutations', async () => {
        const before = await count();
        const results = await Promise.all([service.import(ctx, 'tgt_origin', body(), options()), service.import(ctx, 'tgt_origin', body(), options())]);
        first = results[0];
        assert.equal(first.error, undefined, JSON.stringify(first)); assert.equal(first.created, 2);
        assert.deepEqual(results[1], first);
        const after = await count(); assert.deepEqual(after, { ...before, clues: 2, batches: 1, audits: before.audits + 1 });
        const conflict = await service.import(ctx, 'tgt_origin', body({ source_ref: 'changed' }), options());
        assert.equal(conflict.status, 409);
        const duplicate = await service.import(ctx, 'tgt_origin', body(), options('key-2'));
        assert.equal(duplicate.created, 0); assert.equal(duplicate.deduplicated, 2);
        assert.equal((await count()).clues, 2);
      });
      await t.test('read-only paging and tenant boundaries use persisted rows only', async () => {
        const before = await count();
        const page = await service.list({ ...ctx, role: 'viewer' }, 'tgt_origin', { limit: 1 }, options());
        assert.equal(page.items.length, 1); assert.ok(page.next_cursor);
        const second = await service.list(ctx, 'tgt_origin', { limit: 1, cursor: page.next_cursor }, options());
        assert.equal(second.items.length, 1); assert.equal(second.next_cursor, null);
        assert.notEqual(page.items[0].id, second.items[0].id);
        assert.equal((await service.list({ ...ctx, tenantId: other }, 'tgt_origin', {}, options())).status, 404);
        assert.equal((await sql(other, 'SELECT * FROM origin_clues')).rows.length, 0);
        assert.equal((await sql(other, 'SELECT * FROM origin_clue_batches')).rows.length, 0);
        assert.equal((await pool.query('SELECT * FROM origin_clues')).rows.length, 0, 'unset tenant cannot read rows');
        assert.deepEqual(await count(), before);
      });
      await t.test('clue schema rejects missing provenance and cross-target batch references', async () => {
        await assert.rejects(sql(tenant, `INSERT INTO origin_clues (id, tenant_id, target_id, batch_id, fingerprint, retrieved_at, clue_json)
          VALUES ('invalid_clue', $1, 'tgt_origin', $2, $3, now(), '{}')`, [tenant, first.batch_id, 'c'.repeat(64)]), (error) => error.code === '23514');
        await sql(tenant, `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
          VALUES ('tgt_same_tenant', $1, 'tg_origin', 'fqdn', 'sibling.test', 'sibling.test')`, [tenant]);
        await assert.rejects(sql(tenant, `INSERT INTO origin_clues (id, tenant_id, target_id, batch_id, fingerprint, retrieved_at, clue_json)
          SELECT 'cross_target_clue', tenant_id, 'tgt_same_tenant', batch_id, fingerprint, retrieved_at, clue_json
          FROM origin_clues WHERE tenant_id = $1 AND id = $2`, [tenant, first.items[0].id]), (error) => error.code === '23503');
      });
      await t.test('append-only clue and batch rows reject update and deletion', async () => {
        for (const table of ['origin_clues', 'origin_clue_batches']) {
          await assert.rejects(sql(tenant, `DELETE FROM ${table} WHERE tenant_id = $1`, [tenant]), (error) => error.code === '23514');
          await assert.rejects(sql(tenant, `UPDATE ${table} SET target_id = target_id WHERE tenant_id = $1`, [tenant]), (error) => error.code === '23514');
        }
      });
      await t.test('audit failure rolls back clue and idempotency ledger together', async () => {
        const before = await count();
        const broken = createOriginClueService({ repository: createPostgresOriginClueRepository(pool, { appendAuditEvent: async () => { throw new Error('audit-unavailable'); } }) });
        await assert.rejects(broken.import(ctx, 'tgt_origin', body({ source_ref: 'new-provenance' }), options('failed-audit')), /audit-unavailable/);
        assert.deepEqual(await count(), before);
      });
      await t.test('collection replay never refetches and failed-source coverage persists despite skewed source clocks', async () => {
        let dnsCalls = 0;
        const dns = createOriginClueService({ repository: repo, collectDns: async () => { dnsCalls += 1; return { records: [], sources: [{ type: 'A', hostname: 'origin.test', status: 'unavailable' }], query_count: 3 }; } });
        const result = await dns.collect(ctx, 'tgt_origin', {}, options('collect-1'));
        const replay = await dns.collect(ctx, 'tgt_origin', {}, options('collect-1'));
        assert.deepEqual(replay, result); assert.equal(dnsCalls, 1);
        assert.equal((await dns.list(ctx, 'tgt_origin', {}, options())).coverage.sources[0].status, 'unavailable');
        assert.equal(dnsCalls, 1);
      });
      await t.test('archived/deleted target workflows cannot append or hide the retained history', async () => {
        const before = await count();
        await sql(tenant, `UPDATE target_groups SET archived_at = now() WHERE tenant_id = $1 AND id = 'tg_origin'`, [tenant]);
        assert.equal((await service.import(ctx, 'tgt_origin', body(), options('archived'))).status, 404);
        assert.equal((await service.list(ctx, 'tgt_origin', {}, options())).status, 404);
        assert.deepEqual(await count(), before);
        assert.equal((await sql(tenant, 'SELECT * FROM origin_clues WHERE tenant_id = $1', [tenant])).rows.length, 2);
        assert.equal(first.items.length, 2);
      });
    } finally { await closePgPool(pool); }
  }, availability.env);
});
