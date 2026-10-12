import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { listMigrationFiles, runMigrations } from '../../src/persistence/postgres/migrations.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { MIGRATIONS_DIR, ensureHarnessAppRole, resolvePostgresHarnessAvailability,
  withEphemeralPostgres, withTenantContextAsAppRole } from '../helpers/pg-harness.mjs';

const TENANT = 'ten_transition_order';
const AT = '2026-10-10T00:00:00.000Z';
const MIGRATION = '0077_ownership_transition_order.sql';

test('PostgreSQL ownership history ambiguity and strictly advancing clocks', { timeout: 120_000 }, async (t) => {
  const available = await resolvePostgresHarnessAvailability(process.env);
  if (!available.available) { t.skip(available.reason); return; }
  await withEphemeralPostgres(async (pool) => {
    const files = listMigrationFiles(MIGRATIONS_DIR).filter((file) => file.name < MIGRATION);
    await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files });
    await ensureHarnessAppRole(pool);
    await withTenantContext(pool, TENANT, async (client) => {
      await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'Ownership chronology')`, [TENANT]);
      await client.query(`INSERT INTO target_groups (id, tenant_id, name) VALUES ('tg_order', $1, 'Ownership chronology')`, [TENANT]);
      for (const id of ['conflict', 'equivalent', 'sequential', 'concurrent', 'precision', 'malformed', 'foreign', 'out_of_range', 'boundary']) {
        await client.query(`INSERT INTO targets (id, tenant_id, target_group_id, kind, value)
          VALUES ($1, $2, 'tg_order', 'fqdn', $3)`, [`tgt_${id}`, TENANT, `${id}.example.test`]);
      }
    });
    let sequence = 0;
    const audit = createAuditRepository(pool);
    async function append(target, state = 'dns_verified', source = { token: 'one' }, at = AT) {
      return withTenantContextAsAppRole(pool, TENANT, async (client) => {
        const id = `tv_order_${++sequence}`;
        const entry = await audit.appendAuditEvent({ tenant_id: TENANT, actor_user_id: 'usr_fixture',
          actor_role: 'owner', action: 'target_verification.transitioned', resource_type: 'target_verification',
          resource_id: id, metadata: { target_id: `tgt_${target}`, state } }, { client });
        return (await client.query(
          `INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind, source_ref,
             transitioned_at, transitioned_by, audit_entry_id)
           VALUES ($1, $2, $3, $4, 'dns_txt', $5::jsonb, $6::timestamptz, 'usr_fixture', $7) RETURNING *`,
          [id, TENANT, `tgt_${target}`, state, JSON.stringify(source), at, entry.id],
        )).rows[0];
      });
    }
    async function current(target) {
      return withTenantContextAsAppRole(pool, TENANT, async (client) => (await client.query(
        `SELECT * FROM target_verification_current WHERE tenant_id = $1 AND target_id = $2`,
        [TENANT, `tgt_${target}`],
      )).rows[0]);
    }
    await append('conflict'); await append('conflict', 'dns_verified', { token: 'two' });
    await append('equivalent', 'dns_verified', { b: 2, a: 1 });
    await append('equivalent', 'dns_verified', { a: 1, b: 2 });
    await append('precision', 'dns_verified', {}, '2026-10-10T00:00:00.000999Z');
    await append('malformed', 'pending', {}, '-infinity');
    await append('malformed', 'dns_verified');
    await append('out_of_range', 'dns_verified', {}, '280000-01-01T00:00:00Z');
    await append('boundary', 'dns_verified', {}, '275760-09-13T00:00:00Z');
    const before = await current('conflict');
    assert.equal(before.state, 'dns_verified', 'historical view selected one conflicting verified proof');
    const historyBefore = await withTenantContext(pool, TENANT, async (client) => (await client.query(
      `SELECT to_jsonb(tv) AS value FROM target_verifications tv WHERE tenant_id = $1 ORDER BY id`, [TENANT],
    )).rows);
    await pool.query(readFileSync(new URL(`../../db/migrations/${MIGRATION}`, import.meta.url), 'utf8'));
    await ensureHarnessAppRole(pool);
    const historyAfter = await withTenantContext(pool, TENANT, async (client) => (await client.query(
      `SELECT to_jsonb(tv) AS value FROM target_verifications tv WHERE tenant_id = $1 ORDER BY id`, [TENANT],
    )).rows);
    assert.deepEqual(historyAfter, historyBefore, 'migration must not rewrite historical proof');

    await t.test('legacy conflicting authority stays pending while equivalent duplicates retain proof', async () => {
      const conflict = await current('conflict');
      assert.equal(conflict.state, 'pending'); assert.equal(conflict.source_kind, 'ownership_ambiguous');
      assert.deepEqual(conflict.source_ref, {});
      assert.equal((await current('equivalent')).state, 'dns_verified');
      assert.equal((await current('malformed')).state, 'pending');
      assert.equal((await current('malformed')).source_kind, 'ownership_ambiguous');
    });
    await t.test('new equal/backdated transitions advance by distinct whole milliseconds', async () => {
      const first = await append('sequential');
      const second = await append('sequential', 'pending');
      const third = await append('sequential', 'unverified', {}, '2020-01-01T00:00:00Z');
      assert.equal(second.transitioned_at.getTime(), first.transitioned_at.getTime() + 1);
      assert.equal(third.transitioned_at.getTime(), second.transitioned_at.getTime() + 1);
      assert.equal((await current('sequential')).state, 'unverified');
      const precision = await append('precision', 'pending');
      assert.equal(precision.transitioned_at.toISOString(), '2026-10-10T00:00:00.001Z');
    });
    await t.test('two actual concurrent clients cannot commit the same transition instant', async () => {
      const rows = await Promise.all([append('concurrent'), append('concurrent', 'pending')]);
      const instants = rows.map((row) => row.transitioned_at.getTime()).sort((a, b) => a - b);
      assert.equal(instants[1] - instants[0], 1);
      assert.equal((await current('concurrent')).state, rows.find((row) => row.transitioned_at.getTime() === instants[1]).state);
    });
    await t.test('finite SQL clocks outside JavaScript range and successor overflow fail closed', async () => {
      const invalid = await current('out_of_range');
      assert.equal(invalid.state, 'pending');
      assert.equal(invalid.source_kind, 'ownership_ambiguous');
      assert.deepEqual(invalid.source_ref, {});
      await assert.rejects(append('out_of_range'), { code: '23514' });
      await assert.rejects(append('foreign', 'dns_verified', {}, '280000-01-01T00:00:00Z'), { code: '23514' });
      await assert.rejects(append('boundary'), { code: '23514' });
      const boundary = await current('boundary');
      assert.equal(boundary.state, 'dns_verified', 'existing representable boundary proof is unchanged');
      const exact = await withTenantContextAsAppRole(pool, TENANT, async (client) => (await client.query(
        `SELECT extract(epoch FROM transitioned_at) * 1000 AS epoch_ms
         FROM target_verification_current WHERE tenant_id = $1 AND target_id = 'tgt_boundary'`, [TENANT],
      )).rows[0]);
      assert.equal(Number(exact.epoch_ms), 8_640_000_000_000_000);
    });
    await t.test('nonfinite clock/history and cross-tenant inserts reject without mutation', async () => {
      for (const at of ['infinity', '-infinity']) await assert.rejects(append('foreign', 'dns_verified', {}, at), { code: '23514' });
      await assert.rejects(append('malformed'), { code: '23514' });
      await assert.rejects(withTenantContextAsAppRole(pool, TENANT, (client) => client.query(
        `INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind, transitioned_at)
         VALUES ('tv_order_foreign', 'ten_other', 'tgt_foreign', 'dns_verified', 'dns_txt', $1::timestamptz)`, [AT],
      )), { code: '23514' });
      assert.equal(await current('foreign'), undefined);
    });
  }, process.env, { applyMigrations: false });
});
