import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAssistantWidgetRepository } from '../../src/persistence/postgres/assistantWidgetRepository.mjs';

const ctx = { tenantId: 'ten_widget', userId: 'usr_widget', role: 'viewer', persistenceMode: 'postgres' };
const config = { name: 'Observed findings', question: 'What was observed?', template: 'summary' };
const stored = { id: 'aw_000000000000000000000000', config, version: 1, created_at: new Date('2026-10-19T00:00:00Z'), updated_at: new Date('2026-10-19T00:00:00Z') };
function fixture({ slots = [], existing = stored, auditFails = false, queryFails = false } = {}) {
  const calls = [], audits = [];
  const client = { query: async (sql, params) => {
    calls.push({ sql, params });
    if (queryFails && sql.startsWith('SELECT slot')) throw new Error('database unavailable');
    if (sql.startsWith('SELECT slot')) return { rows: slots.map((slot) => ({ slot })) };
    if (sql.includes('FOR UPDATE')) return { rows: existing ? [existing] : [] };
    if (sql.startsWith('INSERT INTO')) return { rows: [{ ...stored, id: params[0] }] };
    if (sql.startsWith('UPDATE')) return { rows: [{ ...stored, config: JSON.parse(params[3]), version: 2 }] };
    if (sql.startsWith('DELETE')) return { rows: [], rowCount: 1 };
    if (sql.includes('FROM assistant_widgets')) return { rows: [stored] };
    return { rows: [] };
  }, release: () => calls.push({ sql: 'RELEASE' }) };
  const pool = { connect: async () => client };
  const auditRepository = { appendAuditEvent: async (entry, options) => {
    assert.equal(options.client, client); audits.push(entry);
    calls.push({ sql: 'AUDIT' });
    if (auditFails) throw new Error('audit unavailable');
  } };
  return { repository: createAssistantWidgetRepository(pool, { auditRepository }), calls, audits };
}

test('Postgres binds tenant/user + explicit ownership predicate and returns definitions, never dev data', async () => {
  const { repository, calls } = fixture();
  const rows = await repository.list(ctx);
  assert.equal(rows[0].id, stored.id); assert.equal(rows[0].created_at, '2026-10-19T00:00:00.000Z');
  assert.deepEqual(calls.map((call) => call.sql), ['BEGIN', "SELECT set_config('app.tenant_id', $1, true)", "SELECT set_config('app.user_id', $1, true)",
    'SELECT id, config_json AS config, version, created_at, updated_at\n      FROM assistant_widgets WHERE tenant_id = $1 AND user_id = $2 ORDER BY created_at, id LIMIT 12', 'COMMIT', 'RELEASE']);
  assert.deepEqual(calls[1].params, [ctx.tenantId]); assert.deepEqual(calls[2].params, [ctx.userId]); assert.deepEqual(calls[3].params, [ctx.tenantId, ctx.userId]);
});

test('Postgres create/update/delete atomically audit on same client before COMMIT, with revision pin', async () => {
  for (const operation of ['create', 'update', 'remove']) {
    const { repository, calls, audits } = fixture();
    const result = await (operation === 'create' ? repository.create(ctx, config) : operation === 'update' ? repository.update(ctx, stored.id, config, 1) : repository.remove(ctx, stored.id, 1));
    assert.equal(result.error, undefined);
    assert.equal(audits.length, 1); assert.equal(audits[0].actor_user_id, ctx.userId);
    assert.equal(JSON.stringify(audits).includes(config.question), false);
    assert.ok(calls.findIndex((call) => call.sql.startsWith('SELECT pg_advisory')) < calls.findIndex((call) => call.sql === 'AUDIT'));
    assert.deepEqual(calls.slice(-3).map((call) => call.sql), ['AUDIT', 'COMMIT', 'RELEASE']);
    if (operation === 'update') assert.equal(calls.find((call) => call.sql.startsWith('UPDATE')).params[4], 1);
    if (operation === 'remove') assert.equal(calls.find((call) => call.sql.startsWith('DELETE')).params[3], 1);
  }
});

test('Postgres audit/database failure rolls back, no fallback; quota/version/ownership conflicts never audit mutations', async () => {
  for (const operation of ['create', 'update', 'remove']) {
    const { repository, calls } = fixture({ auditFails: true });
    await assert.rejects(operation === 'create' ? repository.create(ctx, config) : operation === 'update' ? repository.update(ctx, stored.id, config, 1) : repository.remove(ctx, stored.id, 1), /audit unavailable/);
    assert.deepEqual(calls.slice(-2).map((call) => call.sql), ['ROLLBACK', 'RELEASE']);
    assert.equal(calls.some((call) => call.sql === 'COMMIT'), false);
  }
  const broken = fixture({ queryFails: true });
  await assert.rejects(broken.repository.create(ctx, config), /database unavailable/);
  assert.equal(broken.audits.length, 0);
  for (const [options, operation, code] of [[{ slots: Array.from({ length: 12 }, (_, i) => i + 1) }, 'create', 'widget_limit_reached'],
    [{ existing: null }, 'remove', 'widget_not_found'], [{ existing: { ...stored, version: 2 } }, 'update', 'widget_version_conflict']]) {
    const { repository, calls, audits } = fixture(options);
    await assert.rejects(operation === 'create' ? repository.create(ctx, config) : operation === 'update' ? repository.update(ctx, stored.id, config, 1) : repository.remove(ctx, stored.id, 1), (error) => error.code === code);
    assert.equal(audits.length, 0); assert.equal(calls.some((call) => /^(INSERT|UPDATE|DELETE)/.test(call.sql)), false);
  }
});
