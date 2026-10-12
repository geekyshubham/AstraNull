import assert from 'node:assert/strict';
import { test } from 'node:test';
import { withManagedTenantClient, withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';

function fixture() {
  const statements = [];
  const client = { async query(statement) { statements.push(statement); return { rows: [] }; }, release() { statements.push('RELEASE'); } };
  let connections = 0;
  const pool = { async connect() { connections += 1; return client; }, async query() { assert.fail('raw Pool query'); } };
  return { pool, client, statements, connections: () => connections };
}
const invalid = (error) => error.code === 'reviewed_operation_authority_client_invalid'
  && error.status === 400 && error.grants_execution === false && error.execution_available === false;

test('managed authority helper rejects pool/autocommit/untracked/manual clients before any reads or callback', async () => {
  const f = fixture();
  for (const client of [f.pool, f.client, { query() {} }, null, false]) {
    let invoked = false;
    await assert.rejects(withManagedTenantClient(f.pool, 'ten_test', client, () => { invoked = true; }), invalid);
    assert.equal(invoked, false);
  }
  assert.deepEqual(f.statements, []); assert.equal(f.connections(), 0);
});
test('only exact active client, tenant and pool are accepted; no alternate-client fallback or acquisition occurs', async () => {
  const f = fixture();
  await withTenantContext(f.pool, 'ten_test', async (held) => {
    const before = f.statements.length;
    for (const [pool, tenant, client] of [[{}, 'ten_test', held], [f.pool, 'ten_other', held],
      [f.pool, 'ten_test', { query() {} }], [f.pool, 'ten_test', f.pool]]) {
      await assert.rejects(withManagedTenantClient(pool, tenant, client, () => assert.fail()), invalid);
    }
    assert.equal(f.statements.length, before);
    assert.equal(await withManagedTenantClient(f.pool, 'ten_test', held, (client) => {
      assert.equal(client, held); return 'exact';
    }), 'exact');
  });
  assert.equal(f.connections(), 1);
  assert.deepEqual(f.statements, ['BEGIN', "SELECT set_config('app.tenant_id', $1, true)", 'COMMIT', 'RELEASE']);
  await assert.rejects(withManagedTenantClient(f.pool, 'ten_test', f.client, () => assert.fail()), invalid);
});
test('a detached async branch cannot reuse a finished managed scope even when it retains the same client', async () => {
  const f = fixture(); let resume, branch;
  const wait = new Promise((resolve) => { resume = resolve; });
  await withTenantContext(f.pool, 'ten_test', (client) => {
    branch = (async () => { await wait; return withManagedTenantClient(f.pool, 'ten_test', client, () => assert.fail()); })();
    void branch.catch(() => {});
  });
  resume(); await assert.rejects(branch, invalid);
  assert.equal(f.connections(), 1);
});
test('managed explicit callback failure poisons outer transaction even when its caller catches the rejection', async () => {
  const f = fixture(), error = new Error('authority consumer failure');
  await assert.rejects(withTenantContext(f.pool, 'ten_test', async (held) => {
    try {
      await withManagedTenantClient(f.pool, 'ten_test', held, async (client) => {
        await client.query('CALLBACK WRITE'); throw error;
      });
    } catch (caught) { assert.equal(caught, error); }
  }), (caught) => caught === error);
  assert.equal(f.connections(), 1);
  assert.deepEqual(f.statements, ['BEGIN', "SELECT set_config('app.tenant_id', $1, true)", 'CALLBACK WRITE', 'ROLLBACK', 'RELEASE']);
});
test('implicit managed callback gets an owned transaction and cannot release it before async work resolves', async () => {
  const f = fixture(); let resume, entered;
  const wait = new Promise((resolve) => { resume = resolve; });
  const ready = new Promise((resolve) => { entered = resolve; });
  const work = withManagedTenantClient(f.pool, 'ten_test', undefined, async (client) => {
    assert.equal(client, f.client); entered(); await wait; return 'complete';
  });
  await ready;
  assert.equal(f.statements.includes('COMMIT'), false); assert.equal(f.statements.includes('RELEASE'), false);
  resume(); assert.equal(await work, 'complete');
  assert.deepEqual(f.statements, ['BEGIN', "SELECT set_config('app.tenant_id', $1, true)", 'COMMIT', 'RELEASE']);
});
