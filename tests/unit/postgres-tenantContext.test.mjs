import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';

function createFakePool() {
  const client = {
    queries: [],
    released: false,
    async query(text, params) {
      this.queries.push({ text, params });
      return { rows: [] };
    },
    release() {
      this.released = true;
    },
  };
  return {
    client,
    async connect() {
      return client;
    },
  };
}

describe('postgres tenant context', () => {
  it('runs BEGIN, set_config tenant id, callback, COMMIT, and releases client', async () => {
    const pool = createFakePool();
    const seen = [];
    const result = await withTenantContext(pool, 'ten_demo', async (client) => {
      await client.query('SELECT 1');
      seen.push('callback');
      return 'ok';
    });
    assert.equal(result, 'ok');
    assert.deepEqual(
      pool.client.queries.map((q) => ({ text: q.text.trim(), params: q.params })),
      [
        { text: 'BEGIN', params: undefined },
        { text: "SELECT set_config('app.tenant_id', $1, true)", params: ['ten_demo'] },
        { text: 'SELECT 1', params: undefined },
        { text: 'COMMIT', params: undefined },
      ],
    );
    assert.equal(pool.client.released, true);
    assert.deepEqual(seen, ['callback']);
  });

  it('rolls back and releases on callback failure', async () => {
    const pool = createFakePool();
    await assert.rejects(
      () =>
        withTenantContext(pool, 'ten_demo', async () => {
          throw new Error('query failed');
        }),
      /query failed/,
    );
    assert.ok(pool.client.queries.some((q) => q.text.trim() === 'ROLLBACK'));
    assert.equal(pool.client.released, true);
  });

  it('shares one transaction across same-pool same-tenant repository callbacks', async () => {
    const pool = createFakePool();
    await withTenantContext(pool, 'ten_demo', async (outer) => {
      await withTenantContext(pool, 'ten_demo', async (inner) => {
        assert.equal(inner, outer);
        assert.equal(inner.released, false);
        await inner.query('INSERT fixture');
      });
      assert.equal(outer.released, false);
    });
    assert.equal(pool.client.queries.filter((q) => q.text === 'BEGIN').length, 1);
    assert.equal(pool.client.queries.filter((q) => q.text === 'COMMIT').length, 1);
  });

  it('rolls back nested writes when admission fails after a repository callback', async () => {
    const pool = createFakePool();
    await assert.rejects(() => withTenantContext(pool, 'ten_demo', async () => {
      await withTenantContext(pool, 'ten_demo', (client) => client.query('INSERT fixture'));
      throw new Error('admission lost authority');
    }), /lost authority/);
    assert.equal(pool.client.queries.filter((q) => q.text === 'COMMIT').length, 0);
    assert.equal(pool.client.queries.filter((q) => q.text === 'ROLLBACK').length, 1);
  });

  it('does not reuse a transaction for a different tenant', async () => {
    const pool = createFakePool();
    await assert.rejects(() => withTenantContext(pool, 'ten_demo', () =>
      withTenantContext(pool, 'ten_other', async () => {})), /tenant context mismatch/);
    assert.equal(pool.client.queries.filter((q) => q.text === 'BEGIN').length, 1);
  });

  it('cannot commit a transaction after a caught nested failure', async () => {
    const pool = createFakePool();
    await assert.rejects(() => withTenantContext(pool, 'ten_demo', async () => {
      try {
        await withTenantContext(pool, 'ten_demo', async () => { throw new Error('nested failed'); });
      } catch { /* A caught callback failure still invalidates the transaction. */ }
    }), /nested failed/);
    assert.equal(pool.client.queries.filter((q) => q.text === 'COMMIT').length, 0);
  });

  it('rejects empty tenant id', async () => {
    const pool = createFakePool();
    await assert.rejects(() => withTenantContext(pool, '  ', async () => {}), /non-empty/);
  });

  it('trims tenant id before set_config', async () => {
    const pool = createFakePool();
    await withTenantContext(pool, '  ten_trimmed  ', async () => {});
    const setConfig = pool.client.queries.find((q) =>
      /set_config\('app\.tenant_id'/.test(q.text),
    );
    assert.deepEqual(setConfig?.params, ['ten_trimmed']);
  });

  it('releases client and preserves COMMIT failure', async () => {
    const pool = createFakePool();
    pool.client.query = async function query(text, params) {
      this.queries.push({ text, params });
      if (String(text).trim() === 'COMMIT') {
        throw new Error('commit failed');
      }
      return { rows: [] };
    };

    await assert.rejects(
      () => withTenantContext(pool, 'ten_demo', async () => 'ok'),
      /commit failed/,
    );
    assert.equal(pool.client.released, true);
  });

  it('releases client and preserves callback error when ROLLBACK also fails', async () => {
    const pool = createFakePool();
    pool.client.query = async function query(text, params) {
      this.queries.push({ text, params });
      const normalized = String(text).trim();
      if (normalized === 'ROLLBACK') {
        throw new Error('rollback failed');
      }
      return { rows: [] };
    };

    await assert.rejects(
      () =>
        withTenantContext(pool, 'ten_demo', async () => {
          throw new Error('query failed');
        }),
      /query failed/,
    );
    assert.equal(pool.client.released, true);
  });
});