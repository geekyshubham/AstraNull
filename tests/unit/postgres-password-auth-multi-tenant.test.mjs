import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createPasswordAuthRepository } from '../../src/persistence/postgres/passwordAuthRepository.mjs';

function createRecordingPool(handler) {
  const clients = [];
  return {
    clients,
    async connect() {
      const client = {
        queries: [],
        released: false,
        async query(text, params) {
          this.queries.push({ text, params });
          return handler(text, params, clients.length - 1);
        },
        release() {
          this.released = true;
        },
      };
      clients.push(client);
      return client;
    },
  };
}

describe('Postgres password auth repository multi-workspace lookup', () => {
  it('loads every candidate workspace in its own tenant scope with the workspace display name', async () => {
    const pool = createRecordingPool((text, params, connection) => {
      if (connection === 0 && /SELECT DISTINCT tenant_id/.test(text)) {
        assert.equal(params[0], 'shared@example.com');
        return { rows: [{ tenant_id: 'ten_a' }, { tenant_id: 'ten_b' }] };
      }
      if (/LEFT JOIN tenants t/.test(text)) {
        const tenantId = params[0];
        return {
          rows: [{
            id: `usr_${tenantId}`,
            tenant_id: tenantId,
            email: 'shared@example.com',
            role: 'viewer',
            status: 'active',
            tenant_name: `Name ${tenantId}`,
            password_hash: `hash-${tenantId}`,
            failed_attempts: 0,
            must_change: false,
          }],
        };
      }
      return { rows: [] };
    });

    const users = await createPasswordAuthRepository(pool).findUsersByEmail('shared@example.com');
    assert.deepEqual(
      users.map((user) => [user.tenant_id, user.tenant_name, user.credential.password_hash]),
      [['ten_a', 'Name ten_a', 'hash-ten_a'], ['ten_b', 'Name ten_b', 'hash-ten_b']],
    );
    const platformQuery = pool.clients[0].queries.find((q) => /SELECT DISTINCT tenant_id/.test(q.text));
    assert.doesNotMatch(platformQuery.text, /password_hash|user_credentials/);
    const tenantScopes = pool.clients.slice(1).map(
      (client) => client.queries.find((q) => /set_config\('app.tenant_id'/.test(q.text)).params,
    );
    assert.deepEqual(tenantScopes, [['ten_a'], ['ten_b']]);
    assert.equal(pool.clients.every((client) => client.released), true);
  });
});
