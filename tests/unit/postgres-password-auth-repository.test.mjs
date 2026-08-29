import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createPasswordAuthRepository } from '../../src/persistence/postgres/passwordAuthRepository.mjs';

const NOW = '2026-08-27T16:00:00.000Z';

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

function compact(text) {
  return String(text).replace(/\s+/g, ' ').trim();
}

describe('Postgres password auth repository', () => {
  it('discovers a unique email under SELECT-only platform scope, then reads its credential in tenant scope', async () => {
    const pool = createRecordingPool((text, _params, connection) => {
      if (connection === 0 && /FROM users/.test(text)) {
        return {
          rows: [{
            id: 'usr_1',
            tenant_id: 'ten_1',
            email: 'person@example.com',
            role: 'viewer',
            status: 'active',
          }],
        };
      }
      if (connection === 1 && /LEFT JOIN user_credentials/.test(text)) {
        return {
          rows: [{
            id: 'usr_1',
            tenant_id: 'ten_1',
            email: 'person@example.com',
            role: 'viewer',
            status: 'active',
            password_hash: 'scrypt$encoded',
            failed_attempts: 0,
            must_change: false,
          }],
        };
      }
      return { rows: [] };
    });

    const users = await createPasswordAuthRepository(pool).findUsersByEmail(
      'person@example.com',
    );
    assert.equal(users.length, 1);
    assert.equal(users[0].credential.password_hash, 'scrypt$encoded');
    assert.equal(pool.clients.length, 2);
    assert.ok(pool.clients[0].queries.some((q) => compact(q.text).includes("set_config('app.platform_scope', 'on', true)")));
    assert.deepEqual(
      pool.clients[1].queries.find((q) => /set_config\('app.tenant_id'/.test(q.text)).params,
      ['ten_1'],
    );
    assert.equal(pool.clients.every((client) => client.released), true);
  });

  it('looks up an invite only under its transaction-local token hash, then re-reads it in tenant scope', async () => {
    const tokenHash = 'a'.repeat(64);
    const pool = createRecordingPool((text, params, connection) => {
      if (connection === 0 && /FROM user_password_invites/.test(text)) {
        assert.deepEqual(params, [tokenHash]);
        return {
          rows: [{
            id: 'pwi_1',
            tenant_id: 'ten_1',
            user_id: 'usr_1',
            token_hash: tokenHash,
            expires_at: '2026-09-01T00:00:00.000Z',
            consumed_at: null,
          }],
        };
      }
      if (connection === 1 && /JOIN users/.test(text)) {
        return {
          rows: [{
            id: 'pwi_1',
            tenant_id: 'ten_1',
            user_id: 'usr_1',
            token_hash: tokenHash,
            expires_at: '2026-09-01T00:00:00.000Z',
            consumed_at: null,
            email: 'person@example.com',
            role: 'viewer',
            user_status: 'invited',
          }],
        };
      }
      return { rows: [] };
    });

    const invite = await createPasswordAuthRepository(pool).findPasswordInviteByTokenHash(tokenHash);
    assert.equal(invite.email, 'person@example.com');
    assert.deepEqual(
      pool.clients[0].queries.find((q) => /app.password_invite_token_hash/.test(q.text)).params,
      [tokenHash],
    );
    assert.equal(
      pool.clients[0].queries.some((q) => /user_credentials/.test(q.text)),
      false,
      'pre-tenant lookup must never read password hashes',
    );
    assert.deepEqual(
      pool.clients[1].queries.find((q) => /set_config\('app.tenant_id'/.test(q.text)).params,
      ['ten_1'],
    );
  });

  it('locks the invite and writes credential, consumption, and user activation in one transaction', async () => {
    const tokenHash = 'b'.repeat(64);
    const pool = createRecordingPool((text) => {
      if (/FOR UPDATE/.test(text)) {
        return {
          rows: [{
            id: 'pwi_1',
            tenant_id: 'ten_1',
            user_id: 'usr_1',
            expires_at: '2026-09-01T00:00:00.000Z',
            consumed_at: null,
          }],
        };
      }
      if (/UPDATE users/.test(text)) {
        return {
          rows: [{
            id: 'usr_1',
            tenant_id: 'ten_1',
            email: 'person@example.com',
            role: 'viewer',
          }],
        };
      }
      return { rows: [] };
    });
    const repository = createPasswordAuthRepository(pool);
    const result = await repository.setPasswordFromInvite(
      {
        id: 'pwi_1',
        tenant_id: 'ten_1',
        user_id: 'usr_1',
      },
      { passwordHash: 'scrypt$encoded', tokenHash, now: NOW },
    );

    assert.deepEqual(result, {
      tenant_id: 'ten_1',
      user_id: 'usr_1',
      email: 'person@example.com',
      role: 'viewer',
    });
    assert.equal(pool.clients.length, 1);
    const statements = pool.clients[0].queries.map((query) => compact(query.text));
    assert.equal(statements[0], 'BEGIN');
    assert.match(statements[1], /set_config\('app.tenant_id'/);
    const inviteLockIndex = statements.findIndex(
      (sql) => /FROM user_password_invites/.test(sql) && /FOR UPDATE/.test(sql),
    );
    const userLockIndex = statements.findIndex(
      (sql) => /FROM users/.test(sql) && /FOR UPDATE/.test(sql),
    );
    const credentialIndex = statements.findIndex((sql) => /INSERT INTO user_credentials/.test(sql));
    const consumeIndex = statements.findIndex((sql) => /UPDATE user_password_invites/.test(sql));
    const activateIndex = statements.findIndex((sql) => /UPDATE users/.test(sql));
    assert.ok(inviteLockIndex > 0);
    assert.ok(userLockIndex > inviteLockIndex);
    assert.ok(credentialIndex > userLockIndex);
    assert.ok(consumeIndex > credentialIndex);
    assert.ok(activateIndex > consumeIndex);
    assert.equal(statements.at(-1), 'COMMIT');
    assert.equal(pool.clients[0].released, true);
  });

  it('does not mutate credentials or consume an invite when the user is no longer eligible', async () => {
    const pool = createRecordingPool((text) => {
      if (/FROM user_password_invites/.test(text) && /FOR UPDATE/.test(text)) {
        return {
          rows: [{
            id: 'pwi_1',
            tenant_id: 'ten_1',
            user_id: 'usr_1',
            expires_at: '2026-09-01T00:00:00.000Z',
            consumed_at: null,
          }],
        };
      }
      if (/FROM users/.test(text) && /FOR UPDATE/.test(text)) return { rows: [] };
      return { rows: [] };
    });

    const result = await createPasswordAuthRepository(pool).setPasswordFromInvite(
      { id: 'pwi_1', tenant_id: 'ten_1', user_id: 'usr_1' },
      { passwordHash: 'scrypt$encoded', tokenHash: 'c'.repeat(64), now: NOW },
    );
    assert.deepEqual(result, { error: 'invalid_invite' });
    const statements = pool.clients[0].queries.map((query) => compact(query.text));
    assert.equal(statements.some((sql) => /INSERT INTO user_credentials/.test(sql)), false);
    assert.equal(statements.some((sql) => /UPDATE user_password_invites/.test(sql)), false);
    assert.equal(statements.at(-1), 'COMMIT');
  });

  it('rolls back every password setup mutation when a write fails', async () => {
    const pool = createRecordingPool((text) => {
      if (/FOR UPDATE/.test(text)) {
        return {
          rows: [{
            id: 'pwi_1',
            tenant_id: 'ten_1',
            user_id: 'usr_1',
            expires_at: '2026-09-01T00:00:00.000Z',
            consumed_at: null,
          }],
        };
      }
      if (/INSERT INTO user_credentials/.test(text)) throw new Error('write failed');
      return { rows: [] };
    });

    await assert.rejects(
      () => createPasswordAuthRepository(pool).setPasswordFromInvite(
        { id: 'pwi_1', tenant_id: 'ten_1', user_id: 'usr_1' },
        { passwordHash: 'scrypt$encoded', tokenHash: 'c'.repeat(64), now: NOW },
      ),
      /write failed/,
    );
    assert.equal(compact(pool.clients[0].queries.at(-1).text), 'ROLLBACK');
    assert.equal(pool.clients[0].released, true);
  });
});
