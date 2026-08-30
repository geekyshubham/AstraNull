import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { computeTotpAtStep } from '../../src/lib/totp.mjs';
import { hashPassword } from '../../src/lib/password.mjs';
import { createPasswordAuthRepository } from '../../src/persistence/postgres/passwordAuthRepository.mjs';
import { createServer } from '../../src/server.mjs';
import { createPasswordAuthService } from '../../src/services/passwordAuth.mjs';
import { createDevPasswordAuthRepository } from '../../src/services/passwordAuthRepository.mjs';
import { getStore, resetStoreForTests } from '../../src/store.mjs';
import { closeServer, request } from '../helpers/http.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');
const SESSION_SECRET = 'password-hardening-route-session-secret-32';
const ENCRYPTION_KEY = Buffer.from(Array.from({ length: 32 }, (_, index) => 255 - index));
const PASSWORD = 'Route-Password-84!Strong';
let server;

afterEach(async () => {
  await closeServer(server);
  server = null;
});

function compact(value) {
  return String(value).replace(/\s+/g, ' ').trim();
}

function createRecordingPool(handler) {
  const clients = [];
  return {
    clients,
    async connect() {
      const connection = clients.length;
      const client = {
        queries: [],
        released: false,
        async query(text, params) {
          this.queries.push({ text, params });
          return handler(text, params, connection);
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

async function startServer(services, runtimeOverrides = {}) {
  const env = {
    ...process.env,
    NODE_ENV: 'test',
    ASTRANULL_AUTH_MODE: 'signed-session',
    ASTRANULL_SESSION_SECRET: SESSION_SECRET,
    ASTRANULL_NO_PERSIST: '1',
    ASTRANULL_PASSWORD_LOGIN_ENABLED: '1',
  };
  const runtimeConfig = {
    ...loadRuntimeConfig(env),
    secretEncryptionKey: ENCRYPTION_KEY,
    secretEncryptionConfigured: true,
    ...runtimeOverrides,
  };
  server = createServer({ env, runtimeConfig, services });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return {
    baseUrl: `http://127.0.0.1:${server.address().port}`,
    runtimeConfig,
  };
}

describe('password recovery HTTP boundary', () => {
  it('is public, injects the durable enqueue dependency, and strips accidental enumeration fields', async () => {
    const delivery = { async enqueuePasswordReset() {} };
    let received;
    const passwordAuth = {
      async requestPasswordReset(body, options) {
        received = { body, options };
        if (body.email === 'leak-error@example.test') {
          return {
            error: 'account_exists',
            status: 418,
            message: 'This account exists.',
            delivered: false,
            email: body.email,
            reset_token: 'must-not-leak',
          };
        }
        return {
          status: 'reset_requested',
          delivered: true,
          account_exists: true,
          email: body.email,
        };
      },
      async resetPasswordWithToken() {
        return { status: 'password_reset' };
      },
    };
    const { baseUrl } = await startServer({ passwordAuth, passwordRecoveryDelivery: delivery });
    const response = await request(baseUrl, 'POST', '/v1/auth/request-password-reset', {
      body: { email: 'person@example.test' },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.json, { status: 'reset_requested' });
    assert.equal(received.body.email, 'person@example.test');
    assert.equal(received.options.delivery, delivery);
    assert.match(received.options.clientKey, /^ip:/);

    const injectedError = await request(baseUrl, 'POST', '/v1/auth/request-password-reset', {
      body: { email: 'leak-error@example.test' },
    });
    assert.equal(injectedError.status, 200);
    assert.deepEqual(injectedError.json, response.json);
  });

  it('fails closed with the same public response when no recovery service or delivery exists', async () => {
    const passwordHash = await hashPassword(PASSWORD);
    resetStoreForTests({
      tenants: [{ id: 'ten_recovery', name: 'Recovery Tenant' }],
      users: [{
        id: 'usr_recovery',
        tenant_id: 'ten_recovery',
        email: 'recovery@example.test',
        name: 'Recovery User',
        role: 'admin',
        status: 'active',
      }],
      userCredentials: [{
        user_id: 'usr_recovery',
        tenant_id: 'ten_recovery',
        password_hash: passwordHash,
        password_updated_at: new Date().toISOString(),
        must_change: false,
        failed_attempts: 0,
        locked_until: null,
        session_generation: 1,
        created_at: new Date().toISOString(),
      }],
      userPasswordInvites: [],
      userPasswordResets: [],
      auditLog: [],
    });
    const passwordAuth = createPasswordAuthService(createDevPasswordAuthRepository());
    let started = await startServer({ passwordAuth });
    const noDelivery = await request(started.baseUrl, 'POST', '/v1/auth/request-password-reset', {
      body: { email: 'recovery@example.test' },
    });
    assert.equal(noDelivery.status, 200);
    assert.deepEqual(noDelivery.json, { status: 'reset_requested' });
    assert.equal(getStore().userPasswordResets.length, 0);
    assert.ok(getStore().auditLog.some(
      (entry) => entry.action === 'auth.password.reset_delivery_enqueue_failed',
    ));

    await closeServer(server);
    server = null;
    started = await startServer({ passwordAuth: {} });
    const noService = await request(started.baseUrl, 'POST', '/v1/auth/request-password-reset', {
      body: { email: 'recovery@example.test' },
    });
    assert.equal(noService.status, 200);
    assert.deepEqual(noService.json, noDelivery.json);
  });

  it('strips account, token, and delivery fields from reset completion responses', async () => {
    const passwordAuth = {
      async requestPasswordReset() {
        return { status: 'reset_requested' };
      },
      async resetPasswordWithToken(body) {
        if (body.token === 'bad') {
          return {
            error: 'invalid_reset_token',
            status: 401,
            message: 'The password reset request is invalid.',
            email: 'leak@example.test',
            reset_token: 'must-not-leak',
            delivered: false,
          };
        }
        return {
          status: 'password_reset',
          tenant_id: 'ten_leak',
          user_id: 'usr_leak',
          email: 'leak@example.test',
          reset_token: 'must-not-leak',
          delivered: true,
        };
      },
    };
    const { baseUrl } = await startServer({ passwordAuth });
    const success = await request(baseUrl, 'POST', '/v1/auth/reset-password', {
      body: { token: 'good', password: PASSWORD },
    });
    assert.equal(success.status, 200);
    assert.deepEqual(success.json, { status: 'password_reset' });

    const failure = await request(baseUrl, 'POST', '/v1/auth/reset-password', {
      body: { token: 'bad', password: PASSWORD },
    });
    assert.equal(failure.status, 401);
    assert.deepEqual(failure.json, {
      error: 'invalid_reset_token',
      message: 'The password reset request is invalid.',
    });
  });
});

describe('password-session generation enforcement', () => {
  it('rejects a locally minted session immediately after MFA enable increments generation', async () => {
    const now = new Date();
    const passwordHash = await hashPassword(PASSWORD);
    resetStoreForTests({
      tenants: [{ id: 'ten_session', name: 'Session Tenant' }],
      users: [{
        id: 'usr_session',
        tenant_id: 'ten_session',
        email: 'session@example.test',
        name: 'Session User',
        role: 'admin',
        status: 'active',
      }],
      userCredentials: [{
        user_id: 'usr_session',
        tenant_id: 'ten_session',
        password_hash: passwordHash,
        password_updated_at: now.toISOString(),
        must_change: false,
        failed_attempts: 0,
        locked_until: null,
        session_generation: 1,
        created_at: now.toISOString(),
      }],
      userPasswordInvites: [],
      userPasswordResets: [],
      auditLog: [],
    });
    const passwordAuth = createPasswordAuthService(createDevPasswordAuthRepository());
    const { baseUrl, runtimeConfig } = await startServer({ passwordAuth });
    const login = await passwordAuth.loginWithPassword(
      { email: 'session@example.test', password: PASSWORD },
      { runtimeConfig, clientKey: 'route-login', now },
    );
    assert.ok(login.access_token);
    const headers = { Authorization: `Bearer ${login.access_token}` };

    const enrollment = await request(baseUrl, 'POST', '/v1/auth/mfa/enroll', { headers, body: {} });
    assert.equal(enrollment.status, 200);
    const step = Math.floor(Date.now() / 1000 / 30);
    const code = computeTotpAtStep(enrollment.json.secret, step);
    const confirmed = await request(baseUrl, 'POST', '/v1/auth/mfa/verify', {
      headers,
      body: { totp: code },
    });
    assert.equal(confirmed.status, 200);
    assert.equal(confirmed.json.status, 'mfa_enabled');

    const stale = await request(baseUrl, 'GET', '/v1/tenants/current', { headers });
    assert.equal(stale.status, 401);
    assert.equal(stale.json.error, 'unauthorized');
  });
});

describe('Postgres password-auth atomic shapes', () => {
  it('records failed-attempt state and its audit in one transaction', async () => {
    const pool = createRecordingPool((text) => {
      if (/UPDATE user_credentials/.test(text)) {
        return {
          rows: [{
            user_id: 'usr_1',
            tenant_id: 'ten_1',
            password_hash: 'scrypt$encoded',
            session_generation: 7,
            failed_attempts: 1,
          }],
          rowCount: 1,
        };
      }
      return { rows: [], rowCount: 1 };
    });
    const result = await createPasswordAuthRepository(pool).recordLoginFailure(
      'ten_1',
      'usr_1',
      {
        now: '2026-08-29T12:00:00.000Z',
        lockUntil: '2026-08-29T12:15:00.000Z',
        maxAttempts: 5,
        audit: (client) => client.query(
          'INSERT INTO audit_logs (tenant_id, action) VALUES ($1, $2)',
          ['ten_1', 'auth.password_login.failed'],
        ),
      },
    );
    assert.equal(result.failed_attempts, 1);
    const statements = pool.clients[0].queries.map((query) => compact(query.text));
    assert.ok(statements.some((sql) => /INSERT INTO audit_logs/.test(sql)));
    assert.equal(statements[0], 'BEGIN');
    assert.equal(statements.at(-1), 'COMMIT');
  });

  it('uses generation-bound MFA CAS so only one concurrent login can consume a step', async () => {
    let winnerAvailable = true;
    const pool = createRecordingPool((text) => {
      if (/UPDATE user_credentials/.test(text) && /mfa_last_step = CASE/.test(text)) {
        if (!winnerAvailable) return { rows: [], rowCount: 0 };
        winnerAvailable = false;
        return {
          rows: [{
            user_id: 'usr_1',
            tenant_id: 'ten_1',
            password_hash: 'scrypt$encoded',
            session_generation: 7,
            mfa_secret_envelope: { version: 1 },
            mfa_enrollment_id: 'mfa_1',
            mfa_enrolled_at: '2026-08-29T00:00:00.000Z',
            mfa_last_step: 99,
          }],
          rowCount: 1,
        };
      }
      if (/FROM audit_logs/.test(text)) return { rows: [] };
      return { rows: [], rowCount: 1 };
    });
    const repository = createPasswordAuthRepository(pool);
    const options = {
      now: '2026-08-29T12:00:00.000Z',
      passwordHash: null,
      matchedMfaStep: 99,
      expectedSessionGeneration: 7,
      audit: (client) => client.query(
        'INSERT INTO audit_logs (tenant_id, action) VALUES ($1, $2)',
        ['ten_1', 'auth.password_login.succeeded'],
      ),
    };
    const results = await Promise.all([
      repository.completeLogin('ten_1', 'usr_1', options),
      repository.completeLogin('ten_1', 'usr_1', options),
    ]);
    assert.equal(results.filter(Boolean).length, 1);
    const casSql = pool.clients
      .flatMap((client) => client.queries)
      .map((query) => compact(query.text))
      .find((sql) => /mfa_last_step = CASE/.test(sql));
    assert.match(casSql, /session_generation = \$6::bigint/);
    assert.match(casSql, /mfa_last_step IS NULL OR mfa_last_step < \$5::bigint/);
    const winner = pool.clients.find((client) => client.queries.some((query) => /INSERT INTO audit_logs/.test(query.text)));
    assert.ok(winner);
    assert.equal(compact(winner.queries[0].text), 'BEGIN');
    assert.equal(compact(winner.queries.at(-1).text), 'COMMIT');
  });

  it('rotates generation and recovery credentials atomically when login rehashes a password', async () => {
    const pool = createRecordingPool((text) => {
      if (/UPDATE user_credentials/.test(text) && /mfa_last_step = CASE/.test(text)) {
        return {
          rows: [{
            user_id: 'usr_1',
            tenant_id: 'ten_1',
            password_hash: 'scrypt$replacement',
            session_generation: 8,
            failed_attempts: 0,
          }],
          rowCount: 1,
        };
      }
      return { rows: [], rowCount: 1 };
    });
    const result = await createPasswordAuthRepository(pool).completeLogin('ten_1', 'usr_1', {
      now: '2026-08-29T12:00:00.000Z',
      passwordHash: 'scrypt$replacement',
      matchedMfaStep: null,
      expectedSessionGeneration: 7,
      audit: (client) => client.query(
        'INSERT INTO audit_logs (tenant_id, action) VALUES ($1, $2)',
        ['ten_1', 'auth.password_login.succeeded'],
      ),
    });
    assert.equal(result.session_generation, 8);
    const statements = pool.clients[0].queries.map((query) => compact(query.text));
    const update = statements.find((sql) => /mfa_last_step = CASE/.test(sql));
    assert.match(update, /session_generation = CASE WHEN \$4::text IS NULL THEN session_generation ELSE session_generation \+ 1 END/);
    assert.ok(statements.some((sql) => /UPDATE user_password_resets SET consumed_at/.test(sql)));
    assert.ok(statements.some((sql) => /UPDATE user_password_invites SET consumed_at/.test(sql)));
    assert.ok(statements.findIndex((sql) => /INSERT INTO audit_logs/.test(sql)) > 0);
    assert.equal(statements.at(-1), 'COMMIT');
  });

  it('uses a null-state CAS so concurrent MFA enrollment cannot overwrite a pending envelope', async () => {
    let available = true;
    const pool = createRecordingPool((text) => {
      if (/SET mfa_secret_envelope/.test(text)) {
        if (!available) return { rows: [], rowCount: 0 };
        available = false;
        return {
          rows: [{
            user_id: 'usr_1',
            tenant_id: 'ten_1',
            password_hash: 'scrypt$encoded',
            session_generation: 1,
            mfa_secret_envelope: { version: 1, algorithm: 'AES-256-GCM' },
            mfa_enrollment_id: 'mfa_first',
            mfa_pending_at: '2026-08-29T12:00:00.000Z',
          }],
          rowCount: 1,
        };
      }
      return { rows: [], rowCount: 1 };
    });
    const repository = createPasswordAuthRepository(pool);
    const options = {
      mfaSecretEnvelope: { version: 1, algorithm: 'AES-256-GCM' },
      mfaEnrollmentId: 'mfa_first',
      now: '2026-08-29T12:00:00.000Z',
    };
    const results = await Promise.all([
      repository.beginMfaEnrollment('ten_1', 'usr_1', options),
      repository.beginMfaEnrollment('ten_1', 'usr_1', options),
    ]);
    assert.equal(results.filter(Boolean).length, 1);
    const sql = compact(pool.clients[0].queries.find((query) => /SET mfa_secret_envelope/.test(query.text)).text);
    assert.match(sql, /mfa_secret_envelope IS NULL/);
    assert.match(sql, /mfa_enrollment_id IS NULL/);
    assert.match(sql, /mfa_enrolled_at IS NULL/);
    assert.match(sql, /mfa_pending_at IS NULL/);
  });

  it('rolls back reset creation and audit when durable enqueue fails', async () => {
    const pool = createRecordingPool((text) => {
      if (/INSERT INTO user_password_resets/.test(text)) {
        return { rows: [{
          id: 'pwr_enqueue',
          tenant_id: 'ten_1',
          user_id: 'usr_1',
          token_hash: 'b'.repeat(64),
          expires_at: '2026-09-01T00:00:00.000Z',
          consumed_at: null,
          created_at: '2026-08-29T12:00:00.000Z',
        }], rowCount: 1 };
      }
      if (/FROM audit_logs/.test(text)) return { rows: [] };
      return { rows: [], rowCount: 1 };
    });
    await assert.rejects(
      () => createPasswordAuthRepository(pool).createPasswordReset(
        {
          id: 'pwr_enqueue',
          tenant_id: 'ten_1',
          user_id: 'usr_1',
          token_hash: 'b'.repeat(64),
          expires_at: '2026-09-01T00:00:00.000Z',
          consumed_at: null,
          created_at: '2026-08-29T12:00:00.000Z',
        },
        {
          audit: (client) => client.query(
            'INSERT INTO audit_logs (tenant_id, action) VALUES ($1, $2)',
            ['ten_1', 'auth.password.reset_requested'],
          ),
          enqueue: async ({ client }) => {
            assert.equal(client, pool.clients[0]);
            throw new Error('queue unavailable');
          },
        },
      ),
      /queue unavailable/,
    );
    const statements = pool.clients[0].queries.map((query) => compact(query.text));
    assert.ok(statements.some((sql) => /INSERT INTO user_password_resets/.test(sql)));
    assert.ok(statements.some((sql) => /INSERT INTO audit_logs/.test(sql)));
    assert.equal(statements.at(-1), 'ROLLBACK');
  });
  it('revokes recovery credentials and audits completed MFA enable/disable atomically', async () => {
    for (const operation of ['confirmMfaEnrollment', 'disableMfa']) {
      const pool = createRecordingPool((text) => {
        if (/SET mfa_enrolled_at/.test(text) || /SET mfa_secret_envelope = NULL/.test(text)) {
          return {
            rows: [{
              user_id: 'usr_1',
              tenant_id: 'ten_1',
              password_hash: 'scrypt$encoded',
              session_generation: 8,
              mfa_secret_envelope: operation === 'confirmMfaEnrollment' ? { version: 1 } : null,
              mfa_enrollment_id: operation === 'confirmMfaEnrollment' ? 'mfa_1' : null,
              mfa_enrolled_at: operation === 'confirmMfaEnrollment'
                ? '2026-08-29T12:00:00.000Z'
                : null,
              mfa_last_step: operation === 'confirmMfaEnrollment' ? 99 : null,
            }],
            rowCount: 1,
          };
        }
        return { rows: [], rowCount: 1 };
      });
      const repository = createPasswordAuthRepository(pool);
      const options = {
        mfaEnrollmentId: 'mfa_1',
        matchedStep: 99,
        now: '2026-08-29T12:00:00.000Z',
        audit: (client) => client.query(
          'INSERT INTO audit_logs (tenant_id, action) VALUES ($1, $2)',
          ['ten_1', `auth.mfa.${operation}`],
        ),
      };
      const result = await repository[operation]('ten_1', 'usr_1', options);
      assert.ok(result, operation);
      const statements = pool.clients[0].queries.map((query) => compact(query.text));
      assert.ok(statements.some((sql) => /UPDATE user_password_resets SET consumed_at/.test(sql)));
      assert.ok(statements.some((sql) => /UPDATE user_password_invites SET consumed_at/.test(sql)));
      assert.ok(statements.some((sql) => /INSERT INTO audit_logs/.test(sql)));
      assert.equal(statements.at(-1), 'COMMIT');
    }
  });

  it('changes the password, revokes generation, invalidates all reset/invite rows, and audits in one transaction', async () => {
    const pool = createRecordingPool((text) => {
      if (/FROM user_password_resets/.test(text) && /FOR UPDATE/.test(text)) {
        return { rows: [{
          id: 'pwr_1',
          tenant_id: 'ten_1',
          user_id: 'usr_1',
          expires_at: '2026-09-01T00:00:00.000Z',
          consumed_at: null,
        }] };
      }
      if (/FROM users/.test(text) && /FOR UPDATE/.test(text)) {
        return { rows: [{
          id: 'usr_1',
          tenant_id: 'ten_1',
          email: 'person@example.test',
          role: 'admin',
          status: 'active',
        }] };
      }
      if (/UPDATE user_credentials/.test(text)) {
        return { rows: [{ session_generation: 8 }], rowCount: 1 };
      }
      if (/FROM audit_logs/.test(text)) return { rows: [] };
      return { rows: [], rowCount: 1 };
    });
    const result = await createPasswordAuthRepository(pool).consumePasswordReset(
      { id: 'pwr_1', tenant_id: 'ten_1', user_id: 'usr_1' },
      {
        passwordHash: 'scrypt$replacement',
        tokenHash: 'a'.repeat(64),
        now: '2026-08-29T12:00:00.000Z',
        expectedSessionGeneration: 7,
        matchedMfaStep: 99,
        mfaEnrollmentId: 'mfa_1',
        audit: (client) => client.query(
          'INSERT INTO audit_logs (tenant_id, action) VALUES ($1, $2)',
          ['ten_1', 'auth.password.reset_completed'],
        ),
      },
    );
    assert.equal(result.session_generation, 8);
    const statements = pool.clients[0].queries.map((query) => compact(query.text));
    assert.ok(statements.some((sql) => /session_generation = session_generation \+ 1/.test(sql)));
    const credentialCas = statements.find((sql) => /UPDATE user_credentials/.test(sql));
    assert.match(credentialCas, /session_generation = \$5::bigint/);
    assert.match(credentialCas, /mfa_enrollment_id = \$7/);
    assert.match(credentialCas, /mfa_last_step IS NULL OR mfa_last_step < \$6::bigint/);
    assert.ok(statements.some((sql) => /UPDATE user_password_resets SET consumed_at/.test(sql) && /user_id = \$2/.test(sql)));
    assert.ok(statements.some((sql) => /UPDATE user_password_invites SET consumed_at/.test(sql) && /user_id = \$2/.test(sql)));
    const auditIndex = statements.findIndex((sql) => /INSERT INTO audit_logs/.test(sql));
    assert.ok(auditIndex > 0);
    assert.equal(statements.at(-1), 'COMMIT');
  });
});

describe('password auth schema hardening', () => {
  it('contains only envelope MFA storage and a positive session generation', () => {
    const schema = readFileSync(path.join(ROOT, 'db/schema.sql'), 'utf8');
    const migration = readFileSync(
      path.join(ROOT, 'db/migrations/0043_password_resets_and_mfa.sql'),
      'utf8',
    );
    for (const sql of [schema, migration]) {
      assert.match(sql, /mfa_secret_envelope\s+JSONB/);
      assert.match(sql, /session_generation\s+BIGINT\s+NOT NULL\s+DEFAULT 1/);
      assert.doesNotMatch(sql, /^\s*mfa_secret\s+TEXT/m);
    }
    assert.match(migration, /DROP COLUMN IF EXISTS mfa_secret/);
    assert.match(migration, /WHERE mfa_secret IS NOT NULL/);
    assert.match(migration, /SET must_change = TRUE,[\s\S]*?session_generation = session_generation \+ 1/);
    assert.match(migration, /mfa_enrollment_id = NULL/);
    for (const sql of [schema, migration]) {
      assert.match(sql, /mfa_enrolled_at IS NOT NULL[\s\S]*?mfa_last_step IS NOT NULL[\s\S]*?mfa_last_step >= 0/);
      assert.match(sql, /ALTER TABLE user_password_resets FORCE ROW LEVEL SECURITY/);
      assert.match(sql, /user_password_resets_token_lookup/);
    }
    assert.match(schema, /CREATE UNIQUE INDEX idx_user_password_resets_token_hash/);
  });
});
