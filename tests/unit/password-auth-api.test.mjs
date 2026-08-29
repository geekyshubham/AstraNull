import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { createServer } from '../../src/server.mjs';
import { resetStoreForTests } from '../../src/store.mjs';
import { closeServer, request } from '../helpers/http.mjs';

const SESSION_SECRET = 'password-api-test-session-secret-32-chars';
let server;

afterEach(async () => {
  await closeServer(server);
  server = null;
});

async function listen(passwordAuth, overrides = {}) {
  resetStoreForTests({
    tenants: [{ id: 'ten_route', name: 'Route Tenant' }],
    users: [],
    auditLog: [],
  });
  const env = {
    ...process.env,
    NODE_ENV: 'test',
    ASTRANULL_AUTH_MODE: 'signed-session',
    ASTRANULL_SESSION_SECRET: SESSION_SECRET,
    ASTRANULL_NO_PERSIST: '1',
    ASTRANULL_PASSWORD_LOGIN_ENABLED: '1',
  };
  const runtimeConfig = { ...loadRuntimeConfig(env), ...overrides };
  server = createServer({ env, runtimeConfig, services: { passwordAuth } });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  return `http://127.0.0.1:${address.port}`;
}

describe('password auth API', () => {
  it('publishes password_login_enabled and dispatches login without echoing the password', async () => {
    let received;
    const baseUrl = await listen({
      async loginWithPassword(body, options) {
        received = { body, options };
        return {
          access_token: 'safe-token',
          token_type: 'Bearer',
          expires_in: 3600,
          principal: 'customer',
          tenant_id: 'ten_route',
          user_id: 'usr_route',
          role: 'viewer',
        };
      },
      async setPasswordWithInvite() {
        throw new Error('not used');
      },
    });

    const config = await request(baseUrl, 'GET', '/v1/public/site-config');
    assert.equal(config.status, 200);
    assert.equal(config.json.password_login_enabled, true);

    const response = await request(baseUrl, 'POST', '/v1/auth/login', {
      body: { email: 'person@example.com', password: 'DoNotEcho9!Xy' },
    });
    assert.equal(response.status, 200);
    assert.equal(response.json.role, 'viewer');
    assert.equal(JSON.stringify(response.json).includes('DoNotEcho9!Xy'), false);
    assert.equal(received.body.password, 'DoNotEcho9!Xy');
    assert.match(received.options.clientKey, /^ip:/);
  });

  it('maps lockout and rate-limit errors to Retry-After responses', async () => {
    let mode = 'locked';
    const baseUrl = await listen({
      async loginWithPassword() {
        return mode === 'locked'
          ? {
              error: 'account_locked',
              status: 423,
              message: 'The account is temporarily locked. Try again later.',
              retry_after_seconds: 900,
            }
          : {
              error: 'rate_limited',
              status: 429,
              message: 'Too many authentication attempts. Try again later.',
              retry_after_seconds: 60,
            };
      },
      async setPasswordWithInvite() {
        throw new Error('not used');
      },
    });

    const locked = await request(baseUrl, 'POST', '/v1/auth/login', {
      body: { email: 'person@example.com', password: 'DoNotEcho9!Xy' },
    });
    assert.equal(locked.status, 423);
    assert.equal(locked.headers['retry-after'], '900');
    assert.equal(locked.json.status, undefined);

    mode = 'limited';
    const limited = await request(baseUrl, 'POST', '/v1/auth/login', {
      body: { email: 'person@example.com', password: 'DoNotEcho9!Xy' },
    });
    assert.equal(limited.status, 429);
    assert.equal(limited.headers['retry-after'], '60');
  });

  it('dispatches one-time password setup and preserves its status field', async () => {
    const baseUrl = await listen({
      async loginWithPassword() {
        throw new Error('not used');
      },
      async setPasswordWithInvite(body) {
        assert.equal(body.token, 'pwi_once');
        assert.equal(body.password, 'DoNotEcho9!Xy');
        return {
          status: 'password_set',
          tenant_id: 'ten_route',
          user_id: 'usr_route',
          email: 'person@example.com',
        };
      },
    });
    const response = await request(baseUrl, 'POST', '/v1/auth/set-password', {
      body: { token: 'pwi_once', password: 'DoNotEcho9!Xy' },
    });
    assert.equal(response.status, 200);
    assert.equal(response.json.status, 'password_set');
    assert.equal(JSON.stringify(response.json).includes('DoNotEcho9!Xy'), false);
  });

  it('returns bounded JSON body errors before calling password services', async () => {
    const baseUrl = await listen({
      async loginWithPassword() {
        throw new Error('must not be called');
      },
      async setPasswordWithInvite() {
        throw new Error('must not be called');
      },
    }, { maxJsonBodyBytes: 32 });

    const malformed = await request(baseUrl, 'POST', '/v1/auth/login', { rawBody: '{' });
    assert.equal(malformed.status, 400);
    assert.deepEqual(malformed.json, { error: 'invalid_json' });

    const oversized = await request(baseUrl, 'POST', '/v1/auth/set-password', {
      rawBody: 'x'.repeat(33),
    });
    assert.equal(oversized.status, 413);
    assert.deepEqual(oversized.json, { error: 'payload_too_large' });
  });

  it('fails closed when the feature or injected service is unavailable', async () => {
    let baseUrl = await listen({}, { passwordLoginEnabled: false });
    const disabled = await request(baseUrl, 'POST', '/v1/auth/login', {
      body: { email: 'person@example.com', password: 'DoNotEcho9!Xy' },
    });
    assert.equal(disabled.status, 403);
    assert.equal(disabled.json.error, 'password_login_disabled');
    const disabledSetup = await request(baseUrl, 'POST', '/v1/auth/set-password', {
      body: { token: 'pwi_once', password: 'DoNotEcho9!Xy' },
    });
    assert.equal(disabledSetup.status, 403);
    assert.equal(disabledSetup.json.error, 'password_login_disabled');
    await closeServer(server);
    server = null;

    baseUrl = await listen({});
    const unavailable = await request(baseUrl, 'POST', '/v1/auth/login', {
      body: { email: 'person@example.com', password: 'DoNotEcho9!Xy' },
    });
    assert.equal(unavailable.status, 503);
    assert.equal(unavailable.json.error, 'password_login_unavailable');
    const unavailableSetup = await request(baseUrl, 'POST', '/v1/auth/set-password', {
      body: { token: 'pwi_once', password: 'DoNotEcho9!Xy' },
    });
    assert.equal(unavailableSetup.status, 503);
    assert.equal(unavailableSetup.json.error, 'password_login_unavailable');
  });
});
