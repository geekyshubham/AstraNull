import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import { verifySignedSessionToken } from '../../src/context.mjs';
import { hashPassword } from '../../src/lib/password.mjs';
import {
  issuePasswordInvite,
  loginWithPassword,
  resetPasswordAuthRateLimitsForTests,
  setPasswordWithInvite,
} from '../../src/services/passwordAuth.mjs';
import { createDevPasswordAuthRepository } from '../../src/services/passwordAuthRepository.mjs';
import { getStore, resetStoreForTests } from '../../src/store.mjs';

const PASSWORD = 'N7!vR2#qL9@z';
const SESSION_SECRET = 'password-auth-test-session-secret-32-chars';
const PASSWORD_HASH = await hashPassword(PASSWORD);
const RUNTIME_CONFIG = {
  authMode: 'signed-session',
  sessionSecret: SESSION_SECRET,
  passwordLoginEnabled: true,
  bundledStagingOidc: false,
};
const NOW = new Date();

function user(overrides = {}) {
  return {
    id: 'usr_login',
    tenant_id: 'ten_login',
    email: 'engineer@example.com',
    name: 'Portal Engineer',
    role: 'engineer',
    status: 'active',
    ...overrides,
  };
}

function credential(overrides = {}) {
  return {
    user_id: 'usr_login',
    tenant_id: 'ten_login',
    password_hash: PASSWORD_HASH,
    password_updated_at: NOW.toISOString(),
    must_change: false,
    failed_attempts: 0,
    locked_until: null,
    last_login_at: null,
    created_at: NOW.toISOString(),
    ...overrides,
  };
}

function seed({ users = [user()], credentials = [credential()], invites = [] } = {}) {
  resetStoreForTests({
    users,
    userCredentials: credentials,
    userPasswordInvites: invites,
    auditLog: [],
  });
  return createDevPasswordAuthRepository();
}

beforeEach(() => {
  resetPasswordAuthRateLimitsForTests();
});

describe('password login', () => {
  it('mints a session with the stored user role and ignores a body-supplied role', async () => {
    const repository = seed();
    const result = await loginWithPassword(
      {
        email: '  ENGINEER@example.com ',
        password: PASSWORD,
        tenant_id: 'ten_login',
        role: 'owner',
      },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'success', now: NOW },
    );

    assert.equal(result.error, undefined);
    assert.equal(result.role, 'engineer');
    assert.equal(result.tenant_id, 'ten_login');
    const verified = verifySignedSessionToken(result.access_token, SESSION_SECRET);
    assert.deepEqual(verified, {
      tenantId: 'ten_login',
      userId: 'usr_login',
      role: 'engineer',
    });
    assert.equal(getStore().userCredentials[0].failed_attempts, 0);
    assert.equal(getStore().userCredentials[0].last_login_at, NOW.toISOString());
    assert.ok(getStore().auditLog.some((entry) => entry.action === 'auth.password_login.succeeded'));
    const auditJson = JSON.stringify(getStore().auditLog);
    assert.equal(auditJson.includes(PASSWORD), false);
    assert.equal(auditJson.includes(PASSWORD_HASH), false);
  });

  it('cannot use body role or tenant_id fields to escalate into another principal', async () => {
    const repository = seed();
    const wrongTenant = await loginWithPassword(
      {
        email: 'engineer@example.com',
        password: PASSWORD,
        tenant_id: 'ten_admin',
        role: 'owner',
      },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'wrong-tenant', now: NOW },
    );
    assert.deepEqual(wrongTenant, {
      error: 'invalid_credentials',
      status: 401,
      message: 'Email or password is incorrect.',
    });
  });

  it('returns identical errors for unknown users, active users without credentials, and bad passwords', async () => {
    let repository = seed();
    const unknown = await loginWithPassword(
      { email: 'unknown@example.com', password: PASSWORD },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'unknown', now: NOW },
    );
    const wrong = await loginWithPassword(
      { email: 'engineer@example.com', password: 'WrongPass9!Zz' },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'wrong', now: NOW },
    );
    assert.ok(getStore().auditLog.some((entry) => entry.action === 'auth.password_login.failed'));
    assert.equal(JSON.stringify(getStore().auditLog).includes('WrongPass9!Zz'), false);

    resetPasswordAuthRateLimitsForTests();
    repository = seed({ credentials: [] });
    const missing = await loginWithPassword(
      { email: 'engineer@example.com', password: PASSWORD },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'missing', now: NOW },
    );
    assert.deepEqual(unknown, wrong);
    assert.deepEqual(unknown, missing);
  });

  it('locks on the fifth consecutive failure and returns 423 without verifying while locked', async () => {
    const repository = seed();
    for (let attempt = 1; attempt <= 4; attempt += 1) {
      const result = await loginWithPassword(
        { email: 'engineer@example.com', password: 'WrongPass9!Zz' },
        { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: `lock-${attempt}`, now: NOW },
      );
      assert.equal(result.status, 401, `attempt ${attempt}`);
    }
    const fifth = await loginWithPassword(
      { email: 'engineer@example.com', password: 'WrongPass9!Zz' },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'lock-5', now: NOW },
    );
    assert.equal(fifth.error, 'account_locked');
    assert.equal(fifth.status, 423);
    assert.equal(fifth.retry_after_seconds, 900);
    assert.equal(getStore().userCredentials[0].failed_attempts, 5);
    assert.ok(getStore().auditLog.some((entry) => entry.action === 'auth.password_login.locked'));

    const locked = await loginWithPassword(
      { email: 'engineer@example.com', password: PASSWORD },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'lock-6', now: NOW },
    );
    assert.equal(locked.error, 'account_locked');
    assert.equal(locked.status, 423);
  });

  it('returns explicit lifecycle statuses and fails closed without a session minter', async () => {
    let repository = seed({ users: [user({ status: 'disabled' })] });
    const disabled = await loginWithPassword(
      { email: 'engineer@example.com', password: PASSWORD },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'disabled', now: NOW },
    );
    assert.equal(disabled.error, 'account_disabled');
    assert.equal(disabled.status, 403);

    repository = seed({ credentials: [credential({ must_change: true })] });
    const mustChange = await loginWithPassword(
      { email: 'engineer@example.com', password: PASSWORD },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'must-change', now: NOW },
    );
    assert.equal(mustChange.error, 'password_change_required');
    assert.equal(mustChange.status, 403);

    repository = seed();
    const unavailable = await loginWithPassword(
      { email: 'engineer@example.com', password: PASSWORD },
      {
        repository,
        runtimeConfig: { ...RUNTIME_CONFIG, authMode: 'dev-headers' },
        clientKey: 'no-minter',
        now: NOW,
      },
    );
    assert.equal(unavailable.error, 'password_login_unavailable');
    assert.equal(unavailable.status, 503);
  });

  it('requires password setup for invited users', async () => {
    const repository = seed({ users: [user({ status: 'invited' })], credentials: [] });
    const result = await loginWithPassword(
      { email: 'engineer@example.com', password: PASSWORD },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'invited', now: NOW },
    );
    assert.equal(result.error, 'password_setup_required');
    assert.equal(result.status, 403);
  });

  it('rate limits repeated attempts by normalized email', async () => {
    const repository = seed();
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const result = await loginWithPassword(
        { email: 'unknown@example.com', password: PASSWORD },
        { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: `rate-${attempt}`, now: NOW },
      );
      assert.equal(result.status, 401);
    }
    const limited = await loginWithPassword(
      { email: 'UNKNOWN@example.com', password: PASSWORD },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'rate-6', now: NOW },
    );
    assert.equal(limited.error, 'rate_limited');
    assert.equal(limited.status, 429);
    assert.ok(limited.retry_after_seconds >= 1);
  });
  it('keeps credential attachment tenant-scoped even when dev data reuses a user id', async () => {
    resetStoreForTests({
      users: [
        user({ tenant_id: 'ten_a', email: 'shared@example.com' }),
        user({ tenant_id: 'ten_b', email: 'shared@example.com' }),
      ],
      userCredentials: [
        credential({ tenant_id: 'ten_a', password_hash: 'tenant-a-hash' }),
        credential({ tenant_id: 'ten_b', password_hash: 'tenant-b-hash' }),
      ],
      auditLog: [],
    });
    const rows = await createDevPasswordAuthRepository().findUsersByEmail(
      'shared@example.com',
      'ten_b',
    );
    assert.equal(rows.length, 1);
    assert.equal(rows[0].credential.password_hash, 'tenant-b-hash');
  });
});

describe('password invitations', () => {
  it('sets a password once, activates the user, and never audits secret material', async () => {
    const repository = seed({ users: [user({ status: 'invited' })], credentials: [] });
    const issued = await issuePasswordInvite(
      {
        tenantId: 'ten_login',
        userId: 'usr_login',
        createdBy: 'staff_support',
      },
      { repository, now: NOW },
    );
    assert.match(issued.token, /^pwi_[A-Za-z0-9_-]+$/);
    assert.equal(getStore().userPasswordInvites[0].token, undefined);
    assert.notEqual(getStore().userPasswordInvites[0].token_hash, issued.token);

    const result = await setPasswordWithInvite(
      { token: issued.token, password: PASSWORD },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'set-happy', now: NOW },
    );
    assert.deepEqual(result, {
      status: 'password_set',
      tenant_id: 'ten_login',
      user_id: 'usr_login',
      email: 'engineer@example.com',
    });
    assert.equal(getStore().users[0].status, 'active');
    assert.equal(getStore().userCredentials[0].must_change, false);
    assert.equal(getStore().userCredentials[0].failed_attempts, 0);
    assert.equal(getStore().userPasswordInvites[0].consumed_at, NOW.toISOString());

    const replay = await setPasswordWithInvite(
      { token: issued.token, password: PASSWORD },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'set-replay', now: NOW },
    );
    assert.equal(replay.error, 'invalid_invite');
    assert.equal(replay.status, 401);

    const auditJson = JSON.stringify(getStore().auditLog);
    assert.equal(auditJson.includes(PASSWORD), false);
    assert.equal(auditJson.includes(issued.token), false);
    assert.equal(auditJson.includes(getStore().userCredentials[0].password_hash), false);
    assert.ok(getStore().auditLog.some((entry) => entry.action === 'auth.password.invite_issued'));
    assert.ok(getStore().auditLog.some((entry) => entry.action === 'auth.password.set'));
  });

  it('rejects expired invitations', async () => {
    const repository = seed({ users: [user({ status: 'invited' })], credentials: [] });
    const issued = await issuePasswordInvite(
      { tenantId: 'ten_login', userId: 'usr_login', createdBy: 'staff_support', ttlMs: 1000 },
      { repository, now: NOW },
    );
    const result = await setPasswordWithInvite(
      { token: issued.token, password: PASSWORD },
      {
        repository,
        runtimeConfig: RUNTIME_CONFIG,
        clientKey: 'set-expired',
        now: new Date(NOW.getTime() + 2000),
      },
    );
    assert.equal(result.error, 'invite_expired');
    assert.equal(result.status, 410);
    assert.equal(getStore().users[0].status, 'invited');
  });

  it('does not reactivate a disabled user with an outstanding invite', async () => {
    const repository = seed({ users: [user({ status: 'disabled' })], credentials: [] });
    const issued = await issuePasswordInvite(
      { tenantId: 'ten_login', userId: 'usr_login', createdBy: 'staff_support' },
      { repository, now: NOW },
    );
    const result = await setPasswordWithInvite(
      { token: issued.token, password: PASSWORD },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'set-disabled', now: NOW },
    );
    assert.equal(result.error, 'invalid_invite');
    assert.equal(result.status, 401);
    assert.equal(getStore().users[0].status, 'disabled');
    assert.equal(getStore().userPasswordInvites[0].consumed_at, null);
    assert.equal(getStore().userCredentials.length, 0);
  });

  it('rejects weak passwords without consuming the invitation', async () => {
    const repository = seed({ users: [user({ status: 'invited' })], credentials: [] });
    const issued = await issuePasswordInvite(
      { tenantId: 'ten_login', userId: 'usr_login', createdBy: 'staff_support' },
      { repository, now: NOW },
    );
    const result = await setPasswordWithInvite(
      { token: issued.token, password: 'Password123!' },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'set-weak', now: NOW },
    );
    assert.equal(result.error, 'weak_password');
    assert.equal(result.status, 400);
    assert.ok(result.failures.includes('common_password'));
    assert.equal(getStore().userPasswordInvites[0].consumed_at, null);
    assert.equal(getStore().users[0].status, 'invited');
  });
});
