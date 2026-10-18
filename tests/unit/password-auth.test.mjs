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
  validatePasswordSession,
} from '../../src/services/passwordAuth.mjs';
import { createDevPasswordAuthRepository } from '../../src/services/passwordAuthRepository.mjs';
import { getStore, resetStoreForTests } from '../../src/store.mjs';

const PASSWORD = 'N7!vR2#qL9@z';
const SESSION_SECRET = 'password-auth-test-session-secret-32-chars';
const PASSWORD_HASH = await hashPassword(PASSWORD);
const OTHER_PASSWORD_HASH = await hashPassword('Other!Pass7#Kq');
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

const INVALID_CREDENTIALS = Object.freeze({
  error: 'invalid_credentials',
  status: 401,
  message: 'Email or password is incorrect.',
});

function multiTenantSeed({ matching = [] } = {}) {
  const tenantIds = ['ten_a', 'ten_b', 'ten_c'];
  return {
    tenants: tenantIds.map((id) => ({ id, name: `Tenant ${id.slice(-1).toUpperCase()} Corp` })),
    users: tenantIds.map((id) => user({ id: `usr_${id.slice(-1)}`, tenant_id: id, email: 'shared@example.com' })),
    credentials: tenantIds.map((id) => credential({
      user_id: `usr_${id.slice(-1)}`,
      tenant_id: id,
      password_hash: matching.includes(id) ? PASSWORD_HASH : OTHER_PASSWORD_HASH,
    })),
  };
}

function seed({ users = [user()], credentials = [credential()], invites = [], tenants = [] } = {}) {
  resetStoreForTests({
    tenants,
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

  it('reports invitation state only after the password is correct', async () => {
    let repository = seed({ users: [user({ status: 'invited' })], credentials: [] });
    const noCredential = await loginWithPassword(
      { email: 'engineer@example.com', password: PASSWORD },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'invited', now: NOW },
    );
    assert.deepEqual(noCredential, INVALID_CREDENTIALS);

    resetPasswordAuthRateLimitsForTests();
    repository = seed({ users: [user({ status: 'invited' })] });
    const correct = await loginWithPassword(
      { email: 'engineer@example.com', password: PASSWORD },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'invited-correct', now: NOW },
    );
    assert.equal(correct.error, 'password_setup_required');
    assert.equal(correct.status, 403);
  });

  it('returns an identical 401 body for every wrong-password and unknown-account shape', async () => {
    const attempts = [
      [{ users: [user()] }, { email: 'engineer@example.com', password: 'WrongPass9!Zz' }],
      [{ users: [user()] }, { email: 'nobody@example.com', password: PASSWORD }],
      [{ users: [user({ status: 'invited' })], credentials: [] }, { email: 'engineer@example.com', password: PASSWORD }],
      [{ users: [user({ status: 'invited' })] }, { email: 'engineer@example.com', password: 'WrongPass9!Zz' }],
      [{ users: [user({ status: 'disabled' })] }, { email: 'engineer@example.com', password: 'WrongPass9!Zz' }],
      [multiTenantSeed(), { email: 'shared@example.com', password: 'WrongPass9!Zz' }],
    ];
    const results = [];
    for (const [seedOptions, body] of attempts) {
      resetPasswordAuthRateLimitsForTests();
      const repository = seed(seedOptions);
      results.push(await loginWithPassword(body, {
        repository,
        runtimeConfig: RUNTIME_CONFIG,
        clientKey: `parity-${results.length}`,
        now: NOW,
      }));
    }
    for (const result of results) assert.deepEqual(result, INVALID_CREDENTIALS);
    assert.ok(results.every((result) => !Object.hasOwn(result, 'workspaces')));
  });

  it('signs a multi-workspace email straight in when the password matches one workspace', async () => {
    const repository = seed(multiTenantSeed({ matching: ['ten_b'] }));
    const result = await loginWithPassword(
      { email: 'shared@example.com', password: PASSWORD },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'multi-one', now: NOW },
    );
    assert.equal(result.error, undefined);
    assert.equal(result.tenant_id, 'ten_b');
    assert.equal(result.user_id, 'usr_b');
  });

  it('asks for a workspace and lists only the workspaces whose password matched', async () => {
    const repository = seed(multiTenantSeed({ matching: ['ten_a', 'ten_c'] }));
    const result = await loginWithPassword(
      { email: 'shared@example.com', password: PASSWORD },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'multi-two', now: NOW },
    );
    assert.equal(result.error, 'tenant_required');
    assert.equal(result.status, 400);
    assert.deepEqual(result.workspaces, [
      { tenant_id: 'ten_a', name: 'Tenant A Corp' },
      { tenant_id: 'ten_c', name: 'Tenant C Corp' },
    ]);

    resetPasswordAuthRateLimitsForTests();
    const chosen = await loginWithPassword(
      { email: 'shared@example.com', password: PASSWORD, tenant_id: 'ten_c' },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'multi-chosen', now: NOW },
    );
    assert.equal(chosen.tenant_id, 'ten_c');
  });

  it('records a failure against every workspace credential when a multi-workspace password is wrong', async () => {
    const repository = seed(multiTenantSeed());
    const result = await loginWithPassword(
      { email: 'shared@example.com', password: 'WrongPass9!Zz' },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'multi-wrong', now: NOW },
    );
    assert.deepEqual(result, INVALID_CREDENTIALS);
    assert.deepEqual(getStore().userCredentials.map((row) => row.failed_attempts), [1, 1, 1]);
  });

  it('withholds the workspace list when a matching workspace still requires MFA', async () => {
    const repository = seed(multiTenantSeed({ matching: ['ten_a', 'ten_c'] }));
    getStore().userCredentials[2].mfa_enrolled_at = NOW.toISOString();
    const result = await loginWithPassword(
      { email: 'shared@example.com', password: PASSWORD },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'multi-mfa', now: NOW },
    );
    assert.equal(result.error, 'tenant_required');
    assert.equal(result.status, 400);
    assert.equal(Object.hasOwn(result, 'workspaces'), false);
  });

  it('rate limits repeated attempts by normalized email', async (t) => {
    let limiterNow = Math.floor(NOW.getTime() / 60_000) * 60_000 + 1_000;
    t.mock.method(Date, 'now', () => limiterNow);
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
    limiterNow += 60_000;
    const nextWindow = await loginWithPassword(
      { email: 'UNKNOWN@example.com', password: PASSWORD },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'rate-7', now: NOW },
    );
    assert.deepEqual(nextWindow, INVALID_CREDENTIALS);
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

  it('exempts demo accounts from lockout and rate limits, and allows OCR/alias variations', async () => {
    const demoUser = {
      id: 'usr_admin',
      tenant_id: 'Astra-D1TrtI4HMTSrwKRW-9',
      email: 'admin@demo.astranull.local',
      name: 'Demo Admin',
      role: 'admin',
      status: 'active',
    };
    const demoCredential = {
      user_id: 'usr_admin',
      tenant_id: 'Astra-D1TrtI4HMTSrwKRW-9',
      password_hash: await hashPassword('Astra-D1TrtI4HMTSrwKRW-9'),
      password_updated_at: NOW.toISOString(),
      must_change: false,
      failed_attempts: 10,
      locked_until: new Date(NOW.getTime() + 60 * 60 * 1000).toISOString(),
      last_login_at: null,
      created_at: NOW.toISOString(),
    };
    const repository = seed({ users: [demoUser], credentials: [demoCredential] });

    // 1. Logs in despite locked_until being set
    const res1 = await loginWithPassword(
      { email: 'admin@demo.astranull.local', password: 'Astra-D1TrtI4HMTSrwKRW-9' },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'demo-1', now: NOW },
    );
    assert.equal(res1.error, undefined);
    assert.equal(res1.tenant_id, 'Astra-D1TrtI4HMTSrwKRW-9');
    assert.ok(res1.access_token);

    // 2. OCR typo (lowercase l instead of uppercase I at pos 11) works
    const res2 = await loginWithPassword(
      { email: 'admin@demo.astranull.local', password: 'Astra-D1Trtl4HMTSrwKRW-9' },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'demo-2', now: NOW },
    );
    assert.equal(res2.error, undefined);
    assert.equal(res2.tenant_id, 'Astra-D1TrtI4HMTSrwKRW-9');

    // 3. Email alias (admin@astranull.site) and user: / pass: prefixes work
    const res3 = await loginWithPassword(
      { email: 'user: admin@astranull.site', password: 'pass: Astra-D1TrtI4HMTSrwKRW-9' },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'demo-3', now: NOW },
    );
    assert.equal(res3.error, undefined);
    assert.equal(res3.tenant_id, 'Astra-D1TrtI4HMTSrwKRW-9');
  });

  it('never accepts or repairs the public demo password for a partial demo identity', async () => {
    for (const overrides of [
      { email: 'admin@demo.astranull.local', tenant_id: 'ten_customer' },
      { email: 'owner@example.com', tenant_id: 'Astra-D1TrtI4HMTSrwKRW-9' },
      { id: 'admin@demo.astranull.local', email: 'owner@example.com', tenant_id: 'ten_customer' },
    ]) {
      const account = user(overrides);
      const repository = seed({ users: [account], credentials: [credential({ user_id: account.id, tenant_id: account.tenant_id })] });
      const result = await loginWithPassword({ email: account.email, tenant_id: account.tenant_id, password: 'Astra-D1TrtI4HMTSrwKRW-9' },
        { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: account.email, now: NOW });
      assert.deepEqual(result, INVALID_CREDENTIALS);
      assert.equal(getStore().userCredentials[0].password_hash, PASSWORD_HASH);
    }
  });

  it('preserves lockout, password-change and MFA requirements for partial demo identities', async () => {
    for (const identity of [
      { email: 'admin@demo.astranull.local', tenant_id: 'ten_customer' },
      { email: 'owner@example.com', tenant_id: 'Astra-D1TrtI4HMTSrwKRW-9' },
      { id: 'admin@demo.astranull.local', email: 'owner@example.com', tenant_id: 'ten_customer' },
    ]) {
      for (const [state, error] of [
        [{ locked_until: new Date(NOW.getTime() + 60_000).toISOString() }, 'account_locked'],
        [{ must_change: true }, 'password_change_required'],
        [{ mfa_enrolled_at: NOW.toISOString() }, 'password_login_unavailable'],
      ]) {
        resetPasswordAuthRateLimitsForTests();
        const account = user(identity);
        const repository = seed({ users: [account], credentials: [credential({ user_id: account.id, tenant_id: account.tenant_id, ...state })] });
        const result = await loginWithPassword({ email: account.email, tenant_id: account.tenant_id, password: PASSWORD },
          { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: account.email, now: NOW });
        assert.equal(result.error, error);
        assert.equal(result.access_token, undefined);
      }
    }
  });

  it('rejects rate-limited ordinary clients before querying accounts', async (t) => {
    t.mock.method(Date, 'now', () => NOW.getTime());
    let lookups = 0;
    const repository = { findUsersByEmail: async () => { lookups += 1; return []; } };
    for (let index = 0; index < 10; index += 1) {
      const result = await loginWithPassword({ email: `unknown-${index}@example.com`, password: PASSWORD },
        { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'limited-client', now: NOW });
      assert.deepEqual(result, INVALID_CREDENTIALS);
    }
    const result = await loginWithPassword({ email: 'another@example.com', password: PASSWORD },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey: 'limited-client', now: NOW });
    assert.equal(result.error, 'rate_limited');
    assert.equal(lookups, 10);
  });

  it('keeps existing demo sessions valid when other visitors sign in with password variants', async () => {
    const demoTenant = 'Astra-D1TrtI4HMTSrwKRW-9';
    const repository = seed({
      users: [{ id: 'usr_admin', tenant_id: demoTenant, email: 'admin@demo.astranull.local', name: 'Demo Admin', role: 'admin', status: 'active' }],
      credentials: [{
        user_id: 'usr_admin',
        tenant_id: demoTenant,
        password_hash: await hashPassword('Astra-D1TrtI4HMTSrwKRW-9'),
        password_updated_at: NOW.toISOString(),
        must_change: false,
        failed_attempts: 0,
        locked_until: null,
        last_login_at: null,
        session_generation: 1,
        created_at: NOW.toISOString(),
      }],
    });
    const login = (password, clientKey) => loginWithPassword(
      { email: 'admin@demo.astranull.local', password },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey, now: NOW },
    );
    const generationOf = (token) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')).session_generation;

    const first = await login('Astra-D1TrtI4HMTSrwKRW-9', 'demo-a');
    for (const [index, variant] of [' Astra-D1TrtI4HMTSrwKRW-9 ', 'astra-d1trti4hmtsrwkrw-9', 'Astra-DlTrtl4HMTSrwKRW-9', 'password: Astra-D1TrtI4HMTSrwKRW-9'].entries()) {
      const other = await login(variant, `demo-b-${index}`);
      assert.equal(other.error, undefined);
      assert.equal(generationOf(other.access_token), generationOf(first.access_token));
    }
    const state = await validatePasswordSession(
      { tenantId: demoTenant, userId: 'usr_admin', sessionGeneration: generationOf(first.access_token) },
      { repository },
    );
    assert.equal(state.valid, true);
    assert.equal(getStore().userCredentials[0].session_generation, 1);
  });

  it('repairs a stale demo password hash to the canonical password exactly once', async () => {
    const demoTenant = 'Astra-D1TrtI4HMTSrwKRW-9';
    const repository = seed({
      users: [{ id: 'usr_admin', tenant_id: demoTenant, email: 'admin@demo.astranull.local', name: 'Demo Admin', role: 'admin', status: 'active' }],
      credentials: [{
        user_id: 'usr_admin',
        tenant_id: demoTenant,
        password_hash: await hashPassword(' astra-d1trti4hmtsrwkrw-9'),
        password_updated_at: NOW.toISOString(),
        must_change: false,
        failed_attempts: 0,
        locked_until: null,
        last_login_at: null,
        session_generation: 3,
        created_at: NOW.toISOString(),
      }],
    });
    const login = (password, clientKey) => loginWithPassword(
      { email: 'admin@demo.astranull.local', password },
      { repository, runtimeConfig: RUNTIME_CONFIG, clientKey, now: NOW },
    );

    assert.equal((await login('Astra-D1TrtI4HMTSrwKRW-9', 'demo-r1')).error, undefined);
    assert.equal(getStore().userCredentials[0].session_generation, 4);
    assert.equal((await login('Astra-D1TrtI4HMTSrwKRW-9', 'demo-r2')).error, undefined);
    assert.equal((await login('astra-d1trti4hmtsrwkrw-9', 'demo-r3')).error, undefined);
    assert.equal(getStore().userCredentials[0].session_generation, 4);
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
