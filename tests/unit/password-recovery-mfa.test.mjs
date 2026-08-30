import assert from 'node:assert/strict';
import { scrypt as scryptCallback } from 'node:crypto';
import { promisify } from 'node:util';
import { beforeEach, describe, it } from 'node:test';
import {
  base32Decode,
  base32Encode,
  buildOtpauthUri,
  computeTotpAtStep,
  generateTotpSecret,
  verifyTotp,
} from '../../src/lib/totp.mjs';
import {
  createPasswordAuthService,
  issuePasswordInvite,
  requestPasswordReset,
  resetPasswordWithToken,
  resetPasswordAuthRateLimitsForTests,
} from '../../src/services/passwordAuth.mjs';
import { createDevPasswordAuthRepository } from '../../src/services/passwordAuthRepository.mjs';
import { buildSecretAad, decryptSecret } from '../../src/lib/secrets.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';

const NOW = new Date('2026-08-29T12:00:00.000Z');
const SEED_PASSWORD = 'Correct-Horse-42!battery';
const NEXT_PASSWORD = 'Even-Better-Password-84!';
const SESSION_SECRET = 'password-recovery-mfa-test-session-secret';
const SECRET_ENCRYPTION_KEY = Buffer.from(Array.from({ length: 32 }, (_, index) => index + 1));
const LOGIN_RUNTIME_CONFIG = {
  authMode: 'signed-session',
  sessionSecret: SESSION_SECRET,
  passwordLoginEnabled: true,
  bundledStagingOidc: false,
  secretEncryptionKey: SECRET_ENCRYPTION_KEY,
};
const scrypt = promisify(scryptCallback);

async function legacyPasswordHash(password) {
  const salt = Buffer.alloc(16, 0x5a);
  const derived = await scrypt(password, salt, 32, {
    N: 8192,
    r: 8,
    p: 1,
    maxmem: 32 * 1024 * 1024,
  });
  return `scrypt$N=8192,r=8,p=1$${salt.toString('base64url')}$${derived.toString('base64url')}`;
}

function addOutstandingRecoveryCredentials(suffix = '1') {
  const store = getStore();
  const reset = {
    id: `passwordReset_pending_${suffix}`,
    tenant_id: 'ten_demo',
    user_id: 'usr_pw_1',
    token_hash: `reset-hash-${suffix}`,
    expires_at: new Date(NOW.getTime() + 60_000).toISOString(),
    consumed_at: null,
    created_at: NOW.toISOString(),
  };
  const invite = {
    id: `passwordInvite_pending_${suffix}`,
    tenant_id: 'ten_demo',
    user_id: 'usr_pw_1',
    token_hash: `invite-hash-${suffix}`,
    expires_at: new Date(NOW.getTime() + 60_000).toISOString(),
    consumed_at: null,
    created_by: 'staff_support',
    created_at: NOW.toISOString(),
  };
  store.userPasswordResets.push(reset);
  store.userPasswordInvites.push(invite);
  return { reset, invite };
}

async function seedUser({ email = 'user@example.test', status = 'active' } = {}) {
  const store = freshStore();
  if (!Array.isArray(store.users)) store.users = [];
  if (!Array.isArray(store.userCredentials)) store.userCredentials = [];
  if (!Array.isArray(store.userPasswordInvites)) store.userPasswordInvites = [];
  if (!Array.isArray(store.userPasswordResets)) store.userPasswordResets = [];
  const user = {
    id: 'usr_pw_1',
    tenant_id: 'ten_demo',
    email,
    name: 'Password User',
    role: 'admin',
    status,
  };
  store.users.push(user);
  const { hashPassword } = await import('../../src/lib/password.mjs');
  store.userCredentials.push({
    user_id: user.id,
    tenant_id: user.tenant_id,
    password_hash: await hashPassword(SEED_PASSWORD),
    password_updated_at: NOW.toISOString(),
    must_change: false,
    failed_attempts: 0,
    locked_until: null,
    last_login_at: null,
    session_generation: 1,
    created_at: NOW.toISOString(),
  });
  return { store, user };
}

function makeService() {
  return createPasswordAuthService(createDevPasswordAuthRepository());
}

function captureResetDelivery() {
  let payload = null;
  let transaction = null;
  return {
    delivery: {
      async enqueuePasswordReset(next, nextTransaction) {
        payload = next;
        transaction = nextTransaction;
        return { delivered: true }; // deliberately ignored by the service
      },
    },
    get payload() {
      return payload;
    },
    get transaction() {
      return transaction;
    },
  };
}

async function enrollAndConfirm(svc, at = NOW) {
  const enrollment = await svc.beginMfaEnrollment(
    { tenantId: 'ten_demo', userId: 'usr_pw_1', actorRole: 'admin' },
    { now: at, runtimeConfig: LOGIN_RUNTIME_CONFIG },
  );
  assert.equal(enrollment.status, 'mfa_enrollment_started');
  const step = Math.floor(at.getTime() / 1000 / 30);
  const code = computeTotpAtStep(enrollment.secret, step);
  const confirmed = await svc.confirmMfaEnrollment(
    { tenantId: 'ten_demo', userId: 'usr_pw_1', actorRole: 'admin', code },
    { now: at, runtimeConfig: LOGIN_RUNTIME_CONFIG },
  );
  assert.equal(confirmed.status, 'mfa_enabled');
  return { enrollment, step };
}

describe('TOTP primitives (RFC 6238)', () => {
  it('round-trips base32 secrets', () => {
    const secret = generateTotpSecret();
    assert.equal(secret.length, 32);
    const decoded = base32Decode(secret);
    assert.equal(base32Encode(decoded), secret);
    assert.equal(base32Decode('not!valid'), null);
  });

  it('verifies the RFC 6238 SHA-1 test vector', () => {
    const secret = base32Encode(Buffer.from('12345678901234567890', 'ascii'));
    const result = verifyTotp(secret, '287082', { now: 59_000, window: 0 });
    assert.equal(result.ok, true);
    assert.equal(result.matchedStep, 1);
    assert.equal(verifyTotp(secret, '287083', { now: 59_000, window: 0 }).ok, false);
  });

  it('honors a bounded drift window and rejects invalid clock parameters', () => {
    const secret = generateTotpSecret();
    const at = Date.parse('2026-08-29T12:00:30.000Z');
    const step = Math.floor(at / 1000 / 30);
    const previous = computeTotpAtStep(secret, step - 1);
    assert.equal(verifyTotp(secret, previous, { now: at, window: 1 }).ok, true);
    assert.equal(verifyTotp(secret, previous, { now: at, window: 0 }).ok, false);
    assert.equal(verifyTotp(secret, 'abcdef', { now: at }).ok, false);
    assert.equal(verifyTotp(secret, '123456', { now: at, stepSeconds: 0 }).ok, false);
    assert.ok(buildOtpauthUri({ secret, accountLabel: 'usr_pw_1' }).startsWith('otpauth://totp/'));
  });
});

describe('password recovery hardening', () => {
  beforeEach(() => {
    resetPasswordAuthRateLimitsForTests();
  });

  it('returns the exact same public shape for unknown, eligible, and enqueue-failed accounts', async () => {
    await seedUser();
    const svc = makeService();
    const capture = captureResetDelivery();
    const unknown = await svc.requestPasswordReset(
      { email: 'nobody@example.test' },
      { clientKey: 'unknown', now: NOW, delivery: capture.delivery },
    );
    const eligible = await svc.requestPasswordReset(
      { email: 'user@example.test' },
      { clientKey: 'eligible', now: NOW, delivery: capture.delivery },
    );
    const enqueueFailed = await svc.requestPasswordReset(
      { email: 'user@example.test' },
      {
        clientKey: 'failed',
        now: new Date(NOW.getTime() + 1000),
        delivery: { async enqueuePasswordReset() { throw new Error('provider down'); } },
      },
    );
    assert.deepEqual(unknown, { status: 'reset_requested' });
    assert.deepEqual(eligible, unknown);
    assert.deepEqual(enqueueFailed, unknown);
    assert.equal('delivered' in eligible, false);
    assert.equal('email' in eligible, false);
    assert.ok(capture.payload.reset_token.startsWith('pwr_'));
    assert.equal(getStore().userPasswordResets.length, 1);
    assert.equal(getStore().userPasswordResets[0].consumed_at, null);
  });

  it('persists only token digests and passes plaintext only to the durable enqueue boundary', async () => {
    await seedUser();
    const svc = makeService();
    const capture = captureResetDelivery();
    const result = await svc.requestPasswordReset(
      { email: 'user@example.test' },
      { clientKey: 'c1', now: NOW, delivery: capture.delivery },
    );
    assert.deepEqual(result, { status: 'reset_requested' });
    const stored = getStore().userPasswordResets[0];
    assert.ok(stored.token_hash);
    assert.equal(stored.reset_token, undefined);
    assert.equal(JSON.stringify(stored).includes(capture.payload.reset_token), false);
    assert.equal(capture.payload.idempotency_key, stored.id);
    assert.deepEqual(capture.transaction, { client: null });
  });

  it('invalidates every outstanding reset and invite and increments session generation', async () => {
    const { user } = await seedUser();
    const repository = createDevPasswordAuthRepository();
    const svc = createPasswordAuthService(repository);
    const invitation = await issuePasswordInvite(
      { tenantId: user.tenant_id, userId: user.id, createdBy: 'staff_support' },
      { repository, now: NOW },
    );
    assert.ok(invitation.token);

    const first = captureResetDelivery();
    await requestPasswordReset(
      { email: user.email },
      { repository, clientKey: 'r1', now: NOW, delivery: first.delivery },
    );
    const second = captureResetDelivery();
    await requestPasswordReset(
      { email: user.email },
      {
        repository,
        clientKey: 'r2',
        now: new Date(NOW.getTime() + 1000),
        delivery: second.delivery,
      },
    );

    const result = await resetPasswordWithToken(
      { token: second.payload.reset_token, password: NEXT_PASSWORD },
      {
        repository,
        clientKey: 'set',
        now: new Date(NOW.getTime() + 2000),
      },
    );
    assert.deepEqual(result, { status: 'password_reset' });
    assert.equal('tenant_id' in result, false);
    assert.equal('user_id' in result, false);
    assert.equal('email' in result, false);
    assert.equal(getStore().userPasswordResets.every((row) => row.consumed_at), true);
    assert.equal(getStore().userPasswordInvites.every((row) => row.consumed_at), true);
    assert.equal(getStore().userCredentials[0].session_generation, 2);

    const oldReset = await svc.resetPasswordWithToken(
      { token: first.payload.reset_token, password: SEED_PASSWORD },
      { clientKey: 'old-reset', now: new Date(NOW.getTime() + 3000) },
    );
    assert.equal(oldReset.error, 'invalid_reset_token');
    const oldInvite = await svc.setPasswordWithInvite(
      { token: invitation.token, password: SEED_PASSWORD },
      { clientKey: 'old-invite', now: new Date(NOW.getTime() + 3000) },
    );
    assert.equal(oldInvite.error, 'invalid_invite');
    assert.ok(getStore().auditLog.some((entry) => entry.action === 'auth.password.reset_completed'));
  });

  it('rejects weak passwords and expired reset tokens without consuming them', async () => {
    await seedUser();
    const svc = makeService();
    const capture = captureResetDelivery();
    await svc.requestPasswordReset(
      { email: 'user@example.test' },
      { clientKey: 'c1', now: NOW, delivery: capture.delivery },
    );
    const weak = await svc.resetPasswordWithToken(
      { token: capture.payload.reset_token, password: 'short' },
      { clientKey: 'c2', now: NOW },
    );
    assert.equal(weak.error, 'weak_password');
    assert.equal(getStore().userPasswordResets[0].consumed_at, null);
    const expired = await svc.resetPasswordWithToken(
      { token: capture.payload.reset_token, password: NEXT_PASSWORD },
      { clientKey: 'c3', now: new Date(NOW.getTime() + 31 * 60_000) },
    );
    assert.equal(expired.error, 'reset_token_expired');
    assert.equal(getStore().userPasswordResets[0].consumed_at, null);
  });
});

describe('MFA and session hardening', () => {
  beforeEach(() => {
    resetPasswordAuthRateLimitsForTests();
  });

  it('persists an authenticated envelope, never the plaintext seed, and blocks overwrite/rotation', async () => {
    await seedUser();
    const svc = makeService();
    const enrollment = await svc.beginMfaEnrollment(
      { tenantId: 'ten_demo', userId: 'usr_pw_1', actorRole: 'admin' },
      { now: NOW, runtimeConfig: LOGIN_RUNTIME_CONFIG },
    );
    assert.equal(enrollment.status, 'mfa_enrollment_started');
    const credential = getStore().userCredentials[0];
    assert.equal(Object.hasOwn(credential, 'mfa_secret'), false);
    assert.equal(typeof credential.mfa_secret_envelope.ciphertext, 'string');
    assert.equal(JSON.stringify(credential).includes(enrollment.secret), false);
    const aad = buildSecretAad({
      id: credential.mfa_enrollment_id,
      tenant_id: credential.tenant_id,
      purpose: 'mfa_totp',
      name: `user:${credential.user_id}`,
      rotation: 0,
    });
    assert.equal(decryptSecret(credential.mfa_secret_envelope, SECRET_ENCRYPTION_KEY, aad), enrollment.secret);
    assert.throws(() => decryptSecret(
      credential.mfa_secret_envelope,
      SECRET_ENCRYPTION_KEY,
      { ...aad, tenant_id: 'ten_other' },
    ));

    const concurrentOverwrite = await svc.beginMfaEnrollment(
      { tenantId: 'ten_demo', userId: 'usr_pw_1', actorRole: 'admin' },
      { now: NOW, runtimeConfig: LOGIN_RUNTIME_CONFIG },
    );
    assert.equal(concurrentOverwrite.error, 'mfa_enrollment_in_progress');

    const outstanding = addOutstandingRecoveryCredentials('enable');
    const step = Math.floor(NOW.getTime() / 1000 / 30);
    const code = computeTotpAtStep(enrollment.secret, step);
    const confirmed = await svc.confirmMfaEnrollment(
      { tenantId: 'ten_demo', userId: 'usr_pw_1', actorRole: 'admin', code },
      { now: NOW, runtimeConfig: LOGIN_RUNTIME_CONFIG },
    );
    assert.equal(confirmed.status, 'mfa_enabled');
    assert.equal(credential.session_generation, 2);
    assert.equal(outstanding.reset.consumed_at, NOW.toISOString());
    assert.equal(outstanding.invite.consumed_at, NOW.toISOString());

    const rotationWithoutDisable = await svc.beginMfaEnrollment(
      { tenantId: 'ten_demo', userId: 'usr_pw_1', actorRole: 'admin' },
      { now: NOW, runtimeConfig: LOGIN_RUNTIME_CONFIG },
    );
    assert.equal(rotationWithoutDisable.error, 'mfa_already_enrolled');
  });

  it('fails closed when secret encryption is unavailable', async () => {
    await seedUser();
    const result = await makeService().beginMfaEnrollment(
      { tenantId: 'ten_demo', userId: 'usr_pw_1' },
      { now: NOW, runtimeConfig: { ...LOGIN_RUNTIME_CONFIG, secretEncryptionKey: null } },
    );
    assert.equal(result.error, 'mfa_unavailable');
    assert.equal(result.status, 503);
    assert.equal(getStore().userCredentials[0].mfa_secret_envelope, undefined);
  });

  it('requires a fresh enrolled factor before completing a password reset', async () => {
    await seedUser();
    const svc = makeService();
    const { enrollment, step } = await enrollAndConfirm(svc);
    const capture = captureResetDelivery();
    await svc.requestPasswordReset(
      { email: 'user@example.test' },
      { clientKey: 'mfa-reset-request', now: NOW, delivery: capture.delivery },
    );
    const resetAt = new Date(NOW.getTime() + 31_000);

    const missing = await svc.resetPasswordWithToken(
      { token: capture.payload.reset_token, password: NEXT_PASSWORD },
      { clientKey: 'mfa-reset-missing', now: resetAt, runtimeConfig: LOGIN_RUNTIME_CONFIG },
    );
    assert.equal(missing.error, 'mfa_required');
    assert.equal(getStore().userPasswordResets[0].consumed_at, null);

    const replayed = await svc.resetPasswordWithToken(
      {
        token: capture.payload.reset_token,
        password: NEXT_PASSWORD,
        totp: computeTotpAtStep(enrollment.secret, step),
      },
      { clientKey: 'mfa-reset-replay', now: resetAt, runtimeConfig: LOGIN_RUNTIME_CONFIG },
    );
    assert.equal(replayed.error, 'mfa_invalid');
    assert.equal(getStore().userPasswordResets[0].consumed_at, null);

    const completed = await svc.resetPasswordWithToken(
      {
        token: capture.payload.reset_token,
        password: NEXT_PASSWORD,
        totp: computeTotpAtStep(enrollment.secret, step + 1),
      },
      { clientKey: 'mfa-reset-complete', now: resetAt, runtimeConfig: LOGIN_RUNTIME_CONFIG },
    );
    assert.deepEqual(completed, { status: 'password_reset' });
    assert.equal(getStore().userCredentials[0].mfa_last_step, step + 1);
    assert.equal(getStore().userCredentials[0].session_generation, 3);
  });

  it('requires TOTP at login and permits only one concurrent consumer of a step', async () => {
    await seedUser();
    const svc = makeService();
    const { enrollment, step } = await enrollAndConfirm(svc);

    const missing = await svc.loginWithPassword(
      { email: 'user@example.test', password: SEED_PASSWORD },
      { runtimeConfig: LOGIN_RUNTIME_CONFIG, clientKey: 'missing', now: NOW },
    );
    assert.equal(missing.error, 'mfa_required');

    const nextAt = new Date(NOW.getTime() + 31_000);
    const code = computeTotpAtStep(enrollment.secret, step + 1);
    const attempts = await Promise.all([
      svc.loginWithPassword(
        { email: 'user@example.test', password: SEED_PASSWORD, totp: code },
        { runtimeConfig: LOGIN_RUNTIME_CONFIG, clientKey: 'race-a', now: nextAt },
      ),
      svc.loginWithPassword(
        { email: 'user@example.test', password: SEED_PASSWORD, totp: code },
        { runtimeConfig: LOGIN_RUNTIME_CONFIG, clientKey: 'race-b', now: nextAt },
      ),
    ]);
    assert.equal(attempts.filter((result) => result.access_token).length, 1);
    assert.equal(attempts.filter((result) => result.error === 'mfa_invalid').length, 1);
    assert.equal(getStore().userCredentials[0].mfa_last_step, step + 1);
  });

  it('does not burn a valid TOTP or mutate a legacy password when session minting fails', async () => {
    await seedUser();
    const svc = makeService();
    const { enrollment, step } = await enrollAndConfirm(svc);
    const credential = getStore().userCredentials[0];
    const legacyHash = await legacyPasswordHash(SEED_PASSWORD);
    credential.password_hash = legacyHash;
    const outstanding = addOutstandingRecoveryCredentials('rehash');
    const code = computeTotpAtStep(enrollment.secret, step + 1);
    const at = new Date(NOW.getTime() + 31_000);

    const unavailable = await svc.loginWithPassword(
      { email: 'user@example.test', password: SEED_PASSWORD, totp: code },
      {
        runtimeConfig: { ...LOGIN_RUNTIME_CONFIG, authMode: 'dev-headers' },
        clientKey: 'no-mint',
        now: at,
      },
    );
    assert.equal(unavailable.error, 'password_login_unavailable');
    assert.equal(credential.mfa_last_step, step);
    assert.equal(credential.password_hash, legacyHash);
    assert.equal(credential.session_generation, 2);
    assert.equal(outstanding.reset.consumed_at, null);
    assert.equal(outstanding.invite.consumed_at, null);

    const retry = await svc.loginWithPassword(
      { email: 'user@example.test', password: SEED_PASSWORD, totp: code },
      { runtimeConfig: LOGIN_RUNTIME_CONFIG, clientKey: 'retry', now: at },
    );
    assert.ok(retry.access_token);
    assert.equal(credential.mfa_last_step, step + 1);
    assert.notEqual(credential.password_hash, legacyHash);
    assert.equal(credential.session_generation, 3);
    assert.equal(outstanding.reset.consumed_at, at.toISOString());
    assert.equal(outstanding.invite.consumed_at, at.toISOString());
    const payload = JSON.parse(Buffer.from(retry.access_token.split('.')[1], 'base64url'));
    assert.equal(payload.session_generation, 3);
    assert.ok(getStore().auditLog.some(
      (entry) => entry.action === 'auth.password_login.succeeded'
        && entry.metadata?.password_rehashed === true,
    ));
  });

  it('requires a fresh step to disable MFA, clears the envelope, and revokes session generation', async () => {
    await seedUser();
    const svc = makeService();
    const { enrollment, step } = await enrollAndConfirm(svc);
    const outstanding = addOutstandingRecoveryCredentials('disable');

    const replayed = await svc.disableMfa(
      { tenantId: 'ten_demo', userId: 'usr_pw_1', actorRole: 'admin', code: computeTotpAtStep(enrollment.secret, step) },
      { now: NOW, runtimeConfig: LOGIN_RUNTIME_CONFIG },
    );
    assert.equal(replayed.error, 'mfa_invalid');
    assert.equal(outstanding.reset.consumed_at, null);
    assert.equal(outstanding.invite.consumed_at, null);

    const disabled = await svc.disableMfa(
      {
        tenantId: 'ten_demo',
        userId: 'usr_pw_1',
        actorRole: 'admin',
        code: computeTotpAtStep(enrollment.secret, step + 1),
      },
      { now: new Date(NOW.getTime() + 31_000), runtimeConfig: LOGIN_RUNTIME_CONFIG },
    );
    assert.equal(disabled.status, 'mfa_disabled');
    const credential = getStore().userCredentials[0];
    assert.equal(credential.mfa_secret_envelope, null);
    assert.equal(credential.mfa_enrollment_id, null);
    assert.equal(credential.session_generation, 3);
    assert.equal(outstanding.reset.consumed_at, new Date(NOW.getTime() + 31_000).toISOString());
    assert.equal(outstanding.invite.consumed_at, new Date(NOW.getTime() + 31_000).toISOString());

    const stale = await svc.validatePasswordSession({
      tenantId: 'ten_demo',
      userId: 'usr_pw_1',
      sessionGeneration: 2,
    });
    assert.deepEqual(stale, { valid: false });
  });
});
