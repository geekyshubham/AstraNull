import { createHmac, randomBytes } from 'node:crypto';
import { mintSignedSessionToken } from '../context.mjs';
import { hashToken } from '../lib/crypto.mjs';
import { newId } from '../lib/ids.mjs';
import { mintBundledStagingOidcJwt } from '../lib/bundledStagingOidc.mjs';
import { assessPassword, hashPassword, needsRehash, verifyPassword } from '../lib/password.mjs';
import { createFixedWindowRateLimiter } from '../lib/rateLimit.mjs';
import { buildSecretAad, decryptSecret, encryptSecret } from '../lib/secrets.mjs';
import { buildOtpauthUri, generateTotpSecret, verifyTotp } from '../lib/totp.mjs';

const LOGIN_WINDOW_MS = 60_000;
const CLIENT_LOGIN_LIMIT = 10;
const EMAIL_LOGIN_LIMIT = 5;
const INVITE_SET_LIMIT = 10;
const RESET_REQUEST_LIMIT = 5;
const RESET_SET_LIMIT = 10;
const LOCKOUT_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60_000;
const DEFAULT_INVITE_TTL_MS = 7 * 24 * 60 * 60_000;
const DEFAULT_RESET_TTL_MS = 30 * 60_000;
const SESSION_EXPIRES_IN_SECONDS = 3600;
const PASSWORD_SESSION_SOURCE = 'password';
const PUBLIC_RESET_RESPONSE = Object.freeze({ status: 'reset_requested' });

// A fixed valid hash keeps unknown-user and missing-credential checks on the same scrypt path as a
// wrong password. The plaintext is intentionally public and has no account attached to it.
const DUMMY_PASSWORD_HASH = 'scrypt$N=16384,r=8,p=1$MDEyMzQ1Njc4OWFiY2RlZg$VQ8aAxKFdgf274iBLzQxsBdq3Vseaw0jbGHTiToLo3g';

let loginClientLimiter;
let loginEmailLimiter;
let inviteClientLimiter;
let resetRequestClientLimiter;
let resetSetClientLimiter;

export function resetPasswordAuthRateLimitsForTests() {
  loginClientLimiter = createFixedWindowRateLimiter({
    windowMs: LOGIN_WINDOW_MS,
    maxRequests: CLIENT_LOGIN_LIMIT,
  });
  loginEmailLimiter = createFixedWindowRateLimiter({
    windowMs: LOGIN_WINDOW_MS,
    maxRequests: EMAIL_LOGIN_LIMIT,
  });
  inviteClientLimiter = createFixedWindowRateLimiter({
    windowMs: LOGIN_WINDOW_MS,
    maxRequests: INVITE_SET_LIMIT,
  });
  resetRequestClientLimiter = createFixedWindowRateLimiter({
    windowMs: LOGIN_WINDOW_MS,
    maxRequests: RESET_REQUEST_LIMIT,
  });
  resetSetClientLimiter = createFixedWindowRateLimiter({
    windowMs: LOGIN_WINDOW_MS,
    maxRequests: RESET_SET_LIMIT,
  });
}

resetPasswordAuthRateLimitsForTests();

function resolveNow(now) {
  const value = typeof now === 'function' ? now() : (now ?? new Date());
  const date = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new TypeError('now must resolve to a valid date');
  return date;
}

function validationFailure(fields) {
  return {
    error: 'validation_failed',
    status: 400,
    message: 'One or more authentication fields are invalid.',
    fields,
  };
}

function invalidCredentials() {
  return {
    error: 'invalid_credentials',
    status: 401,
    message: 'Email or password is incorrect.',
  };
}

function rateLimited(retryAfterSeconds) {
  return {
    error: 'rate_limited',
    status: 429,
    message: 'Too many authentication attempts. Try again later.',
    retry_after_seconds: retryAfterSeconds,
  };
}

function passwordLoginUnavailable() {
  return {
    error: 'password_login_unavailable',
    status: 503,
    message: 'Password login cannot mint or validate sessions on this deployment.',
  };
}

function mfaUnavailable() {
  return {
    error: 'mfa_unavailable',
    status: 503,
    message: 'Multi-factor authentication is unavailable until secret encryption is configured.',
  };
}

function mfaInvalid() {
  return {
    error: 'mfa_invalid',
    status: 401,
    message: 'The authentication code is invalid or expired.',
  };
}

function normalizeLoginBody(body) {
  const fields = [];
  const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
  if (!email || email.length > 320 || !/^[^\s@]+@[^\s@]+$/.test(email)) fields.push('email');
  const password = body?.password;
  if (typeof password !== 'string' || password.length === 0 || password.length > 200) {
    fields.push('password');
  }
  let tenantId;
  if (body?.tenant_id !== undefined) {
    tenantId = typeof body.tenant_id === 'string' ? body.tenant_id.trim() : '';
    if (!tenantId || tenantId.length > 200) fields.push('tenant_id');
  }
  return fields.length ? { error: validationFailure([...new Set(fields)]) } : { email, password, tenantId };
}

async function appendAudit(repository, entry, now) {
  if (!entry.tenant_id || typeof repository?.auditService?.appendAuditEvent !== 'function') return;
  await repository.auditService.appendAuditEvent(entry, { now });
}

function mutationAuditOptions(repository, auditEvent, now) {
  const appendAuditEvent = repository?.auditService?.appendAuditEvent;
  return {
    auditEvent,
    auditNow: now,
    audit: typeof appendAuditEvent === 'function'
      ? (client) => appendAuditEvent(auditEvent, { now, client })
      : undefined,
  };
}

async function auditKnownLogin(repository, user, action, reason, now) {
  if (!user) return;
  await appendAudit(repository, {
    tenant_id: user.tenant_id,
    actor_user_id: user.id,
    actor_role: user.role,
    action,
    resource_type: 'user',
    resource_id: user.id,
    metadata: { reason },
  }, now);
}

function lockedResponse(lockedUntil, now) {
  const retryAfterSeconds = Math.max(
    1,
    Math.ceil((new Date(lockedUntil).getTime() - now.getTime()) / 1000),
  );
  return {
    error: 'account_locked',
    status: 423,
    message: 'The account is temporarily locked. Try again later.',
    retry_after_seconds: retryAfterSeconds,
  };
}

function normalizeSessionGeneration(value) {
  const generation = Number(value ?? 1);
  return Number.isSafeInteger(generation) && generation > 0 ? generation : null;
}

function addPasswordClaimsToSignedSession(token, secret, sessionGeneration) {
  const [version, payloadB64] = String(token).split('.');
  const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  payload.auth_source = PASSWORD_SESSION_SOURCE;
  payload.session_generation = sessionGeneration;
  const taggedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signature = createHmac('sha256', secret)
    .update(`${version}.${taggedPayload}`, 'utf8')
    .digest('base64url');
  return `${version}.${taggedPayload}.${signature}`;
}

function mintPasswordSession(runtimeConfig, user, now, sessionGeneration) {
  if (normalizeSessionGeneration(sessionGeneration) === null) return null;
  const exp = Math.floor(now.getTime() / 1000) + SESSION_EXPIRES_IN_SECONDS;
  if (runtimeConfig?.authMode === 'signed-session' && runtimeConfig.sessionSecret) {
    const token = mintSignedSessionToken({
      tenantId: user.tenant_id,
      userId: user.id,
      role: user.role,
      exp,
    }, runtimeConfig.sessionSecret);
    return addPasswordClaimsToSignedSession(token, runtimeConfig.sessionSecret, sessionGeneration);
  }
  if (runtimeConfig?.authMode === 'oidc-jwt' && runtimeConfig.bundledStagingOidc === true) {
    return mintBundledStagingOidcJwt({
      tenantId: user.tenant_id,
      userId: user.id,
      role: user.role,
      exp,
      extraClaims: {
        auth_source: PASSWORD_SESSION_SOURCE,
        session_generation: sessionGeneration,
      },
    });
  }
  return null;
}

function resolveSecretEncryptionKey(options) {
  return options?.secretEncryptionKey ?? options?.runtimeConfig?.secretEncryptionKey ?? null;
}

function mfaSecretAad(tenantId, userId, enrollmentId) {
  return buildSecretAad({
    id: enrollmentId,
    tenant_id: tenantId,
    purpose: 'mfa_totp',
    name: `user:${userId}`,
    rotation: 0,
  });
}

function decryptCredentialMfaSecret(credential, key) {
  if (!credential?.mfa_secret_envelope || !credential?.mfa_enrollment_id || !key) {
    throw new Error('MFA secret envelope is unavailable');
  }
  return decryptSecret(
    credential.mfa_secret_envelope,
    key,
    mfaSecretAad(credential.tenant_id, credential.user_id, credential.mfa_enrollment_id),
  );
}

export async function loginWithPassword(body, {
  repository,
  runtimeConfig,
  clientKey = 'anonymous',
  now,
  secretEncryptionKey,
} = {}) {
  if (!repository) throw new TypeError('loginWithPassword requires a repository');
  const normalized = normalizeLoginBody(body);
  if (normalized.error) return normalized.error;

  const clientRate = loginClientLimiter.check(`client:${clientKey}`);
  if (!clientRate.allowed) return rateLimited(clientRate.retryAfterSeconds);

  const nowDate = resolveNow(now);
  const users = await repository.findUsersByEmail(normalized.email, normalized.tenantId);
  if (!normalized.tenantId && users.length > 1) {
    return {
      error: 'tenant_required',
      status: 400,
      message: 'This email belongs to more than one tenant; tenant_id is required.',
    };
  }
  const user = users.length === 1 ? users[0] : null;
  const credential = user?.credential ?? null;

  if (credential?.locked_until && new Date(credential.locked_until).getTime() > nowDate.getTime()) {
    const result = lockedResponse(credential.locked_until, nowDate);
    await auditKnownLogin(repository, user, 'auth.password_login.locked', 'existing_lockout', nowDate);
    return result;
  }

  const emailRate = loginEmailLimiter.check(`email:${normalized.email}`);
  if (!emailRate.allowed) {
    await auditKnownLogin(repository, user, 'auth.password_login.failed', 'rate_limited', nowDate);
    return rateLimited(emailRate.retryAfterSeconds);
  }

  // Always execute one scrypt verification after a structurally valid request unless an existing
  // lockout explicitly forbids it. Missing users and missing credentials use the same fixed hash.
  const passwordMatches = await verifyPassword(
    normalized.password,
    credential?.password_hash ?? DUMMY_PASSWORD_HASH,
  );

  if (!user) return invalidCredentials();

  if (user.status === 'invited') {
    await auditKnownLogin(repository, user, 'auth.password_login.failed', 'password_setup_required', nowDate);
    return {
      error: 'password_setup_required',
      status: 403,
      message: 'Set a password using the current invitation before signing in.',
    };
  }
  if (user.status !== 'active') {
    await auditKnownLogin(repository, user, 'auth.password_login.failed', 'account_disabled', nowDate);
    return {
      error: 'account_disabled',
      status: 403,
      message: 'This account is disabled.',
    };
  }

  if (!credential || !passwordMatches) {
    if (credential) {
      const updated = await repository.recordLoginFailure(user.tenant_id, user.id, {
        now: nowDate.toISOString(),
        lockUntil: new Date(nowDate.getTime() + LOCKOUT_MS).toISOString(),
        maxAttempts: LOCKOUT_ATTEMPTS,
        ...mutationAuditOptions(repository, {
          tenant_id: user.tenant_id,
          actor_user_id: user.id,
          actor_role: user.role,
          action: 'auth.password_login.failed',
          resource_type: 'user',
          resource_id: user.id,
          metadata: { reason: 'invalid_credentials' },
        }, nowDate),
      });
      if (updated?.locked_until && new Date(updated.locked_until).getTime() > nowDate.getTime()) {
        const result = lockedResponse(updated.locked_until, nowDate);
        await auditKnownLogin(repository, user, 'auth.password_login.locked', 'failure_threshold', nowDate);
        return result;
      }
    } else {
      await auditKnownLogin(repository, user, 'auth.password_login.failed', 'invalid_credentials', nowDate);
    }
    return invalidCredentials();
  }

  if (credential.must_change === true) {
    await auditKnownLogin(repository, user, 'auth.password_login.failed', 'password_change_required', nowDate);
    return {
      error: 'password_change_required',
      status: 403,
      message: 'The password must be changed before this account can sign in.',
    };
  }

  let matchedMfaStep = null;
  if (credential.mfa_enrolled_at) {
    if (!credential.mfa_secret_envelope || !credential.mfa_enrollment_id) {
      await auditKnownLogin(repository, user, 'auth.password_login.failed', 'mfa_state_invalid', nowDate);
      return passwordLoginUnavailable();
    }
    const key = secretEncryptionKey ?? resolveSecretEncryptionKey({ runtimeConfig });
    let mfaSecret;
    try {
      mfaSecret = decryptCredentialMfaSecret(credential, key);
    } catch {
      await auditKnownLogin(repository, user, 'auth.password_login.failed', 'mfa_decryption_unavailable', nowDate);
      return passwordLoginUnavailable();
    }
    const totpCode = typeof body?.totp === 'string' ? body.totp : '';
    const totpResult = verifyTotp(mfaSecret, totpCode, { now: nowDate });
    const lastStep = credential.mfa_last_step == null ? null : Number(credential.mfa_last_step);
    const replayed = totpResult.ok && lastStep !== null && totpResult.matchedStep <= lastStep;
    if (!totpResult.ok || replayed) {
      await auditKnownLogin(
        repository,
        user,
        'auth.password_login.failed',
        totpCode ? 'mfa_invalid' : 'mfa_required',
        nowDate,
      );
      return {
        error: totpCode ? 'mfa_invalid' : 'mfa_required',
        status: 401,
        message: totpCode
          ? 'The authentication code is invalid or expired.'
          : 'This account requires an authentication code.',
      };
    }
    matchedMfaStep = totpResult.matchedStep;
  }

  const generation = normalizeSessionGeneration(credential.session_generation);
  if (generation === null || typeof repository.completeLogin !== 'function') {
    await auditKnownLogin(repository, user, 'auth.password_login.failed', 'session_generation_unavailable', nowDate);
    return passwordLoginUnavailable();
  }

  const replacementHash = needsRehash(credential.password_hash)
    ? await hashPassword(normalized.password)
    : null;
  const mintedGeneration = generation + (replacementHash ? 1 : 0);
  if (!Number.isSafeInteger(mintedGeneration) || mintedGeneration < 1) {
    await auditKnownLogin(repository, user, 'auth.password_login.failed', 'session_generation_unavailable', nowDate);
    return passwordLoginUnavailable();
  }

  // Mint first, then consume the MFA step with an atomic repository CAS. If minting fails the
  // code is not burned; if a concurrent request wins the CAS this token is discarded.
  let accessToken;
  try {
    accessToken = mintPasswordSession(runtimeConfig, user, nowDate, mintedGeneration);
  } catch {
    accessToken = null;
  }
  if (!accessToken) {
    await auditKnownLogin(repository, user, 'auth.password_login.failed', 'session_mint_unavailable', nowDate);
    return passwordLoginUnavailable();
  }

  const completed = await repository.completeLogin(user.tenant_id, user.id, {
    now: nowDate.toISOString(),
    passwordHash: replacementHash,
    matchedMfaStep,
    expectedSessionGeneration: generation,
    ...mutationAuditOptions(repository, {
      tenant_id: user.tenant_id,
      actor_user_id: user.id,
      actor_role: user.role,
      action: 'auth.password_login.succeeded',
      resource_type: 'user',
      resource_id: user.id,
      metadata: { reason: 'authenticated', password_rehashed: Boolean(replacementHash) },
    }, nowDate),
  });
  if (!completed) {
    await auditKnownLogin(
      repository,
      user,
      'auth.password_login.failed',
      matchedMfaStep === null ? 'credential_generation_changed' : 'mfa_replayed',
      nowDate,
    );
    return matchedMfaStep === null ? invalidCredentials() : mfaInvalid();
  }

  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: SESSION_EXPIRES_IN_SECONDS,
    principal: 'customer',
    tenant_id: user.tenant_id,
    user_id: user.id,
    role: user.role,
  };
}

function normalizeSetPasswordBody(body) {
  const fields = [];
  const token = typeof body?.token === 'string' ? body.token.trim() : '';
  if (!token || token.length > 2048) fields.push('token');
  const password = body?.password;
  if (typeof password !== 'string' || password.length === 0 || password.length > 200) {
    fields.push('password');
  }
  return fields.length ? { error: validationFailure([...new Set(fields)]) } : { token, password };
}

export async function setPasswordWithInvite(body, {
  repository,
  clientKey = 'anonymous',
  now,
} = {}) {
  if (!repository) throw new TypeError('setPasswordWithInvite requires a repository');
  const normalized = normalizeSetPasswordBody(body);
  if (normalized.error) return normalized.error;

  const rate = inviteClientLimiter.check(`invite-client:${clientKey}`);
  if (!rate.allowed) return rateLimited(rate.retryAfterSeconds);

  const nowDate = resolveNow(now);
  const tokenHash = hashToken(normalized.token);
  const invite = await repository.findPasswordInviteByTokenHash(tokenHash);
  if (!invite || invite.consumed_at || !['invited', 'active'].includes(invite.user_status)) {
    return {
      error: 'invalid_invite',
      status: 401,
      message: 'The password invitation is invalid or has already been used.',
    };
  }
  if (new Date(invite.expires_at).getTime() <= nowDate.getTime()) {
    return {
      error: 'invite_expired',
      status: 410,
      message: 'The password invitation has expired.',
    };
  }

  const assessment = assessPassword(normalized.password, { email: invite.email });
  if (!assessment.ok) {
    return {
      error: 'weak_password',
      status: 400,
      message: 'The password does not meet the password policy.',
      failures: assessment.failures,
    };
  }

  const passwordHash = await hashPassword(normalized.password);
  const consumed = await repository.setPasswordFromInvite(invite, {
    passwordHash,
    tokenHash,
    now: nowDate.toISOString(),
    ...mutationAuditOptions(repository, {
      tenant_id: invite.tenant_id,
      actor_user_id: invite.user_id,
      actor_role: invite.role,
      action: 'auth.password.set',
      resource_type: 'user',
      resource_id: invite.user_id,
      metadata: { invite_id: invite.id },
    }, nowDate),
  });
  if (!consumed || consumed.error === 'invalid_invite') {
    return {
      error: 'invalid_invite',
      status: 401,
      message: 'The password invitation is invalid or has already been used.',
    };
  }
  if (consumed.error === 'invite_expired') {
    return {
      error: 'invite_expired',
      status: 410,
      message: 'The password invitation has expired.',
    };
  }

  return {
    status: 'password_set',
    tenant_id: consumed.tenant_id,
    user_id: consumed.user_id,
    email: consumed.email,
  };
}

export async function issuePasswordInvite({
  tenantId,
  userId,
  createdBy = null,
  ttlMs = DEFAULT_INVITE_TTL_MS,
}, { repository, now } = {}) {
  if (!repository) throw new TypeError('issuePasswordInvite requires a repository');
  if (!String(tenantId ?? '').trim() || !String(userId ?? '').trim()) {
    throw new TypeError('issuePasswordInvite requires tenantId and userId');
  }
  if (!Number.isInteger(ttlMs) || ttlMs < 1) {
    throw new RangeError('ttlMs must be a positive integer');
  }

  const nowDate = resolveNow(now);
  const inviteId = newId('passwordInvite');
  const token = `pwi_${randomBytes(32).toString('base64url')}`;
  const record = {
    id: inviteId,
    tenant_id: String(tenantId).trim(),
    user_id: String(userId).trim(),
    token_hash: hashToken(token),
    expires_at: new Date(nowDate.getTime() + ttlMs).toISOString(),
    consumed_at: null,
    created_by: createdBy == null ? null : String(createdBy),
    created_at: nowDate.toISOString(),
  };
  await repository.createPasswordInvite(record, mutationAuditOptions(repository, {
    tenant_id: record.tenant_id,
    actor_user_id: record.created_by,
    actor_role: 'staff',
    action: 'auth.password.invite_issued',
    resource_type: 'user_password_invite',
    resource_id: inviteId,
    metadata: { user_id: record.user_id, expires_at: record.expires_at },
  }, nowDate));

  // This is an authenticated staff operation, so the one-time secret is intentionally returned
  // once to the issuer. Public recovery below never returns its token or delivery state.
  return { invite_id: inviteId, token, expires_at: record.expires_at };
}

export function createPasswordAuthService(repository) {
  return {
    loginWithPassword: (body, options = {}) => loginWithPassword(body, { ...options, repository }),
    setPasswordWithInvite: (body, options = {}) => setPasswordWithInvite(body, { ...options, repository }),
    issuePasswordInvite: (input, options = {}) => issuePasswordInvite(input, { ...options, repository }),
    requestPasswordReset: (body, options = {}) => requestPasswordReset(body, { ...options, repository }),
    resetPasswordWithToken: (body, options = {}) => resetPasswordWithToken(body, { ...options, repository }),
    beginMfaEnrollment: (input, options = {}) => beginMfaEnrollment(input, { ...options, repository }),
    confirmMfaEnrollment: (input, options = {}) => confirmMfaEnrollment(input, { ...options, repository }),
    disableMfa: (input, options = {}) => disableMfa(input, { ...options, repository }),
    validatePasswordSession: (input, options = {}) => validatePasswordSession(input, { ...options, repository }),
  };
}

function normalizeResetRequestBody(body) {
  const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
  return !email || email.length > 320 || !/^[^\s@]+@[^\s@]+$/.test(email)
    ? { error: validationFailure(['email']) }
    : { email };
}

/**
 * Self-service reset request. The response is identical for every eligible/ineligible account.
 * Delivery is an injected durable-enqueue contract: enqueuePasswordReset() must persist an
 * idempotent job before resolving; this layer ignores its return value and never exposes status.
 */
export async function requestPasswordReset(body, {
  repository,
  clientKey = 'anonymous',
  now,
  delivery,
} = {}) {
  if (!repository) throw new TypeError('requestPasswordReset requires a repository');
  const normalized = normalizeResetRequestBody(body);
  if (normalized.error) return normalized.error;

  const clientRate = resetRequestClientLimiter.check(`reset-client:${clientKey}`);
  if (!clientRate.allowed) return rateLimited(clientRate.retryAfterSeconds);

  const nowDate = resolveNow(now);
  await verifyPassword('timing-equalizer', DUMMY_PASSWORD_HASH);
  const users = await repository.findUsersByEmail(normalized.email);
  const user = users.length === 1 ? users[0] : null;
  const credential = user?.credential ?? null;
  if (!user || user.status !== 'active' || !credential) return { ...PUBLIC_RESET_RESPONSE };

  const resetId = newId('passwordReset');
  const token = `pwr_${randomBytes(32).toString('base64url')}`;
  const record = {
    id: resetId,
    tenant_id: user.tenant_id,
    user_id: user.id,
    token_hash: hashToken(token),
    expires_at: new Date(nowDate.getTime() + DEFAULT_RESET_TTL_MS).toISOString(),
    consumed_at: null,
    created_at: nowDate.toISOString(),
  };
  const enqueuePasswordReset = delivery?.enqueuePasswordReset;
  if (typeof enqueuePasswordReset !== 'function') {
    await appendAudit(repository, {
      tenant_id: record.tenant_id,
      actor_user_id: null,
      actor_role: null,
      action: 'auth.password.reset_delivery_enqueue_failed',
      resource_type: 'user',
      resource_id: user.id,
      metadata: { reason: 'delivery_not_configured' },
    }, nowDate);
    return { ...PUBLIC_RESET_RESPONSE };
  }

  const deliveryPayload = {
    idempotency_key: resetId,
    kind: 'password_reset',
    tenant_id: user.tenant_id,
    user_id: user.id,
    email: user.email,
    reset_token: token,
    expires_at: record.expires_at,
  };
  try {
    await repository.createPasswordReset(record, {
      ...mutationAuditOptions(repository, {
        tenant_id: record.tenant_id,
        actor_user_id: null,
        actor_role: null,
        action: 'auth.password.reset_requested',
        resource_type: 'user_password_reset',
        resource_id: resetId,
        metadata: { expires_at: record.expires_at },
      }, nowDate),
      // Repository implementations invoke this before committing reset + audit. The injected
      // method must durably and idempotently enqueue before it resolves. A queue failure rolls
      // back the reset row, avoiding a valid token that can never be delivered.
      enqueue: async (transaction = {}) => {
        try {
          await enqueuePasswordReset.call(delivery, deliveryPayload, transaction);
        } catch {
          const enqueueError = new Error('Password reset delivery enqueue failed.');
          enqueueError.code = 'password_reset_delivery_enqueue_failed';
          throw enqueueError;
        }
      },
    });
  } catch (error) {
    if (error?.code !== 'password_reset_delivery_enqueue_failed') throw error;
    await appendAudit(repository, {
      tenant_id: record.tenant_id,
      actor_user_id: null,
      actor_role: null,
      action: 'auth.password.reset_delivery_enqueue_failed',
      resource_type: 'user',
      resource_id: user.id,
      metadata: { reason: 'durable_enqueue_failed' },
    }, nowDate);
  }
  return { ...PUBLIC_RESET_RESPONSE };
}

function normalizeResetPasswordBody(body) {
  const fields = [];
  const token = typeof body?.token === 'string' ? body.token.trim() : '';
  if (!token || token.length > 2048) fields.push('token');
  const password = body?.password;
  if (typeof password !== 'string' || password.length === 0 || password.length > 200) {
    fields.push('password');
  }
  return fields.length ? { error: validationFailure([...new Set(fields)]) } : { token, password };
}

export async function resetPasswordWithToken(body, {
  repository,
  clientKey = 'anonymous',
  now,
  runtimeConfig,
  secretEncryptionKey,
} = {}) {
  if (!repository) throw new TypeError('resetPasswordWithToken requires a repository');
  const normalized = normalizeResetPasswordBody(body);
  if (normalized.error) return normalized.error;

  const rate = resetSetClientLimiter.check(`reset-set:${clientKey}`);
  if (!rate.allowed) return rateLimited(rate.retryAfterSeconds);

  const nowDate = resolveNow(now);
  const tokenHash = hashToken(normalized.token);
  const reset = await repository.findPasswordResetByTokenHash(tokenHash);
  if (!reset || reset.consumed_at || reset.user_status !== 'active') {
    return {
      error: 'invalid_reset_token',
      status: 401,
      message: 'The password reset request is invalid or has already been used.',
    };
  }
  if (new Date(reset.expires_at).getTime() <= nowDate.getTime()) {
    return {
      error: 'reset_token_expired',
      status: 410,
      message: 'The password reset request has expired.',
    };
  }

  const generation = normalizeSessionGeneration(reset.session_generation);
  if (generation === null) return passwordLoginUnavailable();

  let matchedMfaStep = null;
  if (reset.mfa_enrolled_at) {
    if (!reset.mfa_secret_envelope || !reset.mfa_enrollment_id) return mfaUnavailable();
    const key = secretEncryptionKey ?? resolveSecretEncryptionKey({ runtimeConfig });
    let mfaSecret;
    try {
      mfaSecret = decryptCredentialMfaSecret(reset, key);
    } catch {
      return mfaUnavailable();
    }
    const totpCode = typeof body?.totp === 'string'
      ? body.totp
      : (typeof body?.code === 'string' ? body.code : '');
    const totpResult = verifyTotp(mfaSecret, totpCode, { now: nowDate });
    const lastStep = reset.mfa_last_step == null ? null : Number(reset.mfa_last_step);
    if (!totpResult.ok) {
      return totpCode ? mfaInvalid() : {
        error: 'mfa_required',
        status: 401,
        message: 'This account requires an authentication code.',
      };
    }
    if (lastStep !== null && totpResult.matchedStep <= lastStep) return mfaInvalid();
    matchedMfaStep = totpResult.matchedStep;
  }

  const assessment = assessPassword(normalized.password, { email: reset.email });
  if (!assessment.ok) {
    return {
      error: 'weak_password',
      status: 400,
      message: 'The password does not meet the password policy.',
      failures: assessment.failures,
    };
  }

  const passwordHash = await hashPassword(normalized.password);
  const consumed = await repository.consumePasswordReset(reset, {
    passwordHash,
    tokenHash,
    now: nowDate.toISOString(),
    expectedSessionGeneration: generation,
    matchedMfaStep,
    mfaEnrollmentId: reset.mfa_enrollment_id ?? null,
    ...mutationAuditOptions(repository, {
      tenant_id: reset.tenant_id,
      actor_user_id: reset.user_id,
      actor_role: reset.role,
      action: 'auth.password.reset_completed',
      resource_type: 'user',
      resource_id: reset.user_id,
      metadata: { reset_id: reset.id },
    }, nowDate),
  });
  if (consumed?.error === 'mfa_invalid') return mfaInvalid();
  if (!consumed || consumed.error === 'invalid_reset_token') {
    return {
      error: 'invalid_reset_token',
      status: 401,
      message: 'The password reset request is invalid or has already been used.',
    };
  }
  if (consumed.error === 'reset_token_expired') {
    return {
      error: 'reset_token_expired',
      status: 410,
      message: 'The password reset request has expired.',
    };
  }

  return { status: 'password_reset' };
}

function normalizeMfaPrincipal(tenantId, userId) {
  const tenant = String(tenantId ?? '').trim();
  const user = String(userId ?? '').trim();
  return tenant && user ? { tenantId: tenant, userId: user } : null;
}

export async function beginMfaEnrollment({ tenantId, userId, actorRole }, options = {}) {
  const { repository } = options;
  if (!repository) throw new TypeError('beginMfaEnrollment requires a repository');
  const principal = normalizeMfaPrincipal(tenantId, userId);
  if (!principal) return validationFailure(['tenant_id', 'user_id']);

  const nowDate = resolveNow(options.now);
  const credential = await repository.findCredential(principal.tenantId, principal.userId);
  if (!credential) {
    return {
      error: 'credential_required',
      status: 409,
      message: 'Set a password before enrolling in multi-factor authentication.',
    };
  }
  if (credential.mfa_enrolled_at) {
    return {
      error: 'mfa_already_enrolled',
      status: 409,
      message: 'Disable multi-factor authentication with a current code before rotating it.',
    };
  }
  if (credential.mfa_secret_envelope || credential.mfa_enrollment_id || credential.mfa_pending_at) {
    return {
      error: 'mfa_enrollment_in_progress',
      status: 409,
      message: 'A multi-factor enrollment is already in progress.',
    };
  }

  const key = resolveSecretEncryptionKey(options);
  if (!key) return mfaUnavailable();
  const secret = generateTotpSecret();
  const enrollmentId = newId('mfaEnrollment');
  const envelope = encryptSecret(
    secret,
    key,
    mfaSecretAad(principal.tenantId, principal.userId, enrollmentId),
  );
  const persisted = await repository.beginMfaEnrollment(principal.tenantId, principal.userId, {
    mfaSecretEnvelope: envelope,
    mfaEnrollmentId: enrollmentId,
    now: nowDate.toISOString(),
    ...mutationAuditOptions(repository, {
      tenant_id: principal.tenantId,
      actor_user_id: principal.userId,
      actor_role: actorRole ?? null,
      action: 'auth.mfa.enrollment_started',
      resource_type: 'user',
      resource_id: principal.userId,
      metadata: { enrollment_id: enrollmentId },
    }, nowDate),
  });
  if (!persisted) {
    return {
      error: 'mfa_enrollment_in_progress',
      status: 409,
      message: 'A multi-factor enrollment is already in progress.',
    };
  }
  return {
    status: 'mfa_enrollment_started',
    secret,
    otpauth_uri: buildOtpauthUri({
      secret,
      accountLabel: credential.email ?? principal.userId,
    }),
  };
}

export async function confirmMfaEnrollment({ tenantId, userId, code, actorRole }, options = {}) {
  const { repository } = options;
  if (!repository) throw new TypeError('confirmMfaEnrollment requires a repository');
  const principal = normalizeMfaPrincipal(tenantId, userId);
  if (!principal) return validationFailure(['tenant_id', 'user_id']);
  const nowDate = resolveNow(options.now);
  const credential = await repository.findCredential(principal.tenantId, principal.userId);
  if (credential?.mfa_enrolled_at) {
    return {
      error: 'mfa_already_enrolled',
      status: 409,
      message: 'Multi-factor authentication is already enabled.',
    };
  }
  if (!credential?.mfa_secret_envelope || !credential?.mfa_enrollment_id || !credential?.mfa_pending_at) {
    return {
      error: 'mfa_enrollment_not_started',
      status: 409,
      message: 'Start multi-factor enrollment before confirming it.',
    };
  }
  const key = resolveSecretEncryptionKey(options);
  if (!key) return mfaUnavailable();
  let secret;
  try {
    secret = decryptCredentialMfaSecret(credential, key);
  } catch {
    return mfaUnavailable();
  }
  const totpResult = verifyTotp(secret, code, { now: nowDate });
  if (!totpResult.ok) return mfaInvalid();

  const persisted = await repository.confirmMfaEnrollment(principal.tenantId, principal.userId, {
    mfaEnrollmentId: credential.mfa_enrollment_id,
    matchedStep: totpResult.matchedStep,
    now: nowDate.toISOString(),
    ...mutationAuditOptions(repository, {
      tenant_id: principal.tenantId,
      actor_user_id: principal.userId,
      actor_role: actorRole ?? null,
      action: 'auth.mfa.enabled',
      resource_type: 'user',
      resource_id: principal.userId,
      metadata: {},
    }, nowDate),
  });
  if (!persisted) {
    return {
      error: 'mfa_enrollment_changed',
      status: 409,
      message: 'The multi-factor enrollment changed; start again.',
    };
  }
  return { status: 'mfa_enabled' };
}

export async function disableMfa({ tenantId, userId, code, actorRole }, options = {}) {
  const { repository } = options;
  if (!repository) throw new TypeError('disableMfa requires a repository');
  const principal = normalizeMfaPrincipal(tenantId, userId);
  if (!principal) return validationFailure(['tenant_id', 'user_id']);
  const nowDate = resolveNow(options.now);
  const credential = await repository.findCredential(principal.tenantId, principal.userId);
  if (!credential?.mfa_enrolled_at || !credential?.mfa_secret_envelope || !credential?.mfa_enrollment_id) {
    return {
      error: 'mfa_not_enrolled',
      status: 409,
      message: 'Multi-factor authentication is not enabled for this account.',
    };
  }
  const key = resolveSecretEncryptionKey(options);
  if (!key) return mfaUnavailable();
  let secret;
  try {
    secret = decryptCredentialMfaSecret(credential, key);
  } catch {
    return mfaUnavailable();
  }
  const totpResult = verifyTotp(secret, code, { now: nowDate });
  const lastStep = credential.mfa_last_step == null ? null : Number(credential.mfa_last_step);
  if (!totpResult.ok || (lastStep !== null && totpResult.matchedStep <= lastStep)) return mfaInvalid();

  const disabled = await repository.disableMfa(principal.tenantId, principal.userId, {
    mfaEnrollmentId: credential.mfa_enrollment_id,
    matchedStep: totpResult.matchedStep,
    now: nowDate.toISOString(),
    ...mutationAuditOptions(repository, {
      tenant_id: principal.tenantId,
      actor_user_id: principal.userId,
      actor_role: actorRole ?? null,
      action: 'auth.mfa.disabled',
      resource_type: 'user',
      resource_id: principal.userId,
      metadata: {},
    }, nowDate),
  });
  return disabled ? { status: 'mfa_disabled' } : mfaInvalid();
}

export async function validatePasswordSession({ tenantId, userId, sessionGeneration }, {
  repository,
} = {}) {
  if (!repository) throw new TypeError('validatePasswordSession requires a repository');
  const principal = normalizeMfaPrincipal(tenantId, userId);
  const generation = normalizeSessionGeneration(sessionGeneration);
  if (!principal || generation === null) return { valid: false };
  const credential = await repository.findCredential(principal.tenantId, principal.userId);
  return {
    valid: Boolean(
      credential
      && credential.user_status === 'active'
      && normalizeSessionGeneration(credential.session_generation) === generation
    ),
  };
}
