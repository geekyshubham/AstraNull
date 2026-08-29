import { randomBytes } from 'node:crypto';
import { mintSignedSessionToken } from '../context.mjs';
import { hashToken } from '../lib/crypto.mjs';
import { newId } from '../lib/ids.mjs';
import { mintBundledStagingOidcJwt } from '../lib/bundledStagingOidc.mjs';
import { assessPassword, hashPassword, needsRehash, verifyPassword } from '../lib/password.mjs';
import { createFixedWindowRateLimiter } from '../lib/rateLimit.mjs';

const LOGIN_WINDOW_MS = 60_000;
const CLIENT_LOGIN_LIMIT = 10;
const EMAIL_LOGIN_LIMIT = 5;
const INVITE_SET_LIMIT = 10;
const LOCKOUT_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60_000;
const DEFAULT_INVITE_TTL_MS = 7 * 24 * 60 * 60_000;
const SESSION_EXPIRES_IN_SECONDS = 3600;

// A fixed valid hash keeps unknown-user and missing-credential checks on the same scrypt path as a
// wrong password. The plaintext is intentionally public and has no account attached to it.
const DUMMY_PASSWORD_HASH = 'scrypt$N=16384,r=8,p=1$MDEyMzQ1Njc4OWFiY2RlZg$VQ8aAxKFdgf274iBLzQxsBdq3Vseaw0jbGHTiToLo3g';

let loginClientLimiter;
let loginEmailLimiter;
let inviteClientLimiter;

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

function mintPasswordSession(runtimeConfig, user, now) {
  const exp = Math.floor(now.getTime() / 1000) + SESSION_EXPIRES_IN_SECONDS;
  if (runtimeConfig?.authMode === 'signed-session' && runtimeConfig.sessionSecret) {
    return mintSignedSessionToken({
      tenantId: user.tenant_id,
      userId: user.id,
      role: user.role,
      exp,
    }, runtimeConfig.sessionSecret);
  }
  if (runtimeConfig?.authMode === 'oidc-jwt' && runtimeConfig.bundledStagingOidc === true) {
    return mintBundledStagingOidcJwt({
      tenantId: user.tenant_id,
      userId: user.id,
      role: user.role,
      exp,
    });
  }
  return null;
}

export async function loginWithPassword(body, {
  repository,
  runtimeConfig,
  clientKey = 'anonymous',
  now,
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
    await auditKnownLogin(
      repository,
      user,
      'auth.password_login.failed',
      'password_setup_required',
      nowDate,
    );
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
      });
      if (updated?.locked_until && new Date(updated.locked_until).getTime() > nowDate.getTime()) {
        const result = lockedResponse(updated.locked_until, nowDate);
        await auditKnownLogin(repository, user, 'auth.password_login.locked', 'failure_threshold', nowDate);
        return result;
      }
    }
    await auditKnownLogin(repository, user, 'auth.password_login.failed', 'invalid_credentials', nowDate);
    return invalidCredentials();
  }

  if (credential.must_change === true) {
    await auditKnownLogin(
      repository,
      user,
      'auth.password_login.failed',
      'password_change_required',
      nowDate,
    );
    return {
      error: 'password_change_required',
      status: 403,
      message: 'The password must be changed before this account can sign in.',
    };
  }

  let accessToken;
  try {
    accessToken = mintPasswordSession(runtimeConfig, user, nowDate);
  } catch {
    accessToken = null;
  }
  if (!accessToken) {
    await auditKnownLogin(
      repository,
      user,
      'auth.password_login.failed',
      'session_mint_unavailable',
      nowDate,
    );
    return {
      error: 'password_login_unavailable',
      status: 503,
      message: 'Password login cannot mint sessions on this deployment.',
    };
  }

  const replacementHash = needsRehash(credential.password_hash)
    ? await hashPassword(normalized.password)
    : null;
  await repository.recordLoginSuccess(user.tenant_id, user.id, {
    now: nowDate.toISOString(),
    passwordHash: replacementHash,
  });
  await auditKnownLogin(repository, user, 'auth.password_login.succeeded', 'authenticated', nowDate);

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
  if (
    !invite
    || invite.consumed_at
    || !['invited', 'active'].includes(invite.user_status)
  ) {
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

  await appendAudit(repository, {
    tenant_id: consumed.tenant_id,
    actor_user_id: consumed.user_id,
    actor_role: consumed.role,
    action: 'auth.password.set',
    resource_type: 'user',
    resource_id: consumed.user_id,
    metadata: { invite_id: invite.id },
  }, nowDate);

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
  await repository.createPasswordInvite(record);
  await appendAudit(repository, {
    tenant_id: record.tenant_id,
    actor_user_id: record.created_by,
    actor_role: 'staff',
    action: 'auth.password.invite_issued',
    resource_type: 'user_password_invite',
    resource_id: inviteId,
    metadata: { user_id: record.user_id, expires_at: record.expires_at },
  }, nowDate);

  return { invite_id: inviteId, token, expires_at: record.expires_at };
}

export function createPasswordAuthService(repository) {
  return {
    loginWithPassword: (body, options = {}) => loginWithPassword(body, { ...options, repository }),
    setPasswordWithInvite: (body, options = {}) => setPasswordWithInvite(
      body,
      { ...options, repository },
    ),
    issuePasswordInvite: (input, options = {}) => issuePasswordInvite(
      input,
      { ...options, repository },
    ),
  };
}
