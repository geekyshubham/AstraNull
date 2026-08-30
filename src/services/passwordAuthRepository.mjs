import { buildAuditRecord } from '../audit.mjs';
import { getStore, persistStore } from '../store.mjs';

function ensurePasswordStore() {
  const store = getStore();
  if (!Array.isArray(store.userCredentials)) store.userCredentials = [];
  if (!Array.isArray(store.userPasswordInvites)) store.userPasswordInvites = [];
  if (!Array.isArray(store.userPasswordResets)) store.userPasswordResets = [];
  if (!Array.isArray(store.users)) store.users = [];
  if (!Array.isArray(store.auditLog)) store.auditLog = [];

  // A pre-review local draft stored plaintext mfa_secret. Drop it on sight, invalidate the
  // credential, and require an explicit password-recovery step instead of silently removing MFA.
  let removedPlaintext = false;
  for (const credential of store.userCredentials) {
    if (Object.hasOwn(credential, 'mfa_secret')) {
      delete credential.mfa_secret;
      credential.must_change = true;
      credential.session_generation = (sessionGeneration(credential) ?? 1) + 1;
      credential.mfa_secret_envelope = null;
      credential.mfa_enrollment_id = null;
      credential.mfa_enrolled_at = null;
      credential.mfa_last_step = null;
      credential.mfa_pending_at = null;
      credential.mfa_disabled_at = new Date().toISOString();
      consumeOutstandingCredentials(
        store,
        credential.tenant_id,
        credential.user_id,
        credential.mfa_disabled_at,
      );
      removedPlaintext = true;
    }
  }
  if (removedPlaintext) persistStore();
  return store;
}

function credentialFor(store, user) {
  return store.userCredentials.find(
    (row) => row.user_id === user.id && row.tenant_id === user.tenant_id,
  ) ?? null;
}

function sessionGeneration(credential) {
  const value = Number(credential?.session_generation ?? 1);
  return Number.isSafeInteger(value) && value > 0 ? value : null;
}

function appendAuditToStore(store, entry, now) {
  if (!entry) return null;
  const prior = [...store.auditLog].reverse().find((record) => record?.entry_hash) ?? null;
  const at = now instanceof Date ? now : new Date(now ?? Date.now());
  const record = buildAuditRecord(entry, prior, at);
  store.auditLog.push(record);
  return record;
}

function consumeOutstandingCredentials(store, tenantId, userId, now) {
  for (const reset of store.userPasswordResets) {
    if (reset.tenant_id === tenantId && reset.user_id === userId && !reset.consumed_at) {
      reset.consumed_at = now;
    }
  }
  for (const invite of store.userPasswordInvites) {
    if (invite.tenant_id === tenantId && invite.user_id === userId && !invite.consumed_at) {
      invite.consumed_at = now;
    }
  }
}

export function createDevPasswordAuthRepository() {
  return {
    auditService: {
      async appendAuditEvent(entry, options = {}) {
        const store = ensurePasswordStore();
        const record = appendAuditToStore(store, entry, options.now);
        persistStore();
        return record;
      },
    },

    async findUsersByEmail(email, tenantId) {
      const store = ensurePasswordStore();
      return store.users
        .filter((user) => (
          String(user.email ?? '').trim().toLowerCase() === email
          && (!tenantId || user.tenant_id === tenantId)
        ))
        .map((user) => ({ ...user, credential: credentialFor(store, user) }));
    },

    async recordLoginFailure(tenantId, userId, {
      now,
      lockUntil,
      maxAttempts,
      auditEvent,
      auditNow,
    }) {
      const store = ensurePasswordStore();
      const credential = store.userCredentials.find(
        (row) => row.tenant_id === tenantId && row.user_id === userId,
      );
      if (!credential) return null;
      const lockExpired = credential.locked_until
        && new Date(credential.locked_until).getTime() <= new Date(now).getTime();
      credential.failed_attempts = lockExpired ? 1 : Number(credential.failed_attempts ?? 0) + 1;
      credential.locked_until = credential.failed_attempts >= maxAttempts ? lockUntil : null;
      appendAuditToStore(store, auditEvent, auditNow ?? now);
      persistStore();
      return { ...credential };
    },

    async recordLoginSuccess(tenantId, userId, { now, passwordHash }) {
      const store = ensurePasswordStore();
      const credential = store.userCredentials.find(
        (row) => row.tenant_id === tenantId && row.user_id === userId,
      );
      if (!credential) return null;
      credential.failed_attempts = 0;
      credential.locked_until = null;
      credential.last_login_at = now;
      if (passwordHash) {
        credential.password_hash = passwordHash;
        credential.password_updated_at = now;
      }
      persistStore();
      return { ...credential };
    },

    /**
     * Final login commit. No await occurs between the generation/replay checks and mutation,
     * which gives the single-process dev store the same one-winner CAS semantics as Postgres.
     */
    async completeLogin(tenantId, userId, {
      now,
      passwordHash,
      matchedMfaStep = null,
      expectedSessionGeneration,
      auditEvent,
      auditNow,
    }) {
      const store = ensurePasswordStore();
      const credential = store.userCredentials.find(
        (row) => row.tenant_id === tenantId && row.user_id === userId,
      );
      if (!credential || sessionGeneration(credential) !== expectedSessionGeneration) return null;
      if (matchedMfaStep !== null) {
        const lastStep = credential.mfa_last_step == null ? null : Number(credential.mfa_last_step);
        if (
          !credential.mfa_enrolled_at
          || !credential.mfa_secret_envelope
          || !Number.isSafeInteger(matchedMfaStep)
          || (lastStep !== null && matchedMfaStep <= lastStep)
        ) {
          return null;
        }
        credential.mfa_last_step = matchedMfaStep;
      }
      credential.failed_attempts = 0;
      credential.locked_until = null;
      credential.last_login_at = now;
      if (passwordHash) {
        credential.password_hash = passwordHash;
        credential.password_updated_at = now;
        credential.session_generation = expectedSessionGeneration + 1;
        consumeOutstandingCredentials(store, tenantId, userId, now);
      }
      appendAuditToStore(store, auditEvent, auditNow ?? now);
      persistStore();
      return { ...credential };
    },

    async findPasswordInviteByTokenHash(tokenHash) {
      const store = ensurePasswordStore();
      const invite = store.userPasswordInvites.find((row) => row.token_hash === tokenHash);
      if (!invite) return null;
      const user = store.users.find(
        (row) => row.id === invite.user_id && row.tenant_id === invite.tenant_id,
      );
      if (!user) return null;
      return {
        ...invite,
        email: user.email,
        role: user.role,
        user_status: user.status ?? 'active',
      };
    },

    async setPasswordFromInvite(invite, {
      passwordHash,
      tokenHash,
      now,
      auditEvent,
      auditNow,
    }) {
      const store = ensurePasswordStore();
      const storedInvite = store.userPasswordInvites.find(
        (row) => row.id === invite.id
          && row.tenant_id === invite.tenant_id
          && row.user_id === invite.user_id
          && row.token_hash === tokenHash,
      );
      if (!storedInvite || storedInvite.consumed_at) return { error: 'invalid_invite' };
      if (new Date(storedInvite.expires_at).getTime() <= new Date(now).getTime()) {
        return { error: 'invite_expired' };
      }
      const user = store.users.find(
        (row) => row.id === storedInvite.user_id && row.tenant_id === storedInvite.tenant_id,
      );
      if (!user || !['invited', 'active'].includes(user.status ?? 'active')) {
        return { error: 'invalid_invite' };
      }

      const existing = credentialFor(store, user);
      if (existing) {
        const generation = sessionGeneration(existing);
        if (generation === null) return { error: 'invalid_invite' };
        Object.assign(existing, {
          password_hash: passwordHash,
          password_updated_at: now,
          must_change: false,
          failed_attempts: 0,
          locked_until: null,
          session_generation: generation + 1,
        });
      } else {
        store.userCredentials.push({
          user_id: user.id,
          tenant_id: user.tenant_id,
          password_hash: passwordHash,
          password_updated_at: now,
          must_change: false,
          failed_attempts: 0,
          locked_until: null,
          last_login_at: null,
          session_generation: 1,
          created_at: now,
        });
      }
      consumeOutstandingCredentials(store, user.tenant_id, user.id, now);
      user.status = 'active';
      appendAuditToStore(store, auditEvent, auditNow ?? now);
      persistStore();
      return {
        tenant_id: user.tenant_id,
        user_id: user.id,
        email: user.email,
        role: user.role,
      };
    },

    async createPasswordInvite(record, { auditEvent, auditNow } = {}) {
      const store = ensurePasswordStore();
      const user = store.users.find(
        (row) => row.id === record.user_id && row.tenant_id === record.tenant_id,
      );
      if (!user) throw new Error('password invite user not found in tenant');
      for (const invite of store.userPasswordInvites) {
        if (
          invite.tenant_id === record.tenant_id
          && invite.user_id === record.user_id
          && !invite.consumed_at
        ) {
          invite.consumed_at = record.created_at;
        }
      }
      store.userPasswordInvites.push({ ...record });
      appendAuditToStore(store, auditEvent, auditNow ?? record.created_at);
      persistStore();
      return { ...record };
    },

    async findCredential(tenantId, userId) {
      const store = ensurePasswordStore();
      const user = store.users.find(
        (row) => row.id === userId && row.tenant_id === tenantId,
      );
      if (!user) return null;
      const credential = credentialFor(store, user);
      return credential ? {
        ...credential,
        session_generation: sessionGeneration(credential),
        user_status: user.status ?? 'active',
        email: user.email,
        role: user.role,
      } : null;
    },

    async createPasswordReset(record, { auditEvent, auditNow, enqueue } = {}) {
      const store = ensurePasswordStore();
      const user = store.users.find(
        (row) => row.id === record.user_id && row.tenant_id === record.tenant_id,
      );
      if (!user) throw new Error('password reset user not found in tenant');
      if (typeof enqueue !== 'function') {
        throw new Error('password reset creation requires a durable enqueue callback');
      }
      // Enqueue first in the non-transactional dev store. A crash can at worst produce an
      // unusable message; it cannot leave a valid reset token with no delivery job.
      await enqueue({ client: null });
      for (const reset of store.userPasswordResets) {
        if (
          reset.tenant_id === record.tenant_id
          && reset.user_id === record.user_id
          && !reset.consumed_at
        ) {
          reset.consumed_at = record.created_at;
        }
      }
      store.userPasswordResets.push({ ...record });
      appendAuditToStore(store, auditEvent, auditNow ?? record.created_at);
      persistStore();
      return { ...record };
    },

    async findPasswordResetByTokenHash(tokenHash) {
      const store = ensurePasswordStore();
      const reset = store.userPasswordResets.find((row) => row.token_hash === tokenHash);
      if (!reset) return null;
      const user = store.users.find(
        (row) => row.id === reset.user_id && row.tenant_id === reset.tenant_id,
      );
      if (!user) return null;
      const credential = credentialFor(store, user);
      if (!credential) return null;
      return {
        ...reset,
        email: user.email,
        role: user.role,
        user_status: user.status ?? 'active',
        session_generation: sessionGeneration(credential),
        mfa_secret_envelope: credential.mfa_secret_envelope ?? null,
        mfa_enrollment_id: credential.mfa_enrollment_id ?? null,
        mfa_enrolled_at: credential.mfa_enrolled_at ?? null,
        mfa_last_step: credential.mfa_last_step ?? null,
      };
    },

    async consumePasswordReset(reset, {
      passwordHash,
      tokenHash,
      now,
      expectedSessionGeneration,
      matchedMfaStep = null,
      mfaEnrollmentId = null,
      auditEvent,
      auditNow,
    }) {
      const store = ensurePasswordStore();
      const storedReset = store.userPasswordResets.find(
        (row) => row.id === reset.id
          && row.tenant_id === reset.tenant_id
          && row.user_id === reset.user_id
          && row.token_hash === tokenHash,
      );
      if (!storedReset || storedReset.consumed_at) return { error: 'invalid_reset_token' };
      if (new Date(storedReset.expires_at).getTime() <= new Date(now).getTime()) {
        return { error: 'reset_token_expired' };
      }
      const user = store.users.find(
        (row) => row.id === storedReset.user_id && row.tenant_id === storedReset.tenant_id,
      );
      if (!user || (user.status ?? 'active') !== 'active') {
        return { error: 'invalid_reset_token' };
      }
      const credential = credentialFor(store, user);
      const generation = sessionGeneration(credential);
      if (
        !credential
        || generation === null
        || generation !== expectedSessionGeneration
      ) {
        return { error: 'invalid_reset_token' };
      }
      if (matchedMfaStep === null) {
        if (credential.mfa_enrolled_at) return { error: 'invalid_reset_token' };
      } else {
        const lastStep = credential.mfa_last_step == null ? null : Number(credential.mfa_last_step);
        if (
          !credential.mfa_enrolled_at
          || !credential.mfa_secret_envelope
          || credential.mfa_enrollment_id !== mfaEnrollmentId
          || !Number.isSafeInteger(matchedMfaStep)
          || (lastStep !== null && matchedMfaStep <= lastStep)
        ) {
          return { error: 'mfa_invalid' };
        }
        credential.mfa_last_step = matchedMfaStep;
      }
      Object.assign(credential, {
        password_hash: passwordHash,
        password_updated_at: now,
        must_change: false,
        failed_attempts: 0,
        locked_until: null,
        session_generation: generation + 1,
      });
      consumeOutstandingCredentials(store, user.tenant_id, user.id, now);
      appendAuditToStore(store, auditEvent, auditNow ?? now);
      persistStore();
      return {
        tenant_id: user.tenant_id,
        user_id: user.id,
        email: user.email,
        role: user.role,
        session_generation: credential.session_generation,
      };
    },

    async beginMfaEnrollment(tenantId, userId, {
      mfaSecretEnvelope,
      mfaEnrollmentId,
      now,
      auditEvent,
      auditNow,
    }) {
      const store = ensurePasswordStore();
      const credential = store.userCredentials.find(
        (row) => row.tenant_id === tenantId && row.user_id === userId,
      );
      if (
        !credential
        || credential.mfa_secret_envelope
        || credential.mfa_enrollment_id
        || credential.mfa_enrolled_at
        || credential.mfa_pending_at
      ) {
        return null;
      }
      credential.mfa_secret_envelope = structuredClone(mfaSecretEnvelope);
      credential.mfa_enrollment_id = mfaEnrollmentId;
      credential.mfa_pending_at = now;
      credential.mfa_disabled_at = null;
      appendAuditToStore(store, auditEvent, auditNow ?? now);
      persistStore();
      return { ...credential };
    },

    async confirmMfaEnrollment(tenantId, userId, {
      mfaEnrollmentId,
      matchedStep,
      now,
      auditEvent,
      auditNow,
    }) {
      const store = ensurePasswordStore();
      const credential = store.userCredentials.find(
        (row) => row.tenant_id === tenantId && row.user_id === userId,
      );
      const generation = sessionGeneration(credential);
      if (
        !credential
        || generation === null
        || !credential.mfa_secret_envelope
        || credential.mfa_enrollment_id !== mfaEnrollmentId
        || credential.mfa_enrolled_at
        || !credential.mfa_pending_at
        || credential.mfa_last_step != null
      ) {
        return null;
      }
      credential.mfa_enrolled_at = now;
      credential.mfa_last_step = matchedStep;
      credential.mfa_pending_at = null;
      credential.session_generation = generation + 1;
      consumeOutstandingCredentials(store, tenantId, userId, now);
      appendAuditToStore(store, auditEvent, auditNow ?? now);
      persistStore();
      return { ...credential };
    },

    async disableMfa(tenantId, userId, {
      mfaEnrollmentId,
      matchedStep,
      now,
      auditEvent,
      auditNow,
    }) {
      const store = ensurePasswordStore();
      const credential = store.userCredentials.find(
        (row) => row.tenant_id === tenantId && row.user_id === userId,
      );
      const generation = sessionGeneration(credential);
      const lastStep = credential?.mfa_last_step == null ? null : Number(credential.mfa_last_step);
      if (
        !credential
        || generation === null
        || !credential.mfa_enrolled_at
        || !credential.mfa_secret_envelope
        || credential.mfa_enrollment_id !== mfaEnrollmentId
        || !Number.isSafeInteger(matchedStep)
        || (lastStep !== null && matchedStep <= lastStep)
      ) {
        return null;
      }
      credential.mfa_secret_envelope = null;
      credential.mfa_enrollment_id = null;
      credential.mfa_enrolled_at = null;
      credential.mfa_last_step = null;
      credential.mfa_pending_at = null;
      credential.mfa_disabled_at = now;
      credential.session_generation = generation + 1;
      consumeOutstandingCredentials(store, tenantId, userId, now);
      appendAuditToStore(store, auditEvent, auditNow ?? now);
      persistStore();
      return { ...credential };
    },
  };
}
