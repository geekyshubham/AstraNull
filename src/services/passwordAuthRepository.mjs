import { audit } from '../audit.mjs';
import { getStore, persistStore } from '../store.mjs';

function ensurePasswordStore() {
  const store = getStore();
  if (!Array.isArray(store.userCredentials)) store.userCredentials = [];
  if (!Array.isArray(store.userPasswordInvites)) store.userPasswordInvites = [];
  if (!Array.isArray(store.users)) store.users = [];
  return store;
}

function credentialFor(store, user) {
  return store.userCredentials.find(
    (row) => row.user_id === user.id && row.tenant_id === user.tenant_id,
  ) ?? null;
}

export function createDevPasswordAuthRepository() {
  return {
    auditService: {
      async appendAuditEvent(entry) {
        return audit(entry);
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

    async recordLoginFailure(tenantId, userId, { now, lockUntil, maxAttempts }) {
      const store = ensurePasswordStore();
      const credential = store.userCredentials.find(
        (row) => row.tenant_id === tenantId && row.user_id === userId,
      );
      if (!credential) return null;
      const lockExpired = credential.locked_until
        && new Date(credential.locked_until).getTime() <= new Date(now).getTime();
      credential.failed_attempts = lockExpired ? 1 : Number(credential.failed_attempts ?? 0) + 1;
      credential.locked_until = credential.failed_attempts >= maxAttempts ? lockUntil : null;
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

    async setPasswordFromInvite(invite, { passwordHash, tokenHash, now }) {
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

      const existing = store.userCredentials.find(
        (row) => row.user_id === user.id && row.tenant_id === user.tenant_id,
      );
      const credential = {
        user_id: user.id,
        tenant_id: user.tenant_id,
        password_hash: passwordHash,
        password_updated_at: now,
        must_change: false,
        failed_attempts: 0,
        locked_until: null,
        last_login_at: existing?.last_login_at ?? null,
        created_at: existing?.created_at ?? now,
      };
      if (existing) Object.assign(existing, credential);
      else store.userCredentials.push(credential);
      storedInvite.consumed_at = now;
      user.status = 'active';
      persistStore();
      return {
        tenant_id: user.tenant_id,
        user_id: user.id,
        email: user.email,
        role: user.role,
      };
    },

    async createPasswordInvite(record) {
      const store = ensurePasswordStore();
      const user = store.users.find(
        (row) => row.id === record.user_id && row.tenant_id === record.tenant_id,
      );
      if (!user) throw new Error('password invite user not found in tenant');
      store.userPasswordInvites.push({ ...record });
      persistStore();
      return { ...record };
    },
  };
}
