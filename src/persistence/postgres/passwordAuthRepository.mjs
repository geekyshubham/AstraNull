import { withPlatformScope } from './internalManagementRepository.mjs';
import { withTenantContext } from './tenantContext.mjs';

function toIso(value) {
  if (value == null) return value;
  return value instanceof Date ? value.toISOString() : String(value);
}

function mapCredential(row) {
  if (!row?.password_hash) return null;
  return {
    user_id: row.id ?? row.user_id,
    tenant_id: row.tenant_id,
    password_hash: row.password_hash,
    password_updated_at: toIso(row.password_updated_at),
    must_change: Boolean(row.must_change),
    failed_attempts: Number(row.failed_attempts ?? 0),
    locked_until: toIso(row.locked_until),
    last_login_at: toIso(row.last_login_at),
    session_generation: Number(row.session_generation ?? 1),
    mfa_secret_envelope: row.mfa_secret_envelope ?? null,
    mfa_enrollment_id: row.mfa_enrollment_id ?? null,
    mfa_enrolled_at: toIso(row.mfa_enrolled_at),
    mfa_last_step: row.mfa_last_step == null ? null : Number(row.mfa_last_step),
    mfa_pending_at: toIso(row.mfa_pending_at),
    mfa_disabled_at: toIso(row.mfa_disabled_at),
    created_at: toIso(row.credential_created_at ?? row.created_at),
  };
}

function mapUserWithCredential(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    email: row.email,
    name: row.name ?? null,
    role: row.role,
    status: row.status ?? 'active',
    credential: mapCredential(row),
  };
}

function mapInvite(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    user_id: row.user_id,
    token_hash: row.token_hash,
    expires_at: toIso(row.expires_at),
    consumed_at: toIso(row.consumed_at),
    created_by: row.created_by ?? null,
    created_at: toIso(row.created_at),
    email: row.email,
    role: row.role,
    user_status: row.user_status,
  };
}

function mapReset(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    user_id: row.user_id,
    token_hash: row.token_hash,
    expires_at: toIso(row.expires_at),
    consumed_at: toIso(row.consumed_at),
    created_at: toIso(row.created_at),
    email: row.email,
    role: row.role,
    user_status: row.user_status,
    session_generation: row.session_generation == null ? null : Number(row.session_generation),
    mfa_secret_envelope: row.mfa_secret_envelope ?? null,
    mfa_enrollment_id: row.mfa_enrollment_id ?? null,
    mfa_enrolled_at: toIso(row.mfa_enrolled_at),
    mfa_last_step: row.mfa_last_step == null ? null : Number(row.mfa_last_step),
  };
}

async function withResetTokenLookup(pool, tokenHash, callback) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT set_config('app.tenant_id', '', true)`);
    await client.query(
      `SELECT set_config('app.password_reset_token_hash', $1, true)`,
      [tokenHash],
    );
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // preserve original error
    }
    throw err;
  } finally {
    client.release();
  }
}

async function withInviteTokenLookup(pool, tokenHash, callback) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT set_config('app.tenant_id', '', true)`);
    await client.query(
      `SELECT set_config('app.password_invite_token_hash', $1, true)`,
      [tokenHash],
    );
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // preserve original error
    }
    throw err;
  } finally {
    client.release();
  }
}

const CREDENTIAL_RETURNING = `user_id, tenant_id, password_hash, password_updated_at, must_change,
                     failed_attempts, locked_until, last_login_at, session_generation,
                     mfa_secret_envelope, mfa_enrollment_id, mfa_enrolled_at, mfa_last_step,
                     mfa_pending_at, mfa_disabled_at, created_at`;

export function createPasswordAuthRepository(pool) {
  return {
    async findUsersByEmail(email, tenantId) {
      const findForTenant = async (resolvedTenantId) => withTenantContext(
        pool,
        resolvedTenantId,
        async (client) => {
          const { rows } = await client.query(
            `SELECT u.id, u.tenant_id, u.email, u.name, u.role, u.status,
                    c.password_hash, c.password_updated_at, c.must_change,
                    c.failed_attempts, c.locked_until, c.last_login_at,
                    c.session_generation, c.mfa_secret_envelope, c.mfa_enrollment_id,
                    c.mfa_enrolled_at, c.mfa_last_step, c.mfa_pending_at, c.mfa_disabled_at,
                    c.created_at AS credential_created_at
             FROM users u
             LEFT JOIN user_credentials c
               ON c.tenant_id = u.tenant_id AND c.user_id = u.id
             WHERE u.tenant_id = $1 AND lower(u.email) = $2
             ORDER BY u.created_at, u.id
             LIMIT 2`,
            [resolvedTenantId, email],
          );
          return rows.map(mapUserWithCredential);
        },
      );

      if (tenantId) return findForTenant(tenantId);

      const candidates = await withPlatformScope(pool, async (client) => {
        // tenant-query-audit: allow — necessary pre-auth email-to-tenant lookup. It reads only
        // users, is capped at two, and credential access occurs later in ordinary tenant scope.
        const { rows } = await client.query(
          `SELECT id, tenant_id, email, name, role, status
           FROM users
           WHERE lower(email) = $1
           ORDER BY tenant_id, created_at, id
           LIMIT 2`,
          [email],
        );
        return rows;
      });
      if (candidates.length !== 1) return candidates.map(mapUserWithCredential);
      return findForTenant(candidates[0].tenant_id);
    },

    async recordLoginFailure(tenantId, userId, {
      now,
      lockUntil,
      maxAttempts,
      audit,
    }) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE user_credentials
           SET failed_attempts = CASE
                 WHEN locked_until IS NOT NULL AND locked_until <= $3::timestamptz THEN 1
                 ELSE failed_attempts + 1
               END,
               locked_until = CASE
                 WHEN (CASE
                   WHEN locked_until IS NOT NULL AND locked_until <= $3::timestamptz THEN 1
                   ELSE failed_attempts + 1
                 END) >= $5 THEN $4::timestamptz
                 ELSE NULL
               END
           WHERE tenant_id = $1 AND user_id = $2
           RETURNING ${CREDENTIAL_RETURNING}`,
          [tenantId, userId, now, lockUntil, maxAttempts],
        );
        if (rows[0] && typeof audit === 'function') await audit(client);
        return mapCredential(rows[0] ?? null);
      });
    },

    async recordLoginSuccess(tenantId, userId, { now, passwordHash }) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE user_credentials
           SET failed_attempts = 0,
               locked_until = NULL,
               last_login_at = $3::timestamptz,
               password_hash = COALESCE($4, password_hash),
               password_updated_at = CASE
                 WHEN $4::text IS NULL THEN password_updated_at
                 ELSE $3::timestamptz
               END
           WHERE tenant_id = $1 AND user_id = $2
           RETURNING ${CREDENTIAL_RETURNING}`,
          [tenantId, userId, now, passwordHash],
        );
        return mapCredential(rows[0] ?? null);
      });
    },

    async completeLogin(tenantId, userId, {
      now,
      passwordHash,
      matchedMfaStep = null,
      expectedSessionGeneration,
      audit,
    }) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE user_credentials
           SET failed_attempts = 0,
               locked_until = NULL,
               last_login_at = $3::timestamptz,
               password_hash = COALESCE($4, password_hash),
               password_updated_at = CASE
                 WHEN $4::text IS NULL THEN password_updated_at
                 ELSE $3::timestamptz
               END,
               mfa_last_step = CASE
                 WHEN $5::bigint IS NULL THEN mfa_last_step
                 ELSE $5::bigint
               END,
               session_generation = CASE
                 WHEN $4::text IS NULL THEN session_generation
                 ELSE session_generation + 1
               END
           WHERE tenant_id = $1
             AND user_id = $2
             AND session_generation = $6::bigint
             AND (
               $5::bigint IS NULL
               OR (
                 mfa_enrolled_at IS NOT NULL
                 AND mfa_secret_envelope IS NOT NULL
                 AND (mfa_last_step IS NULL OR mfa_last_step < $5::bigint)
               )
             )
           RETURNING ${CREDENTIAL_RETURNING}`,
          [tenantId, userId, now, passwordHash, matchedMfaStep, expectedSessionGeneration],
        );
        if (!rows[0]) return null;
        if (passwordHash) {
          await client.query(
            `UPDATE user_password_resets
             SET consumed_at = $3::timestamptz
             WHERE tenant_id = $1 AND user_id = $2 AND consumed_at IS NULL`,
            [tenantId, userId, now],
          );
          await client.query(
            `UPDATE user_password_invites
             SET consumed_at = $3::timestamptz
             WHERE tenant_id = $1 AND user_id = $2 AND consumed_at IS NULL`,
            [tenantId, userId, now],
          );
        }
        if (typeof audit === 'function') await audit(client);
        return mapCredential(rows[0]);
      });
    },

    async findPasswordInviteByTokenHash(tokenHash) {
      const invite = await withInviteTokenLookup(pool, tokenHash, async (client) => {
        // tenant-query-audit: allow — RLS limits this pre-tenant read to the exact
        // transaction-local high-entropy token digest and grants no mutation authority.
        const { rows } = await client.query(
          `SELECT id, tenant_id, user_id, token_hash, expires_at, consumed_at, created_by, created_at
           FROM user_password_invites
           WHERE token_hash = $1
           LIMIT 1`,
          [tokenHash],
        );
        return rows[0] ?? null;
      });
      if (!invite) return null;

      return withTenantContext(pool, invite.tenant_id, async (client) => {
        const { rows } = await client.query(
          `SELECT i.id, i.tenant_id, i.user_id, i.token_hash, i.expires_at, i.consumed_at,
                  i.created_by, i.created_at, u.email, u.role, u.status AS user_status
           FROM user_password_invites i
           JOIN users u ON u.tenant_id = i.tenant_id AND u.id = i.user_id
           WHERE i.tenant_id = $1 AND i.id = $2 AND i.token_hash = $3`,
          [invite.tenant_id, invite.id, tokenHash],
        );
        return mapInvite(rows[0] ?? null);
      });
    },

    async setPasswordFromInvite(invite, {
      passwordHash,
      tokenHash,
      now,
      audit,
    }) {
      return withTenantContext(pool, invite.tenant_id, async (client) => {
        const locked = await client.query(
          `SELECT id, tenant_id, user_id, expires_at, consumed_at
           FROM user_password_invites
           WHERE tenant_id = $1 AND id = $2 AND user_id = $3 AND token_hash = $4
           FOR UPDATE`,
          [invite.tenant_id, invite.id, invite.user_id, tokenHash],
        );
        const current = locked.rows[0];
        if (!current || current.consumed_at) return { error: 'invalid_invite' };
        if (new Date(current.expires_at).getTime() <= new Date(now).getTime()) {
          return { error: 'invite_expired' };
        }
        const lockedUser = await client.query(
          `SELECT id, tenant_id, email, role, status
           FROM users
           WHERE tenant_id = $1 AND id = $2 AND status IN ('invited', 'active')
           FOR UPDATE`,
          [invite.tenant_id, invite.user_id],
        );
        if (!lockedUser.rows[0]) return { error: 'invalid_invite' };

        await client.query(
          `INSERT INTO user_credentials (
             user_id, tenant_id, password_hash, password_updated_at, must_change,
             failed_attempts, locked_until, session_generation, created_at
           ) VALUES ($1,$2,$3,$4::timestamptz,FALSE,0,NULL,1,$4::timestamptz)
           ON CONFLICT (user_id) DO UPDATE SET
             tenant_id = EXCLUDED.tenant_id,
             password_hash = EXCLUDED.password_hash,
             password_updated_at = EXCLUDED.password_updated_at,
             must_change = FALSE,
             failed_attempts = 0,
             locked_until = NULL,
             session_generation = user_credentials.session_generation + 1`,
          [invite.user_id, invite.tenant_id, passwordHash, now],
        );
        await client.query(
          `UPDATE user_password_invites
           SET consumed_at = $3::timestamptz
           WHERE tenant_id = $1 AND user_id = $2 AND consumed_at IS NULL`,
          [invite.tenant_id, invite.user_id, now],
        );
        await client.query(
          `UPDATE user_password_resets
           SET consumed_at = $3::timestamptz
           WHERE tenant_id = $1 AND user_id = $2 AND consumed_at IS NULL`,
          [invite.tenant_id, invite.user_id, now],
        );
        const { rows } = await client.query(
          `UPDATE users
           SET status = 'active'
           WHERE tenant_id = $1 AND id = $2
           RETURNING id, tenant_id, email, role`,
          [invite.tenant_id, invite.user_id],
        );
        if (!rows[0]) throw new Error('password invite references a missing tenant user');
        if (typeof audit === 'function') await audit(client);
        return {
          tenant_id: rows[0].tenant_id,
          user_id: rows[0].id,
          email: rows[0].email,
          role: rows[0].role,
        };
      });
    },

    async createPasswordInvite(record, { audit } = {}) {
      return withTenantContext(pool, record.tenant_id, async (client) => {
        await client.query(
          `UPDATE user_password_invites
           SET consumed_at = $3::timestamptz
           WHERE tenant_id = $1 AND user_id = $2 AND consumed_at IS NULL`,
          [record.tenant_id, record.user_id, record.created_at],
        );
        const { rows } = await client.query(
          `INSERT INTO user_password_invites (
             id, tenant_id, user_id, token_hash, expires_at, consumed_at, created_by, created_at
           ) VALUES ($1,$2,$3,$4,$5::timestamptz,$6::timestamptz,$7,$8::timestamptz)
           RETURNING id, tenant_id, user_id, token_hash, expires_at, consumed_at, created_by, created_at`,
          [
            record.id,
            record.tenant_id,
            record.user_id,
            record.token_hash,
            record.expires_at,
            record.consumed_at,
            record.created_by,
            record.created_at,
          ],
        );
        if (typeof audit === 'function') await audit(client);
        return mapInvite(rows[0]);
      });
    },

    async findCredential(tenantId, userId) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT u.id, u.tenant_id, u.email, u.role, u.status AS user_status,
                  c.password_hash, c.password_updated_at, c.must_change,
                  c.failed_attempts, c.locked_until, c.last_login_at, c.session_generation,
                  c.mfa_secret_envelope, c.mfa_enrollment_id, c.mfa_enrolled_at,
                  c.mfa_last_step, c.mfa_pending_at, c.mfa_disabled_at,
                  c.created_at AS credential_created_at
           FROM users u
           LEFT JOIN user_credentials c
             ON c.tenant_id = u.tenant_id AND c.user_id = u.id
           WHERE u.tenant_id = $1 AND u.id = $2
           LIMIT 1`,
          [tenantId, userId],
        );
        const row = rows[0];
        if (!row) return null;
        const credential = mapCredential(row);
        return credential ? {
          ...credential,
          email: row.email,
          role: row.role,
          user_status: row.user_status,
        } : null;
      });
    },

    async createPasswordReset(record, { audit, enqueue } = {}) {
      return withTenantContext(pool, record.tenant_id, async (client) => {
        if (typeof enqueue !== 'function') {
          throw new Error('password reset creation requires a durable enqueue callback');
        }
        await client.query(
          `UPDATE user_password_resets
           SET consumed_at = $3::timestamptz
           WHERE tenant_id = $1 AND user_id = $2 AND consumed_at IS NULL`,
          [record.tenant_id, record.user_id, record.created_at],
        );
        const { rows } = await client.query(
          `INSERT INTO user_password_resets (
             id, tenant_id, user_id, token_hash, expires_at, consumed_at, created_at
           ) VALUES ($1,$2,$3,$4,$5::timestamptz,$6::timestamptz,$7::timestamptz)
           RETURNING id, tenant_id, user_id, token_hash, expires_at, consumed_at, created_at`,
          [
            record.id,
            record.tenant_id,
            record.user_id,
            record.token_hash,
            record.expires_at,
            record.consumed_at,
            record.created_at,
          ],
        );
        if (typeof audit === 'function') await audit(client);
        await enqueue({ client });
        return mapReset(rows[0]);
      });
    },

    async findPasswordResetByTokenHash(tokenHash) {
      const reset = await withResetTokenLookup(pool, tokenHash, async (client) => {
        // tenant-query-audit: allow — RLS limits this pre-tenant read to the exact
        // transaction-local high-entropy token digest and grants no mutation authority.
        const { rows } = await client.query(
          `SELECT id, tenant_id, user_id, token_hash, expires_at, consumed_at, created_at
           FROM user_password_resets
           WHERE token_hash = $1
           LIMIT 1`,
          [tokenHash],
        );
        return rows[0] ?? null;
      });
      if (!reset) return null;

      return withTenantContext(pool, reset.tenant_id, async (client) => {
        const { rows } = await client.query(
          `SELECT r.id, r.tenant_id, r.user_id, r.token_hash, r.expires_at, r.consumed_at,
                  r.created_at, u.email, u.role, u.status AS user_status,
                  c.session_generation, c.mfa_secret_envelope, c.mfa_enrollment_id,
                  c.mfa_enrolled_at, c.mfa_last_step
           FROM user_password_resets r
           JOIN users u ON u.tenant_id = r.tenant_id AND u.id = r.user_id
           JOIN user_credentials c ON c.tenant_id = r.tenant_id AND c.user_id = r.user_id
           WHERE r.tenant_id = $1 AND r.id = $2 AND r.token_hash = $3`,
          [reset.tenant_id, reset.id, tokenHash],
        );
        return mapReset(rows[0] ?? null);
      });
    },

    async consumePasswordReset(reset, {
      passwordHash,
      tokenHash,
      now,
      expectedSessionGeneration,
      matchedMfaStep = null,
      mfaEnrollmentId = null,
      audit,
    }) {
      return withTenantContext(pool, reset.tenant_id, async (client) => {
        const locked = await client.query(
          `SELECT id, tenant_id, user_id, expires_at, consumed_at
           FROM user_password_resets
           WHERE tenant_id = $1 AND id = $2 AND user_id = $3 AND token_hash = $4
           FOR UPDATE`,
          [reset.tenant_id, reset.id, reset.user_id, tokenHash],
        );
        const current = locked.rows[0];
        if (!current || current.consumed_at) return { error: 'invalid_reset_token' };
        if (new Date(current.expires_at).getTime() <= new Date(now).getTime()) {
          return { error: 'reset_token_expired' };
        }
        const lockedUser = await client.query(
          `SELECT id, tenant_id, email, role, status
           FROM users
           WHERE tenant_id = $1 AND id = $2 AND status = 'active'
           FOR UPDATE`,
          [reset.tenant_id, reset.user_id],
        );
        if (!lockedUser.rows[0]) return { error: 'invalid_reset_token' };

        const updatedCredential = await client.query(
          `UPDATE user_credentials
           SET password_hash = $3,
               password_updated_at = $4::timestamptz,
               must_change = FALSE,
               failed_attempts = 0,
               locked_until = NULL,
               mfa_last_step = CASE
                 WHEN $6::bigint IS NULL THEN mfa_last_step
                 ELSE $6::bigint
               END,
               session_generation = session_generation + 1
           WHERE tenant_id = $1
             AND user_id = $2
             AND session_generation = $5::bigint
             AND (
               ($6::bigint IS NULL AND mfa_enrolled_at IS NULL)
               OR (
                 $6::bigint IS NOT NULL
                 AND mfa_enrolled_at IS NOT NULL
                 AND mfa_secret_envelope IS NOT NULL
                 AND mfa_enrollment_id = $7
                 AND (mfa_last_step IS NULL OR mfa_last_step < $6::bigint)
               )
             )
           RETURNING session_generation`,
          [
            reset.tenant_id,
            reset.user_id,
            passwordHash,
            now,
            expectedSessionGeneration,
            matchedMfaStep,
            mfaEnrollmentId,
          ],
        );
        if (updatedCredential.rowCount !== 1) {
          return { error: matchedMfaStep === null ? 'invalid_reset_token' : 'mfa_invalid' };
        }
        await client.query(
          `UPDATE user_password_resets
           SET consumed_at = $3::timestamptz
           WHERE tenant_id = $1 AND user_id = $2 AND consumed_at IS NULL`,
          [reset.tenant_id, reset.user_id, now],
        );
        await client.query(
          `UPDATE user_password_invites
           SET consumed_at = $3::timestamptz
           WHERE tenant_id = $1 AND user_id = $2 AND consumed_at IS NULL`,
          [reset.tenant_id, reset.user_id, now],
        );
        if (typeof audit === 'function') await audit(client);
        const row = lockedUser.rows[0];
        return {
          tenant_id: row.tenant_id,
          user_id: row.id,
          email: row.email,
          role: row.role,
          session_generation: Number(updatedCredential.rows[0].session_generation),
        };
      });
    },

    async beginMfaEnrollment(tenantId, userId, {
      mfaSecretEnvelope,
      mfaEnrollmentId,
      now,
      audit,
    }) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE user_credentials
           SET mfa_secret_envelope = $3::jsonb,
               mfa_enrollment_id = $4,
               mfa_pending_at = $5::timestamptz,
               mfa_disabled_at = NULL
           WHERE tenant_id = $1
             AND user_id = $2
             AND mfa_secret_envelope IS NULL
             AND mfa_enrollment_id IS NULL
             AND mfa_enrolled_at IS NULL
             AND mfa_pending_at IS NULL
           RETURNING ${CREDENTIAL_RETURNING}`,
          [tenantId, userId, JSON.stringify(mfaSecretEnvelope), mfaEnrollmentId, now],
        );
        if (!rows[0]) return null;
        if (typeof audit === 'function') await audit(client);
        return mapCredential(rows[0]);
      });
    },

    async confirmMfaEnrollment(tenantId, userId, {
      mfaEnrollmentId,
      matchedStep,
      now,
      audit,
    }) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE user_credentials
           SET mfa_enrolled_at = $4::timestamptz,
               mfa_last_step = $5::bigint,
               mfa_pending_at = NULL,
               session_generation = session_generation + 1
           WHERE tenant_id = $1
             AND user_id = $2
             AND mfa_enrollment_id = $3
             AND mfa_secret_envelope IS NOT NULL
             AND mfa_enrolled_at IS NULL
             AND mfa_pending_at IS NOT NULL
             AND mfa_last_step IS NULL
           RETURNING ${CREDENTIAL_RETURNING}`,
          [tenantId, userId, mfaEnrollmentId, now, matchedStep],
        );
        if (!rows[0]) return null;
        await client.query(
          `UPDATE user_password_resets
           SET consumed_at = $3::timestamptz
           WHERE tenant_id = $1 AND user_id = $2 AND consumed_at IS NULL`,
          [tenantId, userId, now],
        );
        await client.query(
          `UPDATE user_password_invites
           SET consumed_at = $3::timestamptz
           WHERE tenant_id = $1 AND user_id = $2 AND consumed_at IS NULL`,
          [tenantId, userId, now],
        );
        if (typeof audit === 'function') await audit(client);
        return mapCredential(rows[0]);
      });
    },

    async disableMfa(tenantId, userId, {
      mfaEnrollmentId,
      matchedStep,
      now,
      audit,
    }) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE user_credentials
           SET mfa_secret_envelope = NULL,
               mfa_enrollment_id = NULL,
               mfa_enrolled_at = NULL,
               mfa_last_step = NULL,
               mfa_pending_at = NULL,
               mfa_disabled_at = $5::timestamptz,
               session_generation = session_generation + 1
           WHERE tenant_id = $1
             AND user_id = $2
             AND mfa_enrollment_id = $3
             AND mfa_enrolled_at IS NOT NULL
             AND mfa_secret_envelope IS NOT NULL
             AND (mfa_last_step IS NULL OR mfa_last_step < $4::bigint)
           RETURNING ${CREDENTIAL_RETURNING}`,
          [tenantId, userId, mfaEnrollmentId, matchedStep, now],
        );
        if (!rows[0]) return null;
        await client.query(
          `UPDATE user_password_resets
           SET consumed_at = $3::timestamptz
           WHERE tenant_id = $1 AND user_id = $2 AND consumed_at IS NULL`,
          [tenantId, userId, now],
        );
        await client.query(
          `UPDATE user_password_invites
           SET consumed_at = $3::timestamptz
           WHERE tenant_id = $1 AND user_id = $2 AND consumed_at IS NULL`,
          [tenantId, userId, now],
        );
        if (typeof audit === 'function') await audit(client);
        return mapCredential(rows[0]);
      });
    },
  };
}
