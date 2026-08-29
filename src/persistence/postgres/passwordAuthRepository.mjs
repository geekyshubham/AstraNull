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
        // tenant-query-audit: allow — this is the one necessary pre-auth email-to-tenant lookup.
        // It reads only users (never password hashes), is capped at two rows because the caller
        // needs only unique-vs-ambiguous, and runs under the existing transaction-local,
        // SELECT-only platform-scope RLS policy. Once one tenant is known, the credential join is
        // performed in a separate ordinary tenant transaction above.
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

    async recordLoginFailure(tenantId, userId, { now, lockUntil, maxAttempts }) {
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
           RETURNING user_id, tenant_id, password_hash, password_updated_at, must_change,
                     failed_attempts, locked_until, last_login_at, created_at`,
          [tenantId, userId, now, lockUntil, maxAttempts],
        );
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
           RETURNING user_id, tenant_id, password_hash, password_updated_at, must_change,
                     failed_attempts, locked_until, last_login_at, created_at`,
          [tenantId, userId, now, passwordHash],
        );
        return mapCredential(rows[0] ?? null);
      });
    },

    async findPasswordInviteByTokenHash(tokenHash) {
      const invite = await withInviteTokenLookup(pool, tokenHash, async (client) => {
        // tenant-query-audit: allow — no tenant exists until the high-entropy invite secret is
        // presented. RLS still constrains this read: the special SELECT policy requires an empty
        // app.tenant_id and token_hash equal to the transaction-local lookup hash set above. The
        // query returns at most one row and grants no credential read or write authority.
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

    async setPasswordFromInvite(invite, { passwordHash, tokenHash, now }) {
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
             failed_attempts, locked_until, created_at
           ) VALUES ($1,$2,$3,$4::timestamptz,FALSE,0,NULL,$4::timestamptz)
           ON CONFLICT (user_id) DO UPDATE SET
             tenant_id = EXCLUDED.tenant_id,
             password_hash = EXCLUDED.password_hash,
             password_updated_at = EXCLUDED.password_updated_at,
             must_change = FALSE,
             failed_attempts = 0,
             locked_until = NULL`,
          [invite.user_id, invite.tenant_id, passwordHash, now],
        );
        await client.query(
          `UPDATE user_password_invites
           SET consumed_at = $4::timestamptz
           WHERE tenant_id = $1 AND id = $2 AND user_id = $3`,
          [invite.tenant_id, invite.id, invite.user_id, now],
        );
        const { rows } = await client.query(
          `UPDATE users
           SET status = 'active'
           WHERE tenant_id = $1 AND id = $2
           RETURNING id, tenant_id, email, role`,
          [invite.tenant_id, invite.user_id],
        );
        if (!rows[0]) throw new Error('password invite references a missing tenant user');
        return {
          tenant_id: rows[0].tenant_id,
          user_id: rows[0].id,
          email: rows[0].email,
          role: rows[0].role,
        };
      });
    },

    async createPasswordInvite(record) {
      return withTenantContext(pool, record.tenant_id, async (client) => {
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
        return mapInvite(rows[0]);
      });
    },
  };
}
