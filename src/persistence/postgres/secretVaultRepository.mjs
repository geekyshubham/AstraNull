import { withTenantContext } from './tenantContext.mjs';

const ENCRYPTED_SECRET_COLUMNS = `id, tenant_id, purpose, name, metadata_json, rotation, envelope_json,
  created_at, updated_at, created_by`;

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

/**
 * @param {Record<string, unknown> | null | undefined} row
 */
export function mapEncryptedSecretRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    purpose: row.purpose,
    name: row.name,
    metadata: row.metadata_json ?? {},
    rotation: Number(row.rotation),
    envelope: row.envelope_json ?? null,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
    created_by: row.created_by ?? undefined,
  };
}

/**
 * @param {import('pg').Pool} pool
 */
export function createSecretVaultRepository(pool) {
  return {
    /**
     * @param {{ tenantId: string }} ctx
     * @param {Record<string, unknown>} record
     */
    async createEncryptedSecret(ctx, record) {
      const tenantId = ctx.tenantId;
      const metadata = record.metadata && typeof record.metadata === 'object' ? record.metadata : {};

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO encrypted_secrets (
             id, tenant_id, purpose, name, metadata_json, rotation, envelope_json,
             created_at, updated_at, created_by
           )
           VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7::jsonb, $8::timestamptz, $9::timestamptz, $10)
           RETURNING ${ENCRYPTED_SECRET_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.purpose,
            record.name,
            JSON.stringify(metadata),
            record.rotation ?? 0,
            record.envelope ? JSON.stringify(record.envelope) : null,
            record.created_at,
            record.updated_at,
            record.created_by ?? null,
          ],
        );
        return mapEncryptedSecretRow(rows[0]);
      });
    },

    /**
     * @param {{ tenantId: string }} ctx
     */
    async listEncryptedSecrets(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${ENCRYPTED_SECRET_COLUMNS}
           FROM encrypted_secrets
           WHERE tenant_id = $1
           ORDER BY created_at ASC`,
          [tenantId],
        );
        return rows.map(mapEncryptedSecretRow);
      });
    },

    /**
     * @param {{ tenantId: string }} ctx
     * @param {string} id
     */
    async getEncryptedSecretById(ctx, id) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${ENCRYPTED_SECRET_COLUMNS}
           FROM encrypted_secrets
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        return mapEncryptedSecretRow(rows[0] ?? null);
      });
    },

    /**
     * Metadata-only connector scheduler lookup. Deliberately excludes envelope_json.
     * @param {{ tenantId: string }} ctx
     * @param {string} id
     */
    async getEncryptedSecretMetadataById(ctx, id) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, purpose, metadata_json, rotation, updated_at
           FROM encrypted_secrets
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        const row = rows[0];
        if (!row) return null;
        return {
          id: row.id,
          tenant_id: row.tenant_id,
          purpose: row.purpose,
          metadata: row.metadata_json ?? {},
          rotation: Number(row.rotation),
          updated_at: toIso(row.updated_at),
        };
      });
    },

    /**
     * @param {{ tenantId: string }} ctx
     * @param {string} id
     * @param {{ metadata?: Record<string, unknown>, rotation: number, envelope: Record<string, unknown>, updated_at: string }} patch
     */
    async updateEncryptedSecret(ctx, id, patch) {
      const tenantId = ctx.tenantId;
      const metadata =
        patch.metadata && typeof patch.metadata === 'object' ? patch.metadata : undefined;

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE encrypted_secrets
           SET metadata_json = COALESCE($3::jsonb, metadata_json),
               rotation = $4,
               envelope_json = $5::jsonb,
               updated_at = $6::timestamptz
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${ENCRYPTED_SECRET_COLUMNS}`,
          [
            tenantId,
            id,
            metadata === undefined ? null : JSON.stringify(metadata),
            patch.rotation,
            JSON.stringify(patch.envelope),
            patch.updated_at,
          ],
        );
        if (rows[0]) {
          await client.query(
            `WITH invalidated AS (
               UPDATE waf_connectors
               SET status = CASE
                     WHEN status IN ('disabled', 'revoked') THEN status
                     ELSE 'validating'
                   END,
                   last_success_at = NULL,
                   last_success_revision = 0,
                   poll_revision = poll_revision + 1,
                   updated_at = $3::timestamptz
               WHERE tenant_id = $1 AND secret_id = $2
               RETURNING id
             )
             UPDATE connector_poll_jobs
             SET status = 'cancelled', completed_at = $3::timestamptz,
                 error_code = 'connector_secret_rotated',
                 leased_by = NULL, leased_at = NULL, lease_token = NULL,
                 updated_at = $3::timestamptz
             WHERE tenant_id = $1 AND connector_id IN (SELECT id FROM invalidated)
               AND status IN ('pending', 'leased')`,
            [tenantId, id, patch.updated_at],
          );
          await client.query(
            `UPDATE probe_jobs
             SET status = 'cancelled', completed_at = $3::timestamptz
             WHERE tenant_id = $1 AND status IN ('pending', 'leased')
               AND constraints_json->'ownership_binding'->'provider_provenance'->>'connector_secret_id' = $2`,
            [tenantId, id, patch.updated_at],
          );
        }
        return mapEncryptedSecretRow(rows[0] ?? null);
      });
    },
  };
}