/**
 * Tenant-scoped batch read of active declared targets.
 * Joins the target group, the effective verification view, and the current
 * edge-detection row. Does not call getTargetDetail or WAF-asset rollups.
 * declaration_json is migration 0063. This file does not change that migration.
 */
import { presentTargetDeclaration } from '../../lib/targetDeclarations.mjs';
import {
  presentDeclaredTargetObservation,
  queryDeclaredHostAnalyticsFromReader,
} from '../../services/declaredHostAnalytics.mjs';
import { DeclaredHostQueryError } from '../../lib/declaredHostAnalytics.mjs';

export { DECLARED_HOST_BATCH_SIZE, DECLARED_HOST_ROW_BOUND } from '../../lib/declaredHostAnalytics.mjs';

/**
 * Static parameterized statement. Tenant, keyset, and limit are bound values.
 * evidence_json, source_ref, and metadata blobs are not selected. Tags are the tags array only.
 * verification_state is target_verification_current.state (feature and source invalidation).
 * A disabled feature or a provider source that is not current is pending. Status only.
 */
export const DECLARED_HOST_BATCH_SQL = `
SELECT
  t.id,
  t.tenant_id,
  t.target_group_id,
  t.kind,
  t.value,
  t.normalized_value,
  t.deleted_at,
  t.declaration_json,
  tg.declaration_json AS group_declaration_json,
  tg.name AS target_group_name,
  tg.archived_at AS group_archived_at,
  COALESCE((
    SELECT array_agg(lower(btrim(tag.value)))
    FROM jsonb_array_elements_text(
      CASE
        WHEN jsonb_typeof(COALESCE(t.metadata_json, '{}'::jsonb) -> 'tags') = 'array'
          THEN COALESCE(t.metadata_json, '{}'::jsonb) -> 'tags'
        ELSE '[]'::jsonb
      END
    ) AS tag(value)
    WHERE btrim(tag.value) <> ''
  ), ARRAY[]::text[]) AS tags,
  verification.state AS verification_state,
  ed.id AS edge_id,
  ed.waf_status,
  ed.cdn_status,
  ed.waf_vendor,
  ed.cdn_provider,
  ed.conflicting_vendor_signals,
  ed.observed_at AS edge_observed_at,
  ed.cloud_status,
  ed.cloud_provider,
  (
    SELECT COUNT(*)::int
    FROM findings f
    WHERE f.tenant_id = t.tenant_id
      AND f.target_id = t.id
      AND f.status = 'open'
  ) AS findings_count,
  (
    SELECT MAX(tr.completed_at)
    FROM test_runs tr
    WHERE tr.tenant_id = t.tenant_id
      AND tr.target_id = t.id
  ) AS last_validation_at
FROM targets t
JOIN target_groups tg
  ON tg.tenant_id = t.tenant_id
 AND tg.id = t.target_group_id
LEFT JOIN target_edge_detections ed
  ON ed.tenant_id = t.tenant_id
 AND ed.target_id = t.id
LEFT JOIN target_verification_current verification
  ON verification.tenant_id = t.tenant_id
 AND verification.target_id = t.id
WHERE t.tenant_id = $1
  AND t.deleted_at IS NULL
  AND tg.deleted_at IS NULL
  AND tg.archived_at IS NULL
  AND ($2::text IS NULL OR t.id > $2)
ORDER BY t.id
LIMIT $3
`;

function isoOrNull(value) {
  if (value == null) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

/**
 * Default projector. Declaration uses `presentTargetDeclaration`.
 * Families use deriveProtectionProfile at `options.now` (the cohort clock).
 * `edge_observed_at` is the observation clock. evidence_json is not read.
 *
 * @param {object} raw
 * @param {{ now?: unknown }} [options]
 */
export function presentDeclaredTargetRow(raw, options = {}) {
  const findings = Number(raw.findings_count);
  return {
    id: raw.id,
    tenant_id: raw.tenant_id,
    target_group_id: raw.target_group_id,
    target_group_name: raw.target_group_name ?? null,
    kind: raw.kind,
    value: raw.value,
    normalized_value: raw.normalized_value,
    tags: Array.isArray(raw.tags) ? raw.tags : [],
    verification_state: raw.verification_state ?? null,
    declaration: presentTargetDeclaration(raw.declaration_json, raw.group_declaration_json),
    protection_profile: presentDeclaredTargetObservation(raw, options),
    last_validation_at: isoOrNull(raw.last_validation_at),
    findings_count: Number.isInteger(findings) && findings >= 0 ? findings : null,
    edge_conflict: raw.conflicting_vendor_signals === true,
    edge_cloud: raw.edge_id != null && raw.cloud_status != null
      ? { status: raw.cloud_status, provider: raw.cloud_provider ?? null }
      : null,
  };
}

/**
 * One repeatable-read snapshot for every batch of this request.
 * A caller-owned client keeps the transaction it already has.
 *
 * @param {import('pg').Pool} pool
 * @param {string} tenantId
 * @param {(client: import('pg').PoolClient) => Promise<unknown>} callback
 */
async function withRepeatableTenantRead(pool, tenantId, callback) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
    await client.query(`SELECT set_config('app.tenant_id', $1, true)`, [tenantId]);
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // preserve the original error
    }
    throw err;
  } finally {
    client.release();
  }
}

/**
 * @param {import('pg').PoolClient} client
 * @param {string} tenantId
 * @param {{ afterId?: string | null, limit: number }} page
 */
export async function fetchDeclaredTargetBatch(client, tenantId, { afterId = null, limit }) {
  const { rows } = await client.query(DECLARED_HOST_BATCH_SQL, [tenantId, afterId, limit]);
  return rows;
}

/**
 * @param {import('pg').Pool | import('pg').PoolClient} db
 * @param {string} tenantId
 * @param {unknown} query
 * @param {{ asOf?: unknown, presentRow?: (raw: object) => object, batchSize?: number, rowBound?: number }} [options]
 */
export async function readDeclaredHostAnalytics(db, tenantId, query, options = {}) {
  const tenant = String(tenantId ?? '').trim();
  if (!tenant) {
    throw new DeclaredHostQueryError('invalid_tenant', 'Tenant id is required.', 'tenant_id');
  }
  const now = options.asOf ?? null;
  const present = options.presentRow ?? ((raw) => presentDeclaredTargetRow(raw, { now }));
  const run = (client) => queryDeclaredHostAnalyticsFromReader(async ({ afterId, limit }) => {
    const raws = await fetchDeclaredTargetBatch(client, tenant, { afterId, limit });
    const projectedRows = [];
    for (const raw of raws) {
      const projected = await present(raw);
      if (!projected || typeof projected !== 'object') {
        throw new DeclaredHostQueryError('invalid_presenter', 'presentRow must return an object.', 'presentRow');
      }
      projectedRows.push(projected.id ? projected : { ...projected, id: raw.id });
    }
    return projectedRows;
  }, query, options);

  if (typeof db.release === 'function') return run(db);
  return withRepeatableTenantRead(db, tenant, run);
}
