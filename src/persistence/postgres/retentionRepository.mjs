import { buildAuditRecord } from '../../audit.mjs';
import { normalizePrivacySettings } from '../../lib/privacySettings.mjs';
import {
  buildMetadataRetentionCutoffs,
  buildRetentionPolicySnapshot,
  emptyOriginClueCounts,
} from '../../services/privacyRetention.mjs';
import { withTenantContext } from './tenantContext.mjs';

const LAST_AUDIT_ROW_SQL = `SELECT id, tenant_id, timestamp, sequence, prev_hash, entry_hash,
                  actor_user_id, actor_role, action, resource_type, resource_id, metadata_json
           FROM audit_logs
           WHERE tenant_id = $1
           ORDER BY sequence DESC
           LIMIT 1`;

const INSERT_AUDIT_SQL = `INSERT INTO audit_logs (
             id, tenant_id, timestamp, sequence, prev_hash, entry_hash,
             actor_user_id, actor_role, action, resource_type, resource_id, metadata_json
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb)`;

const RETENTION_COLLECTIONS = Object.freeze([
  { key: 'events', table: 'events', timestampColumn: 'timestamp' },
  { key: 'evidenceVault', table: 'evidence_vault', timestampColumn: 'created_at' },
  { key: 'reports', table: 'reports', timestampColumn: 'created_at' },
  { key: 'notificationEvents', table: 'notification_events', timestampColumn: 'created_at' },
  {
    key: 'connectorPollJobs',
    table: 'connector_poll_jobs',
    timestampColumn: 'created_at',
    extraWhere: "status IN ('completed', 'failed', 'cancelled')",
  },
  {
    key: 'connectorSnapshots',
    table: 'waf_connector_snapshots',
    timestampColumn: 'created_at',
    extraWhere: `NOT EXISTS (
      SELECT 1 FROM waf_connectors current_connector
      WHERE current_connector.tenant_id = waf_connector_snapshots.tenant_id
        AND current_connector.id = waf_connector_snapshots.connector_id
        AND current_connector.last_success_revision = waf_connector_snapshots.poll_revision
        AND current_connector.last_success_at = waf_connector_snapshots.observed_at
    )`,
  },
]);

function rowToAuditEntry(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    timestamp: row.timestamp instanceof Date ? row.timestamp.toISOString() : String(row.timestamp),
    sequence: Number(row.sequence),
    prev_hash: row.prev_hash ?? null,
    entry_hash: row.entry_hash,
    actor_user_id: row.actor_user_id ?? null,
    actor_role: row.actor_role ?? null,
    action: row.action,
    resource_type: row.resource_type ?? null,
    resource_id: row.resource_id ?? null,
    metadata: row.metadata_json ?? {},
  };
}

function auditInsertParams(entry) {
  return [
    entry.id,
    entry.tenant_id,
    entry.timestamp,
    entry.sequence,
    entry.prev_hash ?? null,
    entry.entry_hash,
    entry.actor_user_id ?? null,
    entry.actor_role ?? null,
    entry.action,
    entry.resource_type ?? null,
    entry.resource_id ?? null,
    JSON.stringify(entry.metadata ?? {}),
  ];
}

function zeroCounts() {
  return {
    events: 0,
    evidenceVault: 0,
    reports: 0,
    notificationEvents: 0,
    connectorPollJobs: 0,
    connectorSnapshots: 0,
    ...emptyOriginClueCounts(),
  };
}

function totalCounts(counts) {
  return Object.values(counts).reduce((total, value) => total + Number(value ?? 0), 0);
}

async function countCandidates(client, tenantId, nowIso, privacy) {
  const { metadataCutoffMs, reportCutoffMs } = buildMetadataRetentionCutoffs(privacy, nowIso);
  const cutoffs = {
    events: new Date(metadataCutoffMs).toISOString(),
    evidenceVault: new Date(metadataCutoffMs).toISOString(),
    reports: new Date(reportCutoffMs).toISOString(),
    notificationEvents: new Date(metadataCutoffMs).toISOString(),
    connectorPollJobs: new Date(metadataCutoffMs).toISOString(),
    connectorSnapshots: new Date(metadataCutoffMs).toISOString(),
  };

  const counts = zeroCounts();
  for (const collection of RETENTION_COLLECTIONS) {
    const cutoffIso = cutoffs[collection.key];
    const { rows } = await client.query(
      `SELECT COUNT(*)::int AS count
       FROM ${collection.table}
       WHERE tenant_id = $1 AND ${collection.timestampColumn} < $2::timestamptz
         ${collection.extraWhere ? `AND (${collection.extraWhere})` : ''}`,
      [tenantId, cutoffIso],
    );
    counts[collection.key] = Number(rows[0]?.count ?? 0);
  }

  const originPlan = await readOriginPlan(client, tenantId, new Date(metadataCutoffMs).toISOString(), false);
  Object.assign(counts, originPlan.counts);
  return { counts, cutoffs, originPlan };
}

async function readOriginPlan(client, tenantId, cutoff, erase) {
  const { rows } = await client.query(
    'SELECT public.astranull_origin_clue_lifecycle_plan($1, $2::timestamptz, $3::boolean) AS plan',
    [tenantId, cutoff, erase]);
  return rows[0]?.plan ?? { counts: emptyOriginClueCounts(), plan_digest: null };
}
function originAuditPlan(plan, mode, now) {
  return { mode, at: now.toISOString(), counts: plan.counts, plan_digest: plan.plan_digest };
}
async function applyOriginPlan(client, tenantId, audit, mode, now) {
  const { rows } = await client.query(
    'SELECT public.astranull_apply_origin_clue_lifecycle($1, $2, $3, $4::timestamptz) AS counts',
    [tenantId, audit.id, mode, now.toISOString()]);
  return rows[0].counts;
}

async function deleteCandidates(client, tenantId, cutoffs) {
  const deleted = zeroCounts();
  for (const collection of RETENTION_COLLECTIONS) {
    const cutoffIso = cutoffs[collection.key];
    const result = await client.query(
      `DELETE FROM ${collection.table}
       WHERE tenant_id = $1 AND ${collection.timestampColumn} < $2::timestamptz
         ${collection.extraWhere ? `AND (${collection.extraWhere})` : ''}`,
      [tenantId, cutoffIso],
    );
    deleted[collection.key] = Number(result.rowCount ?? 0);
  }
  return deleted;
}

async function appendAuditEventInTransaction(client, entry, now) {
  await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [entry.tenant_id]);
  const { rows } = await client.query(LAST_AUDIT_ROW_SQL, [entry.tenant_id]);
  const priorEntry = rowToAuditEntry(rows[0] ?? null);
  const record = buildAuditRecord(entry, priorEntry, now);
  await client.query(INSERT_AUDIT_SQL, auditInsertParams(record));
  return record;
}

/**
 * @param {import('pg').Pool} pool
 */
export function createRetentionRepository(pool) {
  return {
    /**
     * @param {string} tenantId
     * @param {{ userId?: string | null, role?: string | null }} [auditContext]
     * @param {{ dryRun?: boolean, now?: Date }} [options]
     */
    async runOriginClueErasure(tenantId, auditContext, request, options = {}) {
      const now = new Date(options.now ?? Date.now());
      return withTenantContext(pool, tenantId, async (client) => {
        await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [tenantId]);
        const { rows } = await client.query('SELECT id, privacy_settings FROM tenants WHERE id = $1 FOR UPDATE', [tenantId]);
        const tenant = rows[0];
        if (!tenant) return { error: 'not_found', status: 404 };
        const privacy = normalizePrivacySettings(tenant.privacy_settings);
        if (!request.dry_run && JSON.stringify(tenant.privacy_settings) !== JSON.stringify(privacy)) {
          await client.query('UPDATE tenants SET privacy_settings = $2::jsonb WHERE id = $1', [tenantId, JSON.stringify(privacy)]);
        }
        const cutoff = new Date(buildMetadataRetentionCutoffs(privacy, now).metadataCutoffMs).toISOString();
        const plan = await readOriginPlan(client, tenantId, cutoff, true);
        const held = privacy.evidence_retention.legal_hold;
        const deleted = held || request.dry_run ? emptyOriginClueCounts() : plan.counts;
        const policy = buildRetentionPolicySnapshot({ ...tenant, privacy_settings: privacy });
        const summary = { tenant_id: tenantId, dry_run: request.dry_run, legal_hold: held, deleted,
          would_delete: plan.counts, blocked_deletions: held ? plan.counts : emptyOriginClueCounts(),
          metadata_retention_days: privacy.metadata_retention_days, policy_snapshot: policy, audit_entry_id: null };
        if (request.dry_run) return summary;
        const auditEntry = await appendAuditEventInTransaction(client, {
          tenant_id: tenantId, actor_user_id: auditContext.userId ?? null, actor_role: auditContext.role,
          action: held ? 'privacy.origin_clues_erasure_blocked' : 'privacy.origin_clues_erased',
          resource_type: 'tenant', resource_id: tenantId,
          metadata: { confirmation_tenant_id: tenantId, reason: request.reason, deleted,
            blocked_deletions: summary.blocked_deletions, policy_snapshot: policy,
            origin_lifecycle: originAuditPlan(plan, 'erase', now) },
        }, now);
        if (!held) summary.deleted = await applyOriginPlan(client, tenantId, auditEntry, 'erase', now);
        summary.audit_entry_id = auditEntry.id;
        return held ? { ...summary, error: 'origin_clue_erasure_legal_hold', status: 409 } : summary;
      });
    },

    async runMetadataRetention(tenantId, auditContext = {}, options = {}) {
      const normalizedTenantId = String(tenantId ?? '').trim();
      if (!normalizedTenantId) {
        throw new Error('tenant id must be a non-empty string.');
      }

      const now = options.now instanceof Date ? options.now : new Date(options.now ?? Date.now());
      const dryRun = options.dryRun === true;

      return withTenantContext(pool, normalizedTenantId, async (client) => {
        await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [normalizedTenantId]);
        const tenantResult = await client.query(
          `SELECT id, privacy_settings
           FROM tenants
           WHERE id = $1
           FOR UPDATE`,
          [normalizedTenantId],
        );
        const tenantRow = tenantResult.rows[0] ?? null;
        if (!tenantRow) {
          return null;
        }

        const originalPrivacy = tenantRow.privacy_settings ?? {};
        const privacy = normalizePrivacySettings(originalPrivacy);
        if (!dryRun && JSON.stringify(originalPrivacy) !== JSON.stringify(privacy)) {
          await client.query(
            `UPDATE tenants
             SET privacy_settings = $2::jsonb
             WHERE id = $1`,
            [normalizedTenantId, JSON.stringify(privacy)],
          );
        }

        return runMetadataRetentionInTransaction(
          client,
          normalizedTenantId,
          { id: tenantRow.id, privacy_settings: privacy },
          auditContext,
          { dryRun, now },
        );
      });
    },
  };
}

export async function runMetadataRetentionInTransaction(
  client,
  tenantId,
  tenant,
  auditContext = {},
  options = {},
) {
  const normalizedTenantId = String(tenantId ?? '').trim();
  if (!normalizedTenantId) {
    throw new Error('tenant id must be a non-empty string.');
  }

  const now = options.now instanceof Date ? options.now : new Date(options.now ?? Date.now());
  const dryRun = options.dryRun === true;
  const privacy = normalizePrivacySettings(tenant?.privacy_settings ?? {});
  const policySnapshot = buildRetentionPolicySnapshot({
    id: tenant?.id ?? normalizedTenantId,
    privacy_settings: privacy,
  });
  const { counts, cutoffs, originPlan } = await countCandidates(
    client,
    normalizedTenantId,
    now.toISOString(),
    privacy,
  );

  if (dryRun) {
    return {
      tenant_id: normalizedTenantId,
      dry_run: true,
      deleted: zeroCounts(),
      would_delete: counts,
      blocked_deletions: privacy.evidence_retention.legal_hold ? counts : zeroCounts(),
      metadata_retention_days: privacy.metadata_retention_days,
      evidence_retention: privacy.evidence_retention,
      policy_snapshot: policySnapshot,
      legal_hold: privacy.evidence_retention.legal_hold,
    };
  }

  if (privacy.evidence_retention.legal_hold) {
    if (totalCounts(counts) > 0) {
      await appendAuditEventInTransaction(
        client,
        {
          tenant_id: normalizedTenantId,
          actor_user_id: auditContext.userId ?? null,
          actor_role: auditContext.role ?? 'system',
          action: 'privacy.retention_legal_hold',
          resource_type: 'tenant',
          resource_id: normalizedTenantId,
          metadata: {
            deleted: zeroCounts(),
            blocked_deletions: counts,
            policy_snapshot: policySnapshot,
          },
        },
        now,
      );
    }

    return {
      tenant_id: normalizedTenantId,
      dry_run: false,
      deleted: zeroCounts(),
      would_delete: counts,
      blocked_deletions: counts,
      metadata_retention_days: privacy.metadata_retention_days,
      evidence_retention: privacy.evidence_retention,
      policy_snapshot: policySnapshot,
      legal_hold: true,
    };
  }

  const deleted =
    totalCounts(counts) > 0 ? await deleteCandidates(client, normalizedTenantId, cutoffs) : zeroCounts();
  Object.assign(deleted, originPlan.counts);
  if (totalCounts(deleted) > 0) {
    const auditEntry = await appendAuditEventInTransaction(
      client,
      {
        tenant_id: normalizedTenantId,
        actor_user_id: auditContext.userId ?? null,
        actor_role: auditContext.role ?? 'system',
        action: 'privacy.retention_purged',
        resource_type: 'tenant',
        resource_id: normalizedTenantId,
        metadata: {
          deleted,
          metadata_retention_days: privacy.metadata_retention_days,
          policy_snapshot: policySnapshot,
          origin_lifecycle: originAuditPlan(originPlan, 'expiry', now),
        },
      },
      now,
    );
    if (totalCounts(originPlan.counts)) Object.assign(deleted,
      await applyOriginPlan(client, normalizedTenantId, auditEntry, 'expiry', now));
  }

  return {
    tenant_id: normalizedTenantId,
    dry_run: false,
    deleted,
    would_delete: counts,
    blocked_deletions: zeroCounts(),
    metadata_retention_days: privacy.metadata_retention_days,
    evidence_retention: privacy.evidence_retention,
    policy_snapshot: policySnapshot,
    legal_hold: false,
  };
}
