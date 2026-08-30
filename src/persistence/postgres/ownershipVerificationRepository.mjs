import {
  VERIFICATION_RANK,
  ownershipSummaryFromTargetStates,
} from '../../lib/ownershipPolicy.mjs';
import { withTenantContext } from './tenantContext.mjs';

const VERIFICATION_COLUMNS = `id, tenant_id, target_group_id, agent_id, declared_fqdn, status,
  challenge_nonce_hash, probe_observed, agent_observed, verified_at, confirmed_by_user_id,
  confirmed_at, probe_job_id, created_at, created_by`;

const OPEN_STATUSES = ['challenge_sent', 'verified'];

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function asObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  return null;
}

/**
 * @param {Record<string, unknown> | null | undefined} row
 */
function mapTargetVerificationRow(row) {
  if (!row) return null;
  return {
    ...row,
    transitioned_at: toIso(row.transitioned_at),
  };
}

export function mapOwnershipVerificationRow(row) {
  if (!row) return null;
  const mapped = {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id,
    agent_id: row.agent_id ?? null,
    declared_fqdn: row.declared_fqdn ?? null,
    status: row.status,
    challenge_nonce_hash: row.challenge_nonce_hash ?? null,
    probe_observed: Boolean(row.probe_observed),
    agent_observed: Boolean(row.agent_observed),
    verified_at: row.verified_at == null ? null : toIso(row.verified_at),
    confirmed_by_user_id: row.confirmed_by_user_id ?? null,
    confirmed_at: row.confirmed_at == null ? null : toIso(row.confirmed_at),
    created_at: toIso(row.created_at),
    created_by: row.created_by ?? null,
  };
  if (row.probe_job_id != null) mapped.probe_job_id = row.probe_job_id;
  return mapped;
}

async function lockActiveTargetBoundToChallenge(client, tenantId, record) {
  const { rows } = await client.query(
    `SELECT t.id, t.tenant_id, t.target_group_id, t.kind, t.value, t.normalized_value
     FROM target_groups tg
     JOIN targets t
       ON t.tenant_id = tg.tenant_id AND t.target_group_id = tg.id
     WHERE tg.tenant_id = $1 AND tg.id = $2
       AND tg.deleted_at IS NULL AND tg.archived_at IS NULL
       AND t.kind = 'fqdn' AND t.deleted_at IS NULL
       AND COALESCE(t.normalized_value, lower(btrim(t.value))) = lower(btrim($3))
       AND t.created_at <= $4::timestamptz
     ORDER BY t.created_at, t.id
     LIMIT 1
     FOR UPDATE OF tg, t`,
    [tenantId, record.target_group_id, record.declared_fqdn, record.created_at],
  );
  return rows[0] ?? null;
}

async function lockCurrentTargetVerification(client, tenantId, targetId) {
  const { rows } = await client.query(
    `SELECT id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at,
            transitioned_by, audit_entry_id
     FROM target_verifications
     WHERE tenant_id = $1 AND target_id = $2
     ORDER BY transitioned_at DESC,
              CASE state
                WHEN 'user_confirmed' THEN 4
                WHEN 'agent_verified' THEN 3
                WHEN 'dns_verified' THEN 2
                WHEN 'pending' THEN 1
                ELSE 0
              END DESC,
              id DESC
     LIMIT 1
     FOR UPDATE`,
    [tenantId, targetId],
  );
  return mapTargetVerificationRow(rows[0] ?? null);
}

async function recomputeTargetGroupOwnershipSummary(client, tenantId, targetGroupId) {
  const summaryResult = await client.query(
    `SELECT t.id AS target_id,
            (
              SELECT tv.state
              FROM target_verifications tv
              WHERE tv.tenant_id = t.tenant_id AND tv.target_id = t.id
              ORDER BY tv.transitioned_at DESC,
                       CASE tv.state
                         WHEN 'user_confirmed' THEN 4
                         WHEN 'agent_verified' THEN 3
                         WHEN 'dns_verified' THEN 2
                         WHEN 'pending' THEN 1
                         ELSE 0
                       END DESC,
                       tv.id DESC
              LIMIT 1
            ) AS state
     FROM targets t
     WHERE t.tenant_id = $1 AND t.target_group_id = $2 AND t.deleted_at IS NULL
     ORDER BY t.id`,
    [tenantId, targetGroupId],
  );
  const ownershipStatus = ownershipSummaryFromTargetStates(
    summaryResult.rows.map((row) => row.state ?? 'unverified'),
  );
  await client.query(
    `UPDATE target_groups
     SET ownership_status = $3
     WHERE tenant_id = $1 AND id = $2
       AND deleted_at IS NULL AND archived_at IS NULL`,
    [tenantId, targetGroupId, ownershipStatus],
  );
  return ownershipStatus;
}

/**
 * @param {import('pg').Pool} pool
 */
export function createOwnershipVerificationRepository(pool) {
  return {
    async insertVerification(ctx, record) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO ownership_verifications (
             id, tenant_id, target_group_id, agent_id, declared_fqdn, status,
             challenge_nonce_hash, probe_observed, agent_observed, verified_at,
             confirmed_by_user_id, confirmed_at, probe_job_id, created_at, created_by
           )
           VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10::timestamptz, $11, $12::timestamptz, $13,
             $14::timestamptz, $15
           )
           RETURNING ${VERIFICATION_COLUMNS}`,
          [
            record.id,
            ctx.tenantId,
            record.target_group_id,
            record.agent_id ?? null,
            record.declared_fqdn ?? null,
            record.status,
            record.challenge_nonce_hash,
            record.probe_observed ?? false,
            record.agent_observed ?? false,
            record.verified_at ?? null,
            record.confirmed_by_user_id ?? null,
            record.confirmed_at ?? null,
            record.probe_job_id ?? null,
            record.created_at,
            record.created_by ?? null,
          ],
        );
        return mapOwnershipVerificationRow(rows[0]);
      });
    },

    async setVerificationProbeJobId(ctx, id, probeJobId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE ownership_verifications
           SET probe_job_id = $3
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${VERIFICATION_COLUMNS}`,
          [ctx.tenantId, id, probeJobId],
        );
        return mapOwnershipVerificationRow(rows[0] ?? null);
      });
    },

    async findById(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VERIFICATION_COLUMNS}
           FROM ownership_verifications
           WHERE id = $1 AND tenant_id = $2`,
          [id, ctx.tenantId],
        );
        return mapOwnershipVerificationRow(rows[0] ?? null);
      });
    },

    async findOpenByNonceHash(ctx, nonceHash) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VERIFICATION_COLUMNS}
           FROM ownership_verifications
           WHERE tenant_id = $1
             AND challenge_nonce_hash = $2
             AND status = ANY($3::text[])`,
          [ctx.tenantId, nonceHash, OPEN_STATUSES],
        );
        return mapOwnershipVerificationRow(rows[0] ?? null);
      });
    },

    async listByTenant(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VERIFICATION_COLUMNS}
           FROM ownership_verifications
           WHERE tenant_id = $1
           ORDER BY created_at`,
          [ctx.tenantId],
        );
        return rows.map(mapOwnershipVerificationRow);
      });
    },

    async recordOwnershipSignalAtomic(ctx, input, auditRepo) {
      if (typeof auditRepo?.appendAuditEvent !== 'function') {
        throw new Error('Postgres ownership completion requires audit.appendAuditEvent().');
      }
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        let selected;
        if (input.verification_id) {
          selected = await client.query(
            `SELECT ${VERIFICATION_COLUMNS}
             FROM ownership_verifications
             WHERE tenant_id = $1 AND id = $2
             FOR UPDATE`,
            [ctx.tenantId, input.verification_id],
          );
        } else {
          selected = await client.query(
            `SELECT ${VERIFICATION_COLUMNS}
             FROM ownership_verifications
             WHERE tenant_id = $1
               AND challenge_nonce_hash = $2
               AND status = ANY($3::text[])
             ORDER BY created_at DESC
             LIMIT 1
             FOR UPDATE`,
            [ctx.tenantId, input.nonce_hash, OPEN_STATUSES],
          );
        }

        const record = mapOwnershipVerificationRow(selected.rows[0] ?? null);
        if (!record) return { error: 'ownership_verification_not_found', status: 404 };
        if (!OPEN_STATUSES.includes(record.status)) {
          return { error: 'ownership_verification_not_open', status: 409 };
        }
        if (input.nonce_hash !== record.challenge_nonce_hash) {
          return { error: 'nonce_mismatch', status: 400 };
        }
        if (input.source !== 'probe' && input.source !== 'agent') {
          return { error: 'invalid_source', status: 400 };
        }

        const probeObserved = record.probe_observed || input.source === 'probe';
        const agentObserved = record.agent_observed || input.source === 'agent';
        const completesChallenge =
          probeObserved && agentObserved && record.status === 'challenge_sent';

        if (!completesChallenge) {
          const { rows } = await client.query(
            `UPDATE ownership_verifications
             SET probe_observed = $3, agent_observed = $4
             WHERE tenant_id = $1 AND id = $2
             RETURNING ${VERIFICATION_COLUMNS}`,
            [ctx.tenantId, record.id, probeObserved, agentObserved],
          );
          return { verification: mapOwnershipVerificationRow(rows[0] ?? null) };
        }

        const observedAt = new Date(input.observed_at);
        if (!Number.isFinite(observedAt.getTime())) {
          throw new Error('Ownership signal has an invalid observed_at timestamp.');
        }
        const target = await lockActiveTargetBoundToChallenge(
          client,
          ctx.tenantId,
          record,
        );
        if (!target) return { error: 'ownership_target_not_active', status: 409 };

        const current = await lockCurrentTargetVerification(client, ctx.tenantId, target.id);
        let targetVerification = current;
        if ((VERIFICATION_RANK[current?.state] ?? 0) < VERIFICATION_RANK.agent_verified) {
          const targetAudit = await auditRepo.appendAuditEvent({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId ?? null,
            actor_role: ctx.role ?? 'system',
            action: 'target_verification.agent_verified',
            resource_type: 'target_verification',
            resource_id: input.target_verification_id,
            metadata: {
              target_id: target.id,
              target_group_id: record.target_group_id,
              ownership_verification_id: record.id,
              agent_id: record.agent_id,
            },
          }, { client, now: observedAt });
          const inserted = await client.query(
            `INSERT INTO target_verifications (
               id, tenant_id, target_id, state, source_kind, source_ref,
               transitioned_at, transitioned_by, audit_entry_id
             ) VALUES ($1,$2,$3,'agent_verified','agent_observation',$4::jsonb,$5::timestamptz,$6,$7)
             RETURNING id, tenant_id, target_id, state, source_kind, source_ref,
                       transitioned_at, transitioned_by, audit_entry_id`,
            [
              input.target_verification_id,
              ctx.tenantId,
              target.id,
              JSON.stringify({
                ownership_verification_id: record.id,
                agent_id: record.agent_id,
                declared_fqdn: record.declared_fqdn,
              }),
              observedAt.toISOString(),
              input.transitioned_by,
              targetAudit.id,
            ],
          );
          targetVerification = mapTargetVerificationRow(inserted.rows[0]);
        }

        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId ?? null,
          actor_role: ctx.role ?? 'system',
          action: 'ownership_verification.agent_verified',
          resource_type: 'ownership_verification',
          resource_id: record.id,
          metadata: { target_group_id: record.target_group_id, target_id: target.id },
        }, { client, now: observedAt });

        const updated = await client.query(
          `UPDATE ownership_verifications
           SET probe_observed = $3, agent_observed = $4,
               status = 'verified', verified_at = $5::timestamptz
           WHERE tenant_id = $1 AND id = $2 AND status = 'challenge_sent'
           RETURNING ${VERIFICATION_COLUMNS}`,
          [ctx.tenantId, record.id, probeObserved, agentObserved, observedAt.toISOString()],
        );
        if (!updated.rows[0]) throw new Error('Ownership verification completion CAS failed.');

        const ownershipStatus = await recomputeTargetGroupOwnershipSummary(
          client,
          ctx.tenantId,
          record.target_group_id,
        );

        return {
          verification: mapOwnershipVerificationRow(updated.rows[0]),
          target_id: target.id,
          target_verification: targetVerification,
          ownership_status: ownershipStatus,
        };
      });
    },

    async confirmOwnershipAtomic(ctx, input, auditRepo) {
      if (typeof auditRepo?.appendAuditEvent !== 'function') {
        throw new Error('Postgres ownership confirmation requires audit.appendAuditEvent().');
      }
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const selected = await client.query(
          `SELECT ${VERIFICATION_COLUMNS}
           FROM ownership_verifications
           WHERE tenant_id = $1 AND id = $2
           FOR UPDATE`,
          [ctx.tenantId, input.verification_id],
        );
        const record = mapOwnershipVerificationRow(selected.rows[0] ?? null);
        if (!record) return { error: 'ownership_verification_not_found', status: 404 };
        if (record.status !== 'verified') {
          return { error: 'ownership_not_verified', status: 409 };
        }

        const confirmedAt = new Date(input.confirmed_at);
        if (!Number.isFinite(confirmedAt.getTime())) {
          throw new Error('Ownership confirmation has an invalid confirmed_at timestamp.');
        }
        const target = await lockActiveTargetBoundToChallenge(
          client,
          ctx.tenantId,
          record,
        );
        if (!target) return { error: 'ownership_target_not_active', status: 409 };

        const current = await lockCurrentTargetVerification(client, ctx.tenantId, target.id);
        let targetVerification = current;
        if ((VERIFICATION_RANK[current?.state] ?? 0) < VERIFICATION_RANK.user_confirmed) {
          const targetAudit = await auditRepo.appendAuditEvent({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId ?? null,
            actor_role: ctx.role ?? 'system',
            action: 'target_verification.user_confirmed',
            resource_type: 'target_verification',
            resource_id: input.target_verification_id,
            metadata: {
              target_id: target.id,
              target_group_id: record.target_group_id,
              ownership_verification_id: record.id,
            },
          }, { client, now: confirmedAt });
          const inserted = await client.query(
            `INSERT INTO target_verifications (
               id, tenant_id, target_id, state, source_kind, source_ref,
               transitioned_at, transitioned_by, audit_entry_id
             ) VALUES ($1,$2,$3,'user_confirmed','user_attestation',$4::jsonb,$5::timestamptz,$6,$7)
             RETURNING id, tenant_id, target_id, state, source_kind, source_ref,
                       transitioned_at, transitioned_by, audit_entry_id`,
            [
              input.target_verification_id,
              ctx.tenantId,
              target.id,
              JSON.stringify({
                ownership_verification_id: record.id,
                agent_id: record.agent_id,
                declared_fqdn: record.declared_fqdn,
                confirmed_by_user_id: input.confirmed_by_user_id,
              }),
              confirmedAt.toISOString(),
              input.transitioned_by,
              targetAudit.id,
            ],
          );
          targetVerification = mapTargetVerificationRow(inserted.rows[0]);
        }

        const firstConfirmation = record.confirmed_at == null;
        const updated = await client.query(
          `UPDATE ownership_verifications
           SET confirmed_by_user_id = COALESCE(confirmed_by_user_id, $3),
               confirmed_at = COALESCE(confirmed_at, $4::timestamptz)
           WHERE tenant_id = $1 AND id = $2 AND status = 'verified'
           RETURNING ${VERIFICATION_COLUMNS}`,
          [
            ctx.tenantId,
            record.id,
            input.confirmed_by_user_id,
            confirmedAt.toISOString(),
          ],
        );
        if (!updated.rows[0]) throw new Error('Ownership confirmation CAS failed.');

        if (firstConfirmation) {
          await auditRepo.appendAuditEvent({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId ?? null,
            actor_role: ctx.role ?? 'system',
            action: 'ownership_verification.user_confirmed',
            resource_type: 'ownership_verification',
            resource_id: record.id,
            metadata: { target_group_id: record.target_group_id, target_id: target.id },
          }, { client, now: confirmedAt });
        }

        const ownershipStatus = await recomputeTargetGroupOwnershipSummary(
          client,
          ctx.tenantId,
          record.target_group_id,
        );
        return {
          verification: mapOwnershipVerificationRow(updated.rows[0]),
          target_id: target.id,
          target_verification: targetVerification,
          ownership_status: ownershipStatus,
        };
      });
    },

    async updateVerificationSignals(ctx, id, patch) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE ownership_verifications
           SET probe_observed = COALESCE($3, probe_observed),
               agent_observed = COALESCE($4, agent_observed),
               status = COALESCE($5, status),
               verified_at = COALESCE($6::timestamptz, verified_at)
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${VERIFICATION_COLUMNS}`,
          [
            ctx.tenantId,
            id,
            patch.probe_observed ?? null,
            patch.agent_observed ?? null,
            patch.status ?? null,
            patch.verified_at ?? null,
          ],
        );
        return mapOwnershipVerificationRow(rows[0] ?? null);
      });
    },

    async updateVerificationConfirmed(ctx, id, { confirmed_by_user_id, confirmed_at }) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE ownership_verifications
           SET confirmed_by_user_id = $3,
               confirmed_at = $4::timestamptz
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${VERIFICATION_COLUMNS}`,
          [ctx.tenantId, id, confirmed_by_user_id, confirmed_at],
        );
        return mapOwnershipVerificationRow(rows[0] ?? null);
      });
    },

    async updateTargetGroupOwnershipStatus(ctx, targetGroupId, ownershipStatus) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        await client.query(
          `UPDATE target_groups
           SET ownership_status = $3
           WHERE tenant_id = $1 AND id = $2 AND archived_at IS NULL`,
          [ctx.tenantId, targetGroupId, ownershipStatus],
        );
      });
    },

    async updateTargetGroupDnsOwnership(ctx, targetGroupId, { dns_ownership, ownership_status }) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const sets = ['dns_ownership = $3::jsonb'];
        const params = [ctx.tenantId, targetGroupId, JSON.stringify(dns_ownership ?? null)];
        if (ownership_status !== undefined) {
          sets.push(`ownership_status = $${params.length + 1}`);
          params.push(ownership_status);
        }
        await client.query(
          `UPDATE target_groups
           SET ${sets.join(', ')}
           WHERE tenant_id = $1 AND id = $2 AND archived_at IS NULL`,
          params,
        );
      });
    },

    async getCurrentTargetVerification(ctx, targetGroupId, targetId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT tv.id, tv.tenant_id, tv.target_id, tv.state, tv.source_kind,
                  tv.source_ref, tv.transitioned_at, tv.transitioned_by, tv.audit_entry_id
           FROM target_groups tg
           JOIN targets t
             ON t.tenant_id = tg.tenant_id AND t.target_group_id = tg.id
           JOIN LATERAL (
             SELECT candidate.*
             FROM target_verifications candidate
             WHERE candidate.tenant_id = t.tenant_id AND candidate.target_id = t.id
             ORDER BY candidate.transitioned_at DESC,
                      CASE candidate.state
                        WHEN 'user_confirmed' THEN 4
                        WHEN 'agent_verified' THEN 3
                        WHEN 'dns_verified' THEN 2
                        WHEN 'pending' THEN 1
                        ELSE 0
                      END DESC,
                      candidate.id DESC
             LIMIT 1
           ) tv ON true
           WHERE tg.tenant_id = $1 AND tg.id = $2 AND t.id = $3
             AND tg.deleted_at IS NULL AND tg.archived_at IS NULL
             AND t.deleted_at IS NULL`,
          [ctx.tenantId, targetGroupId, targetId],
        );
        return mapTargetVerificationRow(rows[0] ?? null);
      });
    },

    async listFqdnTargetValues(ctx, targetGroupId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT value
           FROM targets
           WHERE tenant_id = $1 AND target_group_id = $2 AND kind = 'fqdn'
             AND deleted_at IS NULL
           ORDER BY created_at`,
          [ctx.tenantId, targetGroupId],
        );
        return rows.map((row) => String(row.value).trim().toLowerCase());
      });
    },

    async getActiveTargetGroup(ctx, targetGroupId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, validation_mode, ownership_status, dns_ownership, archived_at
           FROM target_groups
           WHERE tenant_id = $1 AND id = $2 AND archived_at IS NULL`,
          [ctx.tenantId, targetGroupId],
        );
        const row = rows[0];
        if (!row) return null;
        return {
          id: row.id,
          tenant_id: row.tenant_id,
          validation_mode: row.validation_mode ?? 'agent_assisted',
          ownership_status: row.ownership_status ?? 'unverified',
          dns_ownership: asObject(row.dns_ownership),
        };
      });
    },
  };
}