import { randomUUID } from 'node:crypto';
import { SCAN_LEASE_MS } from '../../contracts/validationScanManagement.mjs';
import { redactObject } from '../../lib/redact.mjs';
import { createAuditRepository } from './auditRepository.mjs';
import { runWithTenantClient, withTenantContext } from './tenantContext.mjs';

export const VALIDATION_SCAN_COLUMNS = `id, tenant_id, target_group_id, target_id, name, status, check_ids, plan_snapshot,
  scheduled_for, recurrence, recurrence_series_id, occurrence_key, occurrence_index, previous_scan_id, next_scan_id,
  dispatched_at, started_at, completed_at, abort_reason, cancel_reason, cancelled_by, cancelled_by_role, cancelled_at,
  created_by, created_by_role, lease_token, lease_owner, lease_expires_at, next_eligible_at, revision, summary,
  created_at, updated_at`;

export const VALIDATION_SCAN_STEP_COLUMNS = `id, tenant_id, scan_id, position, check_id, check_name, target_id, status,
  test_run_id, error_code, skip_reason, eligible_at, attempts, request_snapshot, started_at, completed_at,
  created_at, updated_at`;

const AUDIT_COLUMNS = `id, tenant_id, timestamp, sequence, prev_hash, entry_hash,
  actor_user_id, actor_role, action, resource_type, resource_id, metadata_json`;

const SCAN_TEXT_FIELDS = [
  'target_group_id', 'target_id', 'name', 'status', 'recurrence_series_id', 'occurrence_key', 'previous_scan_id',
  'next_scan_id', 'abort_reason', 'cancel_reason', 'cancelled_by', 'cancelled_by_role', 'created_by',
  'created_by_role', 'lease_token', 'lease_owner',
];
const SCAN_TIMESTAMP_FIELDS = [
  'scheduled_for', 'dispatched_at', 'started_at', 'completed_at', 'cancelled_at', 'lease_expires_at',
  'next_eligible_at', 'updated_at',
];
const SCAN_JSON_FIELDS = ['check_ids', 'plan_snapshot', 'recurrence', 'summary'];
const SCAN_NUMERIC_FIELDS = ['occurrence_index', 'revision'];

const STEP_TEXT_FIELDS = ['check_id', 'check_name', 'target_id', 'status', 'test_run_id', 'error_code', 'skip_reason'];
const STEP_TIMESTAMP_FIELDS = ['eligible_at', 'started_at', 'completed_at', 'updated_at'];
const STEP_JSON_FIELDS = ['request_snapshot'];
const STEP_NUMERIC_FIELDS = ['attempts', 'position'];

const MAX_SCAN_LIST_LIMIT = 200;
const MAX_ACTIVITY_LIMIT = 500;
const MAX_RUN_ID_BATCH = 500;

function toIso(value) {
  if (value == null) return null;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function asObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  return {};
}

export function mapValidationScanRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id,
    target_id: row.target_id ?? null,
    name: row.name ?? null,
    status: row.status,
    check_ids: asArray(row.check_ids),
    plan_snapshot: asObject(row.plan_snapshot),
    scheduled_for: toIso(row.scheduled_for),
    recurrence: row.recurrence == null ? null : asObject(row.recurrence),
    recurrence_series_id: row.recurrence_series_id ?? row.id,
    occurrence_key: row.occurrence_key ?? null,
    occurrence_index: Number(row.occurrence_index ?? 0),
    previous_scan_id: row.previous_scan_id ?? null,
    next_scan_id: row.next_scan_id ?? null,
    dispatched_at: toIso(row.dispatched_at),
    started_at: toIso(row.started_at),
    completed_at: toIso(row.completed_at),
    abort_reason: row.abort_reason ?? null,
    cancel_reason: row.cancel_reason ?? null,
    cancelled_by: row.cancelled_by ?? null,
    cancelled_by_role: row.cancelled_by_role ?? null,
    cancelled_at: toIso(row.cancelled_at),
    created_by: row.created_by ?? null,
    created_by_role: row.created_by_role ?? null,
    lease_token: row.lease_token ?? null,
    lease_owner: row.lease_owner ?? null,
    lease_expires_at: toIso(row.lease_expires_at),
    next_eligible_at: toIso(row.next_eligible_at),
    revision: Number(row.revision ?? 1),
    summary: row.summary == null ? null : asObject(row.summary),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
  };
}

export function mapValidationScanStepRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    scan_id: row.scan_id,
    position: Number(row.position ?? 0),
    check_id: row.check_id,
    check_name: row.check_name ?? row.check_id,
    target_id: row.target_id,
    status: row.status,
    test_run_id: row.test_run_id ?? null,
    error_code: row.error_code ?? null,
    skip_reason: row.skip_reason ?? null,
    eligible_at: toIso(row.eligible_at),
    attempts: Number(row.attempts ?? 0),
    request_snapshot: asObject(row.request_snapshot),
    started_at: toIso(row.started_at),
    completed_at: toIso(row.completed_at),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
  };
}

function mapAuditRow(row) {
  if (!row) return null;
  const { metadata_json: metadataJson, ...rest } = row;
  return {
    ...rest,
    timestamp: toIso(row.timestamp),
    sequence: Number(row.sequence),
    metadata: asObject(metadataJson),
  };
}

function jsonParam(value) {
  return value == null ? null : JSON.stringify(value);
}

function buildSetClause(patch, { textFields, timestampFields, jsonFields, numericFields }, params, startIndex) {
  const sets = [];
  let n = startIndex;
  for (const field of textFields) {
    if (patch[field] !== undefined) {
      sets.push(`${field} = $${n++}`);
      params.push(patch[field]);
    }
  }
  for (const field of timestampFields) {
    if (patch[field] !== undefined) {
      sets.push(`${field} = $${n++}::timestamptz`);
      params.push(patch[field]);
    }
  }
  for (const field of jsonFields) {
    if (patch[field] !== undefined) {
      sets.push(`${field} = $${n++}::jsonb`);
      params.push(jsonParam(patch[field]));
    }
  }
  for (const field of numericFields) {
    if (patch[field] !== undefined) {
      sets.push(`${field} = $${n++}`);
      params.push(patch[field]);
    }
  }
  return { sets, nextIndex: n };
}

function normalizeRunIds(runIds) {
  const unique = [...new Set(asArray(runIds).map((id) => String(id ?? '').trim()).filter(Boolean))];
  return unique.slice(0, MAX_RUN_ID_BATCH);
}

function normalizeLimit(value, fallback, max) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 1) return fallback;
  return Math.min(Math.floor(n), max);
}

async function insertSteps(client, tenantId, scanId, steps) {
  const inserted = [];
  for (const step of steps) {
    const { rows } = await client.query(
      `INSERT INTO validation_scan_steps (
         id, tenant_id, scan_id, position, check_id, check_name, target_id, status, test_run_id,
         error_code, skip_reason, eligible_at, attempts, request_snapshot, started_at, completed_at,
         created_at, updated_at
       ) VALUES (
         $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::timestamptz, $13, $14::jsonb,
         $15::timestamptz, $16::timestamptz, $17::timestamptz, $18::timestamptz
       ) RETURNING ${VALIDATION_SCAN_STEP_COLUMNS}`,
      [
        step.id, tenantId, scanId, step.position, step.check_id, step.check_name ?? step.check_id, step.target_id,
        step.status ?? 'pending', step.test_run_id ?? null, step.error_code ?? null, step.skip_reason ?? null,
        step.eligible_at ?? null, step.attempts ?? 0, JSON.stringify(asObject(step.request_snapshot)),
        step.started_at ?? null, step.completed_at ?? null, step.created_at, step.updated_at ?? step.created_at,
      ],
    );
    inserted.push(mapValidationScanStepRow(rows[0]));
  }
  return inserted;
}

async function insertScan(client, tenantId, record, { onConflictOccurrence = false } = {}) {
  const { rows } = await client.query(
    `INSERT INTO validation_scans (
       id, tenant_id, target_group_id, target_id, name, status, check_ids, plan_snapshot, scheduled_for, recurrence,
       recurrence_series_id, occurrence_key, occurrence_index, previous_scan_id, next_scan_id, dispatched_at,
       started_at, completed_at, abort_reason, cancel_reason, cancelled_by, cancelled_by_role, cancelled_at,
       created_by, created_by_role, lease_token, lease_owner, lease_expires_at, next_eligible_at, revision, summary,
       created_at, updated_at
     ) VALUES (
       $1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9::timestamptz, $10::jsonb, $11, $12, $13, $14, $15,
       $16::timestamptz, $17::timestamptz, $18::timestamptz, $19, $20, $21, $22, $23::timestamptz, $24, $25,
       $26, $27, $28::timestamptz, $29::timestamptz, $30, $31::jsonb, $32::timestamptz, $33::timestamptz
     )
     ${onConflictOccurrence ? 'ON CONFLICT (tenant_id, occurrence_key) WHERE occurrence_key IS NOT NULL DO NOTHING' : ''}
     RETURNING ${VALIDATION_SCAN_COLUMNS}`,
    [
      record.id, tenantId, record.target_group_id, record.target_id ?? null, record.name ?? null, record.status,
      JSON.stringify(asArray(record.check_ids)), JSON.stringify(asObject(record.plan_snapshot)),
      record.scheduled_for ?? null, jsonParam(record.recurrence), record.recurrence_series_id ?? record.id,
      record.occurrence_key ?? null, record.occurrence_index ?? 0, record.previous_scan_id ?? null,
      record.next_scan_id ?? null, record.dispatched_at ?? null, record.started_at ?? null,
      record.completed_at ?? null, record.abort_reason ?? null, record.cancel_reason ?? null,
      record.cancelled_by ?? null, record.cancelled_by_role ?? null, record.cancelled_at ?? null,
      record.created_by ?? null, record.created_by_role ?? null, record.lease_token ?? null,
      record.lease_owner ?? null, record.lease_expires_at ?? null, record.next_eligible_at ?? null,
      record.revision ?? 1, JSON.stringify(asObject(record.summary)), record.created_at,
      record.updated_at ?? record.created_at,
    ],
  );
  return mapValidationScanRow(rows[0] ?? null);
}

function mapScanWriteError(error) {
  if (error?.code === '23505' && error?.constraint === 'uniq_active_validation_scan_per_group') {
    return { error: 'concurrent_scan_blocked', status: 409 };
  }
  if (error?.code === '23505' && error?.constraint === 'uniq_validation_scans_occurrence') {
    return { error: 'scan_occurrence_conflict', status: 409 };
  }
  if (error?.code === '23514' && String(error?.constraint ?? '').startsWith('validation_scans_')) {
    return { error: 'scan_state_conflict', status: 409 };
  }
  return null;
}

/**
 * Status/lease-guarded scan update. Returns null when the guard no longer matches so callers
 * working from a stale snapshot never overwrite a concurrent cancel, edit, or dispatch.
 */
async function guardedScanUpdate(client, tenantId, id, patch, options = {}) {
  const params = [];
  const { sets, nextIndex } = buildSetClause(
    { ...patch, updated_at: patch.updated_at ?? new Date().toISOString() },
    {
      textFields: SCAN_TEXT_FIELDS,
      timestampFields: SCAN_TIMESTAMP_FIELDS,
      jsonFields: SCAN_JSON_FIELDS,
      numericFields: SCAN_NUMERIC_FIELDS,
    },
    params,
    1,
  );
  params.push(tenantId, id);
  const conditions = [`tenant_id = $${nextIndex}`, `id = $${nextIndex + 1}`];
  if (Array.isArray(options.expectedStatuses) && options.expectedStatuses.length) {
    params.push(options.expectedStatuses);
    conditions.push(`status = ANY($${params.length}::text[])`);
  }
  if (options.leaseToken) {
    params.push(options.leaseToken);
    conditions.push(`lease_token = $${params.length}`);
  }
  if (options.requireUnleasedAt) {
    params.push(new Date(options.requireUnleasedAt).toISOString());
    conditions.push(`(lease_token IS NULL OR lease_expires_at <= $${params.length}::timestamptz)`);
  }
  try {
    const { rows } = await client.query(
      `UPDATE validation_scans SET ${sets.join(', ')}
       WHERE ${conditions.join(' AND ')}
       RETURNING ${VALIDATION_SCAN_COLUMNS}`,
      params,
    );
    return mapValidationScanRow(rows[0] ?? null);
  } catch (error) {
    const mapped = mapScanWriteError(error);
    if (mapped) return mapped;
    throw error;
  }
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ auditRepository?: ReturnType<typeof createAuditRepository> }} [options]
 */
export function createPostgresValidationScanRepository(pool, options = {}) {
  const auditRepository = options.auditRepository ?? createAuditRepository(pool);

  // Scan locks hold a session-level advisory lock on a dedicated connection for the whole duration
  // of the executor callback, and that callback needs its OWN connections from the main pool for
  // its short tenant transactions. Sharing one pool means ~max concurrent lock holders (10 by
  // default) each pin a connection while starving the queries they depend on, stalling scans and
  // timing out unrelated API requests. A separate small pool keeps lock connections off the query
  // pool's budget. Tests can inject options.lockPool; otherwise it is derived lazily from the main
  // pool's own config so no new connection string plumbing is required.
  const lockPoolMax = Number(options.lockPoolMax) > 0 ? Number(options.lockPoolMax) : 5;
  let ownedLockPool = null;
  const resolveLockPool = () => {
    if (options.lockPool) return options.lockPool;
    if (ownedLockPool) return ownedLockPool;
    const base = pool?.options ?? {};
    ownedLockPool = new pool.constructor({ ...base, max: lockPoolMax });
    // A dropped idle lock connection must not crash the process (same failure mode as the main
    // pool's handler); the pool discards it and the next checkout reconnects.
    ownedLockPool.on('error', (err) => {
      const code = err && typeof err === 'object' && 'code' in err ? ` (${String(err.code)})` : '';
      console.warn(`astranull postgres: idle scan-lock client error${code}: ${String(err?.message ?? err).slice(0, 200)}`);
    });
    return ownedLockPool;
  };

  async function readScan(client, tenantId, id, { forUpdate = false } = {}) {
    const { rows } = await client.query(
      `SELECT ${VALIDATION_SCAN_COLUMNS}
       FROM validation_scans
       WHERE tenant_id = $1 AND id = $2
       ${forUpdate ? 'FOR UPDATE' : ''}`,
      [tenantId, id],
    );
    return mapValidationScanRow(rows[0] ?? null);
  }

  async function readSteps(client, tenantId, scanId) {
    const { rows } = await client.query(
      `SELECT ${VALIDATION_SCAN_STEP_COLUMNS}
       FROM validation_scan_steps
       WHERE tenant_id = $1 AND scan_id = $2
       ORDER BY position`,
      [tenantId, scanId],
    );
    return rows.map(mapValidationScanStepRow);
  }

  return {
    async createScan(ctx, record, steps = []) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        try {
          const scan = await insertScan(client, ctx.tenantId, record);
          const insertedSteps = await insertSteps(client, ctx.tenantId, scan.id, steps);
          return { scan, steps: insertedSteps };
        } catch (error) {
          if (error?.code === '23505' && error?.constraint === 'uniq_active_validation_scan_per_group') {
            return { error: 'concurrent_scan_blocked', status: 409 };
          }
          if (error?.code === '23505' && error?.constraint === 'uniq_validation_scans_occurrence') {
            return { error: 'scan_occurrence_conflict', status: 409 };
          }
          throw error;
        }
      });
    },

    async getScan(ctx, id, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, (client) => readScan(client, ctx.tenantId, id));
    },

    async getStep(ctx, stepId, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VALIDATION_SCAN_STEP_COLUMNS}
           FROM validation_scan_steps
           WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, stepId],
        );
        return mapValidationScanStepRow(rows[0] ?? null);
      });
    },

    async listScans(ctx, options = {}) {
      const limit = normalizeLimit(options.limit, 50, MAX_SCAN_LIST_LIMIT);
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const params = [ctx.tenantId];
        const conditions = ['tenant_id = $1'];
        if (options.targetGroupId) {
          params.push(options.targetGroupId);
          conditions.push(`(target_group_id = $${params.length} OR EXISTS (
            SELECT 1 FROM jsonb_each_text(CASE WHEN jsonb_typeof(plan_snapshot->'target_policy_bindings') = 'object'
              THEN plan_snapshot->'target_policy_bindings' ELSE '{}'::jsonb END) AS binding
            WHERE binding.value = $${params.length}))`);
        }
        if (options.targetId) {
          params.push(options.targetId);
          conditions.push(`(target_id = $${params.length} OR EXISTS (SELECT 1 FROM validation_scan_steps AS selected
            WHERE selected.tenant_id = $1 AND selected.scan_id = validation_scans.id AND selected.target_id = $${params.length}))`);
        }
        const statuses = asArray(options.status).filter(Boolean);
        if (statuses.length) {
          params.push(statuses);
          conditions.push(`status = ANY($${params.length}::text[])`);
        }
        if (options.excludeId) {
          params.push(options.excludeId);
          conditions.push(`id <> $${params.length}`);
        }
        if (options.seriesId) {
          params.push(options.seriesId);
          conditions.push(`recurrence_series_id = $${params.length}`);
        }
        params.push(limit);
        const { rows } = await client.query(
          `SELECT ${VALIDATION_SCAN_COLUMNS}
           FROM validation_scans
           WHERE ${conditions.join(' AND ')}
           ORDER BY created_at DESC, id DESC
           LIMIT $${params.length}`,
          params,
        );
        return rows.map(mapValidationScanRow);
      });
    },

    async listSteps(ctx, scanId, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, (client) => readSteps(client, ctx.tenantId, scanId));
    },

    async listStepsForScans(ctx, scanIds, options = {}) {
      const ids = normalizeRunIds(scanIds);
      if (!ids.length) return [];
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VALIDATION_SCAN_STEP_COLUMNS}
           FROM validation_scan_steps
           WHERE tenant_id = $1 AND scan_id = ANY($2::text[])
           ORDER BY scan_id, position`,
          [ctx.tenantId, ids],
        );
        return rows.map(mapValidationScanStepRow);
      });
    },

    async updateScan(ctx, id, patch = {}, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, (client) => (
        guardedScanUpdate(client, ctx.tenantId, id, patch, options)
      ));
    },

    async updateScanWithSteps(ctx, id, patch = {}, steps = [], options = {}) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const updated = await guardedScanUpdate(client, ctx.tenantId, id, patch, options);
        if (!updated || updated.error) return updated;
        await client.query(
          `DELETE FROM validation_scan_steps WHERE tenant_id = $1 AND scan_id = $2`,
          [ctx.tenantId, id],
        );
        const insertedSteps = await insertSteps(client, ctx.tenantId, id, steps);
        return { ...updated, steps: insertedSteps };
      });
    },

    async updateStep(ctx, stepId, patch = {}, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const params = [];
        const { sets, nextIndex } = buildSetClause(
          { ...patch, updated_at: patch.updated_at ?? new Date().toISOString() },
          {
            textFields: STEP_TEXT_FIELDS,
            timestampFields: STEP_TIMESTAMP_FIELDS,
            jsonFields: STEP_JSON_FIELDS,
            numericFields: STEP_NUMERIC_FIELDS,
          },
          params,
          1,
        );
        params.push(ctx.tenantId, stepId);
        const conditions = [`tenant_id = $${nextIndex}`, `id = $${nextIndex + 1}`];
        if (Array.isArray(options.expectedStatuses) && options.expectedStatuses.length) {
          params.push(options.expectedStatuses);
          conditions.push(`status = ANY($${params.length}::text[])`);
        }
        const { rows } = await client.query(
          `UPDATE validation_scan_steps SET ${sets.join(', ')}
           WHERE ${conditions.join(' AND ')}
           RETURNING ${VALIDATION_SCAN_STEP_COLUMNS}`,
          params,
        );
        return mapValidationScanStepRow(rows[0] ?? null);
      });
    },

    async replaceSteps(ctx, scanId, steps = [], options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        await client.query(
          `DELETE FROM validation_scan_steps WHERE tenant_id = $1 AND scan_id = $2`,
          [ctx.tenantId, scanId],
        );
        return insertSteps(client, ctx.tenantId, scanId, steps);
      });
    },

    async findStepByRunId(ctx, runId, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VALIDATION_SCAN_STEP_COLUMNS}
           FROM validation_scan_steps
           WHERE tenant_id = $1 AND test_run_id = $2
           LIMIT 1`,
          [ctx.tenantId, runId],
        );
        return mapValidationScanStepRow(rows[0] ?? null);
      });
    },

    async findScanByOccurrenceKey(ctx, occurrenceKey, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VALIDATION_SCAN_COLUMNS}
           FROM validation_scans
           WHERE tenant_id = $1 AND occurrence_key = $2
           LIMIT 1`,
          [ctx.tenantId, occurrenceKey],
        );
        return mapValidationScanRow(rows[0] ?? null);
      });
    },

    async listDueScans(ctx, options = {}) {
      const now = new Date(options.now ?? Date.now()).toISOString();
      const limit = normalizeLimit(options.limit, 25, 100);
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VALIDATION_SCAN_COLUMNS}
           FROM validation_scans
           WHERE tenant_id = $1 AND status = 'scheduled'
             AND scheduled_for IS NOT NULL AND scheduled_for <= $2::timestamptz
             AND (lease_expires_at IS NULL OR lease_expires_at <= $2::timestamptz)
           ORDER BY scheduled_for, id
           LIMIT $3`,
          [ctx.tenantId, now, limit],
        );
        return rows.map(mapValidationScanRow);
      });
    },

    async leaseDueScans(ctx, options = {}) {
      const workerId = String(options.workerId ?? '').trim();
      if (!workerId) return { error: 'missing_worker_id', status: 400 };
      const nowDate = new Date(options.now ?? Date.now());
      const now = nowDate.toISOString();
      const leaseMs = Math.max(1_000, Math.min(15 * 60_000, Number(options.leaseMs) || SCAN_LEASE_MS));
      const leaseExpiresAt = new Date(nowDate.getTime() + leaseMs).toISOString();
      const limit = normalizeLimit(options.limit, 25, 100);
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const params = [ctx.tenantId, now];
        const scanFilter = options.scanId ? `AND id = $${params.push(options.scanId)}` : '';
        params.push(limit);
        const { rows: candidates } = await client.query(
          `SELECT id
           FROM validation_scans
           WHERE tenant_id = $1 AND status = 'scheduled'
             AND scheduled_for IS NOT NULL AND scheduled_for <= $2::timestamptz
             AND (lease_expires_at IS NULL OR lease_expires_at <= $2::timestamptz)
             ${scanFilter}
           ORDER BY scheduled_for, id
           FOR UPDATE SKIP LOCKED
           LIMIT $${params.length}`,
          params,
        );
        const leased = [];
        for (const candidate of candidates) {
          const leaseToken = randomUUID();
          const { rows } = await client.query(
            `UPDATE validation_scans
             SET lease_token = $3, lease_owner = $4, lease_expires_at = $5::timestamptz, updated_at = $6::timestamptz
             WHERE tenant_id = $1 AND id = $2 AND status = 'scheduled'
             RETURNING ${VALIDATION_SCAN_COLUMNS}`,
            [ctx.tenantId, candidate.id, leaseToken, workerId, leaseExpiresAt, now],
          );
          if (rows[0]) leased.push(mapValidationScanRow(rows[0]));
        }
        return leased;
      });
    },

    async listRunnableScans(ctx, options = {}) {
      const now = new Date(options.now ?? Date.now()).toISOString();
      const limit = normalizeLimit(options.limit, 25, 100);
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VALIDATION_SCAN_COLUMNS}
           FROM validation_scans
           WHERE tenant_id = $1 AND status IN ('pending', 'running')
             AND (lease_expires_at IS NULL OR lease_expires_at <= $2::timestamptz)
             AND (next_eligible_at IS NULL OR next_eligible_at <= $2::timestamptz)
           ORDER BY next_eligible_at NULLS FIRST, id
           LIMIT $3`,
          [ctx.tenantId, now, limit],
        );
        return rows.map(mapValidationScanRow);
      });
    },

    /**
     * Serialize one scan executor per scan across processes.
     *
     * A session-level advisory lock is held on a dedicated client for the duration of the callback.
     * The executor commits its lease, step, and audit writes in short tenant transactions so that
     * startTestRun, which validates the scan binding through its own connections, can observe them.
     * A transaction-scoped lock would hide those writes until the executor finished.
     */
    async withScanLock(ctx, scanId, callback) {
      const lockKey = `validation_scan:${scanId}`;
      const client = await resolveLockPool().connect();
      let locked = false;
      let clientBroken = false;
      // A busy (checked-out) client re-emits its socket error on the client object, NOT on the
      // pool, so the pool-level handler does not cover it. Without this listener a Postgres restart,
      // failover, or pg_terminate_backend during a held lock is an uncaught 'error' event that kills
      // the control plane or runner. We record the break, log without the connection string, and
      // discard the client on release so a fresh connection is used next time.
      const onClientError = (err) => {
        clientBroken = true;
        const code = err && typeof err === 'object' && 'code' in err ? ` (${String(err.code)})` : '';
        console.warn(`astranull postgres: scan-lock client error${code}: ${String(err?.message ?? err).slice(0, 200)}`);
      };
      client.on('error', onClientError);
      try {
        const { rows } = await client.query('SELECT pg_try_advisory_lock(hashtext($1)) AS acquired', [lockKey]);
        locked = rows[0]?.acquired === true;
        if (!locked) return { acquired: false, result: null };
        const result = await callback();
        return { acquired: true, result };
      } finally {
        // discard = true means hand the pool an Error so it destroys the connection instead of
        // reusing it. Always discard a broken client. If the lock was acquired on a healthy client,
        // unlock and keep it; only keep it when the unlock succeeded.
        let discard = clientBroken;
        if (locked && !clientBroken) {
          try {
            await client.query('SELECT pg_advisory_unlock(hashtext($1))', [lockKey]);
          } catch {
            discard = true;
          }
        }
        client.removeListener('error', onClientError);
        client.release(discard ? new Error('validation scan lock release failed') : undefined);
      }
    },

    async createNextOccurrence(ctx, record, steps = []) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const scan = await insertScan(client, ctx.tenantId, record, { onConflictOccurrence: true });
        if (!scan) {
          const { rows } = await client.query(
            `SELECT ${VALIDATION_SCAN_COLUMNS}
             FROM validation_scans
             WHERE tenant_id = $1 AND occurrence_key = $2
             LIMIT 1`,
            [ctx.tenantId, record.occurrence_key],
          );
          return { scan: mapValidationScanRow(rows[0] ?? null), created: false, steps: [] };
        }
        const insertedSteps = await insertSteps(client, ctx.tenantId, scan.id, steps);
        return { scan, created: true, steps: insertedSteps };
      });
    },

    async appendScanAudit(ctx, event, options = {}) {
      return auditRepository.appendAuditEvent(
        {
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId ?? null,
          actor_role: ctx.role ?? null,
          action: event.action,
          resource_type: event.resource_type ?? 'validation_scan',
          resource_id: event.resource_id,
          metadata: event.metadata == null ? undefined : redactObject(event.metadata),
        },
        { now: options.now ?? new Date(), client: options.client, auditLockHeld: options.auditLockHeld },
      );
    },

    async listAuditEntriesForScan(ctx, options = {}) {
      const scanId = String(options.scanId ?? '').trim();
      if (!scanId) return [];
      const runIds = normalizeRunIds(options.runIds);
      const limit = normalizeLimit(options.limit, 200, MAX_ACTIVITY_LIMIT);
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${AUDIT_COLUMNS}
           FROM audit_logs
           WHERE tenant_id = $1
             AND (
               (resource_type = 'validation_scan' AND resource_id = $2)
               OR (resource_type = 'test_run' AND resource_id = ANY($3::text[]))
               OR metadata_json->>'scan_id' = $2
               OR (metadata_json->>'test_run_id' IS NOT NULL AND metadata_json->>'test_run_id' = ANY($3::text[]))
             )
           ORDER BY sequence DESC
           LIMIT $4`,
          [ctx.tenantId, scanId, runIds, limit],
        );
        return rows.reverse().map(mapAuditRow);
      });
    },

    async listProbeJobsForRuns(ctx, runIds, options = {}) {
      const ids = normalizeRunIds(runIds);
      if (!ids.length) return [];
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT id, test_run_id, status, probe_profile, constraints_json
           FROM probe_jobs
           WHERE tenant_id = $1 AND test_run_id = ANY($2::text[])
             AND ownership_verification_id IS NULL
           ORDER BY created_at`,
          [ctx.tenantId, ids],
        );
        return rows.map((row) => ({
          id: row.id,
          test_run_id: row.test_run_id,
          status: row.status,
          probe_profile: row.probe_profile == null ? null : asObject(row.probe_profile),
          constraints: asObject(row.constraints_json),
        }));
      });
    },

    // Release the dedicated scan-lock pool on shutdown. Only ends a pool this repository created;
    // an injected options.lockPool is owned by the caller.
    async close() {
      if (ownedLockPool) {
        const toClose = ownedLockPool;
        ownedLockPool = null;
        await toClose.end();
      }
    },
  };
}

export const VALIDATION_SCAN_REPOSITORY_METHODS = Object.freeze([
  'createScan',
  'getScan',
  'getStep',
  'listScans',
  'listSteps',
  'listStepsForScans',
  'updateScan',
  'updateScanWithSteps',
  'updateStep',
  'replaceSteps',
  'findStepByRunId',
  'findScanByOccurrenceKey',
  'listDueScans',
  'leaseDueScans',
  'listRunnableScans',
  'withScanLock',
  'createNextOccurrence',
  'appendScanAudit',
  'listAuditEntriesForScan',
  'listProbeJobsForRuns',
]);
