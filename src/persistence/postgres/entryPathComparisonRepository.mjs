// Tenant-scoped storage for migration 0071; each write commits state, attempt rows, and audit entries together.
import { incMetric } from '../../lib/metrics.mjs';
import { EntryPathComparisonConflictError, takePendingComparisonAudits } from '../../services/entryPathComparisons.mjs';
import { withTenantContext } from './tenantContext.mjs';

const STATE = Symbol('entryPathComparisonStoredState');
const ACTIVE_RUN_STATUSES = ['planned', 'running', 'collecting'];
const CANCELLED_SKIP_REASONS = new Set([
  'comparison_cancelled', 'kill_switch_active', 'run_cancelled', 'protection_validation_disabled', 'tenant_suspended',
  'approved_scope_invalid',
]);
const LOCK_NAMESPACE = 'entry_path_comparison';
const LOCK_WAIT_MS = 5_000;
const LOCK_POLL_MS = 50;
const LOCK_CONNECT_TIMEOUT_MS = 2_000;

const COMPARISON_COLUMNS = `id, tenant_id, anchor_target_id, primary_entry_path_id, status, reviewed_plan_digest, scope_digest,
  expectation_json, approved_scope_json, probe_mode, execution_ctx_json, idempotency_key, cancel_reason, evaluation_json,
  evaluation_id, lock_version, reconcile_seq, reconciled_seq, created_by, created_at, started_at, completed_at`;

const ITEM_COLUMNS = `comparison_id, entry_path_id, ordinal, status, skip_reason, test_run_id, probe_job_id, attempts,
  deferred_until, last_start_error, updated_at`;

function iso(value) {
  if (value == null) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

export function itemStatusForState(item) {
  if (item.state === 'started') return 'running';
  if (item.state === 'finalized') return 'completed';
  if (item.state === 'skipped') return CANCELLED_SKIP_REASONS.has(item.skip_reason) ? 'cancelled' : 'failed';
  return item.state;
}

export function itemStateForStatus(status) {
  if (status === 'running') return 'started';
  if (status === 'completed') return 'finalized';
  if (status === 'cancelled' || status === 'failed') return 'skipped';
  return status;
}

function itemRecord(item) {
  return {
    status: itemStatusForState(item),
    skip_reason: item.skip_reason ?? null,
    test_run_id: item.test_run_id ?? null,
    attempts: item.attempts ?? 0,
    deferred_until: iso(item.deferred_until),
    last_start_error: item.last_start_error ? String(item.last_start_error).slice(0, 200) : null,
    updated_at: iso(item.updated_at),
  };
}

function snapshotOf(item) {
  return JSON.stringify(itemRecord(item));
}

function mapItem(row) {
  return {
    entry_path_id: row.entry_path_id,
    state: itemStateForStatus(row.status),
    skip_reason: row.skip_reason ?? null,
    test_run_id: row.test_run_id ?? null,
    attempts: Number(row.attempts ?? 0),
    deferred_until: iso(row.deferred_until),
    last_start_error: row.last_start_error ?? null,
    updated_at: iso(row.updated_at),
  };
}

function mapComparison(row, itemRows) {
  if (!row) return null;
  const items = itemRows.map(mapItem);
  const comparison = {
    id: row.id,
    tenant_id: row.tenant_id,
    anchor_target_id: row.anchor_target_id,
    primary_entry_path_id: row.primary_entry_path_id,
    status: row.status,
    plan_digest: row.reviewed_plan_digest,
    expectation: row.expectation_json,
    approved_scope: row.approved_scope_json,
    probe_mode: row.probe_mode,
    execution_ctx: row.execution_ctx_json,
    items,
    cancel_reason: row.cancel_reason ?? null,
    idempotency_key: row.idempotency_key ?? null,
    created_by: row.created_by ?? null,
    created_at: iso(row.created_at),
    started_at: iso(row.started_at),
    completed_at: iso(row.completed_at),
    evaluation: row.evaluation_json ?? null,
    evaluation_id: row.evaluation_id ?? null,
  };
  Object.defineProperty(comparison, STATE, {
    value: {
      version: Number(row.lock_version),
      reconcileSeq: Number(row.reconcile_seq),
      items: new Map(items.map((item) => [item.entry_path_id, snapshotOf(item)])),
    },
    enumerable: false,
    writable: true,
  });
  return comparison;
}

async function loadItems(client, tenantId, comparisonIds) {
  if (!comparisonIds.length) return new Map();
  const { rows } = await client.query(
    `SELECT ${ITEM_COLUMNS} FROM entry_path_comparison_items
     WHERE tenant_id = $1 AND comparison_id = ANY($2::text[])
     ORDER BY comparison_id, ordinal`,
    [tenantId, comparisonIds],
  );
  const grouped = new Map(comparisonIds.map((id) => [id, []]));
  for (const row of rows) grouped.get(row.comparison_id)?.push(row);
  return grouped;
}

async function readComparisons(client, tenantId, rows) {
  const items = await loadItems(client, tenantId, rows.map((row) => row.id));
  return rows.map((row) => mapComparison(row, items.get(row.id) ?? []));
}

async function appendAudits(audit, entries, client) {
  if (!audit?.appendAuditEvent) return;
  for (const entry of entries) await audit.appendAuditEvent(entry, { client });
}

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ audit?: { appendAuditEvent: Function }, lockPool?: import('pg').Pool, lockPoolMax?: number }} [options]
 */
export function createEntryPathComparisonRepository(pool, options = {}) {
  const audit = options.audit ?? null;
  const lockPoolMax = Number(options.lockPoolMax) > 0 ? Number(options.lockPoolMax) : 4;
  let ownedLockPool = null;

  // Session advisory locks pin a connection for the whole advance, so they live on a small dedicated pool.
  const resolveLockPool = () => {
    if (options.lockPool) return options.lockPool;
    if (ownedLockPool) return ownedLockPool;
    ownedLockPool = new pool.constructor({
      ...(pool?.options ?? {}),
      max: lockPoolMax,
      connectionTimeoutMillis: Number(options.lockConnectTimeoutMs) > 0 ? Number(options.lockConnectTimeoutMs) : LOCK_CONNECT_TIMEOUT_MS,
    });
    ownedLockPool.on('error', (err) => {
      const code = err && typeof err === 'object' && 'code' in err ? ` (${String(err.code)})` : '';
      console.warn(`astranull postgres: idle comparison-lock client error${code}: ${String(err?.message ?? err).slice(0, 200)}`);
    });
    return ownedLockPool;
  };

  async function readOne(client, tenantId, id) {
    const { rows } = await client.query(
      `SELECT ${COMPARISON_COLUMNS} FROM entry_path_comparisons WHERE tenant_id = $1 AND id = $2`,
      [tenantId, id],
    );
    if (!rows[0]) return null;
    return (await readComparisons(client, tenantId, rows))[0];
  }

  async function updateItems(client, comparison, state) {
    for (const item of comparison.items) {
      const snapshot = snapshotOf(item);
      if (state.items.get(item.entry_path_id) === snapshot) continue;
      const record = itemRecord(item);
      const { rowCount } = await client.query(
        `UPDATE entry_path_comparison_items SET
           status = $4, skip_reason = $5, test_run_id = $6,
           probe_job_id = COALESCE(probe_job_id, CASE WHEN $6::text IS NULL THEN NULL ELSE (
             SELECT j.id FROM probe_jobs j WHERE j.tenant_id = $1 AND j.test_run_id = $6 ORDER BY j.created_at LIMIT 1
           ) END),
           attempts = $7, deferred_until = $8::timestamptz, last_start_error = $9, updated_at = COALESCE($10::timestamptz, NOW())
         WHERE tenant_id = $1 AND comparison_id = $2 AND entry_path_id = $3`,
        [comparison.tenant_id, comparison.id, item.entry_path_id, record.status, record.skip_reason, record.test_run_id,
          record.attempts, record.deferred_until, record.last_start_error, record.updated_at],
      );
      if (rowCount !== 1) throw new EntryPathComparisonConflictError(comparison.id);
    }
  }

  function commitSnapshots(comparison, state, version) {
    state.version = version;
    state.items = new Map(comparison.items.map((item) => [item.entry_path_id, snapshotOf(item)]));
  }

  const repo = {
    async insertComparison(ctx, comparison) {
      const audits = takePendingComparisonAudits(comparison);
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const inserted = await client.query(
          `INSERT INTO entry_path_comparisons (
             id, tenant_id, anchor_target_id, primary_entry_path_id, status, reviewed_plan_digest, scope_digest,
             expectation_json, approved_scope_json, probe_mode, execution_ctx_json, idempotency_key, created_by,
             created_at, started_at
           ) VALUES ($1, $2, $3, $4, 'running', $5, $6, $7::jsonb, $8::jsonb, $9, $10::jsonb, $11, $12, $13::timestamptz, $14::timestamptz)
           ON CONFLICT DO NOTHING
           RETURNING id`,
          [
            comparison.id, comparison.tenant_id, comparison.anchor_target_id, comparison.primary_entry_path_id,
            comparison.plan_digest, comparison.approved_scope.scope_digest, JSON.stringify(comparison.expectation),
            JSON.stringify(comparison.approved_scope), comparison.probe_mode, JSON.stringify(comparison.execution_ctx),
            comparison.idempotency_key ?? null, comparison.created_by ?? null, comparison.created_at, comparison.started_at,
          ],
        );
        if (!inserted.rows[0]) return { conflict: true };
        const scopeItems = new Map(comparison.approved_scope.items.map((item) => [item.entry_path_id, item]));
        for (const [ordinal, item] of comparison.items.entries()) {
          const scope = scopeItems.get(item.entry_path_id) ?? {};
          const record = itemRecord(item);
          await client.query(
            `INSERT INTO entry_path_comparison_items (
               tenant_id, comparison_id, entry_path_id, ordinal, is_primary, eligible, target_id, target_group_id, check_id,
               origin_binding_id, target_scope_hash, declaration_digest, status, skip_reason, attempts, created_at, updated_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16::timestamptz, $16::timestamptz)`,
            [
              comparison.tenant_id, comparison.id, item.entry_path_id, ordinal, scope.is_primary === true, scope.eligible === true,
              scope.target_id ?? null, scope.target_group_id ?? null, scope.check_id ?? null, scope.origin_binding_id ?? null,
              scope.target_scope_hash ?? null, scope.declaration_digest ?? null, record.status, record.skip_reason,
              record.attempts, comparison.created_at,
            ],
          );
        }
        await appendAudits(audit, audits, client);
        Object.defineProperty(comparison, STATE, {
          value: { version: 0, reconcileSeq: 0, items: new Map(comparison.items.map((item) => [item.entry_path_id, snapshotOf(item)])) },
          enumerable: false,
          writable: true,
        });
        return { comparison };
      });
    },

    /** Compare-and-set on lock_version: a stale writer rolls back instead of double-recording. */
    async saveComparison(comparison) {
      const state = comparison?.[STATE];
      if (!state) throw new EntryPathComparisonConflictError(comparison?.id ?? null);
      const audits = takePendingComparisonAudits(comparison);
      return withTenantContext(pool, comparison.tenant_id, async (client) => {
        const { rows } = await client.query(
          `UPDATE entry_path_comparisons SET
             status = $3, cancel_reason = $4, evaluation_json = $5::jsonb, completed_at = $6::timestamptz,
             lock_version = lock_version + 1, reconciled_seq = GREATEST(reconciled_seq, $8), updated_at = NOW()
           WHERE tenant_id = $1 AND id = $2 AND lock_version = $7 AND status = 'running'
           RETURNING lock_version`,
          [
            comparison.tenant_id, comparison.id, comparison.status, comparison.cancel_reason ?? null,
            comparison.evaluation ? JSON.stringify(comparison.evaluation) : null, comparison.completed_at ?? null,
            state.version, state.reconcileSeq,
          ],
        );
        if (!rows[0]) throw new EntryPathComparisonConflictError(comparison.id);
        await updateItems(client, comparison, state);
        await appendAudits(audit, audits, client);
        commitSnapshots(comparison, state, Number(rows[0].lock_version));
        return true;
      });
    },

    /** Marks one queued attempt as running before its run is requested, so a crash can never start it twice. */
    async claimItem(comparison, item) {
      const state = comparison?.[STATE];
      if (!state) throw new EntryPathComparisonConflictError(comparison?.id ?? null);
      const updatedAt = iso(new Date());
      const claimed = await withTenantContext(pool, comparison.tenant_id, async (client) => {
        const { rowCount } = await client.query(
          `UPDATE entry_path_comparison_items i SET status = 'running', attempts = $4, deferred_until = NULL, updated_at = $5::timestamptz
           WHERE i.tenant_id = $1 AND i.comparison_id = $2 AND i.entry_path_id = $3
             AND i.status IN ('pending', 'deferred') AND i.test_run_id IS NULL
             AND EXISTS (
               SELECT 1 FROM entry_path_comparisons c
               WHERE c.tenant_id = $1 AND c.id = $2 AND c.status = 'running' AND c.lock_version = $6
             )`,
          [comparison.tenant_id, comparison.id, item.entry_path_id, item.attempts, updatedAt, state.version],
        );
        return rowCount === 1;
      });
      if (!claimed) throw new EntryPathComparisonConflictError(comparison.id);
      state.items.set(item.entry_path_id, snapshotOf({
        ...item, state: 'started', test_run_id: null, deferred_until: null, updated_at: updatedAt,
      }));
    },

    async getComparison(tenantId, id) {
      return withTenantContext(pool, tenantId, (client) => readOne(client, tenantId, id));
    },

    async findByIdempotencyKey(ctx, key) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${COMPARISON_COLUMNS} FROM entry_path_comparisons WHERE tenant_id = $1 AND idempotency_key = $2`,
          [ctx.tenantId, key],
        );
        return rows[0] ? (await readComparisons(client, ctx.tenantId, rows))[0] : null;
      });
    },

    async findRunningByPlanDigest(ctx, digest) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${COMPARISON_COLUMNS} FROM entry_path_comparisons
           WHERE tenant_id = $1 AND reviewed_plan_digest = $2 AND status = 'running'`,
          [ctx.tenantId, digest],
        );
        return rows[0] ? (await readComparisons(client, ctx.tenantId, rows))[0] : null;
      });
    },

    /** Newest first; an unknown or foreign-anchor cursor restarts at the first page, like the dev store. */
    async listComparisons(ctx, filter) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        let cursor = null;
        if (filter.cursor) {
          const { rows } = await client.query(
            `SELECT id, created_at FROM entry_path_comparisons
             WHERE tenant_id = $1 AND id = $2 AND ($3::text IS NULL OR anchor_target_id = $3)`,
            [ctx.tenantId, filter.cursor, filter.anchor_target_id],
          );
          cursor = rows[0] ?? null;
        }
        const { rows } = await client.query(
          `SELECT ${COMPARISON_COLUMNS} FROM entry_path_comparisons
           WHERE tenant_id = $1 AND ($2::text IS NULL OR anchor_target_id = $2)
             AND ($4::timestamptz IS NULL OR (created_at, id COLLATE "C") < ($4::timestamptz, $5::text COLLATE "C"))
           ORDER BY created_at DESC, id COLLATE "C" DESC
           LIMIT $3`,
          [ctx.tenantId, filter.anchor_target_id, filter.limit + 1, cursor?.created_at ?? null, cursor?.id ?? null],
        );
        const page = rows.slice(0, filter.limit);
        const comparisons = await readComparisons(client, ctx.tenantId, page);
        return { rows: comparisons, next_cursor: rows.length > filter.limit ? page.at(-1)?.id ?? null : null };
      });
    },

    /** Running comparisons with startable, interrupted, or settled-but-unrecorded attempts. */
    async listDueComparisonIds(ctx, at, limit) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT c.id, c.tenant_id FROM entry_path_comparisons c
           WHERE c.tenant_id = $1 AND c.status = 'running' AND (
             c.reconcile_seq > c.reconciled_seq
             OR EXISTS (
               SELECT 1 FROM entry_path_comparison_items i
               WHERE i.tenant_id = c.tenant_id AND i.comparison_id = c.id AND (
                 i.status = 'pending'
                 OR (i.status = 'deferred' AND (i.deferred_until IS NULL OR i.deferred_until <= $2::timestamptz))
                 OR (i.status = 'running' AND (i.test_run_id IS NULL OR EXISTS (
                   SELECT 1 FROM test_runs r
                   WHERE r.tenant_id = i.tenant_id AND r.id = i.test_run_id AND NOT (r.status = ANY($4::text[]))
                 )))
               )
             )
           )
           ORDER BY c.created_at, c.id
           LIMIT $3`,
          [ctx.tenantId, at, limit, ACTIVE_RUN_STATUSES],
        );
        return rows;
      });
    },

    async listUnlinkedFinished(ctx, limit) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${COMPARISON_COLUMNS} FROM entry_path_comparisons
           WHERE tenant_id = $1 AND status <> 'running' AND evaluation_json IS NOT NULL AND evaluation_id IS NULL
           ORDER BY completed_at, id
           LIMIT $2`,
          [ctx.tenantId, limit],
        );
        return readComparisons(client, ctx.tenantId, rows);
      });
    },

    async findRunningByRun(tenantId, runId) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT c.id, c.tenant_id FROM entry_path_comparison_items i
           JOIN entry_path_comparisons c ON c.tenant_id = i.tenant_id AND c.id = i.comparison_id
           WHERE i.tenant_id = $1 AND i.test_run_id = $2 AND c.status = 'running'`,
          [tenantId, runId],
        );
        return rows;
      });
    },

    async requestReconcile(tenantId, id) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rowCount } = await client.query(
          `UPDATE entry_path_comparisons SET reconcile_seq = reconcile_seq + 1, updated_at = NOW()
           WHERE tenant_id = $1 AND id = $2 AND status = 'running'`,
          [tenantId, id],
        );
        return rowCount === 1;
      });
    },

    async reconcileRequested(tenantId, id) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT reconcile_seq > reconciled_seq AS requested FROM entry_path_comparisons
           WHERE tenant_id = $1 AND id = $2 AND status = 'running'`,
          [tenantId, id],
        );
        return rows[0]?.requested === true;
      });
    },

    async linkEvaluation(tenantId, id, evaluationId) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rowCount } = await client.query(
          `UPDATE entry_path_comparisons SET evaluation_id = $3, updated_at = NOW()
           WHERE tenant_id = $1 AND id = $2 AND status <> 'running' AND evaluation_id IS NULL`,
          [tenantId, id, evaluationId],
        );
        return rowCount === 1;
      });
    },

    async appendAuditEntries(ctx, entries) {
      if (!entries.length) return;
      await withTenantContext(pool, ctx.tenantId, (client) => appendAudits(audit, entries, client));
    },

    /** Non-blocking per-comparison session lock; `wait` polls briefly for a user-initiated stop; no lock connection reads as busy. */
    async acquireLock(tenantId, id, lockOptions = {}) {
      let client;
      try {
        client = await resolveLockPool().connect();
      } catch {
        incMetric('entry_path_comparison_lock_unavailable');
        return null;
      }
      let broken = false;
      const onError = () => {
        broken = true;
      };
      client.on('error', onError);
      const deadline = Date.now() + (lockOptions.wait ? LOCK_WAIT_MS : 0);
      try {
        for (;;) {
          const { rows } = await client.query(
            'SELECT pg_try_advisory_lock(hashtext($1), hashtext($2)) AS acquired',
            [LOCK_NAMESPACE, `${tenantId}:${id}`],
          );
          if (rows[0]?.acquired === true) return { client, key: `${tenantId}:${id}`, onError, isBroken: () => broken };
          if (Date.now() >= deadline) break;
          await sleep(LOCK_POLL_MS);
        }
      } catch (err) {
        client.removeListener('error', onError);
        client.release(err instanceof Error ? err : new Error('comparison lock failed'));
        incMetric('entry_path_comparison_lock_unavailable');
        return null;
      }
      client.removeListener('error', onError);
      client.release();
      return null;
    },

    async releaseLock(handle) {
      if (!handle?.client) return;
      let discard = handle.isBroken();
      if (!discard) {
        try {
          await handle.client.query('SELECT pg_advisory_unlock(hashtext($1), hashtext($2))', [LOCK_NAMESPACE, handle.key]);
        } catch {
          discard = true;
        }
      }
      handle.client.removeListener('error', handle.onError);
      handle.client.release(discard ? new Error('comparison lock release failed') : undefined);
    },

    async close() {
      if (ownedLockPool) {
        const toClose = ownedLockPool;
        ownedLockPool = null;
        await toClose.end();
      }
    },
  };
  return repo;
}

export const ENTRY_PATH_COMPARISON_REPOSITORY_METHODS = Object.freeze([
  'insertComparison', 'saveComparison', 'claimItem', 'getComparison', 'findByIdempotencyKey', 'findRunningByPlanDigest',
  'listComparisons', 'listDueComparisonIds', 'listUnlinkedFinished', 'findRunningByRun', 'requestReconcile',
  'reconcileRequested', 'linkEvaluation', 'appendAuditEntries', 'acquireLock', 'releaseLock',
]);
