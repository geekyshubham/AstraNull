import { runWithTenantClient, withTenantContext } from './tenantContext.mjs';
import { incMetric } from '../../lib/metrics.mjs';

const PROBE_JOB_COLUMNS = `id, tenant_id, test_run_id, target_id, check_id, vector_family, status,
  nonce_hash, nonce_for_worker, probe_profile, constraints_json, target_descriptor_json,
  worker_metadata_json, job_signature, leased_at, leased_by, completed_at, ownership_verification_id,
  created_at`;

const PROBE_JOB_COLUMNS_QUALIFIED = PROBE_JOB_COLUMNS.split(',')
  .map((column) => `j.${column.trim()}`)
  .join(', ');

// The worker heartbeat is considered stale at 120 seconds. Leasing one row per poll keeps a
// successful cycle bounded to one destination and prevents later rows in a serial batch from
// aging invisibly behind an earlier probe.
const DEFAULT_LEASE_LIMIT = 1;
const MAX_LEASE_LIMIT = 1;

/**
 * Lease TTL derivation for the single-job worker cycle.
 *
 * The worker has its own 110-second hard cycle deadline. The lease remains longer than that
 * deadline (plus restart/clock-skew allowance), preventing a live worker from being duplicated
 * while still reclaiming a crashed worker's row in minutes rather than hours.
 *
 * A missing or non-numeric max_duration_seconds falls back to the catalog maximum rather than
 * erroring, so one malformed constraints_json row cannot break lease polling for the tenant.
 */
const LEASE_TTL_FLOOR_SECONDS = 180;
const LEASE_TTL_DEFAULT_PER_JOB_SECONDS = 120;
const LEASE_TTL_BATCH_FACTOR = MAX_LEASE_LIMIT;
const LEASE_TTL_OVERHEAD_SECONDS = 60;

/**
 * Per-row stale-lease cutoff. Kept as a fragment (not a literal) so every tunable stays a
 * bound parameter.
 */
const LEASE_TTL_INTERVAL_SQL = `(
  GREATEST(
    $5::numeric,
    (CASE
       WHEN constraints_json->>'max_duration_seconds' ~ '^[0-9]+(\\.[0-9]+)?$'
         THEN (constraints_json->>'max_duration_seconds')::numeric
       ELSE $6::numeric
     END) * $7::numeric + $8::numeric
  ) * interval '1 second'
)`;

/**
 * JS mirror of LEASE_TTL_INTERVAL_SQL, for callers that must reason about lease staleness
 * outside the lease query itself (the ingest path's `leased_by` guard). Kept beside the SQL
 * so the two cannot drift.
 *
 * @param {Record<string, unknown> | null | undefined} constraints
 * @returns {number} TTL in seconds
 */
export function probeJobLeaseTtlSeconds(constraints) {
  // Apply the SAME regex as LEASE_TTL_INTERVAL_SQL rather than leaning on Number() coercion.
  // The two disagree in ways that matter: Number('') is 0 (regex rejects ''), Number(' 5 ') is
  // 5 (regex rejects whitespace), Number('1e3') is 1000 (regex rejects exponents). Any such
  // disagreement lets the lease query reclaim a row while this guard still believes the old
  // lease live — the new holder's result is then rejected, re-creating the wedge Defect 2
  // removes. Note '0' IS accepted by both and yields the floor, not the default.
  const raw = asObject(constraints).max_duration_seconds;
  const text = raw == null ? '' : String(raw);
  const perJob = /^[0-9]+(\.[0-9]+)?$/.test(text)
    ? Number(text)
    : LEASE_TTL_DEFAULT_PER_JOB_SECONDS;
  return Math.max(
    LEASE_TTL_FLOOR_SECONDS,
    perJob * LEASE_TTL_BATCH_FACTOR + LEASE_TTL_OVERHEAD_SECONDS,
  );
}

/**
 * Whether a 'leased' job's lease has provably expired.
 *
 * Fails CLOSED (returns false — "still live, do not touch") when `leased_at` is missing or
 * unparseable, so absent evidence never authorizes stealing a lease from a running worker.
 *
 * @param {{ status?: string, leased_at?: string | null, constraints?: Record<string, unknown> }} job
 * @param {Date} now
 */
export function isProbeJobLeaseStale(job, now = new Date()) {
  if (job?.status !== 'leased') return false;
  if (job.leased_at == null) return false;
  const leasedAtMs = new Date(job.leased_at).getTime();
  if (!Number.isFinite(leasedAtMs)) return false;
  const nowMs = now instanceof Date ? now.getTime() : new Date(now).getTime();
  if (!Number.isFinite(nowMs)) return false;
  return nowMs - leasedAtMs > probeJobLeaseTtlSeconds(job.constraints) * 1000;
}

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function asObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  return {};
}

function normalizeLeaseLimit(limit) {
  if (limit === undefined || limit === null) return DEFAULT_LEASE_LIMIT;
  const n = Number(limit);
  if (!Number.isFinite(n) || n < 1) return DEFAULT_LEASE_LIMIT;
  return Math.min(Math.floor(n), MAX_LEASE_LIMIT);
}

/**
 * @param {Record<string, unknown> | null | undefined} row
 */
export function mapProbeJobRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    test_run_id: row.test_run_id,
    target_id: row.target_id ?? undefined,
    check_id: row.check_id,
    vector_family: row.vector_family ?? undefined,
    status: row.status,
    nonce_hash: row.nonce_hash,
    nonce: row.nonce_for_worker ?? undefined,
    probe_profile: asObject(row.probe_profile),
    constraints: asObject(row.constraints_json),
    target: asObject(row.target_descriptor_json),
    worker_metadata: asObject(row.worker_metadata_json),
    job_signature: row.job_signature ?? undefined,
    leased_at: row.leased_at == null ? null : toIso(row.leased_at),
    leased_by: row.leased_by ?? null,
    completed_at: row.completed_at == null ? null : toIso(row.completed_at),
    created_at: toIso(row.created_at),
    ...(row.ownership_verification_id != null
      ? { ownership_verification_id: row.ownership_verification_id }
      : {}),
  };
}

function jobForWorkerResponse(job) {
  const { nonce, ...rest } = job;
  return {
    ...rest,
    nonce,
    job_signature: job.job_signature,
  };
}

/**
 * @param {import('pg').Pool} pool
 */
export function createProbeJobRepository(pool) {
  return {
    /**
     * Lease pending work, and reclaim leases whose holder is provably gone.
     *
     * The staleness branch is what stops one lost worker from wedging the target group's
     * active-run slot until an operator intervenes. Staleness is judged per row against that
     * row's own duration budget (see LEASE_TTL_INTERVAL_SQL) so a long-budget probe is never
     * measured against a short-budget one's clock.
     *
     * `leased_at IS NULL` never satisfies the range comparison, so a 'leased' row missing its
     * timestamp is left alone rather than stolen on no evidence.
     */
    async leasePendingJobsForWorker(ctx, workerId, options = {}) {
      const tenantId = ctx.tenantId;
      const limit = normalizeLeaseLimit(options.limit);
      const leasedAt = options.leasedAt ?? new Date().toISOString();

      return runWithTenantClient(pool, tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `WITH picked AS (
             SELECT id, status AS prior_status
             FROM probe_jobs
             WHERE tenant_id = $1
               AND (
                 status = 'pending'
                 OR (status = 'leased' AND leased_at < now() - ${LEASE_TTL_INTERVAL_SQL})
               )
             ORDER BY created_at
             LIMIT $2
             FOR UPDATE SKIP LOCKED
           )
           UPDATE probe_jobs AS j
           SET status = 'leased',
               leased_at = $3::timestamptz,
               leased_by = $4
           FROM picked
           WHERE j.id = picked.id AND j.tenant_id = $1
           RETURNING ${PROBE_JOB_COLUMNS_QUALIFIED}, picked.prior_status`,
          [
            tenantId,
            limit,
            leasedAt,
            workerId,
            LEASE_TTL_FLOOR_SECONDS,
            LEASE_TTL_DEFAULT_PER_JOB_SECONDS,
            LEASE_TTL_BATCH_FACTOR,
            LEASE_TTL_OVERHEAD_SECONDS,
          ],
        );

        const reclaimed = rows.filter((row) => row.prior_status === 'leased');
        if (reclaimed.length > 0) {
          incMetric('probe_job_leases_reclaimed_total', reclaimed.length);
        }

        return rows.map(mapProbeJobRow).map(jobForWorkerResponse);
      });
    },

    async getProbeJobByTestRun(ctx, testRunId, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT ${PROBE_JOB_COLUMNS}
           FROM probe_jobs
           WHERE tenant_id = $1 AND test_run_id = $2
           ORDER BY created_at
           LIMIT 2`,
          [ctx.tenantId, testRunId],
        );
        if (rows.length > 1) {
          throw new Error('multiple_probe_jobs_for_test_run');
        }
        return mapProbeJobRow(rows[0] ?? null);
      });
    },

    async getJobById(ctx, id, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT ${PROBE_JOB_COLUMNS}
           FROM probe_jobs
           WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapProbeJobRow(rows[0] ?? null);
      });
    },

    async claimPendingJobForWorker(ctx, id, workerId, leasedAt, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `UPDATE probe_jobs
           SET status = 'leased',
               leased_at = $4::timestamptz,
               leased_by = $3
           WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
           RETURNING ${PROBE_JOB_COLUMNS}`,
          [ctx.tenantId, id, workerId, leasedAt],
        );
        return mapProbeJobRow(rows[0] ?? null);
      });
    },

    async markJobCompleted(ctx, id, completedAt, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `UPDATE probe_jobs
           SET status = 'completed',
               completed_at = $3::timestamptz
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${PROBE_JOB_COLUMNS}`,
          [ctx.tenantId, id, completedAt],
        );
        return mapProbeJobRow(rows[0] ?? null);
      });
    },

    async cancelOpenProbeJobsForTestRuns(ctx, testRunIds, cancelledAt) {
      if (!testRunIds?.length) return [];
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE probe_jobs
           SET status = 'cancelled',
               completed_at = $3::timestamptz
           WHERE tenant_id = $1
             AND test_run_id = ANY($2::text[])
             AND status IN ('pending', 'leased')
           RETURNING ${PROBE_JOB_COLUMNS}`,
          [tenantId, testRunIds, cancelledAt],
        );
        return rows.map(mapProbeJobRow);
      });
    },

    async createProbeJob(ctx, record) {
      const tenantId = ctx.tenantId;
      const probeProfile = JSON.stringify(asObject(record.probe_profile));
      const constraintsJson = JSON.stringify(asObject(record.constraints ?? record.constraints_json));
      const targetDescriptorJson = JSON.stringify(asObject(record.target ?? record.target_descriptor_json));
      const workerMetadataJson = JSON.stringify(
        asObject(record.worker_metadata ?? record.worker_metadata_json),
      );

      return withTenantContext(pool, tenantId, async (client) => {
        const ownershipVerificationId = record.ownership_verification_id ?? null;

        // There is intentionally no schema change in this repair. Serialize creators by the
        // tenant/run binding, then reuse the durable row if a prior process committed it before
        // crashing. The lock also closes the concurrent retry race until a unique index can be
        // introduced in a separately governed migration.
        await client.query(
          'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
          [JSON.stringify([tenantId, record.test_run_id])],
        );
        const existingResult = await client.query(
          `SELECT ${PROBE_JOB_COLUMNS}
           FROM probe_jobs
           WHERE tenant_id = $1 AND test_run_id = $2
           ORDER BY created_at
           LIMIT 2`,
          [tenantId, record.test_run_id],
        );
        if (existingResult.rows.length > 1) {
          throw new Error('multiple_probe_jobs_for_test_run');
        }
        const existing = mapProbeJobRow(existingResult.rows[0] ?? null);
        if (existing) {
          const sameBinding = existing.check_id === record.check_id
            && (existing.target_id ?? null) === (record.target_id ?? null)
            && (existing.ownership_verification_id ?? null) === ownershipVerificationId;
          if (!sameBinding) throw new Error('probe_job_test_run_binding_conflict');
          return existing;
        }

        const { rows } = await client.query(
          `INSERT INTO probe_jobs (
             id, tenant_id, test_run_id, target_id, check_id, vector_family, status,
             nonce_hash, nonce_for_worker, probe_profile, constraints_json,
             target_descriptor_json, worker_metadata_json, job_signature,
             ownership_verification_id, created_at
           )
           VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12::jsonb, $13::jsonb,
             $14, $15, $16::timestamptz
           )
           RETURNING ${PROBE_JOB_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.test_run_id,
            record.target_id ?? null,
            record.check_id,
            record.vector_family ?? null,
            record.status ?? 'pending',
            record.nonce_hash,
            record.nonce ?? record.nonce_for_worker,
            probeProfile,
            constraintsJson,
            targetDescriptorJson,
            workerMetadataJson,
            record.job_signature ?? null,
            ownershipVerificationId,
            record.created_at,
          ],
        );
        return mapProbeJobRow(rows[0] ?? null);
      });
    },
  };
}