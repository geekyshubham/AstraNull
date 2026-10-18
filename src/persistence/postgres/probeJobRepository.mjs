import { runWithTenantClient, withTenantContext } from './tenantContext.mjs';
import { incMetric } from '../../lib/metrics.mjs';
import { mergeProbeCapture } from '../../lib/probeExecution.mjs';
import { historicalOriginBindingForRun, validateOriginBindingForExecution } from '../../services/originBindings.mjs';

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
 * Structural half of the reciprocal ownership challenge binding.
 *
 * Open/active status is deliberately enforced by the lease query, while this predicate also
 * applies to terminal reads and transitions so an exact completed retry can be recognized after
 * verification closure without allowing a malformed historical row to reconcile.
 */

/** Revalidate the signed ownership proof at the worker boundary; no new destination is inferred. */
function currentSignedOwnershipProofSql(jobAlias) {
  return `(j.constraints_json ? 'ownership_binding'
                   AND EXISTS (
                     SELECT 1
                     FROM target_verification_current tvc
                     WHERE tvc.tenant_id = j.tenant_id
                       AND tvc.target_id = COALESCE(NULLIF(j.constraints_json->'ownership_binding'->>'inherited_from_target_id', ''), j.target_id)
                       AND (
                         NULLIF(j.constraints_json->'ownership_binding'->>'inherited_from_target_id', '') IS NULL
                         OR EXISTS (
                           SELECT 1 FROM targets child
                           JOIN targets parent ON parent.tenant_id = child.tenant_id AND parent.target_group_id = child.target_group_id
                           JOIN target_groups policy ON policy.tenant_id = child.tenant_id AND policy.id = child.target_group_id
                           WHERE child.tenant_id = j.tenant_id AND child.id = j.target_id
                             AND parent.id = tvc.target_id AND child.kind = 'fqdn' AND parent.kind = 'fqdn'
                             AND child.deleted_at IS NULL AND parent.deleted_at IS NULL
                             AND policy.deleted_at IS NULL AND policy.archived_at IS NULL
                             AND child.metadata_json->'tags' ? ('subdomain-of:' || parent.id)
                             AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(parent.metadata_json->'tags') = 'array'
                               THEN parent.metadata_json->'tags' ELSE '[]'::jsonb END) tag WHERE tag LIKE 'subdomain-of:%')
                             AND right(lower(COALESCE(child.normalized_value, child.value)), length(lower(COALESCE(parent.normalized_value, parent.value))) + 1)
                               = '.' || lower(COALESCE(parent.normalized_value, parent.value))
                         )
                       )
                       AND tvc.state = j.constraints_json->'ownership_binding'->>'state'
                       AND tvc.source_kind = j.constraints_json->'ownership_binding'->>'kind'
                       AND tvc.transitioned_at = (
                         j.constraints_json->'ownership_binding'->>'transitioned_at'
                       )::timestamptz
                       AND (
                         tvc.state <> 'provider_verified'
                         OR EXISTS (
                           SELECT 1
                           FROM tenant_connector_features feature
                           JOIN waf_connectors connector
                             ON connector.tenant_id = feature.tenant_id
                           JOIN waf_connector_snapshots snapshot
                             ON snapshot.tenant_id = connector.tenant_id
                            AND snapshot.connector_id = connector.id
                           WHERE feature.tenant_id = j.tenant_id
                             AND feature.enabled = TRUE
                             AND feature.revision = (
                               j.constraints_json->'ownership_binding'->'provider_provenance'->>'feature_revision'
                             )::bigint
                             AND connector.id = j.constraints_json->'ownership_binding'->'provider_provenance'->>'connector_id'
                             AND connector.provider = j.constraints_json->'ownership_binding'->'provider_provenance'->>'connector_provider'
                             AND connector.secret_id = j.constraints_json->'ownership_binding'->'provider_provenance'->>'connector_secret_id'
                             AND connector.status NOT IN ('disabled', 'revoked')
                             AND connector.last_success_revision = (
                               j.constraints_json->'ownership_binding'->'provider_provenance'->>'connector_revision'
                             )::bigint
                             AND connector.last_success_at = (
                               j.constraints_json->'ownership_binding'->'provider_provenance'->>'connector_generation'
                             )::timestamptz
                             AND snapshot.id = j.constraints_json->'ownership_binding'->'provider_provenance'->>'snapshot_id'
                             AND snapshot.provider = connector.provider
                             AND snapshot.snapshot_kind = 'dns_zone'
                             AND snapshot.evidence_source = 'provider_api'
                             AND snapshot.resource_ref_hash = j.constraints_json->'ownership_binding'->'provider_provenance'->>'snapshot_resource_ref_hash'
                             AND snapshot.poll_revision = connector.last_success_revision
                             AND snapshot.observed_at = connector.last_success_at
                         )
                       )
                   ))`.replace(/\bj\./g, `${jobAlias}.`);
}

function reciprocalOwnershipJobBindingSql(jobAlias) {
  return `(
    (
      ${jobAlias}.check_id <> 'ownership.challenge'
      AND ${jobAlias}.ownership_verification_id IS NULL
      AND NOT EXISTS (
        SELECT 1
        FROM ownership_verifications ordinary_binding
        WHERE ordinary_binding.tenant_id = ${jobAlias}.tenant_id
          AND ordinary_binding.probe_job_id = ${jobAlias}.id
      )
    )
    OR (
      ${jobAlias}.check_id = 'ownership.challenge'
      AND ${jobAlias}.ownership_verification_id IS NOT NULL
      AND EXISTS (
        SELECT 1
        FROM ownership_verifications binding
        WHERE binding.tenant_id = ${jobAlias}.tenant_id
          AND binding.id = ${jobAlias}.ownership_verification_id
          AND binding.probe_job_id = ${jobAlias}.id
          AND ${jobAlias}.test_run_id = binding.id
          AND ${jobAlias}.target_id = binding.agent_id
          AND ${jobAlias}.nonce_hash = binding.challenge_nonce_hash
          AND ${jobAlias}.target_descriptor_json->>'kind' = 'fqdn'
          AND lower(btrim(${jobAlias}.target_descriptor_json->>'value'))
            = lower(btrim(binding.declared_fqdn))
      )
    )
  )`;
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
        // This is the authoritative lease gate. The service-level read is only an inexpensive
        // precheck: activation and leasing serialize on this exact key, then leasing re-reads
        // the flag on the lock-holding transaction before it can mutate a job.
        await client.query(
          'SELECT pg_advisory_xact_lock(hashtext($1))',
          [`kill_switch_state:${tenantId}`],
        );
        const killSwitchResult = await client.query(
          `SELECT active
           FROM soc_kill_switch
           WHERE tenant_id = $1`,
          [tenantId],
        );
        if (killSwitchResult.rows[0]?.active === true) return [];

        const { rows } = await client.query(
          `WITH picked AS (
             SELECT candidate.id, candidate.status AS prior_status
             FROM probe_jobs AS candidate
             WHERE candidate.tenant_id = $1
               AND (
                 candidate.status = 'pending'
                 OR (candidate.status = 'leased' AND candidate.leased_at < now() - ${LEASE_TTL_INTERVAL_SQL})
               )
               AND ${reciprocalOwnershipJobBindingSql('candidate')}
               AND (
                 NULLIF(candidate.constraints_json->>'required_perspective_id', '') IS NULL
                 OR candidate.constraints_json->>'required_perspective_id' = $9::text
               )
               AND (
                 (candidate.ownership_verification_id IS NULL AND EXISTS (
                   SELECT 1
                   FROM test_runs tr
                   WHERE tr.tenant_id = candidate.tenant_id
                     AND tr.id = candidate.test_run_id
                     AND tr.status IN ('running', 'collecting')
                     AND (NOT COALESCE(candidate.constraints_json->'ownership_binding' ? 'inherited_from_target_id', FALSE)
                       OR ${currentSignedOwnershipProofSql('candidate')})
                 ))
                 OR
                 (candidate.ownership_verification_id IS NOT NULL AND EXISTS (
                   SELECT 1
                   FROM ownership_verifications ov
                   JOIN target_groups tg
                     ON tg.tenant_id = ov.tenant_id AND tg.id = ov.target_group_id
                   JOIN agents a
                     ON a.tenant_id = ov.tenant_id AND a.id = ov.agent_id
                   JOIN targets t
                     ON t.tenant_id = ov.tenant_id AND t.target_group_id = ov.target_group_id
                    AND t.deleted_at IS NULL AND t.kind = 'fqdn'
                    AND COALESCE(t.normalized_value, lower(btrim(t.value))) = lower(btrim(ov.declared_fqdn))
                   WHERE ov.tenant_id = candidate.tenant_id
                     AND ov.id = candidate.ownership_verification_id
                     AND ov.status = 'challenge_sent'
                     AND tg.deleted_at IS NULL AND tg.archived_at IS NULL
                     AND a.target_group_id = ov.target_group_id
                     AND a.status = 'online'
                     AND COALESCE(a.last_token_validation_status, 'valid') <> 'invalid'
                 ))
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
            typeof options.perspectiveId === 'string' && options.perspectiveId ? options.perspectiveId : null,
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
           FROM probe_jobs AS j
           WHERE j.tenant_id = $1 AND j.test_run_id = $2
             AND ${reciprocalOwnershipJobBindingSql('j')}
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
           FROM probe_jobs AS j
           WHERE j.tenant_id = $1 AND j.id = $2
             AND ${reciprocalOwnershipJobBindingSql('j')}`,
          [ctx.tenantId, id],
        );
        return mapProbeJobRow(rows[0] ?? null);
      });
    },

    async claimPendingJobForWorker(ctx, id, workerId, leasedAt, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `UPDATE probe_jobs AS j
           SET status = 'leased',
               leased_at = $4::timestamptz,
               leased_by = $3
           WHERE j.tenant_id = $1 AND j.id = $2 AND j.status = 'pending'
             AND ${reciprocalOwnershipJobBindingSql('j')}
             AND (
               (j.ownership_verification_id IS NULL AND EXISTS (
                 SELECT 1 FROM test_runs tr
                 WHERE tr.tenant_id = j.tenant_id AND tr.id = j.test_run_id
                   AND tr.status IN ('running', 'collecting')
                   AND ${currentSignedOwnershipProofSql('j')}
               ))
               OR
               (j.ownership_verification_id IS NOT NULL AND EXISTS (
                 SELECT 1
                 FROM ownership_verifications ov
                 JOIN target_groups tg
                   ON tg.tenant_id = ov.tenant_id AND tg.id = ov.target_group_id
                 JOIN agents a
                   ON a.tenant_id = ov.tenant_id AND a.id = ov.agent_id
                 JOIN targets t
                   ON t.tenant_id = ov.tenant_id AND t.target_group_id = ov.target_group_id
                  AND t.deleted_at IS NULL AND t.kind = 'fqdn'
                  AND COALESCE(t.normalized_value, lower(btrim(t.value))) = lower(btrim(ov.declared_fqdn))
                 WHERE ov.tenant_id = j.tenant_id
                   AND ov.id = j.ownership_verification_id
                   AND ov.status = 'challenge_sent'
                   AND tg.deleted_at IS NULL AND tg.archived_at IS NULL
                   AND a.target_group_id = ov.target_group_id
                   AND a.status = 'online'
                   AND COALESCE(a.last_token_validation_status, 'valid') <> 'invalid'
               ))
             )
           RETURNING ${PROBE_JOB_COLUMNS_QUALIFIED}`,
          [ctx.tenantId, id, workerId, leasedAt],
        );
        return mapProbeJobRow(rows[0] ?? null);
      });
    },

    async claimJobForResult(ctx, id, workerId, leasedAt, expected = {}, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const expectedStatus = expected.status ?? 'pending';
        const expectedLeasedBy = expected.leased_by ?? null;
        const expectedLeasedAt = expected.leased_at ?? null;
        const { rows } = await client.query(
          `UPDATE probe_jobs AS j
           SET status = 'leased', leased_at = CASE
             WHEN j.status = 'leased' AND j.leased_by = $3 THEN j.leased_at
             ELSE $4::timestamptz END, leased_by = $3
           WHERE j.tenant_id = $1 AND j.id = $2
             AND j.status = $5
             AND j.leased_by IS NOT DISTINCT FROM $6
             AND j.leased_at IS NOT DISTINCT FROM $7::timestamptz
             AND ${reciprocalOwnershipJobBindingSql('j')}
           RETURNING ${PROBE_JOB_COLUMNS}`,
          [ctx.tenantId, id, workerId, leasedAt, expectedStatus, expectedLeasedBy, expectedLeasedAt],
        );
        return mapProbeJobRow(rows[0] ?? null);
      });
    },

    async reserveExecution(ctx, job, reservation, options = {}) {
      if (Object.hasOwn(job?.constraints ?? {}, 'reviewed_operation_binding')) return null;
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        // Hold the declared destination and policy rows through the durable grant. The lease
        // alone is not authorization: ownership or target binding can change after polling.
        await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [ctx.tenantId]);
        const runResult = await client.query(`SELECT * FROM test_runs
          WHERE tenant_id = $1 AND id = $2 FOR SHARE`, [ctx.tenantId, job.test_run_id]);
        const run = runResult.rows[0];
        const reference = historicalOriginBindingForRun(run);
        let binding = null;
        if (reference) {
          const found = await client.query(`SELECT * FROM origin_bindings
            WHERE tenant_id = $1 AND id = $2 FOR SHARE`, [ctx.tenantId, reference.id]);
          binding = found.rows[0] ?? null;
        }
        const targetIds = [...new Set([job.target_id, binding?.origin_target_id, binding?.protected_target_id].filter(Boolean))];
        // Verification transitions lock their target row (advance_target_verification_clock).
        // Both descriptors, declarations and both proof clocks remain stable until COMMIT.
        const targets = await client.query(`SELECT t.*, t.metadata_json AS metadata FROM targets t
          JOIN target_groups tg ON tg.tenant_id = t.tenant_id AND tg.id = t.target_group_id
          WHERE t.tenant_id = $1
            AND (t.id = ANY($2::text[]) OR EXISTS (SELECT 1 FROM targets child
              WHERE child.tenant_id = t.tenant_id AND child.id = ANY($2::text[]) AND child.target_group_id = t.target_group_id
                AND child.metadata_json->'tags' ? ('subdomain-of:' || t.id)))
            AND t.deleted_at IS NULL AND tg.deleted_at IS NULL AND tg.archived_at IS NULL
          ORDER BY t.id FOR SHARE OF t, tg`, [ctx.tenantId, targetIds]);
        const proofs = await client.query(`SELECT *,
          to_char(transitioned_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS transitioned_at
          FROM target_verification_current WHERE tenant_id = $1 AND target_id = ANY($2::text[])`, [ctx.tenantId, targets.rows.map((row) => row.id)]);
        const connectors = reference ? await client.query(`SELECT * FROM waf_connectors WHERE tenant_id = $1 FOR SHARE`, [ctx.tenantId]) : { rows: [] };
        const snapshots = reference ? await client.query(`SELECT * FROM waf_connector_snapshots WHERE tenant_id = $1 FOR SHARE`, [ctx.tenantId]) : { rows: [] };
        const records = { targets: targets.rows, targetVerifications: proofs.rows,
          wafConnectors: connectors.rows.map((row) => ({ ...row, has_secret: Boolean(row.secret_id) })),
          wafConnectorSnapshots: snapshots.rows.map((row) => ({ ...row, summary: row.summary_json })) };
        if (validateOriginBindingForExecution({ job, run, binding, records }).error) return null;
        const { rows } = await client.query(`UPDATE probe_jobs AS j SET worker_metadata_json =
          COALESCE(j.worker_metadata_json, '{}'::jsonb) || jsonb_build_object('execution_reservation', $5::jsonb)
          WHERE j.tenant_id = $1 AND j.id = $2 AND j.status = 'leased' AND j.leased_by = $3
            AND j.leased_at = $4::timestamptz AND j.ownership_verification_id IS NULL
            AND NOT (COALESCE(j.worker_metadata_json, '{}'::jsonb) ? 'execution_reservation')
            AND NOT (COALESCE(j.constraints_json, '{}'::jsonb) ? 'reviewed_operation_binding')
            AND ${reciprocalOwnershipJobBindingSql('j')}
            AND ${currentSignedOwnershipProofSql('j')}
            AND EXISTS (SELECT 1 FROM test_runs tr
              JOIN targets t ON t.tenant_id = tr.tenant_id AND t.id = tr.target_id
              JOIN target_groups tg ON tg.tenant_id = t.tenant_id AND tg.id = t.target_group_id
              WHERE tr.tenant_id = j.tenant_id AND tr.id = j.test_run_id AND tr.target_id = j.target_id
                AND tr.check_id = j.check_id AND tr.status IN ('running', 'collecting')
                AND tr.target_group_id = t.target_group_id AND t.deleted_at IS NULL
                AND tg.deleted_at IS NULL AND tg.archived_at IS NULL
                AND t.kind = j.target_descriptor_json->>'kind' AND t.value = j.target_descriptor_json->>'value'
                AND t.port::text IS NOT DISTINCT FROM j.target_descriptor_json->>'port'
                AND t.protocol IS NOT DISTINCT FROM j.target_descriptor_json->>'protocol')
          RETURNING ${PROBE_JOB_COLUMNS_QUALIFIED}`, [ctx.tenantId, job.id, ctx.workerId, job.leased_at, JSON.stringify(reservation)]);
        return mapProbeJobRow(rows[0]);
      });
    },

    async recordJobTelemetry(ctx, job, { capture, acknowledgment } = {}, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const metadata = {};
        if (capture) metadata.capture = mergeProbeCapture(job.worker_metadata?.capture, capture);
        if (acknowledgment) metadata.stop_acknowledgment = job.worker_metadata?.stop_acknowledgment ?? acknowledgment;
        const { rows } = await client.query(`UPDATE probe_jobs SET worker_metadata_json =
          COALESCE(worker_metadata_json, '{}'::jsonb) || $5::jsonb
          WHERE tenant_id = $1 AND id = $2 AND leased_by = $3 AND leased_at = $4::timestamptz
          RETURNING ${PROBE_JOB_COLUMNS}`, [ctx.tenantId, job.id, ctx.workerId, job.leased_at, JSON.stringify(metadata)]);
        return mapProbeJobRow(rows[0]);
      });
    },

    async markJobCompleted(ctx, id, completedAt, lease = {}, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `UPDATE probe_jobs AS j
           SET status = 'completed',
               completed_at = $3::timestamptz
           WHERE j.tenant_id = $1 AND j.id = $2
             AND j.status = 'leased'
             AND j.leased_by = $4
             AND j.leased_at = $5::timestamptz
             AND ${reciprocalOwnershipJobBindingSql('j')}
           RETURNING ${PROBE_JOB_COLUMNS}`,
          [ctx.tenantId, id, completedAt, lease.workerId, lease.leasedAt],
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

    async createProbeJob(ctx, record, options = {}) {
      const tenantId = ctx.tenantId;
      const probeProfile = JSON.stringify(asObject(record.probe_profile));
      const constraintsJson = JSON.stringify(asObject(record.constraints ?? record.constraints_json));
      const targetDescriptorJson = JSON.stringify(asObject(record.target ?? record.target_descriptor_json));
      const workerMetadataJson = JSON.stringify(
        asObject(record.worker_metadata ?? record.worker_metadata_json),
      );

      return runWithTenantClient(pool, tenantId, options.client, async (client) => {
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
          `SELECT ${PROBE_JOB_COLUMNS},
                  ${reciprocalOwnershipJobBindingSql('probe_jobs')} AS ownership_binding_valid
           FROM probe_jobs
           WHERE tenant_id = $1 AND test_run_id = $2
           ORDER BY created_at
           LIMIT 2`,
          [tenantId, record.test_run_id],
        );
        if (existingResult.rows.length > 1) {
          throw new Error('multiple_probe_jobs_for_test_run');
        }
        const existingRow = existingResult.rows[0] ?? null;
        const existing = mapProbeJobRow(existingRow);
        if (existing) {
          if (existingRow.ownership_binding_valid !== true) {
            throw new Error('probe_job_ownership_binding_conflict');
          }
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
