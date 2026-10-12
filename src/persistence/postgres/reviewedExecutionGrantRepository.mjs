import { createHash } from 'node:crypto';
import { withStandaloneTenantContext } from './tenantContext.mjs';
import { mapProbeJobRow } from './probeJobRepository.mjs';

const hash = (value) => createHash('sha256').update(value).digest('hex');
const exactTime = (column) => `to_char(${column} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const millisOnly = (value) => typeof value === 'string' ? value.replace(/(\.\d{3})000Z$/, '$1Z') : value;
const COLUMNS = ['id', 'tenant_id', 'probe_job_id', 'test_run_id', 'target_id', 'check_id', 'reservation_id', 'review_id',
  'plan_digest', 'worker_id', 'leased_at', 'original_job_payload', 'original_job_payload_sha256', 'original_job_signature',
  'original_job_signature_sha256', 'reservation_json', 'provenance_json', 'envelope_json', 'envelope_canonical', 'envelope_sha256',
  'completion_token_hash', 'claimed_at'];
const JSON_COLUMNS = new Set(['reservation_json', 'provenance_json', 'envelope_json']);
const LEDGER_COLUMNS = `*, ${exactTime('leased_at')} AS leased_at, ${exactTime('claimed_at')} AS claimed_at,
  ${exactTime('finished_at')} AS finished_at`;
function ledger(row) {
  return row ? { ...row, leased_at: millisOnly(row.leased_at), claimed_at: millisOnly(row.claimed_at), finished_at: millisOnly(row.finished_at) } : null;
}
const denied = (error) => ({ ok: false, error, status: 409, grants_execution: false, execution_available: false });

/** Unregistered PostgreSQL-only ledger. All callbacks return before COMMIT; callers sign ONLY after withTransaction resolves. */
export function createReviewedExecutionGrantRepository(pool, { audit, authority } = {}) {
  if (typeof pool?.connect !== 'function' || typeof audit?.appendAuditEvent !== 'function'
    || typeof authority?.withCurrentAuthority !== 'function') throw new Error('durable reviewed grant dependencies required');
  const audited = (client, ctx, row, action, metadata = {}) => audit.appendAuditEvent({ tenant_id: ctx.tenantId,
    actor_user_id: ctx.workerId, actor_role: 'probe_worker', action, resource_type: 'reviewed_execution_grant_issuance', resource_id: row.id,
    metadata: { test_run_id: row.test_run_id, probe_job_id: row.probe_job_id, reservation_id: row.reservation_id,
      envelope_sha256: row.envelope_sha256, ...metadata } }, { client });
  async function auditFirst(client, tenant) {
    await client.query("SET LOCAL statement_timeout = '10s'");
    await client.query("SET LOCAL lock_timeout = '5s'");
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [tenant]);
  }
  const now = async (client) => (await client.query("SELECT date_trunc('milliseconds', clock_timestamp()) AS checked_at")).rows[0].checked_at.toISOString();
  return {
    durableReviewedGrantBackend: true,
    withTransaction: (ctx, { jobId, reservationId }, callback) => withStandaloneTenantContext(pool, ctx.tenantId, async (client) => {
      await auditFirst(client, ctx.tenantId);
      const first = (await client.query('SELECT test_run_id FROM probe_jobs WHERE tenant_id = $1 AND id = $2', [ctx.tenantId, jobId])).rows[0];
      if (!first) return denied('reviewed_grant_job_unavailable');
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`test_run_mutation:${first.test_run_id}`]);
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`kill_switch_state:${ctx.tenantId}`]);
      const raw = (await client.query(`SELECT *, ${exactTime('leased_at')} AS exact_leased_at
        FROM probe_jobs WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, [ctx.tenantId, jobId])).rows[0];
      if (!raw || raw.test_run_id !== first.test_run_id) return denied('reviewed_grant_job_changed');
      const runJobs = (await client.query('SELECT id FROM probe_jobs WHERE tenant_id = $1 AND test_run_id = $2 FOR SHARE',
        [ctx.tenantId, raw.test_run_id])).rows;
      if (runJobs.length !== 1 || runJobs[0].id !== jobId) return denied('reviewed_grant_run_jobs_ambiguous');
      const job = mapProbeJobRow(raw);
      job.leased_at = millisOnly(raw.exact_leased_at);
      // Never carry a plaintext worker nonce into persisted envelope/audit material.
      delete job.nonce;
      const run = (await client.query(`SELECT *, ${exactTime('collection_deadline_at')} AS exact_deadline
        FROM test_runs WHERE tenant_id = $1 AND id = $2 FOR SHARE`, [ctx.tenantId, job.test_run_id])).rows[0] ?? null;
      if (run) run.collection_deadline_at = millisOnly(run.exact_deadline);
      const policy = run?.policy_id ? (await client.query('SELECT * FROM test_policies WHERE tenant_id = $1 AND id = $2 FOR SHARE',
        [ctx.tenantId, run.policy_id])).rows[0] ?? null : null;
      const killSwitch = (await client.query('SELECT active FROM soc_kill_switch WHERE tenant_id = $1 FOR SHARE', [ctx.tenantId])).rows[0] ?? null;
      const reservation = raw.worker_metadata_json?.execution_reservation;
      return callback({ job, run, policy, killSwitch, reservation,
        now: () => now(client),
        withAuthority: (fn) => authority.withCurrentAuthority(ctx, { mode: 'compare', targetId: job.target_id,
          checkId: job.check_id, binding: job.constraints.reviewed_operation_binding }, fn, { client }),
        getSlot: async () => ledger((await client.query(`SELECT ${LEDGER_COLUMNS} FROM reviewed_execution_grant_issuances
          WHERE tenant_id = $1 AND (probe_job_id = $2 OR test_run_id = $3 OR reservation_id = $4) FOR UPDATE`,
        [ctx.tenantId, jobId, job.test_run_id, reservationId])).rows[0]),
        async insert(row) {
          const values = COLUMNS.map((column) => JSON_COLUMNS.has(column) ? JSON.stringify(row[column]) : row[column]);
          const parameters = COLUMNS.map((column, index) => `$${index + 1}${JSON_COLUMNS.has(column) ? '::jsonb' : ''}`).join(', ');
          await client.query(`INSERT INTO reviewed_execution_grant_issuances (${COLUMNS.join(', ')}) VALUES (${parameters})`, values);
          await audited(client, ctx, row, 'reviewed_execution_grant.signing_claimed');
        },
        async finish(row, completionToken, signature, finishedAt) {
          const updated = (await client.query(`UPDATE reviewed_execution_grant_issuances SET state = 'issued',
            grant_signature = $4, finished_at = $5 WHERE tenant_id = $1 AND id = $2
            AND state = 'signing_unknown' AND completion_token_hash = $3 RETURNING ${LEDGER_COLUMNS}`,
          [ctx.tenantId, row.id, hash(completionToken), signature, finishedAt])).rows[0];
          if (!updated) return null;
          const result = ledger(updated);
          await audited(client, ctx, result, 'reviewed_execution_grant.issued');
          return result;
        },
      });
    }),
    // Failed reauthorization cannot prevent conservative closure. Still requires the ORIGINAL owner token.
    closeUnknown: (ctx, id, completionToken, failureCode) => withStandaloneTenantContext(pool, ctx.tenantId, async (client) => {
      await auditFirst(client, ctx.tenantId);
      const row = ledger((await client.query(`SELECT ${LEDGER_COLUMNS} FROM reviewed_execution_grant_issuances
        WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, [ctx.tenantId, id])).rows[0]);
      if (!row || row.state !== 'signing_unknown' || row.completion_token_hash !== hash(completionToken)) return false;
      const finishedAt = await now(client);
      await client.query(`UPDATE reviewed_execution_grant_issuances SET state = 'closed_unknown', failure_code = $4, finished_at = $5
        WHERE tenant_id = $1 AND id = $2 AND state = 'signing_unknown' AND completion_token_hash = $3`,
      [ctx.tenantId, id, hash(completionToken), failureCode, finishedAt]);
      await audited(client, ctx, row, 'reviewed_execution_grant.closed_unknown', { failure_code: failureCode });
      return true;
    }),
  };
}
