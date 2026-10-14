import { withStandaloneTenantContext, withTenantContext } from './tenantContext.mjs';
import { mapProbeJobRow } from './probeJobRepository.mjs';
import { canonicalJsonStringify } from '../../lib/custody.mjs';
import { getSubscriptionPlan } from '../../contracts/subscriptions.mjs';
import { isWithinSafeTestWindowRaw } from '../../lib/safeTestGuards.mjs';

const clock = (column) => `to_char(${column} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const millis = (value) => typeof value === 'string' ? value.replace(/(\.\d{3})000Z$/, '$1Z') : value;
const rowTimes = (row) => row && Object.fromEntries(Object.entries(row).map(([k,v]) => [k, v instanceof Date ? v.toISOString() : v]));
/** Server-backed uniqueness, not worker DB credentials. No retry, replacement or refund. */
export function createReviewedSafeExecutionRepository(pool, { audit, authority, validationEvidence, probeJobs } = {}) {
  if (!pool?.connect || !audit?.appendAuditEvent || !authority?.withCurrentAuthority || !validationEvidence?.appendEvent || !probeJobs?.markJobCompleted) throw new Error('reviewed execution durable dependencies required');
  const appendAudit = (client, ctx, job, action, metadata = {}) => audit.appendAuditEvent({ tenant_id: ctx.tenantId,
    actor_user_id: ctx.workerId, actor_role: 'probe_worker', action, resource_type: 'probe_job', resource_id: job.id,
    metadata: { test_run_id: job.test_run_id, ...metadata } }, { client });
  async function tenantGate(client, ctx, { admission = false } = {}) {
    const account = (await client.query('SELECT lifecycle_state FROM tenant_accounts WHERE tenant_id = $1 FOR SHARE', [ctx.tenantId])).rows[0];
    const subscription = (await client.query('SELECT * FROM tenant_subscriptions WHERE tenant_id = $1 FOR SHARE', [ctx.tenantId])).rows[0];
    if (account?.lifecycle_state !== 'active' || subscription?.status !== 'active'
      || !Number.isFinite(Date.parse(subscription.effective_at)) || Date.parse(subscription.effective_at) > Date.now()) {
      return { error: 'reviewed_execution_subscription_unavailable', status: 409 };
    }
    if (admission) {
      const limit = subscription.limits_json?.safe_runs_per_hour ?? getSubscriptionPlan(subscription.plan_id)?.limits.safe_runs_per_hour;
      const usage = (await client.query(`SELECT count(*) AS count FROM test_runs WHERE tenant_id = $1
        AND created_at >= clock_timestamp() - interval '1 hour' AND safety_class = 'safe'`, [ctx.tenantId])).rows[0];
      if (!Number.isSafeInteger(limit) || limit < 1 || Number(usage.count) >= limit) return { error: 'subscription_limit_exceeded', status: 429 };
    }
    return null;
  }
  return {
    durableReviewedExecutionBackend: true,
    withAdmission: (ctx, request, callback) => withTenantContext(pool, ctx.tenantId, (client) => authority.withCurrentAuthority(ctx, request, async (snapshot) => {
      const denied = await tenantGate(client,ctx,{ admission: true });
      if (denied) {
        await audit.appendAuditEvent({ tenant_id: ctx.tenantId, actor_user_id: ctx.userId, actor_role: ctx.role,
          action: 'reviewed_execution.admission_denied', resource_type: 'target', resource_id: snapshot.target.id,
          metadata: { reason: denied.error } }, { client });
        return denied;
      }
      if (!isWithinSafeTestWindowRaw(snapshot.targetGroup,Date.now())) return { error: 'safe_window_closed', status: 429 };
      return callback(snapshot);
    }, { client })),
    withTransaction: (ctx, jobId, callback) => withStandaloneTenantContext(pool, ctx.tenantId, async (client) => {
      await client.query("SET LOCAL statement_timeout = '10s'");
      await client.query("SET LOCAL lock_timeout = '5s'");
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [ctx.tenantId]);
      const first = (await client.query('SELECT test_run_id FROM probe_jobs WHERE tenant_id = $1 AND id = $2', [ctx.tenantId, jobId])).rows[0];
      if (!first) return { error: 'job_not_found', status: 404 };
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`test_run_mutation:${first.test_run_id}`]);
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`kill_switch_state:${ctx.tenantId}`]);
      const raw = (await client.query(`SELECT *, ${clock('leased_at')} AS exact_lease FROM probe_jobs WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, [ctx.tenantId, jobId])).rows[0];
      const job = mapProbeJobRow(raw); if (!job || job.test_run_id !== first.test_run_id) return { error: 'job_not_found', status: 404 };
      job.leased_at = millis(raw.exact_lease); delete job.nonce;
      const run = (await client.query(`SELECT *, ${clock('collection_deadline_at')} AS exact_deadline FROM test_runs WHERE tenant_id = $1 AND id = $2 FOR SHARE`, [ctx.tenantId, job.test_run_id])).rows[0];
      if (run) run.collection_deadline_at = millis(run.exact_deadline);
      const policy = run?.policy_id ? (await client.query('SELECT * FROM test_policies WHERE tenant_id = $1 AND id = $2 FOR SHARE', [ctx.tenantId, run.policy_id])).rows[0] : null;
      const jobs = (await client.query('SELECT id FROM probe_jobs WHERE tenant_id = $1 AND test_run_id = $2 FOR SHARE', [ctx.tenantId, job.test_run_id])).rows;
      const killSwitch = (await client.query('SELECT active FROM soc_kill_switch WHERE tenant_id = $1 FOR SHARE', [ctx.tenantId])).rows[0];
      const at = async () => (await client.query("SELECT date_trunc('milliseconds', clock_timestamp()) AS at")).rows[0].at.toISOString();
      const reservationRow = rowTimes((await client.query('SELECT * FROM reviewed_execution_reservations WHERE tenant_id = $1 AND probe_job_id = $2 FOR SHARE', [ctx.tenantId, jobId])).rows[0]);
      const issuance = rowTimes((await client.query('SELECT * FROM reviewed_execution_grant_issuances WHERE tenant_id = $1 AND probe_job_id = $2 FOR SHARE', [ctx.tenantId, jobId])).rows[0]);
      const claim = rowTimes((await client.query('SELECT * FROM reviewed_execution_claims WHERE tenant_id = $1 AND probe_job_id = $2 FOR SHARE', [ctx.tenantId, jobId])).rows[0]);
      const acceptance = (await client.query('SELECT * FROM reviewed_execution_acceptances WHERE tenant_id = $1 AND probe_job_id = $2 FOR SHARE', [ctx.tenantId, jobId])).rows[0];
      return callback({ job, run, policy, jobs, killSwitch, reservationRow, issuance, claim, acceptance, now: at,
        withAuthority: (fn) => authority.withCurrentAuthority(ctx, { mode: 'compare', targetId: job.target_id,
          checkId: job.check_id, binding: job.constraints.reviewed_operation_binding }, async (snapshot) => {
          const denied = await tenantGate(client,ctx); if (denied) return denied;
          if (!isWithinSafeTestWindowRaw(snapshot.targetGroup,Date.parse(await at()))) return { error: 'safe_window_closed', status: 429 };
          return fn(snapshot);
        }, { client }),
        async reserve(reservation) {
          const b = job.constraints.reviewed_operation_binding;
          await client.query(`INSERT INTO reviewed_execution_reservations (id, tenant_id, probe_job_id, test_run_id, target_id,
            review_id, plan_digest, worker_id, leased_at, reserved_at, not_after, reservation_json)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)`, [reservation.id, ctx.tenantId, jobId, job.test_run_id,
            job.target_id, b.review_id, b.plan_digest, ctx.workerId, job.leased_at, reservation.reserved_at, reservation.not_after, JSON.stringify(reservation)]);
          const updated = await client.query(`UPDATE probe_jobs SET worker_metadata_json = COALESCE(worker_metadata_json, '{}'::jsonb)
            || jsonb_build_object('execution_reservation', $3::jsonb) WHERE tenant_id = $1 AND id = $2
            AND status = 'leased' AND leased_by = $4 AND leased_at = $5 AND NOT (COALESCE(worker_metadata_json, '{}'::jsonb) ? 'execution_reservation') RETURNING id`,
          [ctx.tenantId, jobId, JSON.stringify(reservation), ctx.workerId, job.leased_at]);
          if (updated.rowCount !== 1) throw new Error('reviewed reservation changed');
          await appendAudit(client, ctx, job, 'reviewed_execution.reserved', { reservation_id: reservation.id, max_total_operations: 5 });
        },
        async consume(row) {
          await client.query(`INSERT INTO reviewed_execution_claims (id, tenant_id, probe_job_id, test_run_id, reservation_id,
            issuance_id, worker_id, leased_at, claimed_at, not_after, grant_digest, challenge_hash)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, [row.id, ctx.tenantId, jobId, job.test_run_id, row.reservation_id,
            row.issuance_id, ctx.workerId, job.leased_at, row.claimed_at, row.not_after, row.grant_digest, row.challenge_hash]);
          await appendAudit(client, ctx, job, 'reviewed_execution.consumed', { claim_id: row.id, reservation_id: row.reservation_id, grant_digest: row.grant_digest });
        },
        async activity(records, capture) {
          const existing = await validationEvidence.listRunEvents(ctx, job.test_run_id, { client, ids: records.map((record) => record.event_id) });
          let accepted = 0;
          for (const record of records) {
            const duplicate = existing.find((event) => event.event_id === record.event_id);
            if (duplicate && canonicalJsonStringify(duplicate.metadata?.activity) !== canonicalJsonStringify(record.metadata.activity)) throw new Error('reviewed activity conflict');
            if (!duplicate) { await validationEvidence.appendEvent(ctx,record,{ client }); accepted++; }
          }
          if (capture) await probeJobs.recordJobTelemetry(ctx,job,{ capture },{ client });
          return { accepted, continue: true };
        },
        async acceptedEvent() {
          if (!acceptance) return null;
          return (await validationEvidence.listRunEvents(ctx, job.test_run_id, { client })).find((event) => event.id === acceptance.event_id) ?? null;
        },
        async accept({ event, evidence, receipt, bodyDigest, acceptedAt }) {
          const accepted = await validationEvidence.appendEvent(ctx, event, { client });
          await validationEvidence.appendEvidence(ctx, { ...evidence, related_event_id: accepted.id }, { client });
          await client.query(`INSERT INTO reviewed_execution_acceptances (tenant_id, probe_job_id, test_run_id, claim_id, event_id, body_digest, receipt_json, accepted_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8)`, [ctx.tenantId, jobId, job.test_run_id, claim.id, accepted.id, bodyDigest, JSON.stringify(receipt), acceptedAt]);
          const updated = await probeJobs.markJobCompleted(ctx, jobId, acceptedAt, { workerId: ctx.workerId, leasedAt: job.leased_at }, { client });
          if (!updated) throw new Error('reviewed acceptance lease changed');
          await validationEvidence.updateTestRun(ctx, job.test_run_id, { status: 'collecting', probe_external_result: event.metadata.external_result,
            awaiting_external_probe: false, expected_statuses: ['running','collecting'] }, { client });
          await appendAudit(client, ctx, job, 'reviewed_execution.accepted', { event_id: accepted.id, claim_id: claim.id, receipt_digest: receipt.digest });
          return accepted;
        },
      });
    }),
  };
}
