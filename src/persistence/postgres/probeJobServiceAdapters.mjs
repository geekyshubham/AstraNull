import { newId } from '../../lib/ids.mjs';
import { isProbeJobLeaseStale } from './probeJobRepository.mjs';
import { validateProbeResultBody } from '../../lib/probeResultValidation.mjs';
import { enrichOutsideInWafProbeMetadata } from '../../lib/outsideInWafAgentEvidence.mjs';
import { enrichProbeMetadataWithWafCatalog } from '../../lib/wafProductCatalog.mjs';
import { isTrustedProducerEvent } from '../../lib/trustedEventProvenance.mjs';

/** @type {readonly string[]} */
export const PROBE_JOB_REPOSITORY_METHODS = Object.freeze([
  'leasePendingJobsForWorker',
  'getJobById',
  'claimPendingJobForWorker',
  'claimJobForResult',
  'markJobCompleted',
  'createProbeJob',
  'cancelOpenProbeJobsForTestRuns',
]);

/** @type {readonly string[]} */
export const POSTGRES_PROBE_JOB_SERVICE_METHODS = Object.freeze([
  'listPendingProbeJobsForWorker',
  'ingestProbeResult',
]);

/**
 * Kill-switch methods consulted by the lease and result-ingest paths.
 *
 * Optional at construction: `runtime.mjs` always passes the full repository set (which
 * includes `killSwitch`), so production and staging always get the guard. It is not a hard
 * requirement only because existing callers in tests construct this service with a partial
 * repository set. When the repository is absent the guard is skipped — see
 * `killSwitchActiveForProbeTenant()`.
 *
 * @type {readonly string[]}
 */
export const PROBE_JOB_KILL_SWITCH_REPOSITORY_METHODS = Object.freeze([
  'isKillSwitchActiveForTenant',
]);

const VALIDATION_PROBE_METHODS = Object.freeze([
  'getTestRun',
  'listRunEvents',
  'appendProbeResultEventIdempotent',
  'appendEvidence',
  'updateTestRun',
  'withRunMutationLock',
]);

function assertProbeJobRepositories(repositories) {
  const probeJobs = repositories?.probeJobs;
  if (!probeJobs || typeof probeJobs !== 'object') {
    throw new Error('Postgres probe job service adapter requires repositories.probeJobs.');
  }
  for (const method of PROBE_JOB_REPOSITORY_METHODS) {
    if (typeof probeJobs[method] !== 'function') {
      throw new Error(`Postgres probe job service adapter requires probeJobs.${method}().`);
    }
  }

  const validationEvidence = repositories?.validationEvidence;
  if (!validationEvidence || typeof validationEvidence !== 'object') {
    throw new Error('Postgres probe job service adapter requires repositories.validationEvidence.');
  }
  for (const method of VALIDATION_PROBE_METHODS) {
    if (typeof validationEvidence[method] !== 'function') {
      throw new Error(
        `Postgres probe job service adapter requires validationEvidence.${method}().`,
      );
    }
  }

  const audit = repositories?.audit;
  if (!audit || typeof audit !== 'object') {
    throw new Error('Postgres probe job service adapter requires repositories.audit.');
  }
  if (typeof audit.appendAuditEvent !== 'function') {
    throw new Error('Postgres probe job service adapter requires audit.appendAuditEvent().');
  }
}

/**
 * Tenant kill-switch check for the probe fleet. Costs one query per lease and per ingest.
 *
 * The safe-run start gate is not sufficient on its own: a run can clear the start gate
 * microseconds before the switch is activated, and its probe job would otherwise still be
 * leased and its result still recorded after the emergency stop. These two checks stop that
 * run from executing or recording anything.
 *
 * @param {{ isKillSwitchActiveForTenant?: (...args: unknown[]) => unknown } | undefined} killSwitch
 * @param {{ tenantId?: string }} ctx
 * @returns {Promise<boolean>}
 */
async function killSwitchActiveForProbeTenant(killSwitch, ctx) {
  if (typeof killSwitch?.isKillSwitchActiveForTenant !== 'function') {
    return false;
  }
  return Boolean(await killSwitch.isKillSwitchActiveForTenant(ctx));
}

/**
 * Re-apply the derived state implied by an ALREADY-DURABLE probe event, then complete the job.
 *
 * Why this exists: result ingest is not one transaction, so a crash between the event write and
 * the run patch used to leave the run permanently inconsistent (`awaiting_external_probe` stuck
 * true, status stuck `running`) while the worker's natural retry short-circuited with 409 and
 * could never repair it. Treating "event already present" as *evidence already durable, ensure
 * derived state matches* makes the retry the repair path.
 *
 * Containment — this is the load-bearing part. Every field written here is derived from the
 * durable event or is a constant; NOTHING is taken from the incoming request body. A buggy or
 * malicious worker replaying a mutated body therefore cannot re-drive run state: the worst it can
 * do is re-assert the values already implied by evidence it cannot alter. Specifically:
 *   - `probe_external_result` comes from the stored event's metadata, not the new body, so a
 *     replay cannot flip a recorded `blocked` into `connected`.
 *   - `status` only ever moves `running` -> `collecting`, never backwards and never out of a
 *     terminal state, so a replay cannot resurrect a completed or cancelled run.
 *   - no evidence row is appended (`appendEvidence` is a plain INSERT and would duplicate).
 *
 * @param {{ updateTestRun: Function }} validationEvidence
 * @param {{ markJobCompleted: Function }} probeJobs
 * @param {object} args
 */
async function reconcileDurableProbeResult(
  validationEvidence,
  probeJobs,
  { ctx, evidenceCtx, run, job, existingProbe, nowIso, resultLease = null },
) {
  const durableResult = existingProbe?.metadata?.external_result;
  const runPatch = {
    correlation: { ...run.correlation, nonce_hash: job.nonce_hash },
    awaiting_external_probe: false,
    expected_statuses: ['running', 'collecting'],
  };
  // Only mirror a result the durable event actually carries; never invent one.
  if (typeof durableResult === 'string' && durableResult !== '') {
    runPatch.probe_external_result = durableResult;
  }
  if (run.status === 'running') {
    runPatch.status = 'collecting';
  }
  await validationEvidence.updateTestRun(evidenceCtx, run.id, runPatch);
  // Idempotent, and deliberately skipped when the job is already terminal: re-running the
  // UPDATE would overwrite the original `completed_at` with the retry's clock, drifting the
  // recorded completion time of durable evidence on every replay.
  if (job.status !== 'completed') {
    if (!resultLease) return null;
    const completed = await probeJobs.markJobCompleted(ctx, job.id, nowIso, resultLease);
    if (!completed) return null;
  }
  return runPatch;
}

async function findDuplicateProbeEvent(validationEvidence, ctx, runId, nonceHash) {
  const events = await validationEvidence.listRunEvents(ctx, runId, {
    signalType: 'probe_result',
    limit: 1000,
  });
  return events.find(
    (event) => event.signal_type === 'probe_result'
      && event.nonce_hash === nonceHash
      && isTrustedProducerEvent(event),
  ) ?? null;
}

/**
 * @param {{
 *   probeJobs?: Record<string, unknown>,
 *   validationEvidence?: Record<string, unknown>,
 *   audit?: { appendAuditEvent?: (...args: unknown[]) => unknown },
 * }} repositories
 * @param {{
 *   now?: () => Date,
 *   newId?: typeof newId,
 *   ownershipVerification?: { recordOwnershipSignalByNonce?: Function },
 * }} [options]
 */
export function createPostgresProbeJobServices(repositories, options = {}) {
  assertProbeJobRepositories(repositories);
  const ownershipVerification = options.ownershipVerification;
  const probeJobs = repositories.probeJobs;
  const validationEvidence = repositories.validationEvidence;
  const audit = repositories.audit;
  const killSwitch = repositories.killSwitch;
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;

  return {
    async listPendingProbeJobsForWorker(ctx) {
      const workerId = ctx.workerId;
      if (!workerId) {
        return [];
      }
      // Lease gate: a kill-switched tenant hands out no work. Not audited — workers poll
      // continuously and an entry per poll would flood the tenant audit timeline.
      if (await killSwitchActiveForProbeTenant(killSwitch, ctx)) {
        return [];
      }
      return probeJobs.leasePendingJobsForWorker(ctx, workerId);
    },

    async ingestProbeResult(ctx, jobId, body) {
      const workerId = ctx.workerId;
      // Ingest gate: refuse before any read or write, so a job leased before activation
      // cannot record a probe result after the emergency stop.
      if (await killSwitchActiveForProbeTenant(killSwitch, ctx)) {
        await audit.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: workerId ?? 'probe_worker',
          actor_role: 'probe_worker',
          action: 'probe_job.kill_switch_denied',
          resource_type: 'probe_job',
          resource_id: jobId,
          metadata: { reason: 'kill_switch_active' },
        });
        return {
          error: 'kill_switch_active',
          status: 423,
          message: 'Tenant kill switch is active; probe results are not accepted.',
        };
      }
      const initialJob = await probeJobs.getJobById(ctx, jobId);
      if (!initialJob) return { error: 'job_not_found', status: 404 };

      if (initialJob.ownership_verification_id) {
        if (typeof ownershipVerification?.recordOwnershipSignalByNonce !== 'function') {
          return { error: 'ownership_result_not_wired', status: 503 };
        }
        if (initialJob.status === 'completed') {
          return { error: 'job_not_open', status: 409 };
        }
        if (
          initialJob.status === 'leased'
          && initialJob.leased_by !== workerId
          && !isProbeJobLeaseStale(initialJob, nowFn())
        ) {
          return {
            error: 'job_leased_to_another_worker',
            status: 403,
            message: 'This probe job is leased to a different worker.',
          };
        }
        if (!['pending', 'leased'].includes(initialJob.status)) {
          return { error: 'job_not_open', status: 409 };
        }
        const validated = validateProbeResultBody(body, initialJob.constraints ?? {}, {
          probeKind: initialJob.probe_profile?.kind,
        });
        if (!validated.ok) {
          return {
            error: validated.error,
            status: validated.status,
            message: validated.message,
          };
        }
        const nowIso = nowFn().toISOString();
        const leasedJob = await probeJobs.claimJobForResult(
          ctx,
          initialJob.id,
          workerId,
          nowIso,
          {
            status: initialJob.status,
            leased_by: initialJob.leased_by ?? null,
            leased_at: initialJob.leased_at ?? null,
          },
        );
        if (!leasedJob) return { error: 'job_not_open', status: 409 };
        const resultLease = { workerId, leasedAt: leasedJob.leased_at };
        const ownershipResult = await ownershipVerification.recordOwnershipSignalByNonce(
          { tenantId: initialJob.tenant_id },
          { source: 'probe', nonce_hash: initialJob.nonce_hash },
        );
        if (ownershipResult?.error) return ownershipResult;
        const completed = await probeJobs.markJobCompleted(
          ctx,
          initialJob.id,
          nowIso,
          resultLease,
        );
        if (!completed) return { error: 'job_not_open', status: 409 };
        await audit.appendAuditEvent({
          tenant_id: initialJob.tenant_id,
          actor_user_id: workerId,
          actor_role: 'probe_worker',
          action: 'probe_job.result_ingested',
          resource_type: 'probe_job',
          resource_id: initialJob.id,
          metadata: {
            ownership_verification_id: initialJob.ownership_verification_id,
          },
        });
        return {
          ownership_verification_id: initialJob.ownership_verification_id,
          job_id: initialJob.id,
          tenant_id: initialJob.tenant_id,
        };
      }

      const mutation = await validationEvidence.withRunMutationLock(
        ctx,
        initialJob.test_run_id,
        async () => {
          if (await killSwitchActiveForProbeTenant(killSwitch, ctx)) {
            return { error: 'kill_switch_active', status: 423 };
          }
          const job = await probeJobs.getJobById(ctx, jobId);
          if (!job) return { error: 'job_not_found', status: 404 };
          const evidenceCtx = {
            tenantId: ctx.tenantId,
            userId: 'probe_worker',
            role: 'probe_worker',
          };
          const run = await validationEvidence.getTestRun(evidenceCtx, job.test_run_id);
          if (!run) return { error: 'run_not_found', status: 404 };
          if (!['running', 'collecting'].includes(run.status)) {
            return { error: 'run_not_collecting', status: 409 };
          }

          const nowIso = nowFn().toISOString();

      if (job.status === 'completed') {
        const dupProbe = run
          ? await findDuplicateProbeEvent(validationEvidence, evidenceCtx, run.id, job.nonce_hash)
          : null;
        if (dupProbe) {
          // Evidence is durable. Converge derived state instead of 409-ing, so a crash between
          // the event write and the run patch is repaired by the worker's natural retry rather
          // than left for manual intervention. Idempotent: a second identical retry re-asserts
          // the same values and is a no-op.
          await reconcileDurableProbeResult(validationEvidence, probeJobs, {
            ctx,
            evidenceCtx,
            run,
            job,
            existingProbe: dupProbe,
            nowIso,
          });
          return {
            probe_event: dupProbe,
            run_id: run.id,
            job_id: job.id,
            tenant_id: run.tenant_id,
            reconciled: true,
          };
        }
        return { error: 'job_not_open', status: 409 };
      }

      // A reclaimed job legitimately changes hands: the row still names the lost worker until
      // the next lease, so comparing against `leased_by` alone would reject the new holder's
      // result. Only an EXPIRED lease is overridable — `isProbeJobLeaseStale` fails closed on a
      // missing/unparseable `leased_at`, so a live worker's job is never handed over.
      if (
        job.status === 'leased' &&
        job.leased_by !== workerId &&
        !isProbeJobLeaseStale(job, nowFn())
      ) {
        return {
          error: 'job_leased_to_another_worker',
          status: 403,
          message: 'This probe job is leased to a different worker.',
        };
      }

      if (job.status !== 'pending' && job.status !== 'leased') {
        return { error: 'job_not_open', status: 409 };
      }

      const validated = validateProbeResultBody(body, job.constraints ?? {}, {
        probeKind: job.probe_profile?.kind,
      });
      if (!validated.ok) {
        return {
          error: validated.error,
          status: validated.status,
          message: validated.message,
        };
      }
      const { externalResult, safetyAttestation, workerMetadata } = validated;

      if (!run) return { error: 'run_not_found', status: 404 };

      const leasedJob = await probeJobs.claimJobForResult(
        ctx,
        job.id,
        workerId,
        nowIso,
        {
          status: job.status,
          leased_by: job.leased_by ?? null,
          leased_at: job.leased_at ?? null,
        },
      );
      if (!leasedJob) return { error: 'job_not_open', status: 409 };
      const resultLease = { workerId, leasedAt: leasedJob.leased_at };

      const existingProbe = await findDuplicateProbeEvent(
        validationEvidence,
        evidenceCtx,
        run.id,
        job.nonce_hash,
      );
      if (existingProbe) {
        // Same reconciliation as the completed-job branch: the event is durable, so converge
        // the run and complete the job rather than rejecting. This is the branch a retry after
        // a crash *between the event write and the run patch* lands in — the job is still
        // pending/leased, so the old 409 here was what made that state unrepairable.
        const reconciled = await reconcileDurableProbeResult(validationEvidence, probeJobs, {
          ctx,
          evidenceCtx,
          run,
          job,
          existingProbe,
          nowIso,
          resultLease,
        });
        if (!reconciled) return { error: 'job_not_open', status: 409 };
        await audit.appendAuditEvent({
          tenant_id: run.tenant_id,
          actor_user_id: workerId,
          actor_role: 'probe_worker',
          action: 'probe_job.result_reconciled',
          resource_type: 'probe_job',
          resource_id: job.id,
          metadata: { test_run_id: run.id, probe_event_id: existingProbe.id },
        });
        return {
          probe_event: existingProbe,
          run_id: run.id,
          job_id: job.id,
          tenant_id: run.tenant_id,
          reconciled: true,
        };
      }

      let probeMetadata = enrichProbeMetadataWithWafCatalog(
        {
          ...workerMetadata,
          external_result: externalResult,
          probe_worker_id: workerId,
          safety_attestation: safetyAttestation,
        },
        job.check_id,
      );

      if (job.probe_profile?.kind === 'outside_in_waf_scan') {
        const agentObservations = await validationEvidence.listRunEvents(evidenceCtx, run.id, {
          signalType: 'agent_observation',
          limit: 500,
        });
        probeMetadata = enrichOutsideInWafProbeMetadata(probeMetadata, {
          agents: Array.isArray(agentObservations)
            ? agentObservations.filter(isTrustedProducerEvent)
            : [],
          nonceHash: job.nonce_hash,
        });
      }

      const probeEvent = await validationEvidence.appendProbeResultEventIdempotent(evidenceCtx, {
        id: newIdFn('event'),
        test_run_id: run.id,
        target_id: job.target_id,
        check_id: job.check_id,
        source: 'probe_worker',
        signal_type: 'probe_result',
        producer_kind: 'signed_probe',
        timestamp: nowIso,
        nonce_hash: job.nonce_hash,
        metadata: probeMetadata,
      });

      await validationEvidence.appendEvidence(evidenceCtx, {
        id: newIdFn('ev'),
        test_run_id: run.id,
        label: 'probe_worker_evidence',
        metadata: enrichProbeMetadataWithWafCatalog(
          {
            probe_job_id: job.id,
            probe_event_id: probeEvent.id,
            external_result: externalResult,
            vector_family: job.vector_family,
            safety_attestation: safetyAttestation,
          },
          job.check_id,
        ),
        related_event_id: probeEvent.id,
        created_at: nowIso,
      });

      const correlation = { ...run.correlation, nonce_hash: job.nonce_hash };
      const runPatch = {
        correlation,
        probe_external_result: externalResult,
        awaiting_external_probe: false,
        expected_statuses: ['running', 'collecting'],
      };
      if (run.status === 'running') {
        runPatch.status = 'collecting';
      }
      await validationEvidence.updateTestRun(evidenceCtx, run.id, runPatch);

      const completedJob = await probeJobs.markJobCompleted(ctx, job.id, nowIso, resultLease);
      if (!completedJob) return { error: 'job_not_open', status: 409 };

      await audit.appendAuditEvent({
        tenant_id: run.tenant_id,
        actor_user_id: workerId,
        actor_role: 'probe_worker',
        action: 'probe_job.result_ingested',
        resource_type: 'probe_job',
        resource_id: job.id,
        metadata: { test_run_id: run.id, external_result: externalResult },
      });

          return {
            probe_event: probeEvent,
            run_id: run.id,
            job_id: job.id,
            tenant_id: run.tenant_id,
          };
        },
      );
      if (!mutation.acquired) {
        return { error: 'run_mutation_in_progress', status: 409 };
      }
      return mutation.result;
    },
  };
}