import { newId } from '../../lib/ids.mjs';
import { isProbeJobLeaseStale } from './probeJobRepository.mjs';
import { validateProbeResultBody } from '../../lib/probeResultValidation.mjs';
import { enrichOutsideInWafProbeMetadata } from '../../lib/outsideInWafAgentEvidence.mjs';
import { enrichProbeMetadataWithWafCatalog } from '../../lib/wafProductCatalog.mjs';
import { isTrustedProducerEvent } from '../../lib/trustedEventProvenance.mjs';
import { WAF_EDGE_DETECTION_CHECK_ID } from '../../lib/edgeDetection.mjs';
import {
  edgeDetectionRowFields,
  isPersistableEdgeDetection,
  projectEdgeDetection,
} from '../../lib/edgeDetectionProjection.mjs';

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
  for (const method of ['appendAuditEvent', 'withTenantAuditLock']) {
    if (typeof audit[method] !== 'function') {
      throw new Error(`Postgres probe job service adapter requires audit.${method}().`);
    }
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
 * @param {{ client?: import('pg').PoolClient }} [options]
 * @returns {Promise<boolean>}
 */
async function killSwitchActiveForProbeTenant(killSwitch, ctx, options = {}) {
  if (typeof killSwitch?.isKillSwitchActiveForTenant !== 'function') {
    return false;
  }
  return Boolean(await killSwitch.isKillSwitchActiveForTenant(ctx, options));
}

const PROBE_RESULT_AUDIT_ACTIONS = Object.freeze([
  'probe_job.result_ingested',
  'probe_job.result_reconciled',
]);
const PROBE_KILL_SWITCH_AUDIT_ACTION = 'probe_job.kill_switch_denied';
const PROBE_RESULT_MUTATION_ABORT = Symbol('astranull.probe-result-mutation-abort');

async function appendProbeKillSwitchDeniedAudit(audit, ctx, jobId, workerId, client) {
  return audit.appendAuditEvent(
    {
      tenant_id: ctx.tenantId,
      actor_user_id: workerId ?? 'probe_worker',
      actor_role: 'probe_worker',
      action: PROBE_KILL_SWITCH_AUDIT_ACTION,
      resource_type: 'probe_job',
      resource_id: jobId,
      metadata: { reason: 'kill_switch_active' },
    },
    {
      ...(client ? { client } : {}),
      idempotency: {
        actions: [PROBE_KILL_SWITCH_AUDIT_ACTION],
        resourceType: 'probe_job',
        resourceId: jobId,
        metadata: { reason: 'kill_switch_active' },
      },
    },
  );
}

function killSwitchDeniedResult() {
  return {
    error: 'kill_switch_active',
    status: 423,
    message: 'Tenant kill switch is active; probe results are not accepted.',
  };
}

function abortProbeResultMutation(result) {
  const error = new Error(result.error ?? 'probe_result_mutation_aborted');
  error[PROBE_RESULT_MUTATION_ABORT] = result;
  throw error;
}

function buildProbeEvidenceRecord(job, probeEvent, nowIso, newIdFn) {
  const externalResult = probeEvent?.metadata?.external_result;
  const safetyAttestation = probeEvent?.metadata?.safety_attestation;
  return {
    id: newIdFn('ev'),
    test_run_id: job.test_run_id,
    label: 'probe_worker_evidence',
    metadata: enrichProbeMetadataWithWafCatalog(
      {
        probe_job_id: job.id,
        probe_event_id: probeEvent.id,
        ...(typeof externalResult === 'string' && externalResult !== ''
          ? { external_result: externalResult }
          : {}),
        vector_family: job.vector_family,
        ...(safetyAttestation == null ? {} : { safety_attestation: safetyAttestation }),
      },
      job.check_id,
    ),
    related_event_id: probeEvent.id,
    created_at: probeEvent.timestamp ?? nowIso,
  };
}

async function ensureProbeResultEvidence(
  validationEvidence,
  evidenceCtx,
  job,
  probeEvent,
  nowIso,
  newIdFn,
  client,
) {
  return validationEvidence.appendEvidence(
    evidenceCtx,
    buildProbeEvidenceRecord(job, probeEvent, nowIso, newIdFn),
    { client, idempotentByRelatedEvent: true },
  );
}

/**
 * Refresh the durable per-target WAF/CDN edge detection from a freshly ingested probe result.
 *
 * Postgres twin of the in-memory `recordTargetEdgeDetectionFromEvent` hook: same gate (a
 * `waf.fingerprint.safe` result bound to a target), same shared projection, and the write rides
 * the ingest transaction client so a rolled back probe event never leaves a detection behind.
 */
async function recordProbeResultEdgeDetection(
  validationEvidence,
  evidenceCtx,
  { run, job, probeMetadata, observedAt, newIdFn, client },
) {
  if (job.check_id !== WAF_EDGE_DETECTION_CHECK_ID || !job.target_id) return null;
  const targetGroupId = run.target_group_id ?? job.target_group_id ?? null;
  if (!targetGroupId) return null;
  if (!isPersistableEdgeDetection(probeMetadata)) return null;

  // Not in VALIDATION_PROBE_METHODS: existing callers build partial repository sets, and only
  // this check id reaches the write. Fail loudly rather than silently dropping the detection.
  if (typeof validationEvidence.upsertTargetEdgeDetection !== 'function') {
    throw new Error(
      'Postgres probe result ingest requires validationEvidence.upsertTargetEdgeDetection().',
    );
  }

  const fields = edgeDetectionRowFields(projectEdgeDetection(probeMetadata), {
    testRunId: run.id,
    observedAt,
  });
  return validationEvidence.upsertTargetEdgeDetection(
    evidenceCtx,
    {
      id: newIdFn('edgedet'),
      target_group_id: targetGroupId,
      target_id: job.target_id,
      ...fields,
    },
    { client },
  );
}

async function appendProbeResultAuditOnce(
  audit,
  {
    workerId,
    run,
    job,
    probeEvent,
    action,
    externalResult,
    nowIso,
    client,
  },
) {
  const metadata = {
    test_run_id: run.id,
    probe_event_id: probeEvent.id,
    ...(externalResult == null ? {} : { external_result: externalResult }),
  };
  return audit.appendAuditEvent(
    {
      tenant_id: run.tenant_id,
      actor_user_id: workerId ?? 'probe_worker',
      actor_role: 'probe_worker',
      action,
      resource_type: 'probe_job',
      resource_id: job.id,
      metadata,
    },
    {
      client,
      now: new Date(nowIso),
      idempotency: {
        actions: [...PROBE_RESULT_AUDIT_ACTIONS],
        resourceType: 'probe_job',
        resourceId: job.id,
      },
    },
  );
}

/**
 * Re-apply every artifact implied by an ALREADY-DURABLE probe event.
 *
 * Historical versions committed the event, evidence, run patch, completion, and audit in
 * separate transactions. A crash could therefore leave any suffix absent, including a
 * completed job with no evidence or audit. Reconciliation treats the immutable trusted event
 * as the source of truth and idempotently fills those gaps on the run-mutation transaction.
 * Nothing below is derived from the replay body.
 */
async function reconcileDurableProbeResult(
  validationEvidence,
  probeJobs,
  audit,
  {
    ctx,
    evidenceCtx,
    run,
    job,
    existingProbe,
    nowIso,
    newIdFn,
    workerId,
    client,
    resultLease = null,
  },
) {
  const durableResult = existingProbe?.metadata?.external_result;
  await ensureProbeResultEvidence(
    validationEvidence,
    evidenceCtx,
    job,
    existingProbe,
    nowIso,
    newIdFn,
    client,
  );

  const runPatch = {
    correlation: { ...run.correlation, nonce_hash: job.nonce_hash },
    awaiting_external_probe: false,
    expected_statuses: ['running', 'collecting'],
  };
  if (typeof durableResult === 'string' && durableResult !== '') {
    runPatch.probe_external_result = durableResult;
  }
  if (run.status === 'running') {
    runPatch.status = 'collecting';
  }
  await validationEvidence.updateTestRun(evidenceCtx, run.id, runPatch, { client });

  // Preserve the first durable completion timestamp on every replay.
  if (job.status !== 'completed') {
    if (!resultLease) return null;
    const completed = await probeJobs.markJobCompleted(
      ctx,
      job.id,
      nowIso,
      resultLease,
      { client },
    );
    if (!completed) return null;
  }

  await appendProbeResultAuditOnce(audit, {
    workerId,
    run,
    job,
    probeEvent: existingProbe,
    action: 'probe_job.result_reconciled',
    externalResult: durableResult,
    nowIso,
    client,
  });
  return runPatch;
}

function probeJobMatchesRun(job, run) {
  return job.tenant_id === run.tenant_id
    && job.test_run_id === run.id
    && job.target_id === run.target_id
    && job.check_id === run.check_id
    && typeof job.nonce_hash === 'string'
    && job.nonce_hash !== ''
    && job.nonce_hash === run.correlation?.nonce_hash;
}

async function findDuplicateProbeEvent(
  validationEvidence,
  ctx,
  job,
  options = {},
) {
  const events = await validationEvidence.listRunEvents(ctx, job.test_run_id, {
    signalType: 'probe_result',
    limit: 1000,
    client: options.client,
  });
  const tupleEvents = events.filter(
    (event) => event.signal_type === 'probe_result'
      && event.test_run_id === job.test_run_id
      && event.nonce_hash === job.nonce_hash,
  );
  const structuralConflict = tupleEvents.find(
    (event) => event.target_id !== job.target_id
      || event.check_id !== job.check_id
      || (
        event.metadata?.probe_job_id != null
        && event.metadata.probe_job_id !== job.id
      ),
  );
  if (structuralConflict) return { kind: 'conflict', event: structuralConflict };

  // Durable repair is intentionally narrower than generic correlation trust. Internal
  // simulation remains valid evidence for simulation-mode correlation, but it can never
  // satisfy a signed worker job. The legacy class covers the immediately preceding signed
  // worker writer, which stamped producer_kind/source but did not yet persist probe_job_id.
  const signed = tupleEvents.filter(
    (event) => event.producer_kind === 'signed_probe' && event.source === 'probe_worker',
  );
  const untrustedExactClaim = tupleEvents.find(
    (event) => event.metadata?.probe_job_id === job.id && !signed.includes(event),
  );
  if (untrustedExactClaim) return { kind: 'conflict', event: untrustedExactClaim };

  const exact = signed.filter((event) => event.metadata?.probe_job_id === job.id);
  const legacy = signed.filter((event) => event.metadata?.probe_job_id == null);
  if (exact.length === 1 && legacy.length === 0) return { kind: 'exact', event: exact[0] };
  if (exact.length === 0 && legacy.length === 1) return { kind: 'legacy', event: legacy[0] };
  if (exact.length > 0 || legacy.length > 0) {
    return { kind: 'conflict', event: exact[0] ?? legacy[0] };
  }
  return { kind: 'none', event: null };
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
 *   ownershipVerification?: { recordOwnershipSignal?: Function },
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
        await appendProbeKillSwitchDeniedAudit(audit, ctx, jobId, workerId);
        return killSwitchDeniedResult();
      }
      const initialJob = await probeJobs.getJobById(ctx, jobId);
      if (!initialJob) return { error: 'job_not_found', status: 404 };

      if (initialJob.ownership_verification_id) {
        if (typeof ownershipVerification?.recordOwnershipSignal !== 'function') {
          return { error: 'ownership_result_not_wired', status: 503 };
        }
        try {
          const ownershipMutation = await audit.withTenantAuditLock(
            initialJob.tenant_id,
            async ({ client: auditClient }) => validationEvidence.withRunMutationLock(
              ctx,
              initialJob.test_run_id,
              async (client) => {
                if (await killSwitchActiveForProbeTenant(killSwitch, ctx, { client })) {
                  await appendProbeKillSwitchDeniedAudit(audit, ctx, jobId, workerId, client);
                  return killSwitchDeniedResult();
                }
                const job = await probeJobs.getJobById(ctx, jobId, { client });
                if (!job) return { error: 'job_not_found', status: 404 };
                if (
                  job.tenant_id !== initialJob.tenant_id
                  || job.id !== initialJob.id
                  || job.test_run_id !== initialJob.test_run_id
                  || job.ownership_verification_id !== initialJob.ownership_verification_id
                ) {
                  return { error: 'ownership_job_binding_mismatch', status: 409 };
                }
                if (
                  job.status === 'leased'
                  && job.leased_by !== workerId
                  && !isProbeJobLeaseStale(job, nowFn())
                ) {
                  return {
                    error: 'job_leased_to_another_worker',
                    status: 403,
                    message: 'This probe job is leased to a different worker.',
                  };
                }
                if (!['pending', 'leased', 'completed'].includes(job.status)) {
                  return { error: 'job_not_open', status: 409 };
                }
                const validated = validateProbeResultBody(body, job.constraints ?? {}, {
                  probeKind: job.probe_profile?.kind,
                  probeProfile: job.probe_profile,
                  target: job.target,
                });
                if (!validated.ok) {
                  return {
                    error: validated.error,
                    status: validated.status,
                    message: validated.message,
                  };
                }

                const nowIso = nowFn().toISOString();
                let resultLease = null;
                if (job.status !== 'completed') {
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
                    { client },
                  );
                  if (!leasedJob) {
                    abortProbeResultMutation({ error: 'job_not_open', status: 409 });
                  }
                  resultLease = { workerId, leasedAt: leasedJob.leased_at };
                }

                const ownershipResult = await ownershipVerification.recordOwnershipSignal(
                  { tenantId: job.tenant_id, userId: 'system', role: 'system' },
                  job.ownership_verification_id,
                  {
                    source: 'probe',
                    nonce_hash: job.nonce_hash,
                    probe_job_id: job.id,
                  },
                  { client },
                );
                const completedReplay = job.status === 'completed';
                const alreadyClosed = ownershipResult?.error === 'ownership_verification_not_open';
                if (ownershipResult?.error && !(completedReplay && alreadyClosed)) {
                  abortProbeResultMutation(ownershipResult);
                }

                if (!completedReplay) {
                  const completed = await probeJobs.markJobCompleted(
                    ctx,
                    job.id,
                    nowIso,
                    resultLease,
                    { client },
                  );
                  if (!completed) {
                    abortProbeResultMutation({ error: 'job_not_open', status: 409 });
                  }
                }

                await audit.appendAuditEvent({
                  tenant_id: job.tenant_id,
                  actor_user_id: workerId,
                  actor_role: 'probe_worker',
                  action: completedReplay
                    ? 'probe_job.result_reconciled'
                    : 'probe_job.result_ingested',
                  resource_type: 'probe_job',
                  resource_id: job.id,
                  metadata: {
                    ownership_verification_id: job.ownership_verification_id,
                  },
                }, {
                  client,
                  now: new Date(nowIso),
                  idempotency: {
                    actions: [...PROBE_RESULT_AUDIT_ACTIONS],
                    resourceType: 'probe_job',
                    resourceId: job.id,
                  },
                });
                return {
                  ownership_verification_id: job.ownership_verification_id,
                  job_id: job.id,
                  tenant_id: job.tenant_id,
                  ...(completedReplay ? { reconciled: true } : {}),
                };
              },
              { client: auditClient },
            ),
          );
          if (!ownershipMutation.acquired) {
            return { error: 'run_mutation_in_progress', status: 409 };
          }
          return ownershipMutation.result;
        } catch (error) {
          if (error && typeof error === 'object' && PROBE_RESULT_MUTATION_ABORT in error) {
            return error[PROBE_RESULT_MUTATION_ABORT];
          }
          throw error;
        }
      }

      let mutation;
      try {
        mutation = await audit.withTenantAuditLock(
          initialJob.tenant_id,
          async ({ client: auditClient }) => validationEvidence.withRunMutationLock(
            ctx,
            initialJob.test_run_id,
          async (client) => {
            if (await killSwitchActiveForProbeTenant(killSwitch, ctx, { client })) {
              await appendProbeKillSwitchDeniedAudit(audit, ctx, jobId, workerId, client);
              return killSwitchDeniedResult();
            }
            const job = await probeJobs.getJobById(ctx, jobId, { client });
            if (!job) return { error: 'job_not_found', status: 404 };
            const evidenceCtx = {
              tenantId: ctx.tenantId,
              userId: 'probe_worker',
              role: 'probe_worker',
            };
            const run = await validationEvidence.getTestRun(
              evidenceCtx,
              job.test_run_id,
              { client },
            );
            if (!run) return { error: 'run_not_found', status: 404 };
            if (
              job.tenant_id !== initialJob.tenant_id
              || job.test_run_id !== initialJob.test_run_id
              || !probeJobMatchesRun(job, run)
            ) {
              return { error: 'probe_job_binding_mismatch', status: 409 };
            }
            if (!['pending', 'leased', 'completed'].includes(job.status)) {
              return { error: 'job_not_open', status: 409 };
            }

            const nowIso = nowFn().toISOString();
            const duplicate = await findDuplicateProbeEvent(
              validationEvidence,
              evidenceCtx,
              job,
              { client },
            );
            if (duplicate.kind === 'conflict') {
              return { error: 'probe_event_binding_conflict', status: 409 };
            }

            if (duplicate.kind === 'exact' || duplicate.kind === 'legacy') {
              // A reclaimed job legitimately changes hands: the row still names the lost worker
              // until this claim. Only a provably expired lease is overridable.
              if (
                job.status === 'leased'
                && job.leased_by !== workerId
                && !isProbeJobLeaseStale(job, nowFn())
              ) {
                return {
                  error: 'job_leased_to_another_worker',
                  status: 403,
                  message: 'This probe job is leased to a different worker.',
                };
              }

              let resultLease = null;
              if (job.status !== 'completed') {
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
                  { client },
                );
                if (!leasedJob) {
                  abortProbeResultMutation({ error: 'job_not_open', status: 409 });
                }
                resultLease = { workerId, leasedAt: leasedJob.leased_at };
              }

              const reconciled = await reconcileDurableProbeResult(
                validationEvidence,
                probeJobs,
                audit,
                {
                  ctx,
                  evidenceCtx,
                  run,
                  job,
                  existingProbe: duplicate.event,
                  nowIso,
                  newIdFn,
                  workerId,
                  client,
                  resultLease,
                },
              );
              if (!reconciled) {
                abortProbeResultMutation({ error: 'job_not_open', status: 409 });
              }
              return {
                probe_event: duplicate.event,
                run_id: run.id,
                job_id: job.id,
                tenant_id: run.tenant_id,
                reconciled: true,
              };
            }

            if (job.status === 'completed') {
              return { error: 'job_not_open', status: 409 };
            }
            if (!['running', 'collecting'].includes(run.status)) {
              return { error: 'run_not_collecting', status: 409 };
            }

            if (
              job.status === 'leased'
              && job.leased_by !== workerId
              && !isProbeJobLeaseStale(job, nowFn())
            ) {
              return {
                error: 'job_leased_to_another_worker',
                status: 403,
                message: 'This probe job is leased to a different worker.',
              };
            }

            const validated = validateProbeResultBody(body, job.constraints ?? {}, {
              probeKind: job.probe_profile?.kind,
              probeProfile: job.probe_profile,
              target: job.target,
            });
            if (!validated.ok) {
              return {
                error: validated.error,
                status: validated.status,
                message: validated.message,
              };
            }
            const { externalResult, safetyAttestation, workerMetadata } = validated;

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
              { client },
            );
            if (!leasedJob) {
              abortProbeResultMutation({ error: 'job_not_open', status: 409 });
            }
            const resultLease = { workerId, leasedAt: leasedJob.leased_at };

            let probeMetadata = enrichProbeMetadataWithWafCatalog(
              {
                ...workerMetadata,
                external_result: externalResult,
                probe_job_id: job.id,
                profile_kind: job.probe_profile?.kind ?? null,
                probe_worker_id: workerId,
                safety_attestation: safetyAttestation,
              },
              job.check_id,
            );

            if (job.probe_profile?.kind === 'outside_in_waf_scan') {
              const agentObservations = await validationEvidence.listRunEvents(
                evidenceCtx,
                run.id,
                {
                  signalType: 'agent_observation',
                  limit: 500,
                  client,
                },
              );
              probeMetadata = enrichOutsideInWafProbeMetadata(probeMetadata, {
                agents: Array.isArray(agentObservations)
                  ? agentObservations.filter(isTrustedProducerEvent)
                  : [],
                nonceHash: job.nonce_hash,
              });
            }

            const probeEvent = await validationEvidence.appendProbeResultEventIdempotent(
              evidenceCtx,
              {
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
              },
              { client },
            );
            if (!probeEvent) {
              abortProbeResultMutation({ error: 'probe_event_binding_conflict', status: 409 });
            }

            await ensureProbeResultEvidence(
              validationEvidence,
              evidenceCtx,
              job,
              probeEvent,
              nowIso,
              newIdFn,
              client,
            );

            await recordProbeResultEdgeDetection(validationEvidence, evidenceCtx, {
              run,
              job,
              probeMetadata,
              observedAt: probeEvent.timestamp ?? nowIso,
              newIdFn,
              client,
            });

            const runPatch = {
              correlation: { ...run.correlation, nonce_hash: job.nonce_hash },
              probe_external_result: externalResult,
              awaiting_external_probe: false,
              expected_statuses: ['running', 'collecting'],
            };
            if (run.status === 'running') {
              runPatch.status = 'collecting';
            }
            await validationEvidence.updateTestRun(
              evidenceCtx,
              run.id,
              runPatch,
              { client },
            );

            const completedJob = await probeJobs.markJobCompleted(
              ctx,
              job.id,
              nowIso,
              resultLease,
              { client },
            );
            if (!completedJob) {
              abortProbeResultMutation({ error: 'job_not_open', status: 409 });
            }

            await appendProbeResultAuditOnce(audit, {
              workerId,
              run,
              job,
              probeEvent,
              action: 'probe_job.result_ingested',
              externalResult,
              nowIso,
              client,
            });

            return {
              probe_event: probeEvent,
              run_id: run.id,
              job_id: job.id,
              tenant_id: run.tenant_id,
            };
          },
          { client: auditClient },
        ),
        );
      } catch (error) {
        if (
          error
          && typeof error === 'object'
          && PROBE_RESULT_MUTATION_ABORT in error
        ) {
          return error[PROBE_RESULT_MUTATION_ABORT];
        }
        throw error;
      }
      if (!mutation.acquired) {
        return { error: 'run_mutation_in_progress', status: 409 };
      }
      return mutation.result;
    },
  };
}