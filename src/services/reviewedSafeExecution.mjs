import { randomUUID } from 'node:crypto';
import { roleHasPermission } from '../contracts/roles.mjs';
import { normalizeProbeActivityBatch, probeActivityEvent } from '../lib/probeActivity.mjs';
import { verifyProbeJobSignature } from '../lib/probeJobs.mjs';
import { executionReservation } from '../lib/probeExecution.mjs';
import { reviewedSafeJob, reviewedHash, reviewedClaimSignature, REVIEWED_SAFE_CHECK } from '../lib/reviewedSafeExecution.mjs';
import { verifyReviewedExecutionGrant, resolveReviewedExecutionGrantTrust } from '../lib/reviewedExecutionGrant.mjs';
import { reviewedGrantExact } from '../contracts/reviewedExecutionGrant.mjs';
import { validateProbeResultBody } from '../lib/probeResultValidation.mjs';
import { deriveAssuranceScope } from '../lib/assuranceScope.mjs';
import { canonicalJsonStringify } from '../lib/custody.mjs';
import { reviewedSafeLegDescriptors, validateReviewedSafeObservations } from '../lib/reviewedSafeGetProbe.mjs';

const deny = (error, status = 409) => ({ error, status, grants_execution: false, execution_available: false });
const same = (a,b) => canonicalJsonStringify(a) === canonicalJsonStringify(b);
const id = (value) => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value);
const storedGrant = (tx) => ({ version: 'reviewed-execution-grant.v1', envelope: tx.issuance?.envelope_json, signature: tx.issuance?.grant_signature });
function original(tx, ctx, secret, at, completed = false) {
  const { job, run } = tx;
  if (!verifyProbeJobSignature(job, secret)) return deny('reviewed_grant_original_hmac_invalid');
  if (!run || run.tenant_id !== ctx.tenantId || job.tenant_id !== ctx.tenantId || job.test_run_id !== run.id
    || job.target_id !== run.target_id || job.check_id !== run.check_id || job.nonce_hash !== run.correlation_json?.nonce_hash
    || tx.jobs.length !== 1 || tx.jobs[0].id !== job.id) return deny('reviewed_execution_run_mismatch');
  if (job.leased_by !== ctx.workerId || !job.leased_at || !['leased', ...(completed ? ['completed'] : [])].includes(job.status)) return deny('reviewed_execution_lease_mismatch');
  if (completed) return null;
  if (job.completed_at != null || !['running','collecting'].includes(run.status) || run.completed_at != null
    || run.safety_class !== 'safe' || !tx.killSwitch || tx.killSwitch.active !== false
    || Date.parse(run.collection_deadline_at) <= Date.parse(at)) return deny('reviewed_execution_job_not_open');
  const scoped = reviewedSafeJob(job, Date.parse(at));
  return scoped.ok ? null : deny(scoped.error);
}
function currentMaterial(tx, snapshot) {
  if (!same(tx.run.safety_constraints?.assurance_scope, deriveAssuranceScope({ target: snapshot.target, targetGroup: snapshot.targetGroup, policy: tx.policy }))
    || tx.run.target_group_id !== snapshot.targetGroup.id
    || !same(tx.run.safety_constraints?.reviewed_operation_binding,tx.job.constraints.reviewed_operation_binding)) return deny('reviewed_execution_material_changed');
  if (tx.issuance) {
    const history = [...snapshot.ownershipHistory].sort((a,b) => canonicalJsonStringify(a) < canonicalJsonStringify(b) ? -1 : canonicalJsonStringify(a) > canonicalJsonStringify(b) ? 1 : 0);
    if (tx.issuance.provenance_json?.ownership_history_sha256 !== reviewedHash(history)
      || !same(tx.issuance.provenance_json?.assurance_scope, tx.run.safety_constraints.assurance_scope)) return deny('reviewed_execution_proof_changed');
  }
  return null;
}
function grantContext(tx, ctx, snapshot, at) {
  return { originalJob: tx.job, reservation: tx.reservationRow?.reservation_json, check: snapshot.check,
    tenantId: ctx.tenantId, workerId: ctx.workerId, leasedAt: tx.job.leased_at, now: Date.parse(at) };
}
function issued(tx, ctx, snapshot, at, trust) {
  if (!tx.reservationRow || !same(tx.reservationRow.reservation_json, tx.job.worker_metadata?.execution_reservation)
    || tx.reservationRow.worker_id !== ctx.workerId || tx.reservationRow.leased_at !== tx.job.leased_at
    || tx.issuance?.state !== 'issued' || tx.issuance.reservation_id !== tx.reservationRow.id) return deny('reviewed_execution_grant_unavailable');
  const verified = verifyReviewedExecutionGrant({ grant: storedGrant(tx), context: grantContext(tx,ctx,snapshot,at), trust });
  return verified.ok ? null : deny(verified.error, verified.status);
}
/** Complete dedicated branch; default runtime never constructs a signer. PostgreSQL only. */
export function createReviewedSafeExecution({ repository, issuance, probeWorkerSecret, trust, keyReference } = {}) {
  if (repository?.durableReviewedExecutionBackend !== true || !issuance?.issueOnce || !probeWorkerSecret || !trust || !keyReference) throw new Error('reviewed safe execution dedicated dependencies required');
  const guarded = async (fn) => { try { return await fn(); } catch { return deny('reviewed_execution_backend_unavailable',503); } };
  const api = {
    available: true,
    availability(tenantId) {
      const resolved = resolveReviewedExecutionGrantTrust({ trust, tenantId, keyReference, issuance: true });
      return { available: resolved.ok, check_id: REVIEWED_SAFE_CHECK, reason: resolved.ok ? null : resolved.error };
    },
    withAdmission(ctx, request, callback) {
      if (!ctx?.userId || !roleHasPermission(ctx.role,'test_run:start')
        || Array.isArray(ctx.scopes) && !ctx.scopes.includes('*') && !ctx.scopes.includes('test_run:start')) return deny('forbidden',403);
      if (!api.availability(ctx.tenantId).available || request.checkId !== REVIEWED_SAFE_CHECK) return deny('reviewed_operation_execution_unavailable');
      return repository.withAdmission(ctx, request, (snapshot) => snapshot.binding.plan.template === 'marker-query-v1'
        ? callback(snapshot) : deny('reviewed_safe_scope_unavailable'));
    },
    reserveAndIssue: (ctx, jobId, body) => guarded(async () => {
      if (!id(ctx?.workerId) || !id(ctx?.tenantId)) return deny('unauthorized',401);
      if (!reviewedGrantExact(body, ['leased_at'])) return deny('invalid_probe_execution',400);
      const reservation = await repository.withTransaction(ctx, jobId, async (tx) => {
        const invalid = original(tx,ctx,probeWorkerSecret,await tx.now()); if (invalid) return invalid;
        if (body.leased_at !== tx.job.leased_at) return deny('reviewed_execution_lease_mismatch');
        return tx.withAuthority(async (snapshot) => {
          const material = currentMaterial(tx,snapshot); if (material) return material;
          if (tx.reservationRow || tx.issuance || tx.claim) return deny('reviewed_execution_opportunity_consumed');
          const at = await tx.now(); const fresh = original(tx,ctx,probeWorkerSecret,at); if (fresh) return fresh;
          const parsed = executionReservation(tx.job,ctx.workerId,body.leased_at,`rres_${randomUUID()}`,new Date(at)); if (parsed.error) return parsed;
          const b = snapshot.binding;
          parsed.reservation.reviewed_operation = { binding_version: b.version, review_id: b.review_id, plan_version: b.plan.version, plan_digest: b.plan_digest };
          await tx.reserve(parsed.reservation); return { reservation: parsed.reservation };
        });
      });
      if (reservation.error || !reservation.reservation) return reservation;
      const signed = await issuance.issueOnce(ctx,{ jobId, reservationId: reservation.reservation.id });
      if (!signed.ok) return deny(signed.error,signed.status);
      if (signed.replayed !== false) return deny('reviewed_execution_opportunity_consumed');
      return { reviewed: true, grant: signed.grant, issuance_id: signed.issuance_id, reservation: reservation.reservation,
        grants_execution: true, execution_available: true };
    }),
    consumeExecution: (ctx, jobId, body) => guarded(async () => {
      if (!id(ctx?.workerId) || !id(ctx?.tenantId)) return deny('unauthorized',401);
      if (!reviewedGrantExact(body,['reservation_id','grant_digest','challenge']) || !id(body.reservation_id)
        || ![body.grant_digest,body.challenge].every((v) => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v))) return deny('invalid_reviewed_execution_claim',400);
      const result = await repository.withTransaction(ctx,jobId,async (tx) => {
        const invalid = original(tx,ctx,probeWorkerSecret,await tx.now()); if (invalid) return invalid;
        return tx.withAuthority(async (snapshot) => {
          const at = await tx.now(), invalid = original(tx,ctx,probeWorkerSecret,at) || currentMaterial(tx,snapshot) || issued(tx,ctx,snapshot,at,trust); if (invalid) return invalid;
          if (tx.claim || tx.acceptance) return deny('reviewed_execution_already_consumed');
          if (body.reservation_id !== tx.reservationRow.id || body.grant_digest !== reviewedHash(storedGrant(tx))) return deny('reviewed_execution_grant_mismatch');
          const receipt = { version: 'reviewed-execution-claim.v1', id: `rclaim_${randomUUID()}`, tenant_id: ctx.tenantId,
            job_id: tx.job.id, run_id: tx.run.id, reservation_id: tx.reservationRow.id, worker_id: ctx.workerId, leased_at: tx.job.leased_at,
            grant_digest: body.grant_digest, challenge: body.challenge, claimed_at: at, not_after: tx.job.constraints.not_after };
          await tx.consume({ ...receipt, issuance_id: tx.issuance.id, challenge_hash: reviewedHash(body.challenge) });
          return { receipt, grant: storedGrant(tx), context: grantContext(tx,ctx,snapshot,at) };
        });
      });
      if (result.error) return result;
      // Response signed only after this invocation's own durable COMMIT acknowledgement.
      const verified = verifyReviewedExecutionGrant({ grant: result.grant, context: { ...result.context, now: Date.now() }, trust });
      if (!verified.ok) return deny(verified.error,verified.status);
      return { receipt: result.receipt, signature: reviewedClaimSignature(result.receipt,probeWorkerSecret) };
    }),
    ingestActivity: (ctx,jobId,body) => guarded(() => repository.withTransaction(ctx,jobId,async (tx) => {
      const invalid = original(tx,ctx,probeWorkerSecret,await tx.now()); if (invalid) return invalid;
      return tx.withAuthority(async (snapshot) => {
        const at = await tx.now(), invalid = original(tx,ctx,probeWorkerSecret,at) || currentMaterial(tx,snapshot); if (invalid) return invalid;
        // Before claim, capture may record job_started but never authorizes destination I/O.
        if (tx.claim && issued(tx,ctx,snapshot,at,trust)) return deny('reviewed_execution_current_authority_invalid');
        const parsed = normalizeProbeActivityBatch(body,tx.job,new Date(at)); if (parsed.error) return parsed;
        return tx.activity(parsed.items.map((item) => probeActivityEvent(tx.job,item,ctx.workerId)),parsed.capture);
      });
    })),
    ingestResult: (ctx,jobId,body) => guarded(() => repository.withTransaction(ctx,jobId,async (tx) => {
      const invalid = original(tx,ctx,probeWorkerSecret,await tx.now(),Boolean(tx.acceptance)); if (invalid) return invalid;
      if (tx.acceptance) {
        if (reviewedHash(body) !== tx.acceptance.body_digest) return deny('reviewed_result_replay_conflict');
        const event = await tx.acceptedEvent();
        if (!event || !same(event.metadata.execution_receipt,tx.acceptance.receipt_json)) return deny('reviewed_result_custody_unavailable');
        return { probe_event: event, run_id: tx.run.id, job_id: jobId, tenant_id: ctx.tenantId, reconciled: true };
      }
      return tx.withAuthority(async (snapshot) => {
        const at = await tx.now(), invalid = original(tx,ctx,probeWorkerSecret,at) || currentMaterial(tx,snapshot) || issued(tx,ctx,snapshot,at,trust); if (invalid) return invalid;
        if (!tx.claim || tx.claim.worker_id !== ctx.workerId || tx.claim.leased_at !== tx.job.leased_at
          || tx.claim.grant_digest !== reviewedHash(storedGrant(tx))) return deny('reviewed_result_claim_missing');
        if (!reviewedGrantExact(body,['external_result','metadata','safety_attestation'])) return deny('invalid_reviewed_result',400);
        const observed = validateReviewedSafeObservations(body.metadata?.reviewed_execution, { job: tx.job, claim: tx.claim, now: at,
          expected: reviewedSafeLegDescriptors(tx.job) }); if (!observed.ok) return deny(observed.error,400);
        const validated = validateProbeResultBody(body,tx.job.constraints,{ probeKind: tx.job.probe_profile.kind, probeProfile: tx.job.probe_profile, target: tx.job.target });
        if (!validated.ok) return deny(validated.error,validated.status);
        const { externalResult, safetyAttestation, workerMetadata } = validated;
        if (safetyAttestation.probe_requests_sent !== observed.legs.length || safetyAttestation.destination_resolver_attempts > 2
          || safetyAttestation.total_operations !== safetyAttestation.probe_requests_sent + safetyAttestation.destination_resolver_attempts
          || ['blocked','connected'].includes(externalResult) && (!observed.complete || observed.legs[0].health !== 'healthy')) return deny('reviewed_result_comparison_invalid',400);
        const receipt = { version: 'accepted-reviewed-probe-execution.v1', digest: reviewedHash({ tenant_id: ctx.tenantId, job_id: jobId,
          original_job_payload: tx.issuance.original_job_payload, original_job_signature: tx.job.job_signature,
          reservation: tx.reservationRow.reservation_json, issuance_id: tx.issuance.id, grant_digest: tx.claim.grant_digest,
          claim_id: tx.claim.id, nonce_hash: tx.job.nonce_hash, observations: body.metadata.reviewed_execution,
          safety_attestation: safetyAttestation, external_result: externalResult }) };
        const metadata = { ...workerMetadata, reviewed_execution: body.metadata.reviewed_execution, external_result: externalResult,
          probe_job_id: jobId, probe_worker_id: ctx.workerId, profile_kind: tx.job.probe_profile.kind, execution_receipt: receipt,
          reviewed_authority: { review_id: snapshot.binding.review_id, plan_digest: snapshot.binding.plan_digest,
            reservation_id: tx.reservationRow.id, issuance_id: tx.issuance.id, claim_id: tx.claim.id, grant_digest: tx.claim.grant_digest }, safety_attestation: safetyAttestation };
        const event = { id: `event_${randomUUID()}`, test_run_id: tx.run.id, target_id: tx.job.target_id, check_id: tx.job.check_id,
          source: 'probe_worker', signal_type: 'probe_result', producer_kind: 'signed_probe', nonce_hash: tx.job.nonce_hash,
          timestamp: body.metadata.reviewed_execution.completed_at, metadata };
        const accepted = await tx.accept({ event, receipt, bodyDigest: reviewedHash(body), acceptedAt: at,
          evidence: { id: `ev_${randomUUID()}`, test_run_id: tx.run.id, label: 'reviewed_safe_probe_evidence', metadata: { execution_receipt: receipt, probe_job_id: jobId }, created_at: at } });
        return { probe_event: accepted, run_id: tx.run.id, job_id: jobId, tenant_id: ctx.tenantId };
      });
    })),
  };
  return api;
}
