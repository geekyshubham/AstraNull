import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { assertNoManagedTenantTransaction } from '../persistence/postgres/tenantContext.mjs';
import { verifyProbeJobSignature } from '../lib/probeJobs.mjs';
import { canonicalJsonStringify } from '../lib/custody.mjs';
import { deriveAssuranceScope } from '../lib/assuranceScope.mjs';
import { signPreparedReviewedExecutionGrant } from '../lib/preparedReviewedExecutionGrant.mjs';
import { resolveReviewedExecutionGrantTrust, verifyReviewedExecutionGrant } from '../lib/reviewedExecutionGrant.mjs';
import { buildReviewedExecutionGrantEnvelope, validateReviewedExecutionGrantEnvelope, reviewedGrantExact,
  reviewedGrantJson, reviewedGrantUtc, REVIEWED_EXECUTION_GRANT_VERSION } from '../contracts/reviewedExecutionGrant.mjs';

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const hash = (value) => createHash('sha256').update(value).digest('hex');
const same = (a, b) => canonicalJsonStringify(a) === canonicalJsonStringify(b);
const deny = (error, status = 409) => ({ ok: false, error, status, grants_execution: false, execution_available: false });
const millisOnly = (value) => typeof value === 'string' ? value.replace(/(\.\d{3})000Z$/, '$1Z') : value;

/** The loader decides current authority BEFORE this deterministic evidence selection.
 * Equivalent duplicate latest rows may vary in query order, not in authority. Full history
 * (including every nonwinning/malformed/ambiguous row) is still bound; there is no fallback.
 */
function provenance(snapshot, run, policy) {
  const recorded = run.safety_constraints?.assurance_scope;
  const current = deriveAssuranceScope({ target: snapshot.target, targetGroup: snapshot.targetGroup, policy });
  if (!recorded || recorded.version !== 'assurance-scope.v3' || !same(recorded, current)
    || run.policy_id && !policy || run.target_group_id !== snapshot.targetGroup.id) return null;
  const history = snapshot.ownershipHistory.map((row) => ({ row, bytes: canonicalJsonStringify(row) }))
    .sort((a, b) => a.bytes < b.bytes ? -1 : a.bytes > b.bytes ? 1 : 0);
  const selected = history.find(({ row }) => row.tenant_id === snapshot.tenantId && row.target_id === snapshot.target.id
    && row.state === snapshot.ownership.state && row.source_kind === snapshot.ownership.source_kind
    && millisOnly(row.transitioned_at) === snapshot.ownership.transitioned_at
    && same(row.source_ref, snapshot.ownership.source_ref))?.row;
  if (!selected || selected.source_ref?.dns_target_binding?.version !== 'dns-ownership-target.v2') return null;
  const result = { assurance_scope: recorded, dns_proof: selected,
    ownership_history_sha256: hash(canonicalJsonStringify(history.map(({ row }) => row))) };
  return reviewedGrantJson(result) && Buffer.byteLength(canonicalJsonStringify(result)) <= 262144 ? result : null;
}
function authenticate(tx, ctx, request, secret) {
  const { job, run, reservation, killSwitch } = tx;
  if (!verifyProbeJobSignature(job, secret)) return deny('reviewed_grant_original_hmac_invalid');
  if (!run || job.tenant_id !== ctx.tenantId || job.id !== request.jobId || run.tenant_id !== ctx.tenantId
    || job.test_run_id !== run.id || job.target_id !== run.target_id || job.check_id !== run.check_id
    || job.nonce_hash !== run.correlation_json?.nonce_hash) return deny('reviewed_grant_run_mismatch');
  if (job.status !== 'leased' || job.completed_at != null || job.leased_by !== ctx.workerId
    || !Number.isFinite(reviewedGrantUtc(job.leased_at)) || !['running', 'collecting'].includes(run.status)
    || run.completed_at != null || run.safety_class !== 'safe') return deny('reviewed_grant_job_not_open');
  if (!killSwitch || killSwitch.active !== false) return deny('reviewed_grant_kill_switch_unavailable_or_active');
  if (!reviewedGrantJson(reservation) || reservation?.id !== request.reservationId) return deny('reviewed_grant_reservation_unavailable');
  return null;
}
function context(tx, ctx, snapshot, at) {
  return { originalJob: tx.job, reservation: tx.reservation, check: snapshot.check, tenantId: ctx.tenantId,
    workerId: ctx.workerId, leasedAt: tx.job.leased_at, now: at };
}
function rowMatches(row, tx, ctx, request, evidence, c) {
  if (row.probe_job_id !== request.jobId || row.test_run_id !== tx.run.id || row.reservation_id !== request.reservationId
    || row.worker_id !== ctx.workerId || row.leased_at !== tx.job.leased_at
    || row.original_job_signature !== tx.job.job_signature || !same(row.provenance_json, evidence)
    || !same(row.reservation_json, tx.reservation) || row.envelope_canonical !== canonicalJsonStringify(row.envelope_json)
    || row.envelope_sha256 !== hash(row.envelope_canonical)
    || row.original_job_payload !== row.envelope_json.original_job_payload
    || row.original_job_payload_sha256 !== hash(row.original_job_payload)
    || row.original_job_signature_sha256 !== hash(tx.job.job_signature)
    || row.claimed_at !== row.envelope_json.authority.grant_issued_at) return false;
  return validateReviewedExecutionGrantEnvelope(row.envelope_json, c).ok;
}
const storedGrant = (row) => ({ version: REVIEWED_EXECUTION_GRANT_VERSION, envelope: row.envelope_json, signature: row.grant_signature });
const success = (row, replayed) => ({ ok: true, grant: storedGrant(row), issuance_id: row.id, replayed,
  grants_execution: false, execution_available: false });
function releaseCommitted(result, trust) {
  if (!result.ok) return result;
  const { currentContext, ...reply } = result;
  // COMMIT itself can wait. A committed historical row is never released as renewed current authority.
  const verified = verifyReviewedExecutionGrant({ grant: reply.grant, context: { ...currentContext, now: Date.now() }, trust });
  return verified.ok ? reply : deny(verified.error, verified.status);
}

/** INTERNAL / UNREGISTERED. No route, admission, reservation, worker or ingestion wiring.
 * Input is identifiers only; ctx.workerId must come from authenticated server context.
 * There is no dev fallback, external signer default, takeover, retry, refund or renewal.
 */
export function createReviewedExecutionGrantIssuance({ repository, probeWorkerSecret, trust, keyReference, signingAdapter, timeoutMs = 5000 } = {}) {
  return {
    async issueOnce(ctx, request) {
      let claimed, completionToken;
      try {
        assertNoManagedTenantTransaction();
        if (!reviewedGrantExact(request, ['jobId', 'reservationId'])
          || ![request.jobId, request.reservationId].every((value) => typeof value === 'string' && ID.test(value))) return deny('reviewed_grant_request_invalid', 400);
        if (![ctx?.tenantId, ctx?.workerId].every((value) => typeof value === 'string' && ID.test(value))) return deny('unauthorized', 401);
        if (repository?.durableReviewedGrantBackend !== true || typeof repository.withTransaction !== 'function'
          || typeof repository.closeUnknown !== 'function') return deny('reviewed_grant_durable_backend_unavailable', 503);
        if (typeof probeWorkerSecret !== 'string' || !probeWorkerSecret.length || typeof signingAdapter?.signEnvelope !== 'function'
          || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) return deny('reviewed_grant_configuration_unavailable', 503);
        // Copy trusted context identifiers too; mutation during a signer wait cannot change tenant/worker.
        ctx = { tenantId: ctx.tenantId, workerId: ctx.workerId };
        request = { jobId: request.jobId, reservationId: request.reservationId };
        completionToken = randomBytes(32);
        const prepared = await repository.withTransaction(ctx, request, async (tx) => {
          const invalid = authenticate(tx, ctx, request, probeWorkerSecret);
          if (invalid) return invalid;
          return tx.withAuthority(async (snapshot) => {
            const row = await tx.getSlot(); // Lock any competing slot BEFORE sampling the fresh DB clock.
            const at = await tx.now(), evidence = provenance(snapshot, tx.run, tx.policy);
            if (!evidence) return deny('reviewed_grant_material_provenance_invalid');
            if (!Number.isFinite(reviewedGrantUtc(tx.run.collection_deadline_at))
              || Date.parse(at) >= Date.parse(tx.run.collection_deadline_at)) return deny('reviewed_grant_run_expired');
            const c = context(tx, ctx, snapshot, at);
            if (row) {
              if (!rowMatches(row, tx, ctx, request, evidence, c)) return deny('reviewed_grant_existing_claim_mismatch');
              if (row.state !== 'issued') return deny('reviewed_grant_consumed_unknown');
              const verified = verifyReviewedExecutionGrant({ grant: storedGrant(row), context: c, trust });
              return verified.ok ? { ...success(row, true), currentContext: c } : deny(verified.error, verified.status);
            }
            const resolved = resolveReviewedExecutionGrantTrust({ trust, tenantId: ctx.tenantId, keyReference, issuance: true });
            if (!resolved.ok) return deny(resolved.error, resolved.status);
            const built = buildReviewedExecutionGrantEnvelope(c, { algorithm: 'ed25519', key_reference: keyReference,
              public_key_fingerprint_sha256: resolved.material.publicKeyFingerprintSha256 });
            if (!built.ok) return deny(built.error, built.status);
            const envelope = built.envelope, payload = envelope.original_job_payload, canonical = canonicalJsonStringify(envelope);
            const claim = { id: `regi_${randomUUID()}`, tenant_id: ctx.tenantId, probe_job_id: tx.job.id, test_run_id: tx.run.id,
              target_id: tx.job.target_id, check_id: tx.job.check_id, reservation_id: tx.reservation.id,
              review_id: snapshot.binding.review_id, plan_digest: snapshot.binding.plan_digest,
              worker_id: ctx.workerId, leased_at: tx.job.leased_at, original_job_payload: payload,
              original_job_payload_sha256: hash(payload), original_job_signature: tx.job.job_signature,
              original_job_signature_sha256: hash(tx.job.job_signature), reservation_json: tx.reservation, provenance_json: evidence,
              envelope_json: envelope, envelope_canonical: canonical, envelope_sha256: hash(canonical),
              completion_token_hash: hash(completionToken), claimed_at: envelope.authority.grant_issued_at, state: 'signing_unknown' };
            await tx.insert(claim);
            return { ok: true, claim, context: c };
          });
        });
        // An ambiguous COMMIT throws above: zero signer calls, no claim takeover/compensation.
        if (!prepared.ok) return prepared;
        if (!prepared.claim) return releaseCommitted(prepared, trust);
        claimed = prepared.claim;
        const signed = await signPreparedReviewedExecutionGrant({ envelope: claimed.envelope_json, context: prepared.context,
          trust, signingAdapter, timeoutMs }); // REAL current clock; never replay the issuance timestamp as now.
        if (!signed.ok) {
          await repository.closeUnknown(ctx, claimed.id, completionToken, signed.error).catch(() => {});
          return deny(signed.error, signed.status);
        }
        const finalized = await repository.withTransaction(ctx, request, async (tx) => {
          const invalid = authenticate(tx, ctx, request, probeWorkerSecret);
          if (invalid) return invalid;
          return tx.withAuthority(async (snapshot) => {
            const row = await tx.getSlot(), at = await tx.now(), evidence = provenance(snapshot, tx.run, tx.policy);
            const c = context(tx, ctx, snapshot, at);
            if (!row || row.id !== claimed.id || row.state !== 'signing_unknown'
              || row.completion_token_hash !== hash(completionToken)) return deny('reviewed_grant_completion_owner_invalid');
            if (!evidence || !rowMatches(row, tx, ctx, request, evidence, c)
              || !same(signed.grant.envelope, row.envelope_json)) return deny('reviewed_grant_final_authority_changed');
            if (!Number.isFinite(reviewedGrantUtc(tx.run.collection_deadline_at))
              || Date.parse(at) >= Date.parse(tx.run.collection_deadline_at)) return deny('reviewed_grant_run_expired');
            const verified = verifyReviewedExecutionGrant({ grant: signed.grant, context: c, trust });
            if (!verified.ok) return deny(verified.error, verified.status);
            const issued = await tx.finish(row, completionToken, signed.grant.signature, at);
            return issued ? { ...success(issued, false), currentContext: c } : deny('reviewed_grant_completion_owner_invalid');
          });
        });
        if (!finalized.ok) await repository.closeUnknown(ctx, claimed.id, completionToken, 'reviewed_grant_final_authority_changed').catch(() => {});
        // withTransaction has acknowledged issued + audit COMMIT before this return.
        return releaseCommitted(finalized, trust);
      } catch (error) {
        if (claimed) await repository.closeUnknown(ctx, claimed.id, completionToken, 'reviewed_grant_finalization_failed').catch(() => {});
        return deny(error?.code === 'reviewed_grant_enclosing_transaction' ? error.code : 'reviewed_grant_issuance_unavailable', 503);
      } finally { completionToken?.fill(0); }
    },
  };
}
