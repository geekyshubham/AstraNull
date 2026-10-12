import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { canonicalJsonStringify } from './custody.mjs';
import { verifyProbeJobSignature } from './probeJobs.mjs';
import { verifyReviewedExecutionGrant } from './reviewedExecutionGrant.mjs';
import { getCheckById } from '../contracts/checks.mjs';
import { reviewedGrantExact, reviewedGrantUtc } from '../contracts/reviewedExecutionGrant.mjs';
import { validateSignedReviewedOperationBinding } from '../contracts/reviewedOperationBinding.mjs';

export const REVIEWED_SAFE_CHECK = 'waf.evasion_base64_wrap.safe';
export const reviewedHash = (value) => createHash('sha256').update(typeof value === 'string' ? value : canonicalJsonStringify(value)).digest('hex');
export function reviewedSafeJob(job, now = Date.now()) {
  const checked = validateSignedReviewedOperationBinding(job, { check: getCheckById(REVIEWED_SAFE_CHECK), now });
  const c = job?.constraints;
  return checked.ok && !checked.legacy && job.check_id === REVIEWED_SAFE_CHECK && c.max_probe_requests === 3
    && c.max_destination_resolver_attempts === 2 && c.max_total_operations === 5 && c.max_requests === 5
    && c.execution_attempts === 1 && job.probe_profile.evasion_transform === 'base64_wrap'
    ? { ok: true } : { ok: false, error: checked.error ?? 'reviewed_safe_scope_unavailable' };
}
export function reviewedClaimSignature(receipt, secret) {
  return createHmac('sha256', secret).update(`reviewed-execution-claim.v1\n${canonicalJsonStringify(receipt)}`).digest('hex');
}
function equal(a, b) {
  return typeof a === 'string' && typeof b === 'string' && a.length === b.length
    && timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
/** Each invocation creates its own unpredictable response challenge. A retained response,
 * client boolean, or a received Ed25519 grant is NEVER an execution capability. The server
 * must commit the globally unique original job/run/reservation claim before replying. */
export async function consumeReviewedWorkerExecution(job, { grant, trust, secret, workerId, claimExecution } = {}) {
  try {
    if (!verifyProbeJobSignature(job, secret)) return { ok: false, error: 'invalid_job_signature' };
    const scope = reviewedSafeJob(job);
    if (!scope.ok) return scope;
    const context = () => ({ originalJob: job, reservation: grant?.envelope?.reservation,
      check: getCheckById(REVIEWED_SAFE_CHECK), tenantId: job.tenant_id, workerId, leasedAt: job.leased_at, now: Date.now() });
    const verified = verifyReviewedExecutionGrant({ grant, context: context(), trust });
    if (!verified.ok) return verified;
    if (typeof claimExecution !== 'function') return { ok: false, error: 'reviewed_execution_claim_unavailable' };
    const challenge = randomBytes(32).toString('hex');
    const response = await claimExecution({ reservation_id: grant.envelope.reservation.id, grant_digest: reviewedHash(grant), challenge });
    const receipt = response?.receipt;
    if (!reviewedGrantExact(response, ['receipt', 'signature']) || !reviewedGrantExact(receipt,
      ['version', 'id', 'tenant_id', 'job_id', 'run_id', 'reservation_id', 'worker_id', 'leased_at', 'grant_digest', 'challenge', 'claimed_at', 'not_after'])
      || receipt.version !== 'reviewed-execution-claim.v1' || receipt.tenant_id !== job.tenant_id || receipt.job_id !== job.id
      || receipt.run_id !== job.test_run_id || receipt.reservation_id !== grant.envelope.reservation.id || receipt.worker_id !== workerId
      || receipt.leased_at !== job.leased_at || receipt.grant_digest !== reviewedHash(grant) || receipt.challenge !== challenge
      || receipt.not_after !== job.constraints.not_after || !Number.isFinite(reviewedGrantUtc(receipt.claimed_at))
      || Date.parse(receipt.claimed_at) > Date.now() || Date.parse(receipt.claimed_at) < Date.parse(grant.envelope.authority.grant_issued_at)
      || !equal(response.signature, reviewedClaimSignature(receipt, secret))) return { ok: false, error: 'reviewed_execution_claim_response_invalid' };
    const current = verifyReviewedExecutionGrant({ grant, context: context(), trust });
    return current.ok ? { ok: true, receipt } : current;
  } catch { return { ok: false, error: 'reviewed_execution_claim_unavailable' }; }
}
