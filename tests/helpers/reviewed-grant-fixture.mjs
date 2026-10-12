import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { getCheckById, buildProbeProfile } from '../../src/contracts/checks.mjs';
import { buildReviewedOperationPlan } from '../../src/contracts/reviewedOperations.mjs';
import { buildReviewedOperationBinding } from '../../src/contracts/reviewedOperationBinding.mjs';
import { dnsOwnershipTargetBinding } from '../../src/lib/dnsOwnershipTarget.mjs';
import { deriveAssuranceScope } from '../../src/lib/assuranceScope.mjs';
import { signProbeJob, targetDescriptor } from '../../src/lib/probeJobs.mjs';
import { canonicalJsonStringify } from '../../src/lib/custody.mjs';

export const SECRET = 'configured-original-worker-test-secret';
export const KEY = 'key://astranull/reviewed-execution/issuance-test';
export const CHECK = 'waf.evasion_base64_wrap.safe';
export const iso = (value) => new Date(value).toISOString();
export function keyFixture(tenantId = 'ten_grant_test') {
  const pair = generateKeyPairSync('ed25519');
  const der = pair.publicKey.export({ type: 'spki', format: 'der' });
  const fingerprint = createHash('sha256').update(der).digest('hex');
  const trust = { version: 'reviewed-execution-grant-trust.v1', purpose: 'astranull.reviewed-operation.execution-grant',
    tenants: { [tenantId]: { [KEY]: { algorithm: 'ed25519', public_key_spki_der_base64: der.toString('base64'),
      public_key_fingerprint_sha256: fingerprint, signing_enabled: true } } } };
  const signer = { algorithm: 'ed25519', key_reference: KEY, public_key_fingerprint_sha256: fingerprint };
  const receipt = (envelope) => ({ version: 'reviewed-execution-grant-signature.v1', ...signer,
    signature: sign(null, Buffer.from(canonicalJsonStringify(envelope)), pair.privateKey).toString('base64') });
  return { trust, signer, receipt, pair };
}
export function grantFixture({ suffix = 'unit', tenantId = 'ten_grant_test', at = Date.now() - 1000, target: actualTarget, group: actualGroup } = {}) {
  const target = actualTarget ?? { id: `tgt_${suffix}`, tenant_id: tenantId, target_group_id: `tg_${suffix}`, kind: 'url',
    value: `https://${suffix.replaceAll('_', '-')}.example.test/diagnostic`, protocol: 'https', port: 443,
    expected_behavior: 'must_block_before_origin', declaration_json: { operation: 'inert' } };
  const group = actualGroup ?? { id: target.target_group_id, tenant_id: tenantId };
  const check = structuredClone(getCheckById(CHECK));
  const proposal = buildReviewedOperationPlan({ target_id: target.id, check_id: CHECK, template: 'marker-query-v1',
    semantics: 'inert_diagnostic', side_effects: 'none', expires_at: iso(at + 3_600_000) },
  { tenantId, target, check, now: iso(at) });
  assert.ok(proposal.plan, JSON.stringify(proposal));
  const review = { id: `rop_${suffix}`, tenant_id: tenantId, target_id: target.id, plan: proposal.plan, plan_digest: proposal.plan_digest,
    approved_by: 'usr_grant_owner', approved_role: 'owner', approved_at: iso(at), revoked_at: null, revoked_by: null };
  const ownership = { id: `proof_${suffix}`, tenant_id: tenantId, target_id: target.id, state: 'dns_verified', source_kind: 'dns_txt',
    transitioned_at: iso(at - 1000), source_ref: { dns_target_binding: dnsOwnershipTargetBinding(target) } };
  const built = buildReviewedOperationBinding({ tenantId, reviewId: review.id, review, target, check, ownership,
    originalAuthority: { issued_at: iso(at + 1), not_after: iso(at + 120_000) }, now: iso(at + 2) });
  assert.equal(built.ok, true, JSON.stringify(built));
  const binding = built.binding;
  const job = { id: `job_${suffix}`, tenant_id: tenantId, test_run_id: `run_${suffix}`, target_id: target.id, check_id: CHECK,
    nonce_hash: 'a'.repeat(64), target: targetDescriptor(target), probe_profile: buildProbeProfile(check.probe_profile),
    constraints: { authority_version: 'probe-authority-v2', issued_at: binding.authority.issued_at, not_after: binding.authority.not_after,
      execution_attempts: 1, timeout_ms: 5000, max_probe_requests: 4, min_destination_resolver_attempts: 2,
      max_destination_resolver_attempts: 2, max_total_operations: 6, max_requests: 6, ownership_binding: binding.ownership,
      reviewed_operation_binding: binding }, leased_at: iso(at + 2), leased_by: 'worker_grant', status: 'leased', completed_at: null };
  job.job_signature = signProbeJob(job, SECRET);
  const reservation = { version: 'execution-reservation.v1', id: `res_${suffix}`, worker_id: job.leased_by, leased_at: job.leased_at,
    reserved_at: iso(at + 3), not_after: job.constraints.not_after, max_probe_requests: 4, max_destination_resolver_attempts: 2,
    max_total_operations: 6, state: 'reserved_unknown', reviewed_operation: { binding_version: binding.version,
      review_id: binding.review_id, plan_version: binding.plan.version, plan_digest: binding.plan_digest } };
  const run = { id: job.test_run_id, tenant_id: tenantId, target_group_id: group.id, target_id: target.id, check_id: CHECK,
    status: 'running', safety_class: 'safe', collection_deadline_at: iso(at + 120_000), correlation_json: { nonce_hash: job.nonce_hash },
    safety_constraints: { assurance_scope: deriveAssuranceScope({ target, targetGroup: group }) }, completed_at: null };
  const ctx = { tenantId, workerId: job.leased_by }, request = { jobId: job.id, reservationId: reservation.id };
  const snapshot = { tenantId, target, targetGroup: group, check, ownership, ownershipHistory: [ownership], binding };
  const context = { originalJob: job, reservation, check, tenantId, workerId: ctx.workerId, leasedAt: job.leased_at, now: iso(at + 4) };
  return { target, group, check, proposal, review, ownership, job, reservation, run, ctx, request, snapshot, context };
}
export function deferred() {
  let resolve;
  const promise = new Promise((yes) => { resolve = yes; });
  return { promise, resolve };
}
