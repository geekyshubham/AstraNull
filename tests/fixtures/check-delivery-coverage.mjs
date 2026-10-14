import { createHash } from 'node:crypto';
import { CHECK_CATALOG, ALLOWED_PROBE_PROFILE_KINDS, PENDING_T7_PROBE_KINDS, isCustomerRunnable } from '../../src/contracts/checks.mjs';
import { buildVectorTargetMatrix } from '../../src/contracts/vectorTargetMatrix.mjs';
import { canonicalJsonStringify } from '../../src/lib/custody.mjs';
import { deriveCheckDefinitionVersion } from '../../src/lib/checkDefinitionVersion.mjs';
import { evidenceTierForCheck, SUPPORTED_EVASION_TRANSFORMS } from '../../src/lib/probeEvidenceTiers.mjs';
import { executorNameForProbeKind } from '../../workers/probe-worker.mjs';
import { probeExecutionEvidenceReceipt } from '../../src/lib/probeExecution.mjs';

// This is an inventory, NOT an evidence generator. A supported row without an actual
// invocation receipt is a failing delivery gap, never an implicit unsupported row.
export const DELIVERY_INVENTORY_VERSION = 'check-delivery-coverage.v1';
export const SHIPPED_PROFILE_KINDS = Object.freeze([...ALLOWED_PROBE_PROFILE_KINDS]);
const supportedTransforms = new Set(SUPPORTED_EVASION_TRANSFORMS);

export function deliveryDisposition(check) {
  const p = check.probe_profile;
  if (!isCustomerRunnable(check)) return { disposition: 'soc_request_only', reason: 'soc_gated_check', execution: 'none' };
  if (p.kind === 'metadata_marker') return { disposition: 'declaration_only', reason: 'metadata_only_check_has_no_executable_probe', execution: 'metadata' };
  if (p.kind === 'ops_readiness') return { disposition: 'governance_inline', reason: p.scenario, execution: 'inline' };
  if (p.kind === 'host_sni_bypass') {
    const reason = check.check_id === 'nfw.origin_lockdown.safe' ? 'declared_origin_lockdown_required' : 'missing_target_bound_direct_address';
    return { disposition: 'additional_target_input', reason, execution: 'admission_refusal' };
  }
  if (PENDING_T7_PROBE_KINDS.includes(p.kind) && !executorNameForProbeKind(p.kind)) {
    return { disposition: 'additional_target_input', reason: 't7_probe_module_pending', execution: 'admission_refusal' };
  }
  if ((check.runnable_requires ?? []).includes('two_perspectives')) return { disposition: 'additional_target_input', reason: 'two_perspectives_required', execution: 'admission_refusal' };
  if ((check.runnable_requires ?? []).includes('declared_tcp_deny')) return { disposition: 'additional_target_input', reason: 'declared_tcp_deny_required', execution: 'admission_refusal' };
  if ((check.runnable_requires ?? []).includes('declared_udp_deny')) return { disposition: 'additional_target_input', reason: 'declared_udp_deny_required', execution: 'admission_refusal' };
  if ((check.runnable_requires ?? []).includes('port_or_declared_tcp_deny') || (check.runnable_requires ?? []).includes('port_or_declared_udp_deny')) {
    return { disposition: 'additional_target_input', reason: 'port_or_declared_deny_required', execution: 'admission_refusal' };
  }
  if ((check.runnable_requires ?? []).includes('port') && !Number.isInteger(p.default_port) && !Number.isInteger(p.service_port) && !Number.isInteger(p.port)) {
    return { disposition: 'additional_target_input', reason: 'port_required', execution: 'admission_refusal' };
  }
  if (p.kind === 'alert_webhook_ping') return { disposition: 'additional_signed_scope', reason: 'approved_signed_callback_scope_required', execution: 'worker_refusal' };
  if (p.kind === 'waf_evasion_marker_probe' && !supportedTransforms.has(p.evasion_transform)) return { disposition: 'unsupported_delivery', reason: 'unsupported_evasion_delivery', execution: 'worker_refusal' };
  if (p.kind === 'reflection_service_probe' && p.payload_profile === 'ipp_get_printer_attributes') return { disposition: 'unsupported_delivery', reason: 'unsupported_or_unapproved_protocol_request', execution: 'worker_refusal' };
  if (p.kind === 'waf_inspection_limit_probe') return { disposition: 'unsupported_delivery', reason: 'approved_business_safe_body_endpoint_required', execution: 'worker_refusal' };
  if (p.kind === 'l7_resource_posture_probe' && p.marker_class === 'declared_content_encoding') return { disposition: 'unsupported_delivery', reason: 'approved_business_safe_body_endpoint_required', execution: 'worker_refusal' };
  if (!executorNameForProbeKind(p.kind)) throw new Error(`Unclassified live profile: ${check.check_id}/${p.kind}`);
  return { disposition: evidenceTierForCheck(check) === 'E3' ? 'supported_semantic_safe' : 'supported_observation', reason: null, execution: 'socket' };
}

/** Include every signed profile field, caps, target classes, declarations and expectations.
 * mechanism_id alone is deliberately insufficient (qtype/transport, method/path,
 * settings assertions, service port/response shape, class/transform all affect delivery).
 */
export function deliveryMaterial(check) {
  return {
    profile: check.probe_profile ?? null,
    supported_targets: check.supported_targets,
    prerequisites: check.prerequisites,
    required_customer_setup: check.required_customer_setup,
    default_expected_behavior: check.default_expected_behavior ?? null,
    safety_constraints: check.safety_constraints,
    evidence_required: check.evidence_required,
    stop_conditions: check.stop_conditions,
    customer_runnable: isCustomerRunnable(check),
  };
}
export function deliveryFingerprint(check) {
  return createHash('sha256').update(canonicalJsonStringify(deliveryMaterial(check))).digest('hex');
}

export function buildCheckDeliveryInventory(catalog = CHECK_CATALOG) {
  const rows = catalog.map((check) => ({
    check_id: check.check_id,
    check_version: deriveCheckDefinitionVersion(check).check_version,
    definition_digest: deriveCheckDefinitionVersion(check).digest,
    kind: check.probe_profile?.kind ?? null,
    mechanism_id: check.mechanism_id ?? null,
    evidence_tier: evidenceTierForCheck(check),
    delivery_fingerprint: deliveryFingerprint(check),
    delivery_material: structuredClone(deliveryMaterial(check)),
    ...deliveryDisposition(check),
  }));
  // Explicit equality aliases do not multiply independently delivered mechanisms.
  const aliases = Object.values(Object.groupBy(rows, (row) => row.delivery_fingerprint))
    .filter((group) => group.length > 1)
    .map((group) => ({ fingerprint: group[0].delivery_fingerprint, check_ids: group.map((row) => row.check_id) }));
  const matrix = buildVectorTargetMatrix();
  return {
    version: DELIVERY_INVENTORY_VERSION,
    summary: {
      definitions: rows.length, vectors: matrix.rows.length,
      default_fqdn_safe_ids: matrix.runnable_safe_check_ids.length,
      allowed_kinds: SHIPPED_PROFILE_KINDS.length,
      distinct_delivery_fingerprints: new Set(rows.map((row) => row.delivery_fingerprint)).size,
      dispositions: Object.fromEntries(Object.entries(Object.groupBy(rows, (row) => row.disposition)).map(([key, values]) => [key, values.length])),
    },
    aliases, rows,
  };
}
// Finite existing-behavior obligations, NOT a universal mechanism certification.
// Each distinct complete delivery fingerprint owns branches; exact aliases share
// these obligations but retain their own default definition invocations.
export const DELIVERY_BRANCH_POLICIES = Object.freeze({
  origin_leak_scan: ['peer_error', 'timeout', 'cancel'],
  host_sni_bypass: ['peer_error', 'timeout', 'cancel'],
  port_scan_bounded: ['peer_refused', 'timeout', 'cancel'],
  http_head: ['peer_error', 'timeout', 'cancel'],
  tcp_connect: ['peer_refused', 'timeout', 'cancel'],
  udp_probe: ['unconfirmed_response', 'timeout', 'cancel'],
  dns_wire_query: ['malformed_response', 'wrong_peer', 'timeout', 'cancel'],
  dns_open_recursion: ['negative_dns', 'timeout', 'cancel'],
  waf_enforcement_probe: ['permitted_unhealthy', 'peer_error', 'timeout', 'cancel'],
  waf_fingerprint_observation: ['peer_error', 'timeout', 'cancel'],
  rate_limit_sequence: ['peer_error', 'timeout', 'cancel'],
  http_method_matrix: ['peer_error', 'timeout', 'cancel'],
  header_size_probe: ['peer_error', 'timeout', 'cancel'],
  tls_audit: ['invalid_tls', 'timeout', 'cancel'],
  http2_settings: ['invalid_h2', 'timeout', 'cancel'],
  quic_reachability: ['peer_error', 'timeout', 'cancel'],
  dnssec_posture: ['negative_dns', 'timeout', 'cancel'],
  dns_failover_posture: ['negative_dns', 'timeout', 'cancel'],
  dns_axfr_leak: ['malformed_response', 'axfr_transfer', 'timeout', 'cancel'],
  cache_abuse_probe: ['peer_error', 'timeout', 'cancel'],
  graphql_posture_probe: ['peer_error', 'timeout', 'cancel'],
  bot_challenge_probe: ['peer_error', 'timeout', 'cancel'],
  slow_header_probe: ['peer_error', 'timeout', 'cancel'],
  tls_session: ['invalid_tls', 'timeout', 'cancel'],
  grpc_reflection_probe: ['malformed_response', 'unimplemented', 'timeout', 'cancel'],
  websocket_upgrade_posture: ['invalid_upgrade', 'timeout', 'cancel'],
  api_surface_scan: ['peer_error', 'timeout', 'cancel'],
  cors_posture_probe: ['peer_error', 'timeout', 'cancel'],
  reflection_service_probe: ['payload_bytes', 'unconfirmed_response', 'timeout', 'cancel'],
  http2_frame_probe: ['invalid_h2', 'timeout', 'cancel'],
  http3_control_probe: ['peer_error', 'timeout', 'cancel'],
  waf_class_marker_probe: ['permitted_unhealthy', 'unsigned_denial', 'peer_error', 'timeout', 'cancel'],
  waf_evasion_marker_probe: ['permitted_unhealthy', 'variant_allowed', 'partial', 'unsigned_denial', 'peer_error', 'timeout', 'cancel'],
  l7_resource_posture_probe: ['peer_error', 'timeout', 'cancel'],
  connection_limit_probe: ['peer_refused', 'timeout', 'cancel'],
  waf_method_policy_probe: ['peer_error', 'timeout', 'cancel'],
  rate_limit_canary_probe: ['peer_error', 'timeout', 'cancel'],
});

export function buildDeliveryBranchObligations(inventory) {
  const seen = new Set();
  const obligations = [];
  for (const row of inventory.rows.filter((candidate) => candidate.execution === 'socket')) {
    if (seen.has(row.delivery_fingerprint)) continue;
    seen.add(row.delivery_fingerprint);
    const branches = DELIVERY_BRANCH_POLICIES[row.kind];
    if (!branches) throw new Error(`Branch policy missing: ${row.kind}`);
    for (const branch of [...branches, ...(row.check_id === 'dns.random_prefix_nxdomain.safe' ? ['nxdomain'] : [])]) {
      obligations.push({ branch_id: `${row.delivery_fingerprint}:${branch}`, branch, check_id: row.check_id, kind: row.kind, delivery_fingerprint: row.delivery_fingerprint });
    }
  }
  return obligations;
}
export const CHECK_DELIVERY_INVENTORY = buildCheckDeliveryInventory();
CHECK_DELIVERY_INVENTORY.branch_obligations = buildDeliveryBranchObligations(CHECK_DELIVERY_INVENTORY);

/** Aggregate only receipts produced by actual test invocations, not test names. */
export function accountDeliveryReceipts(receipts, inventory = CHECK_DELIVERY_INVENTORY, { definitionsOnly = false } = {}) {
  const byId = new Map(inventory.rows.map((row) => [row.check_id, row]));
  const obligations = inventory.branch_obligations ?? buildDeliveryBranchObligations(inventory);
  const byBranch = new Map(obligations.map((row) => [row.branch_id, row]));
  const seenBranches = new Set();
  const seenInvocations = new Set();
  const seen = new Set();
  const errors = [];
  for (const receipt of receipts) {
    const row = byId.get(receipt.check_id);
    if (!row) { errors.push(`unknown_check:${receipt.check_id}`); continue; }
    if (receipt.delivery_fingerprint !== row.delivery_fingerprint || receipt.check_version !== row.check_version || receipt.definition_digest !== row.definition_digest) errors.push(`catalog_binding_mismatch:${row.check_id}`);
    if (!receipt.tenant_id || !receipt.invocation_id) errors.push(`invocation_binding_missing:${row.check_id}`);
    if (receipt.execution !== row.execution || receipt.disposition !== row.disposition) errors.push(`disposition_mismatch:${row.check_id}`);
    if (['socket', 'metadata', 'worker_refusal'].includes(row.execution)) {
      const job = receipt.signed_job, event = receipt.accepted_event, verdict = receipt.published_verdict;
      if (!job || !event || !verdict || !receipt.reservation_id || !receipt.run_id || !receipt.nonce_hash || !receipt.job_signature || !receipt.execution_receipt?.digest || !receipt.result_body?.safety_attestation) {
        errors.push(`actual_proof_missing:${row.check_id}`);
      } else {
        if (job.id !== receipt.job_id || job.test_run_id !== receipt.run_id || job.tenant_id !== receipt.tenant_id || job.check_id !== row.check_id || job.nonce_hash !== receipt.nonce_hash || job.job_signature !== receipt.job_signature || event.id !== receipt.event_id || event.tenant_id !== receipt.tenant_id || event.test_run_id !== receipt.run_id || event.check_id !== row.check_id || event.target_id !== job.target_id || event.nonce_hash !== job.nonce_hash || event.metadata?.probe_job_id !== job.id || verdict.id !== receipt.verdict_id || verdict.tenant_id !== receipt.tenant_id || verdict.test_run_id !== receipt.run_id || verdict.check_id !== row.check_id || verdict.target_id !== job.target_id || !verdict.evidence_ids?.includes(event.id)) errors.push(`accepted_binding_mismatch:${row.check_id}`);
        const digest = probeExecutionEvidenceReceipt(job, event.metadata?.probe_worker_id, receipt.result_body.safety_attestation, receipt.outcome?.external_result).digest;
        if (digest !== receipt.execution_receipt.digest || digest !== event.metadata?.execution_receipt?.digest) errors.push(`accepted_custody_mismatch:${row.check_id}`);
        if (canonicalJsonStringify(job.constraints) !== canonicalJsonStringify(receipt.signed_caps) || canonicalJsonStringify(job.probe_profile) !== canonicalJsonStringify(receipt.signed_profile) || canonicalJsonStringify(job.target) !== canonicalJsonStringify(receipt.signed_target)) errors.push(`signed_delivery_mismatch:${row.check_id}`);
      }
    }
    if (row.execution === 'socket') {
      const dnsKind = ['dns_wire_query', 'dnssec_posture', 'dns_axfr_leak', 'dns_open_recursion', 'dns_failover_posture', 'dns_resolve'].includes(row.kind);
      if (!receipt.actual_wire?.some((wire) => dnsKind ? ['dns_udp', 'dns_tcp'].includes(wire.transport) : !['dns_udp', 'dns_tcp'].includes(wire.transport))) errors.push(`actual_probe_wire_missing:${row.check_id}`);
    } else if (receipt.actual_wire?.length) errors.push(`unexpected_no_execution_wire:${row.check_id}`);
    if (['none', 'admission_refusal'].includes(row.execution) && receipt.admission?.error !== row.reason) errors.push(`admission_reason_mismatch:${row.check_id}`);
    if (['metadata', 'worker_refusal'].includes(row.execution) && ((receipt.outcome?.metadata?.inconclusive_reason ?? receipt.outcome?.metadata?.not_run_reason) !== row.reason || receipt.outcome?.total_operations !== 0)) errors.push(`worker_refusal_mismatch:${row.check_id}`);
    if (row.execution === 'inline' && (!receipt.run_id || !receipt.accepted_event || !receipt.published_verdict || receipt.accepted_event.metadata?.scenario !== row.reason)) errors.push(`inline_governance_missing:${row.check_id}`);
    if (seenInvocations.has(receipt.invocation_id)) errors.push(`duplicate_actual_invocation:${receipt.invocation_id}`);
    seenInvocations.add(receipt.invocation_id);
    if (receipt.branch_id) {
      const obligation = byBranch.get(receipt.branch_id);
      if (!obligation || obligation.check_id !== row.check_id || obligation.delivery_fingerprint !== receipt.delivery_fingerprint) errors.push(`unknown_branch_binding:${receipt.branch_id}`);
      if (seenBranches.has(receipt.branch_id)) errors.push(`duplicate_branch_invocation:${receipt.branch_id}`);
      seenBranches.add(receipt.branch_id);
      if (!receipt.branch_assertions?.length || !receipt.branch_peer_evidence?.length) errors.push(`branch_assertion_missing:${receipt.branch_id}`);
      if (obligation?.branch === 'timeout' && receipt.outcome?.external_result !== 'timeout') errors.push(`timeout_branch_not_observed:${receipt.branch_id}`);
      if (obligation?.branch === 'cancel' && !receipt.branch_peer_evidence?.some((item) => item.event === 'cancel_requested')) errors.push(`cancel_branch_not_observed:${receipt.branch_id}`);
      if (receipt.readiness?.coverage?.passed_count > 0 && !['payload_bytes', 'axfr_transfer'].includes(obligation?.branch)) errors.push(`negative_branch_readiness_credit:${receipt.branch_id}`);
    } else {
      if (seen.has(row.check_id)) errors.push(`duplicate_definition_invocation:${row.check_id}`);
      seen.add(row.check_id);
    }
  }
  const gaps = inventory.rows.filter((row) => !seen.has(row.check_id)).map((row) => ({ check_id: row.check_id, disposition: row.disposition, reason: 'definition_invocation_missing' }));
  const branch_gaps = definitionsOnly ? [] : obligations.filter((row) => !seenBranches.has(row.branch_id)).map((row) => ({ ...row, reason: 'required_branch_invocation_missing' }));
  return { complete: gaps.length === 0 && branch_gaps.length === 0 && errors.length === 0, invoked_definitions: seen.size, invoked_branches: seenBranches.size, errors, gaps, branch_gaps, receipts };
}
