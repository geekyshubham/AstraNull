import { createHash } from 'node:crypto';
import { CHECK_CATALOG, ALLOWED_PROBE_PROFILE_KINDS, PENDING_T7_PROBE_KINDS, isCustomerRunnable } from '../../src/contracts/checks.mjs';
import { buildVectorTargetMatrix } from '../../src/contracts/vectorTargetMatrix.mjs';
import { canonicalJsonStringify } from '../../src/lib/custody.mjs';
import { deriveCheckDefinitionVersion } from '../../src/lib/checkDefinitionVersion.mjs';
import { evidenceTierForCheck, SUPPORTED_EVASION_TRANSFORMS } from '../../src/lib/probeEvidenceTiers.mjs';
import { executorNameForProbeKind, sanitizeProbeMetadata } from '../../workers/probe-worker.mjs';
import { probeExecutionEvidenceReceipt } from '../../src/lib/probeExecution.mjs';
import { checkPresentation } from '../../src/lib/checkPresentation.mjs';
import { isVerdictCapableProbeKind } from '../../src/lib/probeEvidenceTiers.mjs';
import { parseDnsResponseStructure } from '../../src/lib/dnsTcpWire.mjs';
import { hardTimeoutSchedulerToleranceMs } from '../../src/lib/probeResultValidation.mjs';
import { RISKY_ADMIN_PORTS } from '../../src/lib/capabilityProbes.mjs';
import { assertDeliveredReflectorRequest } from '../helpers/check-delivery-payload-assertions.mjs';

// This is an inventory, NOT an evidence generator. A supported row without an actual
// invocation receipt is a failing delivery gap, never an implicit unsupported row.
export const DELIVERY_INVENTORY_VERSION = 'check-delivery-coverage.v1';
export const SHIPPED_PROFILE_KINDS = Object.freeze([...ALLOWED_PROBE_PROFILE_KINDS]);
const supportedTransforms = new Set(SUPPORTED_EVASION_TRANSFORMS);

export function deliveryDisposition(check) {
  const p = check.probe_profile;
  // SOC request markers now start like any other check. They carry no probe profile, so the
  // signed job is a metadata-only probe: the run is admitted and finalized without wire I/O.
  if (check.risk_class === 'soc_gated' || !p) return { disposition: 'soc_request_only', reason: 'metadata_only_check_has_no_executable_probe', execution: 'metadata' };
  if (p.kind === 'metadata_marker') return { disposition: 'declaration_only', reason: 'metadata_only_check_has_no_executable_probe', execution: 'metadata' };
  if (p.kind === 'ops_readiness') return { disposition: 'governance_inline', reason: p.scenario, scenario: p.scenario, execution: 'inline' };
  if (p.kind === 'origin_identity_pair') return { disposition: 'additional_target_input', reason: 'origin_identity_review_required', execution: 'admission_refusal' };
  if (p.kind === 'host_sni_bypass') {
    const reason = check.check_id === 'nfw.origin_lockdown.safe' ? 'declared_origin_lockdown_required' : 'missing_target_bound_direct_address';
    return { disposition: 'additional_target_input', reason, execution: 'missing_input' };
  }
  if (PENDING_T7_PROBE_KINDS.includes(p.kind) && !executorNameForProbeKind(p.kind)) {
    return { disposition: 'additional_target_input', reason: 't7_probe_module_pending', execution: 'missing_input' };
  }
  if ((check.runnable_requires ?? []).includes('two_perspectives')) return { disposition: 'additional_target_input', reason: 'two_perspectives_required', execution: 'missing_input' };
  if ((check.runnable_requires ?? []).includes('declared_tcp_deny')) return { disposition: 'additional_target_input', reason: 'declared_tcp_deny_required', execution: 'missing_input' };
  if ((check.runnable_requires ?? []).includes('declared_udp_deny')) return { disposition: 'additional_target_input', reason: 'declared_udp_deny_required', execution: 'missing_input' };
  if ((check.runnable_requires ?? []).includes('port_or_declared_tcp_deny') || (check.runnable_requires ?? []).includes('port_or_declared_udp_deny')) {
    return { disposition: 'additional_target_input', reason: 'port_or_declared_deny_required', execution: 'missing_input' };
  }
  if ((check.runnable_requires ?? []).includes('port') && !Number.isInteger(p.default_port) && !Number.isInteger(p.service_port) && !Number.isInteger(p.port)) {
    return { disposition: 'additional_target_input', reason: 'port_required', execution: 'missing_input' };
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

const SPECIALIZED_EVALUATORS = Object.freeze({
  tcp_connect: 'correlateNfwViolation', udp_probe: 'correlateNfwViolation', port_scan_bounded: 'nfwPortResults → correlateNfwViolation',
  reflection_service_probe: 'correlateNfwViolation → correlateReflectorExposure', connection_limit_probe: 'correlateNfwViolation',
  host_sni_bypass: 'correlateOriginLockdownVerdict', rate_limit_canary_probe: 'correlateRateLimitCanary',
  waf_class_marker_probe: 'markerComparisonComplete → correlateChallengeRedirectPenalty → correlateClassMarkerVerdict',
  waf_evasion_marker_probe: 'correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table',
  outside_in_waf_scan: 'markerComparisonComplete → correlateChallengeRedirectPenalty → expected-behavior table',
  waf_method_policy_probe: 'correlateMethodPolicyVerdict (E2 verdict, no readiness)', dns_axfr_leak: 'correlateAxfrVerdict',
});

/** Contract mapping, NOT an executed assertion receipt and never branch-coverage proof. */
export function checkEvaluatorAudit(check) {
  const p = check.probe_profile;
  const disposition = deliveryDisposition(check);
  const custom = p?.assurance_scope === 'custom_canary_rule';
  const inline = p?.kind === 'ops_readiness';
  const executable = disposition.execution === 'socket';
  const specialized = SPECIALIZED_EVALUATORS[p?.kind];
  const evaluator = check.check_id === 'nfw.perspective_allowlist.safe'
    ? 'correlatePerspectiveAllowlist (registered-source override)'
    : custom ? 'setup-required inert-token observation'
      : specialized ?? (inline ? 'correlateOpsReadinessVerdict (local declarations)' : 'correlateObservationOnlyVerdict');
  const verdictCapable = executable && !custom && isVerdictCapableProbeKind(p?.kind);
  const violationOnly = ['tcp_connect', 'udp_probe', 'port_scan_bounded', 'reflection_service_probe', 'connection_limit_probe', 'host_sni_bypass'].includes(p?.kind);
  const conclusions = !verdictCapable ? ['inconclusive'] : violationOnly ? ['exposed', 'inconclusive']
    : ['waf_class_marker_probe', 'waf_method_policy_probe', 'rate_limit_canary_probe', 'dns_axfr_leak'].includes(p?.kind) ? ['protected', 'exposed', 'inconclusive']
      : ['protected', 'exposed', 'edge_protected', 'edge_exposed', 'allowed_as_expected', 'inconclusive'];
  return {
    presentation: checkPresentation(check),
    executor: inline ? 'evaluateOpsReadiness' : executorNameForProbeKind(p?.kind) ?? 'none',
    evaluation_order: ['admission/setup/governance and signed delivery/refusal', 'required-input/evidence-gap guards', 'specialized result-state and attested-I/O guards where applicable', evaluator, 'observation-only/failure/allowlist/expected-behavior fallback as applicable'],
    id_specific_override: check.check_id === 'nfw.perspective_allowlist.safe' ? 'requires two registered perspectives and declared denied source' : p?.entry_path_scenario ?? p?.settings_assertion ?? p?.payload_profile ?? p?.marker_class ?? p?.evasion_transform ?? null,
    parameters: structuredClone(p ?? {}),
    prerequisites: check.prerequisites ?? [],
    required_customer_setup: check.required_customer_setup ?? [],
    expected_behavior: check.default_expected_behavior ?? null,
    safety_bounds: structuredClone(check.safety_constraints),
    evidence_requirements: check.evidence_required ?? [],
    supported_conclusions: inline ? ['protected (local declaration only)', 'inconclusive'] : conclusions,
    conclusion_scope: 'current default disposition; target-dependent declarations may enable violation-only conclusions after admission',
    produces_verdict: verdictCapable,
    readiness_eligible_kind: verdictCapable && evidenceTierForCheck(check) === 'E3',
    capture_support: !executable ? 'no target exchange; admission/refusal or local declaration' : /^(http2|dns|tcp|udp|port_scan|tls|reflection_service|connection_limit)/.test(p.kind) ? 'typed protocol/wire facts; no fabricated HTTP exchange' : 'only recorded bounded transport activity; missing legacy fields remain unavailable',
    test_references: ['tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)', 'tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)', 'tests/unit/check-delivery-branches.test.mjs (only receipted branches)'],
    audit_mapping_is_execution_proof: false,
  };
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
    ...checkEvaluatorAudit(check),
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

export function unreachableBranchReason(row, branch) {
  if (row.kind === 'dns_wire_query' && row.delivery_material?.profile?.dns_transport === 'tcp' && branch === 'wrong_peer') return 'connected_tcp_has_no_datagram_source';
  if (row.kind === 'waf_enforcement_probe' && branch === 'permitted_unhealthy') return 'single_marker_request_has_no_permitted_control';
  return null;
}

export function buildCandidateBranchObligations(inventory) {
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

function unreachableReasonFor(inventory, obligation) {
  const owner = inventory.rows.find((row) => row.delivery_fingerprint === obligation.delivery_fingerprint);
  return unreachableBranchReason(owner, obligation.branch);
}

export function buildDeliveryBranchObligations(inventory) {
  return buildCandidateBranchObligations(inventory).filter((row) => !unreachableReasonFor(inventory, row));
}

export function buildInapplicableBranchObligations(inventory) {
  return buildCandidateBranchObligations(inventory).flatMap((row) => {
    const reason = unreachableReasonFor(inventory, row);
    return reason ? [{ ...row, reason }] : [];
  });
}
export const CHECK_DELIVERY_INVENTORY = buildCheckDeliveryInventory();
CHECK_DELIVERY_INVENTORY.candidate_branch_obligations = buildCandidateBranchObligations(CHECK_DELIVERY_INVENTORY);
CHECK_DELIVERY_INVENTORY.inapplicable_branch_obligations = buildInapplicableBranchObligations(CHECK_DELIVERY_INVENTORY);
CHECK_DELIVERY_INVENTORY.branch_obligations = buildDeliveryBranchObligations(CHECK_DELIVERY_INVENTORY);

export const OWNED_INVALID_TLS_REPLY_HEX = Buffer.from('HTTP/1.1 400 Owned invalid TLS peer\r\n\r\n').toString('hex');
const nonemptyStrings = (items) => Array.isArray(items) && items.length > 0 && items.every((item) => typeof item === 'string' && item.trim());
const hexBytes = (value) => typeof value === 'string' && /^(?:[a-f0-9]{2})+$/i.test(value) ? Buffer.from(value, 'hex') : null;
const loopback = (value) => ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(value);
const timestamp = (value) => typeof value === 'string' && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value ? Date.parse(value) : NaN;

const TCP_ATTEMPT_KINDS = ['tcp_connect', 'port_scan_bounded', 'connection_limit_probe'];

/** Refusal is a client-observed attempt, never fabricated peer-received wire evidence. */
export function validRefusedDeliveryAttempts(receipt) {
  return validUnacceptedDeliveryAttempts(receipt, 'refused');
}

/** A timeout attempt is an actual client connect that never completed against a peer whose accept queue was proven saturated first. */
export function validTimedOutDeliveryAttempts(receipt) {
  return validUnacceptedDeliveryAttempts(receipt, 'timeout');
}

function validUnacceptedDeliveryAttempts(receipt, mode) {
  const attempts = receipt.actual_network_attempts;
  if (!Array.isArray(attempts) || !attempts.length || attempts.length !== receipt.outcome?.probe_requests_sent
    || !['tcp_connect', 'port_scan_bounded', 'connection_limit_probe'].includes(receipt.signed_profile?.kind)) return false;
  if (receipt.runtime_provenance?.scope !== 'owned_loopback' || !['darwin', 'linux', 'win32'].includes(receipt.runtime_provenance.platform)
    || !/^v\d+\.\d+\.\d+/.test(receipt.runtime_provenance.node ?? '')) return false;
  const profile = receipt.signed_profile;
  const target = receipt.signed_target;
  const ports = profile.kind === 'port_scan_bounded' ? profile.ports ?? RISKY_ADMIN_PORTS : [target?.port ?? profile.port ?? profile.default_port ?? profile.service_port];
  const seen = new Set();
  return attempts.every((attempt) => {
    const start = timestamp(attempt.started_at), error = timestamp(attempt.error_at), close = timestamp(attempt.closed_at);
    const route = receipt.transport_routes?.find((entry) => entry.transport === 'tcp' && entry.requested_host === attempt.requested_host && entry.requested_port === attempt.requested_port
      && entry.fixture_host === attempt.fixture_host && entry.fixture_port === attempt.fixture_port && entry.mapping === attempt.mapping);
    const evidence = receipt.branch_peer_evidence ?? [];
    const boundEvent = (event) => event.attempt_id === attempt.attempt_id && event.phase === 'connect' && event.transport === 'tcp'
      && event.fixture_host === attempt.fixture_host && event.fixture_port === attempt.fixture_port;
    const valid = !!attempt.attempt_id && !seen.has(attempt.attempt_id) && attempt.source === 'native_node_net_socket'
      && attempt.transport === 'tcp_connect' && attempt.phase === 'connect' && attempt.accepted === false && !attempt.connected_at
      && (mode === 'refused' ? attempt.error_code === 'ECONNREFUSED' : attempt.error_code !== 'ECONNREFUSED')
      && attempt.job_id === receipt.job_id && attempt.invocation_id === receipt.invocation_id && attempt.target_id === receipt.target_id
      && loopback(attempt.requested_host) && loopback(attempt.fixture_host) && ports?.includes(attempt.requested_port)
      && Number.isInteger(attempt.fixture_port) && attempt.fixture_port > 0 && attempt.fixture_port <= 65535
      && attempt.mapping === (attempt.requested_port === attempt.fixture_port ? 'unchanged' : 'owned_transport_pin_not_production_port_proof')
      && !!route && start >= timestamp(receipt.signed_job?.leased_at) && (mode === 'timeout' || (start <= error && error <= close))
      && start <= close && (mode === 'timeout' || error <= timestamp(receipt.result_body?.safety_attestation?.completed_at))
      && close <= timestamp(receipt.result_body?.safety_attestation?.completed_at) + 1000
      && (mode === 'refused'
        ? evidence.some((event) => boundEvent(event) && event.event === 'connection_refused' && event.error_code === 'ECONNREFUSED' && event.at === attempt.error_at)
        : evidence.some((event) => boundEvent(event) && event.event === 'connect_aborted_without_synack' && event.at === attempt.closed_at && event.error_code === (attempt.error_code ?? null))
          && evidence.some((event) => event.event === 'listen_queue_saturated' && event.transport === 'tcp' && event.fixture_host === attempt.fixture_host
            && event.fixture_port === attempt.fixture_port && event.probe_result === 'syn_ack_withheld' && event.filler_connections >= 1
            && timestamp(event.at) <= start))
      && evidence.some((event) => boundEvent(event) && event.event === 'owned_client_socket_closed' && event.at === attempt.closed_at);
    seen.add(attempt.attempt_id);
    return valid;
  });
}

/** Scenario labels/assertion prose are inventory, not causal evidence. Validate the actual
 * peer action, corresponding transport bytes/status and accepted terminal outcome together.
 * These checks do not create or re-sign evidence and never turn blockers into passes. */
export function validateDeliveryBranchEvidence(receipt, obligation) {
  const errors = [];
  const fail = (reason) => errors.push(`${reason}:${receipt.branch_id}`);
  const evidence = Array.isArray(receipt.branch_peer_evidence) ? receipt.branch_peer_evidence : [];
  const wire = Array.isArray(receipt.actual_wire) ? receipt.actual_wire : [];
  const metadata = receipt.outcome?.metadata ?? {};
  const terminal = receipt.outcome?.external_result;
  const failed = ['error', 'timeout', 'not_run'].includes(terminal);
  const branch = obligation.branch;
  const transportFamilies = {
    tcp: ['tcp_connect', 'reflection_tcp', 'raw_protocol_input', 'tls_session', 'h2_tls_session', 'http', 'https', 'websocket_upgrade', 'slow_header_connection'],
    http: ['http', 'https'], https: ['https'], udp: ['udp'], dns: ['dns_udp', 'dns_tcp'], dns_udp: ['dns_udp'], dns_tcp: ['dns_tcp'],
    grpc: ['h2_stream'], h2: ['h2_stream', 'h2_tls_session', 'h2_client_preface'], websocket: ['websocket_upgrade'], slow_header: ['slow_header_connection'], reflection_tcp: ['reflection_tcp'],
  };
  const dnsKind = ['dns_wire_query', 'dnssec_posture', 'dns_axfr_leak', 'dns_open_recursion', 'dns_failover_posture'].includes(obligation.kind);
  const primaryWire = wire.filter((entry) => dnsKind ? ['dns_udp', 'dns_tcp'].includes(entry.transport) : !['dns_udp', 'dns_tcp'].includes(entry.transport));
  const onWire = (item) => transportFamilies[item.transport]?.some((transport) => primaryWire.some((entry) => entry.transport === transport));
  const has = (event, predicate = () => true) => evidence.some((item) => item.event === event && onWire(item) && predicate(item));
  const validPort = (port) => Number.isInteger(port) && port > 0 && port <= 65535;
  const tupleBound = (item) => loopback(item.local_address) && loopback(item.remote_address) && validPort(item.local_port) && validPort(item.remote_port)
    && item.connection_id === `${item.local_address}:${item.local_port}<-${item.remote_address}:${item.remote_port}`
    && (dnsKind || receipt.transport_routes?.some((route) => loopback(route.fixture_host) && route.fixture_port === item.local_port))
    && primaryWire.some((entry) => entry.connection_id === item.connection_id
      && ['local_address', 'local_port', 'remote_address', 'remote_port'].every((key) => entry[key] === item[key])
      && (!item.method || (entry.method === item.method && (entry.url ?? entry.path) === item.path))
      && (item.request_hex === undefined || item.request_hex === entry.request_hex || item.request_hex === entry.request_body_hex));
  const causalPhase = (item) => {
    const expected = ['dns', 'dns_udp', 'dns_tcp'].includes(item.transport) ? 'dns_query'
      : item.transport === 'udp' ? 'datagram'
        : ['tls_session', 'tls_audit', 'http2_settings', 'http2_frame_probe'].includes(obligation.kind) && item.transport === 'tcp' ? 'tls_handshake' : 'request';
    return item.phase === expected;
  };
  const causal = (event) => evidence.find((item) => item.event === event && onWire(item) && tupleBound(item) && causalPhase(item));
  if (!nonemptyStrings(receipt.branch_assertions) || !evidence.length) fail('branch_assertion_missing');
  const dnsWire = wire.filter((item) => ['dns_udp', 'dns_tcp'].includes(item.transport));
  const dnsResponses = evidence.filter((item) => item.event === 'dns_response_constructed').filter((item) => {
    const bytes = hexBytes(item.response_hex);
    return bytes?.length >= 12 && (bytes.readUInt16BE(2) & 0x8000) !== 0 && (bytes.readUInt16BE(2) & 15) === item.rcode
      && dnsWire.some((query) => query.qtype === item.qtype && query.transaction_id === bytes.readUInt16BE(0)
        && query.transport === item.transport && query.connection_id === item.connection_id && query.request_hex === item.request_hex
        && tupleBound(item) && causalPhase(item)
        && parseDnsResponseStructure(bytes, { expectedQuestion: { name: query.name, qtype: query.qtype, qclass: 1 } }).question_matches === true);
  });
  const httpWire = wire.filter((item) => ['http', 'https'].includes(item.transport));
  const responses = evidence.filter((item) => item.event === 'response_sent').filter((item) => {
    const request = httpWire[item.request_ordinal - 1];
    return request && tupleBound(item) && causalPhase(item) && request.connection_id === item.connection_id
      && ['local_address', 'local_port', 'remote_address', 'remote_port'].every((key) => request[key] === item[key])
      && request.transport === item.transport && request.method === item.method && request.url === item.path
      && loopback(item.local_address) && Number.isInteger(item.local_port)
      && receipt.transport_routes?.some((route) => route.transport === item.transport && route.fixture_port === item.local_port);
  });
  const phase = (name, predicate) => responses.some((item) => item.request_phase === name && predicate(item));
  const denial = (item) => [403, 406, 429].includes(item.status);
  const signedDenial = (item) => denial(item) && item.headers?.['x-waf-block'] === '1';
  const healthy = (item) => item.status >= 200 && item.status < 300;
  if (branch === 'timeout') {
    if (TCP_ATTEMPT_KINDS.includes(obligation.kind)) {
      const silentScan = obligation.kind === 'port_scan_bounded' && terminal === 'blocked' && receipt.outcome?.probe_requests_sent > 0
        && !metadata.open_ports?.length && !metadata.closed_ports?.length && !metadata.rejected_ports?.length
        && metadata.filtered_ports?.length > 0 && metadata.ports_scanned?.every((port) => metadata.filtered_ports.includes(port));
      if ((terminal !== 'timeout' && !silentScan) || !validTimedOutDeliveryAttempts(receipt)
        || !(receipt.outcome?.duration_ms <= receipt.signed_caps?.timeout_ms + hardTimeoutSchedulerToleranceMs(receipt.signed_caps?.timeout_ms))) fail('tcp_syn_timeout_branch_not_observed');
    } else if (terminal !== 'timeout' || !causal('response_withheld')) fail('timeout_branch_not_observed');
  } else if (branch === 'cancel') {
    if (!failed || !has('cancel_requested') || !(has('owned_peer_socket_closed', (item) => item.closure_cause !== 'resolver_timeout') || has('owned_client_socket_closed', (item) => item.closure_cause !== 'resolver_timeout'))
      || !(receipt.outcome?.duration_ms < Math.min(1000, receipt.signed_caps?.timeout_ms))) fail('cancel_branch_not_observed');
    if (['tcp_connect', 'port_scan_bounded', 'connection_limit_probe'].includes(obligation.kind)) {
      const cancellation = evidence.find((item) => item.event === 'cancel_requested' && item.transport === 'tcp' && item.source === 'native_connect_event'
        && item.phase === 'established_connection_before_next_attempt' && item.attempt_id && loopback(item.fixture_host)
        && timestamp(item.at) >= timestamp(receipt.signed_job?.leased_at)
        && timestamp(item.at) <= timestamp(receipt.result_body?.safety_attestation?.completed_at)
        && wire.some((peer) => peer.transport === 'tcp_connect' && peer.fixture_host === item.fixture_host && peer.fixture_port === item.fixture_port && peer.remote_port === item.client_local_port));
      if (!cancellation || !has('owned_client_socket_closed', (item) => item.phase === 'connect' && item.attempt_id === cancellation.attempt_id
        && item.fixture_host === cancellation.fixture_host && item.fixture_port === cancellation.fixture_port && item.closure_cause !== 'resolver_timeout'
        && timestamp(item.at) >= timestamp(cancellation.at)
        && timestamp(item.at) <= timestamp(receipt.result_body?.safety_attestation?.completed_at) + 1000)) fail('cancel_phase_binding_mismatch');
    } else {
      const cancellation = causal('cancel_requested');
      if (!cancellation || !evidence.some((item) => ['owned_peer_socket_closed', 'owned_client_socket_closed'].includes(item.event)
        && item.connection_id === cancellation.connection_id && item.phase === cancellation.phase && item.closure_cause !== 'resolver_timeout' && tupleBound(item)
        && Number.isFinite(cancellation.observed_at_ms) && Number.isFinite(item.observed_at_ms)
        && cancellation.observed_at_ms >= timestamp(receipt.signed_job?.leased_at)
        && cancellation.observed_at_ms <= timestamp(receipt.result_body?.safety_attestation?.completed_at)
        && item.observed_at_ms >= cancellation.observed_at_ms
        && item.observed_at_ms <= timestamp(receipt.result_body?.safety_attestation?.completed_at) + 1000)) fail('cancel_socket_binding_mismatch');
    }
  } else if (branch === 'peer_error') {
    if (!failed || !causal('peer_reset')) fail('peer_error_branch_not_observed');
  } else if (branch === 'peer_refused') {
    const refusedOutcome = obligation.kind === 'tcp_connect' ? metadata.tcp_outcome === 'refused_rst'
      : obligation.kind === 'port_scan_bounded' ? Array.isArray(metadata.closed_ports) && metadata.closed_ports.length > 0 && metadata.open_ports?.length === 0
        : obligation.kind === 'connection_limit_probe' && metadata.accepted_count === 0 && metadata.refused_after === 0;
    if (terminal !== 'blocked' || !refusedOutcome || !validRefusedDeliveryAttempts(receipt)) fail('peer_refused_branch_not_observed');
  } else if (branch === 'invalid_tls') {
    if (!failed || !has('malformed_tls_sent', (item) => tupleBound(item) && causalPhase(item)
      && hexBytes(item.request_hex)?.subarray(0, 2).toString('hex') === '1603'
      && item.response_hex === OWNED_INVALID_TLS_REPLY_HEX)) fail('invalid_tls_branch_not_observed');
  } else if (branch === 'invalid_h2') {
    if (!failed || !has('malformed_h2_sent', (item) => tupleBound(item) && causalPhase(item) && item.transport === 'h2' && item.alpn === 'h2'
      && /^TLSv1\.[23]$/.test(item.tls_protocol ?? '') && hexBytes(item.request_hex)?.subarray(0, 24).toString() === 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' && item.response_hex === '00000104000000000000'
      && loopback(item.local_address) && Number.isInteger(item.local_port)
      && receipt.transport_routes?.some((route) => route.transport === 'h2_tls' && route.fixture_port === item.local_port))) fail('invalid_h2_branch_not_observed');
  } else if (branch === 'negative_dns' || branch === 'nxdomain') {
    const negativeOutcome = obligation.kind === 'dns_open_recursion'
      ? terminal === 'connected' && metadata.same_target_answer_observed === false && metadata.recursion_proof_available === false && metadata.open_recursion_detected === null
      : obligation.kind === 'dns_failover_posture'
        ? terminal === 'connected' && metadata.nameserver_count === 0 && metadata.nameservers?.length === 0 && metadata.nameserver_count_below_two === true && metadata.failover_exercised === false && metadata.weak_failover === null
        : obligation.kind === 'dnssec_posture'
          ? terminal === 'error' && metadata.rcode === 3 && metadata.error_class === 'non_definitive_dns_response' && metadata.protocol_identity_confirmed !== true && metadata.dnskey_present === undefined && metadata.dnssec_configured === undefined
          : metadata.rcode === 3 && terminal === 'connected' && metadata.protocol_identity_confirmed === true;
    if (!dnsResponses.some((item) => item.rcode === 3) || !negativeOutcome) fail('negative_dns_branch_not_observed');
  } else if (branch === 'wrong_peer') {
    if (terminal !== 'timeout' || metadata.protocol_identity_confirmed === true || !dnsResponses.length
      || !has('wrong_peer_response_sent', (item) => tupleBound(item) && causalPhase(item) && item.transport === 'dns_udp' && validPort(item.actual_port)
        && item.expected_port === item.local_port && item.actual_port !== item.expected_port
        && item.response_sender?.local_port === item.actual_port && loopback(item.response_sender.local_address)
        && item.response_sender.remote_address === item.remote_address && item.response_sender.remote_port === item.remote_port
        && item.response_sender.connection_id === `${item.response_sender.local_address}:${item.actual_port}<-${item.remote_address}:${item.remote_port}`
        && dnsWire.some((query) => query.transport === item.transport && query.connection_id === item.connection_id && query.request_hex === item.request_hex)
        && dnsResponses.some((response) => response.connection_id === item.connection_id && response.response_hex === item.response_hex))) fail('wrong_peer_branch_not_observed');
  } else if (branch === 'malformed_response') {
    const malformedDns = dnsResponses.some((item) => parseDnsResponseStructure(hexBytes(item.response_hex)).structure_valid === false);
    const malformedGrpc = has('grpc_response_sent', (item) => { const bytes = hexBytes(item.response_hex); return tupleBound(item) && causalPhase(item) && bytes?.length >= 5 && bytes.readUInt32BE(1) > bytes.length - 5; });
    if (metadata.protocol_identity_confirmed === true || !(malformedDns || malformedGrpc)) fail('malformed_response_branch_not_observed');
  } else if (branch === 'axfr_transfer') {
    if (terminal !== 'connected' || metadata.transfer_complete !== true || metadata.axfr_leak !== true || metadata.protocol_identity_confirmed !== true
      || !dnsResponses.some((item) => item.qtype === 252 && item.rcode === 0 && parseDnsResponseStructure(hexBytes(item.response_hex)).soa_answer_count >= 2)) fail('axfr_transfer_branch_not_observed');
  } else if (branch === 'unimplemented') {
    if (metadata.grpc_status !== '12' || metadata.reflection_service_routed === true || metadata.protocol_identity_confirmed === true
      || !has('grpc_response_sent', (item) => tupleBound(item) && causalPhase(item) && item.grpc_status === '12' && item.response_hex === '')
      || !wire.some((item) => item.transport === 'h2_stream' && item.content_type === 'application/grpc' && !!hexBytes(item.request_body_hex))) fail('unimplemented_branch_not_observed');
  } else if (branch === 'invalid_upgrade') {
    if (metadata.websocket_upgrade_supported === true || !has('invalid_upgrade_sent', (item) => tupleBound(item) && causalPhase(item) && item.accept === 'invalid-owned-peer-accept')
      || !wire.some((item) => item.transport === 'websocket_upgrade' && item.request_headers?.['sec-websocket-key'])) fail('invalid_upgrade_branch_not_observed');
  } else if (branch === 'permitted_unhealthy') {
    if (!phase('permitted', denial) || (metadata.baseline_health ?? metadata.permitted_baseline_health) !== 'unhealthy' || metadata.enforcement !== 'unknown'
      || metadata.comparison_complete !== false || terminal !== 'not_run' || receipt.published_verdict?.verdict !== 'inconclusive') fail('permitted_unhealthy_branch_not_observed');
  } else if (branch === 'variant_allowed') {
    if (!phase('permitted', healthy) || !phase('clean_control', healthy) || !phase('reference', signedDenial) || !phase('transform', healthy)
      || metadata.permitted_baseline_health !== 'healthy' || metadata.comparison_complete !== true
      || metadata.completed_marker_legs !== metadata.planned_marker_legs || metadata.completed_marker_legs !== 2
      || metadata.reference_outcome !== 'blocked' || metadata.transform_outcome !== 'allowed' || metadata.enforcement !== 'partial') fail('variant_allowed_branch_not_observed');
  } else if (branch === 'partial') {
    if (!phase('permitted', healthy) || !phase('reference', signedDenial) || !phase('transform', (item) => item.status === 503 && !item.headers?.['x-waf-block'])
      || metadata.comparison_complete !== false || metadata.transform_outcome !== 'inconclusive'
      || !(metadata.completed_marker_legs < metadata.planned_marker_legs) || terminal !== 'not_run'
      || receipt.published_verdict?.verdict !== 'inconclusive') fail('partial_branch_not_observed');
  } else if (branch === 'unsigned_denial') {
    const denied = responses.filter((item) => ['reference', 'transform'].includes(item.request_phase));
    if (!phase('permitted', healthy) || !denied.length || !denied.every((item) => denial(item) && !item.headers?.['x-waf-block'] && !item.headers?.['cf-mitigated'])
      || (metadata.baseline_health ?? metadata.permitted_baseline_health) !== 'healthy' || metadata.enforcement !== 'unknown'
      || metadata.comparison_complete !== false || terminal !== 'not_run' || receipt.published_verdict?.verdict !== 'inconclusive') fail('unsigned_denial_branch_not_observed');
  } else if (branch === 'payload_bytes' || branch === 'unconfirmed_response') {
    if (obligation.kind === 'reflection_service_probe') {
      try { assertDeliveredReflectorRequest(receipt); } catch { fail('reflector_payload_not_observed'); }
      if (!has('request_received', (item) => tupleBound(item) && causalPhase(item) && typeof item.request_hex === 'string' && wire.some((entry) => entry.connection_id === item.connection_id && entry.payload_profile === receipt.signed_profile?.payload_profile && entry.request_hex === item.request_hex))) fail('reflector_peer_request_not_observed');
    }
    if (branch === 'unconfirmed_response' && (metadata.protocol_identity_confirmed === true || metadata.reflector_confirmed === true
      || terminal === 'blocked' || !causal('request_received') || !wire.some((item) => ['udp', 'reflection_tcp'].includes(item.transport)))) fail('unconfirmed_response_branch_not_observed');
  } else fail('unknown_branch_scenario');
  const att = receipt.result_body?.safety_attestation;
  if (!att || !(att.duration_ms <= receipt.signed_caps?.timeout_ms + hardTimeoutSchedulerToleranceMs(receipt.signed_caps?.timeout_ms))
    || att.total_operations > receipt.signed_caps?.max_total_operations) fail('branch_signed_budget_mismatch');
  if (!Number.isInteger(receipt.readiness?.coverage?.passed_count) || receipt.readiness.coverage.passed_count < 0) fail('branch_readiness_missing');
  if (receipt.readiness?.coverage?.passed_count > 0 && !['payload_bytes', 'axfr_transfer'].includes(branch)) fail('negative_branch_readiness_credit');
  return errors;
}

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
    if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) { errors.push('invalid_delivery_receipt'); continue; }
    const beforeErrors = errors.length;
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
        if (job.id !== receipt.job_id || job.target_id !== receipt.target_id || job.test_run_id !== receipt.run_id || job.tenant_id !== receipt.tenant_id || job.check_id !== row.check_id || job.nonce_hash !== receipt.nonce_hash || job.job_signature !== receipt.job_signature || event.id !== receipt.event_id || event.tenant_id !== receipt.tenant_id || event.test_run_id !== receipt.run_id || event.check_id !== row.check_id || event.target_id !== job.target_id || event.nonce_hash !== job.nonce_hash || event.metadata?.probe_job_id !== job.id || verdict.id !== receipt.verdict_id || verdict.tenant_id !== receipt.tenant_id || verdict.test_run_id !== receipt.run_id || verdict.check_id !== row.check_id || verdict.target_id !== job.target_id || !verdict.evidence_ids?.includes(event.id)) errors.push(`accepted_binding_mismatch:${row.check_id}`);
        const digest = probeExecutionEvidenceReceipt(job, event.metadata?.probe_worker_id, receipt.result_body.safety_attestation, receipt.outcome?.external_result).digest;
        if (digest !== receipt.execution_receipt.digest || digest !== event.metadata?.execution_receipt?.digest) errors.push(`accepted_custody_mismatch:${row.check_id}`);
        if (receipt.result_body.external_result !== receipt.outcome?.external_result || event.metadata?.external_result !== receipt.outcome?.external_result
          || canonicalJsonStringify(event.metadata?.safety_attestation) !== canonicalJsonStringify(receipt.result_body.safety_attestation)
          || ['duration_ms', 'probe_requests_sent', 'destination_resolver_attempts', 'total_operations'].some((key) => receipt.outcome?.[key] !== receipt.result_body.safety_attestation[key])) errors.push(`accepted_outcome_mismatch:${row.check_id}`);
        // Accepted metadata is the production redacted projection, not every raw fixture detail.
        const projectedMetadata = sanitizeProbeMetadata(receipt.outcome?.metadata ?? {});
        for (const key of ['rcode', 'protocol_identity_confirmed', 'transfer_complete', 'axfr_leak', 'grpc_status', 'reflection_service_routed', 'websocket_upgrade_supported',
          'comparison_complete', 'permitted_baseline_health', 'baseline_health', 'reference_outcome', 'transform_outcome', 'enforcement',
          'planned_marker_legs', 'completed_marker_legs', 'classifier_version', 'grading_version', 'same_target_answer_observed', 'recursion_proof_available',
          'open_recursion_detected', 'nameserver_count', 'nameservers', 'nameserver_count_below_two', 'failover_exercised', 'weak_failover', 'error_class',
          'tcp_outcome', 'closed_ports', 'open_ports', 'accepted_count', 'refused_after']) {
          if (canonicalJsonStringify(receipt.result_body.metadata?.[key]) !== canonicalJsonStringify(projectedMetadata[key])
            || canonicalJsonStringify(event.metadata?.[key]) !== canonicalJsonStringify(projectedMetadata[key])) errors.push(`accepted_branch_metadata_mismatch:${row.check_id}:${key}`);
        }
        if (canonicalJsonStringify(job.constraints) !== canonicalJsonStringify(receipt.signed_caps) || canonicalJsonStringify(job.probe_profile) !== canonicalJsonStringify(receipt.signed_profile) || canonicalJsonStringify(job.target) !== canonicalJsonStringify(receipt.signed_target)) errors.push(`signed_delivery_mismatch:${row.check_id}`);
      }
    }
    if (row.execution === 'socket') {
      if (receipt.confidence !== 'external_only' || receipt.published_verdict?.confidence !== 'external_only') errors.push(`external_confidence_missing:${row.check_id}`);
      const dnsKind = ['dns_wire_query', 'dnssec_posture', 'dns_axfr_leak', 'dns_open_recursion', 'dns_failover_posture', 'dns_resolve'].includes(row.kind);
      const actualWire = Array.isArray(receipt.actual_wire) ? receipt.actual_wire : [];
      const refused = receipt.branch_id && ((byBranch.get(receipt.branch_id)?.branch === 'peer_refused' && validRefusedDeliveryAttempts(receipt))
        || (byBranch.get(receipt.branch_id)?.branch === 'timeout' && validTimedOutDeliveryAttempts(receipt)));
      if (!actualWire.some((wire) => dnsKind ? ['dns_udp', 'dns_tcp'].includes(wire.transport) : !['dns_udp', 'dns_tcp'].includes(wire.transport)) && !refused) errors.push(`actual_probe_wire_missing:${row.check_id}`);
      if (receipt.actual_network_attempts?.length && !refused) errors.push(`unbound_network_attempt:${row.check_id}`);
    } else if (receipt.actual_wire?.length) errors.push(`unexpected_no_execution_wire:${row.check_id}`);
    if (['none', 'admission_refusal'].includes(row.execution) && receipt.admission?.error !== row.reason) errors.push(`admission_reason_mismatch:${row.check_id}`);
    if (['metadata', 'worker_refusal'].includes(row.execution) && ((receipt.outcome?.metadata?.inconclusive_reason ?? receipt.outcome?.metadata?.not_run_reason) !== row.reason || receipt.outcome?.total_operations !== 0)) errors.push(`worker_refusal_mismatch:${row.check_id}`);
    if (row.execution === 'inline' && (!receipt.run_id || !receipt.accepted_event || !receipt.published_verdict || receipt.accepted_event.metadata?.scenario !== (row.scenario ?? row.reason))) errors.push(`inline_governance_missing:${row.check_id}`);
    if (seenInvocations.has(receipt.invocation_id)) errors.push(`duplicate_actual_invocation:${receipt.invocation_id}`);
    seenInvocations.add(receipt.invocation_id);
    if (receipt.branch_id) {
      const obligation = byBranch.get(receipt.branch_id);
      if (!obligation || obligation.check_id !== row.check_id || obligation.delivery_fingerprint !== receipt.delivery_fingerprint) errors.push(`unknown_branch_binding:${receipt.branch_id}`);
      if (seenBranches.has(receipt.branch_id)) errors.push(`duplicate_branch_invocation:${receipt.branch_id}`);
      if (obligation) errors.push(...validateDeliveryBranchEvidence(receipt, obligation));
      if (errors.length === beforeErrors) seenBranches.add(receipt.branch_id);
    } else {
      if (receipt.branch_assertions || receipt.branch_peer_evidence || receipt.actual_network_attempts?.length) errors.push(`branch_identity_missing:${row.check_id}`);
      if (seen.has(row.check_id)) errors.push(`duplicate_definition_invocation:${row.check_id}`);
      if (errors.length === beforeErrors) seen.add(row.check_id);
    }
  }
  const gaps = inventory.rows.filter((row) => !seen.has(row.check_id)).map((row) => ({ check_id: row.check_id, disposition: row.disposition, reason: 'definition_invocation_missing' }));
  const branch_gaps = definitionsOnly ? [] : obligations.filter((row) => !seenBranches.has(row.branch_id)).map((row) => ({ ...row, reason: 'required_branch_invocation_missing' }));
  return { complete: gaps.length === 0 && branch_gaps.length === 0 && errors.length === 0, invoked_definitions: seen.size, invoked_branches: seenBranches.size, errors, gaps, branch_gaps, receipts };
}
