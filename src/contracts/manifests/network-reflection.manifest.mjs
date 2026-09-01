/**
 * Wave 4 manifest — network / reflection / DNS-application E0 closure (ticket W4-NET).
 *
 * PROPOSES additions consumed by the integration worker. It edits nothing itself.
 * Every one of the 70 owned catalog vectors (NET 46 + REFLECT/AMP 17 + DNS-APP 7)
 * leaves E0 for E3 (safe protocol-correct reflector / bounded DNS wire query),
 * E4 (governed scenario family — never a flood generator), or E1 (posture).
 *
 * New payload builders live in src/lib/vectorProbes/extraReflectorPayloads.mjs.
 */

export const PROPOSED_PROBE_KINDS = Object.freeze([]);

export const PROPOSED_PROFILE_FIELDS = Object.freeze([]);

/**
 * New reflector payload profile ids to append to ALLOWED_PAYLOAD_PROFILES in
 * src/contracts/checks.mjs. Each is implemented in extraReflectorPayloads.mjs as
 * one minimal, protocol-correct, <=512B request with no amplification-maximising
 * parameter and no repeat/count/concurrency knob.
 */
export const PROPOSED_PAYLOAD_PROFILES = Object.freeze([
  { payload_profile: 'slp_srvrqst', transport: 'udp', default_port: 427, sends: 'One SLPv2 Service Request for service:service-agent (RFC 2608).' },
  { payload_profile: 'tp240_status_request', transport: 'udp', default_port: 10074, sends: 'One benign 4-byte tp240dvr status/counter word — deliberately NOT the start-blast command.' },
  { payload_profile: 'l2tp_sccrq', transport: 'udp', default_port: 1701, sends: 'One L2TP Start-Control-Connection-Request control message (RFC 2661).' },
  { payload_profile: 'natpmp_external_address', transport: 'udp', default_port: 5351, sends: 'One 2-byte NAT-PMP public-address request (version 0, opcode 0).' },
  { payload_profile: 'ipp_get_printer_attributes', transport: 'tcp', default_port: 631, sends: 'One read-only IPP Get-Printer-Attributes request over HTTP; printer-uri is localhost so it cannot fan out to a third party.' },
]);

export const PROPOSED_CHECKS = Object.freeze([
  Object.freeze({
    check_id: 'reflect.slp_amplification_exposure.safe',
    version: '1.0.0',
    name: 'SLP Amplification Exposure (Safe)',
    vector_family: 'reflection',
    description: 'One bounded UDP Service Location Protocol request on the declared host documents open-SLP reflector exposure via response size class and amplification-ratio metadata.',
    required_agent_modes: ['packet', 'heartbeat'],
    supported_targets: ['fqdn', 'ip'],
    required_customer_setup: ['declared_slp_responder_host'],
    evidence_required: ['probe_result', 'agent_observation'],
    verdict_logic: 'An unexpected amplifying SLP response from the declared host raises a reflector-exposure finding; Internet-facing hosts must not run open SLP.',
    probe_profile: { kind: 'reflection_service_probe', max_requests: 1, timeout_ms: 3000, service_port: 427, payload_profile: 'slp_srvrqst', expected_response_shape: 'amplifying_response' },
    safety_constraints: { max_events: 3, max_duration_seconds: 60, max_concurrent_runs_per_target_group: 1 },
    default_expected_behavior: 'must_block_before_origin',
    probe_simulation_profile: 'external_blocked',
  }),
  Object.freeze({
    check_id: 'reflect.tp240_amplification_exposure.safe',
    version: '1.0.0',
    name: 'TP240 PhoneHome Amplification Exposure (Safe)',
    vector_family: 'reflection',
    description: 'One bounded UDP status request to the declared Mitel MiCollab tp240dvr port documents reflector exposure by response size class only; the request is never the start-blast amplification command.',
    required_agent_modes: ['packet', 'heartbeat'],
    supported_targets: ['fqdn', 'ip'],
    required_customer_setup: ['declared_tp240_responder_host'],
    evidence_required: ['probe_result', 'agent_observation'],
    verdict_logic: 'Any tp240dvr response on an Internet-facing host raises a reflector-exposure finding (CVE-2022-26143 class); the driver test port must not be exposed.',
    probe_profile: { kind: 'reflection_service_probe', max_requests: 1, timeout_ms: 3000, service_port: 10074, payload_profile: 'tp240_status_request', expected_response_shape: 'amplifying_response' },
    safety_constraints: { max_events: 3, max_duration_seconds: 60, max_concurrent_runs_per_target_group: 1 },
    default_expected_behavior: 'must_block_before_origin',
    probe_simulation_profile: 'external_blocked',
  }),
  Object.freeze({
    check_id: 'reflect.l2tp_reflection_exposure.safe',
    version: '1.0.0',
    name: 'L2TP Reflection Exposure (Safe)',
    vector_family: 'reflection',
    description: 'One bounded L2TP Start-Control-Connection-Request on the declared host documents reflector exposure via response size class metadata.',
    required_agent_modes: ['packet', 'heartbeat'],
    supported_targets: ['fqdn', 'ip'],
    required_customer_setup: ['declared_l2tp_responder_host'],
    evidence_required: ['probe_result', 'agent_observation'],
    verdict_logic: 'An unexpected L2TP control-response from the declared host raises a reflector-exposure finding; Internet-facing L2TP control ports must be filtered.',
    probe_profile: { kind: 'reflection_service_probe', max_requests: 1, timeout_ms: 3000, service_port: 1701, payload_profile: 'l2tp_sccrq', expected_response_shape: 'amplifying_response' },
    safety_constraints: { max_events: 3, max_duration_seconds: 60, max_concurrent_runs_per_target_group: 1 },
    default_expected_behavior: 'must_block_before_origin',
    probe_simulation_profile: 'external_blocked',
  }),
  Object.freeze({
    check_id: 'reflect.natpmp_amplification_exposure.safe',
    version: '1.0.0',
    name: 'NAT-PMP Amplification Exposure (Safe)',
    vector_family: 'reflection',
    description: 'One bounded NAT-PMP public-address request on the declared host documents open-gateway reflector exposure via response size class and amplification-ratio metadata.',
    required_agent_modes: ['packet', 'heartbeat'],
    supported_targets: ['fqdn', 'ip'],
    required_customer_setup: ['declared_natpmp_responder_host'],
    evidence_required: ['probe_result', 'agent_observation'],
    verdict_logic: 'A NAT-PMP response on an Internet-facing (WAN) interface raises a reflector-exposure finding; NAT-PMP must be answered only on the LAN side.',
    probe_profile: { kind: 'reflection_service_probe', max_requests: 1, timeout_ms: 3000, service_port: 5351, payload_profile: 'natpmp_external_address', expected_response_shape: 'amplifying_response' },
    safety_constraints: { max_events: 3, max_duration_seconds: 60, max_concurrent_runs_per_target_group: 1 },
    default_expected_behavior: 'must_block_before_origin',
    probe_simulation_profile: 'external_blocked',
  }),
  Object.freeze({
    check_id: 'reflect.ipp_callback_exposure.safe',
    version: '1.0.0',
    name: 'CUPS/IPP Reflector Exposure (Safe)',
    vector_family: 'reflection',
    description: 'One bounded read-only IPP Get-Printer-Attributes request on the declared host documents exposed CUPS/IPP; the request carries no callback URL, so it cannot trigger callback fan-out to a third party.',
    required_agent_modes: ['packet', 'heartbeat'],
    supported_targets: ['fqdn', 'ip'],
    required_customer_setup: ['declared_ipp_responder_host'],
    evidence_required: ['probe_result', 'agent_observation'],
    verdict_logic: 'An IPP attribute response on an Internet-facing host raises a reflector-exposure finding (CVE-2024-47176 class); CUPS/IPP must not be reachable from the Internet.',
    probe_profile: { kind: 'reflection_service_probe', max_requests: 1, timeout_ms: 3000, service_port: 631, payload_profile: 'ipp_get_printer_attributes', expected_response_shape: 'service_banner' },
    safety_constraints: { max_events: 3, max_duration_seconds: 60, max_concurrent_runs_per_target_group: 1 },
    default_expected_behavior: 'must_block_before_origin',
    probe_simulation_profile: 'external_blocked',
  }),
  Object.freeze({
    check_id: 'dns.multi_question_oversized.safe',
    version: '1.0.0',
    name: 'DNS Multi-Question / Oversized Parser Posture (Safe)',
    vector_family: 'dns',
    description: 'One bounded direct DNS wire query on the declared zone documents multi-question/oversized-message parser handling; a single query, never a query flood.',
    required_agent_modes: ['heartbeat'],
    supported_targets: ['fqdn', 'dns'],
    required_customer_setup: ['declared_zone_for_parser_posture'],
    evidence_required: ['probe_result'],
    verdict_logic: 'One labeled bounded DNS wire query observes how the resolver handles an unusual (multi-question/oversized) message; permissive handling raises a readiness finding.',
    probe_profile: { kind: 'dns_wire_query', max_requests: 1, timeout_ms: 5000, dns_qtype: 'NS', dns_transport: 'tcp' },
    safety_constraints: { max_events: 3, max_duration_seconds: 60, max_concurrent_runs_per_target_group: 1 },
    default_expected_behavior: 'must_block_before_origin',
    probe_simulation_profile: 'external_blocked',
  }),
]);

/** E3 wiring — attach the new safe checks to the registry entries that own each catalog vector. */
export const PROPOSED_REGISTRY_MAPPING = Object.freeze([
  { registry_id: 'ATT-086', catalog_vector_ids: ['AMP-029'], add_check_ids: ['reflect.slp_amplification_exposure.safe'], target_tier: 'E3' },
  { registry_id: 'ATT-089', catalog_vector_ids: ['AMP-046'], add_check_ids: ['reflect.tp240_amplification_exposure.safe'], target_tier: 'E3' },
  { registry_id: 'ATT-087', catalog_vector_ids: ['AMP-032'], add_check_ids: ['reflect.l2tp_reflection_exposure.safe'], target_tier: 'E3' },
  { registry_id: 'ATT-181', catalog_vector_ids: ['AMP-058'], add_check_ids: ['reflect.natpmp_amplification_exposure.safe'], target_tier: 'E3' },
  { registry_id: 'ATT-180', catalog_vector_ids: ['AMP-057'], add_check_ids: ['reflect.ipp_callback_exposure.safe'], target_tier: 'E3' },
  { registry_id: 'ATT-187', catalog_vector_ids: ['APP-168', 'APP-169'], add_check_ids: ['dns.multi_question_oversized.safe'], target_tier: 'E3' },
]);

/**
 * E4 governed reclassifications — every remaining owned registry entry maps to a
 * governed scenario family (see GOVERNED_SCENARIO_FAMILIES). None of these builds
 * a traffic generator; the fact can only be established by SOC-governed scaled traffic.
 */
export const PROPOSED_TIER_RECLASSIFICATION = Object.freeze([
  // --- NET: malformed-packet, control-plane, and service floods (46 catalog vectors) ---
  { registry_id: 'ATT-028', catalog_vector_ids: ['NET-004', 'NET-005', 'NET-006'], target_tier: 'E4', governed_scenario_family: 'packet_processing_flood', reason: 'IP-protocol and empty-payload packet floods require a governed raw-IP packet generator; no safe outside-in proof.' },
  { registry_id: 'ATT-029', catalog_vector_ids: ['NET-020', 'NET-021', 'NET-022'], target_tier: 'E4', governed_scenario_family: 'icmp_flood', reason: 'ICMP control-message abuse is only established by governed ICMP generation plus edge/agent telemetry.' },
  { registry_id: 'ATT-030', catalog_vector_ids: ['NET-025', 'NET-109', 'NET-110', 'NET-111', 'NET-112'], target_tier: 'E4', governed_scenario_family: 'packet_processing_flood', reason: 'IPv6 extension-header and routing-header abuse needs an isolated-lab packet suite.' },
  { registry_id: 'ATT-031', catalog_vector_ids: ['NET-027'], target_tier: 'E4', governed_scenario_family: 'packet_processing_flood', reason: 'IPv6 atomic-fragment abuse needs an isolated-lab fragment parser test.' },
  { registry_id: 'ATT-032', catalog_vector_ids: ['NET-035'], target_tier: 'E4', governed_scenario_family: 'packet_processing_flood', reason: 'IPv6 neighbor-cache destination-scan exhaustion needs bounded off-link scans plus router neighbor-table telemetry.' },
  { registry_id: 'ATT-033', catalog_vector_ids: ['NET-040', 'NET-041'], target_tier: 'E4', governed_scenario_family: 'packet_processing_flood', reason: 'TTL-expiry and unroutable-destination control-plane floods need governed packets plus control-plane CPU telemetry.' },
  { registry_id: 'ATT-034', catalog_vector_ids: ['NET-055'], target_tier: 'E4', governed_scenario_family: 'udp_flood', reason: 'UDP application packet-loop needs a lab-only pair of declared services to prove a bounded protocol loop.' },
  { registry_id: 'ATT-035', catalog_vector_ids: ['NET-069', 'NET-071', 'NET-115', 'NET-116', 'NET-117', 'NET-146'], target_tier: 'E4', governed_scenario_family: 'packet_processing_flood', reason: 'Malformed TCP checksum/length/option/window floods need an isolated-lab TCP segment builder.' },
  { registry_id: 'ATT-036', catalog_vector_ids: ['NET-074'], target_tier: 'E4', governed_scenario_family: 'syn_flood', reason: 'DCCP request flood needs a governed DCCP request client against a declared endpoint.' },
  { registry_id: 'ATT-037', catalog_vector_ids: ['NET-080'], target_tier: 'E4', governed_scenario_family: 'tls_handshake_exhaustion', reason: 'TLS record-fragmentation exhaustion needs a governed fragmenting TLS record client with CPU telemetry.' },
  { registry_id: 'ATT-038', catalog_vector_ids: ['NET-083'], target_tier: 'E4', governed_scenario_family: 'app_connection_exhaustion', reason: 'L2TP control-session exhaustion needs a governed L2TP control-session flood (reflection exposure covered E3 at AMP-032).' },
  { registry_id: 'ATT-039', catalog_vector_ids: ['NET-088'], target_tier: 'E4', governed_scenario_family: 'tcp_connection_flood', reason: 'SNAT ephemeral-port exhaustion needs governed connection scenarios correlated with SNAT-table telemetry.' },
  { registry_id: 'ATT-040', catalog_vector_ids: ['NET-098', 'NET-099'], target_tier: 'E4', governed_scenario_family: 'icmp_flood', reason: 'Malformed ICMP floods need an isolated-lab ICMP frame builder.' },
  { registry_id: 'ATT-076', catalog_vector_ids: ['NET-101', 'NET-102', 'NET-103', 'NET-104', 'NET-164'], target_tier: 'E4', governed_scenario_family: 'packet_processing_flood', reason: 'Malformed IPv4 header floods need an isolated-lab IPv4 header builder.' },
  { registry_id: 'ATT-077', catalog_vector_ids: ['NET-106', 'NET-107', 'NET-108', 'NET-113', 'NET-114'], target_tier: 'E4', governed_scenario_family: 'packet_processing_flood', reason: 'Malformed IPv6 packet floods need an isolated-lab IPv6 packet builder.' },
  { registry_id: 'ATT-078', catalog_vector_ids: ['NET-122', 'NET-123'], target_tier: 'E4', governed_scenario_family: 'udp_flood', reason: 'Malformed UDP packet floods need an isolated-lab UDP packet builder.' },
  { registry_id: 'ATT-079', catalog_vector_ids: ['NET-124'], target_tier: 'E4', governed_scenario_family: 'packet_processing_flood', reason: 'Malformed SCTP packet flood needs an isolated-lab SCTP builder with invalid CRC32c.' },
  { registry_id: 'ATT-080', catalog_vector_ids: ['NET-126'], target_tier: 'E4', governed_scenario_family: 'udp_flood', reason: 'Legacy AFS service flood needs a governed AFS service-specific client against a declared endpoint.' },
  { registry_id: 'ATT-081', catalog_vector_ids: ['NET-127'], target_tier: 'E4', governed_scenario_family: 'udp_flood', reason: 'Advanced device-discovery (ADDP) service flood needs a governed ADDP request generator.' },
  { registry_id: 'ATT-082', catalog_vector_ids: ['NET-139'], target_tier: 'E4', governed_scenario_family: 'udp_flood', reason: 'Direct NAT-PMP request flood needs a governed request generator; single-request reflector exposure is covered E3 at AMP-058.' },
  { registry_id: 'ATT-083', catalog_vector_ids: ['NET-141'], target_tier: 'E4', governed_scenario_family: 'udp_flood', reason: 'Direct Sentinel license-service flood needs a governed Sentinel license-protocol client.' },
  { registry_id: 'ATT-084', catalog_vector_ids: ['NET-143'], target_tier: 'E4', governed_scenario_family: 'packet_processing_flood', reason: 'No-listener/service-miss flood needs governed packets to declared closed ports plus firewall/host-lookup telemetry.' },

  // --- REFLECT/AMP: reflection/amplification without a safe single-request exposure (12 catalog vectors) ---
  { registry_id: 'ATT-085', catalog_vector_ids: ['AMP-022'], target_tier: 'E4', governed_scenario_family: 'udp_flood', reason: 'Kad P2P reflection is spoofed-source DRDoS delivered via udp_flood; no scoped safe Kad DHT exposure request.' },
  { registry_id: 'ATT-088', catalog_vector_ids: ['AMP-045'], target_tier: 'E4', governed_scenario_family: 'udp_flood', reason: 'Sentinel license-server reflection is spoofed-source; discovery-request exposure not scoped in this ticket.' },
  { registry_id: 'ATT-177', catalog_vector_ids: ['AMP-048'], target_tier: 'E4', governed_scenario_family: 'syn_flood', reason: 'TCP SYN-ACK reflection is spoofed-source amplification; exposure needs provider/agent evidence, not a safe single request.' },
  { registry_id: 'ATT-178', catalog_vector_ids: ['AMP-051'], target_tier: 'E4', governed_scenario_family: 'udp_flood', reason: 'Cross-protocol UDP loop needs a lab-only pair of declared services to prove a bounded loop.' },
  { registry_id: 'ATT-179', catalog_vector_ids: ['AMP-055'], target_tier: 'E4', governed_scenario_family: 'udp_flood', reason: 'VxWorks WDBRPC reflection is spoofed-source; WDBRPC request exposure not scoped in this ticket.' },
  { registry_id: 'ATT-182', catalog_vector_ids: ['AMP-061'], target_tier: 'E4', governed_scenario_family: 'udp_flood', reason: 'Gateway-discovery reflection is spoofed-source; request-shape exposure not scoped in this ticket.' },
  { registry_id: 'ATT-183', catalog_vector_ids: ['AMP-067', 'AMP-068', 'AMP-069'], target_tier: 'E4', governed_scenario_family: 'dns_query_flood', reason: 'TsuKing DNS retry/chain/loop amplification needs a controlled multi-resolver topology and pulse-amplification telemetry.' },
  { registry_id: 'ATT-184', catalog_vector_ids: ['AMP-072'], target_tier: 'E4', governed_scenario_family: 'http_get_flood', reason: 'HTTP callback/fan-out reflection needs a declared callback canary that proves server-side fan-out.' },
  { registry_id: 'ATT-185', catalog_vector_ids: ['AMP-074'], target_tier: 'E4', governed_scenario_family: 'udp_flood', reason: 'fastd VPN reconnect amplification is spoofed-source; handshake exposure not scoped in this ticket.' },
  { registry_id: 'ATT-186', catalog_vector_ids: ['AMP-075'], target_tier: 'E4', governed_scenario_family: 'udp_flood', reason: 'Attacker-controlled UDP callback reflection needs a declared callback canary and acknowledgement workflow.' },

  // --- DNS-APP: DNS-application exhaustion requiring scaled traffic or a stream client (5 catalog vectors) ---
  { registry_id: 'ATT-188', catalog_vector_ids: ['APP-104', 'APP-105', 'APP-171'], target_tier: 'E4', governed_scenario_family: 'dns_query_flood', reason: 'DNSSEC validation/signing exhaustion needs scaled bounded DNSSEC queries plus resolver and authoritative CPU telemetry.' },
  { registry_id: 'ATT-189', catalog_vector_ids: ['APP-172', 'APP-173'], target_tier: 'E4', governed_scenario_family: 'dns_query_flood', reason: 'Encrypted DoQ/DoH3 stream exhaustion needs a bounded DoQ/DoH3 client; dns_wire_query is plain UDP/TCP only.' },
]);
