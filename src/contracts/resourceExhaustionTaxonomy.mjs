/**
 * Resource-exhaustion DDoS taxonomy — classifies attacks by what they exhaust,
 * not just protocol layer. Validated against CHECK_CATALOG via
 * scripts/validate-resource-exhaustion-taxonomy.mjs
 */

import { registerReadinessCheckCatalog } from '../lib/readinessVerdicts.mjs';
import {
  evidenceTierForCheck,
  evidenceTierForTaxonomyCheckIds,
} from '../lib/probeEvidenceTiers.mjs';

/** @typedef {'volumetric'|'packet_processing'|'state_exhaustion'|'application_l7'|'computational'|'memory_exhaustion'|'backend_exhaustion'|'dns_exhaustion'|'reflection'|'amplification'|'exploit_dos'|'delivery_pattern'|'integrity_attack'|'access_control'|'data_exposure'|'automation_abuse'|'ai_agentic'} ExhaustedResource */

/** @typedef {'implemented'|'partial'|'soc_only'|'pending'} CoverageStatus */

export const COVERAGE_STATUS_SEMANTICS = Object.freeze({
  implemented: 'A live semantic probe or inline validator establishes the mapped check evidence model.',
  partial: 'Only metadata, transport/liveness, posture, or otherwise incomplete semantic evidence is implemented.',
  soc_only: 'Coverage exists only through SOC-gated governed execution; no customer-runnable safe check is mapped.',
  pending: 'No mapped implementation exists yet.',
});

export const ATTACK_SURFACE_DOMAINS = Object.freeze([
  { id: 'A1a', label: 'IP / Transport Packet Processing', probe_reachable: true, note: 'Partially reachable; some vectors require a governed packet-generation tier.' },
  { id: 'A1b', label: 'LAN / Routing Control Plane', probe_reachable: false, note: 'Requires L2 adjacency or a routing peer session.' },
  { id: 'A1c', label: 'Wireless / RF', probe_reachable: false, note: 'Requires RF proximity.' },
  { id: 'A1d', label: 'Mobile / Telecom Signalling', probe_reachable: false, note: 'Requires a mobile-core interface.' },
  { id: 'A2', label: 'Reflection & Amplification Exposure', probe_reachable: true, note: 'Reachable with bounded protocol-correct requests to declared services.' },
  { id: 'A3', label: 'DNS Service Exhaustion', probe_reachable: true, note: 'Reachable with bounded direct DNS wire queries.' },
  { id: 'A4a', label: 'HTTP / API Application Exhaustion', probe_reachable: true, note: 'Reachable on customer-declared HTTP and API paths.' },
  { id: 'A4b', label: 'Non-HTTP Application Services', probe_reachable: true, note: 'Reachable where a bounded service-specific client exists.' },
  { id: 'A5', label: 'Protocol Machinery (H2/H3/QUIC/WS/gRPC/TLS)', probe_reachable: true, note: 'Reachable with bounded protocol- and frame-level clients.' },
  { id: 'A7', label: 'Web Application Attack Classes', probe_reachable: true, note: 'Safe markers are outside-in reachable; offensive suites remain SOC-governed.' },
  { id: 'A8', label: 'Evasion & Delivery Patterns', probe_reachable: true, note: 'Cross-cutting behavior and delivery-pattern evidence.' },
]);

/**
 * Governed delivery-pattern labels (DET-022). Declared on registry entries whose
 * attack class is primarily a delivery pattern and surfaced on checks and
 * high-scale requests via `delivery_patterns[]`.
 */
export const DELIVERY_PATTERN_LABELS = Object.freeze([
  'direct',
  'spoofed',
  'drdos',
  'coordinated_swarm',
  'carpet_bombing',
  'pulse_wave',
  'multi_vector',
  'application_aware',
  'ransom',
  'multi_destination',
  'adaptive_evasion',
  'residential_proxy',
  'api_scraping',
  'recovery_drill',
  'rate_limit_evasion',
]);

/**
 * @typedef {Object} AttackVectorEntry
 * @property {string} id
 * @property {string} name
 * @property {ExhaustedResource} exhausted_resource
 * @property {CoverageStatus} coverage_status
 * @property {string} task_id
 * @property {string[]} [check_ids]
 * @property {string[]} [delivery_patterns]
 * @property {string} [notes]
 */

export const EXHAUSTED_RESOURCE_FAMILIES = Object.freeze([
  { id: 'volumetric', label: 'Volumetric', metric: 'Gbps/Tbps', layer: 'L3/L4', scored_for_ddos_readiness: true },
  { id: 'packet_processing', label: 'Packet-processing', metric: 'Mpps/Bpps', layer: 'L3/L4', scored_for_ddos_readiness: true },
  { id: 'state_exhaustion', label: 'State exhaustion', metric: 'CPS / concurrent states', layer: 'L3/L4/L7', scored_for_ddos_readiness: true },
  { id: 'application_l7', label: 'Application L7', metric: 'RPS', layer: 'L7', scored_for_ddos_readiness: true },
  { id: 'computational', label: 'Computational', metric: 'CPU %, RPS', layer: 'L7/TLS', scored_for_ddos_readiness: true },
  { id: 'memory_exhaustion', label: 'Memory exhaustion', metric: 'connections/streams', layer: 'L7/TLS', scored_for_ddos_readiness: true },
  { id: 'backend_exhaustion', label: 'Backend exhaustion', metric: 'queries/sec', layer: 'L7/app', scored_for_ddos_readiness: true },
  { id: 'dns_exhaustion', label: 'DNS exhaustion', metric: 'QPS', layer: 'DNS', scored_for_ddos_readiness: true },
  { id: 'reflection', label: 'Reflection', metric: 'pps/bps', layer: 'L3/L4', scored_for_ddos_readiness: true },
  { id: 'amplification', label: 'Amplification', metric: 'amplification ratio', layer: 'L3/L4/DNS', scored_for_ddos_readiness: true },
  { id: 'exploit_dos', label: 'Exploit-based DoS', metric: 'varies', layer: 'L3/L7', scored_for_ddos_readiness: true },
  { id: 'delivery_pattern', label: 'Attack delivery pattern', metric: 'n/a', layer: 'cross-cutting', scored_for_ddos_readiness: true },
  { id: 'integrity_attack', label: 'Integrity attack', metric: 'validated findings', layer: 'L7/WAF', scored_for_ddos_readiness: false },
  { id: 'access_control', label: 'Access control', metric: 'validated findings', layer: 'L7/WAF', scored_for_ddos_readiness: false },
  { id: 'data_exposure', label: 'Data exposure', metric: 'validated findings', layer: 'L7/WAF', scored_for_ddos_readiness: false },
  { id: 'automation_abuse', label: 'Automation abuse', metric: 'validated findings', layer: 'L7/API', scored_for_ddos_readiness: false },
  { id: 'ai_agentic', label: 'AI / agentic abuse', metric: 'validated findings', layer: 'L7/AI', scored_for_ddos_readiness: false },
]);

/**
 * Per-family build specification — what AstraNull must research, catalog, probe, and score.
 * Detailed narrative: docs/detection/21-resource-exhaustion-family-build-spec.md
 */
export const FAMILY_BUILD_SPECS = Object.freeze([
  {
    id: 'volumetric',
    research_sources: ['AWS DDoS Resiliency (infrastructure layer)', 'Cloudflare network-layer coverage', 'Microsoft Azure volumetric vectors'],
    has_today: ['l3.forbidden_udp_port.safe', 'protocol.http3_quic_exposure.safe', 'high_scale.volumetric.request_only', 'l3.icmp_flood.readiness', 'l3.gre_esp_flood.readiness', 'l3.ipv6_volumetric.readiness', 'l3.sip_voip_flood.readiness', 'l3.sctp_exposure.readiness', 'l3.multicast_broadcast_storm.readiness'],
    build_probes: ['SOC-gated volumetric scenario families (governedScenarios contract): udp_flood, icmp_flood, gre_flood, quic_flood, sip_flood with max Gbps in authorization pack'],
    build_soc: ['udp_flood', 'icmp_flood', 'gre_flood', 'quic_flood', 'sip_flood governed scenarios via certified partner adapter (SOC-011)'],
    build_ui: ['Dashboard Gbps/Tbps readiness chip per target group', 'High-scale request scenario picker by volumetric class'],
    build_telemetry: ['provider_bps_pps', 'interface_drops', 'scrubber_redirect_state'],
    missing_vectors: ['Execution-only remainder: live volumetric scenarios via certified partner adapter (SOC-011)'],
    registry_attack_ids: ['ATT-001', 'ATT-002', 'ATT-013', 'ATT-015', 'ATT-074', 'ATT-124', 'ATT-135', 'ATT-137'],
    task_ids: ['DET-017', 'DET-023', 'SOC-011'],
  },
  {
    id: 'packet_processing',
    research_sources: ['Cloudflare ACK/RST/out-of-state TCP', 'AWS protocol attacks', 'Microsoft fragmentation attacks'],
    has_today: ['l3.firewall_exposure_scan.safe', 'l3.basic_deny_rule.safe', 'l3.ack_flood.readiness', 'l3.rst_flood.readiness', 'l3.syn_ack_flood.readiness', 'l3.tcp_flag_anomaly.readiness', 'l3.out_of_state_tcp.readiness', 'l3.fragmentation_flood.readiness'],
    build_probes: ['SOC-gated packet_processing scenario metadata on high_scale.volumetric.request_only'],
    build_soc: ['packet_processing scenario metadata with mpps/pps caps in authorization pack'],
    build_ui: ['PPS/Bpps budget display on run detail when telemetry present'],
    build_telemetry: ['mpps', 'firewall_cpu', 'nic_drops', 'fragment_reassembly_errors'],
    missing_vectors: ['Execution-only remainder: governed PPS scenarios (SOC-011)'],
    registry_attack_ids: ['ATT-004', 'ATT-005', 'ATT-006', 'ATT-007', 'ATT-009', 'ATT-010', 'ATT-014', 'ATT-028', 'ATT-029', 'ATT-033', 'ATT-084', 'ATT-231'],
    task_ids: ['DET-017', 'DET-023'],
  },
  {
    id: 'state_exhaustion',
    research_sources: ['AWS SYN flood', 'Cloudflare TCP connection floods', 'Microsoft connection exhaustion'],
    has_today: ['l3.forbidden_tcp_port.safe', 'l3.connection_table_exhaustion.request_only', 'tls.idle_connection_timeout.safe', 'l3.syn_flood.readiness', 'l3.tcp_connection_flood.readiness', 'l7.connection_hoarding.readiness', 'l3.nat_state_table.readiness', 'l3.smtp_connection_flood.readiness', 'l3.ssh_connection_flood.readiness', 'l3.ftp_connection_flood.readiness', 'l3.ike_ipsec_negotiation.readiness'],
    build_probes: ['SOC-gated syn_flood/tcp_connection_flood/connection_exhaustion scenario families'],
    build_soc: ['syn_flood', 'tcp_connection_flood', 'application_connection_exhaustion governed scenarios (SOC-011)'],
    build_ui: ['Concurrent connection limit evidence on target detail', 'State table saturation signal'],
    build_telemetry: ['cps', 'half_open_connections', 'nat_table_utilization', 'load_balancer_active_connections'],
    missing_vectors: ['Execution-only remainder: governed CPS scenarios (SOC-011)'],
    registry_attack_ids: ['ATT-003', 'ATT-008', 'ATT-075', 'ATT-123', 'ATT-125', 'ATT-136', 'ATT-138', 'ATT-139', 'ATT-032', 'ATT-036', 'ATT-038', 'ATT-039', 'ATT-204', 'ATT-222', 'ATT-223'],
    task_ids: ['DET-017', 'DET-020', 'SOC-011'],
  },
  {
    id: 'application_l7',
    research_sources: ['AWS application-layer attacks', 'Cloudflare HTTP DDoS', 'Microsoft app resource attacks', 'OWASP API Security'],
    has_today: ['l7.http_method_restriction.safe', 'l7.low_rate_rate_limit.safe', 'l7.cache_busting.safe', 'l7.bot_challenge_marker.safe', 'l7.cors_posture.safe', 'high_scale.application.request_only', 'origin.direct_bypass.safe', 'origin.direct_reachability.safe', 'origin.host_sni_bypass.safe', 'origin.leak_scan.safe', 'path.protected_canary.safe', 'waf.origin_bypass.safe', 'waf.fingerprint.safe', 'waf.enforcement.safe', 'waf.marker_rule.safe', 'l7.waf_marker_rule.safe', 'l7.http_get_flood.validation', 'l7.http_post_flood.validation', 'l7.search_abuse.validation', 'l7.export_abuse.validation', 'l7.batch_api_abuse.validation', 'l7.webhook_flood.readiness', 'l7.health_check_flood.readiness', 'l7.wordpress_xmlrpc.readiness', 'l7.captcha_challenge_abuse.readiness', 'l7.mqtt_broker_exposure.readiness', 'l7.http_pipelining.readiness', 'l7.http_range_abuse.readiness', 'l7.conditional_revalidation.readiness', 'origin.dns_hostname_bypass.readiness', 'origin.cdn_bypass.readiness'],
    build_probes: ['SOC-gated http_get_flood/http_post_flood/cache_busting_at_scale scenario families'],
    build_soc: ['http_get_flood', 'http_post_flood', 'cache_busting_at_scale governed scenarios (SOC-011)'],
    build_ui: ['RPS limit evidence', 'Origin vs CDN path on cache-bust runs', 'Per-endpoint cost asymmetry panel'],
    build_telemetry: ['rps', 'status_code_distribution', 'origin_vs_edge_ratio', 'waf_challenge_rate'],
    missing_vectors: ['Execution-only remainder: governed RPS scenarios (SOC-011)'],
    registry_attack_ids: ['ATT-051', 'ATT-052', 'ATT-053', 'ATT-056', 'ATT-058', 'ATT-066', 'ATT-070', 'ATT-072', 'ATT-073', 'ATT-100', 'ATT-101', 'ATT-102', 'ATT-103', 'ATT-108', 'ATT-109', 'ATT-122', 'ATT-126', 'ATT-127', 'ATT-128', 'ATT-129', 'ATT-130', 'ATT-131', 'ATT-132', 'ATT-140', 'ATT-141', 'ATT-142', 'ATT-145', 'ATT-153', 'ATT-167', 'ATT-170', 'ATT-174', 'ATT-176', 'ATT-080', 'ATT-081', 'ATT-082', 'ATT-083', 'ATT-190'],
    task_ids: ['DET-001', 'DET-020', 'DET-023', 'SOC-011'],
  },
  {
    id: 'computational',
    research_sources: ['Cloudflare TLS/HTTP DDoS', 'Google Rapid Reset advisory', 'CERT/CC MadeYouReset VU#767506'],
    has_today: ['l7.expensive_endpoint.safe', 'tls.full_audit.safe', 'protocol.http2_rapid_reset_readiness.safe', 'tls.handshake_rate.readiness', 'tls.renegotiation.readiness', 'l7.http2_rapid_reset.validation', 'l7.http2_made_you_reset.readiness', 'l7.http2_continuation.readiness', 'l7.http2_priority_abuse.readiness', 'tls.ocsp_stapling.readiness', 'l7.redos.readiness', 'tls.zero_rtt.readiness'],
    build_probes: ['SOC-gated rapid_reset_validation/made_you_reset_validation/tls_handshake_exhaustion scenario families'],
    build_soc: ['rapid_reset_validation', 'made_you_reset_validation', 'tls_handshake_exhaustion governed scenarios (SOC-011)'],
    build_ui: ['Crypto CPU / handshake rate telemetry panel', 'HTTP/2 CVE readiness badges'],
    build_telemetry: ['tls_handshakes_per_sec', 'cpu_percent', 'http2_reset_rate', 'stream_creation_rate'],
    missing_vectors: ['Execution-only remainder: governed reset/handshake scenarios (SOC-011)'],
    registry_attack_ids: ['ATT-054', 'ATT-064', 'ATT-065', 'ATT-067', 'ATT-069', 'ATT-110', 'ATT-111', 'ATT-147', 'ATT-152', 'ATT-155', 'ATT-156', 'ATT-037', 'ATT-188', 'ATT-194', 'ATT-196', 'ATT-197', 'ATT-208', 'ATT-219', 'ATT-228', 'ATT-232', 'ATT-235'],
    task_ids: ['DET-020', 'DET-021', 'SOC-011'],
  },
  {
    id: 'memory_exhaustion',
    research_sources: ['Microsoft slowloris/slow read', 'Cloudflare HTTP/2 stream abuse', 'RFC 9113 CONTINUATION issues'],
    has_today: ['tls.slow_header_body_timeout.safe', 'protocol.http2_stream_concurrency.safe', 'protocol.websocket_connection_controls.safe', 'l7.header_size_boundary.safe', 'l7.slowloris.readiness', 'l7.slow_post.readiness', 'l7.slow_read.readiness', 'l7.low_and_slow.readiness', 'l7.large_body_post.readiness', 'protocol.sse_stream.readiness', 'l7.hpack_bomb.readiness', 'l7.http2_push_promise.readiness', 'l7.json_xml_bomb.readiness', 'l7.file_upload_abuse.readiness', 'protocol.websocket_message_rate.readiness'],
    build_probes: ['SOC-gated slowloris/slow_post/slow_read scenario families with strict duration caps'],
    build_soc: ['slowloris', 'slow_post', 'slow_read governed scenarios with hard duration caps + kill switch (SOC-011)'],
    build_ui: ['Connection slot / worker exhaustion indicators', 'Slow-client timeout policy evidence'],
    build_telemetry: ['active_connections', 'worker_queue_depth', 'request_stall_duration_p99'],
    missing_vectors: ['Execution-only remainder: governed slow-client scenarios (SOC-011)'],
    registry_attack_ids: ['ATT-059', 'ATT-060', 'ATT-061', 'ATT-062', 'ATT-063', 'ATT-068', 'ATT-071', 'ATT-104', 'ATT-113', 'ATT-148', 'ATT-149', 'ATT-150', 'ATT-151', 'ATT-198', 'ATT-199', 'ATT-205', 'ATT-226', 'ATT-227', 'ATT-229', 'ATT-230', 'ATT-234'],
    task_ids: ['DET-020', 'DET-021', 'SOC-011'],
  },
  {
    id: 'backend_exhaustion',
    research_sources: ['AWS expensive API / cache busting', 'GraphQL OWASP', 'Database connection pool exhaustion patterns'],
    has_today: ['l7.api_quota_exhaustion.safe', 'l7.graphql_complexity.safe', 'l7.login_abuse_flow.safe', 'l7.password_reset.safe', 'l7.search_abuse.validation', 'l7.export_abuse.validation', 'l7.graphql_batch_abuse.validation', 'l7.oauth_token_abuse.validation', 'l7.file_upload_abuse.readiness', 'l7.signup_registration_abuse.validation', 'l7.elasticsearch_abuse.readiness', 'l7.otp_sms_cost.readiness', 'l7.checkout_abuse.validation'],
    build_probes: ['SOC-gated database_exhaustion/graphql_depth_at_scale scenario families on declared endpoints only'],
    build_soc: ['database_exhaustion', 'graphql_depth_at_scale governed scenarios on declared endpoints (SOC-011)'],
    build_ui: ['DB pool / query latency correlation on run detail', 'Backend dependency map for expensive endpoints'],
    build_telemetry: ['db_connections', 'query_latency_p99', 'cache_miss_rate', 'queue_depth'],
    missing_vectors: ['Execution-only remainder: governed backend scenarios (SOC-011)'],
    registry_attack_ids: ['ATT-055', 'ATT-057', 'ATT-105', 'ATT-106', 'ATT-107', 'ATT-112', 'ATT-114', 'ATT-143', 'ATT-144', 'ATT-157', 'ATT-158', 'ATT-166', 'ATT-191', 'ATT-193', 'ATT-195', 'ATT-200', 'ATT-201', 'ATT-202', 'ATT-203', 'ATT-209', 'ATT-210', 'ATT-211', 'ATT-212', 'ATT-213', 'ATT-214', 'ATT-216', 'ATT-220', 'ATT-221', 'ATT-224'],
    task_ids: ['DET-020', 'SOC-011'],
  },
  {
    id: 'dns_exhaustion',
    research_sources: ['Cloudflare DNS DDoS / laundering / random prefix', 'AWS Route53 shield', 'USENIX NXNSAttack', 'DNSBomb research'],
    has_today: ['dns.authoritative_response.safe', 'dns.random_prefix_nxdomain.safe', 'dns.open_recursion_behavior.safe', 'dns.dnssec_expensive_query.safe', 'dns.zone_transfer_exposure.safe', 'high_scale.dns_high_query.request_only', 'dns.laundering.readiness', 'dns.garbage_flood.readiness', 'dns.phantom_domain.readiness', 'dns.domain_lockup.readiness', 'dns.nxns_attack.readiness', 'dns.dnsbomb.readiness', 'dns.qname_minimization.readiness', 'dns.doh_dot_exposure.readiness', 'dns.tcp_fallback.readiness', 'dns.zone_walking.readiness'],
    build_probes: ['SOC-gated dns_query_flood/water_torture/nxdomain_at_scale scenario families'],
    build_soc: ['dns_query_flood', 'water_torture', 'nxdomain_at_scale governed scenarios (SOC-011)'],
    build_ui: ['Resolver vs authoritative path diagram', 'NXDOMAIN ratio / QPS charts'],
    build_telemetry: ['dns_qps', 'nxdomain_ratio', 'resolver_latency', 'authoritative_cpu'],
    missing_vectors: ['Execution-only remainder: governed DNS QPS scenarios (SOC-011)'],
    registry_attack_ids: ['ATT-041', 'ATT-043', 'ATT-044', 'ATT-045', 'ATT-046', 'ATT-047', 'ATT-048', 'ATT-049', 'ATT-050', 'ATT-159', 'ATT-160', 'ATT-161', 'ATT-162', 'ATT-187', 'ATT-189'],
    task_ids: ['DET-019', 'DET-023', 'SOC-011'],
  },
  {
    id: 'reflection',
    research_sources: ['AWS UDP reflection', 'Cloudflare attack coverage list', 'Akamai WS-Discovery/ARMS advisories'],
    has_today: ['dns.amplification_exposure.safe', 'reflect.ssdp_exposure.safe', 'reflect.snmp_exposure.safe', 'reflect.chargen_qotd_exposure.safe', 'reflect.mdns_netbios_wsdiscovery_exposure.safe', 'reflect.portmap_service_exposure.safe', 'reflect.dtls_sip_rdp_tftp_exposure.safe', 'reflect.quic_reflection_exposure.safe', 'reflect.tcp_middlebox_exposure.safe', 'reflect.mssql_resolver_exposure.safe', 'reflect.jenkins_discovery_exposure.safe', 'reflect.coap_iot_exposure.safe', 'reflect.legacy_device_discovery_exposure.safe', 'reflect.stun_turn_exposure.safe', 'reflect.ipmi_bmc_exposure.safe', 'reflect.redis_direct_exposure.safe', 'reflect.openvpn_wireguard_exposure.safe'],
    has_today_notes: 'Full reflector exposure inventory shipped: one bounded UDP fingerprint / TCP connect per declared host with response size class metadata; never launches reflection. Legacy responder and device/game discovery classes (Echo, QOTD, Ubiquiti, Lantronix, VxWorks/WDBRPC, TeamSpeak 3) included.',
    build_probes: ['reflector_exposure_metadata (delivered via bounded udp_probe/tcp_connect fingerprints)'],
    build_soc: ['reflection_exposure_assessment only — never launch reflection'],
    build_ui: ['Reflector exposure inventory (metadata)', 'DRDoS readiness score'],
    build_telemetry: ['unexpected_udp_response_volume', 'spoofed_source_indicators from provider'],
    missing_vectors: [],
    registry_attack_ids: ['ATT-020', 'ATT-021', 'ATT-022', 'ATT-023', 'ATT-024', 'ATT-025', 'ATT-026', 'ATT-027', 'ATT-116', 'ATT-117', 'ATT-118', 'ATT-163', 'ATT-164', 'ATT-165', 'ATT-168', 'ATT-085', 'ATT-087', 'ATT-088', 'ATT-177', 'ATT-179', 'ATT-180', 'ATT-182', 'ATT-184', 'ATT-186'],
    task_ids: ['DET-018'],
  },
  {
    id: 'amplification',
    research_sources: ['AWS amplification protocol list', 'Cloudflare CLDAP/Memcached advisories', 'CAIDA amplifier census methods'],
    has_today: ['dns.amplification_exposure.safe', 'amp.ntp_exposure.safe', 'amp.cldap_exposure.safe', 'amp.memcached_exposure.safe', 'amp.dns_any_txt_exposure.safe', 'amp.smurf_broadcast_exposure.safe', 'amp.authoritative_resolver_exposure.safe'],
    has_today_notes: 'Amplification exposure shipped as config/response-class posture metadata; no amplifier query traffic is ever generated.',
    build_probes: ['amplification_ratio_metadata (posture metadata only)'],
    build_soc: ['amplification_exposure_audit — no amplifier traffic generation'],
    build_ui: ['Amplification ratio / open service risk panel'],
    build_telemetry: ['response_size_class', 'provider_amplification_alerts'],
    missing_vectors: [],
    registry_attack_ids: ['ATT-016', 'ATT-017', 'ATT-018', 'ATT-019', 'ATT-042', 'ATT-115', 'ATT-134', 'ATT-086', 'ATT-089', 'ATT-178', 'ATT-181', 'ATT-183', 'ATT-185', 'ATT-206', 'ATT-207'],
    task_ids: ['DET-018'],
  },
  {
    id: 'exploit_dos',
    research_sources: ['Microsoft legacy IP fragmentation attacks', 'CVE databases for HTTP/2/TLS parser bugs', 'Embedded device advisories'],
    has_today: ['exploit.ping_of_death.posture', 'exploit.teardrop.posture', 'exploit.ip_options.posture', 'exploit.malformed_quic.posture', 'exploit.land_attack.posture', 'exploit.quic_migration.posture'],
    has_today_notes: 'Parser/firmware CVE posture metadata only; exploit validation stays lab-only SOC scope.',
    build_probes: ['parser_version_fingerprint (posture metadata only)'],
    build_soc: ['exploit_validation only on isolated lab targets with explicit authorization'],
    build_ui: ['Firmware/parser CVE readiness on edge assets'],
    build_telemetry: ['crash_restarts', 'parser_error_rate'],
    missing_vectors: [],
    registry_attack_ids: ['ATT-011', 'ATT-012', 'ATT-119', 'ATT-120', 'ATT-133', 'ATT-154', 'ATT-030', 'ATT-031', 'ATT-034', 'ATT-035', 'ATT-040', 'ATT-076', 'ATT-077', 'ATT-078', 'ATT-079', 'ATT-192', 'ATT-218', 'ATT-225', 'ATT-233'],
    task_ids: ['DET-017', 'DET-021', 'DET-026'],
  },
  {
    id: 'delivery_pattern',
    research_sources: ['Cloudflare carpet bombing / 7.3 Tbps case study', 'Pulse-wave DDoS research', 'Multi-vector SOC playbooks'],
    has_today: ['high_scale.multi_vector.request_only', 'high_scale.volumetric.request_only', 'high_scale.degradation_recovery.request_only', 'ops.alert_workflow_marker.safe', 'pattern.carpet_bombing.readiness', 'pattern.pulse_wave.readiness', 'pattern.spoofed_source.readiness', 'pattern.ransom_ddos.readiness', 'pattern.rate_limit_evasion.readiness', 'pattern.adaptive_evasion.readiness', 'pattern.residential_proxy.readiness'],
    has_today_notes: 'High-scale requests now carry delivery_patterns[] metadata bound to the governed scenario taxonomy (DET-022/SOC-011).',
    build_probes: [],
    build_soc: ['carpet_bombing', 'pulse_wave', 'multi_vector_switching', 'ATT-093 coordinated device swarm (soc_only) scenarios with governed adapter'],
    build_ui: ['Attack pattern timeline on SOC console', 'Multi-destination heatmap', 'Vector-switching detection from telemetry'],
    build_telemetry: ['destination_spread', 'vector_change_events', 'pulse_frequency'],
    missing_vectors: [],
    registry_attack_ids: ['ATT-090', 'ATT-091', 'ATT-092', 'ATT-093', 'ATT-094', 'ATT-095', 'ATT-096', 'ATT-097', 'ATT-098', 'ATT-099', 'ATT-121', 'ATT-146', 'ATT-169', 'ATT-171', 'ATT-172', 'ATT-173', 'ATT-175', 'ATT-236', 'ATT-237', 'ATT-238', 'ATT-239', 'ATT-240', 'ATT-241', 'ATT-242', 'ATT-243', 'ATT-246', 'ATT-247', 'ATT-248', 'ATT-249', 'ATT-250', 'ATT-251', 'ATT-252', 'ATT-254'],
    task_ids: ['DET-022', 'DET-026', 'SOC-011'],
  },
]);

/** Vectors documented in product docs but outside classic DDoS taxonomy — tracked separately. */
const REGISTRY_CATALOG_VECTOR_IDS = Object.freeze({
  'ATT-001': Object.freeze(['NET-048', 'NET-049', 'NET-050', 'NET-051']),
  'ATT-002': Object.freeze(['NET-016', 'NET-017', 'NET-018', 'NET-019', 'NET-023', 'NET-028', 'NET-029', 'NET-162', 'NET-163']),
  'ATT-003': Object.freeze(['NET-056', 'NET-119', 'NET-144']),
  'ATT-004': Object.freeze(['NET-057']),
  'ATT-005': Object.freeze(['NET-059']),
  'ATT-006': Object.freeze(['NET-058']),
  'ATT-007': Object.freeze(['NET-060', 'NET-061', 'NET-062', 'NET-063', 'NET-064', 'NET-118']),
  'ATT-008': Object.freeze(['NET-065', 'NET-067']),
  'ATT-009': Object.freeze(['NET-068', 'NET-121']),
  'ATT-010': Object.freeze(['NET-009', 'NET-010', 'NET-012', 'NET-013', 'NET-026', 'NET-052', 'NET-070', 'NET-161', 'NET-166']),
  'ATT-011': Object.freeze(['NET-014', 'NET-090', 'NET-100']),
  'ATT-012': Object.freeze(['NET-011', 'NET-165']),
  'ATT-013': Object.freeze(['NET-036', 'NET-037', 'NET-160']),
  'ATT-014': Object.freeze(['NET-038', 'NET-039']),
  'ATT-015': Object.freeze(['NET-075']),
  'ATT-017': Object.freeze(['NET-130', 'AMP-004']),
  'ATT-018': Object.freeze(['AMP-005', 'AMP-006']),
  'ATT-019': Object.freeze(['AMP-007']),
  'ATT-020': Object.freeze(['NET-131', 'AMP-008', 'AMP-040', 'AMP-043', 'AMP-044', 'AMP-052', 'AMP-059']),
  'ATT-021': Object.freeze(['NET-129', 'AMP-009']),
  'ATT-022': Object.freeze(['NET-138', 'AMP-010', 'AMP-011', 'AMP-012']),
  'ATT-023': Object.freeze(['NET-132', 'NET-133', 'NET-137', 'AMP-014', 'AMP-015', 'AMP-020']),
  'ATT-024': Object.freeze(['NET-134', 'NET-135', 'NET-142', 'AMP-013', 'AMP-016', 'AMP-017', 'AMP-019', 'AMP-021', 'AMP-023', 'AMP-024', 'AMP-025', 'AMP-053', 'AMP-062', 'AMP-063']),
  'ATT-025': Object.freeze(['NET-086', 'NET-136', 'NET-140', 'AMP-018', 'AMP-028', 'AMP-034', 'AMP-035', 'AMP-036', 'AMP-041']),
  'ATT-026': Object.freeze(['AMP-037']),
  'ATT-027': Object.freeze(['AMP-047', 'AMP-071']),
  'ATT-041': Object.freeze(['APP-099', 'APP-153', 'APP-154', 'APP-156', 'APP-157', 'APP-158', 'APP-159', 'APP-160', 'APP-161', 'APP-165']),
  'ATT-042': Object.freeze(['AMP-001', 'AMP-002', 'APP-103']),
  'ATT-043': Object.freeze(['APP-101']),
  'ATT-044': Object.freeze(['APP-100']),
  'ATT-045': Object.freeze(['APP-110']),
  'ATT-046': Object.freeze(['APP-102', 'APP-166', 'APP-167']),
  'ATT-047': Object.freeze(['APP-170']),
  'ATT-048': Object.freeze(['APP-107']),
  'ATT-049': Object.freeze(['AMP-066']),
  'ATT-050': Object.freeze(['AMP-065']),
  'ATT-051': Object.freeze(['APP-001', 'APP-005', 'APP-006', 'WAF-156']),
  'ATT-052': Object.freeze(['APP-003']),
  'ATT-053': Object.freeze(['APP-002']),
  'ATT-054': Object.freeze(['APP-007']),
  'ATT-055': Object.freeze(['APP-050', 'APP-051', 'APP-052', 'APP-053', 'APP-130']),
  'ATT-056': Object.freeze(['APP-136', 'WAF-129']),
  'ATT-057': Object.freeze(['APP-062', 'APP-065', 'APP-066', 'WAF-133']),
  'ATT-058': Object.freeze(['APP-008', 'APP-009', 'APP-010', 'WAF-021']),
  'ATT-059': Object.freeze(['APP-014', 'APP-024', 'APP-040']),
  'ATT-060': Object.freeze(['APP-016']),
  'ATT-061': Object.freeze(['APP-017']),
  'ATT-062': Object.freeze(['APP-018']),
  'ATT-064': Object.freeze(['NET-077', 'NET-078']),
  'ATT-065': Object.freeze(['NET-079']),
  'ATT-066': Object.freeze(['APP-088']),
  'ATT-067': Object.freeze(['APP-077', 'APP-087']),
  'ATT-068': Object.freeze(['APP-079']),
  'ATT-069': Object.freeze(['APP-078']),
  'ATT-070': Object.freeze(['APP-092', 'APP-093']),
  'ATT-071': Object.freeze(['APP-072', 'APP-073', 'APP-074', 'APP-193']),
  'ATT-072': Object.freeze(['APP-068', 'APP-069', 'APP-070']),
  'ATT-073': Object.freeze(['APP-133']),
  'ATT-074': Object.freeze(['APP-112', 'APP-113', 'APP-114', 'APP-176', 'APP-177', 'APP-178', 'APP-179', 'APP-180', 'APP-181', 'APP-182', 'APP-183', 'APP-184']),
  'ATT-075': Object.freeze(['NET-066', 'NET-089', 'NET-120', 'APP-019', 'APP-042', 'APP-043']),
  'ATT-090': Object.freeze(['NET-001', 'NET-002', 'NET-003', 'NET-167']),
  'ATT-091': Object.freeze(['NET-145']),
  'ATT-092': Object.freeze(['AMP-056']),
  'ATT-094': Object.freeze(['NET-045']),
  'ATT-095': Object.freeze(['NET-046', 'EVA-057']),
  'ATT-096': Object.freeze(['EVA-082']),
  'ATT-097': Object.freeze(['APP-011']),
  'ATT-100': Object.freeze(['WAF-012', 'EVA-074', 'EVA-078']),
  'ATT-102': Object.freeze(['WAF-018', 'WAF-019']),
  'ATT-104': Object.freeze(['APP-020', 'APP-021']),
  'ATT-105': Object.freeze(['APP-055', 'APP-056']),
  'ATT-106': Object.freeze(['APP-054']),
  'ATT-107': Object.freeze(['WAF-135']),
  'ATT-108': Object.freeze(['APP-142']),
  'ATT-110': Object.freeze(['APP-086']),
  'ATT-111': Object.freeze(['APP-098', 'APP-192']),
  'ATT-112': Object.freeze(['APP-058', 'APP-059', 'WAF-112']),
  'ATT-113': Object.freeze(['APP-015', 'APP-138']),
  'ATT-114': Object.freeze(['APP-063', 'APP-064', 'EVA-042', 'EVA-043']),
  'ATT-115': Object.freeze(['AMP-003', 'APP-106', 'APP-155', 'APP-162']),
  'ATT-116': Object.freeze(['AMP-030']),
  'ATT-117': Object.freeze(['AMP-042']),
  'ATT-118': Object.freeze(['NET-128', 'AMP-026', 'AMP-039', 'AMP-060']),
  'ATT-119': Object.freeze(['NET-007', 'NET-008', 'NET-105']),
  'ATT-120': Object.freeze(['NET-076']),
  'ATT-121': Object.freeze(['EVA-056', 'EVA-064']),
  'ATT-123': Object.freeze(['APP-115', 'APP-116']),
  'ATT-124': Object.freeze(['NET-024', 'AMP-070']),
  'ATT-125': Object.freeze(['NET-053', 'NET-054', 'NET-087']),
  'ATT-127': Object.freeze(['EVA-075']),
  'ATT-129': Object.freeze(['WAF-123', 'WAF-127']),
  'ATT-130': Object.freeze(['NET-168', 'EVA-076']),
  'ATT-132': Object.freeze(['WAF-001']),
  'ATT-133': Object.freeze(['NET-015']),
  'ATT-134': Object.freeze(['AMP-049', 'AMP-050']),
  'ATT-135': Object.freeze(['NET-072', 'NET-073']),
  'ATT-136': Object.freeze(['NET-082', 'AMP-031']),
  'ATT-137': Object.freeze([]),
  'ATT-138': Object.freeze(['APP-126']),
  'ATT-139': Object.freeze(['APP-128']),
  'ATT-140': Object.freeze(['APP-022']),
  'ATT-141': Object.freeze(['APP-013', 'WAF-023']),
  'ATT-142': Object.freeze(['APP-195']),
  'ATT-143': Object.freeze(['APP-144', 'APP-149', 'APP-150', 'WAF-162']),
  'ATT-144': Object.freeze(['APP-141', 'WAF-100']),
  'ATT-145': Object.freeze(['APP-061', 'WAF-103', 'WAF-150']),
  'ATT-146': Object.freeze(['NET-047', 'EVA-054', 'EVA-055']),
  'ATT-147': Object.freeze(['APP-027']),
  'ATT-148': Object.freeze(['APP-030']),
  'ATT-149': Object.freeze(['APP-031', 'WAF-069']),
  'ATT-150': Object.freeze(['APP-089']),
  'ATT-152': Object.freeze(['APP-094', 'APP-095']),
  'ATT-153': Object.freeze(['APP-096']),
  'ATT-154': Object.freeze(['APP-097']),
  'ATT-155': Object.freeze(['NET-081']),
  'ATT-157': Object.freeze(['WAF-160']),
  'ATT-158': Object.freeze(['WAF-102']),
  'ATT-159': Object.freeze(['APP-108', 'APP-109', 'APP-174', 'APP-175']),
  'ATT-161': Object.freeze(['APP-111', 'APP-163', 'APP-164']),
  'ATT-163': Object.freeze(['AMP-027']),
  'ATT-164': Object.freeze(['AMP-038']),
  'ATT-165': Object.freeze(['APP-131']),
  'ATT-167': Object.freeze(['APP-121', 'APP-122', 'APP-123']),
  'ATT-168': Object.freeze(['NET-084', 'NET-085', 'AMP-033']),
  'ATT-169': Object.freeze(['APP-151', 'WAF-131', 'WAF-152', 'WAF-159']),
  'ATT-170': Object.freeze(['EVA-001', 'EVA-002', 'EVA-003', 'EVA-014', 'EVA-016', 'EVA-021', 'EVA-039', 'EVA-040']),
  'ATT-174': Object.freeze(['WAF-137']),
  'ATT-175': Object.freeze(['EVA-052', 'EVA-053']),
  'ND-006': Object.freeze(['WAF-096', 'WAF-097', 'WAF-098', 'WAF-148', 'WAF-149']),
  'WV-001': Object.freeze(['WAF-025', 'WAF-026', 'WAF-027', 'WAF-028', 'WAF-029', 'WAF-030', 'WAF-031', 'WAF-032']),
  'WV-002': Object.freeze(['WAF-070', 'WAF-071', 'WAF-072', 'WAF-073', 'WAF-074', 'WAF-075', 'WAF-076', 'WAF-077', 'WAF-078', 'WAF-079']),
  'WV-003': Object.freeze(['WAF-044']),
  'WV-004': Object.freeze(['WAF-082', 'WAF-083', 'WAF-085', 'WAF-094']),
  'WV-005': Object.freeze(['WAF-040', 'WAF-041', 'WAF-042', 'WAF-043']),
  'WV-006': Object.freeze(['WAF-037']),
  'WV-007': Object.freeze(['WAF-045', 'WAF-046']),
});

const ATTACK_DOMAIN_ID_SETS = Object.freeze({
  A1a: new Set(['ATT-001', 'ATT-002', 'ATT-003', 'ATT-004', 'ATT-005', 'ATT-006', 'ATT-007', 'ATT-008', 'ATT-009', 'ATT-010', 'ATT-011', 'ATT-012', 'ATT-013', 'ATT-014', 'ATT-119', 'ATT-124', 'ATT-125', 'ATT-133', 'ATT-135', 'ATT-136', 'ATT-137']),
  A4b: new Set(['ATT-074', 'ATT-123', 'ATT-138', 'ATT-139', 'ATT-165', 'ATT-167']),
  A5: new Set(['ATT-015', 'ATT-064', 'ATT-065', 'ATT-066', 'ATT-067', 'ATT-068', 'ATT-069', 'ATT-070', 'ATT-071', 'ATT-072', 'ATT-110', 'ATT-111', 'ATT-120', 'ATT-150', 'ATT-151', 'ATT-152', 'ATT-153', 'ATT-154', 'ATT-155', 'ATT-156', 'ATT-176']),
  A7: new Set(['ATT-100', 'ATT-101', 'ATT-102', 'ATT-103', 'ATT-122', 'ATT-127', 'ATT-128', 'ATT-129', 'ATT-130', 'ATT-131', 'ATT-132', 'ATT-141', 'ATT-145', 'ATT-149', 'ATT-157', 'ATT-158', 'ATT-169', 'ATT-170', 'ATT-174']),
});

function domainForAttackVector(entry) {
  for (const [domain, ids] of Object.entries(ATTACK_DOMAIN_ID_SETS)) {
    if (ids.has(entry.id)) return domain;
  }
  if (entry.exhausted_resource === 'reflection' || entry.exhausted_resource === 'amplification') return 'A2';
  if (entry.exhausted_resource === 'dns_exhaustion') return 'A3';
  if (entry.exhausted_resource === 'delivery_pattern') return 'A8';
  return 'A4a';
}

const WAF_EXHAUSTED_RESOURCE_BY_ID = Object.freeze({
  'WV-001': 'integrity_attack',
  'WV-002': 'integrity_attack',
  'WV-003': 'integrity_attack',
  'WV-004': 'data_exposure',
  'WV-005': 'integrity_attack',
  'WV-006': 'access_control',
  'WV-007': 'integrity_attack',
  'WV-008': 'integrity_attack',
});

function coverageStatusForEvidenceTier(tier) {
  if (tier === 'E3') return 'implemented';
  if (tier === 'E1' || tier === 'E2') return 'partial';
  if (tier === 'E4') return 'soc_only';
  return 'pending';
}

export const OUT_OF_SCOPE_VECTORS = Object.freeze([
  {
    catalog_vector_ids: Object.freeze(['NET-030', 'NET-031', 'NET-032', 'NET-033', 'NET-034', 'NET-091', 'NET-092', 'NET-093', 'NET-094', 'NET-095', 'NET-096', 'NET-097', 'NET-147', 'NET-148', 'NET-149', 'NET-150', 'NET-151', 'NET-152', 'NET-153', 'NET-154', 'NET-155']),
    reason: 'requires_l2_adjacency',
    domain: 'A1b',
    note: 'This vector is confined to a local Ethernet, IPv6 neighbor-discovery, or multicast-control domain and cannot traverse an outside-in routed probe path.',
  },
  {
    catalog_vector_ids: Object.freeze(['NET-042', 'NET-043', 'NET-044', 'NET-125', 'NET-156', 'NET-157']),
    reason: 'requires_routing_peer_session',
    domain: 'A1b',
    note: 'This vector requires an accepted routing, BFD, multicast-routing, or MPLS control relationship that AstraNull cannot establish from an anonymous SaaS probe.',
  },
  {
    catalog_vector_ids: Object.freeze(['NET-169', 'NET-170', 'NET-171', 'NET-172', 'NET-173', 'NET-174', 'NET-175', 'NET-176', 'NET-177']),
    reason: 'requires_rf_proximity',
    domain: 'A1c',
    note: 'This vector requires a radio physically near the protected wireless network.',
  },
  {
    catalog_vector_ids: Object.freeze(['NET-158', 'NET-159', 'NET-178', 'NET-179', 'NET-180']),
    reason: 'requires_mobile_core_interface',
    domain: 'A1d',
    note: 'This vector requires access to a mobile-core user-plane or signalling interface.',
  },
]);

/**
 * Honest monitor-only detection layer for the OUT_OF_SCOPE_VECTORS.
 *
 * These 41 vectors can never be safely ORIGINATED by an outside-in SaaS probe
 * (that is why they stay in OUT_OF_SCOPE_VECTORS and keep their probe_reachable:false
 * domains). They can, however, be passively DETECTED where the customer already
 * runs the right observer. This layer annotates the same catalog ids with that
 * passive detection story — it never claims an active probe. It mirrors the
 * existing NON_DDOS_AVAILABILITY_THREATS monitor_only pattern (E5, scope-bounded).
 *
 * detection_mode:
 *   - integration_telemetry (local): for L2-adjacency floods, detection depends on a
 *     customer-supplied on-host telemetry feed (host interface counters, netlink
 *     neighbor/route churn, kernel/syslog exported to the customer's SIEM/metrics) —
 *     genuinely useful passive detection when a host sits in the affected L2/broadcast
 *     domain. AstraNull is outside-in only (ADR-0008) and ships no on-host agent.
 *   - integration_telemetry: detection depends on a customer-supplied feed/sensor
 *     (routing-session state, WIDS/wireless sensor, or a mobile-core signalling tap).
 *     RF and mobile-core sensors are specialised and most customers do not have them,
 *     so those families are honestly "detection-only-if-integrated".
 *
 * Bookkeeping: this is an ANNOTATION layer, not a catalog claimant. The 41 ids remain
 * counted exactly once via OUT_OF_SCOPE_VECTORS; MONITOR_ONLY_VECTORS is NOT added to
 * the registry claim set, so it introduces no duplicate claim.
 *
 * @typedef {Object} MonitorOnlyVectorEntry
 * @property {string} id
 * @property {string} name
 * @property {string[]} catalog_vector_ids
 * @property {'integration_telemetry'} detection_mode
 * @property {string} signal_source
 * @property {string} dependency
 * @property {true} monitor_only
 * @property {string} notes
 */
const MONITOR_ONLY_VECTORS_SOURCE = [
  {
    id: 'MON-001',
    name: 'IPv6 neighbor / router-discovery flood (local observation)',
    catalog_vector_ids: ['NET-030', 'NET-031', 'NET-032', 'NET-033', 'NET-034'],
    reason: 'requires_l2_adjacency',
    domain: 'A1b',
    detection_mode: 'integration_telemetry',
    signal_source: 'customer-supplied on-host telemetry: interface counters + netlink neighbor-table churn + kernel/syslog ND/RA/MLD messages',
    dependency: 'customer_local_telemetry_required',
    monitor_only: true,
    notes: 'Locally observable via customer-supplied telemetry: NS/NA/RS/RA/MLD floods show as neighbor-table churn and interface-counter spikes on a host in the affected link; nothing safe can originate them.',
  },
  {
    id: 'MON-002',
    name: 'Ethernet / ARP L2 frame flood (local observation)',
    catalog_vector_ids: ['NET-091', 'NET-092', 'NET-093', 'NET-094'],
    reason: 'requires_l2_adjacency',
    domain: 'A1b',
    detection_mode: 'integration_telemetry',
    signal_source: 'customer-supplied on-host telemetry: interface counters (broadcast/multicast rate) + ARP-table churn + syslog',
    dependency: 'customer_local_telemetry_required',
    monitor_only: true,
    notes: 'Locally observable via customer-supplied telemetry: ARP/broadcast/multicast/malformed-MAC floods surface as local broadcast-storm counters and ARP-cache thrash; detection only, no origination.',
  },
  {
    id: 'MON-003',
    name: 'IGMP multicast-control flood (local observation)',
    catalog_vector_ids: ['NET-095', 'NET-096', 'NET-097'],
    reason: 'requires_l2_adjacency',
    domain: 'A1b',
    detection_mode: 'integration_telemetry',
    signal_source: 'customer-supplied on-host telemetry: multicast-group state + interface counters + kernel/syslog IGMP messages',
    dependency: 'customer_local_telemetry_required',
    monitor_only: true,
    notes: 'Locally observable via customer-supplied telemetry: IGMP / fragmented / malformed IGMP floods appear in local multicast group-membership churn and packet counters.',
  },
  {
    id: 'MON-004',
    name: 'Switching / STP / CAM-table flood (local observation)',
    catalog_vector_ids: ['NET-147', 'NET-148'],
    reason: 'requires_l2_adjacency',
    domain: 'A1b',
    detection_mode: 'integration_telemetry',
    signal_source: 'customer-supplied on-host telemetry: interface counters + STP topology-change events in syslog (switch-integration feed optional)',
    dependency: 'customer_local_telemetry_required',
    monitor_only: true,
    notes: 'Locally observable via customer-supplied telemetry (indirectly): CAM exhaustion and STP/BPDU topology-change floods manifest as unicast-flooding and link-flap symptoms on attached hosts; switch SNMP/syslog integration sharpens it.',
  },
  {
    id: 'MON-005',
    name: 'DHCP starvation flood (local observation)',
    catalog_vector_ids: ['NET-149', 'NET-150'],
    reason: 'requires_l2_adjacency',
    domain: 'A1b',
    detection_mode: 'integration_telemetry',
    signal_source: 'customer-supplied on-host telemetry: DHCP client-state + lease-acquisition failures + kernel/syslog',
    dependency: 'customer_local_telemetry_required',
    monitor_only: true,
    notes: 'Locally observable via customer-supplied telemetry: DHCPv4/DHCPv6 discover/solicit starvation surfaces as lease-acquisition failure and DISCOVER retries on hosts in the same segment.',
  },
  {
    id: 'MON-006',
    name: 'L2 access / admission-control flood (local observation)',
    catalog_vector_ids: ['NET-151', 'NET-152', 'NET-153', 'NET-154', 'NET-155'],
    reason: 'requires_l2_adjacency',
    domain: 'A1b',
    detection_mode: 'integration_telemetry',
    signal_source: 'customer-supplied on-host telemetry: interface counters + 802.1X supplicant/link-control events in kernel/syslog',
    dependency: 'customer_local_telemetry_required',
    monitor_only: true,
    notes: 'Locally observable via customer-supplied telemetry: PPPoE / 802.1X-EAPOL / LLDP-CDP / LACP / FHRP control floods appear as link-control event storms and interface-counter spikes on attached hosts.',
  },
  {
    id: 'MON-007',
    name: 'BGP control-plane flood (routing-session observation)',
    catalog_vector_ids: ['NET-042', 'NET-043'],
    reason: 'requires_routing_peer_session',
    domain: 'A1b',
    detection_mode: 'integration_telemetry',
    signal_source: 'BGP session-state / route-churn feed (router telemetry, BMP, or looking-glass export)',
    dependency: 'routing_session_feed_required',
    monitor_only: true,
    notes: 'Detection-only-if-integrated: BGP session-establishment and update/route-churn floods are visible in a BGP/BMP session-state feed; AstraNull cannot form the peering to originate them.',
  },
  {
    id: 'MON-008',
    name: 'IGP / BFD / multicast-routing / MPLS control flood (routing-session observation)',
    catalog_vector_ids: ['NET-044', 'NET-125', 'NET-156', 'NET-157'],
    reason: 'requires_routing_peer_session',
    domain: 'A1b',
    detection_mode: 'integration_telemetry',
    signal_source: 'routing/control-plane session-state feed (OSPF/BFD/PIM/MPLS adjacency + control-packet counters)',
    dependency: 'routing_session_feed_required',
    monitor_only: true,
    notes: 'Detection-only-if-integrated: OSPF adjacency churn, BFD, PIM, and MPLS RSVP-TE/LDP control floods are visible only through a routing-control-plane telemetry feed.',
  },
  {
    id: 'MON-009',
    name: '802.11 management / control-frame flood (wireless-sensor observation)',
    catalog_vector_ids: ['NET-169', 'NET-170', 'NET-171', 'NET-172', 'NET-173', 'NET-174', 'NET-175', 'NET-176'],
    reason: 'requires_rf_proximity',
    domain: 'A1c',
    detection_mode: 'integration_telemetry',
    signal_source: 'WIDS / wireless sensor management- and control-frame telemetry',
    dependency: 'wireless_sensor_required',
    monitor_only: true,
    notes: 'Detection-only-if-integrated: 802.11 assoc/auth/deauth/probe/beacon/RTS-CTS/PS-Poll/BlockACK floods are detectable only where a WIDS or wireless sensor is deployed; most customers lack one, and no SaaS probe can hear the RF.',
  },
  {
    id: 'MON-010',
    name: 'RF jamming / interference denial (spectrum-sensor observation)',
    catalog_vector_ids: ['NET-177'],
    reason: 'requires_rf_proximity',
    domain: 'A1c',
    detection_mode: 'integration_telemetry',
    signal_source: 'spectrum-analysis / RF-interference sensor feed',
    dependency: 'wireless_sensor_required',
    monitor_only: true,
    notes: 'Detection-only-if-integrated: raw RF jamming is a physical-layer effect observable only by a spectrum sensor; without one it is honestly not covered.',
  },
  {
    id: 'MON-011',
    name: 'Mobile user / control-plane flood (mobile-core tap observation)',
    catalog_vector_ids: ['NET-158', 'NET-159', 'NET-179'],
    reason: 'requires_mobile_core_interface',
    domain: 'A1d',
    detection_mode: 'integration_telemetry',
    signal_source: 'mobile-core signalling tap (SGW/PGW/UPF for GTP-U/GTP-C, SMF for PFCP)',
    dependency: 'mobile_core_tap_required',
    monitor_only: true,
    notes: 'Detection-only-if-integrated (telco deployments only): GTP-U/GTP-C/PFCP session and control-plane floods require a mobile-core interface tap that only carrier operators possess.',
  },
  {
    id: 'MON-012',
    name: 'Telecom signalling flood (mobile-core tap observation)',
    catalog_vector_ids: ['NET-178', 'NET-180'],
    reason: 'requires_mobile_core_interface',
    domain: 'A1d',
    detection_mode: 'integration_telemetry',
    signal_source: 'mobile-core signalling tap (Diameter edge/DRA, AMF/MME attach signalling)',
    dependency: 'mobile_core_tap_required',
    monitor_only: true,
    notes: 'Detection-only-if-integrated (telco deployments only): Diameter and mobile-attach signalling floods are visible only on an operator signalling interface.',
  },
];

/**
 * Monitor-only annotation layer over OUT_OF_SCOPE_VECTORS. Tagged E5 (not probeable;
 * derives the same monitor-only tier as NON_DDOS_AVAILABILITY_THREATS). Passive
 * detection only — never an active outside-in probe.
 * @type {readonly MonitorOnlyVectorEntry[]}
 */
export const MONITOR_ONLY_VECTORS = Object.freeze(
  MONITOR_ONLY_VECTORS_SOURCE.map((entry) => Object.freeze({
    ...entry,
    catalog_vector_ids: Object.freeze([...entry.catalog_vector_ids]),
    evidence_tier: 'E5',
  })),
);

const NON_DDOS_AVAILABILITY_THREATS_SOURCE = [
  { id: 'ND-001', name: 'BGP hijacking', classification: 'routing_attack', task_id: 'DET-026', monitor_only: true, scope_boundary: 'Monitor-only integration; out of probe scope. Never conflated with DDoS readiness score.', notes: 'Not resource-exhaustion DDoS; monitor-only integration future.' },
  { id: 'ND-002', name: 'BGP route leak', classification: 'routing_incident', task_id: 'DET-026', monitor_only: true, scope_boundary: 'Monitor-only integration; out of probe scope.' },
  { id: 'ND-003', name: 'DNS hijacking / cache poisoning', classification: 'dns_integrity', task_id: 'DET-026', monitor_only: true, scope_boundary: 'Monitor-only integration; out of probe scope.' },
  { id: 'ND-004', name: 'Control-plane autoscaling cost exhaustion', classification: 'operational_exhaustion', task_id: 'DET-026', check_ids: ['l7.health_check_flood.readiness', 'ops.autoscaling_cost.readiness'], notes: 'Health-check flood triggering scale-out; maps to ATT-109.' },
  { id: 'ND-005', name: 'Alert fatigue / blind spots during attack', classification: 'operational_exhaustion', task_id: 'DET-026', check_ids: ['ops.alert_workflow_marker.safe', 'ops.attack_alert_coverage.readiness'] },
  { id: 'ND-006', name: 'Credential stuffing / brute force', classification: 'authentication_attack', task_id: null, notes: 'Out of scope for DDoS taxonomy; partial overlap l7.login_abuse_flow.safe.' },
  { id: 'ND-007', name: 'Provider control-plane API rate exhaustion', classification: 'operational_exhaustion', task_id: 'DET-026', monitor_only: true, scope_boundary: 'Monitor-only provider-API budget guardrail; no probe.', notes: 'Cloud API throttling during mitigation orchestration.' },
  { id: 'ND-008', name: 'Log / SIEM ingestion cost exhaustion', classification: 'operational_exhaustion', task_id: 'DET-026', monitor_only: true, scope_boundary: 'Monitor-only telemetry-budget guardrail; no probe.', notes: 'Telemetry flood raises observability cost without service outage.' },
  { id: 'ND-009', name: 'Certificate transparency / CT log noise', classification: 'operational_exhaustion', task_id: 'DET-026', monitor_only: true, scope_boundary: 'Monitor-only; out of probe scope.', notes: 'Monitor-only; related to ATT-122 origin leakage.' },
  { id: 'ND-010', name: 'Provider-reported UDS reflection signal', domain: 'A2', exhausted_resource: 'reflection', catalog_vector_ids: ['AMP-073'], task_id: 'DET-026', notes: 'Monitor-only provider taxonomy signal; no generic outside-in payload is defined.', check_ids: [], classification: 'reflection_incident', monitor_only: true, scope_boundary: 'Monitor-only provider taxonomy signal; no generic outside-in payload is defined.' },
  { id: 'ND-011', name: 'Autoscaling thrash exhaustion', domain: 'A4a', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-048'], task_id: 'DET-026', notes: 'Monitor service scaling oscillation and cost-budget telemetry from customer-supplied feeds; no cloud credentials are required.', check_ids: [], classification: 'operational_exhaustion', monitor_only: true, scope_boundary: 'Monitor service scaling oscillation and cost-budget telemetry from customer-supplied feeds; no cloud credentials are required.' },
  { id: 'ND-012', name: 'Log, trace, and telemetry exhaustion', domain: 'A4a', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-139'], task_id: 'DET-026', notes: 'Monitor observability pipeline volume, queue, drop, and cost-budget telemetry from customer-supplied feeds.', check_ids: [], classification: 'operational_exhaustion', monitor_only: true, scope_boundary: 'Monitor observability pipeline volume, queue, drop, and cost-budget telemetry from customer-supplied feeds.' },
];

export const NON_DDOS_AVAILABILITY_THREATS = Object.freeze(
  NON_DDOS_AVAILABILITY_THREATS_SOURCE.map((entry) => ({
    ...entry,
    catalog_vector_ids: [...(entry.catalog_vector_ids ?? REGISTRY_CATALOG_VECTOR_IDS[entry.id] ?? [])],
    evidence_tier: 'E5',
  })),
);

/** @type {readonly AttackVectorEntry[]} */
const ATTACK_VECTOR_REGISTRY_SOURCE = [
  // --- L3/L4 volumetric & packet processing ---
  { id: 'ATT-001', name: 'UDP flood', exhausted_resource: 'volumetric', task_id: 'DET-017', check_ids: ['l3.forbidden_udp_port.safe', 'high_scale.volumetric.request_only'], notes: 'Single-datagram probe + SOC volumetric marker; no flood generator in repo.' },
  { id: 'ATT-002', name: 'ICMP / ping flood', exhausted_resource: 'volumetric', task_id: 'DET-017', check_ids: ['l3.icmp_flood.readiness', 'high_scale.volumetric.request_only'], notes: 'Bounded readiness posture + SOC volumetric scenario; no flood generator in repo.' },
  { id: 'ATT-003', name: 'SYN flood', exhausted_resource: 'state_exhaustion', task_id: 'DET-017', check_ids: ['l3.forbidden_tcp_port.safe', 'l3.basic_deny_rule.safe', 'l3.syn_flood.readiness', 'l3.connection_table_exhaustion.request_only', 'high_scale.volumetric.request_only'] },
  { id: 'ATT-004', name: 'ACK flood', exhausted_resource: 'packet_processing', task_id: 'DET-017', check_ids: ['l3.ack_flood.readiness'], notes: 'Readiness posture via declared PPS policy and external probe evidence; execution is SOC-gated.' },
  { id: 'ATT-005', name: 'SYN-ACK flood', exhausted_resource: 'packet_processing', task_id: 'DET-017', check_ids: ['l3.syn_ack_flood.readiness'] },
  { id: 'ATT-006', name: 'RST flood', exhausted_resource: 'packet_processing', task_id: 'DET-017', check_ids: ['l3.rst_flood.readiness'] },
  { id: 'ATT-007', name: 'TCP flag floods (FIN/PSH/URG/NULL/Xmas)', exhausted_resource: 'packet_processing', task_id: 'DET-017', check_ids: ['l3.tcp_flag_anomaly.readiness'] },
  { id: 'ATT-008', name: 'TCP connection flood', exhausted_resource: 'state_exhaustion', task_id: 'DET-017', check_ids: ['l3.connection_table_exhaustion.request_only', 'l3.tcp_connection_flood.readiness'] },
  { id: 'ATT-009', name: 'Out-of-state TCP flood', exhausted_resource: 'packet_processing', task_id: 'DET-017', check_ids: ['l3.out_of_state_tcp.readiness'] },
  { id: 'ATT-010', name: 'Fragmentation flood', exhausted_resource: 'packet_processing', task_id: 'DET-017', check_ids: ['l3.fragmentation_flood.readiness'] },
  { id: 'ATT-011', name: 'Ping of Death', exhausted_resource: 'exploit_dos', task_id: 'DET-017', check_ids: ['exploit.ping_of_death.posture'], notes: 'Patch/filtering posture only; exploit validation is isolated-lab SOC scope.' },
  { id: 'ATT-012', name: 'Teardrop', exhausted_resource: 'exploit_dos', task_id: 'DET-017', check_ids: ['exploit.teardrop.posture'] },
  { id: 'ATT-013', name: 'GRE flood', exhausted_resource: 'volumetric', task_id: 'DET-017', check_ids: ['l3.gre_esp_flood.readiness', 'high_scale.volumetric.request_only'] },
  { id: 'ATT-014', name: 'ESP / IPsec flood', exhausted_resource: 'packet_processing', task_id: 'DET-017', check_ids: ['l3.gre_esp_flood.readiness'] },
  { id: 'ATT-015', name: 'QUIC flood', exhausted_resource: 'volumetric', task_id: 'DET-021', check_ids: ['protocol.http3_quic_exposure.safe', 'high_scale.volumetric.request_only'] },

  // --- Reflection / amplification (16–40) ---
  { id: 'ATT-016', name: 'DNS reflection/amplification', exhausted_resource: 'amplification', task_id: 'DET-018', check_ids: ['dns.amplification_exposure.safe'] },
  { id: 'ATT-017', name: 'NTP amplification', exhausted_resource: 'amplification', task_id: 'DET-018', check_ids: ['amp.ntp_exposure.safe'], notes: 'Config/mode-6-7 restriction posture metadata; no amplifier query traffic.' },
  { id: 'ATT-018', name: 'CLDAP amplification', exhausted_resource: 'amplification', task_id: 'DET-018', check_ids: ['amp.cldap_exposure.safe'], notes: 'Exposed-LDAP posture metadata only.' },
  { id: 'ATT-019', name: 'Memcached amplification', exhausted_resource: 'amplification', task_id: 'DET-018', check_ids: ['amp.memcached_exposure.safe'], notes: 'One bounded TCP connect exposure check; no UDP memcached query.' },
  { id: 'ATT-020', name: 'SSDP/UPnP and device-discovery reflection', exhausted_resource: 'reflection', task_id: 'DET-018', check_ids: ['reflect.ssdp_exposure.safe', 'reflect.legacy_device_discovery_exposure.safe'], notes: 'Single bounded UDP fingerprint on declared host; response size class metadata only. Device-management discovery classes (Ubiquiti, Lantronix, VxWorks/WDBRPC) covered by the legacy discovery check.' },
  { id: 'ATT-021', name: 'SNMP reflection', exhausted_resource: 'reflection', task_id: 'DET-018', check_ids: ['reflect.snmp_exposure.safe'] },
  { id: 'ATT-022', name: 'CHARGEN/QOTD/Echo reflection', exhausted_resource: 'reflection', task_id: 'DET-018', check_ids: ['reflect.chargen_qotd_exposure.safe'] },
  { id: 'ATT-023', name: 'mDNS / NetBIOS / WS-Discovery reflection', exhausted_resource: 'reflection', task_id: 'DET-018', check_ids: ['reflect.mdns_netbios_wsdiscovery_exposure.safe'] },
  { id: 'ATT-024', name: 'Portmap/RIPv1/BitTorrent/Jenkins/TeamSpeak reflectors', exhausted_resource: 'reflection', task_id: 'DET-018', check_ids: ['reflect.portmap_service_exposure.safe', 'reflect.jenkins_discovery_exposure.safe', 'reflect.legacy_device_discovery_exposure.safe'], notes: 'Portmapper/RIPv1/RPC via the service-exposure check; Jenkins via discovery; TeamSpeak 3 and game/voice discovery via the legacy discovery check.' },
  { id: 'ATT-025', name: 'DTLS / SIP / RDP / TFTP / ARMS / CoAP reflection', exhausted_resource: 'reflection', task_id: 'DET-018', check_ids: ['reflect.dtls_sip_rdp_tftp_exposure.safe'] },
  { id: 'ATT-026', name: 'QUIC reflection', exhausted_resource: 'reflection', task_id: 'DET-018', check_ids: ['reflect.quic_reflection_exposure.safe'] },
  { id: 'ATT-027', name: 'TCP middlebox reflection', exhausted_resource: 'reflection', task_id: 'DET-018', check_ids: ['reflect.tcp_middlebox_exposure.safe'] },

  // --- DNS exhaustion (41–50) ---
  { id: 'ATT-041', name: 'DNS query flood', exhausted_resource: 'dns_exhaustion', task_id: 'DET-019', check_ids: ['dns.authoritative_response.safe', 'high_scale.dns_high_query.request_only'] },
  { id: 'ATT-042', name: 'DNS amplification (authoritative/resolver)', exhausted_resource: 'amplification', task_id: 'DET-019', check_ids: ['dns.amplification_exposure.safe', 'dns.open_recursion_behavior.safe', 'amp.authoritative_resolver_exposure.safe', 'dns.qname_minimization.readiness'] },
  { id: 'ATT-043', name: 'NXDOMAIN flood', exhausted_resource: 'dns_exhaustion', task_id: 'DET-019', check_ids: ['dns.random_prefix_nxdomain.safe'] },
  { id: 'ATT-044', name: 'Random-subdomain / water-torture', exhausted_resource: 'dns_exhaustion', task_id: 'DET-019', check_ids: ['dns.random_prefix_nxdomain.safe'] },
  { id: 'ATT-045', name: 'DNS laundering', exhausted_resource: 'dns_exhaustion', task_id: 'DET-019', check_ids: ['dns.laundering.readiness'], notes: 'Readiness posture via declared resolver policy; no laundering query sequences.' },
  { id: 'ATT-046', name: 'DNS garbage flood', exhausted_resource: 'dns_exhaustion', task_id: 'DET-019', check_ids: ['dns.garbage_flood.readiness'] },
  { id: 'ATT-047', name: 'Phantom domain attack', exhausted_resource: 'dns_exhaustion', task_id: 'DET-019', check_ids: ['dns.phantom_domain.readiness'] },
  { id: 'ATT-048', name: 'DNS domain lock-up', exhausted_resource: 'dns_exhaustion', task_id: 'DET-019', check_ids: ['dns.domain_lockup.readiness'] },
  { id: 'ATT-049', name: 'NXNSAttack', exhausted_resource: 'dns_exhaustion', task_id: 'DET-019', check_ids: ['dns.nxns_attack.readiness'], notes: 'Bounded NS delegation lookup of declared zone; no referral flood.' },
  { id: 'ATT-050', name: 'DNSBomb', exhausted_resource: 'dns_exhaustion', task_id: 'DET-019', check_ids: ['dns.dnsbomb.readiness'], notes: 'Pulsed TTL / deferred-response posture metadata + provider telemetry.' },

  // --- L7 / application (51–75) ---
  { id: 'ATT-051', name: 'HTTP GET flood', exhausted_resource: 'application_l7', task_id: 'DET-020', check_ids: ['l7.http_method_restriction.safe', 'l7.low_rate_rate_limit.safe', 'l7.http_get_flood.validation', 'high_scale.application.request_only'] },
  { id: 'ATT-052', name: 'HTTP POST flood', exhausted_resource: 'application_l7', task_id: 'DET-020', check_ids: ['l7.http_post_flood.validation', 'high_scale.application.request_only'], notes: 'Declared-endpoint limit readiness; POST flood execution is SOC-gated.' },
  { id: 'ATT-053', name: 'HTTP HEAD flood', exhausted_resource: 'application_l7', task_id: 'DET-020', check_ids: ['l7.http_method_restriction.safe'] },
  { id: 'ATT-054', name: 'Dynamic-endpoint / computational DDoS', exhausted_resource: 'computational', task_id: 'DET-020', check_ids: ['l7.expensive_endpoint.safe', 'l7.graphql_complexity.safe'] },
  { id: 'ATT-055', name: 'Database exhaustion attack', exhausted_resource: 'backend_exhaustion', task_id: 'DET-020', check_ids: ['l7.api_quota_exhaustion.safe', 'l7.graphql_complexity.safe'] },
  {
    id: 'ATT-056',
    name: 'API flood',
    exhausted_resource: 'application_l7',
    task_id: 'DET-020',
    check_ids: [
      'l7.api_surface_scan.safe',
      'l7.api_quota_exhaustion.safe',
    ],
  },
  { id: 'ATT-057', name: 'GraphQL exhaustion', exhausted_resource: 'backend_exhaustion', task_id: 'DET-020', check_ids: ['l7.graphql_complexity.safe'] },
  { id: 'ATT-058', name: 'Cache-busting DDoS', exhausted_resource: 'application_l7', task_id: 'DET-020', check_ids: ['l7.cache_busting.safe'] },
  { id: 'ATT-059', name: 'Large-payload POST', exhausted_resource: 'memory_exhaustion', task_id: 'DET-020', check_ids: ['l7.header_size_boundary.safe', 'l7.large_body_post.readiness'] },
  { id: 'ATT-060', name: 'Slowloris', exhausted_resource: 'memory_exhaustion', task_id: 'DET-020', check_ids: ['tls.slow_header_body_timeout.safe', 'l7.slowloris.readiness'], notes: 'Timeout policy + header-drain readiness; no sustained partial headers hold.' },
  { id: 'ATT-061', name: 'Slow POST / RUDY', exhausted_resource: 'memory_exhaustion', task_id: 'DET-020', check_ids: ['l7.slow_post.readiness'] },
  { id: 'ATT-062', name: 'Slow read', exhausted_resource: 'memory_exhaustion', task_id: 'DET-020', check_ids: ['l7.slow_read.readiness'] },
  { id: 'ATT-063', name: 'Generic low-and-slow DDoS', exhausted_resource: 'memory_exhaustion', task_id: 'DET-020', check_ids: ['l7.low_and_slow.readiness'] },
  { id: 'ATT-064', name: 'TLS handshake / SSL negotiation exhaustion', exhausted_resource: 'computational', task_id: 'DET-020', check_ids: ['tls.full_audit.safe', 'tls.profile_exposure.safe', 'tls.handshake_rate.readiness'] },
  { id: 'ATT-065', name: 'TLS renegotiation attacks', exhausted_resource: 'computational', task_id: 'DET-020', check_ids: ['tls.renegotiation.readiness'] },
  { id: 'ATT-066', name: 'HTTP/2 multiplexing flood', exhausted_resource: 'application_l7', task_id: 'DET-021', check_ids: ['protocol.http2_stream_concurrency.safe'] },
  { id: 'ATT-067', name: 'HTTP/2 Rapid Reset', exhausted_resource: 'computational', task_id: 'DET-021', check_ids: ['protocol.http2_rapid_reset_readiness.safe', 'l7.http2_rapid_reset.validation'], notes: 'Bounded SETTINGS/reset-policy validation; reset-storm execution is SOC-gated.' },
  { id: 'ATT-068', name: 'HTTP/2 CONTINUATION flood', exhausted_resource: 'memory_exhaustion', task_id: 'DET-021', check_ids: ['l7.http2_continuation.readiness'], notes: 'Header-frame limit readiness via bounded HTTP/2 SETTINGS probe.' },
  { id: 'ATT-069', name: 'HTTP/2 MadeYouReset', exhausted_resource: 'computational', task_id: 'DET-021', check_ids: ['l7.http2_made_you_reset.readiness'], notes: 'CVE-2025-8671 class readiness via settings/flow-control metadata.' },
  { id: 'ATT-070', name: 'HTTP/3 / QUIC application flood', exhausted_resource: 'application_l7', task_id: 'DET-021', check_ids: ['protocol.http3_quic_exposure.safe', 'high_scale.application.request_only'] },
  { id: 'ATT-071', name: 'WebSocket DDoS', exhausted_resource: 'memory_exhaustion', task_id: 'DET-021', check_ids: ['protocol.websocket_connection_controls.safe', 'protocol.websocket_message_rate.readiness'] },
  { id: 'ATT-072', name: 'gRPC / RPC floods', exhausted_resource: 'application_l7', task_id: 'DET-021', check_ids: ['protocol.grpc_reflection_stream.safe'], notes: 'Bounded single gRPC health/reflection reachability probe; stream flood execution is SOC-gated.' },
  { id: 'ATT-073', name: 'WordPress XML-RPC / pingback DDoS', exhausted_resource: 'application_l7', task_id: 'DET-020', check_ids: ['l7.wordpress_xmlrpc.readiness'] },
  { id: 'ATT-074', name: 'SIP / VoIP flood', exhausted_resource: 'volumetric', task_id: 'DET-017', check_ids: ['l3.sip_voip_flood.readiness', 'high_scale.volumetric.request_only'] },
  { id: 'ATT-075', name: 'Application connection exhaustion', exhausted_resource: 'state_exhaustion', task_id: 'DET-020', check_ids: ['tls.idle_connection_timeout.safe', 'l3.connection_table_exhaustion.request_only', 'l7.connection_hoarding.readiness'] },

  // --- Delivery patterns ---
  { id: 'ATT-090', name: 'Direct flood', exhausted_resource: 'delivery_pattern', task_id: 'DET-022', delivery_patterns: ['direct'], check_ids: ['high_scale.volumetric.request_only'] },
  { id: 'ATT-091', name: 'Spoofed flood', exhausted_resource: 'delivery_pattern', task_id: 'DET-022', delivery_patterns: ['spoofed'], check_ids: ['pattern.spoofed_source.readiness'], notes: 'BCP38/uRPF ingress-filtering readiness posture.' },
  { id: 'ATT-092', name: 'DRDoS / reflection delivery', exhausted_resource: 'delivery_pattern', task_id: 'DET-022', delivery_patterns: ['drdos'], check_ids: ['dns.amplification_exposure.safe'] },
  { id: 'ATT-093', name: 'Coordinated Device Swarm DDoS (docs: ATT-093)', exhausted_resource: 'delivery_pattern', task_id: 'DET-022', delivery_patterns: ['coordinated_swarm'], check_ids: ['high_scale.multi_vector.request_only'] },
  { id: 'ATT-094', name: 'Carpet bombing', exhausted_resource: 'delivery_pattern', task_id: 'DET-022', delivery_patterns: ['carpet_bombing'], check_ids: ['pattern.carpet_bombing.readiness'], notes: 'Multi-port/multi-destination scrubbing readiness; execution is SOC-gated.' },
  { id: 'ATT-095', name: 'Pulse-wave / burst attacks', exhausted_resource: 'delivery_pattern', task_id: 'DET-022', delivery_patterns: ['pulse_wave'], check_ids: ['pattern.pulse_wave.readiness'] },
  { id: 'ATT-096', name: 'Multi-vector / vector switching', exhausted_resource: 'delivery_pattern', task_id: 'DET-022', delivery_patterns: ['multi_vector'], check_ids: ['high_scale.multi_vector.request_only'] },
  { id: 'ATT-097', name: 'Application-aware targeting', exhausted_resource: 'delivery_pattern', task_id: 'DET-022', delivery_patterns: ['application_aware'], check_ids: ['l7.expensive_endpoint.safe'] },

  // --- Origin / edge (readiness, not numbered in user list) ---
  { id: 'ATT-100', name: 'Direct origin bypass', exhausted_resource: 'application_l7', task_id: 'DET-001', check_ids: ['origin.direct_bypass.safe', 'origin.direct_reachability.safe', 'origin.host_sni_bypass.safe'] },
  { id: 'ATT-101', name: 'Origin leak scan', exhausted_resource: 'application_l7', task_id: 'DET-001', check_ids: ['origin.leak_scan.safe'] },
  { id: 'ATT-102', name: 'WAF marker / enforcement', exhausted_resource: 'application_l7', task_id: 'DET-007', check_ids: ['waf.marker_rule.safe', 'waf.enforcement.safe', 'l7.waf_marker_rule.safe'] },

  // --- Gap analysis: documented elsewhere but missing from initial registry ---
  { id: 'ATT-103', name: 'CDN / shield bypass', exhausted_resource: 'application_l7', task_id: 'DET-001', check_ids: ['origin.direct_bypass.safe', 'origin.host_sni_bypass.safe', 'origin.cdn_bypass.readiness'] },
  { id: 'ATT-104', name: 'SSE long-lived stream exhaustion', exhausted_resource: 'memory_exhaustion', task_id: 'DET-021', check_ids: ['protocol.sse_stream.readiness'], notes: 'SSE duration/connection-limit readiness metadata.' },
  { id: 'ATT-105', name: 'Search endpoint abuse', exhausted_resource: 'backend_exhaustion', task_id: 'DET-020', check_ids: ['l7.search_abuse.validation'], notes: 'Declared search endpoint low-rate sequence validation.' },
  { id: 'ATT-106', name: 'Export / report generation abuse', exhausted_resource: 'backend_exhaustion', task_id: 'DET-020', check_ids: ['l7.export_abuse.validation'] },
  { id: 'ATT-107', name: 'Batch API abuse', exhausted_resource: 'backend_exhaustion', task_id: 'DET-020', check_ids: ['l7.batch_api_abuse.validation'] },
  { id: 'ATT-108', name: 'Webhook / callback flood', exhausted_resource: 'application_l7', task_id: 'DET-020', check_ids: ['l7.webhook_flood.readiness'] },
  { id: 'ATT-109', name: 'Health-check endpoint flood', exhausted_resource: 'application_l7', task_id: 'DET-026', check_ids: ['l7.health_check_flood.readiness'], notes: 'Can trigger autoscaling cost exhaustion (ND-004).' },
  { id: 'ATT-110', name: 'HTTP/2 priority tree abuse', exhausted_resource: 'computational', task_id: 'DET-021', check_ids: ['l7.http2_priority_abuse.readiness'] },
  { id: 'ATT-111', name: 'TLS 0-RTT / early data abuse', exhausted_resource: 'computational', task_id: 'DET-020', check_ids: ['tls.zero_rtt.readiness'] },
  { id: 'ATT-112', name: 'OAuth / token endpoint abuse', exhausted_resource: 'backend_exhaustion', task_id: 'DET-020', check_ids: ['l7.login_abuse_flow.safe', 'l7.api_quota_exhaustion.safe', 'l7.oauth_token_abuse.validation'] },
  { id: 'ATT-113', name: 'File upload flood', exhausted_resource: 'memory_exhaustion', task_id: 'DET-020', check_ids: ['l7.file_upload_abuse.readiness'] },
  { id: 'ATT-114', name: 'GraphQL batch / alias abuse', exhausted_resource: 'backend_exhaustion', task_id: 'DET-020', check_ids: ['l7.graphql_complexity.safe', 'l7.graphql_batch_abuse.validation'], notes: 'Depth/complexity plus batch-limit readiness.' },
  { id: 'ATT-115', name: 'DNS ANY/TXT query class abuse', exhausted_resource: 'amplification', task_id: 'DET-019', check_ids: ['dns.amplification_exposure.safe', 'dns.dnssec_expensive_query.safe', 'amp.dns_any_txt_exposure.safe'] },
  { id: 'ATT-116', name: 'MSSQL resolver reflection', exhausted_resource: 'reflection', task_id: 'DET-018', check_ids: ['reflect.mssql_resolver_exposure.safe'] },
  { id: 'ATT-117', name: 'Jenkins / CI discovery reflection', exhausted_resource: 'reflection', task_id: 'DET-018', check_ids: ['reflect.jenkins_discovery_exposure.safe'] },
  { id: 'ATT-118', name: 'CoAP / IoT device-management reflector abuse', exhausted_resource: 'reflection', task_id: 'DET-018', check_ids: ['reflect.coap_iot_exposure.safe', 'reflect.legacy_device_discovery_exposure.safe'], notes: 'CoAP plus embedded device-management discovery classes (Lantronix, VxWorks/WDBRPC) via the legacy discovery check.' },
  { id: 'ATT-119', name: 'IP options / malformed IP header abuse', exhausted_resource: 'exploit_dos', task_id: 'DET-017', check_ids: ['exploit.ip_options.posture'] },
  { id: 'ATT-120', name: 'Malformed QUIC version / spin bit abuse', exhausted_resource: 'exploit_dos', task_id: 'DET-021', check_ids: ['exploit.malformed_quic.posture'] },
  { id: 'ATT-121', name: 'Adaptive / randomized flood (entropy evasion)', exhausted_resource: 'delivery_pattern', task_id: 'DET-022', delivery_patterns: ['adaptive_evasion'], check_ids: ['pattern.adaptive_evasion.readiness'] },
  { id: 'ATT-122', name: 'Certificate / SAN origin leakage', exhausted_resource: 'application_l7', task_id: 'DET-001', check_ids: ['origin.leak_scan.safe', 'tls.profile_exposure.safe'] },
  { id: 'ATT-123', name: 'SMTP / email connection flood', exhausted_resource: 'state_exhaustion', task_id: 'DET-020', check_ids: ['l3.smtp_connection_flood.readiness'] },
  { id: 'ATT-124', name: 'IPv6 volumetric flood (beyond reachability check)', exhausted_resource: 'volumetric', task_id: 'DET-017', check_ids: ['l3.ipv6_reachability.safe', 'l3.ipv6_volumetric.readiness'], notes: 'Reachability plus IPv6 filtering readiness; no volumetric execution.' },
  { id: 'ATT-125', name: 'NAT / firewall state table exhaustion', exhausted_resource: 'state_exhaustion', task_id: 'DET-017', check_ids: ['l3.nat_state_table.readiness'] },
  { id: 'ATT-098', name: 'Ransom DDoS (extortion workflow)', exhausted_resource: 'delivery_pattern', task_id: 'DET-022', delivery_patterns: ['ransom'], check_ids: ['pattern.ransom_ddos.readiness'], notes: 'Extortion runbook readiness marker; SOC workflow + audit; not a probe vector.' },
  { id: 'ATT-099', name: 'Multi-destination / multi-service simultaneous attack', exhausted_resource: 'delivery_pattern', task_id: 'DET-022', delivery_patterns: ['multi_destination'], check_ids: ['high_scale.multi_vector.request_only'] },

  // --- Origin / edge exposure (enables direct-path DDoS) ---
  { id: 'ATT-126', name: 'Stale DNS / legacy subdomain origin leak', exhausted_resource: 'application_l7', task_id: 'DET-001', check_ids: ['origin.leak_scan.safe'] },
  { id: 'ATT-127', name: 'DNS-only hostname bypass', exhausted_resource: 'application_l7', task_id: 'DET-001', check_ids: ['origin.dns_hostname_bypass.readiness'], notes: 'DNS alias/hostname coverage readiness; no dedicated bypass probe.' },
  { id: 'ATT-128', name: 'Protected canary path bypass', exhausted_resource: 'application_l7', task_id: 'DET-001', check_ids: ['path.protected_canary.safe'] },
  { id: 'ATT-129', name: 'Admin / management surface exposure', exhausted_resource: 'application_l7', task_id: 'DET-001', check_ids: ['l3.firewall_exposure_scan.safe'], notes: 'Port scan finds admin surfaces; not admin-specific check.' },
  { id: 'ATT-130', name: 'Ephemeral port / accidental service exposure', exhausted_resource: 'application_l7', task_id: 'DET-017', check_ids: ['l3.firewall_exposure_scan.safe'] },
  { id: 'ATT-131', name: 'WAF-to-origin bypass path', exhausted_resource: 'application_l7', task_id: 'DET-001', check_ids: ['waf.origin_bypass.safe', 'origin.direct_bypass.safe'] },
  { id: 'ATT-132', name: 'HTTP TRACE / unusual method abuse', exhausted_resource: 'application_l7', task_id: 'DET-020', check_ids: ['l7.http_method_restriction.safe'] },

  // --- L3/L4 extended ---
  { id: 'ATT-133', name: 'Land attack (same src/dst IP)', exhausted_resource: 'exploit_dos', task_id: 'DET-017', check_ids: ['exploit.land_attack.posture'] },
  { id: 'ATT-134', name: 'Smurf / ICMP-to-broadcast amplification', exhausted_resource: 'amplification', task_id: 'DET-018', check_ids: ['amp.smurf_broadcast_exposure.safe'], notes: 'Directed-broadcast filtering posture metadata.' },
  { id: 'ATT-135', name: 'SCTP flood', exhausted_resource: 'volumetric', task_id: 'DET-017', check_ids: ['l3.sctp_exposure.readiness'] },
  { id: 'ATT-136', name: 'IKE / IPsec negotiation flood', exhausted_resource: 'state_exhaustion', task_id: 'DET-017', check_ids: ['l3.ike_ipsec_negotiation.readiness'] },
  { id: 'ATT-137', name: 'Multicast / broadcast storm', exhausted_resource: 'volumetric', task_id: 'DET-017', check_ids: ['l3.multicast_broadcast_storm.readiness'] },
  { id: 'ATT-138', name: 'SSH connection flood', exhausted_resource: 'state_exhaustion', task_id: 'DET-020', check_ids: ['l3.ssh_connection_flood.readiness'] },
  { id: 'ATT-139', name: 'FTP connection flood', exhausted_resource: 'state_exhaustion', task_id: 'DET-020', check_ids: ['l3.ftp_connection_flood.readiness'] },

  // --- L7 extended ---
  { id: 'ATT-140', name: 'HTTP pipelining abuse', exhausted_resource: 'application_l7', task_id: 'DET-020', check_ids: ['l7.http_pipelining.readiness'] },
  { id: 'ATT-141', name: 'HTTP Range header abuse', exhausted_resource: 'application_l7', task_id: 'DET-020', check_ids: ['l7.http_range_abuse.readiness'] },
  { id: 'ATT-142', name: 'HTTP conditional revalidation flood (If-None-Match/IMS)', exhausted_resource: 'application_l7', task_id: 'DET-020', check_ids: ['l7.conditional_revalidation.readiness'] },
  { id: 'ATT-143', name: 'Checkout / cart transaction abuse', exhausted_resource: 'backend_exhaustion', task_id: 'DET-020', check_ids: ['l7.checkout_abuse.validation'], notes: 'Customer-declared endpoint only.' },
  { id: 'ATT-144', name: 'OTP / SMS cost exhaustion', exhausted_resource: 'backend_exhaustion', task_id: 'DET-020', check_ids: ['l7.login_abuse_flow.safe', 'l7.otp_sms_cost.readiness'] },
  { id: 'ATT-145', name: 'CAPTCHA / challenge endpoint abuse', exhausted_resource: 'application_l7', task_id: 'DET-020', check_ids: ['l7.bot_challenge_marker.safe', 'l7.captcha_challenge_abuse.readiness'] },
  { id: 'ATT-146', name: 'Distributed low-rate / residential proxy flood', exhausted_resource: 'delivery_pattern', task_id: 'DET-022', delivery_patterns: ['residential_proxy'], check_ids: ['pattern.residential_proxy.readiness'] },

  // --- Computational / parser bombs ---
  { id: 'ATT-147', name: 'ReDoS / regex algorithmic complexity', exhausted_resource: 'computational', task_id: 'DET-020', check_ids: ['l7.redos.readiness'] },
  { id: 'ATT-148', name: 'JSON bomb / deeply nested payload', exhausted_resource: 'memory_exhaustion', task_id: 'DET-020', check_ids: ['l7.json_xml_bomb.readiness'] },
  { id: 'ATT-149', name: 'XML bomb / entity expansion (billion laughs class)', exhausted_resource: 'memory_exhaustion', task_id: 'DET-020', check_ids: ['l7.json_xml_bomb.readiness'] },
  { id: 'ATT-150', name: 'HPACK decompression bomb', exhausted_resource: 'memory_exhaustion', task_id: 'DET-021', check_ids: ['l7.hpack_bomb.readiness'] },
  { id: 'ATT-151', name: 'HTTP/2 push promise abuse', exhausted_resource: 'memory_exhaustion', task_id: 'DET-021', check_ids: ['l7.http2_push_promise.readiness'] },
  { id: 'ATT-152', name: 'QPACK / HTTP/3 header compression bomb', exhausted_resource: 'computational', task_id: 'DET-021', check_ids: ['l7.qpack_bomb.readiness'] },
  { id: 'ATT-153', name: 'HTTP/3 control stream / SETTINGS flood', exhausted_resource: 'application_l7', task_id: 'DET-021', check_ids: ['protocol.http3_control_stream.readiness'] },
  { id: 'ATT-154', name: 'QUIC migration / path validation abuse', exhausted_resource: 'exploit_dos', task_id: 'DET-021', check_ids: ['exploit.quic_migration.posture'] },
  { id: 'ATT-155', name: 'OCSP stapling / certificate validation exhaustion', exhausted_resource: 'computational', task_id: 'DET-020', check_ids: ['tls.ocsp_stapling.readiness'] },
  { id: 'ATT-156', name: 'Cipher suite negotiation exhaustion', exhausted_resource: 'computational', task_id: 'DET-020', check_ids: ['tls.full_audit.safe', 'tls.profile_exposure.safe'] },

  // --- Backend / signup ---
  { id: 'ATT-157', name: 'Signup / registration flood', exhausted_resource: 'backend_exhaustion', task_id: 'DET-020', check_ids: ['l7.login_abuse_flow.safe', 'l7.signup_registration_abuse.validation'] },
  { id: 'ATT-158', name: 'Password reset OTP flood', exhausted_resource: 'backend_exhaustion', task_id: 'DET-020', check_ids: ['l7.password_reset.safe'] },

  // --- DNS extended ---
  { id: 'ATT-159', name: 'DNS over HTTPS/TLS (DoH/DoT) query exhaustion', exhausted_resource: 'dns_exhaustion', task_id: 'DET-019', check_ids: ['dns.doh_dot_exposure.readiness'] },
  { id: 'ATT-160', name: 'DNS TCP fallback / truncation pressure', exhausted_resource: 'dns_exhaustion', task_id: 'DET-019', check_ids: ['dns.tcp_fallback.readiness'] },
  { id: 'ATT-161', name: 'DNS zone walking / enumeration at scale', exhausted_resource: 'dns_exhaustion', task_id: 'DET-019', check_ids: ['dns.zone_transfer_exposure.safe', 'dns.zone_walking.readiness'], notes: 'AXFR plus NSEC walking posture.' },
  { id: 'ATT-162', name: 'DNS secondary failover stress', exhausted_resource: 'dns_exhaustion', task_id: 'DET-019', check_ids: ['dns.secondary_failover.safe'] },

  // --- Reflection / protocol extended ---
  { id: 'ATT-163', name: 'STUN/TURN reflection', exhausted_resource: 'reflection', task_id: 'DET-018', check_ids: ['reflect.stun_turn_exposure.safe'] },
  { id: 'ATT-164', name: 'IPMI / BMC reflector exposure', exhausted_resource: 'reflection', task_id: 'DET-018', check_ids: ['reflect.ipmi_bmc_exposure.safe'] },
  { id: 'ATT-165', name: 'Redis direct protocol flood', exhausted_resource: 'reflection', task_id: 'DET-018', check_ids: ['reflect.redis_direct_exposure.safe'], notes: 'Open Redis exposure metadata via one bounded TCP connect; not Memcached amp.' },
  { id: 'ATT-166', name: 'Elasticsearch / OpenSearch query flood', exhausted_resource: 'backend_exhaustion', task_id: 'DET-020', check_ids: ['l7.elasticsearch_abuse.readiness'] },
  { id: 'ATT-167', name: 'MQTT broker flood', exhausted_resource: 'application_l7', task_id: 'DET-020', check_ids: ['l7.mqtt_broker_exposure.readiness'] },
  { id: 'ATT-168', name: 'OpenVPN / WireGuard reflector exposure', exhausted_resource: 'reflection', task_id: 'DET-018', check_ids: ['reflect.openvpn_wireguard_exposure.safe'] },

  // --- Delivery / operational ---
  { id: 'ATT-169', name: 'API scraping / enumeration at scale', exhausted_resource: 'delivery_pattern', task_id: 'DET-022', delivery_patterns: ['api_scraping'], check_ids: ['l7.api_surface_scan.safe'] },
  { id: 'ATT-170', name: 'WAF bypass enabling volumetric success', exhausted_resource: 'application_l7', task_id: 'DET-001', check_ids: ['waf.fingerprint.safe', 'waf.enforcement.safe', 'waf.marker_rule.safe'] },
  { id: 'ATT-171', name: 'Kill-switch / runbook failure under attack load', exhausted_resource: 'delivery_pattern', task_id: 'DET-026', delivery_patterns: ['recovery_drill'], check_ids: ['ops.kill_switch_drill.safe', 'ops.kill_switch_drill.request_only', 'ops.runbook_contact_validation.safe', 'ops.runbook_contact_validation.request_only'] },
  { id: 'ATT-172', name: 'Provider telemetry blind spot during test', exhausted_resource: 'delivery_pattern', task_id: 'DET-026', check_ids: ['ops.provider_telemetry.request_only', 'ops.attack_alert_coverage.readiness'] },
  { id: 'ATT-173', name: 'Post-attack degradation / recovery drill', exhausted_resource: 'delivery_pattern', task_id: 'DET-022', delivery_patterns: ['recovery_drill'], check_ids: ['high_scale.degradation_recovery.request_only'] },
  { id: 'ATT-174', name: 'CORS misconfiguration enabling cross-origin abuse', exhausted_resource: 'application_l7', task_id: 'DET-020', check_ids: ['l7.cors_posture.safe'], notes: 'Configuration exposure; enables browser-origin abuse patterns.' },
  { id: 'ATT-175', name: 'Rate-limit evasion via header/IP rotation', exhausted_resource: 'delivery_pattern', task_id: 'DET-022', delivery_patterns: ['rate_limit_evasion'], check_ids: ['l7.low_rate_rate_limit.safe', 'waf.low_rate_limit.safe', 'pattern.rate_limit_evasion.readiness'] },
  { id: 'ATT-176', name: 'HTTP/2 general protocol readiness gap', exhausted_resource: 'application_l7', task_id: 'DET-021', check_ids: ['protocol.http2_readiness.safe'] },
  { id: 'ATT-028', name: 'IP protocol and empty-payload floods', domain: 'A1a', exhausted_resource: 'packet_processing', catalog_vector_ids: ['NET-004', 'NET-005', 'NET-006'], task_id: 'DET-017', notes: 'needs a governed raw-IP packet client with protocol-field and payload controls', check_ids: [] },
  { id: 'ATT-029', name: 'ICMP control-message abuse', domain: 'A1a', exhausted_resource: 'packet_processing', catalog_vector_ids: ['NET-020', 'NET-021', 'NET-022'], task_id: 'DET-017', notes: 'needs bounded ICMP control-message generation with edge and customer-supplied telemetry observations', check_ids: [] },
  { id: 'ATT-030', name: 'IPv6 extension-header abuse', domain: 'A1a', exhausted_resource: 'exploit_dos', catalog_vector_ids: ['NET-025', 'NET-109', 'NET-110', 'NET-111', 'NET-112'], task_id: 'DET-017', notes: 'needs an isolated-lab IPv6 extension-header and routing-header packet suite', check_ids: [] },
  { id: 'ATT-031', name: 'IPv6 atomic-fragment abuse', domain: 'A1a', exhausted_resource: 'exploit_dos', catalog_vector_ids: ['NET-027'], task_id: 'DET-017', notes: 'needs an isolated-lab IPv6 atomic-fragment parser test', check_ids: [] },
  { id: 'ATT-032', name: 'IPv6 neighbor-cache destination-scan exhaustion', domain: 'A1a', exhausted_resource: 'state_exhaustion', catalog_vector_ids: ['NET-035'], task_id: 'DET-017', notes: 'needs bounded off-link destination scans plus router neighbor-table telemetry', check_ids: [] },
  { id: 'ATT-033', name: 'TTL and exception-path control-plane floods', domain: 'A1a', exhausted_resource: 'packet_processing', catalog_vector_ids: ['NET-040', 'NET-041'], task_id: 'DET-017', notes: 'needs governed TTL-expiry and unroutable-destination packets plus control-plane CPU telemetry', check_ids: [] },
  { id: 'ATT-034', name: 'UDP application packet-loop attack', domain: 'A1a', exhausted_resource: 'exploit_dos', catalog_vector_ids: ['NET-055'], task_id: 'DET-017', notes: 'needs a lab-only pair of declared UDP services to prove a bounded protocol loop', check_ids: [] },
  { id: 'ATT-035', name: 'Malformed TCP and option floods', domain: 'A1a', exhausted_resource: 'exploit_dos', catalog_vector_ids: ['NET-069', 'NET-071', 'NET-115', 'NET-116', 'NET-117', 'NET-146'], task_id: 'DET-017', notes: 'needs an isolated-lab TCP segment builder for checksum, length, option, and window anomalies', check_ids: [] },
  { id: 'ATT-036', name: 'DCCP request flood', domain: 'A1a', exhausted_resource: 'state_exhaustion', catalog_vector_ids: ['NET-074'], task_id: 'DET-017', notes: 'needs a governed DCCP request client and declared service endpoint', check_ids: [] },
  { id: 'ATT-037', name: 'TLS record fragmentation exhaustion', domain: 'A1a', exhausted_resource: 'computational', catalog_vector_ids: ['NET-080'], task_id: 'DET-021', notes: 'needs a bounded TLS record-level client that can fragment and emit empty records', check_ids: [] },
  { id: 'ATT-038', name: 'L2TP control-session exhaustion', domain: 'A1a', exhausted_resource: 'state_exhaustion', catalog_vector_ids: ['NET-083'], task_id: 'DET-017', notes: 'needs a bounded L2TP control-session client for a declared UDP/1701 service', check_ids: [] },
  { id: 'ATT-039', name: 'SNAT ephemeral-port exhaustion', domain: 'A1a', exhausted_resource: 'state_exhaustion', catalog_vector_ids: ['NET-088'], task_id: 'DET-017', notes: 'needs gateway or customer-supplied SNAT-table telemetry correlated with a governed connection scenario', check_ids: [] },
  { id: 'ATT-040', name: 'Malformed ICMP floods', domain: 'A1a', exhausted_resource: 'exploit_dos', catalog_vector_ids: ['NET-098', 'NET-099'], task_id: 'DET-017', notes: 'needs an isolated-lab ICMP frame builder for checksum and structural anomalies', check_ids: [] },
  { id: 'ATT-076', name: 'Malformed IPv4 packet floods', domain: 'A1a', exhausted_resource: 'exploit_dos', catalog_vector_ids: ['NET-101', 'NET-102', 'NET-103', 'NET-104', 'NET-164'], task_id: 'DET-017', notes: 'needs an isolated-lab IPv4 header builder for version, TTL, IHL, length, and checksum anomalies', check_ids: [] },
  { id: 'ATT-077', name: 'Malformed IPv6 packet floods', domain: 'A1a', exhausted_resource: 'exploit_dos', catalog_vector_ids: ['NET-106', 'NET-107', 'NET-108', 'NET-113', 'NET-114'], task_id: 'DET-017', notes: 'needs an isolated-lab IPv6 packet builder for version, hop-limit, length, address, and missing-L4 anomalies', check_ids: [] },
  { id: 'ATT-078', name: 'Malformed UDP packet floods', domain: 'A1a', exhausted_resource: 'exploit_dos', catalog_vector_ids: ['NET-122', 'NET-123'], task_id: 'DET-017', notes: 'needs an isolated-lab UDP packet builder for checksum and length anomalies', check_ids: [] },
  { id: 'ATT-079', name: 'Malformed SCTP packet flood', domain: 'A1a', exhausted_resource: 'exploit_dos', catalog_vector_ids: ['NET-124'], task_id: 'DET-017', notes: 'needs an isolated-lab SCTP packet builder with an invalid CRC32c', check_ids: [] },
  { id: 'ATT-080', name: 'Legacy AFS service flood', domain: 'A1a', exhausted_resource: 'application_l7', catalog_vector_ids: ['NET-126'], task_id: 'DET-020', notes: 'needs a bounded AFS service-specific client against a declared endpoint', check_ids: [] },
  { id: 'ATT-081', name: 'Advanced device-discovery service flood', domain: 'A1a', exhausted_resource: 'application_l7', catalog_vector_ids: ['NET-127'], task_id: 'DET-020', notes: 'needs a protocol-correct bounded ADDP request to a declared device endpoint', check_ids: [] },
  { id: 'ATT-082', name: 'Direct NAT-PMP request flood', domain: 'A1a', exhausted_resource: 'application_l7', catalog_vector_ids: ['NET-139'], task_id: 'DET-020', notes: 'needs a bounded NAT-PMP request client for a declared UDP/5351 service', check_ids: [] },
  { id: 'ATT-083', name: 'Direct Sentinel license-service flood', domain: 'A1a', exhausted_resource: 'application_l7', catalog_vector_ids: ['NET-141'], task_id: 'DET-020', notes: 'needs a bounded Sentinel license-protocol client for the declared service port', check_ids: [] },
  { id: 'ATT-084', name: 'No-listener or service-miss flood', domain: 'A1a', exhausted_resource: 'packet_processing', catalog_vector_ids: ['NET-143'], task_id: 'DET-017', notes: 'needs governed packets to declared closed ports plus firewall and host lookup telemetry', check_ids: [] },
  { id: 'ATT-085', name: 'Kad peer-to-peer reflection exposure', domain: 'A2', exhausted_resource: 'reflection', catalog_vector_ids: ['AMP-022'], task_id: 'DET-018', notes: 'needs a protocol-correct bounded Kad request with response-size measurement', check_ids: [] },
  { id: 'ATT-086', name: 'Service Location Protocol amplification exposure', domain: 'A2', exhausted_resource: 'amplification', catalog_vector_ids: ['AMP-029'], task_id: 'DET-018', notes: 'needs a protocol-correct bounded SLP request with response-size and amplification-ratio evidence', check_ids: [] },
  { id: 'ATT-087', name: 'L2TP reflection exposure', domain: 'A2', exhausted_resource: 'reflection', catalog_vector_ids: ['AMP-032'], task_id: 'DET-018', notes: 'needs a protocol-correct bounded L2TP control request with response-size measurement', check_ids: [] },
  { id: 'ATT-088', name: 'Sentinel license-server reflection exposure', domain: 'A2', exhausted_resource: 'reflection', catalog_vector_ids: ['AMP-045'], task_id: 'DET-018', notes: 'needs a protocol-correct bounded Sentinel discovery request with response-size measurement', check_ids: [] },
  { id: 'ATT-089', name: 'TP240 PhoneHome amplification exposure', domain: 'A2', exhausted_resource: 'amplification', catalog_vector_ids: ['AMP-046'], task_id: 'DET-018', notes: 'needs a protocol-correct bounded TP240 request with strict response-size and amplification-ratio caps', check_ids: [] },
  { id: 'ATT-177', name: 'TCP SYN-ACK reflection exposure', domain: 'A2', exhausted_resource: 'reflection', catalog_vector_ids: ['AMP-048'], task_id: 'DET-018', notes: 'needs provider or customer-supplied telemetry evidence for unsolicited SYN-ACK response behavior; no spoofed traffic', check_ids: [] },
  { id: 'ATT-178', name: 'Cross-protocol UDP loop exposure', domain: 'A2', exhausted_resource: 'amplification', catalog_vector_ids: ['AMP-051'], task_id: 'DET-018', notes: 'needs a lab-only pair of declared services to test a bounded cross-protocol loop', check_ids: [] },
  { id: 'ATT-179', name: 'VxWorks service reflection exposure', domain: 'A2', exhausted_resource: 'reflection', catalog_vector_ids: ['AMP-055'], task_id: 'DET-018', notes: 'needs a protocol-correct bounded WDBRPC request with response-size measurement', check_ids: [] },
  { id: 'ATT-180', name: 'CUPS/IPP callback reflection exposure', domain: 'A2', exhausted_resource: 'reflection', catalog_vector_ids: ['AMP-057'], task_id: 'DET-018', notes: 'needs a declared callback canary and bounded IPP request to prove callback fan-out', check_ids: [] },
  { id: 'ATT-181', name: 'NAT-PMP amplification exposure', domain: 'A2', exhausted_resource: 'amplification', catalog_vector_ids: ['AMP-058'], task_id: 'DET-018', notes: 'needs a protocol-correct bounded NAT-PMP request with response-size measurement', check_ids: [] },
  { id: 'ATT-182', name: 'Gateway-discovery reflection exposure', domain: 'A2', exhausted_resource: 'reflection', catalog_vector_ids: ['AMP-061'], task_id: 'DET-018', notes: 'needs a protocol-correct bounded gateway-discovery request with response-size measurement', check_ids: [] },
  { id: 'ATT-183', name: 'TsuKing DNS retry/chain/loop amplification', domain: 'A2', exhausted_resource: 'amplification', catalog_vector_ids: ['AMP-067', 'AMP-068', 'AMP-069'], task_id: 'DET-019', notes: 'needs a controlled multi-resolver DNS topology and pulse-amplification telemetry', check_ids: [] },
  { id: 'ATT-184', name: 'HTTP callback and fan-out reflection', domain: 'A2', exhausted_resource: 'reflection', catalog_vector_ids: ['AMP-072'], task_id: 'DET-018', notes: 'needs a declared callback canary and bounded HTTP request that proves server-side fan-out', check_ids: [] },
  { id: 'ATT-185', name: 'fastd VPN reconnect amplification exposure', domain: 'A2', exhausted_resource: 'amplification', catalog_vector_ids: ['AMP-074'], task_id: 'DET-018', notes: 'needs a protocol-correct bounded fastd handshake with response-size measurement', check_ids: [] },
  { id: 'ATT-186', name: 'Attacker-controlled UDP callback reflection', domain: 'A2', exhausted_resource: 'reflection', catalog_vector_ids: ['AMP-075'], task_id: 'DET-018', notes: 'needs a declared callback canary and bounded UDP acknowledgement workflow', check_ids: [] },
  { id: 'ATT-187', name: 'DNS parser and multi-message exhaustion', domain: 'A3', exhausted_resource: 'dns_exhaustion', catalog_vector_ids: ['APP-168', 'APP-169'], task_id: 'DET-019', notes: 'needs a direct DNS wire client for multi-question queries and response-message handling', check_ids: [] },
  { id: 'ATT-188', name: 'DNSSEC validation and signing exhaustion', domain: 'A3', exhausted_resource: 'computational', catalog_vector_ids: ['APP-104', 'APP-105', 'APP-171'], task_id: 'DET-019', notes: 'needs bounded DNSSEC vectors against declared resolver and authoritative endpoints with CPU telemetry', check_ids: [] },
  { id: 'ATT-189', name: 'Encrypted DNS stream exhaustion', domain: 'A3', exhausted_resource: 'dns_exhaustion', catalog_vector_ids: ['APP-172', 'APP-173'], task_id: 'DET-019', notes: 'needs a bounded DoQ/DoH3 client with connection and stream-limit evidence', check_ids: [] },
  { id: 'ATT-190', name: 'State-changing HTTP method flood', domain: 'A4a', exhausted_resource: 'application_l7', catalog_vector_ids: ['APP-004'], task_id: 'DET-020', notes: 'needs a declared idempotent canary endpoint and bounded PUT/PATCH/DELETE method matrix', check_ids: [] },
  { id: 'ATT-191', name: 'Large-response request flood', domain: 'A4a', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-012'], task_id: 'DET-020', notes: 'needs a declared large-response endpoint and response-cost telemetry', check_ids: [] },
  { id: 'ATT-192', name: 'HTTP request-smuggling availability attack', domain: 'A4a', exhausted_resource: 'exploit_dos', catalog_vector_ids: ['APP-023'], task_id: 'DET-021', notes: 'needs an isolated parser-differential harness across the edge and origin', check_ids: [] },
  { id: 'ATT-193', name: 'HTTP parameter and error-log exhaustion', domain: 'A4a', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-025', 'APP-026', 'APP-140'], task_id: 'DET-020', notes: 'needs declared canary endpoints plus parameter-count, error-rate, and log-volume telemetry', check_ids: [] },
  { id: 'ATT-194', name: 'Hash and comparison algorithmic complexity', domain: 'A4a', exhausted_resource: 'computational', catalog_vector_ids: ['APP-028', 'APP-029'], task_id: 'DET-020', notes: 'needs a bounded corpus for hash-collision and pathological sort/filter inputs', check_ids: [] },
  { id: 'ATT-195', name: 'External resource-fetch parser exhaustion', domain: 'A4a', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-032'], task_id: 'DET-020', notes: 'needs a declared callback canary and bounded external-resource parser input', check_ids: [] },
  { id: 'ATT-196', name: 'Compressed, image, and document processing bombs', domain: 'A4a', exhausted_resource: 'computational', catalog_vector_ids: ['APP-033', 'APP-034', 'APP-035', 'APP-146'], task_id: 'DET-020', notes: 'needs bounded decompression and media/document fixtures with CPU, memory, and expansion caps', check_ids: [] },
  { id: 'ATT-197', name: 'Template and deserialization resource exhaustion', domain: 'A4a', exhausted_resource: 'computational', catalog_vector_ids: ['APP-036', 'APP-037'], task_id: 'DET-020', notes: 'needs an isolated rendering/deserialization fixture suite for the declared runtime', check_ids: [] },
  { id: 'ATT-198', name: 'Object binding and session-state exhaustion', domain: 'A4a', exhausted_resource: 'memory_exhaustion', catalog_vector_ids: ['APP-038', 'APP-039'], task_id: 'DET-020', notes: 'needs an authenticated canary flow with bounded object-count and session-memory evidence', check_ids: [] },
  { id: 'ATT-199', name: 'Memory-leak trigger flood', domain: 'A4a', exhausted_resource: 'memory_exhaustion', catalog_vector_ids: ['APP-041'], task_id: 'DET-020', notes: 'needs an isolated repeatable trigger plus process-memory and restart telemetry', check_ids: [] },
  { id: 'ATT-200', name: 'Lock contention and cache stampede', domain: 'A4a', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-044', 'APP-047'], task_id: 'DET-020', notes: 'needs a declared hot-key canary and backend lock/cache-miss telemetry', check_ids: [] },
  { id: 'ATT-201', name: 'Queue, retry, and recursive-call exhaustion', domain: 'A4a', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-045', 'APP-046', 'APP-049'], task_id: 'DET-020', notes: 'needs a declared canary workflow plus queue-depth, retry-count, and call-graph telemetry', check_ids: [] },
  { id: 'ATT-202', name: 'N+1 object-expansion abuse', domain: 'A4a', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-057'], task_id: 'DET-020', notes: 'needs an authenticated declared object endpoint with query-count telemetry', check_ids: [] },
  { id: 'ATT-203', name: 'Federated identity-provider exhaustion', domain: 'A4a', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-060'], task_id: 'DET-020', notes: 'needs a tenant-declared federated login canary and identity-provider rate telemetry', check_ids: [] },
  { id: 'ATT-204', name: 'GraphQL subscription exhaustion', domain: 'A4a', exhausted_resource: 'state_exhaustion', catalog_vector_ids: ['APP-067'], task_id: 'DET-020', notes: 'needs a declared GraphQL subscription and bounded concurrent-stream client', check_ids: [] },
  { id: 'ATT-205', name: 'HTTP/2 Bomb composite exhaustion', domain: 'A5', exhausted_resource: 'memory_exhaustion', catalog_vector_ids: ['APP-187'], task_id: 'DET-021', notes: 'needs an isolated frame-level HTTP/2 composite test with strict stream and memory caps', check_ids: [] },
  { id: 'ATT-206', name: 'HTTP/3 to HTTP/1 translation amplification', domain: 'A5', exhausted_resource: 'amplification', catalog_vector_ids: ['APP-188', 'APP-189'], task_id: 'DET-021', notes: 'needs a bounded H3-to-H1 translation harness with bandwidth and connection-ratio evidence', check_ids: [] },
  { id: 'ATT-207', name: 'HTML5 ping browser fan-out', domain: 'A4a', exhausted_resource: 'amplification', catalog_vector_ids: ['APP-190'], task_id: 'DET-020', notes: 'needs a controlled browser fixture and declared callback canary', check_ids: [] },
  { id: 'ATT-208', name: 'TLS session-resumption validation exhaustion', domain: 'A5', exhausted_resource: 'computational', catalog_vector_ids: ['APP-191'], task_id: 'DET-021', notes: 'needs a bounded TLS ticket/resumption client with handshake CPU telemetry', check_ids: [] },
  { id: 'ATT-209', name: 'Cache purge API exhaustion', domain: 'A4a', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-194'], task_id: 'DET-020', notes: 'needs an authenticated declared purge canary and cache invalidation telemetry', check_ids: [] },
  { id: 'ATT-210', name: 'Media streaming and transcode exhaustion', domain: 'A4a', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-132'], task_id: 'DET-020', notes: 'needs a declared media endpoint and bounded segment/transcode cost comparison', check_ids: [] },
  { id: 'ATT-211', name: 'SOAP and generic RPC operation flood', domain: 'A4a', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-134'], task_id: 'DET-020', notes: 'needs a declared idempotent RPC operation and protocol-specific bounded client', check_ids: [] },
  { id: 'ATT-212', name: 'Serverless denial-of-wallet', domain: 'A4a', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-135'], task_id: 'DET-020', notes: 'needs a declared serverless canary plus invocation, concurrency, and cost-budget telemetry', check_ids: [] },
  { id: 'ATT-213', name: 'Object-storage request and egress exhaustion', domain: 'A4a', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-137'], task_id: 'DET-020', notes: 'needs a declared object canary and bounded request/egress telemetry without cloud credentials', check_ids: [] },
  { id: 'ATT-214', name: 'Third-party API fan-out exhaustion', domain: 'A4a', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-143'], task_id: 'DET-020', notes: 'needs a declared integration canary and downstream request/quota telemetry', check_ids: [] },
  { id: 'ATT-215', name: 'ML and LLM inference exhaustion', domain: 'A4a', exhausted_resource: 'ai_agentic', catalog_vector_ids: ['APP-145'], task_id: 'DET-020', notes: 'requires the tenant to declare an ML or LLM endpoint and a bounded token-cost canary', check_ids: [] },
  { id: 'ATT-216', name: 'URL preview and crawler SSRF fan-out', domain: 'A4a', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-147'], task_id: 'DET-020', notes: 'needs a declared URL-preview endpoint and callback canary with strict egress boundaries', check_ids: [] },
  { id: 'ATT-217', name: 'Account-lockout denial attack', domain: 'A4a', exhausted_resource: 'access_control', catalog_vector_ids: ['APP-148'], task_id: 'DET-020', notes: 'needs an authenticated disposable account and declared lockout-policy canary', check_ids: [] },
  { id: 'ATT-218', name: 'Application crash, hang, or deadlock trigger', domain: 'A4a', exhausted_resource: 'exploit_dos', catalog_vector_ids: ['APP-152'], task_id: 'DET-020', notes: 'needs an isolated lab target, an approved trigger fixture, and restart/health telemetry', check_ids: [] },
  { id: 'ATT-219', name: 'Incremental XML rescanning exhaustion', domain: 'A4a', exhausted_resource: 'computational', catalog_vector_ids: ['APP-201'], task_id: 'DET-020', notes: 'needs a bounded trickle-feed XML client with parser CPU and timeout evidence', check_ids: [] },
  { id: 'ATT-220', name: 'Mail queue and mailbox command exhaustion', domain: 'A4b', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-117', 'APP-118'], task_id: 'DET-020', notes: 'needs declared SMTP and IMAP/POP canaries with queue and authentication-rate telemetry', check_ids: [] },
  { id: 'ATT-221', name: 'LDAP bind and expensive-search exhaustion', domain: 'A4b', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-119', 'APP-120'], task_id: 'DET-020', notes: 'needs a declared LDAP test account/base DN and bounded bind/search clients', check_ids: [] },
  { id: 'ATT-222', name: 'AMQP connection and message exhaustion', domain: 'A4b', exhausted_resource: 'state_exhaustion', catalog_vector_ids: ['APP-124', 'APP-125'], task_id: 'DET-020', notes: 'needs a declared AMQP vhost and bounded channel, queue, routing, and publish client', check_ids: [] },
  { id: 'ATT-223', name: 'RDP authentication flood', domain: 'A4b', exhausted_resource: 'state_exhaustion', catalog_vector_ids: ['APP-127'], task_id: 'DET-020', notes: 'needs a bounded RDP negotiation client for a declared service endpoint', check_ids: [] },
  { id: 'ATT-224', name: 'SMB and NFS operation flood', domain: 'A4b', exhausted_resource: 'backend_exhaustion', catalog_vector_ids: ['APP-129'], task_id: 'DET-020', notes: 'needs a declared disposable share/export and bounded service-specific operation client', check_ids: [] },
  { id: 'ATT-225', name: 'Malformed SIP parser exhaustion', domain: 'A4b', exhausted_resource: 'exploit_dos', catalog_vector_ids: ['APP-185', 'APP-186'], task_id: 'DET-020', notes: 'needs an isolated SIP parser client for malformed messages, URI length, and field-count boundaries', check_ids: [] },
  { id: 'ATT-226', name: 'STOMP header-count exhaustion', domain: 'A4b', exhausted_resource: 'memory_exhaustion', catalog_vector_ids: ['APP-199'], task_id: 'DET-020', notes: 'needs a bounded STOMP frame client with header-count and memory limits', check_ids: [] },
  { id: 'ATT-227', name: 'Redis decoder memory exhaustion', domain: 'A4b', exhausted_resource: 'memory_exhaustion', catalog_vector_ids: ['APP-200'], task_id: 'DET-020', notes: 'needs an isolated Redis protocol parser test for unterminated length lines', check_ids: [] },
  { id: 'ATT-228', name: 'gRPC decompression exhaustion', domain: 'A5', exhausted_resource: 'computational', catalog_vector_ids: ['APP-071'], task_id: 'DET-021', notes: 'needs a declared gRPC method and bounded compressed-message client', check_ids: [] },
  { id: 'ATT-229', name: 'WebSocket fan-out and compression exhaustion', domain: 'A5', exhausted_resource: 'memory_exhaustion', catalog_vector_ids: ['APP-075', 'APP-076'], task_id: 'DET-021', notes: 'needs a declared WebSocket room plus bounded broadcast and compression fixtures', check_ids: [] },
  { id: 'ATT-230', name: 'HTTP/2 flow-control exhaustion', domain: 'A5', exhausted_resource: 'memory_exhaustion', catalog_vector_ids: ['APP-080', 'APP-085', 'APP-090'], task_id: 'DET-021', notes: 'needs a frame-level HTTP/2 client for stalled windows, buffering, and WINDOW_UPDATE sequences', check_ids: [] },
  { id: 'ATT-231', name: 'HTTP/2 control-frame floods', domain: 'A5', exhausted_resource: 'packet_processing', catalog_vector_ids: ['APP-081', 'APP-082', 'APP-083'], task_id: 'DET-021', notes: 'needs a frame-level HTTP/2 client for bounded PING, SETTINGS, and empty-frame sequences', check_ids: [] },
  { id: 'ATT-232', name: 'HTTP/2 zero-length header flood', domain: 'A5', exhausted_resource: 'computational', catalog_vector_ids: ['APP-084'], task_id: 'DET-021', notes: 'needs a frame-level HTTP/2 header encoder for bounded zero-length header sequences', check_ids: [] },
  { id: 'ATT-233', name: 'Malformed HTTP/2 frame flood', domain: 'A5', exhausted_resource: 'exploit_dos', catalog_vector_ids: ['APP-091'], task_id: 'DET-021', notes: 'needs an isolated frame-level HTTP/2 state-machine and malformed-frame suite', check_ids: [] },
  { id: 'ATT-234', name: 'HTTP/3 header and reserved-frame buffering', domain: 'A5', exhausted_resource: 'memory_exhaustion', catalog_vector_ids: ['APP-196', 'APP-197'], task_id: 'DET-021', notes: 'needs a frame-level HTTP/3 client for bounded header-section and declared-length fixtures', check_ids: [] },
  { id: 'ATT-235', name: 'Fragmented TLS ClientHello reassembly exhaustion', domain: 'A5', exhausted_resource: 'computational', catalog_vector_ids: ['APP-198'], task_id: 'DET-021', notes: 'needs a bounded TLS record-fragment client with reassembly CPU telemetry', check_ids: [] },
  { id: 'ATT-236', name: 'WAF encoding and canonicalization evasion', domain: 'A8', exhausted_resource: 'delivery_pattern', catalog_vector_ids: ['EVA-004', 'EVA-005', 'EVA-006', 'EVA-007', 'EVA-008', 'EVA-009', 'EVA-010', 'EVA-011', 'EVA-012', 'EVA-013'], task_id: 'DET-022', notes: 'needs a safe-marker corpus spanning Unicode, charset, entity, escape, base64, and numeric encodings', check_ids: [] },
  { id: 'ATT-237', name: 'WAF lexical and control-character evasion', domain: 'A8', exhausted_resource: 'delivery_pattern', catalog_vector_ids: ['EVA-015', 'EVA-017', 'EVA-018', 'EVA-019', 'EVA-020'], task_id: 'DET-022', notes: 'needs a safe-marker mutation corpus for whitespace, operators, literals, nulls, and control characters', check_ids: [] },
  { id: 'ATT-238', name: 'WAF path and network canonicalization evasion', domain: 'A8', exhausted_resource: 'delivery_pattern', catalog_vector_ids: ['EVA-022', 'EVA-023', 'EVA-024'], task_id: 'DET-022', notes: 'needs a safe-marker path and alternate-IP representation matrix', check_ids: [] },
  { id: 'ATT-239', name: 'WAF duplicate-input parser differentials', domain: 'A8', exhausted_resource: 'delivery_pattern', catalog_vector_ids: ['EVA-025', 'EVA-026', 'EVA-027'], task_id: 'DET-022', notes: 'needs paired edge/origin parsing evidence for duplicate parameters, JSON keys, and headers', check_ids: [] },
  { id: 'ATT-240', name: 'WAF message-framing differentials', domain: 'A8', exhausted_resource: 'delivery_pattern', catalog_vector_ids: ['EVA-028', 'EVA-029', 'EVA-030', 'EVA-031', 'EVA-032'], task_id: 'DET-022', notes: 'needs an isolated edge/origin framing harness for CL/TE, transfer coding, H2 translation, line endings, and trailers', check_ids: [] },
  { id: 'ATT-241', name: 'WAF body decoding and inspection limits', domain: 'A8', exhausted_resource: 'delivery_pattern', catalog_vector_ids: ['EVA-033', 'EVA-034', 'EVA-035', 'EVA-036', 'EVA-037', 'EVA-038'], task_id: 'DET-022', notes: 'needs waf_inspection_limit_probe coverage for compressed bodies, size/count limits, parser budgets, and late payloads', check_ids: [] },
  { id: 'ATT-242', name: 'WAF structured-input location and type confusion', domain: 'A8', exhausted_resource: 'delivery_pattern', catalog_vector_ids: ['EVA-041', 'EVA-044', 'EVA-045', 'EVA-046'], task_id: 'DET-022', notes: 'needs safe markers across binary/protobuf, type changes, nesting, and parameter locations', check_ids: [] },
  { id: 'ATT-243', name: 'WAF protocol, routing, and reassembly differentials', domain: 'A8', exhausted_resource: 'delivery_pattern', catalog_vector_ids: ['EVA-047', 'EVA-048', 'EVA-049', 'EVA-050', 'EVA-051'], task_id: 'DET-022', notes: 'needs paired edge/origin evidence across methods, HTTP versions, upgrades, cache keys, and packet reassembly', check_ids: [] },
  { id: 'ATT-244', name: 'Browser emulation and session warming', domain: 'A8', exhausted_resource: 'automation_abuse', catalog_vector_ids: ['EVA-058', 'EVA-059', 'EVA-060'], task_id: 'DET-022', notes: 'needs a bounded browser client with declared session-warming and fingerprint controls', check_ids: [] },
  { id: 'ATT-245', name: 'Identity and target rotation evasion', domain: 'A8', exhausted_resource: 'automation_abuse', catalog_vector_ids: ['EVA-061', 'EVA-062', 'EVA-063'], task_id: 'DET-022', notes: 'needs authenticated disposable identities and declared endpoints to measure rotation controls', check_ids: [] },
  { id: 'ATT-246', name: 'WAF padding and rule-discovery evasion', domain: 'A8', exhausted_resource: 'delivery_pattern', catalog_vector_ids: ['EVA-065', 'EVA-066'], task_id: 'DET-022', notes: 'needs a safe-marker sequence that varies padding and records threshold responses', check_ids: [] },
  { id: 'ATT-247', name: 'WAF exclusions, allowlists, and fail-open behavior', domain: 'A8', exhausted_resource: 'delivery_pattern', catalog_vector_ids: ['EVA-067', 'EVA-068', 'EVA-069'], task_id: 'DET-022', notes: 'needs waf_inspection_limit_probe coverage for exception abuse, trusted identity, and WAF error paths', check_ids: [] },
  { id: 'ATT-248', name: 'WAF policy drift and rule-gap evasion', domain: 'A8', exhausted_resource: 'delivery_pattern', catalog_vector_ids: ['EVA-070', 'EVA-071'], task_id: 'DET-022', notes: 'needs repeated safe markers across declared nodes and environments with rule-version evidence', check_ids: [] },
  { id: 'ATT-249', name: 'Stored and multi-request payload assembly', domain: 'A8', exhausted_resource: 'delivery_pattern', catalog_vector_ids: ['EVA-072', 'EVA-073'], task_id: 'DET-022', notes: 'needs a disposable object and bounded multi-request safe-marker workflow', check_ids: [] },
  { id: 'ATT-250', name: 'Alternate-protocol WAF bypass', domain: 'A8', exhausted_resource: 'delivery_pattern', catalog_vector_ids: ['EVA-077'], task_id: 'DET-022', notes: 'needs the same safe marker sent over every tenant-declared alternate protocol', check_ids: [] },
  { id: 'ATT-251', name: 'Encrypted, signed, and polyglot payload opacity', domain: 'A8', exhausted_resource: 'delivery_pattern', catalog_vector_ids: ['EVA-079', 'EVA-080', 'EVA-081'], task_id: 'DET-022', notes: 'needs tenant-declared decrypt/verify/parser paths and benign multi-parser fixtures', check_ids: [] },
  { id: 'ATT-252', name: 'Modern HTTP and TLS inspection gaps', domain: 'A8', exhausted_resource: 'delivery_pattern', catalog_vector_ids: ['EVA-083', 'EVA-084', 'EVA-085', 'EVA-086'], task_id: 'DET-022', notes: 'needs H3/H2 translation, header-compression, coalescing, and ECH visibility evidence', check_ids: [] },
  { id: 'ATT-253', name: 'AI semantic and agent-boundary evasion', domain: 'A8', exhausted_resource: 'ai_agentic', catalog_vector_ids: ['EVA-087', 'EVA-088', 'EVA-089'], task_id: 'DET-022', notes: 'requires a tenant-declared AI endpoint plus text, multimodal, tool-schema, and agent-message safe markers', check_ids: [] },
  { id: 'ATT-254', name: 'Multipart charset and XML attribute inspection gaps', domain: 'A8', exhausted_resource: 'delivery_pattern', catalog_vector_ids: ['EVA-090', 'EVA-091'], task_id: 'DET-022', notes: 'needs benign per-part charset and XML attribute-value marker fixtures', check_ids: [] },
];

/**
 * Wave-4 integration (W4-INTEGRATE): check_ids wired onto formerly-E0 registry entries.
 * Keyed by registry id (ATT or WV); evasion and l7 catalog-id mappings were resolved to
 * their owning registry entry. Tiers derive from these mapped checks — never hand-authored.
 */
export const WAVE4_REGISTRY_CHECK_IDS = Object.freeze({
  'ATT-028': ['high_scale.volumetric.request_only'],
  'ATT-029': ['high_scale.volumetric.request_only'],
  'ATT-030': ['high_scale.volumetric.request_only'],
  'ATT-031': ['high_scale.volumetric.request_only'],
  'ATT-032': ['high_scale.volumetric.request_only'],
  'ATT-033': ['high_scale.volumetric.request_only'],
  'ATT-034': ['high_scale.volumetric.request_only'],
  'ATT-035': ['high_scale.volumetric.request_only'],
  'ATT-036': ['high_scale.volumetric.request_only'],
  'ATT-037': ['high_scale.volumetric.request_only'],
  'ATT-038': ['l3.connection_table_exhaustion.request_only'],
  'ATT-039': ['l3.connection_table_exhaustion.request_only'],
  'ATT-040': ['high_scale.volumetric.request_only'],
  'ATT-076': ['high_scale.volumetric.request_only'],
  'ATT-077': ['high_scale.volumetric.request_only'],
  'ATT-078': ['high_scale.volumetric.request_only'],
  'ATT-079': ['high_scale.volumetric.request_only'],
  'ATT-080': ['high_scale.volumetric.request_only'],
  'ATT-081': ['high_scale.volumetric.request_only'],
  'ATT-082': ['high_scale.volumetric.request_only'],
  'ATT-083': ['high_scale.volumetric.request_only'],
  'ATT-084': ['high_scale.volumetric.request_only'],
  'ATT-085': ['high_scale.volumetric.request_only'],
  'ATT-086': ['reflect.slp_amplification_exposure.safe'],
  'ATT-087': ['reflect.l2tp_reflection_exposure.safe'],
  'ATT-088': ['high_scale.volumetric.request_only'],
  'ATT-089': ['reflect.tp240_amplification_exposure.safe'],
  'ATT-177': ['high_scale.volumetric.request_only'],
  'ATT-178': ['high_scale.volumetric.request_only'],
  'ATT-179': ['high_scale.volumetric.request_only'],
  'ATT-180': ['reflect.ipp_callback_exposure.safe'],
  'ATT-181': ['reflect.natpmp_amplification_exposure.safe'],
  'ATT-182': ['high_scale.volumetric.request_only'],
  'ATT-183': ['high_scale.dns_high_query.request_only'],
  'ATT-184': ['high_scale.application.request_only'],
  'ATT-185': ['high_scale.volumetric.request_only'],
  'ATT-186': ['high_scale.volumetric.request_only'],
  'ATT-187': ['dns.multi_question_oversized.safe'],
  'ATT-188': ['high_scale.dns_high_query.request_only'],
  'ATT-189': ['high_scale.dns_high_query.request_only'],
  'ATT-190': ['high_scale.application.request_only'],
  'ATT-191': ['high_scale.application.request_only'],
  'ATT-192': ['high_scale.multi_vector.request_only'],
  'ATT-193': ['high_scale.application.request_only', 'l7.request_parser_size.posture'],
  'ATT-194': ['high_scale.multi_vector.request_only'],
  'ATT-195': ['high_scale.multi_vector.request_only'],
  'ATT-196': ['high_scale.multi_vector.request_only', 'l7.compressed_request_decompression.posture'],
  'ATT-197': ['high_scale.multi_vector.request_only'],
  'ATT-198': ['high_scale.multi_vector.request_only', 'l3.connection_table_exhaustion.request_only'],
  'ATT-199': ['high_scale.multi_vector.request_only'],
  'ATT-200': ['high_scale.application.request_only'],
  'ATT-201': ['high_scale.application.request_only', 'high_scale.multi_vector.request_only'],
  'ATT-202': ['high_scale.application.request_only'],
  'ATT-203': ['high_scale.application.request_only'],
  'ATT-204': ['high_scale.application.request_only'],
  'ATT-205': ['high_scale.multi_vector.request_only'],
  'ATT-206': ['high_scale.multi_vector.request_only', 'l3.connection_table_exhaustion.request_only'],
  'ATT-207': ['high_scale.application.request_only'],
  'ATT-208': ['high_scale.volumetric.request_only'],
  'ATT-209': ['high_scale.application.request_only'],
  'ATT-210': ['high_scale.application.request_only'],
  'ATT-211': ['high_scale.application.request_only'],
  'ATT-212': ['ops.autoscaling_cost.readiness'],
  'ATT-213': ['ops.autoscaling_cost.readiness'],
  'ATT-214': ['high_scale.application.request_only'],
  'ATT-215': ['high_scale.application.request_only'],
  'ATT-216': ['high_scale.multi_vector.request_only'],
  'ATT-217': ['high_scale.application.request_only'],
  'ATT-218': ['high_scale.multi_vector.request_only'],
  'ATT-219': ['high_scale.multi_vector.request_only'],
  'ATT-220': ['l3.connection_table_exhaustion.request_only'],
  'ATT-221': ['high_scale.application.request_only', 'l3.connection_table_exhaustion.request_only'],
  'ATT-222': ['l3.connection_table_exhaustion.request_only'],
  'ATT-223': ['l3.connection_table_exhaustion.request_only'],
  'ATT-224': ['l3.connection_table_exhaustion.request_only'],
  'ATT-225': ['high_scale.volumetric.request_only'],
  'ATT-226': ['high_scale.multi_vector.request_only'],
  'ATT-227': ['high_scale.multi_vector.request_only'],
  'ATT-228': ['high_scale.multi_vector.request_only'],
  'ATT-229': ['high_scale.multi_vector.request_only', 'l3.connection_table_exhaustion.request_only'],
  'ATT-230': ['l7.http2_continuation.readiness'],
  'ATT-231': ['l7.http2_continuation.readiness'],
  'ATT-232': ['l7.http2_continuation.readiness'],
  'ATT-233': ['l7.http2_continuation.readiness'],
  'ATT-234': ['protocol.http3_control_stream.readiness'],
  'ATT-235': ['high_scale.volumetric.request_only'],
  'ATT-236': ['waf.evasion_alt_charset.safe', 'waf.evasion_base64_wrap.safe', 'waf.evasion_css_escape.safe', 'waf.evasion_homoglyph.safe', 'waf.evasion_html_entity.safe', 'waf.evasion_js_escape.safe', 'waf.evasion_json_unicode_escape.safe', 'waf.evasion_numeric_repr.safe', 'waf.evasion_overlong_utf8.safe', 'waf.evasion_unicode_normalization.safe'],
  'ATT-237': ['waf.evasion_control_char.safe', 'waf.evasion_lexical_literal.safe', 'waf.evasion_lexical_operator.safe', 'waf.evasion_lexical_tautology.safe', 'waf.evasion_whitespace.safe'],
  'ATT-238': ['waf.evasion_ip_representation.safe', 'waf.evasion_path_matrix.safe', 'waf.evasion_path_suffix.safe'],
  'ATT-239': ['waf.evasion_parser_header_dup.safe', 'waf.evasion_parser_hpp.safe', 'waf.evasion_parser_json_dup.safe'],
  'ATT-240': ['waf.evasion_framing_chunk_ext.safe', 'waf.evasion_framing_cl_te.safe', 'waf.evasion_framing_h2_h1.safe', 'waf.evasion_framing_line_ending.safe', 'waf.evasion_framing_transfer_coding.safe'],
  'ATT-241': ['waf.evasion_body_gzip.safe', 'waf.evasion_body_nested_encoding.safe', 'waf.inspection_limit.safe'],
  'ATT-242': ['waf.evasion_content_type_binary.safe', 'waf.evasion_parameter_location.safe', 'waf.evasion_struct_deep_nesting.safe', 'waf.evasion_struct_type_confusion.safe'],
  'ATT-243': ['waf.evasion_cache_key_mismatch.posture', 'waf.evasion_method_override.safe', 'waf.evasion_protocol_upgrade.safe', 'waf.evasion_protocol_version.safe', 'waf.evasion_reassembly_differential.posture'],
  'ATT-244': ['pattern.residential_proxy.readiness'],
  'ATT-245': ['pattern.rate_limit_evasion.readiness'],
  'ATT-246': ['pattern.adaptive_evasion.readiness', 'waf.evasion_benign_padding.safe'],
  'ATT-247': ['waf.inspection_limit.safe'],
  'ATT-248': ['pattern.adaptive_evasion.readiness', 'waf.evasion_rule_gap.posture'],
  'ATT-249': ['pattern.adaptive_evasion.readiness', 'waf.evasion_second_order.posture'],
  'ATT-250': ['pattern.adaptive_evasion.readiness'],
  'ATT-251': ['waf.evasion_encrypted_payload.posture', 'waf.evasion_polyglot_content.safe', 'waf.evasion_signed_structured_data.posture'],
  'ATT-252': ['waf.evasion_connection_coalescing.posture', 'waf.evasion_ech_routing_metadata.posture', 'waf.evasion_protocol_h3_h1.safe', 'waf.evasion_protocol_qpack_hpack.safe'],
  'ATT-253': ['pattern.adaptive_evasion.readiness'],
  'ATT-254': ['waf.evasion_multipart_charset.safe', 'waf.evasion_xml_attribute.safe'],
  'WV-009': ['waf.http_method_policy_marker.safe'],
  'WV-010': ['waf.request_smuggling_marker.safe'],
  'WV-011': ['waf.crlf_injection_marker.safe'],
  'WV-012': ['waf.http_routing_trust.posture'],
  'WV-013': ['waf.open_redirect_marker.safe'],
  'WV-014': ['waf.nosql_injection_marker.safe'],
  'WV-015': ['waf.xpath_injection_marker.safe'],
  'WV-016': ['waf.jndi_ldap_marker.safe'],
  'WV-017': ['waf.csv_formula_marker.safe'],
  'WV-018': ['waf.prototype_pollution_marker.safe'],
  'WV-019': ['waf.deserialization_marker.safe'],
  'WV-020': ['waf.ssrf_marker.safe'],
  'WV-021': ['waf.xxe_marker.safe'],
  'WV-022': ['waf.jsonp_css_policy.posture'],
  'WV-023': ['waf.offensive_combined.soc'],
  'WV-024': ['waf.file_upload_marker.safe'],
  'WV-025': ['waf.offensive_combined.soc'],
  'WV-026': ['waf.offensive_combined.soc'],
  'WV-027': ['waf.offensive_combined.soc'],
  'WV-028': ['waf.jwt_tamper_marker.safe'],
  'WV-029': ['waf.offensive_combined.soc'],
  'WV-030': ['waf.offensive_combined.soc'],
  'WV-031': ['waf.offensive_combined.soc'],
  'WV-032': ['waf.offensive_combined.soc'],
  'WV-033': ['waf.offensive_combined.soc'],
  'WV-034': ['waf.offensive_combined.soc'],
  'WV-035': ['waf.offensive_combined.soc'],
  'WV-036': ['waf.offensive_combined.soc'],
  'WV-037': ['waf.offensive_combined.soc'],
  'WV-038': ['waf.offensive_combined.soc'],
  'WV-039': ['waf.offensive_combined.soc'],
  'WV-040': ['waf.offensive_combined.soc'],
  'WV-041': ['waf.offensive_combined.soc'],
  'WV-042': ['waf.offensive_combined.soc'],
});

function mergeWave4CheckIds(id, existing = []) {
  const extra = WAVE4_REGISTRY_CHECK_IDS[id] ?? [];
  if (extra.length === 0) return existing ?? [];
  return [...new Set([...(existing ?? []), ...extra])];
}

export const ATTACK_VECTOR_REGISTRY = Object.freeze(
  ATTACK_VECTOR_REGISTRY_SOURCE.map((entry) => {
    const check_ids = mergeWave4CheckIds(entry.id, entry.check_ids);
    const evidenceTier = evidenceTierForTaxonomyCheckIds(check_ids);
    return {
      ...entry,
      check_ids,
      domain: entry.domain ?? domainForAttackVector(entry),
      catalog_vector_ids: [...(entry.catalog_vector_ids ?? REGISTRY_CATALOG_VECTOR_IDS[entry.id] ?? [])],
      evidence_tier: evidenceTier,
      coverage_status: coverageStatusForEvidenceTier(evidenceTier),
    };
  }),
);

/** WAF offensive validation — separate from DDoS resource-exhaustion; SOC-only. */
const WAF_VULNERABILITY_REGISTRY_SOURCE = [
  { id: 'WV-001', name: 'SQL injection WAF validation', check_ids: ['waf.offensive_sqli.soc'], task_id: 'DET-007', classification: 'waf_offensive_soc' },
  { id: 'WV-002', name: 'XSS WAF validation', check_ids: ['waf.offensive_xss.soc'], task_id: 'DET-007', classification: 'waf_offensive_soc' },
  { id: 'WV-003', name: 'RCE WAF validation', check_ids: ['waf.offensive_rce.soc'], task_id: 'DET-007', classification: 'waf_offensive_soc' },
  { id: 'WV-004', name: 'Path traversal WAF validation', check_ids: ['waf.offensive_path_traversal.soc'], task_id: 'DET-007', classification: 'waf_offensive_soc' },
  { id: 'WV-005', name: 'Command injection WAF validation', check_ids: ['waf.offensive_command_injection.soc'], task_id: 'DET-007', classification: 'waf_offensive_soc' },
  { id: 'WV-006', name: 'LDAP injection WAF validation', check_ids: ['waf.offensive_ldap_injection.soc'], task_id: 'DET-007', classification: 'waf_offensive_soc' },
  { id: 'WV-007', name: 'SSTI WAF validation', check_ids: ['waf.offensive_ssti.soc'], task_id: 'DET-007', classification: 'waf_offensive_soc' },
  { id: 'WV-008', name: 'Combined WAF offensive suite', check_ids: ['waf.offensive_combined.soc'], task_id: 'DET-007', classification: 'waf_offensive_soc' },
  { id: 'WV-009', name: 'HTTP protocol and header policy validation', domain: 'A7', exhausted_resource: 'integrity_attack', catalog_vector_ids: ['WAF-002', 'WAF-003', 'WAF-004', 'WAF-005', 'WAF-006'], task_id: 'DET-007', notes: 'needs a bounded malformed-request and header-policy suite', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-010', name: 'HTTP request smuggling validation', domain: 'A7', exhausted_resource: 'integrity_attack', catalog_vector_ids: ['WAF-007', 'WAF-008', 'WAF-009', 'WAF-010'], task_id: 'DET-007', notes: 'needs an isolated edge/origin parser-differential suite', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-011', name: 'CRLF and response-splitting validation', domain: 'A7', exhausted_resource: 'integrity_attack', catalog_vector_ids: ['WAF-011'], task_id: 'DET-007', notes: 'needs a benign response-header canary and CRLF marker suite', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-012', name: 'HTTP routing and trust validation', domain: 'A7', exhausted_resource: 'access_control', catalog_vector_ids: ['WAF-013', 'WAF-014', 'WAF-015'], task_id: 'DET-007', notes: 'needs declared proxy boundaries and authority, forwarded-header, and HTTPoxy markers', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-013', name: 'HTTP parameter and path policy validation', domain: 'A7', exhausted_resource: 'integrity_attack', catalog_vector_ids: ['WAF-016', 'WAF-017', 'WAF-020', 'WAF-022', 'WAF-024'], task_id: 'DET-007', notes: 'needs benign duplicate-input, path-routing, cache-deception, and redirect canaries', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-014', name: 'NoSQL injection validation', domain: 'A7', exhausted_resource: 'integrity_attack', catalog_vector_ids: ['WAF-033', 'WAF-034', 'WAF-035', 'WAF-036'], task_id: 'DET-007', notes: 'needs a database-specific NoSQL operator, expression, regex, and pipeline suite', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-015', name: 'XPath and XML injection validation', domain: 'A7', exhausted_resource: 'integrity_attack', catalog_vector_ids: ['WAF-038', 'WAF-039'], task_id: 'DET-007', notes: 'needs a declared XML endpoint and benign XPath/XQuery/XML marker suite', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-016', name: 'JNDI injection validation', domain: 'A7', exhausted_resource: 'integrity_attack', catalog_vector_ids: ['WAF-047'], task_id: 'DET-007', notes: 'needs an isolated naming-context callback canary and JNDI marker suite', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-017', name: 'Server-side and data-channel injection validation', domain: 'A7', exhausted_resource: 'integrity_attack', catalog_vector_ids: ['WAF-048', 'WAF-049', 'WAF-050', 'WAF-051', 'WAF-052'], task_id: 'DET-007', notes: 'needs benign SSI, mail-header, formula, log, and generic-header marker suites', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-018', name: 'Prototype and object-graph injection validation', domain: 'A7', exhausted_resource: 'integrity_attack', catalog_vector_ids: ['WAF-053', 'WAF-054'], task_id: 'DET-007', notes: 'needs a disposable object endpoint and prototype/property-path marker suite', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-019', name: 'Unsafe deserialization validation', domain: 'A7', exhausted_resource: 'integrity_attack', catalog_vector_ids: ['WAF-055', 'WAF-056', 'WAF-057', 'WAF-058', 'WAF-059', 'WAF-060'], task_id: 'DET-007', notes: 'needs isolated runtime-specific Java, .NET, PHP, Python, and YAML deserialization fixtures', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-020', name: 'SSRF validation', domain: 'A7', exhausted_resource: 'access_control', catalog_vector_ids: ['WAF-061', 'WAF-062', 'WAF-063', 'WAF-064', 'WAF-065', 'WAF-066'], task_id: 'DET-007', notes: 'needs a declared URL-fetch endpoint and controlled callback canary for direct, blind, metadata, scheme, redirect, and rebinding cases', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-021', name: 'XXE validation', domain: 'A7', exhausted_resource: 'data_exposure', catalog_vector_ids: ['WAF-067', 'WAF-068'], task_id: 'DET-007', notes: 'needs a declared XML endpoint and controlled external-entity callback canary', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-022', name: 'JSONP and CSS injection validation', domain: 'A7', exhausted_resource: 'integrity_attack', catalog_vector_ids: ['WAF-080', 'WAF-081'], task_id: 'DET-007', notes: 'needs benign callback-name and CSS active-content marker suites', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-023', name: 'Remote file inclusion and write validation', domain: 'A7', exhausted_resource: 'access_control', catalog_vector_ids: ['WAF-084', 'WAF-086', 'WAF-095'], task_id: 'DET-007', notes: 'needs a disposable filesystem canary and remote-include, write, symlink, and race fixtures', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-024', name: 'File upload validation', domain: 'A7', exhausted_resource: 'integrity_attack', catalog_vector_ids: ['WAF-087', 'WAF-088', 'WAF-089', 'WAF-090', 'WAF-091', 'WAF-092', 'WAF-093'], task_id: 'DET-007', notes: 'needs an authenticated disposable upload endpoint and bounded web-shell, MIME, archive, parser, and active-content fixtures', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-025', name: 'Account enumeration and MFA fatigue validation', domain: 'A7', exhausted_resource: 'automation_abuse', catalog_vector_ids: ['WAF-099', 'WAF-101'], task_id: 'DET-007', notes: 'needs disposable accounts and bounded enumeration/push-fatigue workflows', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-026', name: 'Session security validation', domain: 'A7', exhausted_resource: 'access_control', catalog_vector_ids: ['WAF-104', 'WAF-105', 'WAF-106'], task_id: 'DET-007', notes: 'needs an authenticated disposable session and fixation, replay, and tampering fixtures', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-027', name: 'CSRF validation', domain: 'A7', exhausted_resource: 'access_control', catalog_vector_ids: ['WAF-107'], task_id: 'DET-007', notes: 'needs an authenticated disposable state-changing action and cross-origin canary', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-028', name: 'JWT and bearer-token validation', domain: 'A7', exhausted_resource: 'access_control', catalog_vector_ids: ['WAF-108', 'WAF-109', 'WAF-110', 'WAF-111'], task_id: 'DET-007', notes: 'needs a declared token issuer and disposable signed/unsigned/replay fixtures', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-029', name: 'OAuth and OIDC validation', domain: 'A7', exhausted_resource: 'access_control', catalog_vector_ids: ['WAF-113', 'WAF-114', 'WAF-115'], task_id: 'DET-007', notes: 'needs a disposable OAuth client and redirect, state, PKCE, and leakage canaries', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-030', name: 'SAML validation', domain: 'A7', exhausted_resource: 'access_control', catalog_vector_ids: ['WAF-116', 'WAF-117'], task_id: 'DET-007', notes: 'needs a disposable SAML service provider and signature-wrapping/replay fixtures', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-031', name: 'Alternate authentication-path validation', domain: 'A7', exhausted_resource: 'access_control', catalog_vector_ids: ['WAF-118'], task_id: 'DET-007', notes: 'needs every declared auth endpoint, method, and content type exercised with a disposable identity', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-032', name: 'Object and function authorization validation', domain: 'A7', exhausted_resource: 'access_control', catalog_vector_ids: ['WAF-119', 'WAF-120', 'WAF-121', 'WAF-122', 'WAF-124', 'WAF-125', 'WAF-126'], task_id: 'DET-007', notes: 'needs two disposable users/tenants, declared object ids, and a bounded BOLA/BOPLA/BFLA/mass-assignment suite', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-033', name: 'API data exposure and authorization validation', domain: 'A7', exhausted_resource: 'data_exposure', catalog_vector_ids: ['WAF-128', 'WAF-130', 'WAF-132', 'WAF-134', 'WAF-136'], task_id: 'DET-007', notes: 'needs disposable identities and declared REST, GraphQL, gRPC, business-flow, and third-party API canaries', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-034', name: 'Business-logic validation', domain: 'A7', exhausted_resource: 'integrity_attack', catalog_vector_ids: ['WAF-138', 'WAF-139', 'WAF-140', 'WAF-141'], task_id: 'DET-007', notes: 'needs a disposable transaction workflow for parameter, sequence, race, and replay tests', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-035', name: 'Automated commercial abuse validation', domain: 'A7', exhausted_resource: 'automation_abuse', catalog_vector_ids: ['WAF-142', 'WAF-143', 'WAF-144', 'WAF-145', 'WAF-146', 'WAF-147', 'WAF-151', 'WAF-153', 'WAF-154', 'WAF-155', 'WAF-157', 'WAF-158', 'WAF-161'], task_id: 'DET-007', notes: 'needs tenant-declared disposable business flows and bounded OAT automation scenarios', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-036', name: 'Direct and indirect prompt-injection validation', domain: 'A7', exhausted_resource: 'ai_agentic', catalog_vector_ids: ['WAF-163', 'WAF-164'], task_id: 'DET-007', notes: 'requires the tenant to declare an LLM endpoint plus direct and retrieved-content prompt canaries', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-037', name: 'System-prompt extraction and output-handling validation', domain: 'A7', exhausted_resource: 'ai_agentic', catalog_vector_ids: ['WAF-165', 'WAF-171'], task_id: 'DET-007', notes: 'requires a tenant-declared LLM endpoint, a non-secret prompt canary, and output-sink assertions', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-038', name: 'AI tool, goal, identity, and privilege validation', domain: 'A7', exhausted_resource: 'ai_agentic', catalog_vector_ids: ['WAF-166', 'WAF-167', 'WAF-168'], task_id: 'DET-007', notes: 'requires a sandboxed agent with declared tools, identities, and denylisted canary actions', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-039', name: 'Agent supply-chain, memory, and retrieval validation', domain: 'A7', exhausted_resource: 'ai_agentic', catalog_vector_ids: ['WAF-169', 'WAF-170'], task_id: 'DET-007', notes: 'requires a disposable agent runtime and canary documents in declared memory and retrieval stores', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-040', name: 'Multimodal and adversarial prompt validation', domain: 'A7', exhausted_resource: 'ai_agentic', catalog_vector_ids: ['WAF-172', 'WAF-173'], task_id: 'DET-007', notes: 'requires a tenant-declared multimodal endpoint and benign hidden-instruction/adversarial-suffix corpus', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-041', name: 'Unbounded model resource-consumption validation', domain: 'A7', exhausted_resource: 'ai_agentic', catalog_vector_ids: ['WAF-174'], task_id: 'DET-007', notes: 'requires a tenant-declared LLM endpoint and bounded token, tool-call, time, and cost budgets', check_ids: [], classification: 'waf_offensive_pending' },
  { id: 'WV-042', name: 'Cross-agent message and rogue-agent validation', domain: 'A7', exhausted_resource: 'ai_agentic', catalog_vector_ids: ['WAF-175', 'WAF-176'], task_id: 'DET-007', notes: 'requires a sandboxed multi-agent workflow with signed message, trust-boundary, and kill-switch canaries', check_ids: [], classification: 'waf_offensive_pending' },
];

export const WAF_VULNERABILITY_REGISTRY = Object.freeze(
  WAF_VULNERABILITY_REGISTRY_SOURCE.map((entry) => {
    const check_ids = mergeWave4CheckIds(entry.id, entry.check_ids);
    const evidenceTier = evidenceTierForTaxonomyCheckIds(check_ids);
    return {
      ...entry,
      check_ids,
      domain: entry.domain ?? 'A7',
      exhausted_resource: entry.exhausted_resource ?? WAF_EXHAUSTED_RESOURCE_BY_ID[entry.id],
      catalog_vector_ids: [...(entry.catalog_vector_ids ?? REGISTRY_CATALOG_VECTOR_IDS[entry.id] ?? [])],
      evidence_tier: evidenceTier,
      coverage_status: coverageStatusForEvidenceTier(evidenceTier),
    };
  }),
);

export const WAF_SOC_CHECK_IDS = Object.freeze(WAF_VULNERABILITY_REGISTRY.flatMap((e) => e.check_ids));

export const RESOURCE_EXHAUSTION_TASKS = Object.freeze([
  { id: 'DET-016', title: 'Add exhausted_resource schema to check catalog', depends_on: [] },
  { id: 'DET-017', title: 'L3/L4 packet-processing, state, and protocol flood vectors', depends_on: ['DET-016'] },
  { id: 'DET-018', title: 'Reflection and non-DNS amplification exposure vectors', depends_on: ['DET-016'] },
  { id: 'DET-019', title: 'Advanced DNS exhaustion vectors (laundering, NXNS, DNSBomb, etc.)', depends_on: ['DET-016'] },
  { id: 'DET-020', title: 'L7 volumetric, computational, slow-client, and backend exhaustion vectors', depends_on: ['DET-016'] },
  { id: 'DET-021', title: 'HTTP/2–3 modern attack classes (Rapid Reset execution, CONTINUATION, MadeYouReset)', depends_on: ['DET-016'] },
  { id: 'DET-022', title: 'Attack delivery patterns (carpet bombing, pulse-wave, multi-vector UI)', depends_on: ['DET-016'] },
  { id: 'DET-023', title: 'Volumetric probe profiles and governed SOC execution scenarios', depends_on: ['DET-017', 'DET-020', 'SOC-011'] },
  { id: 'DET-024', title: 'Resource-exhaustion taxonomy UI, scoring, and readiness matrix', depends_on: ['DET-016'] },
  { id: 'DET-025', title: 'Taxonomy validation harness and staging matrix signoff', depends_on: ['DET-016'] },
  { id: 'DET-026', title: 'Operational/control-plane exhaustion and non-DDoS availability threats', depends_on: ['DET-016'] },
  { id: 'SOC-011', title: 'Governed volumetric execution scenarios (UDP/SYN/HTTP/DNS floods)', depends_on: ['SOC-007'] },
]);

/**
 * @param {readonly AttackVectorEntry[]} registry
 * @returns {{ total: number, implemented: number, partial: number, soc_only: number, pending: number, by_resource: Record<string, number> }}
 */
export function summarizeCoverage(registry = ATTACK_VECTOR_REGISTRY) {
  /** @type {Record<string, number>} */
  const by_resource = {};
  /** @type {Record<CoverageStatus, number>} */
  const counts = { implemented: 0, partial: 0, soc_only: 0, pending: 0 };
  const scoredFamilyIds = new Set(
    EXHAUSTED_RESOURCE_FAMILIES
      .filter((family) => family.scored_for_ddos_readiness)
      .map((family) => family.id),
  );
  const scoredRegistry = registry.filter((entry) => scoredFamilyIds.has(entry.exhausted_resource));
  for (const entry of scoredRegistry) {
    counts[entry.coverage_status] += 1;
    by_resource[entry.exhausted_resource] = (by_resource[entry.exhausted_resource] ?? 0) + 1;
  }
  return {
    total: scoredRegistry.length,
    ...counts,
    by_resource,
  };
}

/** @param {string} familyId @returns {string[]} */
export function getAttackIdsByFamily(familyId) {
  return ATTACK_VECTOR_REGISTRY.filter((e) => e.exhausted_resource === familyId).map((e) => e.id);
}

/**
 * Collect every check_id referenced across ATT, NON_DDOS, and WAF registries.
 * @returns {Set<string>}
 */
export function collectMappedCheckIds() {
  const ids = new Set(WAF_SOC_CHECK_IDS);
  for (const entry of ATTACK_VECTOR_REGISTRY) {
    for (const checkId of entry.check_ids ?? []) ids.add(checkId);
  }
  for (const threat of NON_DDOS_AVAILABILITY_THREATS) {
    for (const checkId of threat.check_ids ?? []) ids.add(checkId);
  }
  for (const entry of WAF_VULNERABILITY_REGISTRY) {
    for (const checkId of entry.check_ids ?? []) ids.add(checkId);
  }
  return ids;
}

/**
 * DET-016: derive per-check resource-exhaustion metadata from the registries so the
 * catalog has a single source of truth. For each check_id this produces:
 *  - `exhausted_resource`: compatibility alias for the first mapped ATT family
 *    (registry order), or null when no ATT entry maps the check.
 *  - `exhausted_resources`: every distinct ATT family mapped to the check, in registry order.
 *  - `attack_vector_ids`: every ATT-* id referencing the check.
 *  - `delivery_patterns`: union of delivery-pattern labels from mapped entries.
 *  - `waf_vulnerability_ids` / `non_ddos_threat_ids`: WV-* / ND-* back-references.
 *
 * @returns {Map<string, {
 *   exhausted_resource: ExhaustedResource|null,
 *   exhausted_resources: ExhaustedResource[],
 *   attack_vector_ids: string[],
 *   delivery_patterns: string[],
 *   waf_vulnerability_ids: string[],
 *   non_ddos_threat_ids: string[],
 * }>}
 */
export function buildResourceExhaustionCheckMetadata() {
  const familyIds = new Set(EXHAUSTED_RESOURCE_FAMILIES.map((f) => f.id));
  const metadata = new Map();
  const ensure = (checkId) => {
    let entry = metadata.get(checkId);
    if (!entry) {
      entry = {
        exhausted_resource: null,
        exhausted_resources: [],
        attack_vector_ids: [],
        delivery_patterns: [],
        waf_vulnerability_ids: [],
        non_ddos_threat_ids: [],
      };
      metadata.set(checkId, entry);
    }
    return entry;
  };

  for (const attack of ATTACK_VECTOR_REGISTRY) {
    for (const checkId of attack.check_ids ?? []) {
      const entry = ensure(checkId);
      entry.attack_vector_ids.push(attack.id);
      if (familyIds.has(attack.exhausted_resource)) {
        if (!entry.exhausted_resources.includes(attack.exhausted_resource)) {
          entry.exhausted_resources.push(attack.exhausted_resource);
        }
        if (entry.exhausted_resource === null) {
          entry.exhausted_resource = attack.exhausted_resource;
        }
      }
      for (const pattern of attack.delivery_patterns ?? []) {
        if (!entry.delivery_patterns.includes(pattern)) entry.delivery_patterns.push(pattern);
      }
    }
  }
  for (const threat of NON_DDOS_AVAILABILITY_THREATS) {
    for (const checkId of threat.check_ids ?? []) {
      ensure(checkId).non_ddos_threat_ids.push(threat.id);
    }
  }
  for (const vuln of WAF_VULNERABILITY_REGISTRY) {
    for (const checkId of vuln.check_ids ?? []) {
      const entry = ensure(checkId);
      entry.waf_vulnerability_ids.push(vuln.id);
      if (familyIds.has(vuln.exhausted_resource)) {
        if (!entry.exhausted_resources.includes(vuln.exhausted_resource)) {
          entry.exhausted_resources.push(vuln.exhausted_resource);
        }
        if (entry.exhausted_resource === null) entry.exhausted_resource = vuln.exhausted_resource;
      }
    }
  }
  return metadata;
}

function applyRegistryEvidenceTiers(catalog) {
  registerReadinessCheckCatalog(catalog);
  for (const check of catalog) {
    check.evidence_tier = evidenceTierForCheck(check);
  }
  for (const registry of [ATTACK_VECTOR_REGISTRY, WAF_VULNERABILITY_REGISTRY]) {
    for (const entry of registry) {
      const evidenceTier = evidenceTierForTaxonomyCheckIds(entry.check_ids ?? []);
      entry.evidence_tier = evidenceTier;
      entry.coverage_status = coverageStatusForEvidenceTier(evidenceTier);
    }
  }
}

/**
 * Attach derived resource-exhaustion metadata onto catalog entries in place.
 * Every entry gets the fields (empty/null when intentionally unmapped to DDoS
 * families, e.g. WAF offensive or monitor-only operational checks).
 * @param {Array<Object>} catalog mutable CHECK_CATALOG entries
 */
export function applyResourceExhaustionMetadata(catalog) {
  applyRegistryEvidenceTiers(catalog);
  const metadata = buildResourceExhaustionCheckMetadata();
  const fallback = () => ({
    exhausted_resource: null,
    exhausted_resources: [],
    attack_vector_ids: [],
    delivery_patterns: [],
    waf_vulnerability_ids: [],
    non_ddos_threat_ids: [],
  });
  for (const check of catalog) {
    Object.assign(check, metadata.get(check.check_id) ?? fallback());
  }
  return catalog;
}
