/**
 * Resource-exhaustion DDoS taxonomy — classifies attacks by what they exhaust,
 * not just protocol layer. Validated against CHECK_CATALOG via
 * scripts/validate-resource-exhaustion-taxonomy.mjs
 */

/** @typedef {'volumetric'|'packet_processing'|'state_exhaustion'|'application_l7'|'computational'|'memory_exhaustion'|'backend_exhaustion'|'dns_exhaustion'|'reflection'|'amplification'|'exploit_dos'|'delivery_pattern'} ExhaustedResource */

/** @typedef {'implemented'|'partial'|'soc_only'|'pending'} CoverageStatus */

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
  { id: 'volumetric', label: 'Volumetric', metric: 'Gbps/Tbps', layer: 'L3/L4' },
  { id: 'packet_processing', label: 'Packet-processing', metric: 'Mpps/Bpps', layer: 'L3/L4' },
  { id: 'state_exhaustion', label: 'State exhaustion', metric: 'CPS / concurrent states', layer: 'L3/L4/L7' },
  { id: 'application_l7', label: 'Application L7', metric: 'RPS', layer: 'L7' },
  { id: 'computational', label: 'Computational', metric: 'CPU %, RPS', layer: 'L7/TLS' },
  { id: 'memory_exhaustion', label: 'Memory exhaustion', metric: 'connections/streams', layer: 'L7/TLS' },
  { id: 'backend_exhaustion', label: 'Backend exhaustion', metric: 'queries/sec', layer: 'L7/app' },
  { id: 'dns_exhaustion', label: 'DNS exhaustion', metric: 'QPS', layer: 'DNS' },
  { id: 'reflection', label: 'Reflection', metric: 'pps/bps', layer: 'L3/L4' },
  { id: 'amplification', label: 'Amplification', metric: 'amplification ratio', layer: 'L3/L4/DNS' },
  { id: 'exploit_dos', label: 'Exploit-based DoS', metric: 'varies', layer: 'L3/L7' },
  { id: 'delivery_pattern', label: 'Attack delivery pattern', metric: 'n/a', layer: 'cross-cutting' },
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
    registry_attack_ids: ['ATT-004', 'ATT-005', 'ATT-006', 'ATT-007', 'ATT-009', 'ATT-010', 'ATT-014'],
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
    registry_attack_ids: ['ATT-003', 'ATT-008', 'ATT-075', 'ATT-123', 'ATT-125', 'ATT-136', 'ATT-138', 'ATT-139'],
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
    registry_attack_ids: ['ATT-051', 'ATT-052', 'ATT-053', 'ATT-056', 'ATT-058', 'ATT-066', 'ATT-070', 'ATT-072', 'ATT-073', 'ATT-100', 'ATT-101', 'ATT-102', 'ATT-103', 'ATT-108', 'ATT-109', 'ATT-122', 'ATT-126', 'ATT-127', 'ATT-128', 'ATT-129', 'ATT-130', 'ATT-131', 'ATT-132', 'ATT-140', 'ATT-141', 'ATT-142', 'ATT-145', 'ATT-153', 'ATT-167', 'ATT-170', 'ATT-174', 'ATT-176'],
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
    registry_attack_ids: ['ATT-054', 'ATT-064', 'ATT-065', 'ATT-067', 'ATT-069', 'ATT-110', 'ATT-111', 'ATT-147', 'ATT-152', 'ATT-155', 'ATT-156'],
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
    registry_attack_ids: ['ATT-059', 'ATT-060', 'ATT-061', 'ATT-062', 'ATT-063', 'ATT-068', 'ATT-071', 'ATT-104', 'ATT-113', 'ATT-148', 'ATT-149', 'ATT-150', 'ATT-151'],
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
    registry_attack_ids: ['ATT-055', 'ATT-057', 'ATT-105', 'ATT-106', 'ATT-107', 'ATT-112', 'ATT-114', 'ATT-143', 'ATT-144', 'ATT-157', 'ATT-158', 'ATT-166'],
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
    registry_attack_ids: ['ATT-041', 'ATT-043', 'ATT-044', 'ATT-045', 'ATT-046', 'ATT-047', 'ATT-048', 'ATT-049', 'ATT-050', 'ATT-159', 'ATT-160', 'ATT-161', 'ATT-162'],
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
    registry_attack_ids: ['ATT-020', 'ATT-021', 'ATT-022', 'ATT-023', 'ATT-024', 'ATT-025', 'ATT-026', 'ATT-027', 'ATT-116', 'ATT-117', 'ATT-118', 'ATT-163', 'ATT-164', 'ATT-165', 'ATT-168'],
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
    registry_attack_ids: ['ATT-016', 'ATT-017', 'ATT-018', 'ATT-019', 'ATT-042', 'ATT-115', 'ATT-134'],
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
    registry_attack_ids: ['ATT-011', 'ATT-012', 'ATT-119', 'ATT-120', 'ATT-133', 'ATT-154'],
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
    registry_attack_ids: ['ATT-090', 'ATT-091', 'ATT-092', 'ATT-093', 'ATT-094', 'ATT-095', 'ATT-096', 'ATT-097', 'ATT-098', 'ATT-099', 'ATT-121', 'ATT-146', 'ATT-169', 'ATT-171', 'ATT-172', 'ATT-173', 'ATT-175'],
    task_ids: ['DET-022', 'DET-026', 'SOC-011'],
  },
]);

/** Vectors documented in product docs but outside classic DDoS taxonomy — tracked separately. */
export const NON_DDOS_AVAILABILITY_THREATS = Object.freeze([
  { id: 'ND-001', name: 'BGP hijacking', classification: 'routing_attack', task_id: 'DET-026', monitor_only: true, scope_boundary: 'Monitor-only integration; out of probe scope. Never conflated with DDoS readiness score.', notes: 'Not resource-exhaustion DDoS; monitor-only integration future.' },
  { id: 'ND-002', name: 'BGP route leak', classification: 'routing_incident', task_id: 'DET-026', monitor_only: true, scope_boundary: 'Monitor-only integration; out of probe scope.' },
  { id: 'ND-003', name: 'DNS hijacking / cache poisoning', classification: 'dns_integrity', task_id: 'DET-026', monitor_only: true, scope_boundary: 'Monitor-only integration; out of probe scope.' },
  { id: 'ND-004', name: 'Control-plane autoscaling cost exhaustion', classification: 'operational_exhaustion', task_id: 'DET-026', check_ids: ['l7.health_check_flood.readiness', 'ops.autoscaling_cost.readiness'], notes: 'Health-check flood triggering scale-out; maps to ATT-109.' },
  { id: 'ND-005', name: 'Alert fatigue / blind spots during attack', classification: 'operational_exhaustion', task_id: 'DET-026', check_ids: ['ops.alert_workflow_marker.safe', 'ops.attack_alert_coverage.readiness'] },
  { id: 'ND-006', name: 'Credential stuffing / brute force', classification: 'authentication_attack', task_id: null, notes: 'Out of scope for DDoS taxonomy; partial overlap l7.login_abuse_flow.safe.' },
  { id: 'ND-007', name: 'Provider control-plane API rate exhaustion', classification: 'operational_exhaustion', task_id: 'DET-026', monitor_only: true, scope_boundary: 'Monitor-only provider-API budget guardrail; no probe.', notes: 'Cloud API throttling during mitigation orchestration.' },
  { id: 'ND-008', name: 'Log / SIEM ingestion cost exhaustion', classification: 'operational_exhaustion', task_id: 'DET-026', monitor_only: true, scope_boundary: 'Monitor-only telemetry-budget guardrail; no probe.', notes: 'Telemetry flood raises observability cost without service outage.' },
  { id: 'ND-009', name: 'Certificate transparency / CT log noise', classification: 'operational_exhaustion', task_id: 'DET-026', monitor_only: true, scope_boundary: 'Monitor-only; out of probe scope.', notes: 'Monitor-only; related to ATT-122 origin leakage.' },
]);

/** @type {readonly AttackVectorEntry[]} */
export const ATTACK_VECTOR_REGISTRY = Object.freeze([
  // --- L3/L4 volumetric & packet processing ---
  { id: 'ATT-001', name: 'UDP flood', exhausted_resource: 'volumetric', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.forbidden_udp_port.safe', 'high_scale.volumetric.request_only'], notes: 'Single-datagram probe + SOC volumetric marker; no flood generator in repo.' },
  { id: 'ATT-002', name: 'ICMP / ping flood', exhausted_resource: 'volumetric', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.icmp_flood.readiness', 'high_scale.volumetric.request_only'], notes: 'Bounded readiness posture + SOC volumetric scenario; no flood generator in repo.' },
  { id: 'ATT-003', name: 'SYN flood', exhausted_resource: 'state_exhaustion', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.forbidden_tcp_port.safe', 'l3.basic_deny_rule.safe', 'l3.syn_flood.readiness', 'l3.connection_table_exhaustion.request_only', 'high_scale.volumetric.request_only'] },
  { id: 'ATT-004', name: 'ACK flood', exhausted_resource: 'packet_processing', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.ack_flood.readiness'], notes: 'Readiness posture via declared PPS policy + agent observation; execution is SOC-gated.' },
  { id: 'ATT-005', name: 'SYN-ACK flood', exhausted_resource: 'packet_processing', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.syn_ack_flood.readiness'] },
  { id: 'ATT-006', name: 'RST flood', exhausted_resource: 'packet_processing', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.rst_flood.readiness'] },
  { id: 'ATT-007', name: 'TCP flag floods (FIN/PSH/URG/NULL/Xmas)', exhausted_resource: 'packet_processing', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.tcp_flag_anomaly.readiness'] },
  { id: 'ATT-008', name: 'TCP connection flood', exhausted_resource: 'state_exhaustion', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.connection_table_exhaustion.request_only', 'l3.tcp_connection_flood.readiness'] },
  { id: 'ATT-009', name: 'Out-of-state TCP flood', exhausted_resource: 'packet_processing', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.out_of_state_tcp.readiness'] },
  { id: 'ATT-010', name: 'Fragmentation flood', exhausted_resource: 'packet_processing', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.fragmentation_flood.readiness'] },
  { id: 'ATT-011', name: 'Ping of Death', exhausted_resource: 'exploit_dos', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['exploit.ping_of_death.posture'], notes: 'Patch/filtering posture only; exploit validation is isolated-lab SOC scope.' },
  { id: 'ATT-012', name: 'Teardrop', exhausted_resource: 'exploit_dos', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['exploit.teardrop.posture'] },
  { id: 'ATT-013', name: 'GRE flood', exhausted_resource: 'volumetric', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.gre_esp_flood.readiness', 'high_scale.volumetric.request_only'] },
  { id: 'ATT-014', name: 'ESP / IPsec flood', exhausted_resource: 'packet_processing', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.gre_esp_flood.readiness'] },
  { id: 'ATT-015', name: 'QUIC flood', exhausted_resource: 'volumetric', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['protocol.http3_quic_exposure.safe', 'high_scale.volumetric.request_only'] },

  // --- Reflection / amplification (16–40) ---
  { id: 'ATT-016', name: 'DNS reflection/amplification', exhausted_resource: 'amplification', coverage_status: 'partial', task_id: 'DET-018', check_ids: ['dns.amplification_exposure.safe'] },
  { id: 'ATT-017', name: 'NTP amplification', exhausted_resource: 'amplification', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['amp.ntp_exposure.safe'], notes: 'Config/mode-6-7 restriction posture metadata; no amplifier query traffic.' },
  { id: 'ATT-018', name: 'CLDAP amplification', exhausted_resource: 'amplification', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['amp.cldap_exposure.safe'], notes: 'Exposed-LDAP posture metadata only.' },
  { id: 'ATT-019', name: 'Memcached amplification', exhausted_resource: 'amplification', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['amp.memcached_exposure.safe'], notes: 'One bounded TCP connect exposure check; no UDP memcached query.' },
  { id: 'ATT-020', name: 'SSDP/UPnP and device-discovery reflection', exhausted_resource: 'reflection', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['reflect.ssdp_exposure.safe', 'reflect.legacy_device_discovery_exposure.safe'], notes: 'Single bounded UDP fingerprint on declared host; response size class metadata only. Device-management discovery classes (Ubiquiti, Lantronix, VxWorks/WDBRPC) covered by the legacy discovery check.' },
  { id: 'ATT-021', name: 'SNMP reflection', exhausted_resource: 'reflection', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['reflect.snmp_exposure.safe'] },
  { id: 'ATT-022', name: 'CHARGEN/QOTD/Echo reflection', exhausted_resource: 'reflection', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['reflect.chargen_qotd_exposure.safe'] },
  { id: 'ATT-023', name: 'mDNS / NetBIOS / WS-Discovery reflection', exhausted_resource: 'reflection', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['reflect.mdns_netbios_wsdiscovery_exposure.safe'] },
  { id: 'ATT-024', name: 'Portmap/RIPv1/BitTorrent/Jenkins/TeamSpeak reflectors', exhausted_resource: 'reflection', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['reflect.portmap_service_exposure.safe', 'reflect.jenkins_discovery_exposure.safe', 'reflect.legacy_device_discovery_exposure.safe'], notes: 'Portmapper/RIPv1/RPC via the service-exposure check; Jenkins via discovery; TeamSpeak 3 and game/voice discovery via the legacy discovery check.' },
  { id: 'ATT-025', name: 'DTLS / SIP / RDP / TFTP / ARMS / CoAP reflection', exhausted_resource: 'reflection', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['reflect.dtls_sip_rdp_tftp_exposure.safe'] },
  { id: 'ATT-026', name: 'QUIC reflection', exhausted_resource: 'reflection', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['reflect.quic_reflection_exposure.safe'] },
  { id: 'ATT-027', name: 'TCP middlebox reflection', exhausted_resource: 'reflection', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['reflect.tcp_middlebox_exposure.safe'] },

  // --- DNS exhaustion (41–50) ---
  { id: 'ATT-041', name: 'DNS query flood', exhausted_resource: 'dns_exhaustion', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.authoritative_response.safe', 'high_scale.dns_high_query.request_only'] },
  { id: 'ATT-042', name: 'DNS amplification (authoritative/resolver)', exhausted_resource: 'amplification', coverage_status: 'implemented', task_id: 'DET-019', check_ids: ['dns.amplification_exposure.safe', 'dns.open_recursion_behavior.safe', 'amp.authoritative_resolver_exposure.safe', 'dns.qname_minimization.readiness'] },
  { id: 'ATT-043', name: 'NXDOMAIN flood', exhausted_resource: 'dns_exhaustion', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.random_prefix_nxdomain.safe'] },
  { id: 'ATT-044', name: 'Random-subdomain / water-torture', exhausted_resource: 'dns_exhaustion', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.random_prefix_nxdomain.safe'] },
  { id: 'ATT-045', name: 'DNS laundering', exhausted_resource: 'dns_exhaustion', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.laundering.readiness'], notes: 'Readiness posture via declared resolver policy; no laundering query sequences.' },
  { id: 'ATT-046', name: 'DNS garbage flood', exhausted_resource: 'dns_exhaustion', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.garbage_flood.readiness'] },
  { id: 'ATT-047', name: 'Phantom domain attack', exhausted_resource: 'dns_exhaustion', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.phantom_domain.readiness'] },
  { id: 'ATT-048', name: 'DNS domain lock-up', exhausted_resource: 'dns_exhaustion', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.domain_lockup.readiness'] },
  { id: 'ATT-049', name: 'NXNSAttack', exhausted_resource: 'dns_exhaustion', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.nxns_attack.readiness'], notes: 'Bounded NS delegation lookup of declared zone; no referral flood.' },
  { id: 'ATT-050', name: 'DNSBomb', exhausted_resource: 'dns_exhaustion', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.dnsbomb.readiness'], notes: 'Pulsed TTL / deferred-response posture metadata + provider telemetry.' },

  // --- L7 / application (51–75) ---
  { id: 'ATT-051', name: 'HTTP GET flood', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.http_method_restriction.safe', 'l7.low_rate_rate_limit.safe', 'l7.http_get_flood.validation', 'high_scale.application.request_only'] },
  { id: 'ATT-052', name: 'HTTP POST flood', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.http_post_flood.validation', 'high_scale.application.request_only'], notes: 'Declared-endpoint limit readiness; POST flood execution is SOC-gated.' },
  { id: 'ATT-053', name: 'HTTP HEAD flood', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.http_method_restriction.safe'] },
  { id: 'ATT-054', name: 'Dynamic-endpoint / computational DDoS', exhausted_resource: 'computational', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.expensive_endpoint.safe', 'l7.graphql_complexity.safe'] },
  { id: 'ATT-055', name: 'Database exhaustion attack', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.api_quota_exhaustion.safe', 'l7.graphql_complexity.safe'] },
  {
    id: 'ATT-056',
    name: 'API flood',
    exhausted_resource: 'application_l7',
    coverage_status: 'partial',
    task_id: 'DET-020',
    check_ids: [
      'l7.api_surface_scan.safe',
      'l7.api_quota_exhaustion.safe',
    ],
  },
  { id: 'ATT-057', name: 'GraphQL exhaustion', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.graphql_complexity.safe'] },
  { id: 'ATT-058', name: 'Cache-busting DDoS', exhausted_resource: 'application_l7', coverage_status: 'implemented', task_id: 'DET-020', check_ids: ['l7.cache_busting.safe'] },
  { id: 'ATT-059', name: 'Large-payload POST', exhausted_resource: 'memory_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.header_size_boundary.safe', 'l7.large_body_post.readiness'] },
  { id: 'ATT-060', name: 'Slowloris', exhausted_resource: 'memory_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['tls.slow_header_body_timeout.safe', 'l7.slowloris.readiness'], notes: 'Timeout policy + header-drain readiness; no sustained partial headers hold.' },
  { id: 'ATT-061', name: 'Slow POST / RUDY', exhausted_resource: 'memory_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.slow_post.readiness'] },
  { id: 'ATT-062', name: 'Slow read', exhausted_resource: 'memory_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.slow_read.readiness'] },
  { id: 'ATT-063', name: 'Generic low-and-slow DDoS', exhausted_resource: 'memory_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.low_and_slow.readiness'] },
  { id: 'ATT-064', name: 'TLS handshake / SSL negotiation exhaustion', exhausted_resource: 'computational', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['tls.full_audit.safe', 'tls.profile_exposure.safe', 'tls.handshake_rate.readiness'] },
  { id: 'ATT-065', name: 'TLS renegotiation attacks', exhausted_resource: 'computational', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['tls.renegotiation.readiness'] },
  { id: 'ATT-066', name: 'HTTP/2 multiplexing flood', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['protocol.http2_stream_concurrency.safe'] },
  { id: 'ATT-067', name: 'HTTP/2 Rapid Reset', exhausted_resource: 'computational', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['protocol.http2_rapid_reset_readiness.safe', 'l7.http2_rapid_reset.validation'], notes: 'Bounded SETTINGS/reset-policy validation; reset-storm execution is SOC-gated.' },
  { id: 'ATT-068', name: 'HTTP/2 CONTINUATION flood', exhausted_resource: 'memory_exhaustion', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['l7.http2_continuation.readiness'], notes: 'Header-frame limit readiness via bounded HTTP/2 SETTINGS probe.' },
  { id: 'ATT-069', name: 'HTTP/2 MadeYouReset', exhausted_resource: 'computational', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['l7.http2_made_you_reset.readiness'], notes: 'CVE-2025-8671 class readiness via settings/flow-control metadata.' },
  { id: 'ATT-070', name: 'HTTP/3 / QUIC application flood', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['protocol.http3_quic_exposure.safe', 'high_scale.application.request_only'] },
  { id: 'ATT-071', name: 'WebSocket DDoS', exhausted_resource: 'memory_exhaustion', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['protocol.websocket_connection_controls.safe', 'protocol.websocket_message_rate.readiness'] },
  { id: 'ATT-072', name: 'gRPC / RPC floods', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['protocol.grpc_reflection_stream.safe'], notes: 'Bounded single gRPC health/reflection reachability probe; stream flood execution is SOC-gated.' },
  { id: 'ATT-073', name: 'WordPress XML-RPC / pingback DDoS', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.wordpress_xmlrpc.readiness'] },
  { id: 'ATT-074', name: 'SIP / VoIP flood', exhausted_resource: 'volumetric', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.sip_voip_flood.readiness', 'high_scale.volumetric.request_only'] },
  { id: 'ATT-075', name: 'Application connection exhaustion', exhausted_resource: 'state_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['tls.idle_connection_timeout.safe', 'l3.connection_table_exhaustion.request_only', 'l7.connection_hoarding.readiness'] },

  // --- Delivery patterns ---
  { id: 'ATT-090', name: 'Direct flood', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-022', delivery_patterns: ['direct'], check_ids: ['high_scale.volumetric.request_only'] },
  { id: 'ATT-091', name: 'Spoofed flood', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-022', delivery_patterns: ['spoofed'], check_ids: ['pattern.spoofed_source.readiness'], notes: 'BCP38/uRPF ingress-filtering readiness posture.' },
  { id: 'ATT-092', name: 'DRDoS / reflection delivery', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-022', delivery_patterns: ['drdos'], check_ids: ['dns.amplification_exposure.safe'] },
  { id: 'ATT-093', name: 'Coordinated Device Swarm DDoS (docs: ATT-093)', exhausted_resource: 'delivery_pattern', coverage_status: 'soc_only', task_id: 'DET-022', delivery_patterns: ['coordinated_swarm'], check_ids: ['high_scale.multi_vector.request_only'] },
  { id: 'ATT-094', name: 'Carpet bombing', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-022', delivery_patterns: ['carpet_bombing'], check_ids: ['pattern.carpet_bombing.readiness'], notes: 'Multi-port/multi-destination scrubbing readiness; execution is SOC-gated.' },
  { id: 'ATT-095', name: 'Pulse-wave / burst attacks', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-022', delivery_patterns: ['pulse_wave'], check_ids: ['pattern.pulse_wave.readiness'] },
  { id: 'ATT-096', name: 'Multi-vector / vector switching', exhausted_resource: 'delivery_pattern', coverage_status: 'soc_only', task_id: 'DET-022', delivery_patterns: ['multi_vector'], check_ids: ['high_scale.multi_vector.request_only'] },
  { id: 'ATT-097', name: 'Application-aware targeting', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-022', delivery_patterns: ['application_aware'], check_ids: ['l7.expensive_endpoint.safe'] },

  // --- Origin / edge (readiness, not numbered in user list) ---
  { id: 'ATT-100', name: 'Direct origin bypass', exhausted_resource: 'application_l7', coverage_status: 'implemented', task_id: 'DET-001', check_ids: ['origin.direct_bypass.safe', 'origin.direct_reachability.safe', 'origin.host_sni_bypass.safe'] },
  { id: 'ATT-101', name: 'Origin leak scan', exhausted_resource: 'application_l7', coverage_status: 'implemented', task_id: 'DET-001', check_ids: ['origin.leak_scan.safe'] },
  { id: 'ATT-102', name: 'WAF marker / enforcement', exhausted_resource: 'application_l7', coverage_status: 'implemented', task_id: 'DET-007', check_ids: ['waf.marker_rule.safe', 'waf.enforcement.safe', 'l7.waf_marker_rule.safe'] },

  // --- Gap analysis: documented elsewhere but missing from initial registry ---
  { id: 'ATT-103', name: 'CDN / shield bypass', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-001', check_ids: ['origin.direct_bypass.safe', 'origin.host_sni_bypass.safe', 'origin.cdn_bypass.readiness'] },
  { id: 'ATT-104', name: 'SSE long-lived stream exhaustion', exhausted_resource: 'memory_exhaustion', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['protocol.sse_stream.readiness'], notes: 'SSE duration/connection-limit readiness metadata.' },
  { id: 'ATT-105', name: 'Search endpoint abuse', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.search_abuse.validation'], notes: 'Declared search endpoint low-rate sequence validation.' },
  { id: 'ATT-106', name: 'Export / report generation abuse', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.export_abuse.validation'] },
  { id: 'ATT-107', name: 'Batch API abuse', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.batch_api_abuse.validation'] },
  { id: 'ATT-108', name: 'Webhook / callback flood', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.webhook_flood.readiness'] },
  { id: 'ATT-109', name: 'Health-check endpoint flood', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-026', check_ids: ['l7.health_check_flood.readiness'], notes: 'Can trigger autoscaling cost exhaustion (ND-004).' },
  { id: 'ATT-110', name: 'HTTP/2 priority tree abuse', exhausted_resource: 'computational', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['l7.http2_priority_abuse.readiness'] },
  { id: 'ATT-111', name: 'TLS 0-RTT / early data abuse', exhausted_resource: 'computational', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['tls.zero_rtt.readiness'] },
  { id: 'ATT-112', name: 'OAuth / token endpoint abuse', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.login_abuse_flow.safe', 'l7.api_quota_exhaustion.safe', 'l7.oauth_token_abuse.validation'] },
  { id: 'ATT-113', name: 'File upload flood', exhausted_resource: 'memory_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.file_upload_abuse.readiness'] },
  { id: 'ATT-114', name: 'GraphQL batch / alias abuse', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.graphql_complexity.safe', 'l7.graphql_batch_abuse.validation'], notes: 'Depth/complexity plus batch-limit readiness.' },
  { id: 'ATT-115', name: 'DNS ANY/TXT query class abuse', exhausted_resource: 'amplification', coverage_status: 'implemented', task_id: 'DET-019', check_ids: ['dns.amplification_exposure.safe', 'dns.dnssec_expensive_query.safe', 'amp.dns_any_txt_exposure.safe'] },
  { id: 'ATT-116', name: 'MSSQL resolver reflection', exhausted_resource: 'reflection', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['reflect.mssql_resolver_exposure.safe'] },
  { id: 'ATT-117', name: 'Jenkins / CI discovery reflection', exhausted_resource: 'reflection', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['reflect.jenkins_discovery_exposure.safe'] },
  { id: 'ATT-118', name: 'CoAP / IoT device-management reflector abuse', exhausted_resource: 'reflection', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['reflect.coap_iot_exposure.safe', 'reflect.legacy_device_discovery_exposure.safe'], notes: 'CoAP plus embedded device-management discovery classes (Lantronix, VxWorks/WDBRPC) via the legacy discovery check.' },
  { id: 'ATT-119', name: 'IP options / malformed IP header abuse', exhausted_resource: 'exploit_dos', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['exploit.ip_options.posture'] },
  { id: 'ATT-120', name: 'Malformed QUIC version / spin bit abuse', exhausted_resource: 'exploit_dos', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['exploit.malformed_quic.posture'] },
  { id: 'ATT-121', name: 'Adaptive / randomized flood (entropy evasion)', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-022', delivery_patterns: ['adaptive_evasion'], check_ids: ['pattern.adaptive_evasion.readiness'] },
  { id: 'ATT-122', name: 'Certificate / SAN origin leakage', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-001', check_ids: ['origin.leak_scan.safe', 'tls.profile_exposure.safe'] },
  { id: 'ATT-123', name: 'SMTP / email connection flood', exhausted_resource: 'state_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l3.smtp_connection_flood.readiness'] },
  { id: 'ATT-124', name: 'IPv6 volumetric flood (beyond reachability check)', exhausted_resource: 'volumetric', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.ipv6_reachability.safe', 'l3.ipv6_volumetric.readiness'], notes: 'Reachability plus IPv6 filtering readiness; no volumetric execution.' },
  { id: 'ATT-125', name: 'NAT / firewall state table exhaustion', exhausted_resource: 'state_exhaustion', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.nat_state_table.readiness'] },
  { id: 'ATT-098', name: 'Ransom DDoS (extortion workflow)', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-022', delivery_patterns: ['ransom'], check_ids: ['pattern.ransom_ddos.readiness'], notes: 'Extortion runbook readiness marker; SOC workflow + audit; not a probe vector.' },
  { id: 'ATT-099', name: 'Multi-destination / multi-service simultaneous attack', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-022', delivery_patterns: ['multi_destination'], check_ids: ['high_scale.multi_vector.request_only'] },

  // --- Origin / edge exposure (enables direct-path DDoS) ---
  { id: 'ATT-126', name: 'Stale DNS / legacy subdomain origin leak', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-001', check_ids: ['origin.leak_scan.safe'] },
  { id: 'ATT-127', name: 'DNS-only hostname bypass', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-001', check_ids: ['origin.dns_hostname_bypass.readiness'], notes: 'DNS alias/hostname coverage readiness; no dedicated bypass probe.' },
  { id: 'ATT-128', name: 'Protected canary path bypass', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-001', check_ids: ['path.protected_canary.safe'] },
  { id: 'ATT-129', name: 'Admin / management surface exposure', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-001', check_ids: ['l3.firewall_exposure_scan.safe'], notes: 'Port scan finds admin surfaces; not admin-specific check.' },
  { id: 'ATT-130', name: 'Ephemeral port / accidental service exposure', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.firewall_exposure_scan.safe'] },
  { id: 'ATT-131', name: 'WAF-to-origin bypass path', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-001', check_ids: ['waf.origin_bypass.safe', 'origin.direct_bypass.safe'] },
  { id: 'ATT-132', name: 'HTTP TRACE / unusual method abuse', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.http_method_restriction.safe'] },

  // --- L3/L4 extended ---
  { id: 'ATT-133', name: 'Land attack (same src/dst IP)', exhausted_resource: 'exploit_dos', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['exploit.land_attack.posture'] },
  { id: 'ATT-134', name: 'Smurf / ICMP-to-broadcast amplification', exhausted_resource: 'amplification', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['amp.smurf_broadcast_exposure.safe'], notes: 'Directed-broadcast filtering posture metadata.' },
  { id: 'ATT-135', name: 'SCTP flood', exhausted_resource: 'volumetric', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.sctp_exposure.readiness'] },
  { id: 'ATT-136', name: 'IKE / IPsec negotiation flood', exhausted_resource: 'state_exhaustion', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.ike_ipsec_negotiation.readiness'] },
  { id: 'ATT-137', name: 'Multicast / broadcast storm', exhausted_resource: 'volumetric', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.multicast_broadcast_storm.readiness'] },
  { id: 'ATT-138', name: 'SSH connection flood', exhausted_resource: 'state_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l3.ssh_connection_flood.readiness'] },
  { id: 'ATT-139', name: 'FTP connection flood', exhausted_resource: 'state_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l3.ftp_connection_flood.readiness'] },

  // --- L7 extended ---
  { id: 'ATT-140', name: 'HTTP pipelining abuse', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.http_pipelining.readiness'] },
  { id: 'ATT-141', name: 'HTTP Range header abuse', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.http_range_abuse.readiness'] },
  { id: 'ATT-142', name: 'HTTP conditional revalidation flood (If-None-Match/IMS)', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.conditional_revalidation.readiness'] },
  { id: 'ATT-143', name: 'Checkout / cart transaction abuse', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.checkout_abuse.validation'], notes: 'Customer-declared endpoint only.' },
  { id: 'ATT-144', name: 'OTP / SMS cost exhaustion', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.login_abuse_flow.safe', 'l7.otp_sms_cost.readiness'] },
  { id: 'ATT-145', name: 'CAPTCHA / challenge endpoint abuse', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.bot_challenge_marker.safe', 'l7.captcha_challenge_abuse.readiness'] },
  { id: 'ATT-146', name: 'Distributed low-rate / residential proxy flood', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-022', delivery_patterns: ['residential_proxy'], check_ids: ['pattern.residential_proxy.readiness'] },

  // --- Computational / parser bombs ---
  { id: 'ATT-147', name: 'ReDoS / regex algorithmic complexity', exhausted_resource: 'computational', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.redos.readiness'] },
  { id: 'ATT-148', name: 'JSON bomb / deeply nested payload', exhausted_resource: 'memory_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.json_xml_bomb.readiness'] },
  { id: 'ATT-149', name: 'XML bomb / entity expansion (billion laughs class)', exhausted_resource: 'memory_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.json_xml_bomb.readiness'] },
  { id: 'ATT-150', name: 'HPACK decompression bomb', exhausted_resource: 'memory_exhaustion', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['l7.hpack_bomb.readiness'] },
  { id: 'ATT-151', name: 'HTTP/2 push promise abuse', exhausted_resource: 'memory_exhaustion', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['l7.http2_push_promise.readiness'] },
  { id: 'ATT-152', name: 'QPACK / HTTP/3 header compression bomb', exhausted_resource: 'computational', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['l7.qpack_bomb.readiness'] },
  { id: 'ATT-153', name: 'HTTP/3 control stream / SETTINGS flood', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['protocol.http3_control_stream.readiness'] },
  { id: 'ATT-154', name: 'QUIC migration / path validation abuse', exhausted_resource: 'exploit_dos', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['exploit.quic_migration.posture'] },
  { id: 'ATT-155', name: 'OCSP stapling / certificate validation exhaustion', exhausted_resource: 'computational', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['tls.ocsp_stapling.readiness'] },
  { id: 'ATT-156', name: 'Cipher suite negotiation exhaustion', exhausted_resource: 'computational', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['tls.full_audit.safe', 'tls.profile_exposure.safe'] },

  // --- Backend / signup ---
  { id: 'ATT-157', name: 'Signup / registration flood', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.login_abuse_flow.safe', 'l7.signup_registration_abuse.validation'] },
  { id: 'ATT-158', name: 'Password reset OTP flood', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.password_reset.safe'] },

  // --- DNS extended ---
  { id: 'ATT-159', name: 'DNS over HTTPS/TLS (DoH/DoT) query exhaustion', exhausted_resource: 'dns_exhaustion', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.doh_dot_exposure.readiness'] },
  { id: 'ATT-160', name: 'DNS TCP fallback / truncation pressure', exhausted_resource: 'dns_exhaustion', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.tcp_fallback.readiness'] },
  { id: 'ATT-161', name: 'DNS zone walking / enumeration at scale', exhausted_resource: 'dns_exhaustion', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.zone_transfer_exposure.safe', 'dns.zone_walking.readiness'], notes: 'AXFR plus NSEC walking posture.' },
  { id: 'ATT-162', name: 'DNS secondary failover stress', exhausted_resource: 'dns_exhaustion', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.secondary_failover.safe'] },

  // --- Reflection / protocol extended ---
  { id: 'ATT-163', name: 'STUN/TURN reflection', exhausted_resource: 'reflection', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['reflect.stun_turn_exposure.safe'] },
  { id: 'ATT-164', name: 'IPMI / BMC reflector exposure', exhausted_resource: 'reflection', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['reflect.ipmi_bmc_exposure.safe'] },
  { id: 'ATT-165', name: 'Redis direct protocol flood', exhausted_resource: 'reflection', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['reflect.redis_direct_exposure.safe'], notes: 'Open Redis exposure metadata via one bounded TCP connect; not Memcached amp.' },
  { id: 'ATT-166', name: 'Elasticsearch / OpenSearch query flood', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.elasticsearch_abuse.readiness'] },
  { id: 'ATT-167', name: 'MQTT broker flood', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.mqtt_broker_exposure.readiness'] },
  { id: 'ATT-168', name: 'OpenVPN / WireGuard reflector exposure', exhausted_resource: 'reflection', coverage_status: 'implemented', task_id: 'DET-018', check_ids: ['reflect.openvpn_wireguard_exposure.safe'] },

  // --- Delivery / operational ---
  { id: 'ATT-169', name: 'API scraping / enumeration at scale', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-022', delivery_patterns: ['api_scraping'], check_ids: ['l7.api_surface_scan.safe'] },
  { id: 'ATT-170', name: 'WAF bypass enabling volumetric success', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-001', check_ids: ['waf.fingerprint.safe', 'waf.enforcement.safe', 'waf.marker_rule.safe'] },
  { id: 'ATT-171', name: 'Kill-switch / runbook failure under attack load', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-026', delivery_patterns: ['recovery_drill'], check_ids: ['ops.kill_switch_drill.safe', 'ops.kill_switch_drill.request_only', 'ops.runbook_contact_validation.safe', 'ops.runbook_contact_validation.request_only'] },
  { id: 'ATT-172', name: 'Provider telemetry blind spot during test', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-026', check_ids: ['ops.provider_telemetry.request_only', 'ops.attack_alert_coverage.readiness'] },
  { id: 'ATT-173', name: 'Post-attack degradation / recovery drill', exhausted_resource: 'delivery_pattern', coverage_status: 'soc_only', task_id: 'DET-022', delivery_patterns: ['recovery_drill'], check_ids: ['high_scale.degradation_recovery.request_only'] },
  { id: 'ATT-174', name: 'CORS misconfiguration enabling cross-origin abuse', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.cors_posture.safe'], notes: 'Configuration exposure; enables browser-origin abuse patterns.' },
  { id: 'ATT-175', name: 'Rate-limit evasion via header/IP rotation', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-022', delivery_patterns: ['rate_limit_evasion'], check_ids: ['l7.low_rate_rate_limit.safe', 'waf.low_rate_limit.safe', 'pattern.rate_limit_evasion.readiness'] },
  { id: 'ATT-176', name: 'HTTP/2 general protocol readiness gap', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['protocol.http2_readiness.safe'] },
]);

/** WAF offensive validation — separate from DDoS resource-exhaustion; SOC-only. */
export const WAF_VULNERABILITY_REGISTRY = Object.freeze([
  { id: 'WV-001', name: 'SQL injection WAF validation', check_ids: ['waf.offensive_sqli.soc'], task_id: 'DET-007', classification: 'waf_offensive_soc' },
  { id: 'WV-002', name: 'XSS WAF validation', check_ids: ['waf.offensive_xss.soc'], task_id: 'DET-007', classification: 'waf_offensive_soc' },
  { id: 'WV-003', name: 'RCE WAF validation', check_ids: ['waf.offensive_rce.soc'], task_id: 'DET-007', classification: 'waf_offensive_soc' },
  { id: 'WV-004', name: 'Path traversal WAF validation', check_ids: ['waf.offensive_path_traversal.soc'], task_id: 'DET-007', classification: 'waf_offensive_soc' },
  { id: 'WV-005', name: 'Command injection WAF validation', check_ids: ['waf.offensive_command_injection.soc'], task_id: 'DET-007', classification: 'waf_offensive_soc' },
  { id: 'WV-006', name: 'LDAP injection WAF validation', check_ids: ['waf.offensive_ldap_injection.soc'], task_id: 'DET-007', classification: 'waf_offensive_soc' },
  { id: 'WV-007', name: 'SSTI WAF validation', check_ids: ['waf.offensive_ssti.soc'], task_id: 'DET-007', classification: 'waf_offensive_soc' },
  { id: 'WV-008', name: 'Combined WAF offensive suite', check_ids: ['waf.offensive_combined.soc'], task_id: 'DET-007', classification: 'waf_offensive_soc' },
]);

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
  for (const entry of registry) {
    counts[entry.coverage_status] += 1;
    by_resource[entry.exhausted_resource] = (by_resource[entry.exhausted_resource] ?? 0) + 1;
  }
  return {
    total: registry.length,
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
 *  - `exhausted_resource`: family of the first mapped ATTACK_VECTOR_REGISTRY entry
 *    (registry order), or null when the check is only mapped to non-DDoS threats
 *    (ND-*) or the WAF vulnerability registry (WV-*) — those checks are not scored
 *    in the DDoS resource-exhaustion readiness matrix.
 *  - `attack_vector_ids`: every ATT-* id referencing the check.
 *  - `delivery_patterns`: union of delivery-pattern labels from mapped entries.
 *  - `waf_vulnerability_ids` / `non_ddos_threat_ids`: WV-* / ND-* back-references.
 *
 * @returns {Map<string, {
 *   exhausted_resource: ExhaustedResource|null,
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
      if (entry.exhausted_resource === null && familyIds.has(attack.exhausted_resource)) {
        entry.exhausted_resource = attack.exhausted_resource;
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
      ensure(checkId).waf_vulnerability_ids.push(vuln.id);
    }
  }
  return metadata;
}

/**
 * Attach derived resource-exhaustion metadata onto catalog entries in place.
 * Every entry gets the fields (empty/null when intentionally unmapped to DDoS
 * families, e.g. WAF offensive or monitor-only operational checks).
 * @param {Array<Object>} catalog mutable CHECK_CATALOG entries
 */
export function applyResourceExhaustionMetadata(catalog) {
  const metadata = buildResourceExhaustionCheckMetadata();
  const fallback = () => ({
    exhausted_resource: null,
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
