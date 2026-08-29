/**
 * Resource-exhaustion DDoS taxonomy — classifies attacks by what they exhaust,
 * not just protocol layer. Validated against CHECK_CATALOG via
 * scripts/validate-resource-exhaustion-taxonomy.mjs
 */

/** @typedef {'volumetric'|'packet_processing'|'state_exhaustion'|'application_l7'|'computational'|'memory_exhaustion'|'backend_exhaustion'|'dns_exhaustion'|'reflection'|'amplification'|'exploit_dos'|'delivery_pattern'} ExhaustedResource */

/** @typedef {'implemented'|'partial'|'soc_only'|'pending'} CoverageStatus */

/**
 * @typedef {Object} AttackVectorEntry
 * @property {string} id
 * @property {string} name
 * @property {ExhaustedResource} exhausted_resource
 * @property {CoverageStatus} coverage_status
 * @property {string} task_id
 * @property {string[]} [check_ids]
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
    has_today: ['l3.forbidden_udp_port.safe', 'protocol.http3_quic_exposure.safe', 'high_scale.volumetric.request_only'],
    build_checks: ['l3.icmp_flood.readiness', 'l3.gre_esp_flood.readiness', 'l3.ipv6_volumetric.readiness', 'protocol.quic_flood.validation'],
    build_probes: ['icmp_echo_bounded', 'gre_datagram_bounded', 'quic_initial_flood_profile', 'volumetric_udp_profile', 'volumetric_icmp_profile'],
    build_soc: ['high_scale.volumetric.request_only scenario families: udp_flood, icmp_flood, gre_flood, quic_flood'],
    build_ui: ['Dashboard Gbps/Tbps readiness chip per target group', 'High-scale request scenario picker by volumetric class'],
    build_telemetry: ['provider_bps_pps', 'interface_drops', 'scrubber_redirect_state'],
    missing_vectors: ['ATT-002 ICMP', 'ATT-013 GRE', 'ATT-014 ESP/IPsec', 'ATT-074 SIP/VoIP', 'ATT-124 IPv6 volumetric', 'ATT-135 SCTP', 'ATT-137 multicast/broadcast'],
    registry_attack_ids: ['ATT-001', 'ATT-002', 'ATT-013', 'ATT-015', 'ATT-074', 'ATT-124', 'ATT-135', 'ATT-137'],
    task_ids: ['DET-017', 'DET-023', 'SOC-011'],
  },
  {
    id: 'packet_processing',
    research_sources: ['Cloudflare ACK/RST/out-of-state TCP', 'AWS protocol attacks', 'Microsoft fragmentation attacks'],
    has_today: ['l3.firewall_exposure_scan.safe', 'l3.basic_deny_rule.safe'],
    build_checks: ['l3.ack_flood.readiness', 'l3.rst_flood.readiness', 'l3.syn_ack_flood.readiness', 'l3.tcp_flag_anomaly.readiness', 'l3.out_of_state_tcp.readiness', 'l3.fragmentation_flood.readiness'],
    build_probes: ['tcp_flag_probe', 'fragment_policy_probe', 'stateful_firewall_lookup_probe'],
    build_soc: ['packet_processing scenario metadata on high_scale.volumetric.request_only'],
    build_ui: ['PPS/Bpps budget display on run detail when telemetry present'],
    build_telemetry: ['mpps', 'firewall_cpu', 'nic_drops', 'fragment_reassembly_errors'],
    missing_vectors: ['ATT-004–010', 'ATT-119 IP options', 'ATT-133 Land', 'ATT-130 ephemeral ports'],
    registry_attack_ids: ['ATT-004', 'ATT-005', 'ATT-006', 'ATT-007', 'ATT-009', 'ATT-010', 'ATT-014'],
    task_ids: ['DET-017', 'DET-023'],
  },
  {
    id: 'state_exhaustion',
    research_sources: ['AWS SYN flood', 'Cloudflare TCP connection floods', 'Microsoft connection exhaustion'],
    has_today: ['l3.forbidden_tcp_port.safe', 'l3.connection_table_exhaustion.request_only', 'tls.idle_connection_timeout.safe'],
    build_checks: ['l3.syn_flood.readiness', 'l3.tcp_connection_flood.readiness', 'l7.connection_hoarding.readiness', 'nat.state_table.readiness'],
    build_probes: ['tcp_connect_sequence', 'connection_hold_probe', 'websocket_hold_probe'],
    build_soc: ['syn_flood', 'tcp_connection_flood', 'application_connection_exhaustion scenarios'],
    build_ui: ['Concurrent connection limit evidence on target detail', 'State table saturation signal'],
    build_telemetry: ['cps', 'half_open_connections', 'nat_table_utilization', 'load_balancer_active_connections'],
    missing_vectors: ['ATT-003/008 execution', 'ATT-075 slow-client path', 'ATT-123 SMTP', 'ATT-125 NAT', 'ATT-136 IKE', 'ATT-138 SSH', 'ATT-139 FTP'],
    registry_attack_ids: ['ATT-003', 'ATT-008', 'ATT-075', 'ATT-123', 'ATT-125', 'ATT-136', 'ATT-138', 'ATT-139'],
    task_ids: ['DET-017', 'DET-020', 'SOC-011'],
  },
  {
    id: 'application_l7',
    research_sources: ['AWS application-layer attacks', 'Cloudflare HTTP DDoS', 'Microsoft app resource attacks', 'OWASP API Security'],
    has_today: ['l7.http_method_restriction.safe', 'l7.low_rate_rate_limit.safe', 'l7.cache_busting.safe', 'l7.bot_challenge_marker.safe', 'l7.cors_posture.safe', 'high_scale.application.request_only', 'origin.direct_bypass.safe', 'origin.direct_reachability.safe', 'origin.host_sni_bypass.safe', 'origin.leak_scan.safe', 'path.protected_canary.safe', 'waf.origin_bypass.safe', 'waf.fingerprint.safe', 'waf.enforcement.safe', 'waf.marker_rule.safe', 'l7.waf_marker_rule.safe'],
    build_checks: ['l7.http_get_flood.validation', 'l7.http_post_flood.validation', 'l7.search_abuse.validation', 'l7.export_abuse.validation', 'l7.batch_api_abuse.validation', 'l7.webhook_flood.validation', 'l7.health_check_flood.validation', 'l7.wordpress_xmlrpc.validation', 'origin.dns_hostname_bypass.readiness', 'origin.cdn_bypass.dedicated'],
    build_probes: ['http_get_sequence', 'http_post_body_profile', 'api_batch_profile'],
    build_soc: ['http_get_flood', 'http_post_flood', 'cache_busting_at_scale scenarios'],
    build_ui: ['RPS limit evidence', 'Origin vs CDN path on cache-bust runs', 'Per-endpoint cost asymmetry panel'],
    build_telemetry: ['rps', 'status_code_distribution', 'origin_vs_edge_ratio', 'waf_challenge_rate'],
    missing_vectors: ['ATT-052 POST', 'ATT-073 XML-RPC', 'ATT-103 CDN dedicated', 'ATT-104 SSE', 'ATT-105–109', 'ATT-126–132 origin/edge', 'ATT-140–142 HTTP abuse', 'ATT-145 CAPTCHA', 'ATT-167 MQTT', 'ATT-170 WAF bypass', 'ATT-174 CORS'],
    registry_attack_ids: ['ATT-051', 'ATT-052', 'ATT-053', 'ATT-056', 'ATT-058', 'ATT-066', 'ATT-070', 'ATT-072', 'ATT-073', 'ATT-100', 'ATT-101', 'ATT-102', 'ATT-103', 'ATT-108', 'ATT-109', 'ATT-122', 'ATT-126', 'ATT-127', 'ATT-128', 'ATT-129', 'ATT-130', 'ATT-131', 'ATT-132', 'ATT-140', 'ATT-141', 'ATT-142', 'ATT-145', 'ATT-153', 'ATT-167', 'ATT-170', 'ATT-174', 'ATT-176'],
    task_ids: ['DET-001', 'DET-020', 'DET-023', 'SOC-011'],
  },
  {
    id: 'computational',
    research_sources: ['Cloudflare TLS/HTTP DDoS', 'Google Rapid Reset advisory', 'CERT/CC MadeYouReset VU#767506'],
    has_today: ['l7.expensive_endpoint.safe', 'tls.full_audit.safe', 'protocol.http2_rapid_reset_readiness.safe'],
    build_checks: ['tls.handshake_rate.readiness', 'tls.renegotiation.readiness', 'l7.http2_rapid_reset.validation', 'l7.http2_made_you_reset.readiness', 'l7.http2_continuation.readiness', 'l7.http2_priority_abuse.readiness', 'tls.ocsp_stapling.readiness', 'l7.redos.readiness'],
    missing_vectors: ['ATT-065', 'ATT-067 execution', 'ATT-068', 'ATT-069', 'ATT-110', 'ATT-111', 'ATT-147 ReDoS', 'ATT-152 QPACK', 'ATT-155 OCSP', 'ATT-156 cipher negotiation'],
    build_probes: ['tls_handshake_burst', 'http2_settings_and_reset_profile', 'http2_continuation_profile'],
    build_soc: ['rapid_reset_validation', 'made_you_reset_validation', 'tls_handshake_exhaustion scenarios'],
    build_ui: ['Crypto CPU / handshake rate telemetry panel', 'HTTP/2 CVE readiness badges'],
    build_telemetry: ['tls_handshakes_per_sec', 'cpu_percent', 'http2_reset_rate', 'stream_creation_rate'],
    registry_attack_ids: ['ATT-054', 'ATT-064', 'ATT-065', 'ATT-067', 'ATT-069', 'ATT-110', 'ATT-111', 'ATT-147', 'ATT-152', 'ATT-155', 'ATT-156'],
    task_ids: ['DET-020', 'DET-021', 'SOC-011'],
  },
  {
    id: 'memory_exhaustion',
    research_sources: ['Microsoft slowloris/slow read', 'Cloudflare HTTP/2 stream abuse', 'RFC 9113 CONTINUATION issues'],
    has_today: ['tls.slow_header_body_timeout.safe', 'protocol.http2_stream_concurrency.safe', 'protocol.websocket_connection_controls.safe', 'l7.header_size_boundary.safe'],
    build_checks: ['l7.slowloris.validation', 'l7.slow_post.validation', 'l7.slow_read.validation', 'l7.large_body_post.validation', 'protocol.sse_stream.readiness', 'l7.hpack_bomb.readiness', 'l7.http2_push_promise.readiness', 'l7.json_xml_bomb.readiness'],
    missing_vectors: ['ATT-060–063 slow attacks', 'ATT-059 large POST body', 'ATT-104 SSE', 'ATT-113 upload', 'ATT-148 JSON bomb', 'ATT-149 XML bomb', 'ATT-150 HPACK', 'ATT-151 push promise', 'ATT-068 CONTINUATION'],
    build_probes: ['slow_header_probe', 'slow_body_probe', 'slow_read_probe', 'websocket_message_rate_probe'],
    build_soc: ['slowloris', 'slow_post', 'slow_read scenarios with strict duration caps'],
    build_ui: ['Connection slot / worker exhaustion indicators', 'Slow-client timeout policy evidence'],
    build_telemetry: ['active_connections', 'worker_queue_depth', 'request_stall_duration_p99'],
    registry_attack_ids: ['ATT-059', 'ATT-060', 'ATT-061', 'ATT-062', 'ATT-063', 'ATT-068', 'ATT-071', 'ATT-104', 'ATT-113', 'ATT-148', 'ATT-149', 'ATT-150', 'ATT-151'],
    task_ids: ['DET-020', 'DET-021', 'SOC-011'],
  },
  {
    id: 'backend_exhaustion',
    research_sources: ['AWS expensive API / cache busting', 'GraphQL OWASP', 'Database connection pool exhaustion patterns'],
    has_today: ['l7.api_quota_exhaustion.safe', 'l7.graphql_complexity.safe', 'l7.login_abuse_flow.safe', 'l7.password_reset.safe'],
    build_checks: ['l7.search_query_abuse.validation', 'l7.report_generation_abuse.validation', 'l7.graphql_batch_abuse.validation', 'l7.oauth_token_abuse.validation', 'l7.file_upload_abuse.validation', 'l7.signup_registration_abuse.validation', 'l7.elasticsearch_abuse.validation'],
    missing_vectors: ['ATT-105 search', 'ATT-106 export', 'ATT-107 batch', 'ATT-112 OAuth', 'ATT-113 upload', 'ATT-114 GraphQL batch', 'ATT-143 checkout', 'ATT-144 OTP/SMS', 'ATT-157 signup', 'ATT-158 password reset', 'ATT-166 Elasticsearch'],
    build_probes: ['graphql_batch_profile', 'search_query_profile', 'export_job_profile'],
    build_soc: ['database_exhaustion', 'graphql_depth_at_scale scenarios on declared endpoints only'],
    build_ui: ['DB pool / query latency correlation on run detail', 'Backend dependency map for expensive endpoints'],
    build_telemetry: ['db_connections', 'query_latency_p99', 'cache_miss_rate', 'queue_depth'],
    registry_attack_ids: ['ATT-055', 'ATT-057', 'ATT-105', 'ATT-106', 'ATT-107', 'ATT-112', 'ATT-114', 'ATT-143', 'ATT-144', 'ATT-157', 'ATT-158', 'ATT-166'],
    task_ids: ['DET-020', 'SOC-011'],
  },
  {
    id: 'dns_exhaustion',
    research_sources: ['Cloudflare DNS DDoS / laundering / random prefix', 'AWS Route53 shield', 'USENIX NXNSAttack', 'DNSBomb research'],
    has_today: ['dns.authoritative_response.safe', 'dns.random_prefix_nxdomain.safe', 'dns.open_recursion_behavior.safe', 'dns.dnssec_expensive_query.safe', 'dns.zone_transfer_exposure.safe', 'high_scale.dns_high_query.request_only'],
    build_checks: ['dns.laundering.readiness', 'dns.garbage_flood.readiness', 'dns.phantom_domain.readiness', 'dns.domain_lockup.readiness', 'dns.nxns_attack.readiness', 'dns.dnsbomb.readiness', 'dns.qname_minimization.readiness', 'dns.doh_dot.readiness', 'dns.tcp_fallback.readiness'],
    missing_vectors: ['ATT-045 laundering', 'ATT-046–050 advanced DNS', 'ATT-159 DoH/DoT', 'ATT-160 TCP fallback', 'ATT-161 zone walking'],
    build_probes: ['dns_random_prefix_sequence', 'dns_edns_padding_probe', 'dns_tcp_fallback_probe'],
    build_soc: ['dns_query_flood', 'water_torture', 'nxdomain_at_scale scenarios'],
    build_ui: ['Resolver vs authoritative path diagram', 'NXDOMAIN ratio / QPS charts'],
    build_telemetry: ['dns_qps', 'nxdomain_ratio', 'resolver_latency', 'authoritative_cpu'],
    registry_attack_ids: ['ATT-041', 'ATT-043', 'ATT-044', 'ATT-045', 'ATT-046', 'ATT-047', 'ATT-048', 'ATT-049', 'ATT-050', 'ATT-159', 'ATT-160', 'ATT-161', 'ATT-162'],
    task_ids: ['DET-019', 'DET-023', 'SOC-011'],
  },
  {
    id: 'reflection',
    research_sources: ['AWS UDP reflection', 'Cloudflare attack coverage list', 'Akamai WS-Discovery/ARMS advisories'],
    has_today: ['dns.amplification_exposure.safe'],
    has_today_notes: 'DNS-side reflection metadata only; no non-DNS reflector checks yet.',
    build_checks: ['reflect.ssdp_exposure.safe', 'reflect.snmp_exposure.safe', 'reflect.ws_discovery_exposure.safe', 'reflect.tcp_middlebox_exposure.safe', 'reflect.quic_reflection.safe', 'reflect.stun_turn_exposure.safe', 'reflect.ipmi_exposure.safe', 'reflect.openvpn_exposure.safe'],
    missing_vectors: ['ATT-020–027 non-DNS reflectors', 'ATT-116–118', 'ATT-163 STUN/TURN', 'ATT-164 IPMI', 'ATT-168 OpenVPN', 'ATT-165 Redis direct'],
    build_probes: ['reflector_exposure_metadata', 'open_udp_service_scan_bounded'],
    build_soc: ['reflection_exposure_assessment only — never launch reflection'],
    build_ui: ['Reflector exposure inventory (metadata)', 'DRDoS readiness score'],
    build_telemetry: ['unexpected_udp_response_volume', 'spoofed_source_indicators from provider'],
    registry_attack_ids: ['ATT-020', 'ATT-021', 'ATT-022', 'ATT-023', 'ATT-024', 'ATT-025', 'ATT-026', 'ATT-027', 'ATT-116', 'ATT-117', 'ATT-118', 'ATT-163', 'ATT-164', 'ATT-165', 'ATT-168'],
    task_ids: ['DET-018'],
  },
  {
    id: 'amplification',
    research_sources: ['AWS amplification protocol list', 'Cloudflare CLDAP/Memcached advisories', 'CAIDA amplifier census methods'],
    has_today: ['dns.amplification_exposure.safe'],
    build_checks: ['amp.ntcp_exposure.safe', 'amp.cldap_exposure.safe', 'amp.memcached_exposure.safe', 'amp.chargen_exposure.safe', 'amp.dns_any_txt_exposure.safe', 'amp.smurf_exposure.safe'],
    build_probes: ['amplification_ratio_metadata', 'open_resolver_policy_probe'],
    build_soc: ['amplification_exposure_audit — no amplifier traffic generation'],
    build_ui: ['Amplification ratio / open service risk panel'],
    build_telemetry: ['response_size_class', 'provider_amplification_alerts'],
    missing_vectors: ['ATT-017–019 NTP/CLDAP/Memcached', 'ATT-042 authoritative amp', 'ATT-115 ANY/TXT', 'ATT-134 Smurf'],
    registry_attack_ids: ['ATT-016', 'ATT-017', 'ATT-018', 'ATT-019', 'ATT-042', 'ATT-115', 'ATT-134'],
    task_ids: ['DET-018'],
  },
  {
    id: 'exploit_dos',
    research_sources: ['Microsoft legacy IP fragmentation attacks', 'CVE databases for HTTP/2/TLS parser bugs', 'Embedded device advisories'],
    has_today: [],
    build_checks: ['exploit.ping_of_death.posture', 'exploit.teardrop.posture', 'exploit.http2_parser_cve.posture', 'exploit.quic_parser_cve.posture', 'exploit.land_attack.posture'],
    build_probes: ['parser_version_fingerprint', 'cve_patch_level_metadata'],
    build_soc: ['exploit_validation only on isolated lab targets with explicit authorization'],
    build_ui: ['Firmware/parser CVE readiness on edge assets'],
    build_telemetry: ['crash_restarts', 'parser_error_rate'],
    missing_vectors: ['ATT-011 Ping of Death', 'ATT-012 Teardrop', 'ATT-119 IP options', 'ATT-120 malformed QUIC', 'ATT-133 Land', 'ATT-154 QUIC migration'],
    registry_attack_ids: ['ATT-011', 'ATT-012', 'ATT-119', 'ATT-120', 'ATT-133', 'ATT-154'],
    task_ids: ['DET-017', 'DET-021', 'DET-026'],
  },
  {
    id: 'delivery_pattern',
    research_sources: ['Cloudflare carpet bombing / 7.3 Tbps case study', 'Pulse-wave DDoS research', 'Multi-vector SOC playbooks'],
    has_today: ['high_scale.multi_vector.request_only', 'high_scale.volumetric.request_only', 'high_scale.degradation_recovery.request_only', 'ops.alert_workflow_marker.safe'],
    build_checks: ['pattern.carpet_bombing.readiness', 'pattern.pulse_wave.readiness', 'pattern.spoofed_source.readiness', 'pattern.ransom_ddos.workflow', 'pattern.rate_limit_evasion.readiness'],
    build_probes: [],
    build_soc: ['carpet_bombing', 'pulse_wave', 'multi_vector_switching', 'ATT-093 coordinated device swarm (soc_only) scenarios with governed adapter'],
    build_ui: ['Attack pattern timeline on SOC console', 'Multi-destination heatmap', 'Vector-switching detection from telemetry'],
    build_telemetry: ['destination_spread', 'vector_change_events', 'pulse_frequency'],
    missing_vectors: ['ATT-091 spoofed', 'ATT-094 carpet bombing', 'ATT-095 pulse-wave', 'ATT-098 ransom', 'ATT-121 adaptive', 'ATT-146 residential proxy'],
    registry_attack_ids: ['ATT-090', 'ATT-091', 'ATT-092', 'ATT-093', 'ATT-094', 'ATT-095', 'ATT-096', 'ATT-097', 'ATT-098', 'ATT-099', 'ATT-121', 'ATT-146', 'ATT-169', 'ATT-171', 'ATT-172', 'ATT-173', 'ATT-175'],
    task_ids: ['DET-022', 'DET-026', 'SOC-011'],
  },
]);

/** Vectors documented in product docs but outside classic DDoS taxonomy — tracked separately. */
export const NON_DDOS_AVAILABILITY_THREATS = Object.freeze([
  { id: 'ND-001', name: 'BGP hijacking', classification: 'routing_attack', task_id: 'DET-026', notes: 'Not resource-exhaustion DDoS; monitor-only integration future.' },
  { id: 'ND-002', name: 'BGP route leak', classification: 'routing_incident', task_id: 'DET-026' },
  { id: 'ND-003', name: 'DNS hijacking / cache poisoning', classification: 'dns_integrity', task_id: 'DET-026' },
  { id: 'ND-004', name: 'Control-plane autoscaling cost exhaustion', classification: 'operational_exhaustion', task_id: 'DET-026', notes: 'Health-check flood triggering scale-out; maps to ATT-109.' },
  { id: 'ND-005', name: 'Alert fatigue / blind spots during attack', classification: 'operational_exhaustion', task_id: 'DET-026', check_ids: ['ops.alert_workflow_marker.safe'] },
  { id: 'ND-006', name: 'Credential stuffing / brute force', classification: 'authentication_attack', task_id: null, notes: 'Out of scope for DDoS taxonomy; partial overlap l7.login_abuse_flow.safe.' },
  { id: 'ND-007', name: 'Provider control-plane API rate exhaustion', classification: 'operational_exhaustion', task_id: 'DET-026', notes: 'Cloud API throttling during mitigation orchestration.' },
  { id: 'ND-008', name: 'Log / SIEM ingestion cost exhaustion', classification: 'operational_exhaustion', task_id: 'DET-026', notes: 'Telemetry flood raises observability cost without service outage.' },
  { id: 'ND-009', name: 'Certificate transparency / CT log noise', classification: 'operational_exhaustion', task_id: 'DET-026', notes: 'Monitor-only; related to ATT-122 origin leakage.' },
]);

/** @type {readonly AttackVectorEntry[]} */
export const ATTACK_VECTOR_REGISTRY = Object.freeze([
  // --- L3/L4 volumetric & packet processing ---
  { id: 'ATT-001', name: 'UDP flood', exhausted_resource: 'volumetric', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.forbidden_udp_port.safe', 'high_scale.volumetric.request_only'], notes: 'Single-datagram probe + SOC volumetric marker; no flood generator in repo.' },
  { id: 'ATT-002', name: 'ICMP / ping flood', exhausted_resource: 'volumetric', coverage_status: 'pending', task_id: 'DET-017' },
  { id: 'ATT-003', name: 'SYN flood', exhausted_resource: 'state_exhaustion', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.forbidden_tcp_port.safe', 'l3.basic_deny_rule.safe', 'l3.connection_table_exhaustion.request_only', 'high_scale.volumetric.request_only'] },
  { id: 'ATT-004', name: 'ACK flood', exhausted_resource: 'packet_processing', coverage_status: 'pending', task_id: 'DET-017' },
  { id: 'ATT-005', name: 'SYN-ACK flood', exhausted_resource: 'packet_processing', coverage_status: 'pending', task_id: 'DET-017' },
  { id: 'ATT-006', name: 'RST flood', exhausted_resource: 'packet_processing', coverage_status: 'pending', task_id: 'DET-017' },
  { id: 'ATT-007', name: 'TCP flag floods (FIN/PSH/URG/NULL/Xmas)', exhausted_resource: 'packet_processing', coverage_status: 'pending', task_id: 'DET-017' },
  { id: 'ATT-008', name: 'TCP connection flood', exhausted_resource: 'state_exhaustion', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.connection_table_exhaustion.request_only'] },
  { id: 'ATT-009', name: 'Out-of-state TCP flood', exhausted_resource: 'packet_processing', coverage_status: 'pending', task_id: 'DET-017' },
  { id: 'ATT-010', name: 'Fragmentation flood', exhausted_resource: 'packet_processing', coverage_status: 'pending', task_id: 'DET-017' },
  { id: 'ATT-011', name: 'Ping of Death', exhausted_resource: 'exploit_dos', coverage_status: 'pending', task_id: 'DET-017' },
  { id: 'ATT-012', name: 'Teardrop', exhausted_resource: 'exploit_dos', coverage_status: 'pending', task_id: 'DET-017' },
  { id: 'ATT-013', name: 'GRE flood', exhausted_resource: 'volumetric', coverage_status: 'pending', task_id: 'DET-017' },
  { id: 'ATT-014', name: 'ESP / IPsec flood', exhausted_resource: 'packet_processing', coverage_status: 'pending', task_id: 'DET-017' },
  { id: 'ATT-015', name: 'QUIC flood', exhausted_resource: 'volumetric', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['protocol.http3_quic_exposure.safe', 'high_scale.volumetric.request_only'] },

  // --- Reflection / amplification (16–40) ---
  { id: 'ATT-016', name: 'DNS reflection/amplification', exhausted_resource: 'amplification', coverage_status: 'partial', task_id: 'DET-018', check_ids: ['dns.amplification_exposure.safe'] },
  { id: 'ATT-017', name: 'NTP amplification', exhausted_resource: 'amplification', coverage_status: 'pending', task_id: 'DET-018' },
  { id: 'ATT-018', name: 'CLDAP amplification', exhausted_resource: 'amplification', coverage_status: 'pending', task_id: 'DET-018' },
  { id: 'ATT-019', name: 'Memcached amplification', exhausted_resource: 'amplification', coverage_status: 'pending', task_id: 'DET-018' },
  { id: 'ATT-020', name: 'SSDP/UPnP reflection', exhausted_resource: 'reflection', coverage_status: 'pending', task_id: 'DET-018' },
  { id: 'ATT-021', name: 'SNMP reflection', exhausted_resource: 'reflection', coverage_status: 'pending', task_id: 'DET-018' },
  { id: 'ATT-022', name: 'CHARGEN/QOTD reflection', exhausted_resource: 'reflection', coverage_status: 'pending', task_id: 'DET-018' },
  { id: 'ATT-023', name: 'mDNS / NetBIOS / WS-Discovery reflection', exhausted_resource: 'reflection', coverage_status: 'pending', task_id: 'DET-018' },
  { id: 'ATT-024', name: 'Portmap/RIPv1/BitTorrent/Jenkins/TeamSpeak reflectors', exhausted_resource: 'reflection', coverage_status: 'pending', task_id: 'DET-018' },
  { id: 'ATT-025', name: 'DTLS / SIP / RDP / TFTP / ARMS / CoAP reflection', exhausted_resource: 'reflection', coverage_status: 'pending', task_id: 'DET-018' },
  { id: 'ATT-026', name: 'QUIC reflection', exhausted_resource: 'reflection', coverage_status: 'pending', task_id: 'DET-018' },
  { id: 'ATT-027', name: 'TCP middlebox reflection', exhausted_resource: 'reflection', coverage_status: 'pending', task_id: 'DET-018' },

  // --- DNS exhaustion (41–50) ---
  { id: 'ATT-041', name: 'DNS query flood', exhausted_resource: 'dns_exhaustion', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.authoritative_response.safe', 'high_scale.dns_high_query.request_only'] },
  { id: 'ATT-042', name: 'DNS amplification (authoritative/resolver)', exhausted_resource: 'amplification', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.amplification_exposure.safe', 'dns.open_recursion_behavior.safe'] },
  { id: 'ATT-043', name: 'NXDOMAIN flood', exhausted_resource: 'dns_exhaustion', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.random_prefix_nxdomain.safe'] },
  { id: 'ATT-044', name: 'Random-subdomain / water-torture', exhausted_resource: 'dns_exhaustion', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.random_prefix_nxdomain.safe'] },
  { id: 'ATT-045', name: 'DNS laundering', exhausted_resource: 'dns_exhaustion', coverage_status: 'pending', task_id: 'DET-019', notes: 'No named check; random-prefix proxy only.' },
  { id: 'ATT-046', name: 'DNS garbage flood', exhausted_resource: 'dns_exhaustion', coverage_status: 'pending', task_id: 'DET-019' },
  { id: 'ATT-047', name: 'Phantom domain attack', exhausted_resource: 'dns_exhaustion', coverage_status: 'pending', task_id: 'DET-019' },
  { id: 'ATT-048', name: 'DNS domain lock-up', exhausted_resource: 'dns_exhaustion', coverage_status: 'pending', task_id: 'DET-019' },
  { id: 'ATT-049', name: 'NXNSAttack', exhausted_resource: 'dns_exhaustion', coverage_status: 'pending', task_id: 'DET-019' },
  { id: 'ATT-050', name: 'DNSBomb', exhausted_resource: 'dns_exhaustion', coverage_status: 'pending', task_id: 'DET-019' },

  // --- L7 / application (51–75) ---
  { id: 'ATT-051', name: 'HTTP GET flood', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.http_method_restriction.safe', 'l7.low_rate_rate_limit.safe', 'high_scale.application.request_only'] },
  { id: 'ATT-052', name: 'HTTP POST flood', exhausted_resource: 'application_l7', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-053', name: 'HTTP HEAD flood', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.http_method_restriction.safe'] },
  { id: 'ATT-054', name: 'Dynamic-endpoint / computational DDoS', exhausted_resource: 'computational', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.expensive_endpoint.safe', 'l7.graphql_complexity.safe'] },
  { id: 'ATT-055', name: 'Database exhaustion attack', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.api_quota_exhaustion.safe', 'l7.graphql_complexity.safe'] },
  { id: 'ATT-056', name: 'API flood', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.api_surface_scan.safe', 'l7.api_quota_exhaustion.safe'] },
  { id: 'ATT-057', name: 'GraphQL exhaustion', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.graphql_complexity.safe'] },
  { id: 'ATT-058', name: 'Cache-busting DDoS', exhausted_resource: 'application_l7', coverage_status: 'implemented', task_id: 'DET-020', check_ids: ['l7.cache_busting.safe'] },
  { id: 'ATT-059', name: 'Large-payload POST', exhausted_resource: 'memory_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.header_size_boundary.safe'] },
  { id: 'ATT-060', name: 'Slowloris', exhausted_resource: 'memory_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['tls.slow_header_body_timeout.safe'], notes: 'HEAD timeout metadata; not full slowloris hold.' },
  { id: 'ATT-061', name: 'Slow POST / RUDY', exhausted_resource: 'memory_exhaustion', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-062', name: 'Slow read', exhausted_resource: 'memory_exhaustion', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-063', name: 'Generic low-and-slow DDoS', exhausted_resource: 'memory_exhaustion', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-064', name: 'TLS handshake / SSL negotiation exhaustion', exhausted_resource: 'computational', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['tls.full_audit.safe', 'tls.profile_exposure.safe'] },
  { id: 'ATT-065', name: 'TLS renegotiation attacks', exhausted_resource: 'computational', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-066', name: 'HTTP/2 multiplexing flood', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['protocol.http2_stream_concurrency.safe'] },
  { id: 'ATT-067', name: 'HTTP/2 Rapid Reset', exhausted_resource: 'computational', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['protocol.http2_rapid_reset_readiness.safe'], notes: 'Readiness only; no reset-storm execution.' },
  { id: 'ATT-068', name: 'HTTP/2 CONTINUATION flood', exhausted_resource: 'memory_exhaustion', coverage_status: 'pending', task_id: 'DET-021' },
  { id: 'ATT-069', name: 'HTTP/2 MadeYouReset', exhausted_resource: 'computational', coverage_status: 'pending', task_id: 'DET-021' },
  { id: 'ATT-070', name: 'HTTP/3 / QUIC application flood', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['protocol.http3_quic_exposure.safe', 'high_scale.application.request_only'] },
  { id: 'ATT-071', name: 'WebSocket DDoS', exhausted_resource: 'memory_exhaustion', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['protocol.websocket_connection_controls.safe'] },
  { id: 'ATT-072', name: 'gRPC / RPC floods', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-021', check_ids: ['protocol.grpc_reflection_stream.safe'], notes: 'metadata_marker only.' },
  { id: 'ATT-073', name: 'WordPress XML-RPC / pingback DDoS', exhausted_resource: 'application_l7', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-074', name: 'SIP / VoIP flood', exhausted_resource: 'volumetric', coverage_status: 'pending', task_id: 'DET-017' },
  { id: 'ATT-075', name: 'Application connection exhaustion', exhausted_resource: 'state_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['tls.idle_connection_timeout.safe', 'l3.connection_table_exhaustion.request_only'] },

  // --- Delivery patterns ---
  { id: 'ATT-090', name: 'Direct flood', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-022', check_ids: ['high_scale.volumetric.request_only'] },
  { id: 'ATT-091', name: 'Spoofed flood', exhausted_resource: 'delivery_pattern', coverage_status: 'pending', task_id: 'DET-022' },
  { id: 'ATT-092', name: 'DRDoS / reflection delivery', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-022', check_ids: ['dns.amplification_exposure.safe'] },
  { id: 'ATT-093', name: 'Coordinated Device Swarm DDoS (docs: ATT-093)', exhausted_resource: 'delivery_pattern', coverage_status: 'soc_only', task_id: 'DET-022', check_ids: ['high_scale.multi_vector.request_only'] },
  { id: 'ATT-094', name: 'Carpet bombing', exhausted_resource: 'delivery_pattern', coverage_status: 'pending', task_id: 'DET-022' },
  { id: 'ATT-095', name: 'Pulse-wave / burst attacks', exhausted_resource: 'delivery_pattern', coverage_status: 'pending', task_id: 'DET-022' },
  { id: 'ATT-096', name: 'Multi-vector / vector switching', exhausted_resource: 'delivery_pattern', coverage_status: 'soc_only', task_id: 'DET-022', check_ids: ['high_scale.multi_vector.request_only'] },
  { id: 'ATT-097', name: 'Application-aware targeting', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-022', check_ids: ['l7.expensive_endpoint.safe'] },

  // --- Origin / edge (readiness, not numbered in user list) ---
  { id: 'ATT-100', name: 'Direct origin bypass', exhausted_resource: 'application_l7', coverage_status: 'implemented', task_id: 'DET-001', check_ids: ['origin.direct_bypass.safe', 'origin.direct_reachability.safe', 'origin.host_sni_bypass.safe'] },
  { id: 'ATT-101', name: 'Origin leak scan', exhausted_resource: 'application_l7', coverage_status: 'implemented', task_id: 'DET-001', check_ids: ['origin.leak_scan.safe'] },
  { id: 'ATT-102', name: 'WAF marker / enforcement', exhausted_resource: 'application_l7', coverage_status: 'implemented', task_id: 'DET-007', check_ids: ['waf.marker_rule.safe', 'waf.enforcement.safe', 'l7.waf_marker_rule.safe'] },

  // --- Gap analysis: documented elsewhere but missing from initial registry ---
  { id: 'ATT-103', name: 'CDN / shield bypass', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-001', check_ids: ['origin.direct_bypass.safe', 'origin.host_sni_bypass.safe'], notes: 'No dedicated CDN-bypass check_id; folded into origin family.' },
  { id: 'ATT-104', name: 'SSE long-lived stream exhaustion', exhausted_resource: 'memory_exhaustion', coverage_status: 'pending', task_id: 'DET-021', notes: 'Documented in 10-protocol-vectors.md; no catalog entry.' },
  { id: 'ATT-105', name: 'Search endpoint abuse', exhausted_resource: 'backend_exhaustion', coverage_status: 'pending', task_id: 'DET-020', notes: 'Enterprise backlog row; no check_id.' },
  { id: 'ATT-106', name: 'Export / report generation abuse', exhausted_resource: 'backend_exhaustion', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-107', name: 'Batch API abuse', exhausted_resource: 'backend_exhaustion', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-108', name: 'Webhook / callback flood', exhausted_resource: 'application_l7', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-109', name: 'Health-check endpoint flood', exhausted_resource: 'application_l7', coverage_status: 'pending', task_id: 'DET-026', notes: 'Can trigger autoscaling cost exhaustion (ND-004).' },
  { id: 'ATT-110', name: 'HTTP/2 priority tree abuse', exhausted_resource: 'computational', coverage_status: 'pending', task_id: 'DET-021' },
  { id: 'ATT-111', name: 'TLS 0-RTT / early data abuse', exhausted_resource: 'computational', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-112', name: 'OAuth / token endpoint abuse', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.login_abuse_flow.safe', 'l7.api_quota_exhaustion.safe'] },
  { id: 'ATT-113', name: 'File upload flood', exhausted_resource: 'memory_exhaustion', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-114', name: 'GraphQL batch / alias abuse', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.graphql_complexity.safe'], notes: 'Depth/complexity only; no batch/alias-specific check.' },
  { id: 'ATT-115', name: 'DNS ANY/TXT query class abuse', exhausted_resource: 'amplification', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.amplification_exposure.safe', 'dns.dnssec_expensive_query.safe'] },
  { id: 'ATT-116', name: 'MSSQL resolver reflection', exhausted_resource: 'reflection', coverage_status: 'pending', task_id: 'DET-018' },
  { id: 'ATT-117', name: 'Jenkins / CI discovery reflection', exhausted_resource: 'reflection', coverage_status: 'pending', task_id: 'DET-018' },
  { id: 'ATT-118', name: 'CoAP IoT reflector abuse', exhausted_resource: 'reflection', coverage_status: 'pending', task_id: 'DET-018' },
  { id: 'ATT-119', name: 'IP options / malformed IP header abuse', exhausted_resource: 'exploit_dos', coverage_status: 'pending', task_id: 'DET-017' },
  { id: 'ATT-120', name: 'Malformed QUIC version / spin bit abuse', exhausted_resource: 'exploit_dos', coverage_status: 'pending', task_id: 'DET-021' },
  { id: 'ATT-121', name: 'Adaptive / randomized flood (entropy evasion)', exhausted_resource: 'delivery_pattern', coverage_status: 'pending', task_id: 'DET-022' },
  { id: 'ATT-122', name: 'Certificate / SAN origin leakage', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-001', check_ids: ['origin.leak_scan.safe', 'tls.profile_exposure.safe'] },
  { id: 'ATT-123', name: 'SMTP / email connection flood', exhausted_resource: 'state_exhaustion', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-124', name: 'IPv6 volumetric flood (beyond reachability check)', exhausted_resource: 'volumetric', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.ipv6_reachability.safe'], notes: 'Reachability only; no volumetric profile.' },
  { id: 'ATT-125', name: 'NAT / firewall state table exhaustion', exhausted_resource: 'state_exhaustion', coverage_status: 'pending', task_id: 'DET-017' },
  { id: 'ATT-098', name: 'Ransom DDoS (extortion workflow)', exhausted_resource: 'delivery_pattern', coverage_status: 'pending', task_id: 'DET-022', notes: 'SOC workflow + audit; not a probe vector.' },
  { id: 'ATT-099', name: 'Multi-destination / multi-service simultaneous attack', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-022', check_ids: ['high_scale.multi_vector.request_only'] },

  // --- Origin / edge exposure (enables direct-path DDoS) ---
  { id: 'ATT-126', name: 'Stale DNS / legacy subdomain origin leak', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-001', check_ids: ['origin.leak_scan.safe'] },
  { id: 'ATT-127', name: 'DNS-only hostname bypass', exhausted_resource: 'application_l7', coverage_status: 'pending', task_id: 'DET-001', notes: 'Documented in 05-origin-bypass.md; no dedicated check_id.' },
  { id: 'ATT-128', name: 'Protected canary path bypass', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-001', check_ids: ['path.protected_canary.safe'] },
  { id: 'ATT-129', name: 'Admin / management surface exposure', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-001', check_ids: ['l3.firewall_exposure_scan.safe'], notes: 'Port scan finds admin surfaces; not admin-specific check.' },
  { id: 'ATT-130', name: 'Ephemeral port / accidental service exposure', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-017', check_ids: ['l3.firewall_exposure_scan.safe'] },
  { id: 'ATT-131', name: 'WAF-to-origin bypass path', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-001', check_ids: ['waf.origin_bypass.safe', 'origin.direct_bypass.safe'] },
  { id: 'ATT-132', name: 'HTTP TRACE / unusual method abuse', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.http_method_restriction.safe'] },

  // --- L3/L4 extended ---
  { id: 'ATT-133', name: 'Land attack (same src/dst IP)', exhausted_resource: 'exploit_dos', coverage_status: 'pending', task_id: 'DET-017' },
  { id: 'ATT-134', name: 'Smurf / ICMP-to-broadcast amplification', exhausted_resource: 'amplification', coverage_status: 'pending', task_id: 'DET-018' },
  { id: 'ATT-135', name: 'SCTP flood', exhausted_resource: 'volumetric', coverage_status: 'pending', task_id: 'DET-017' },
  { id: 'ATT-136', name: 'IKE / IPsec negotiation flood', exhausted_resource: 'state_exhaustion', coverage_status: 'pending', task_id: 'DET-017' },
  { id: 'ATT-137', name: 'Multicast / broadcast storm', exhausted_resource: 'volumetric', coverage_status: 'pending', task_id: 'DET-017' },
  { id: 'ATT-138', name: 'SSH connection flood', exhausted_resource: 'state_exhaustion', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-139', name: 'FTP connection flood', exhausted_resource: 'state_exhaustion', coverage_status: 'pending', task_id: 'DET-020' },

  // --- L7 extended ---
  { id: 'ATT-140', name: 'HTTP pipelining abuse', exhausted_resource: 'application_l7', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-141', name: 'HTTP Range header abuse', exhausted_resource: 'application_l7', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-142', name: 'HTTP conditional revalidation flood (If-None-Match/IMS)', exhausted_resource: 'application_l7', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-143', name: 'Checkout / cart transaction abuse', exhausted_resource: 'backend_exhaustion', coverage_status: 'pending', task_id: 'DET-020', notes: 'Matrix row search/checkout/API; customer-declared endpoint only.' },
  { id: 'ATT-144', name: 'OTP / SMS cost exhaustion', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.login_abuse_flow.safe'], notes: 'Login flow partial; no SMS-cost-specific check.' },
  { id: 'ATT-145', name: 'CAPTCHA / challenge endpoint abuse', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.bot_challenge_marker.safe'] },
  { id: 'ATT-146', name: 'Distributed low-rate / residential proxy flood', exhausted_resource: 'delivery_pattern', coverage_status: 'pending', task_id: 'DET-022' },

  // --- Computational / parser bombs ---
  { id: 'ATT-147', name: 'ReDoS / regex algorithmic complexity', exhausted_resource: 'computational', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-148', name: 'JSON bomb / deeply nested payload', exhausted_resource: 'memory_exhaustion', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-149', name: 'XML bomb / entity expansion (billion laughs class)', exhausted_resource: 'memory_exhaustion', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-150', name: 'HPACK decompression bomb', exhausted_resource: 'memory_exhaustion', coverage_status: 'pending', task_id: 'DET-021' },
  { id: 'ATT-151', name: 'HTTP/2 push promise abuse', exhausted_resource: 'memory_exhaustion', coverage_status: 'pending', task_id: 'DET-021' },
  { id: 'ATT-152', name: 'QPACK / HTTP/3 header compression bomb', exhausted_resource: 'computational', coverage_status: 'pending', task_id: 'DET-021' },
  { id: 'ATT-153', name: 'HTTP/3 control stream / SETTINGS flood', exhausted_resource: 'application_l7', coverage_status: 'pending', task_id: 'DET-021' },
  { id: 'ATT-154', name: 'QUIC migration / path validation abuse', exhausted_resource: 'exploit_dos', coverage_status: 'pending', task_id: 'DET-021' },
  { id: 'ATT-155', name: 'OCSP stapling / certificate validation exhaustion', exhausted_resource: 'computational', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-156', name: 'Cipher suite negotiation exhaustion', exhausted_resource: 'computational', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['tls.full_audit.safe', 'tls.profile_exposure.safe'] },

  // --- Backend / signup ---
  { id: 'ATT-157', name: 'Signup / registration flood', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.login_abuse_flow.safe'] },
  { id: 'ATT-158', name: 'Password reset OTP flood', exhausted_resource: 'backend_exhaustion', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.password_reset.safe'] },

  // --- DNS extended ---
  { id: 'ATT-159', name: 'DNS over HTTPS/TLS (DoH/DoT) query exhaustion', exhausted_resource: 'dns_exhaustion', coverage_status: 'pending', task_id: 'DET-019' },
  { id: 'ATT-160', name: 'DNS TCP fallback / truncation pressure', exhausted_resource: 'dns_exhaustion', coverage_status: 'pending', task_id: 'DET-019' },
  { id: 'ATT-161', name: 'DNS zone walking / enumeration at scale', exhausted_resource: 'dns_exhaustion', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.zone_transfer_exposure.safe'], notes: 'AXFR only; zone walking distinct.' },
  { id: 'ATT-162', name: 'DNS secondary failover stress', exhausted_resource: 'dns_exhaustion', coverage_status: 'partial', task_id: 'DET-019', check_ids: ['dns.secondary_failover.safe'] },

  // --- Reflection / protocol extended ---
  { id: 'ATT-163', name: 'STUN/TURN reflection', exhausted_resource: 'reflection', coverage_status: 'pending', task_id: 'DET-018' },
  { id: 'ATT-164', name: 'IPMI / BMC reflector exposure', exhausted_resource: 'reflection', coverage_status: 'pending', task_id: 'DET-018' },
  { id: 'ATT-165', name: 'Redis direct protocol flood', exhausted_resource: 'reflection', coverage_status: 'pending', task_id: 'DET-018', notes: 'Open Redis exposure metadata; not Memcached amp.' },
  { id: 'ATT-166', name: 'Elasticsearch / OpenSearch query flood', exhausted_resource: 'backend_exhaustion', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-167', name: 'MQTT broker flood', exhausted_resource: 'application_l7', coverage_status: 'pending', task_id: 'DET-020' },
  { id: 'ATT-168', name: 'OpenVPN / WireGuard reflector exposure', exhausted_resource: 'reflection', coverage_status: 'pending', task_id: 'DET-018' },

  // --- Delivery / operational ---
  { id: 'ATT-169', name: 'API scraping / enumeration at scale', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-022', check_ids: ['l7.api_surface_scan.safe'] },
  { id: 'ATT-170', name: 'WAF bypass enabling volumetric success', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-001', check_ids: ['waf.fingerprint.safe', 'waf.enforcement.safe', 'waf.marker_rule.safe'] },
  { id: 'ATT-171', name: 'Kill-switch / runbook failure under attack load', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-026', check_ids: ['ops.kill_switch_drill.safe', 'ops.kill_switch_drill.request_only', 'ops.runbook_contact_validation.safe', 'ops.runbook_contact_validation.request_only'] },
  { id: 'ATT-172', name: 'Provider telemetry blind spot during test', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-026', check_ids: ['ops.provider_telemetry.request_only'] },
  { id: 'ATT-173', name: 'Post-attack degradation / recovery drill', exhausted_resource: 'delivery_pattern', coverage_status: 'soc_only', task_id: 'DET-022', check_ids: ['high_scale.degradation_recovery.request_only'] },
  { id: 'ATT-174', name: 'CORS misconfiguration enabling cross-origin abuse', exhausted_resource: 'application_l7', coverage_status: 'partial', task_id: 'DET-020', check_ids: ['l7.cors_posture.safe'], notes: 'Configuration exposure; enables browser-origin abuse patterns.' },
  { id: 'ATT-175', name: 'Rate-limit evasion via header/IP rotation', exhausted_resource: 'delivery_pattern', coverage_status: 'partial', task_id: 'DET-022', check_ids: ['l7.low_rate_rate_limit.safe', 'waf.low_rate_limit.safe'] },
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
