/** Presentation only: no execution definitions, digest input or network behavior.
 * Every shipped runtime ID has an explicit short name and mechanism template.
 */
const TEMPLATES = [
  {
    "mechanism": "One declared-address HTTP Host/SNI observation",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Bounded declared-host DNS and HTTP observations",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Bounded TCP connects to catalogued or declared ports",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "One HTTP HEAD response observation",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Bounded TCP connection samples",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Bounded UDP service samples",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Bounded DNS wire query",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "One query to a declared resolver",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "One inert-marker HTTP response observation",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Ordinary GET with DNS/address/HTTP provider signals",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Small fixed HTTP request sequence",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Bounded HTTP method response matrix",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Bounded HTTP header-size comparison",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "One TLS handshake and certificate/configuration inspection",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "One HTTP/2 SETTINGS observation",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "HTTP Alt-Svc advertisement observation, not a QUIC exchange",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "No callback delivery without separately approved signed scope",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Local operational-declaration evaluation; no target traffic",
    "limitations": "Customer-provided operational information is not live enforcement or capacity evidence.",
    "next_step": "Review declared control evidence and its freshness; arrange an authorized assessment if needed."
  },
  {
    "mechanism": "Bounded DNSKEY observation",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Bounded nameserver/address observations, not a failover drill",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Bounded authorized DNS zone-transfer comparison",
    "limitations": "One confirmed transfer can establish exposure; protection requires every declared nameserver to refuse. No DNS resilience or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Small HTTP cache-marker comparison",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Bounded GraphQL metadata observation",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "One HTTP challenge observation",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "One bounded slow-header timeout sample",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "One TLS session observation",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "One bounded gRPC reflection response observation",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "One WebSocket upgrade response observation",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Bounded catalogue-path HTTP observations",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "One CORS response-header observation",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Governed request only; no customer probe executor",
    "limitations": "A request is not execution, approval, a traffic result or readiness evidence.",
    "next_step": "Request an authorized SOC review; do not execute from this entry."
  },
  {
    "mechanism": "Stored declaration only; zero target traffic",
    "limitations": "Customer-provided operational information is not live enforcement or capacity evidence.",
    "next_step": "Review declared control evidence and its freshness; arrange an authorized assessment if needed."
  },
  {
    "mechanism": "Bounded TCP connection samples after explicit target setup",
    "limitations": "The current entry lacks the required declared port or deny policy. No connection-flood validation or protection conclusion.",
    "next_step": "Provide the required declared target and port or deny policy before an explicitly authorized bounded retest."
  },
  {
    "mechanism": "Bounded labelled service requests without spoofing or amplification",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Bounded existing HTTP/2 control-frame or SETTINGS sample",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "HTTP Alt-Svc advertisement observation, not HTTP/3 control traffic",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Bounded labelled service requests without spoofing or amplification",
    "limitations": "The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion.",
    "next_step": "Keep untested and seek an approved supported assessment."
  },
  {
    "mechanism": "GET inert-token query/path/header placements and benign controls",
    "limitations": "No exact installed-token rule binding exists in current declarations. No attack-method test, installed-rule failure finding or readiness credit.",
    "next_step": "Review the recorded token response. Exact installed-rule validation is unavailable; do not infer failure or configure unrelated controls as a substitute."
  },
  {
    "mechanism": "GET inert-token query/path/header placements and benign controls",
    "limitations": "Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Benign control, plain inert reference and supported transformed marker comparison",
    "limitations": "Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Benign control, plain inert reference and supported transformed marker comparison",
    "limitations": "The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion.",
    "next_step": "Keep untested and seek an approved supported assessment."
  },
  {
    "mechanism": "Unavailable: no approved business-safe body endpoint",
    "limitations": "The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion.",
    "next_step": "Keep untested and seek an approved supported assessment."
  },
  {
    "mechanism": "Bounded URI/parameter-size observation; body plans unavailable",
    "limitations": "The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion.",
    "next_step": "Keep untested and seek an approved supported assessment."
  },
  {
    "mechanism": "Bounded URI/parameter-size observation; body plans unavailable",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "GET inert scanner User-Agent and benign controls",
    "limitations": "Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "GET controls and bodyless TRACE/nonstandard-token method comparison",
    "limitations": "A scoped E2 method-policy verdict is possible; no readiness, exploit or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Bounded sequence on a declared low-threshold canary route",
    "limitations": "Only the declared route, threshold and observed sequence are covered; no production quota, identity-key or DDoS-capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  },
  {
    "mechanism": "Bounded connection acceptance samples",
    "limitations": "Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance.",
    "next_step": "Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope."
  }
];
const PAIRED_IDENTITY_TEMPLATE = TEMPLATES.push({
  mechanism: "Reviewed two-leg E2 application-identity observation",
  limitations: "Compares the protected route with one declared, verified origin using the reviewed HEAD or bounded GET scope. Content or certificate similarity alone is not confirmed application identity. No protected result, readiness credit, capacity assurance or proof of bypassing a particular WAF rule.",
  next_step: "Inspect both observations, current authorization and fresh nonce-baseline comparability before interpreting the direct application path."
}) - 1;
const ENTRIES = {
  "origin.identity_pair.head.v1": ["Paired origin identity · HEAD", PAIRED_IDENTITY_TEMPLATE],
  "origin.identity_pair.get.v1": ["Paired origin identity · bounded GET", PAIRED_IDENTITY_TEMPLATE],
  "origin.direct_reachability.safe": ["Direct Origin Reachability", 0],
  "origin.direct_bypass.safe": ["Declared-origin response", 0],
  "origin.host_sni_bypass.safe": ["Declared Host/SNI response", 0],
  "origin.leak_scan.safe": ["Origin Leak Scan", 1],
  "l3.firewall_exposure_scan.safe": ["Firewall Exposure Scan", 2],
  "path.protected_canary.safe": ["Canary HTTP response", 3],
  "l3.forbidden_tcp_port.safe": ["Forbidden TCP Port", 4],
  "l3.forbidden_udp_port.safe": ["Forbidden UDP Port", 5],
  "l3.basic_deny_rule.safe": ["Basic Deny-Rule Validation", 4],
  "dns.authoritative_response.safe": ["DNS Authoritative Response", 6],
  "dns.random_prefix_nxdomain.safe": ["DNS Random-Prefix / NXDOMAIN", 6],
  "dns.open_recursion_behavior.safe": ["Open Recursion Behavior", 7],
  "l7.waf_marker_rule.safe": ["WAF token response sample", 8],
  "waf.fingerprint.safe": ["WAF and CDN Fingerprint", 9],
  "waf.marker_rule.safe": ["WAF token response posture", 8],
  "waf.origin_bypass.safe": ["Declared-origin WAF observation", 0],
  "waf.low_rate_limit.safe": ["Low-rate response sequence", 10],
  "l7.http_method_restriction.safe": ["HTTP method responses", 11],
  "l7.header_size_boundary.safe": ["Header/Size Boundary", 12],
  "l7.low_rate_rate_limit.safe": ["Rate-limit response sample", 10],
  "tls.profile_exposure.safe": ["TLS Profile Exposure", 13],
  "protocol.http2_readiness.safe": ["HTTP/2 settings observation", 14],
  "protocol.http3_quic_exposure.safe": ["HTTP/3 Alt-Svc Observation", 15],
  "ops.alert_workflow_marker.safe": ["Alert Workflow Webhook Ping", 16],
  "ops.runbook_contact_validation.safe": ["Runbook declaration review", 17],
  "ops.kill_switch_drill.safe": ["Stop-readiness declaration review", 17],
  "l3.ipv6_reachability.safe": ["IPv6 Declared Reachability", 4],
  "dns.amplification_exposure.safe": ["DNS response size sample", 6],
  "dns.dnssec_expensive_query.safe": ["DNSKEY presence", 18],
  "dns.secondary_failover.safe": ["Secondary DNS observations", 19],
  "dns.zone_transfer_exposure.safe": ["Zone Transfer Exposure", 20],
  "l7.cache_busting.safe": ["Cache response comparison", 21],
  "l7.expensive_endpoint.safe": ["Expensive Endpoint", 3],
  "l7.login_abuse_flow.safe": ["Login-route response sample", 10],
  "l7.password_reset.safe": ["Reset-route HEAD response", 3],
  "l7.api_quota_exhaustion.safe": ["API quota response signals", 10],
  "l7.graphql_complexity.safe": ["GraphQL metadata response", 22],
  "l7.bot_challenge_marker.safe": ["Bot / Challenge Marker", 23],
  "tls.slow_header_body_timeout.safe": ["Slow-header timeout sample", 24],
  "tls.idle_connection_timeout.safe": ["TLS session sample", 25],
  "protocol.http2_rapid_reset_readiness.safe": ["HTTP/2 advertised settings", 14],
  "protocol.http2_stream_concurrency.safe": ["HTTP/2 advertised stream limits", 14],
  "protocol.grpc_reflection_stream.safe": ["gRPC reflection response", 26],
  "protocol.websocket_connection_controls.safe": ["WebSocket upgrade response", 27],
  "tls.full_audit.safe": ["TLS certificate and settings", 13],
  "l7.api_surface_scan.safe": ["API Surface Scan", 28],
  "l7.cors_posture.safe": ["CORS Posture", 29],
  "waf.enforcement.safe": ["WAF token response", 8],
  "l3.connection_table_exhaustion.request_only": ["Connection Table Exhaustion request", 30],
  "high_scale.dns_high_query.request_only": ["DNS High-Query review request", 30],
  "ops.runbook_contact_validation.request_only": ["Runbook / Emergency Contact Validation request", 30],
  "ops.kill_switch_drill.request_only": ["Kill Switch Drill request", 30],
  "ops.provider_telemetry.request_only": ["Provider Telemetry Validation request", 30],
  "high_scale.multi_vector.request_only": ["Multi-Vector review request", 30],
  "high_scale.degradation_recovery.request_only": ["Degradation / Recovery Drill request", 30],
  "high_scale.volumetric.request_only": ["Volumetric L3/L4 request", 30],
  "waf.offensive_sqli.soc": ["WAF SQLi review request", 30],
  "waf.offensive_xss.soc": ["WAF XSS review request", 30],
  "waf.offensive_rce.soc": ["WAF RCE review request", 30],
  "waf.offensive_path_traversal.soc": ["WAF Path Traversal review request", 30],
  "waf.offensive_command_injection.soc": ["WAF Command Injection review request", 30],
  "waf.offensive_ldap_injection.soc": ["WAF LDAP Injection review request", 30],
  "waf.offensive_ssti.soc": ["WAF SSTI review request", 30],
  "waf.offensive_combined.soc": ["WAF Combined review request", 30],
  "high_scale.application.request_only": ["Application-Layer High-Scale request", 30],
  "l3.icmp_flood.readiness": ["ICMP Flood declaration", 31],
  "l3.gre_esp_flood.readiness": ["GRE / ESP Tunnel Flood declaration", 31],
  "l3.ipv6_volumetric.readiness": ["IPv6 Volumetric declaration", 31],
  "l3.sip_voip_flood.readiness": ["SIP-port UDP response sample", 5],
  "l3.sctp_exposure.readiness": ["SCTP Exposure declaration", 31],
  "l3.multicast_broadcast_storm.readiness": ["Multicast / Broadcast Storm declaration", 31],
  "l3.ack_flood.readiness": ["ACK Flood declaration", 31],
  "l3.rst_flood.readiness": ["RST Flood declaration", 31],
  "l3.syn_ack_flood.readiness": ["SYN-ACK Flood declaration", 31],
  "l3.tcp_flag_anomaly.readiness": ["TCP flag test unavailable", 32],
  "l3.out_of_state_tcp.readiness": ["Out-of-State TCP Filtering declaration", 31],
  "l3.fragmentation_flood.readiness": ["Fragmentation Flood declaration", 31],
  "l3.syn_flood.readiness": ["SYN Flood declaration", 31],
  "l3.tcp_connection_flood.readiness": ["TCP connection setup required", 32],
  "l3.nat_state_table.readiness": ["NAT / State Table declaration", 31],
  "l3.smtp_connection_flood.readiness": ["SMTP-port TCP reachability", 4],
  "l3.ssh_connection_flood.readiness": ["SSH-port TCP reachability", 4],
  "l3.ftp_connection_flood.readiness": ["FTP-port TCP reachability", 4],
  "l3.ike_ipsec_negotiation.readiness": ["IKE / IPsec Negotiation declaration", 31],
  "l7.connection_hoarding.readiness": ["Application Connection Hoarding declaration", 31],
  "exploit.ping_of_death.posture": ["Legacy Oversized-Packet Filtering declaration", 31],
  "exploit.teardrop.posture": ["Overlapping-Fragment Filtering declaration", 31],
  "exploit.ip_options.posture": ["IP Options Filtering declaration", 31],
  "exploit.malformed_quic.posture": ["QUIC Parser Robustness declaration", 31],
  "exploit.land_attack.posture": ["Spoofed Same-Source Filtering declaration", 31],
  "exploit.quic_migration.posture": ["QUIC Migration Abuse declaration", 31],
  "reflect.ssdp_exposure.safe": ["SSDP / UPnP Reflector Exposure", 33],
  "reflect.snmp_exposure.safe": ["SNMP Responder Exposure", 33],
  "reflect.chargen_qotd_exposure.safe": ["CHARGEN / QOTD / Echo Responder Exposure", 33],
  "reflect.mdns_netbios_wsdiscovery_exposure.safe": ["mDNS / NetBIOS NBSTAT / WS-Discovery Composite Exposure", 33],
  "reflect.portmap_service_exposure.safe": ["Portmapper / RIPv1 / RPC Service Exposure", 33],
  "reflect.dtls_sip_rdp_tftp_exposure.safe": ["DTLS/SIP/RDP/TFTP responses", 33],
  "reflect.quic_reflection_exposure.safe": ["QUIC Alt-Svc Advertisement Observation", 15],
  "reflect.tcp_middlebox_exposure.safe": ["TCP service reachability", 32],
  "reflect.mssql_resolver_exposure.safe": ["MSSQL Resolver Exposure", 33],
  "reflect.jenkins_discovery_exposure.safe": ["Jenkins / CI Discovery Exposure", 33],
  "reflect.coap_iot_exposure.safe": ["CoAP IoT Responder Exposure", 33],
  "reflect.legacy_device_discovery_exposure.safe": ["Legacy Device / Game Discovery Exposure", 33],
  "reflect.stun_turn_exposure.safe": ["STUN / TURN Responder Exposure", 33],
  "reflect.ipmi_bmc_exposure.safe": ["IPMI / BMC Responder Exposure", 33],
  "reflect.redis_direct_exposure.safe": ["Redis-port TCP reachability", 4],
  "reflect.openvpn_wireguard_exposure.safe": ["OpenVPN / WireGuard Responder Exposure", 33],
  "amp.ntp_exposure.safe": ["NTP Mode Restriction Exposure", 33],
  "amp.cldap_exposure.safe": ["CLDAP Exposure Posture", 33],
  "amp.memcached_exposure.safe": ["Memcached Exposure", 33],
  "amp.dns_any_txt_exposure.safe": ["DNS ANY/TXT Response-Class Posture", 6],
  "amp.smurf_broadcast_exposure.safe": ["Directed Broadcast Filtering declaration", 31],
  "amp.authoritative_resolver_exposure.safe": ["DNS service response sample", 6],
  "dns.laundering.readiness": ["DNS Laundering declaration", 31],
  "dns.garbage_flood.readiness": ["DNS query response sample", 6],
  "dns.phantom_domain.readiness": ["Phantom Domain declaration", 31],
  "dns.domain_lockup.readiness": ["Domain Lock-Up declaration", 31],
  "dns.nxns_attack.readiness": ["DNS nameserver response sample", 6],
  "dns.dnsbomb.readiness": ["DNSBomb Pulsing declaration", 31],
  "dns.qname_minimization.readiness": ["QNAME Minimization declaration", 31],
  "dns.doh_dot_exposure.readiness": ["DoH / DoT Endpoint declaration", 31],
  "dns.tcp_fallback.readiness": ["DNS TCP fallback sample", 6],
  "dns.zone_walking.readiness": ["DNS Zone-Walking declaration", 31],
  "l7.http_get_flood.validation": ["GET response sequence", 10],
  "l7.http_post_flood.validation": ["HTTP POST Limit declaration", 31],
  "l7.slowloris.readiness": ["Slow-header connection sample", 24],
  "l7.slow_post.readiness": ["Slow Body Client declaration", 31],
  "l7.slow_read.readiness": ["Slow Read Response declaration", 31],
  "l7.low_and_slow.readiness": ["Low-and-Slow Header Timeout Sample", 24],
  "l7.large_body_post.readiness": ["Large Body Limit declaration", 31],
  "l7.file_upload_abuse.readiness": ["File Upload Abuse declaration", 31],
  "l7.json_xml_bomb.readiness": ["Parser Depth Limit declaration", 31],
  "l7.search_abuse.validation": ["Search-route response sample", 10],
  "l7.export_abuse.validation": ["Export-route response sample", 10],
  "l7.batch_api_abuse.validation": ["Batch API Limit declaration", 31],
  "l7.oauth_token_abuse.validation": ["Token-route response sample", 10],
  "l7.checkout_abuse.validation": ["Checkout Endpoint Limit declaration", 31],
  "l7.otp_sms_cost.readiness": ["OTP / SMS Cost Guardrail declaration", 31],
  "l7.signup_registration_abuse.validation": ["Signup-route response sample", 10],
  "l7.elasticsearch_abuse.readiness": ["Search-Cluster Query Cost declaration", 31],
  "l7.health_check_flood.readiness": ["Health-Check Flood declaration", 31],
  "l7.wordpress_xmlrpc.readiness": ["XML-RPC Endpoint Posture", 3],
  "l7.webhook_flood.readiness": ["Webhook Callback Limit declaration", 31],
  "l7.http_pipelining.readiness": ["HTTP Pipelining Limit declaration", 31],
  "l7.http_range_abuse.readiness": ["Range Request Limit declaration", 31],
  "l7.conditional_revalidation.readiness": ["Conditional Revalidation Cost declaration", 31],
  "l7.captcha_challenge_abuse.readiness": ["Challenge Endpoint Cost declaration", 31],
  "l7.mqtt_broker_exposure.readiness": ["MQTT Broker declaration", 31],
  "l7.redos.readiness": ["Regex Complexity declaration", 31],
  "l7.graphql_batch_abuse.validation": ["GraphQL response posture", 22],
  "tls.handshake_rate.readiness": ["TLS Handshake Rate declaration", 31],
  "tls.renegotiation.readiness": ["TLS Renegotiation Posture", 25],
  "tls.zero_rtt.readiness": ["TLS 0-RTT Early Data declaration", 31],
  "tls.ocsp_stapling.readiness": ["OCSP Stapling Posture", 13],
  "l7.http2_rapid_reset.validation": ["HTTP/2 reset sample", 34],
  "l7.http2_made_you_reset.readiness": ["HTTP/2 control-frame sample", 34],
  "l7.http2_continuation.readiness": ["HTTP/2 control-frame posture", 34],
  "l7.http2_priority_abuse.readiness": ["HTTP/2 Priority Abuse declaration", 31],
  "l7.hpack_bomb.readiness": ["HTTP/2 advertised header limits", 34],
  "l7.http2_push_promise.readiness": ["HTTP/2 Server Push declaration", 31],
  "l7.qpack_bomb.readiness": ["QPACK Compression Limit declaration", 31],
  "protocol.sse_stream.readiness": ["SSE Stream Limit declaration", 31],
  "protocol.http3_control_stream.readiness": ["HTTP/3 Alt-Svc Posture Observation", 35],
  "protocol.websocket_message_rate.readiness": ["WebSocket Message Rate declaration", 31],
  "origin.cdn_bypass.readiness": ["Declared-host origin observations", 1],
  "origin.dns_hostname_bypass.readiness": ["DNS Hostname Bypass Sample", 1],
  "pattern.carpet_bombing.readiness": ["Carpet Bombing declaration", 31],
  "pattern.pulse_wave.readiness": ["Pulse-Wave declaration", 31],
  "pattern.spoofed_source.readiness": ["Spoofed Source Filtering declaration", 31],
  "pattern.ransom_ddos.readiness": ["Ransom DDoS Runbook declaration", 31],
  "pattern.rate_limit_evasion.readiness": ["Rate-Limit Evasion Resistance declaration", 31],
  "pattern.adaptive_evasion.readiness": ["Adaptive Evasion Resistance declaration", 31],
  "pattern.residential_proxy.readiness": ["Residential Proxy Resistance declaration", 31],
  "ops.autoscaling_cost.readiness": ["Autoscaling Cost Guardrail declaration", 31],
  "ops.attack_alert_coverage.readiness": ["Attack Alert Coverage declaration", 31],
  "reflect.slp_amplification_exposure.safe": ["SLP Amplification Exposure", 33],
  "reflect.tp240_amplification_exposure.safe": ["TP240 PhoneHome Amplification Exposure", 33],
  "reflect.l2tp_reflection_exposure.safe": ["L2TP Reflection Exposure", 33],
  "reflect.natpmp_amplification_exposure.safe": ["NAT-PMP Amplification Exposure", 33],
  "reflect.ipp_callback_exposure.safe": ["IPP callback test unavailable", 36],
  "dns.multi_question_oversized.safe": ["DNS parser response sample", 6],
  "waf.http_method_policy_marker.safe": ["HTTP-policy token observation", 37],
  "waf.request_smuggling_marker.safe": ["Request Smuggling token observation", 37],
  "waf.crlf_injection_marker.safe": ["CRLF/Response-Splitting token observation", 37],
  "waf.open_redirect_marker.safe": ["Open Redirect / Parameter Policy token observation", 37],
  "waf.nosql_injection_marker.safe": ["NoSQL Injection token observation", 37],
  "waf.xpath_injection_marker.safe": ["XPath/XML Injection token observation", 37],
  "waf.jndi_ldap_marker.safe": ["JNDI/LDAP token observation", 37],
  "waf.csv_formula_marker.safe": ["CSV/Formula token observation", 37],
  "waf.prototype_pollution_marker.safe": ["Prototype Pollution token observation", 37],
  "waf.deserialization_marker.safe": ["Unsafe Deserialization token observation", 37],
  "waf.ssrf_marker.safe": ["SSRF token observation", 37],
  "waf.xxe_marker.safe": ["XXE token observation", 37],
  "waf.file_upload_marker.safe": ["File Upload token observation", 37],
  "waf.jwt_tamper_marker.safe": ["JWT Tamper token observation", 37],
  "waf.entry_path_login_marker.safe": ["WAF Declared Login Path Marker", 38],
  "waf.entry_path_api_marker.safe": ["WAF Declared API Path Marker", 38],
  "waf.evasion_unicode_normalization.safe": ["Unicode Normalization marker comparison", 39],
  "waf.evasion_homoglyph.safe": ["Homoglyph marker comparison", 39],
  "waf.evasion_overlong_utf8.safe": ["Overlong Utf8 marker comparison", 39],
  "waf.evasion_alt_charset.safe": ["ALT Charset test unavailable", 40],
  "waf.evasion_html_entity.safe": ["Html Entity marker comparison", 39],
  "waf.evasion_js_escape.safe": ["JS Escape marker comparison", 39],
  "waf.evasion_json_unicode_escape.safe": ["Json Unicode Escape test unavailable", 40],
  "waf.evasion_css_escape.safe": ["CSS Escape marker comparison", 39],
  "waf.evasion_base64_wrap.safe": ["Base64 Wrap marker comparison", 39],
  "waf.evasion_numeric_repr.safe": ["Numeric Repr marker comparison", 39],
  "waf.evasion_whitespace.safe": ["Whitespace marker comparison", 39],
  "waf.evasion_lexical_operator.safe": ["Lexical Operator test unavailable", 40],
  "waf.evasion_lexical_tautology.safe": ["Lexical Tautology test unavailable", 40],
  "waf.evasion_lexical_literal.safe": ["Lexical Literal test unavailable", 40],
  "waf.evasion_control_char.safe": ["Control Char marker comparison", 39],
  "waf.evasion_path_matrix.safe": ["Path Matrix test unavailable", 40],
  "waf.evasion_path_suffix.safe": ["Path Suffix test unavailable", 40],
  "waf.evasion_ip_representation.safe": ["IP Representation test unavailable", 40],
  "waf.evasion_parser_hpp.safe": ["Parser HPP marker comparison", 39],
  "waf.evasion_parser_json_dup.safe": ["Parser Json DUP test unavailable", 40],
  "waf.evasion_parser_header_dup.safe": ["Parser Header DUP test unavailable", 40],
  "waf.evasion_framing_cl_te.safe": ["Framing CL TE test unavailable", 40],
  "waf.evasion_framing_transfer_coding.safe": ["Framing Transfer Coding test unavailable", 40],
  "waf.evasion_framing_h2_h1.safe": ["Framing H2 H1 test unavailable", 40],
  "waf.evasion_framing_line_ending.safe": ["Framing Line Ending test unavailable", 40],
  "waf.evasion_framing_chunk_ext.safe": ["Framing Chunk EXT test unavailable", 40],
  "waf.evasion_body_gzip.safe": ["Body Gzip test unavailable", 40],
  "waf.evasion_body_nested_encoding.safe": ["Body Nested Encoding test unavailable", 40],
  "waf.evasion_content_type_binary.safe": ["Content Type Binary test unavailable", 40],
  "waf.evasion_struct_type_confusion.safe": ["Struct Type Confusion test unavailable", 40],
  "waf.evasion_struct_deep_nesting.safe": ["Struct Deep Nesting test unavailable", 40],
  "waf.evasion_parameter_location.safe": ["Parameter Location marker comparison", 39],
  "waf.evasion_method_override.safe": ["Method Override test unavailable", 40],
  "waf.evasion_protocol_version.safe": ["Protocol Version test unavailable", 40],
  "waf.evasion_protocol_upgrade.safe": ["Protocol Upgrade test unavailable", 40],
  "waf.evasion_benign_padding.safe": ["Benign Padding marker comparison", 39],
  "waf.evasion_polyglot_content.safe": ["Polyglot Content test unavailable", 40],
  "waf.evasion_protocol_h3_h1.safe": ["Protocol H3 H1 test unavailable", 40],
  "waf.evasion_protocol_qpack_hpack.safe": ["Protocol Qpack Hpack test unavailable", 40],
  "waf.evasion_multipart_charset.safe": ["Multipart Charset test unavailable", 40],
  "waf.evasion_xml_attribute.safe": ["XML Attribute test unavailable", 40],
  "waf.inspection_limit.safe": ["Body inspection unavailable", 41],
  "waf.evasion_cache_key_mismatch.posture": ["Cache-key / routing mismatch declaration", 31],
  "waf.evasion_reassembly_differential.posture": ["IP fragmentation / TCP segmentation differential declaration", 31],
  "waf.evasion_rule_gap.posture": ["Zero-day / rule-gap evasion declaration", 31],
  "waf.evasion_second_order.posture": ["Stored / deferred second-order payload declaration", 31],
  "waf.evasion_encrypted_payload.posture": ["Application-layer encrypted / opaque payload declaration", 31],
  "waf.evasion_signed_structured_data.posture": ["Signed but malicious structured data declaration", 31],
  "waf.evasion_connection_coalescing.posture": ["Connection coalescing identity confusion declaration", 31],
  "waf.evasion_ech_routing_metadata.posture": ["Encrypted ClientHello / hidden routing-metadata gap declaration", 31],
  "l7.compressed_request_decompression.posture": ["Compressed-body test unavailable", 42],
  "l7.request_parser_size.posture": ["Request URI / Parameter Size Limit Posture", 43],
  "waf.http_routing_trust.posture": ["WAF HTTP Routing & Proxy-Trust declaration", 31],
  "waf.jsonp_css_policy.posture": ["WAF JSONP & CSS-Injection Policy declaration", 31],
  "waf.sqli_managed_marker.safe": ["SQLi marker comparison", 38],
  "waf.xss_managed_marker.safe": ["XSS marker comparison", 38],
  "waf.path_traversal_managed_marker.safe": ["Path-traversal marker comparison", 38],
  "waf.ssti_marker.safe": ["SSTI token observation", 37],
  "waf.scanner_signature_marker.safe": ["Scanner User-Agent marker", 44],
  "waf.evasion_double_url.safe": ["Double URL marker comparison", 39],
  "waf.evasion_mixed_url.safe": ["Mixed URL marker comparison", 39],
  "waf.evasion_case_fold.safe": ["Case Fold marker comparison", 39],
  "waf.http_method_policy_enforced.safe": ["HTTP method enforcement", 45],
  "waf.rate_limit_canary.validation": ["WAF Rate-Limit Canary", 46],
  "waf.body_json_marker.soc": ["WAF JSON Body Marker request", 30],
  "waf.body_form_marker.soc": ["WAF Form Body Marker request", 30],
  "waf.body_multipart_marker.soc": ["WAF Multipart Body Marker request", 30],
  "waf.body_inspection_limit.soc": ["WAF Body Inspection Limit request", 30],
  "waf.response_dlp_canary.soc": ["WAF Response DLP Canary request", 30],
  "nfw.declared_deny_tcp.safe": ["Declared TCP Deny", 4],
  "nfw.declared_deny_udp.safe": ["Declared UDP Deny", 5],
  "nfw.management_port_exposure.safe": ["Management and Database Port Exposure", 2],
  "nfw.ipv6_parity.safe": ["IPv6/IPv4 Policy Parity", 4],
  "nfw.connection_limit.safe": ["Per-Source Connection Limit", 47],
  "nfw.origin_lockdown.safe": ["Origin Lockdown to Declared Binding", 0],
  "nfw.perspective_allowlist.safe": ["Multi-Perspective Allowlist", 4],
};
const PRESENTATION = Object.freeze(Object.fromEntries(Object.entries(ENTRIES).map(([id, [name, index]]) => {
  const template = TEMPLATES[index];
  return [id, Object.freeze({ name, purpose: name + ': ' + template.mechanism + '.', ...template })];
})));
export const CHECK_PRESENTATION_IDS = Object.freeze(Object.keys(PRESENTATION));
const UNKNOWN = Object.freeze({
  name: 'Unknown check', purpose: 'This check is not in the current presentation registry.',
  limitations: 'No mechanism or supported conclusion is established by an unknown ID.',
  next_step: 'Review the exact check ID and current catalog.', mechanism: 'Unknown',
});

/** Stable metadata, independent of mutable/caller-supplied check display fields. */
export function checkPresentation(checkOrId) {
  const id = typeof checkOrId === 'string' ? checkOrId : checkOrId?.check_id;
  return Object.hasOwn(PRESENTATION, id) ? PRESENTATION[id] : UNKNOWN;
}
