# Current audit catalog acceptance index

Companion to [remediation ledger](verified-capability-audit-remediation.md). Generated from the current catalog on 2026-10-09, not archived live evidence. A definition, engine/profile, vector mapping and independently exercised mechanism are different counts. E3 is an eligible semantic contract, not proof a particular run passed; governance is not protection credit. Unsupported entries remain non-executable.

## Current matrix and support boundaries

- 251 definitions; 721 vector mappings; 161 unique runnable safe check IDs.
- Current definition tiers: E1 72, E2 130, E3 32, E4 17. There are 31 explicitly unsupported definitions (28 evasion profiles, inspection limit, compressed request, IPP).
- Evidence-capability mapping counts: 71 semantic-safe, 230 observation-only, 102 declaration-only, 269 SOC-governed, 49 monitor-only. 116 mechanism IDs identify shared profiles, not independent validated defenses.
- Mapping dispositions: safe_runnable: 357, additional_input_required: 10, target_incompatible: 0, soc_gated: 269, monitor_only: 49, not_runnable: 36.
- IPP callback exposure has no supported safe executor; alert webhook observation requires approved signed callback scope with no current declaration producer. Both remain unavailable without that authority.
- Standalone host/SNI is E2, baseline absent, observation-only; DNSKEY and HTTP/2 SETTINGS are E2 observations, not resilience proof. The unsupported evasion rows have exact delivery-specific identifiers rather than unrelated supported grouped alternatives.

## All check definitions

| Check | Shared engine/profile | Evidence tier | Delivery/mechanism declared supported | Complete marker proof required |
|---|---|---|---|---|
| `origin.direct_reachability.safe` | `host_sni_bypass` | E2 | yes (bounded contract only) | engine contract |
| `origin.direct_bypass.safe` | `host_sni_bypass` | E2 | yes (bounded contract only) | engine contract |
| `origin.host_sni_bypass.safe` | `host_sni_bypass` | E2 | yes (bounded contract only) | engine contract |
| `origin.leak_scan.safe` | `origin_leak_scan` | E2 | yes (bounded contract only) | engine contract |
| `l3.firewall_exposure_scan.safe` | `port_scan_bounded` | E2 | yes (bounded contract only) | engine contract |
| `path.protected_canary.safe` | `http_head` | E2 | yes (bounded contract only) | engine contract |
| `l3.forbidden_tcp_port.safe` | `tcp_connect` | E2 | yes (bounded contract only) | engine contract |
| `l3.forbidden_udp_port.safe` | `udp_probe` | E2 | yes (bounded contract only) | engine contract |
| `l3.basic_deny_rule.safe` | `tcp_connect` | E2 | yes (bounded contract only) | engine contract |
| `dns.authoritative_response.safe` | `dns_wire_query` | E2 | yes (bounded contract only) | engine contract |
| `dns.random_prefix_nxdomain.safe` | `dns_wire_query` | E2 | yes (bounded contract only) | engine contract |
| `dns.open_recursion_behavior.safe` | `dns_open_recursion` | E2 | yes (bounded contract only) | engine contract |
| `l7.waf_marker_rule.safe` | `waf_enforcement_probe` | E2 | yes (bounded contract only) | engine contract |
| `waf.fingerprint.safe` | `waf_fingerprint_observation` | E2 | yes (bounded contract only) | engine contract |
| `waf.marker_rule.safe` | `waf_enforcement_probe` | E2 | yes (bounded contract only) | engine contract |
| `waf.origin_bypass.safe` | `host_sni_bypass` | E2 | yes (bounded contract only) | engine contract |
| `waf.low_rate_limit.safe` | `rate_limit_sequence` | E2 | yes (bounded contract only) | engine contract |
| `l7.http_method_restriction.safe` | `http_method_matrix` | E2 | yes (bounded contract only) | engine contract |
| `l7.header_size_boundary.safe` | `header_size_probe` | E2 | yes (bounded contract only) | engine contract |
| `l7.low_rate_rate_limit.safe` | `rate_limit_sequence` | E2 | yes (bounded contract only) | engine contract |
| `tls.profile_exposure.safe` | `tls_audit` | E2 | yes (bounded contract only) | engine contract |
| `protocol.http2_readiness.safe` | `http2_settings` | E2 | yes (bounded contract only) | engine contract |
| `protocol.http3_quic_exposure.safe` | `quic_reachability` | E2 | yes (bounded contract only) | engine contract |
| `ops.alert_workflow_marker.safe` | `alert_webhook_ping` | E2 | yes (bounded contract only) | engine contract |
| `ops.runbook_contact_validation.safe` | `ops_readiness` | E3 | yes (bounded contract only) | engine contract |
| `ops.kill_switch_drill.safe` | `ops_readiness` | E3 | yes (bounded contract only) | engine contract |
| `l3.ipv6_reachability.safe` | `tcp_connect` | E2 | yes (bounded contract only) | engine contract |
| `dns.amplification_exposure.safe` | `dns_wire_query` | E2 | yes (bounded contract only) | engine contract |
| `dns.dnssec_expensive_query.safe` | `dnssec_posture` | E2 | yes (bounded contract only) | engine contract |
| `dns.secondary_failover.safe` | `dns_failover_posture` | E2 | yes (bounded contract only) | engine contract |
| `dns.zone_transfer_exposure.safe` | `dns_axfr_leak` | E3 | yes (bounded contract only) | engine contract |
| `l7.cache_busting.safe` | `cache_abuse_probe` | E2 | yes (bounded contract only) | engine contract |
| `l7.expensive_endpoint.safe` | `http_head` | E2 | yes (bounded contract only) | engine contract |
| `l7.login_abuse_flow.safe` | `rate_limit_sequence` | E2 | yes (bounded contract only) | engine contract |
| `l7.password_reset.safe` | `http_head` | E2 | yes (bounded contract only) | engine contract |
| `l7.api_quota_exhaustion.safe` | `rate_limit_sequence` | E2 | yes (bounded contract only) | engine contract |
| `l7.graphql_complexity.safe` | `graphql_posture_probe` | E2 | yes (bounded contract only) | engine contract |
| `l7.bot_challenge_marker.safe` | `bot_challenge_probe` | E2 | yes (bounded contract only) | engine contract |
| `tls.slow_header_body_timeout.safe` | `slow_header_probe` | E2 | yes (bounded contract only) | engine contract |
| `tls.idle_connection_timeout.safe` | `tls_session` | E2 | yes (bounded contract only) | engine contract |
| `protocol.http2_rapid_reset_readiness.safe` | `http2_settings` | E2 | yes (bounded contract only) | engine contract |
| `protocol.http2_stream_concurrency.safe` | `http2_settings` | E2 | yes (bounded contract only) | engine contract |
| `protocol.grpc_reflection_stream.safe` | `grpc_reflection_probe` | E2 | yes (bounded contract only) | engine contract |
| `protocol.websocket_connection_controls.safe` | `websocket_upgrade_posture` | E2 | yes (bounded contract only) | engine contract |
| `tls.full_audit.safe` | `tls_audit` | E2 | yes (bounded contract only) | engine contract |
| `l7.api_surface_scan.safe` | `api_surface_scan` | E2 | yes (bounded contract only) | engine contract |
| `l7.cors_posture.safe` | `cors_posture_probe` | E2 | yes (bounded contract only) | engine contract |
| `waf.enforcement.safe` | `waf_enforcement_probe` | E2 | yes (bounded contract only) | engine contract |
| `l3.connection_table_exhaustion.request_only` | `soc_gated` | E4 | no: existing SOC request only | engine contract |
| `high_scale.dns_high_query.request_only` | `soc_gated` | E4 | no: existing SOC request only | engine contract |
| `ops.runbook_contact_validation.request_only` | `soc_gated` | E4 | no: existing SOC request only | engine contract |
| `ops.kill_switch_drill.request_only` | `soc_gated` | E4 | no: existing SOC request only | engine contract |
| `ops.provider_telemetry.request_only` | `soc_gated` | E4 | no: existing SOC request only | engine contract |
| `high_scale.multi_vector.request_only` | `soc_gated` | E4 | no: existing SOC request only | engine contract |
| `high_scale.degradation_recovery.request_only` | `soc_gated` | E4 | no: existing SOC request only | engine contract |
| `high_scale.volumetric.request_only` | `soc_gated` | E4 | no: existing SOC request only | engine contract |
| `waf.offensive_sqli.soc` | `soc_gated` | E4 | no: existing SOC request only | engine contract |
| `waf.offensive_xss.soc` | `soc_gated` | E4 | no: existing SOC request only | engine contract |
| `waf.offensive_rce.soc` | `soc_gated` | E4 | no: existing SOC request only | engine contract |
| `waf.offensive_path_traversal.soc` | `soc_gated` | E4 | no: existing SOC request only | engine contract |
| `waf.offensive_command_injection.soc` | `soc_gated` | E4 | no: existing SOC request only | engine contract |
| `waf.offensive_ldap_injection.soc` | `soc_gated` | E4 | no: existing SOC request only | engine contract |
| `waf.offensive_ssti.soc` | `soc_gated` | E4 | no: existing SOC request only | engine contract |
| `waf.offensive_combined.soc` | `soc_gated` | E4 | no: existing SOC request only | engine contract |
| `high_scale.application.request_only` | `soc_gated` | E4 | no: existing SOC request only | engine contract |
| `l3.icmp_flood.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l3.gre_esp_flood.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l3.ipv6_volumetric.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l3.sip_voip_flood.readiness` | `udp_probe` | E2 | yes (bounded contract only) | engine contract |
| `l3.sctp_exposure.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l3.multicast_broadcast_storm.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l3.ack_flood.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l3.rst_flood.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l3.syn_ack_flood.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l3.tcp_flag_anomaly.readiness` | `tcp_connect` | E2 | yes (bounded contract only) | engine contract |
| `l3.out_of_state_tcp.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l3.fragmentation_flood.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l3.syn_flood.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l3.tcp_connection_flood.readiness` | `tcp_connect` | E2 | yes (bounded contract only) | engine contract |
| `l3.nat_state_table.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l3.smtp_connection_flood.readiness` | `tcp_connect` | E2 | yes (bounded contract only) | engine contract |
| `l3.ssh_connection_flood.readiness` | `tcp_connect` | E2 | yes (bounded contract only) | engine contract |
| `l3.ftp_connection_flood.readiness` | `tcp_connect` | E2 | yes (bounded contract only) | engine contract |
| `l3.ike_ipsec_negotiation.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.connection_hoarding.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `exploit.ping_of_death.posture` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `exploit.teardrop.posture` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `exploit.ip_options.posture` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `exploit.malformed_quic.posture` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `exploit.land_attack.posture` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `exploit.quic_migration.posture` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `reflect.ssdp_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `reflect.snmp_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `reflect.chargen_qotd_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `reflect.mdns_netbios_wsdiscovery_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `reflect.portmap_service_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `reflect.dtls_sip_rdp_tftp_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `reflect.quic_reflection_exposure.safe` | `quic_reachability` | E2 | yes (bounded contract only) | engine contract |
| `reflect.tcp_middlebox_exposure.safe` | `tcp_connect` | E2 | yes (bounded contract only) | engine contract |
| `reflect.mssql_resolver_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `reflect.jenkins_discovery_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `reflect.coap_iot_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `reflect.legacy_device_discovery_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `reflect.stun_turn_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `reflect.ipmi_bmc_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `reflect.redis_direct_exposure.safe` | `tcp_connect` | E2 | yes (bounded contract only) | engine contract |
| `reflect.openvpn_wireguard_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `amp.ntp_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `amp.cldap_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `amp.memcached_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `amp.dns_any_txt_exposure.safe` | `dns_wire_query` | E2 | yes (bounded contract only) | engine contract |
| `amp.smurf_broadcast_exposure.safe` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `amp.authoritative_resolver_exposure.safe` | `dns_wire_query` | E2 | yes (bounded contract only) | engine contract |
| `dns.laundering.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `dns.garbage_flood.readiness` | `dns_wire_query` | E2 | yes (bounded contract only) | engine contract |
| `dns.phantom_domain.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `dns.domain_lockup.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `dns.nxns_attack.readiness` | `dns_wire_query` | E2 | yes (bounded contract only) | engine contract |
| `dns.dnsbomb.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `dns.qname_minimization.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `dns.doh_dot_exposure.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `dns.tcp_fallback.readiness` | `dns_wire_query` | E2 | yes (bounded contract only) | engine contract |
| `dns.zone_walking.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.http_get_flood.validation` | `rate_limit_sequence` | E2 | yes (bounded contract only) | engine contract |
| `l7.http_post_flood.validation` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.slowloris.readiness` | `slow_header_probe` | E2 | yes (bounded contract only) | engine contract |
| `l7.slow_post.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.slow_read.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.low_and_slow.readiness` | `slow_header_probe` | E2 | yes (bounded contract only) | engine contract |
| `l7.large_body_post.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.file_upload_abuse.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.json_xml_bomb.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.search_abuse.validation` | `rate_limit_sequence` | E2 | yes (bounded contract only) | engine contract |
| `l7.export_abuse.validation` | `rate_limit_sequence` | E2 | yes (bounded contract only) | engine contract |
| `l7.batch_api_abuse.validation` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.oauth_token_abuse.validation` | `rate_limit_sequence` | E2 | yes (bounded contract only) | engine contract |
| `l7.checkout_abuse.validation` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.otp_sms_cost.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.signup_registration_abuse.validation` | `rate_limit_sequence` | E2 | yes (bounded contract only) | engine contract |
| `l7.elasticsearch_abuse.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.health_check_flood.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.wordpress_xmlrpc.readiness` | `http_head` | E2 | yes (bounded contract only) | engine contract |
| `l7.webhook_flood.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.http_pipelining.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.http_range_abuse.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.conditional_revalidation.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.captcha_challenge_abuse.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.mqtt_broker_exposure.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.redos.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.graphql_batch_abuse.validation` | `graphql_posture_probe` | E2 | yes (bounded contract only) | engine contract |
| `tls.handshake_rate.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `tls.renegotiation.readiness` | `tls_session` | E2 | yes (bounded contract only) | engine contract |
| `tls.zero_rtt.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `tls.ocsp_stapling.readiness` | `tls_audit` | E2 | yes (bounded contract only) | engine contract |
| `l7.http2_rapid_reset.validation` | `http2_frame_probe` | E2 | yes (bounded contract only) | engine contract |
| `l7.http2_made_you_reset.readiness` | `http2_frame_probe` | E2 | yes (bounded contract only) | engine contract |
| `l7.http2_continuation.readiness` | `http2_frame_probe` | E2 | yes (bounded contract only) | engine contract |
| `l7.http2_priority_abuse.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.hpack_bomb.readiness` | `http2_frame_probe` | E2 | yes (bounded contract only) | engine contract |
| `l7.http2_push_promise.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.qpack_bomb.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `protocol.sse_stream.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `protocol.http3_control_stream.readiness` | `http3_control_probe` | E2 | yes (bounded contract only) | engine contract |
| `protocol.websocket_message_rate.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `origin.cdn_bypass.readiness` | `origin_leak_scan` | E2 | yes (bounded contract only) | engine contract |
| `origin.dns_hostname_bypass.readiness` | `origin_leak_scan` | E2 | yes (bounded contract only) | engine contract |
| `pattern.carpet_bombing.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `pattern.pulse_wave.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `pattern.spoofed_source.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `pattern.ransom_ddos.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `pattern.rate_limit_evasion.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `pattern.adaptive_evasion.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `pattern.residential_proxy.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `ops.autoscaling_cost.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `ops.attack_alert_coverage.readiness` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `reflect.slp_amplification_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `reflect.tp240_amplification_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `reflect.l2tp_reflection_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `reflect.natpmp_amplification_exposure.safe` | `reflection_service_probe` | E2 | yes (bounded contract only) | engine contract |
| `reflect.ipp_callback_exposure.safe` | `reflection_service_probe` | E2 | no: unsupported/not-tested | engine contract |
| `dns.multi_question_oversized.safe` | `dns_wire_query` | E2 | yes (bounded contract only) | engine contract |
| `waf.http_method_policy_marker.safe` | `waf_class_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.request_smuggling_marker.safe` | `waf_class_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.crlf_injection_marker.safe` | `waf_class_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.open_redirect_marker.safe` | `waf_class_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.nosql_injection_marker.safe` | `waf_class_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.xpath_injection_marker.safe` | `waf_class_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.jndi_ldap_marker.safe` | `waf_class_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.csv_formula_marker.safe` | `waf_class_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.prototype_pollution_marker.safe` | `waf_class_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.deserialization_marker.safe` | `waf_class_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.ssrf_marker.safe` | `waf_class_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.xxe_marker.safe` | `waf_class_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.file_upload_marker.safe` | `waf_class_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.jwt_tamper_marker.safe` | `waf_class_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.entry_path_login_marker.safe` | `waf_class_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.entry_path_api_marker.safe` | `waf_class_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.evasion_unicode_normalization.safe` | `waf_evasion_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.evasion_homoglyph.safe` | `waf_evasion_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.evasion_overlong_utf8.safe` | `waf_evasion_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.evasion_alt_charset.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_html_entity.safe` | `waf_evasion_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.evasion_js_escape.safe` | `waf_evasion_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.evasion_json_unicode_escape.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_css_escape.safe` | `waf_evasion_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.evasion_base64_wrap.safe` | `waf_evasion_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.evasion_numeric_repr.safe` | `waf_evasion_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.evasion_whitespace.safe` | `waf_evasion_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.evasion_lexical_operator.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_lexical_tautology.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_lexical_literal.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_control_char.safe` | `waf_evasion_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.evasion_path_matrix.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_path_suffix.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_ip_representation.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_parser_hpp.safe` | `waf_evasion_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.evasion_parser_json_dup.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_parser_header_dup.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_framing_cl_te.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_framing_transfer_coding.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_framing_h2_h1.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_framing_line_ending.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_framing_chunk_ext.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_body_gzip.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_body_nested_encoding.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_content_type_binary.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_struct_type_confusion.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_struct_deep_nesting.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_parameter_location.safe` | `waf_evasion_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.evasion_method_override.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_protocol_version.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_protocol_upgrade.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_benign_padding.safe` | `waf_evasion_marker_probe` | E3 | yes (bounded contract only) | yes |
| `waf.evasion_polyglot_content.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_protocol_h3_h1.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_protocol_qpack_hpack.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_multipart_charset.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.evasion_xml_attribute.safe` | `waf_evasion_marker_probe` | E2 | no: unsupported/not-tested | yes |
| `waf.inspection_limit.safe` | `waf_inspection_limit_probe` | E2 | no: unsupported/not-tested | engine contract |
| `waf.evasion_cache_key_mismatch.posture` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `waf.evasion_reassembly_differential.posture` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `waf.evasion_rule_gap.posture` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `waf.evasion_second_order.posture` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `waf.evasion_encrypted_payload.posture` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `waf.evasion_signed_structured_data.posture` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `waf.evasion_connection_coalescing.posture` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `waf.evasion_ech_routing_metadata.posture` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `l7.compressed_request_decompression.posture` | `l7_resource_posture_probe` | E2 | no: unsupported/not-tested | engine contract |
| `l7.request_parser_size.posture` | `l7_resource_posture_probe` | E2 | yes (bounded contract only) | engine contract |
| `waf.http_routing_trust.posture` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |
| `waf.jsonp_css_policy.posture` | `metadata_marker` | E1 | yes (bounded contract only) | engine contract |

Regressions: `capability-probes`, `safe-network-probes`, `waf-class-probes`, `evasion-probes`, `reflector-guardrails`, `vectors`, `vector-library`, `resource-exhaustion-taxonomy`, `check-definition-version`, `full-catalog-live-evidence`, and exact local wire fixtures. Original custody artifacts are never regenerated to match new support counts. Current metadata generator v2/schema3 rejects incompatible old assessment semantics; it executes no probes.
