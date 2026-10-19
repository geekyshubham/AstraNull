# Plain-language check review

Date: 2026-10-18

The shared presentation registry now contains an individually written name, purpose, mechanism, limitation and next step for each of the 275 runtime checks. These fields are not built by joining a title to a family template. Every value in each of the five fields is distinct across the catalog. The generated [check library](../check-library.html) contains the complete explanations; `src/lib/checkPresentation.mjs` is their source of truth.

## Evidence and writing rules

- Purpose explains why someone would select the check. How it works says what the current worker actually sends, reads or records. Limits state what that observation cannot establish. Next step identifies a relevant action.
- Names describe the current implemented check, rather than repeating an attack name that suggests an attack was performed. For example, the current multi-question DNS ID sends one NS question over TCP; the STUN/TURN ID makes a STUN request; the OpenVPN/WireGuard ID sends the OpenVPN sample. Their explanations make those differences explicit.
- A declaration says that it records a statement and performs no test traffic. A request-only entry says that it arranges a separately reviewed assessment. An unavailable request format says why it cannot be sent. A small connection or response sample does not claim attack resistance or capacity.
- Comparisons explain ordinary requests, original test text, the specific changed form and the need for a usable blocked original response. Base64 is explained as a letters-and-numbers data encoding. Look-alike, Base64 and numeric forms do not prove the application interprets them equivalently.
- Technical IDs, executable definitions, request budgets, evidence tiers, authorization and grading remain unchanged. The registry stays outside definition digests. Known old comparison explanations receive a display translation; original stored records are preserved.
- The main check page shows purpose, steps, limits and next action once. Stored evaluation rules and original templates remain available under Technical details. Selection, findings, evidence and schedule references resolve the same names by check ID.

## Research used to verify terminology

External references explain the concepts. The local executor, signed profile and evaluator determine what AstraNull actually does. Descriptions of unavailable mechanisms are not execution evidence.

| Reference | Application to the review |
| --- | --- |
| [RFC 4648, Base encodings](https://www.rfc-editor.org/rfc/rfc4648) | Base64 represents bytes using a restricted alphabet. The description does not call it encryption or assume the application decodes it. |
| [OWASP, Double Encoding](https://owasp.org/www-community/Double_Encoding) | Explains repeated decoding. The twice-encoded URL check describes its actual transmitted transformation. |
| [OWASP WSTG, HTTP Parameter Pollution](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution) | Repeated parameter names can be handled differently by application components; a duplicate parameter alone does not establish a vulnerability. |
| [OWASP, Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | Separates text validation from proving that application processing is safe. Custom test labels are described as labels, not functional exploits. |
| [OWASP, Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) | Provides context for request, size, time and resource limits. A small sample or saved declaration is not a load test. |
| [RFC 9110, HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110.html) | Verifies method names and the distinction between requesting response headers and submitting application data. |
| [RFC 9113, HTTP/2](https://www.rfc-editor.org/rfc/rfc9113.html) | Provides settings, stream and reset terminology. Reading settings or canceling one stream does not establish flood resistance; this limit follows from the local executor's small sequence. |
| [RFC 5358, Recursive DNS reflector prevention](https://www.rfc-editor.org/rfc/rfc5358) | Distinguishes public recursive DNS access from measuring reflected traffic or mitigation capacity. |
| [RFC 9267, DNS implementation pitfalls](https://www.rfc-editor.org/rfc/rfc9267.html) | Supports the distinction between a DNS response observation and a separate parser or oversized-message assessment. |
| [RFC 8489, STUN](https://www.rfc-editor.org/rfc/rfc8489.html) | A binding request observes address/connectivity information; it is not evidence of unauthorized TURN relay access. |
| [RFC 7252, CoAP](https://www.rfc-editor.org/rfc/rfc7252.html) | Clarifies device-resource discovery without suggesting that the check operates the device. |
| [RFC 6886, NAT-PMP](https://www.rfc-editor.org/rfc/rfc6886.html) | Distinguishes an external-address query from creating or changing a port mapping. |
| [RFC 8011, IPP](https://www.rfc-editor.org/rfc/rfc8011.html) | Distinguishes a printer-information query from a print job; the current catalog's IPP delivery remains unavailable. |
| [RFC 8633, NTP practices](https://www.rfc-editor.org/rfc/rfc8633.html) | Frames the public NTP query as an access-policy observation, not a traffic amplification measurement. |

## Implementation cross-check

The review uses `src/contracts/checks.mjs`, `src/lib/probeEvidenceTiers.mjs`, `src/lib/capabilityProbes.mjs`, `src/lib/safeNetworkProbes.mjs`, and `src/lib/vectorProbes/` (especially `evasionProbes.mjs`, `wafClassProbes.mjs`, `l7ResourceProbes.mjs` and `wafProbeSupport.mjs`). The existing delivery inventory identifies the executor for every runtime ID; it is an implementation map, not proof of successful execution.

The index below is generated from the live catalog and shared presentation registry. Every row links to that check's full purpose, steps, limits and next action in the generated check library.

| Check ID | Customer-facing name | Current implementation kind |
| --- | --- | --- |
| [`origin.direct_reachability.safe`](../check-library.html#origin.direct_reachability.safe) | Direct server response | `host_sni_bypass` |
| [`origin.direct_bypass.safe`](../check-library.html#origin.direct_bypass.safe) | Access outside the public website route | `host_sni_bypass` |
| [`origin.host_sni_bypass.safe`](../check-library.html#origin.host_sni_bypass.safe) | Website name on a direct server connection | `host_sni_bypass` |
| [`origin.leak_scan.safe`](../check-library.html#origin.leak_scan.safe) | Public clues to the server behind your website | `origin_leak_scan` |
| [`l3.firewall_exposure_scan.safe`](../check-library.html#l3.firewall_exposure_scan.safe) | Internet access to common service ports | `port_scan_bounded` |
| [`path.protected_canary.safe`](../check-library.html#path.protected_canary.safe) | Response from your test URL | `http_head` |
| [`l3.forbidden_tcp_port.safe`](../check-library.html#l3.forbidden_tcp_port.safe) | Access to a TCP port you marked blocked | `tcp_connect` |
| [`l3.forbidden_udp_port.safe`](../check-library.html#l3.forbidden_udp_port.safe) | Response from a UDP port you marked blocked | `udp_probe` |
| [`l3.basic_deny_rule.safe`](../check-library.html#l3.basic_deny_rule.safe) | Connection through a declared deny rule | `tcp_connect` |
| [`dns.authoritative_response.safe`](../check-library.html#dns.authoritative_response.safe) | Response from your domain's DNS server | `dns_wire_query` |
| [`dns.random_prefix_nxdomain.safe`](../check-library.html#dns.random_prefix_nxdomain.safe) | DNS response for a name that should not exist | `dns_wire_query` |
| [`dns.open_recursion_behavior.safe`](../check-library.html#dns.open_recursion_behavior.safe) | Public access to DNS lookups | `dns_open_recursion` |
| [`l7.waf_marker_rule.safe`](../check-library.html#l7.waf_marker_rule.safe) | Response to your firewall test label | `waf_enforcement_probe` |
| [`waf.fingerprint.safe`](../check-library.html#waf.fingerprint.safe) | Identify your website's protection services | `waf_fingerprint_observation` |
| [`waf.marker_rule.safe`](../check-library.html#waf.marker_rule.safe) | Custom firewall label response | `waf_enforcement_probe` |
| [`waf.origin_bypass.safe`](../check-library.html#waf.origin_bypass.safe) | Firewall response on the direct server route | `host_sni_bypass` |
| [`waf.low_rate_limit.safe`](../check-library.html#waf.low_rate_limit.safe) | Response to a short request sequence | `rate_limit_sequence` |
| [`l7.http_method_restriction.safe`](../check-library.html#l7.http_method_restriction.safe) | Responses to different HTTP methods | `http_method_matrix` |
| [`l7.header_size_boundary.safe`](../check-library.html#l7.header_size_boundary.safe) | Response to a larger request header | `header_size_probe` |
| [`l7.low_rate_rate_limit.safe`](../check-library.html#l7.low_rate_rate_limit.safe) | Rate-limit signals at a low request rate | `rate_limit_sequence` |
| [`tls.profile_exposure.safe`](../check-library.html#tls.profile_exposure.safe) | Encrypted connection settings | `tls_audit` |
| [`protocol.http2_readiness.safe`](../check-library.html#protocol.http2_readiness.safe) | HTTP/2 connection settings | `http2_settings` |
| [`protocol.http3_quic_exposure.safe`](../check-library.html#protocol.http3_quic_exposure.safe) | HTTP/3 availability announcement | `quic_reachability` |
| [`ops.alert_workflow_marker.safe`](../check-library.html#ops.alert_workflow_marker.safe) | Test notification delivery | `alert_webhook_ping` |
| [`ops.runbook_contact_validation.safe`](../check-library.html#ops.runbook_contact_validation.safe) | Response plan and emergency contacts | `ops_readiness` |
| [`ops.kill_switch_drill.safe`](../check-library.html#ops.kill_switch_drill.safe) | Readiness to stop a validation | `ops_readiness` |
| [`l3.ipv6_reachability.safe`](../check-library.html#l3.ipv6_reachability.safe) | Connection to your IPv6 endpoint | `tcp_connect` |
| [`dns.amplification_exposure.safe`](../check-library.html#dns.amplification_exposure.safe) | Size of a DNS reply | `dns_wire_query` |
| [`dns.dnssec_expensive_query.safe`](../check-library.html#dns.dnssec_expensive_query.safe) | DNS signing-key records | `dnssec_posture` |
| [`dns.secondary_failover.safe`](../check-library.html#dns.secondary_failover.safe) | Secondary DNS server observations | `dns_failover_posture` |
| [`dns.zone_transfer_exposure.safe`](../check-library.html#dns.zone_transfer_exposure.safe) | Public DNS zone transfer | `dns_axfr_leak` |
| [`l7.cache_busting.safe`](../check-library.html#l7.cache_busting.safe) | Response when a URL's cache key changes | `cache_abuse_probe` |
| [`l7.expensive_endpoint.safe`](../check-library.html#l7.expensive_endpoint.safe) | Response from a resource-heavy URL | `http_head` |
| [`l7.login_abuse_flow.safe`](../check-library.html#l7.login_abuse_flow.safe) | Responses from the login test route | `rate_limit_sequence` |
| [`l7.password_reset.safe`](../check-library.html#l7.password_reset.safe) | Response from the password-reset URL | `http_head` |
| [`l7.api_quota_exhaustion.safe`](../check-library.html#l7.api_quota_exhaustion.safe) | Visible API quota signals | `rate_limit_sequence` |
| [`l7.graphql_complexity.safe`](../check-library.html#l7.graphql_complexity.safe) | Public GraphQL endpoint response | `graphql_posture_probe` |
| [`l7.bot_challenge_marker.safe`](../check-library.html#l7.bot_challenge_marker.safe) | Bot challenge response | `bot_challenge_probe` |
| [`tls.slow_header_body_timeout.safe`](../check-library.html#tls.slow_header_body_timeout.safe) | Timeout for an unfinished web request | `slow_header_probe` |
| [`tls.idle_connection_timeout.safe`](../check-library.html#tls.idle_connection_timeout.safe) | HTTPS session response | `tls_session` |
| [`protocol.http2_rapid_reset_readiness.safe`](../check-library.html#protocol.http2_rapid_reset_readiness.safe) | HTTP/2 settings relevant to reset protection | `http2_settings` |
| [`protocol.http2_stream_concurrency.safe`](../check-library.html#protocol.http2_stream_concurrency.safe) | Advertised HTTP/2 stream limit | `http2_settings` |
| [`protocol.grpc_reflection_stream.safe`](../check-library.html#protocol.grpc_reflection_stream.safe) | Public gRPC service information | `grpc_reflection_probe` |
| [`protocol.websocket_connection_controls.safe`](../check-library.html#protocol.websocket_connection_controls.safe) | WebSocket connection upgrade response | `websocket_upgrade_posture` |
| [`tls.full_audit.safe`](../check-library.html#tls.full_audit.safe) | HTTPS certificate and connection details | `tls_audit` |
| [`l7.api_surface_scan.safe`](../check-library.html#l7.api_surface_scan.safe) | Responses from common API paths | `api_surface_scan` |
| [`l7.cors_posture.safe`](../check-library.html#l7.cors_posture.safe) | Cross-site browser access headers | `cors_posture_probe` |
| [`waf.enforcement.safe`](../check-library.html#waf.enforcement.safe) | Website response to a firewall test token | `waf_enforcement_probe` |
| [`l3.connection_table_exhaustion.request_only`](../check-library.html#l3.connection_table_exhaustion.request_only) | Plan a connection-capacity test | `reviewed_request_only` |
| [`high_scale.dns_high_query.request_only`](../check-library.html#high_scale.dns_high_query.request_only) | Plan a high-volume DNS test | `reviewed_request_only` |
| [`ops.runbook_contact_validation.request_only`](../check-library.html#ops.runbook_contact_validation.request_only) | Arrange a response-team contact drill | `reviewed_request_only` |
| [`ops.kill_switch_drill.request_only`](../check-library.html#ops.kill_switch_drill.request_only) | Arrange a validation stop drill | `reviewed_request_only` |
| [`ops.provider_telemetry.request_only`](../check-library.html#ops.provider_telemetry.request_only) | Arrange provider monitoring verification | `reviewed_request_only` |
| [`high_scale.multi_vector.request_only`](../check-library.html#high_scale.multi_vector.request_only) | Plan a mixed-traffic resilience test | `reviewed_request_only` |
| [`high_scale.degradation_recovery.request_only`](../check-library.html#high_scale.degradation_recovery.request_only) | Plan a service recovery exercise | `reviewed_request_only` |
| [`high_scale.volumetric.request_only`](../check-library.html#high_scale.volumetric.request_only) | Plan a network-capacity exercise | `reviewed_request_only` |
| [`waf.offensive_sqli.soc`](../check-library.html#waf.offensive_sqli.soc) | Request a supervised database-injection assessment | `reviewed_request_only` |
| [`waf.offensive_xss.soc`](../check-library.html#waf.offensive_xss.soc) | Request a supervised browser-script assessment | `reviewed_request_only` |
| [`waf.offensive_rce.soc`](../check-library.html#waf.offensive_rce.soc) | Request a supervised server-execution assessment | `reviewed_request_only` |
| [`waf.offensive_path_traversal.soc`](../check-library.html#waf.offensive_path_traversal.soc) | Request a supervised file-path assessment | `reviewed_request_only` |
| [`waf.offensive_command_injection.soc`](../check-library.html#waf.offensive_command_injection.soc) | Request a supervised command-input assessment | `reviewed_request_only` |
| [`waf.offensive_ldap_injection.soc`](../check-library.html#waf.offensive_ldap_injection.soc) | Request a supervised directory-query assessment | `reviewed_request_only` |
| [`waf.offensive_ssti.soc`](../check-library.html#waf.offensive_ssti.soc) | Request a supervised page-template assessment | `reviewed_request_only` |
| [`waf.offensive_combined.soc`](../check-library.html#waf.offensive_combined.soc) | Request a coordinated web-security assessment | `reviewed_request_only` |
| [`high_scale.application.request_only`](../check-library.html#high_scale.application.request_only) | Plan a high-volume website test | `reviewed_request_only` |
| [`l3.icmp_flood.readiness`](../check-library.html#l3.icmp_flood.readiness) | Ping traffic surge plan | `metadata_marker` |
| [`l3.gre_esp_flood.readiness`](../check-library.html#l3.gre_esp_flood.readiness) | Tunnel traffic surge plan | `metadata_marker` |
| [`l3.ipv6_volumetric.readiness`](../check-library.html#l3.ipv6_volumetric.readiness) | IPv6 traffic surge plan | `metadata_marker` |
| [`l3.sip_voip_flood.readiness`](../check-library.html#l3.sip_voip_flood.readiness) | UDP response on the voice-signaling port | `udp_probe` |
| [`l3.sctp_exposure.readiness`](../check-library.html#l3.sctp_exposure.readiness) | SCTP service access review | `metadata_marker` |
| [`l3.multicast_broadcast_storm.readiness`](../check-library.html#l3.multicast_broadcast_storm.readiness) | Broadcast traffic containment plan | `metadata_marker` |
| [`l3.ack_flood.readiness`](../check-library.html#l3.ack_flood.readiness) | Unexpected acknowledgment traffic plan | `metadata_marker` |
| [`l3.rst_flood.readiness`](../check-library.html#l3.rst_flood.readiness) | Unexpected connection-reset traffic plan | `metadata_marker` |
| [`l3.syn_ack_flood.readiness`](../check-library.html#l3.syn_ack_flood.readiness) | Unexpected connection-reply traffic plan | `metadata_marker` |
| [`l3.tcp_flag_anomaly.readiness`](../check-library.html#l3.tcp_flag_anomaly.readiness) | TCP connection for packet-flag review | `tcp_connect` |
| [`l3.out_of_state_tcp.readiness`](../check-library.html#l3.out_of_state_tcp.readiness) | Traffic outside valid connections review | `metadata_marker` |
| [`l3.fragmentation_flood.readiness`](../check-library.html#l3.fragmentation_flood.readiness) | Split network-packet traffic plan | `metadata_marker` |
| [`l3.syn_flood.readiness`](../check-library.html#l3.syn_flood.readiness) | New-connection traffic surge plan | `metadata_marker` |
| [`l3.tcp_connection_flood.readiness`](../check-library.html#l3.tcp_connection_flood.readiness) | Reachability of the declared connection service | `tcp_connect` |
| [`l3.nat_state_table.readiness`](../check-library.html#l3.nat_state_table.readiness) | Network address-translation capacity plan | `metadata_marker` |
| [`l3.smtp_connection_flood.readiness`](../check-library.html#l3.smtp_connection_flood.readiness) | Connection to the mail service port | `tcp_connect` |
| [`l3.ssh_connection_flood.readiness`](../check-library.html#l3.ssh_connection_flood.readiness) | Connection to the remote-login port | `tcp_connect` |
| [`l3.ftp_connection_flood.readiness`](../check-library.html#l3.ftp_connection_flood.readiness) | Connection to the file-transfer port | `tcp_connect` |
| [`l3.ike_ipsec_negotiation.readiness`](../check-library.html#l3.ike_ipsec_negotiation.readiness) | VPN negotiation surge plan | `metadata_marker` |
| [`l7.connection_hoarding.readiness`](../check-library.html#l7.connection_hoarding.readiness) | Long-lived connection resource plan | `metadata_marker` |
| [`exploit.ping_of_death.posture`](../check-library.html#exploit.ping_of_death.posture) | Oversized ping handling review | `metadata_marker` |
| [`exploit.teardrop.posture`](../check-library.html#exploit.teardrop.posture) | Overlapping packet-fragment review | `metadata_marker` |
| [`exploit.ip_options.posture`](../check-library.html#exploit.ip_options.posture) | Unusual IP packet options review | `metadata_marker` |
| [`exploit.malformed_quic.posture`](../check-library.html#exploit.malformed_quic.posture) | Invalid QUIC message handling review | `metadata_marker` |
| [`exploit.land_attack.posture`](../check-library.html#exploit.land_attack.posture) | Same-source-and-destination packet review | `metadata_marker` |
| [`exploit.quic_migration.posture`](../check-library.html#exploit.quic_migration.posture) | QUIC connection address-change review | `metadata_marker` |
| [`reflect.ssdp_exposure.safe`](../check-library.html#reflect.ssdp_exposure.safe) | Public device-discovery replies | `reflection_service_probe` |
| [`reflect.snmp_exposure.safe`](../check-library.html#reflect.snmp_exposure.safe) | Public network-management replies | `reflection_service_probe` |
| [`reflect.chargen_qotd_exposure.safe`](../check-library.html#reflect.chargen_qotd_exposure.safe) | Public character-generator service | `reflection_service_probe` |
| [`reflect.mdns_netbios_wsdiscovery_exposure.safe`](../check-library.html#reflect.mdns_netbios_wsdiscovery_exposure.safe) | Public local-network discovery services | `reflection_service_probe` |
| [`reflect.portmap_service_exposure.safe`](../check-library.html#reflect.portmap_service_exposure.safe) | Public RPC service-directory replies | `reflection_service_probe` |
| [`reflect.dtls_sip_rdp_tftp_exposure.safe`](../check-library.html#reflect.dtls_sip_rdp_tftp_exposure.safe) | Public replies from selected UDP services | `reflection_service_probe` |
| [`reflect.quic_reflection_exposure.safe`](../check-library.html#reflect.quic_reflection_exposure.safe) | QUIC availability advertised by the website | `quic_reachability` |
| [`reflect.tcp_middlebox_exposure.safe`](../check-library.html#reflect.tcp_middlebox_exposure.safe) | Connection to a declared network intermediary | `tcp_connect` |
| [`reflect.mssql_resolver_exposure.safe`](../check-library.html#reflect.mssql_resolver_exposure.safe) | Public SQL Server discovery replies | `reflection_service_probe` |
| [`reflect.jenkins_discovery_exposure.safe`](../check-library.html#reflect.jenkins_discovery_exposure.safe) | Public Jenkins discovery replies | `reflection_service_probe` |
| [`reflect.coap_iot_exposure.safe`](../check-library.html#reflect.coap_iot_exposure.safe) | Public device-service information | `reflection_service_probe` |
| [`reflect.legacy_device_discovery_exposure.safe`](../check-library.html#reflect.legacy_device_discovery_exposure.safe) | Public WS-Discovery response | `reflection_service_probe` |
| [`reflect.stun_turn_exposure.safe`](../check-library.html#reflect.stun_turn_exposure.safe) | Public STUN address-discovery replies | `reflection_service_probe` |
| [`reflect.ipmi_bmc_exposure.safe`](../check-library.html#reflect.ipmi_bmc_exposure.safe) | Public server-management discovery replies | `reflection_service_probe` |
| [`reflect.redis_direct_exposure.safe`](../check-library.html#reflect.redis_direct_exposure.safe) | Connection to the Redis service port | `tcp_connect` |
| [`reflect.openvpn_wireguard_exposure.safe`](../check-library.html#reflect.openvpn_wireguard_exposure.safe) | Public OpenVPN service reply | `reflection_service_probe` |
| [`amp.ntp_exposure.safe`](../check-library.html#amp.ntp_exposure.safe) | Public time-service information replies | `reflection_service_probe` |
| [`amp.cldap_exposure.safe`](../check-library.html#amp.cldap_exposure.safe) | Public directory-discovery replies | `reflection_service_probe` |
| [`amp.memcached_exposure.safe`](../check-library.html#amp.memcached_exposure.safe) | Public UDP cache-service replies | `reflection_service_probe` |
| [`amp.dns_any_txt_exposure.safe`](../check-library.html#amp.dns_any_txt_exposure.safe) | DNS text-record response size | `dns_wire_query` |
| [`amp.smurf_broadcast_exposure.safe`](../check-library.html#amp.smurf_broadcast_exposure.safe) | Directed-broadcast restriction review | `metadata_marker` |
| [`amp.authoritative_resolver_exposure.safe`](../check-library.html#amp.authoritative_resolver_exposure.safe) | DNS nameserver response behavior | `dns_wire_query` |
| [`dns.laundering.readiness`](../check-library.html#dns.laundering.readiness) | DNS traffic from public resolvers review | `metadata_marker` |
| [`dns.garbage_flood.readiness`](../check-library.html#dns.garbage_flood.readiness) | DNS responses to sampled address queries | `dns_wire_query` |
| [`dns.phantom_domain.readiness`](../check-library.html#dns.phantom_domain.readiness) | DNS requests for unresponsive domains review | `metadata_marker` |
| [`dns.domain_lockup.readiness`](../check-library.html#dns.domain_lockup.readiness) | Slow DNS reply resource review | `metadata_marker` |
| [`dns.nxns_attack.readiness`](../check-library.html#dns.nxns_attack.readiness) | DNS delegation-record response | `dns_wire_query` |
| [`dns.dnsbomb.readiness`](../check-library.html#dns.dnsbomb.readiness) | Delayed DNS reply surge review | `metadata_marker` |
| [`dns.qname_minimization.readiness`](../check-library.html#dns.qname_minimization.readiness) | DNS lookup privacy review | `metadata_marker` |
| [`dns.doh_dot_exposure.readiness`](../check-library.html#dns.doh_dot_exposure.readiness) | Encrypted DNS access review | `metadata_marker` |
| [`dns.tcp_fallback.readiness`](../check-library.html#dns.tcp_fallback.readiness) | DNS response over TCP | `dns_wire_query` |
| [`dns.zone_walking.readiness`](../check-library.html#dns.zone_walking.readiness) | Public DNS record enumeration review | `metadata_marker` |
| [`l7.http_get_flood.validation`](../check-library.html#l7.http_get_flood.validation) | Response to a small page-request burst | `rate_limit_sequence` |
| [`l7.http_post_flood.validation`](../check-library.html#l7.http_post_flood.validation) | Form-submission traffic surge review | `metadata_marker` |
| [`l7.slowloris.readiness`](../check-library.html#l7.slowloris.readiness) | One slowly started HTTP request | `slow_header_probe` |
| [`l7.slow_post.readiness`](../check-library.html#l7.slow_post.readiness) | Slow form-upload handling review | `metadata_marker` |
| [`l7.slow_read.readiness`](../check-library.html#l7.slow_read.readiness) | Slow response-reader handling review | `metadata_marker` |
| [`l7.low_and_slow.readiness`](../check-library.html#l7.low_and_slow.readiness) | Single slow-request timeout sample | `slow_header_probe` |
| [`l7.large_body_post.readiness`](../check-library.html#l7.large_body_post.readiness) | Large submitted-request limits review | `metadata_marker` |
| [`l7.file_upload_abuse.readiness`](../check-library.html#l7.file_upload_abuse.readiness) | Upload abuse controls review | `metadata_marker` |
| [`l7.json_xml_bomb.readiness`](../check-library.html#l7.json_xml_bomb.readiness) | Complex document-processing limits review | `metadata_marker` |
| [`l7.search_abuse.validation`](../check-library.html#l7.search_abuse.validation) | Request-limit signals on the search test route | `rate_limit_sequence` |
| [`l7.export_abuse.validation`](../check-library.html#l7.export_abuse.validation) | Request-limit signals on the export test route | `rate_limit_sequence` |
| [`l7.batch_api_abuse.validation`](../check-library.html#l7.batch_api_abuse.validation) | Bulk API operation limits review | `metadata_marker` |
| [`l7.oauth_token_abuse.validation`](../check-library.html#l7.oauth_token_abuse.validation) | Response limits on the token-service test route | `rate_limit_sequence` |
| [`l7.checkout_abuse.validation`](../check-library.html#l7.checkout_abuse.validation) | Checkout abuse prevention review | `metadata_marker` |
| [`l7.otp_sms_cost.readiness`](../check-library.html#l7.otp_sms_cost.readiness) | Text-message and verification-code cost review | `metadata_marker` |
| [`l7.signup_registration_abuse.validation`](../check-library.html#l7.signup_registration_abuse.validation) | Response limits on the signup test route | `rate_limit_sequence` |
| [`l7.elasticsearch_abuse.readiness`](../check-library.html#l7.elasticsearch_abuse.readiness) | Search-cluster access and query limits review | `metadata_marker` |
| [`l7.health_check_flood.readiness`](../check-library.html#l7.health_check_flood.readiness) | Health-check route abuse review | `metadata_marker` |
| [`l7.wordpress_xmlrpc.readiness`](../check-library.html#l7.wordpress_xmlrpc.readiness) | Response from the declared WordPress route | `http_head` |
| [`l7.webhook_flood.readiness`](../check-library.html#l7.webhook_flood.readiness) | Incoming webhook traffic review | `metadata_marker` |
| [`l7.http_pipelining.readiness`](../check-library.html#l7.http_pipelining.readiness) | Multiple requests on one HTTP connection review | `metadata_marker` |
| [`l7.http_range_abuse.readiness`](../check-library.html#l7.http_range_abuse.readiness) | Partial-file request limits review | `metadata_marker` |
| [`l7.conditional_revalidation.readiness`](../check-library.html#l7.conditional_revalidation.readiness) | Cache revalidation workload review | `metadata_marker` |
| [`l7.captcha_challenge_abuse.readiness`](../check-library.html#l7.captcha_challenge_abuse.readiness) | Browser challenge abuse review | `metadata_marker` |
| [`l7.mqtt_broker_exposure.readiness`](../check-library.html#l7.mqtt_broker_exposure.readiness) | MQTT messaging service access review | `metadata_marker` |
| [`l7.redos.readiness`](../check-library.html#l7.redos.readiness) | Regular-expression processing limits review | `metadata_marker` |
| [`l7.graphql_batch_abuse.validation`](../check-library.html#l7.graphql_batch_abuse.validation) | GraphQL route headers for a batch-limit review | `graphql_posture_probe` |
| [`tls.handshake_rate.readiness`](../check-library.html#tls.handshake_rate.readiness) | Encrypted connection setup load review | `metadata_marker` |
| [`tls.renegotiation.readiness`](../check-library.html#tls.renegotiation.readiness) | Client-requested TLS renegotiation | `tls_session` |
| [`tls.zero_rtt.readiness`](../check-library.html#tls.zero_rtt.readiness) | Early encrypted-request replay review | `metadata_marker` |
| [`tls.ocsp_stapling.readiness`](../check-library.html#tls.ocsp_stapling.readiness) | Certificate information for a revocation-status review | `tls_audit` |
| [`l7.http2_rapid_reset.validation`](../check-library.html#l7.http2_rapid_reset.validation) | HTTP/2 response to one canceled request | `http2_frame_probe` |
| [`l7.http2_made_you_reset.readiness`](../check-library.html#l7.http2_made_you_reset.readiness) | HTTP/2 cancellation behavior sample | `http2_frame_probe` |
| [`l7.http2_continuation.readiness`](../check-library.html#l7.http2_continuation.readiness) | HTTP/2 advertised header limits | `http2_frame_probe` |
| [`l7.http2_priority_abuse.readiness`](../check-library.html#l7.http2_priority_abuse.readiness) | HTTP/2 request-priority handling review | `metadata_marker` |
| [`l7.hpack_bomb.readiness`](../check-library.html#l7.hpack_bomb.readiness) | HTTP/2 header-compression settings | `http2_frame_probe` |
| [`l7.http2_push_promise.readiness`](../check-library.html#l7.http2_push_promise.readiness) | HTTP/2 server-push handling review | `metadata_marker` |
| [`l7.qpack_bomb.readiness`](../check-library.html#l7.qpack_bomb.readiness) | HTTP/3 header-compression limits review | `metadata_marker` |
| [`protocol.sse_stream.readiness`](../check-library.html#protocol.sse_stream.readiness) | Long-running event-stream controls review | `metadata_marker` |
| [`protocol.http3_control_stream.readiness`](../check-library.html#protocol.http3_control_stream.readiness) | HTTP/3 announcement for a control-stream review | `http3_control_probe` |
| [`protocol.websocket_message_rate.readiness`](../check-library.html#protocol.websocket_message_rate.readiness) | WebSocket message limits review | `metadata_marker` |
| [`origin.cdn_bypass.readiness`](../check-library.html#origin.cdn_bypass.readiness) | Public clues to routes outside the CDN | `origin_leak_scan` |
| [`origin.dns_hostname_bypass.readiness`](../check-library.html#origin.dns_hostname_bypass.readiness) | Alternate DNS names for the server | `origin_leak_scan` |
| [`pattern.carpet_bombing.readiness`](../check-library.html#pattern.carpet_bombing.readiness) | Traffic spread across many addresses review | `metadata_marker` |
| [`pattern.pulse_wave.readiness`](../check-library.html#pattern.pulse_wave.readiness) | Repeated traffic-burst response review | `metadata_marker` |
| [`pattern.spoofed_source.readiness`](../check-library.html#pattern.spoofed_source.readiness) | Forged source-address protection review | `metadata_marker` |
| [`pattern.ransom_ddos.readiness`](../check-library.html#pattern.ransom_ddos.readiness) | DDoS extortion response review | `metadata_marker` |
| [`pattern.rate_limit_evasion.readiness`](../check-library.html#pattern.rate_limit_evasion.readiness) | Request limits across changing clients review | `metadata_marker` |
| [`pattern.adaptive_evasion.readiness`](../check-library.html#pattern.adaptive_evasion.readiness) | Changing attack-pattern response review | `metadata_marker` |
| [`pattern.residential_proxy.readiness`](../check-library.html#pattern.residential_proxy.readiness) | Abuse through household internet addresses review | `metadata_marker` |
| [`ops.autoscaling_cost.readiness`](../check-library.html#ops.autoscaling_cost.readiness) | Unexpected infrastructure growth and cost review | `metadata_marker` |
| [`ops.attack_alert_coverage.readiness`](../check-library.html#ops.attack_alert_coverage.readiness) | Attack monitoring and alert ownership review | `metadata_marker` |
| [`reflect.slp_amplification_exposure.safe`](../check-library.html#reflect.slp_amplification_exposure.safe) | Public service-location discovery | `reflection_service_probe` |
| [`reflect.tp240_amplification_exposure.safe`](../check-library.html#reflect.tp240_amplification_exposure.safe) | Public TP240 device-status reply | `reflection_service_probe` |
| [`reflect.l2tp_reflection_exposure.safe`](../check-library.html#reflect.l2tp_reflection_exposure.safe) | Public L2TP tunnel-setup reply | `reflection_service_probe` |
| [`reflect.natpmp_amplification_exposure.safe`](../check-library.html#reflect.natpmp_amplification_exposure.safe) | Public router address-discovery reply | `reflection_service_probe` |
| [`reflect.ipp_callback_exposure.safe`](../check-library.html#reflect.ipp_callback_exposure.safe) | Printer-service query availability | `reflection_service_probe` |
| [`dns.multi_question_oversized.safe`](../check-library.html#dns.multi_question_oversized.safe) | DNS nameserver query over TCP | `dns_wire_query` |
| [`waf.http_method_policy_marker.safe`](../check-library.html#waf.http_method_policy_marker.safe) | Response to an HTTP-method test label | `waf_class_marker_probe` |
| [`waf.request_smuggling_marker.safe`](../check-library.html#waf.request_smuggling_marker.safe) | Response to a request-framing test label | `waf_class_marker_probe` |
| [`waf.crlf_injection_marker.safe`](../check-library.html#waf.crlf_injection_marker.safe) | Response to a line-break test label | `waf_class_marker_probe` |
| [`waf.open_redirect_marker.safe`](../check-library.html#waf.open_redirect_marker.safe) | Response to a redirect-rule test label | `waf_class_marker_probe` |
| [`waf.nosql_injection_marker.safe`](../check-library.html#waf.nosql_injection_marker.safe) | Response to a document-database test label | `waf_class_marker_probe` |
| [`waf.xpath_injection_marker.safe`](../check-library.html#waf.xpath_injection_marker.safe) | Response to an XML-query test label | `waf_class_marker_probe` |
| [`waf.jndi_ldap_marker.safe`](../check-library.html#waf.jndi_ldap_marker.safe) | Response to a directory-lookup test label | `waf_class_marker_probe` |
| [`waf.csv_formula_marker.safe`](../check-library.html#waf.csv_formula_marker.safe) | Response to a spreadsheet-formula test label | `waf_class_marker_probe` |
| [`waf.prototype_pollution_marker.safe`](../check-library.html#waf.prototype_pollution_marker.safe) | Response to a JavaScript object-change test label | `waf_class_marker_probe` |
| [`waf.deserialization_marker.safe`](../check-library.html#waf.deserialization_marker.safe) | Response to a stored-object test label | `waf_class_marker_probe` |
| [`waf.ssrf_marker.safe`](../check-library.html#waf.ssrf_marker.safe) | Response to a server-fetch test label | `waf_class_marker_probe` |
| [`waf.xxe_marker.safe`](../check-library.html#waf.xxe_marker.safe) | Response to an XML external-file test label | `waf_class_marker_probe` |
| [`waf.file_upload_marker.safe`](../check-library.html#waf.file_upload_marker.safe) | Response to an upload-filename test label | `waf_class_marker_probe` |
| [`waf.jwt_tamper_marker.safe`](../check-library.html#waf.jwt_tamper_marker.safe) | Response to a sign-in-token test label | `waf_class_marker_probe` |
| [`waf.entry_path_login_marker.safe`](../check-library.html#waf.entry_path_login_marker.safe) | Firewall checks on your declared login URL | `waf_class_marker_probe` |
| [`waf.entry_path_api_marker.safe`](../check-library.html#waf.entry_path_api_marker.safe) | Firewall checks on your declared API URL | `waf_class_marker_probe` |
| [`waf.evasion_unicode_normalization.safe`](../check-library.html#waf.evasion_unicode_normalization.safe) | Firewall handling of wide Unicode characters | `waf_evasion_marker_probe` |
| [`waf.evasion_homoglyph.safe`](../check-library.html#waf.evasion_homoglyph.safe) | Firewall response to look-alike letters | `waf_evasion_marker_probe` |
| [`waf.evasion_overlong_utf8.safe`](../check-library.html#waf.evasion_overlong_utf8.safe) | Firewall handling of invalid text encoding | `waf_evasion_marker_probe` |
| [`waf.evasion_alt_charset.safe`](../check-library.html#waf.evasion_alt_charset.safe) | Alternative text-encoding test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_html_entity.safe`](../check-library.html#waf.evasion_html_entity.safe) | Firewall handling of HTML-encoded text | `waf_evasion_marker_probe` |
| [`waf.evasion_js_escape.safe`](../check-library.html#waf.evasion_js_escape.safe) | Firewall handling of JavaScript-style escapes | `waf_evasion_marker_probe` |
| [`waf.evasion_json_unicode_escape.safe`](../check-library.html#waf.evasion_json_unicode_escape.safe) | JSON character-escape test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_css_escape.safe`](../check-library.html#waf.evasion_css_escape.safe) | Firewall handling of stylesheet-style escapes | `waf_evasion_marker_probe` |
| [`waf.evasion_base64_wrap.safe`](../check-library.html#waf.evasion_base64_wrap.safe) | Firewall response to Base64-encoded text | `waf_evasion_marker_probe` |
| [`waf.evasion_numeric_repr.safe`](../check-library.html#waf.evasion_numeric_repr.safe) | Firewall response to characters written as numbers | `waf_evasion_marker_probe` |
| [`waf.evasion_whitespace.safe`](../check-library.html#waf.evasion_whitespace.safe) | Firewall handling of changed spacing | `waf_evasion_marker_probe` |
| [`waf.evasion_lexical_operator.safe`](../check-library.html#waf.evasion_lexical_operator.safe) | Database operator-variation test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_lexical_tautology.safe`](../check-library.html#waf.evasion_lexical_tautology.safe) | Database condition-variation test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_lexical_literal.safe`](../check-library.html#waf.evasion_lexical_literal.safe) | Database text-value variation test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_control_char.safe`](../check-library.html#waf.evasion_control_char.safe) | Firewall handling of an encoded null character | `waf_evasion_marker_probe` |
| [`waf.evasion_path_matrix.safe`](../check-library.html#waf.evasion_path_matrix.safe) | Path-parameter test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_path_suffix.safe`](../check-library.html#waf.evasion_path_suffix.safe) | Extra path-suffix test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_ip_representation.safe`](../check-library.html#waf.evasion_ip_representation.safe) | Alternative IP-address notation test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_parser_hpp.safe`](../check-library.html#waf.evasion_parser_hpp.safe) | Firewall handling of a repeated URL parameter | `waf_evasion_marker_probe` |
| [`waf.evasion_parser_json_dup.safe`](../check-library.html#waf.evasion_parser_json_dup.safe) | Repeated JSON-field test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_parser_header_dup.safe`](../check-library.html#waf.evasion_parser_header_dup.safe) | Repeated-header test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_framing_cl_te.safe`](../check-library.html#waf.evasion_framing_cl_te.safe) | Conflicting request-length test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_framing_transfer_coding.safe`](../check-library.html#waf.evasion_framing_transfer_coding.safe) | Unusual transfer-format test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_framing_h2_h1.safe`](../check-library.html#waf.evasion_framing_h2_h1.safe) | HTTP/2 to HTTP/1 translation test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_framing_line_ending.safe`](../check-library.html#waf.evasion_framing_line_ending.safe) | Nonstandard HTTP line-ending test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_framing_chunk_ext.safe`](../check-library.html#waf.evasion_framing_chunk_ext.safe) | Chunked-request extension test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_body_gzip.safe`](../check-library.html#waf.evasion_body_gzip.safe) | Compressed request-body test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_body_nested_encoding.safe`](../check-library.html#waf.evasion_body_nested_encoding.safe) | Multiply compressed body test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_content_type_binary.safe`](../check-library.html#waf.evasion_content_type_binary.safe) | Binary-labeled request-body test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_struct_type_confusion.safe`](../check-library.html#waf.evasion_struct_type_confusion.safe) | Changed JSON value-type test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_struct_deep_nesting.safe`](../check-library.html#waf.evasion_struct_deep_nesting.safe) | Nested JSON inspection test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_parameter_location.safe`](../check-library.html#waf.evasion_parameter_location.safe) | Firewall comparison of URL and cookie input | `waf_evasion_marker_probe` |
| [`waf.evasion_method_override.safe`](../check-library.html#waf.evasion_method_override.safe) | HTTP method-override test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_protocol_version.safe`](../check-library.html#waf.evasion_protocol_version.safe) | HTTP-version comparison availability | `waf_evasion_marker_probe` |
| [`waf.evasion_protocol_upgrade.safe`](../check-library.html#waf.evasion_protocol_upgrade.safe) | Protocol-upgrade inspection test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_benign_padding.safe`](../check-library.html#waf.evasion_benign_padding.safe) | Firewall inspection after extra leading text | `waf_evasion_marker_probe` |
| [`waf.evasion_polyglot_content.safe`](../check-library.html#waf.evasion_polyglot_content.safe) | Multiple-format content test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_protocol_h3_h1.safe`](../check-library.html#waf.evasion_protocol_h3_h1.safe) | HTTP/3 to HTTP/1 translation test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_protocol_qpack_hpack.safe`](../check-library.html#waf.evasion_protocol_qpack_hpack.safe) | HTTP header-compression translation test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_multipart_charset.safe`](../check-library.html#waf.evasion_multipart_charset.safe) | Uploaded-field character-set test availability | `waf_evasion_marker_probe` |
| [`waf.evasion_xml_attribute.safe`](../check-library.html#waf.evasion_xml_attribute.safe) | XML attribute inspection test availability | `waf_evasion_marker_probe` |
| [`waf.inspection_limit.safe`](../check-library.html#waf.inspection_limit.safe) | Request-body inspection test availability | `waf_inspection_limit_probe` |
| [`waf.evasion_cache_key_mismatch.posture`](../check-library.html#waf.evasion_cache_key_mismatch.posture) | Cache and firewall URL interpretation review | `metadata_marker` |
| [`waf.evasion_reassembly_differential.posture`](../check-library.html#waf.evasion_reassembly_differential.posture) | Split-request interpretation review | `metadata_marker` |
| [`waf.evasion_rule_gap.posture`](../check-library.html#waf.evasion_rule_gap.posture) | New and uncovered web-threat response review | `metadata_marker` |
| [`waf.evasion_second_order.posture`](../check-library.html#waf.evasion_second_order.posture) | Stored-input processing review | `metadata_marker` |
| [`waf.evasion_encrypted_payload.posture`](../check-library.html#waf.evasion_encrypted_payload.posture) | Application-encrypted request inspection review | `metadata_marker` |
| [`waf.evasion_signed_structured_data.posture`](../check-library.html#waf.evasion_signed_structured_data.posture) | Signed data validation review | `metadata_marker` |
| [`waf.evasion_connection_coalescing.posture`](../check-library.html#waf.evasion_connection_coalescing.posture) | Shared connection website-identity review | `metadata_marker` |
| [`waf.evasion_ech_routing_metadata.posture`](../check-library.html#waf.evasion_ech_routing_metadata.posture) | Encrypted website-name routing review | `metadata_marker` |
| [`l7.compressed_request_decompression.posture`](../check-library.html#l7.compressed_request_decompression.posture) | Compressed-body processing test availability | `l7_resource_posture_probe` |
| [`l7.request_parser_size.posture`](../check-library.html#l7.request_parser_size.posture) | Response to a longer URL parameter | `l7_resource_posture_probe` |
| [`waf.http_routing_trust.posture`](../check-library.html#waf.http_routing_trust.posture) | Proxy-supplied routing information review | `metadata_marker` |
| [`waf.jsonp_css_policy.posture`](../check-library.html#waf.jsonp_css_policy.posture) | Script callback and stylesheet input review | `metadata_marker` |
| [`waf.sqli_managed_marker.safe`](../check-library.html#waf.sqli_managed_marker.safe) | Firewall blocking of database-like test text | `waf_class_marker_probe` |
| [`waf.xss_managed_marker.safe`](../check-library.html#waf.xss_managed_marker.safe) | Firewall blocking of HTML-like test text | `waf_class_marker_probe` |
| [`waf.path_traversal_managed_marker.safe`](../check-library.html#waf.path_traversal_managed_marker.safe) | Firewall blocking of parent-folder test paths | `waf_class_marker_probe` |
| [`waf.ssti_marker.safe`](../check-library.html#waf.ssti_marker.safe) | Response to a page-template test label | `waf_class_marker_probe` |
| [`waf.scanner_signature_marker.safe`](../check-library.html#waf.scanner_signature_marker.safe) | Firewall response to a scanner's browser label | `waf_class_marker_probe` |
| [`waf.evasion_double_url.safe`](../check-library.html#waf.evasion_double_url.safe) | Firewall handling of twice-encoded URL text | `waf_evasion_marker_probe` |
| [`waf.evasion_mixed_url.safe`](../check-library.html#waf.evasion_mixed_url.safe) | Firewall handling of partly encoded URL text | `waf_evasion_marker_probe` |
| [`waf.evasion_case_fold.safe`](../check-library.html#waf.evasion_case_fold.safe) | Firewall handling of changed letter case | `waf_evasion_marker_probe` |
| [`waf.http_method_policy_enforced.safe`](../check-library.html#waf.http_method_policy_enforced.safe) | Actual HTTP request-method enforcement | `waf_method_policy_probe` |
| [`waf.rate_limit_canary.validation`](../check-library.html#waf.rate_limit_canary.validation) | Request limiting on your dedicated test URL | `rate_limit_canary_probe` |
| [`waf.body_json_marker.soc`](../check-library.html#waf.body_json_marker.soc) | Plan a firewall test for JSON request data | `reviewed_request_only` |
| [`waf.body_form_marker.soc`](../check-library.html#waf.body_form_marker.soc) | Plan a firewall test for form submissions | `reviewed_request_only` |
| [`waf.body_multipart_marker.soc`](../check-library.html#waf.body_multipart_marker.soc) | Plan a firewall test for uploaded form data | `reviewed_request_only` |
| [`waf.body_inspection_limit.soc`](../check-library.html#waf.body_inspection_limit.soc) | Plan a request-body inspection limit test | `reviewed_request_only` |
| [`waf.response_dlp_canary.soc`](../check-library.html#waf.response_dlp_canary.soc) | Plan a test for sensitive-data filtering | `reviewed_request_only` |
| [`nfw.declared_deny_tcp.safe`](../check-library.html#nfw.declared_deny_tcp.safe) | TCP connection against your network deny policy | `tcp_connect` |
| [`nfw.declared_deny_udp.safe`](../check-library.html#nfw.declared_deny_udp.safe) | UDP reply against your network deny policy | `udp_probe` |
| [`nfw.management_port_exposure.safe`](../check-library.html#nfw.management_port_exposure.safe) | Public administration and database connections | `port_scan_bounded` |
| [`nfw.ipv6_parity.safe`](../check-library.html#nfw.ipv6_parity.safe) | Compare IPv4 and IPv6 connection access | `tcp_connect` |
| [`nfw.connection_limit.safe`](../check-library.html#nfw.connection_limit.safe) | Sample your declared connection limit | `connection_limit_probe` |
| [`nfw.origin_lockdown.safe`](../check-library.html#nfw.origin_lockdown.safe) | Direct access to your approved origin server | `host_sni_bypass` |
| [`nfw.perspective_allowlist.safe`](../check-library.html#nfw.perspective_allowlist.safe) | Connection from the selected probe location | `tcp_connect` |
| [`origin.identity_pair.head.v1`](../check-library.html#origin.identity_pair.head.v1) | Compare website and direct-server headers | `origin_identity_pair` |
| [`origin.identity_pair.get.v1`](../check-library.html#origin.identity_pair.get.v1) | Compare website and direct-server page samples | `origin_identity_pair` |
