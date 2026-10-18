# Current audit catalog acceptance index

## Origin identity delta 2026-10-16

The current runtime has **275 definitions / 45 profile kinds** after adding `origin.identity_pair.head.v1` and `origin.identity_pair.get.v1` (`origin_identity_pair`, executor `probeOriginIdentityPair`). Both require the separately reviewed one-origin comparison workflow and current ownership proofs for both endpoints. Default unreviewed execution is refused with `origin_identity_review_required`; two bounded HEAD/GET legs can record application identity but never a protected/readiness/capacity or particular-WAF-rule conclusion. See [ADR-0032](../adr/0032-origin-associations-and-paired-identity.md) and [origin exposure](../detection/24-origin-exposure.md).

The presentation registry and executable inventory include the two IDs. The preserved 2026-10-15 per-ID table, numerical summaries and source-bound captures below describe the prior 273-definition snapshot; they are **not current acceptance receipts** for the changed source or these two reviewed-only definitions. Fresh strict capture/reconciliation and live acceptance remain separate. Local reviewed start/grant/worker/ingest/finalize tests are recorded in `PROGRESS.md`.

## Runtime audit 2026-10-15 (preserved snapshot)

This section supersedes the preserved 2026-10-09 index below. It maps all **273 current runtime IDs** without inferring execution from a mapping. Runtime source: `CHECK_CATALOG`; executable audit mapping and receipt accounting: `tests/fixtures/check-delivery-coverage.mjs`; presentation: `src/lib/checkPresentation.mjs` (outside execution digests). No live/customer traffic, stopped producers or migration 0079 were enabled.

### Counts and acceptance boundaries

- 273 definitions, 721 vector mappings, 165 default FQDN-safe IDs, 44 allowed profile kinds, 264 distinct full delivery fingerprints. Definitions, aliases, mechanisms, verdicts, vector mappings and independently tested defenses are not interchangeable.
- Default dispositions: `additional_target_input` 14; `supported_observation` 107; `additional_signed_scope` 1; `governance_inline` 2; `supported_semantic_safe` 24; `soc_request_only` 22; `declaration_only` 72; `unsupported_delivery` 31. Setup-dependent admission refusals are not intrinsic protocol incapability.
- The separate 721-row default-FQDN vector matrix has 364 safe-runnable rows, 10 requiring input, 254 SOC-gated, 49 monitor-only and 44 not runnable. Its capability classes are 46 semantic-safe, 270 transport-only, 102 declaration-only, 254 SOC-governed and 49 monitor-only. These mapping counts are not unique check counts or independently proven defenses. Passive evidence exports use artifact schema 4 / generator v3; old schemas/captured inputs are not relabeled.
- Full deterministic definition invocation and exact refusal assertions exercise all 273 IDs through existing owned fixtures. Inventory rows themselves are not assertion receipts.
- Fresh source-bound delivery-only reconciliation establishes **273/273 definitions, 509/524 branches and 15 remaining gaps, with zero invalid receipts** (`/tmp/astranull-fault-delivery-final-v2.delivery-report.json`). The preceding checkpoint was 112/524 with 412 gaps; 397 additional obligations now have accepted proof. All 524 original identities remain fixed. The child passes 821/821 with zero failures/skips; the recorder exits 0 with 782 validated envelopes (491 native branches, 18 TCP branches, 273 definitions). Source digest: `d19cf92d5143da217f49aeaf77b7e52ac94294af8152c266702df482fa6ea839`. Strict reconciliation correctly exits 1/incomplete for the 15 gaps; no full-catalog certification is claimed. The independent in-memory omission mutation exposes exactly one additional gap (508 branches/16 gaps) without changing retained artifacts. Separate regressions and passing limitation assertions are not branch receipts. The codec/causal-validator gate passes 365/365, zero failures/skips; fresh full npm verification passes 8051/8051 first-stage and 959/959 integration tests, zero failures/cancellations/skips (`/tmp/astranull-fault-npm-final-v2.log`). Serial Make verification is running, with remaining static/isolated-scale gates pending. The remaining-gap assessment changes no source or policy dispositions. See the [fault-expansion ledger](verified-capability-audit-remediation.md#tracked-catalog-fault-case-expansion-2026-10-15).
- Class/entry-path/scanner comparison v5 separates planned/attempted/completed/graded/ungraded/missing legs. Received unsigned placements are ungraded, not missing. An abort cannot shrink the planned denominator. Conclusions cover only graded placements and budget-selected paths; healthy controls and at least one graded leg remain required. Method/evasion retain v4 comparison contracts. Global WAF grading is v3. Historical rows/digests are not regraded.
- Custom opaque tokens lack exact installed-rule setup in current typed declarations: observation only, no installed-rule failure finding, no readiness credit. Actual-method E2 is separately verdict-capable but never readiness-eligible. E2 does not universally mean no finding (e.g. direct protocol/declared-policy violations).

### Per-ID execution/evaluator index

Conclusions below describe the current default disposition, not universal target applicability. Required declared data can enable violation-only evaluation after normal admission. Governance declarations are never network protection credit. `readiness-kind eligible` does not mean any run passed. Full version, digest, parameters, caps and evidence are repeated below rather than inferred from labels.

| Check ID | Short presentation name | Derived version / definition SHA-256 | Kind / executor | Default disposition | Actual bounded mechanism | Specialized evaluator / override | Default conclusions / readiness |
|---|---|---|---|---|---|---|---|
| `origin.direct_reachability.safe` | Direct Origin Reachability | `1.2.1` / `50e75a8e26d67fd51fb841e37195cdd731ae692d15f7c86332b202399dbc2bd6` | `host_sni_bypass` / `probeHostSniBypass` | `additional_target_input`: `missing_target_bound_direct_address` | One declared-address HTTP Host/SNI observation | correlateOriginLockdownVerdict; none | inconclusive; readiness-kind excluded |
| `origin.direct_bypass.safe` | Declared-origin response | `1.2.1` / `39d2f44fc3b03e37ae19ed130f040c12e21e1c08e2ad39ad182c9f3df2263d23` | `host_sni_bypass` / `probeHostSniBypass` | `additional_target_input`: `missing_target_bound_direct_address` | One declared-address HTTP Host/SNI observation | correlateOriginLockdownVerdict; none | inconclusive; readiness-kind excluded |
| `origin.host_sni_bypass.safe` | Declared Host/SNI response | `1.2.1` / `9e5b986f81dac9c6f21269cbae3177b5f38a3b8021bd7666071c47d4f2464f37` | `host_sni_bypass` / `probeHostSniBypass` | `additional_target_input`: `missing_target_bound_direct_address` | One declared-address HTTP Host/SNI observation | correlateOriginLockdownVerdict; none | inconclusive; readiness-kind excluded |
| `origin.leak_scan.safe` | Origin Leak Scan | `1.0.1` / `bd9fef4bb179361f62ca650c9d5f0b1c6ec2cc0a9960af11dd17f4c4362e24f7` | `origin_leak_scan` / `probeOriginLeakScan` | `supported_observation` | Bounded declared-host DNS and HTTP observations | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l3.firewall_exposure_scan.safe` | Firewall Exposure Scan | `1.1.1` / `5fc096db9839949fc63ecfa95860c3e69ddec9ff629b3e56f5d72d9aecb31b75` | `port_scan_bounded` / `probePortScanBounded` | `supported_observation` | Bounded TCP connects to catalogued or declared ports | nfwPortResults → correlateNfwViolation; none | exposed, inconclusive; readiness-kind excluded |
| `path.protected_canary.safe` | Canary HTTP response | `1.0.1` / `501a724d6c5a6662d6dfd384ea7cc0601192c72f4aa6b2b590b0587ea2d68c0e` | `http_head` / `probeHttpHead` | `supported_observation` | One HTTP HEAD response observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l3.forbidden_tcp_port.safe` | Forbidden TCP Port | `1.1.0` / `6eace424711931cbd2b5a86dbea8bfa7c3dd959b4cec4a46a07297da3a24c1db` | `tcp_connect` / `probeTcpConnect` | `additional_target_input`: `port_or_declared_deny_required` | Bounded TCP connection samples | correlateNfwViolation; none | inconclusive; readiness-kind excluded |
| `l3.forbidden_udp_port.safe` | Forbidden UDP Port | `1.0.1` / `204a211bf10f6c8f5aacd86615ee4cc7d0f264ec9f2766646e75259eaaea2bcb` | `udp_probe` / `probeUdpDatagram` | `additional_target_input`: `port_or_declared_deny_required` | Bounded UDP service samples | correlateNfwViolation; none | inconclusive; readiness-kind excluded |
| `l3.basic_deny_rule.safe` | Basic Deny-Rule Validation | `1.1.0` / `aff857f3eced0fb52cdc3eaaef113f4fa578d71f31d1130e88b888db196d68f8` | `tcp_connect` / `probeTcpConnect` | `additional_target_input`: `port_or_declared_deny_required` | Bounded TCP connection samples | correlateNfwViolation; none | inconclusive; readiness-kind excluded |
| `dns.authoritative_response.safe` | DNS Authoritative Response | `1.0.1` / `84ce00d1ef38373a935b0be9ab3f7cb033fb3ed3ffb1cae3b9517e39de1777c3` | `dns_wire_query` / `probeDnsWireQuery` | `supported_observation` | Bounded DNS wire query | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `dns.random_prefix_nxdomain.safe` | DNS Random-Prefix / NXDOMAIN | `1.0.1` / `159de6c97ab367a8e2d7403a4b1816b482c03db7b66d9fb53bb57bab8fdae874` | `dns_wire_query` / `probeDnsWireQuery` | `supported_observation` | Bounded DNS wire query | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `dns.open_recursion_behavior.safe` | Open Recursion Behavior | `1.1.1` / `da617412b346696151e0c8d21b0595c6225e656c0bcb3cc29abacb959b8866ac` | `dns_open_recursion` / `probeOpenRecursion` | `supported_observation` | One query to a declared resolver | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.waf_marker_rule.safe` | WAF token response sample | `1.1.1` / `9e4dbbd312fa61ad1d573a55105c358979a36501bb95d2884f396b468abb6c09` | `waf_enforcement_probe` / `probeWafEnforcement` | `supported_observation` | One inert-marker HTTP response observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.fingerprint.safe` | WAF and CDN Fingerprint | `2.1.1` / `afad13d9c8bac7ec0350f3e5f64b54e75e4159dde60e2ad8c6bcda83c99ab29e` | `waf_fingerprint_observation` / `probeOutsideInWafScan` | `supported_observation` | Ordinary GET with DNS/address/HTTP provider signals | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.marker_rule.safe` | WAF token response posture | `1.1.1` / `c28f9842b0b907c9a656e7d35a33f80efa8545a7fcdf1c57bc0461e48be4c464` | `waf_enforcement_probe` / `probeWafEnforcement` | `supported_observation` | One inert-marker HTTP response observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.origin_bypass.safe` | Declared-origin WAF observation | `1.2.1` / `7044878e738c343a83dda1d111a5fc9b072d722afda22ad96f64a18f349e2e19` | `host_sni_bypass` / `probeHostSniBypass` | `additional_target_input`: `missing_target_bound_direct_address` | One declared-address HTTP Host/SNI observation | correlateOriginLockdownVerdict; none | inconclusive; readiness-kind excluded |
| `waf.low_rate_limit.safe` | Low-rate response sequence | `1.0.1` / `5bd6eddafc55645e4bad35e3f87f617bab4e74097e06213da5fe482a4d224145` | `rate_limit_sequence` / `probeRateLimitSequence` | `supported_observation` | Small fixed HTTP request sequence | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.http_method_restriction.safe` | HTTP method responses | `1.0.1` / `057079ba973730ac1a6c6cebbe5c77c6cf4776c55edfbdb7473c54ffd8c1ca87` | `http_method_matrix` / `probeHttpMethodMatrix` | `supported_observation` | Bounded HTTP method response matrix | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.header_size_boundary.safe` | Header/Size Boundary | `1.0.1` / `d81859209e913be493f5f2ead2414379679c288931644f218e13dcfdf74d65b1` | `header_size_probe` / `probeHeaderSizeBoundary` | `supported_observation` | Bounded HTTP header-size comparison | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.low_rate_rate_limit.safe` | Rate-limit response sample | `1.0.1` / `cfcce585249f3a88704994fb593067bb190789ee7ddf3323005b2923511a4bb0` | `rate_limit_sequence` / `probeRateLimitSequence` | `supported_observation` | Small fixed HTTP request sequence | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `tls.profile_exposure.safe` | TLS Profile Exposure | `1.0.1` / `bb8f37a1a7298dea635262cbd0fbe95d59dc3f787ad95f5a2265d42bc0a271da` | `tls_audit` / `probeTlsAudit` | `supported_observation` | One TLS handshake and certificate/configuration inspection | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `protocol.http2_readiness.safe` | HTTP/2 settings observation | `1.0.1` / `da5af93a8fc464d433d5c480933c5dfc8f56dd6968f762ad190ff9a16165b3f9` | `http2_settings` / `probeHttp2Settings` | `supported_observation` | One HTTP/2 SETTINGS observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `protocol.http3_quic_exposure.safe` | HTTP/3 Alt-Svc Observation | `1.0.1` / `b9f121f03d51e5fa336283e91807c90464d26b46b209446875cd236b9a162cab` | `quic_reachability` / `probeQuicReachability` | `supported_observation` | HTTP Alt-Svc advertisement observation, not a QUIC exchange | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `ops.alert_workflow_marker.safe` | Alert Workflow Webhook Ping | `1.0.1` / `e9fff0edd2a88a499157d60b604e779cc4f3782745041f870c78e05af4e279a0` | `alert_webhook_ping` / `probeAlertWebhookPing` | `additional_signed_scope`: `approved_signed_callback_scope_required` | No callback delivery without separately approved signed scope | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `ops.runbook_contact_validation.safe` | Runbook declaration review | `1.0.0` / `a9ab228f5e8d18500918289cccb7db3af402578121939379c9b8d81798fbe35b` | `ops_readiness` / `evaluateOpsReadiness` | `governance_inline`: `runbook_contacts` | Local operational-declaration evaluation; no target traffic | correlateOpsReadinessVerdict (local declarations); none | protected (local declaration only), inconclusive; readiness-kind excluded |
| `ops.kill_switch_drill.safe` | Stop-readiness declaration review | `1.0.0` / `52bdcb110e640217299a626413a5e342b9b3c5584850bae7f790fddf1bfd07a1` | `ops_readiness` / `evaluateOpsReadiness` | `governance_inline`: `kill_switch_readiness` | Local operational-declaration evaluation; no target traffic | correlateOpsReadinessVerdict (local declarations); none | protected (local declaration only), inconclusive; readiness-kind excluded |
| `l3.ipv6_reachability.safe` | IPv6 Declared Reachability | `1.0.1` / `d410355e98c740c5e886e2d1c0f4b3b3fc153d58fbb8454605850337da530286` | `tcp_connect` / `probeTcpConnect` | `supported_observation` | Bounded TCP connection samples | correlateNfwViolation; none | exposed, inconclusive; readiness-kind excluded |
| `dns.amplification_exposure.safe` | DNS response size sample | `1.0.1` / `5a3ed73857de35cb34b219d380d2a020f29b79e920c0ff6478a39b7289ad57e7` | `dns_wire_query` / `probeDnsWireQuery` | `supported_observation` | Bounded DNS wire query | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `dns.dnssec_expensive_query.safe` | DNSKEY presence | `2.0.1` / `b43d0b6f42f887c84f6fff9d336c4144e04dd1dd6c55b41191f8e63e0a3c77eb` | `dnssec_posture` / `probeDnssecPosture` | `supported_observation` | Bounded DNSKEY observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `dns.secondary_failover.safe` | Secondary DNS observations | `1.0.1` / `8f766bfda13ebd3cd75eacc092bf6d0735d6f774343a1125a7daacb5d221dbac` | `dns_failover_posture` / `probeDnsFailoverPosture` | `supported_observation` | Bounded nameserver/address observations, not a failover drill | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `dns.zone_transfer_exposure.safe` | Zone Transfer Exposure | `1.1.0` / `8494207f437360fbdea27a947a6b1907732edd59f71166e57495c483091ccb8a` | `dns_axfr_leak` / `probeAxfrLeak` | `supported_semantic_safe` | Bounded authorized DNS zone-transfer comparison | correlateAxfrVerdict; none | protected, exposed, inconclusive; readiness-kind eligible only with exact proof |
| `l7.cache_busting.safe` | Cache response comparison | `1.0.1` / `9739e93afd4bff878ea56ffb1cbe02e7c29a9fc569c51ab427e2df7e3789d669` | `cache_abuse_probe` / `probeCacheAbuse` | `supported_observation` | Small HTTP cache-marker comparison | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.expensive_endpoint.safe` | Expensive Endpoint | `1.0.1` / `d7c6dcedccc6a2db0d173c25e7205a4070495c41a9f926552bc4d790960239ee` | `http_head` / `probeHttpHead` | `supported_observation` | One HTTP HEAD response observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.login_abuse_flow.safe` | Login-route response sample | `1.0.1` / `c69212b07c752fe3ef6def73ddcc3bf0b292f1d659d2c6e572d78551e87d452e` | `rate_limit_sequence` / `probeRateLimitSequence` | `supported_observation` | Small fixed HTTP request sequence | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.password_reset.safe` | Reset-route HEAD response | `1.0.1` / `0c26bf0f26187f2cef361689e14ead59588f4fafc346855188e913da7d64bd24` | `http_head` / `probeHttpHead` | `supported_observation` | One HTTP HEAD response observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.api_quota_exhaustion.safe` | API quota response signals | `1.0.1` / `089cb26b7a2f0b2ef30aba574b6605e5cbba28da5f6481b2640675b343f1fbf0` | `rate_limit_sequence` / `probeRateLimitSequence` | `supported_observation` | Small fixed HTTP request sequence | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.graphql_complexity.safe` | GraphQL metadata response | `1.0.1` / `9a7f14ad28af283b48661c6257813cb7d7dd63b15067de093b12940bccf1de00` | `graphql_posture_probe` / `probeGraphqlPosture` | `supported_observation` | Bounded GraphQL metadata observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.bot_challenge_marker.safe` | Bot / Challenge Marker | `1.0.1` / `21eb7858406a1b237f7b4727b32679523bc5880899d31afdfdfb1d4c6d0b0cb1` | `bot_challenge_probe` / `probeBotChallenge` | `supported_observation` | One HTTP challenge observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `tls.slow_header_body_timeout.safe` | Slow-header timeout sample | `1.0.1` / `2a192184f9a35657e1797d3d8f3f3b98b33236ee493e957a407a3c2c6c60b505` | `slow_header_probe` / `probeSlowHeaderTimeout` | `supported_observation` | One bounded slow-header timeout sample | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `tls.idle_connection_timeout.safe` | TLS session sample | `1.0.1` / `59f66e3d06b6045367bdfdf1dc24362ca7429110eb1bea82767ad85c230b9ea7` | `tls_session` / `probeTlsSession` | `supported_observation` | One TLS session observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `protocol.http2_rapid_reset_readiness.safe` | HTTP/2 advertised settings | `1.0.1` / `72d03d839492ce653af1c6074c219dbc59d121672b740002a4bd06700544cac0` | `http2_settings` / `probeHttp2Settings` | `supported_observation` | One HTTP/2 SETTINGS observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `protocol.http2_stream_concurrency.safe` | HTTP/2 advertised stream limits | `1.0.1` / `d9ee4b0f7783209dd79f0a91a8b079db6eba4f311d96b17ba5ba308fa5e8403c` | `http2_settings` / `probeHttp2Settings` | `supported_observation` | One HTTP/2 SETTINGS observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `protocol.grpc_reflection_stream.safe` | gRPC reflection response | `1.1.1` / `0ef6ed6b32d2b1efcedb1a2dd8082ce8ef6d3019b90a1f36c7d19efa17bd2b15` | `grpc_reflection_probe` / `probeGrpcReflection` | `supported_observation` | One bounded gRPC reflection response observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `protocol.websocket_connection_controls.safe` | WebSocket upgrade response | `1.0.1` / `c0eaa3f74f797fec4f3b5f0899bc5b1246e86f6c5020f8d919bf237c9ae51723` | `websocket_upgrade_posture` / `probeWebsocketUpgradePosture` | `supported_observation` | One WebSocket upgrade response observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `tls.full_audit.safe` | TLS certificate and settings | `1.0.1` / `422ad61deec48295cc1053b053fda74009b24d54da62d348b3121042879f33a8` | `tls_audit` / `probeTlsAudit` | `supported_observation` | One TLS handshake and certificate/configuration inspection | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.api_surface_scan.safe` | API Surface Scan | `1.0.1` / `44cb3401be7268ca22bf55a92c2fb7fce3a7bd312e0ac83f0e271690778c42f2` | `api_surface_scan` / `probeApiSurfaceScan` | `supported_observation` | Bounded catalogue-path HTTP observations | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.cors_posture.safe` | CORS Posture | `1.0.1` / `05572390531b25e9422343b95ea13d6a3cc007ff7e40764ca657a2df681af80c` | `cors_posture_probe` / `probeCorsPosture` | `supported_observation` | One CORS response-header observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.enforcement.safe` | WAF token response | `1.1.1` / `a436c91141facbc1d7607c889b25cd16e348613aae1c12f942eae6958bb194d6` | `waf_enforcement_probe` / `probeWafEnforcement` | `supported_observation` | One inert-marker HTTP response observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l3.connection_table_exhaustion.request_only` | Connection Table Exhaustion request | `1.0.0` / `bb41b8f4c39588dad0444fb9c26d0a04c1d9d8eaf933990a36a08ae15f1aa981` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `high_scale.dns_high_query.request_only` | DNS High-Query review request | `1.0.0` / `22d64f55baa6cdfd0c74376e9dc171aee6d2d847c705bef243185b9b012fbcd2` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `ops.runbook_contact_validation.request_only` | Runbook / Emergency Contact Validation request | `1.0.0` / `0124675e7356de674aa14f94ccaf62ad3b89035182a6e118806b589aa89c7161` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `ops.kill_switch_drill.request_only` | Kill Switch Drill request | `1.0.0` / `d355d7c53f74c818480e966ca91c0e12df4405220ec6ad3fef10e73cf5c40160` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `ops.provider_telemetry.request_only` | Provider Telemetry Validation request | `1.0.0` / `c167c339f11d53e7e0e8f3c30a728a3c76b685a6ab46fbb04c93b4e43b0313e5` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `high_scale.multi_vector.request_only` | Multi-Vector review request | `1.0.0` / `c7af3467a5add47faa249803ac9531e0f523d86f709dc4a8dda7847acb215699` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `high_scale.degradation_recovery.request_only` | Degradation / Recovery Drill request | `1.0.0` / `27bb3d01ef5e4fd1f028af38d8b5d326944afb8508c42e410258dedba7cd4a1a` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `high_scale.volumetric.request_only` | Volumetric L3/L4 request | `1.0.0` / `29e11209d1f2f1806059275fce446ae533f5584f962fe9f84742ce204a88a763` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.offensive_sqli.soc` | WAF SQLi review request | `1.0.0` / `37b3eba96a45b0dd286c066a5ec8d2e501ab661a717de47bc54553356bad214e` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.offensive_xss.soc` | WAF XSS review request | `1.0.0` / `995e2e1ea04bb33d1a156ded8e0223b9c6576b54800b2d5fcc97781d8e963ee0` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.offensive_rce.soc` | WAF RCE review request | `1.0.0` / `620405c9f02b1ed5f9789b8ed60db1be9ad59fb656c3ede6cc67ef4ffd951455` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.offensive_path_traversal.soc` | WAF Path Traversal review request | `1.0.0` / `1109dd271a859c3e0bb55b1037ead7084673836c7425804e367798e526ea2568` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.offensive_command_injection.soc` | WAF Command Injection review request | `1.0.0` / `8cc890bd7d98897af3199f2d68d1f29270f6df1ac55f31d8a0e1a4d8e0de4a6d` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.offensive_ldap_injection.soc` | WAF LDAP Injection review request | `1.0.0` / `b4bce68fe3ab71e55b83aacbf66040ccdfdbd6e0f1dd733902e9407f5ee5e439` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.offensive_ssti.soc` | WAF SSTI review request | `1.0.0` / `30f7c56d1a39ef758dd5b916dd2faa659907ad7956f7d156e35e093b3afa2d5b` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.offensive_combined.soc` | WAF Combined review request | `1.0.0` / `4ef88efee94671df87b58d690db95e2db6d24c372c4474290f35803f9db7c55a` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `high_scale.application.request_only` | Application-Layer High-Scale request | `1.0.0` / `0bcfeffa592ab76bfed06f2c7f885cbba4ea16c7fd9076bfcb384226cb1c5a5b` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l3.icmp_flood.readiness` | ICMP Flood declaration | `1.0.0` / `aff5b084185b6660feb55d9a272bbfe0c04b20a9913612334e40d9cdc279001a` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l3.gre_esp_flood.readiness` | GRE / ESP Tunnel Flood declaration | `1.0.0` / `001b8c59dd73b2bf092d479ae966cd5a61c9f3266a9ddf47eb684e7a6c8e8edf` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l3.ipv6_volumetric.readiness` | IPv6 Volumetric declaration | `1.0.0` / `a2428f9594b3d95829ba954cb668b1881564595c6d9031577ec1933e633c6b75` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l3.sip_voip_flood.readiness` | SIP-port UDP response sample | `1.0.1` / `f006bf5fb4c4608862f1d905a5c5d0bcbfaf6f0a5bd4c1026c0af87a6a36f786` | `udp_probe` / `probeUdpDatagram` | `supported_observation` | Bounded UDP service samples | correlateNfwViolation; none | exposed, inconclusive; readiness-kind excluded |
| `l3.sctp_exposure.readiness` | SCTP Exposure declaration | `1.0.0` / `a87da9505d93cb53313d9b6583276718764772254fdf0a5dc1c1c6d976e10e27` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l3.multicast_broadcast_storm.readiness` | Multicast / Broadcast Storm declaration | `1.0.0` / `ddc66d9ab772bb8bf54d3c6f646eec266adb9898a8e3a1b80bac53c6b2ec8a96` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l3.ack_flood.readiness` | ACK Flood declaration | `1.0.0` / `bce5d77e81f8968d3ac0ff1b5df419497fa2d33b1e5d7a81eb4500ecafbc46b4` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l3.rst_flood.readiness` | RST Flood declaration | `1.0.0` / `5511dd1c2007b445a374d3df3f7111ab805f8bb0fd2953576ffb93434b6a788f` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l3.syn_ack_flood.readiness` | SYN-ACK Flood declaration | `1.0.0` / `05f2e2bc7a874763fb8e40bfcc929dbcb5d2219c63de4ef6ea172a0e96d06ab5` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l3.tcp_flag_anomaly.readiness` | TCP flag test unavailable | `1.0.1` / `3f3dad9e5feadac5b58f071dbc3a7fb0bfe7c209033fe25831346e80befb58c9` | `tcp_connect` / `probeTcpConnect` | `additional_target_input`: `port_required` | Bounded TCP connection samples after explicit target setup | correlateNfwViolation; none | inconclusive; readiness-kind excluded |
| `l3.out_of_state_tcp.readiness` | Out-of-State TCP Filtering declaration | `1.0.0` / `1041b03f6c13fa3f56d0991bad00f3291c3672a8b0cbc488c83dc182a0933d1c` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l3.fragmentation_flood.readiness` | Fragmentation Flood declaration | `1.0.0` / `a9bbf1df0eb65857e9d1cbdd493511b97d0ee604fb701c64273e837d2d75e60d` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l3.syn_flood.readiness` | SYN Flood declaration | `1.0.0` / `74643b1cb2c7eea5b30039c78f190613fecef32da5e2927051f983103a32d989` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l3.tcp_connection_flood.readiness` | TCP connection setup required | `1.0.1` / `09755b5cd36f383d0d0e24002aaf50d7d97c48a1dbdadf2869ff2db797e68349` | `tcp_connect` / `probeTcpConnect` | `additional_target_input`: `port_required` | Bounded TCP connection samples after explicit target setup | correlateNfwViolation; none | inconclusive; readiness-kind excluded |
| `l3.nat_state_table.readiness` | NAT / State Table declaration | `1.0.0` / `361ed26eaaee2a213b03e60eea806bde092dbd2ca398f3d5d4511b611cc8fc25` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l3.smtp_connection_flood.readiness` | SMTP-port TCP reachability | `1.0.1` / `59d10bd921c40c48b924df6861033e2c1d59d873727f8b74797b06af2f5133a8` | `tcp_connect` / `probeTcpConnect` | `supported_observation` | Bounded TCP connection samples | correlateNfwViolation; none | exposed, inconclusive; readiness-kind excluded |
| `l3.ssh_connection_flood.readiness` | SSH-port TCP reachability | `1.0.1` / `befb442d811309060034b71ebb2091144deffcd069f488ec1f4ebe5a0a7e7ffa` | `tcp_connect` / `probeTcpConnect` | `supported_observation` | Bounded TCP connection samples | correlateNfwViolation; none | exposed, inconclusive; readiness-kind excluded |
| `l3.ftp_connection_flood.readiness` | FTP-port TCP reachability | `1.0.1` / `c3793a5a998a8e86c04a7a157c267fc0b1d263b7f17b5c51f69fb26bf0a24c5b` | `tcp_connect` / `probeTcpConnect` | `supported_observation` | Bounded TCP connection samples | correlateNfwViolation; none | exposed, inconclusive; readiness-kind excluded |
| `l3.ike_ipsec_negotiation.readiness` | IKE / IPsec Negotiation declaration | `1.0.0` / `e7c4a51dab1532c3b1fdb5f75a689dd266d58e5006a5df5ee7dff17dec30946f` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.connection_hoarding.readiness` | Application Connection Hoarding declaration | `1.0.0` / `1e6c9dcbe676e7807a7e734ab10e54b15c90dfc641494b4cc0ac5982f0b4d97f` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `exploit.ping_of_death.posture` | Legacy Oversized-Packet Filtering declaration | `1.0.0` / `b4fede8ca07fa544e8600d10510c24a7088edfef7a969a7408d392e5ceafc512` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `exploit.teardrop.posture` | Overlapping-Fragment Filtering declaration | `1.0.0` / `6f428bfbf159ca993d50ca16d1d6e3a3895bf47759218b11dbaa6f9f27a049c3` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `exploit.ip_options.posture` | IP Options Filtering declaration | `1.0.0` / `5652355fd317ec9afa0ac02f6ed0c6686f09cf4433e9df9177a0123c4c00f8ee` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `exploit.malformed_quic.posture` | QUIC Parser Robustness declaration | `1.0.0` / `39fc156b0440ce75f69c288814d9adc34b55f00845ba1599fc50a847bfeeb360` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `exploit.land_attack.posture` | Spoofed Same-Source Filtering declaration | `1.0.0` / `5b5254cb4b1b7cd5324b659be05511116e45b591b82650e952085530bc23d5a4` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `exploit.quic_migration.posture` | QUIC Migration Abuse declaration | `1.0.0` / `d3e1097d1980ffdd6bca075b936e7d7ee47a095004c389cc30a52fbb17ad5bb6` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `reflect.ssdp_exposure.safe` | SSDP / UPnP Reflector Exposure | `1.1.0` / `7386a37435c132055ce949d90f0e6b850da7bbb54e0ecc609865b8283d2c53df` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; ssdp_msearch | exposed, inconclusive; readiness-kind excluded |
| `reflect.snmp_exposure.safe` | SNMP Responder Exposure | `1.1.0` / `3bcd1fe30794caa7da72cf841010adfd4bda1aed31406467c24aa492a095b662` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; snmp_v2c_get_sysdescr | exposed, inconclusive; readiness-kind excluded |
| `reflect.chargen_qotd_exposure.safe` | CHARGEN / QOTD / Echo Responder Exposure | `1.1.0` / `90f32fe77790015e260c0b13a9f67db3b9727da5470852560d06f450f6f9afe9` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; chargen_trigger | exposed, inconclusive; readiness-kind excluded |
| `reflect.mdns_netbios_wsdiscovery_exposure.safe` | mDNS / NetBIOS NBSTAT / WS-Discovery Composite Exposure | `1.2.0` / `94b769ac2fc69878feea119e778eb87d06f3f8fe9b3bfdc2cef4460d780b6fdb` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; mdns_ptr_query | exposed, inconclusive; readiness-kind excluded |
| `reflect.portmap_service_exposure.safe` | Portmapper / RIPv1 / RPC Service Exposure | `1.1.0` / `dd2da98e0bb3b42acb6281c7195a36aceb88930ffd69dd8da5a94065060e552c` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; portmap_dump | exposed, inconclusive; readiness-kind excluded |
| `reflect.dtls_sip_rdp_tftp_exposure.safe` | DTLS/SIP/RDP/TFTP responses | `1.2.0` / `f5f7453cc34c4e1a22772a949bcbf4b779358880a696e5b24001b84b95fa1883` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; tftp_read_request | exposed, inconclusive; readiness-kind excluded |
| `reflect.quic_reflection_exposure.safe` | QUIC Alt-Svc Advertisement Observation | `1.0.1` / `b3ffa5e523caa9e73bb6f872298c65c4f6b20b6e01ef797eeb594db483181c1d` | `quic_reachability` / `probeQuicReachability` | `supported_observation` | HTTP Alt-Svc advertisement observation, not a QUIC exchange | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `reflect.tcp_middlebox_exposure.safe` | TCP service reachability | `1.0.1` / `ebd9ae597eb696e002622848bb1b997101c49a7ede23f97aa213bcf37f8305e9` | `tcp_connect` / `probeTcpConnect` | `additional_target_input`: `port_required` | Bounded TCP connection samples after explicit target setup | correlateNfwViolation; none | inconclusive; readiness-kind excluded |
| `reflect.mssql_resolver_exposure.safe` | MSSQL Resolver Exposure | `1.1.0` / `4db23add3a28098526331a608e92198b6f5fc29c967c44b88a9310231c905410` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; mssql_resolution_request | exposed, inconclusive; readiness-kind excluded |
| `reflect.jenkins_discovery_exposure.safe` | Jenkins / CI Discovery Exposure | `1.1.0` / `77d4f5ae5db77f049de2dbb98c75cdc2d35fcd3a70a441ce14d85e46f17fde51` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; jenkins_discovery | exposed, inconclusive; readiness-kind excluded |
| `reflect.coap_iot_exposure.safe` | CoAP IoT Responder Exposure | `1.1.0` / `f7b42c9cc4147d786080f9a966e43b9d472e6f460e409e4f2aa3b2bdceb04e97` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; coap_get_wellknown | exposed, inconclusive; readiness-kind excluded |
| `reflect.legacy_device_discovery_exposure.safe` | Legacy Device / Game Discovery Exposure | `1.1.0` / `bdda11a5f12121cc3fb3b211f16381b05fa413afaa2ac799eb53a9797ef1156b` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; ws_discovery_probe | exposed, inconclusive; readiness-kind excluded |
| `reflect.stun_turn_exposure.safe` | STUN / TURN Responder Exposure | `1.1.0` / `6061883be3a753f3cf94e17e82acf5b695f3f2c2b70bd2915f729c81d43e2f8e` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; stun_binding_request | exposed, inconclusive; readiness-kind excluded |
| `reflect.ipmi_bmc_exposure.safe` | IPMI / BMC Responder Exposure | `1.1.0` / `9add22fbbd69e8e99eeb78536043aa7aac5ac830eadb211f67c6eddfd6598766` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; ipmi_rmcp_ping | exposed, inconclusive; readiness-kind excluded |
| `reflect.redis_direct_exposure.safe` | Redis-port TCP reachability | `1.1.0` / `01a26c420a6211b491068f305d6f1624f1f6ccafba4d5593678a7a0c9fc723ea` | `tcp_connect` / `probeTcpConnect` | `supported_observation` | Bounded TCP connection samples | correlateNfwViolation; none | exposed, inconclusive; readiness-kind excluded |
| `reflect.openvpn_wireguard_exposure.safe` | OpenVPN / WireGuard Responder Exposure | `1.1.0` / `c35bc5dafaf88555284fcd00f865a231f3645c0681f95aeb649fa14d81ede715` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; openvpn_reset | exposed, inconclusive; readiness-kind excluded |
| `amp.ntp_exposure.safe` | NTP Mode Restriction Exposure | `1.1.0` / `5f889373144883911bde03eb112eb85071e0c573f3ce50ad72465a76980a65dc` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; ntp_mode6_readvar | exposed, inconclusive; readiness-kind excluded |
| `amp.cldap_exposure.safe` | CLDAP Exposure Posture | `1.1.0` / `b2c07721b3ed5629e506c01c77837c4750e110b8733db78383a8d3f2e118b5f1` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; cldap_root_dse | exposed, inconclusive; readiness-kind excluded |
| `amp.memcached_exposure.safe` | Memcached Exposure | `1.1.0` / `f9b10aa80242e106134cdd74767404230475b9e591dcfc7faae120e9f02bcacb` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; memcached_udp_stats | exposed, inconclusive; readiness-kind excluded |
| `amp.dns_any_txt_exposure.safe` | DNS ANY/TXT Response-Class Posture | `1.0.1` / `67020468530a84bae40d699a0aacafcb318a9b4a284e23beeca7baaf32f09c85` | `dns_wire_query` / `probeDnsWireQuery` | `supported_observation` | Bounded DNS wire query | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `amp.smurf_broadcast_exposure.safe` | Directed Broadcast Filtering declaration | `1.0.0` / `075f674c39d2c798cbbe26180fd01cc3a49ceb8607539a83e6a54687074b6186` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `amp.authoritative_resolver_exposure.safe` | DNS service response sample | `1.0.1` / `0d82ab1f484f34da1308b7cf7ea6d5e971af229db218988affff9bac5ea904e6` | `dns_wire_query` / `probeDnsWireQuery` | `supported_observation` | Bounded DNS wire query | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `dns.laundering.readiness` | DNS Laundering declaration | `1.0.0` / `01d82e092d17dd9cb8ccac836c8bd45ecb664e1b14f671ef9c2c9e938adc3307` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `dns.garbage_flood.readiness` | DNS query response sample | `1.0.1` / `f83de7fd19b71b8a9812866756be58c5d39e2fd722e01a33a5fbdf15df26e0bc` | `dns_wire_query` / `probeDnsWireQuery` | `supported_observation` | Bounded DNS wire query | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `dns.phantom_domain.readiness` | Phantom Domain declaration | `1.0.0` / `45818935819870e53e977da16647fb18d2d20dacadc375c1a0d087b5659b998f` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `dns.domain_lockup.readiness` | Domain Lock-Up declaration | `1.0.0` / `fbf558e4347c1e395c96e7d54f3fac3451e8e0b67ee102abd9ddd7039c0e1989` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `dns.nxns_attack.readiness` | DNS nameserver response sample | `1.0.1` / `dd047e6fa7f76e9d1c7b6b7d583f78d786f800ace3a2f63afe20ce7cd9d9a22a` | `dns_wire_query` / `probeDnsWireQuery` | `supported_observation` | Bounded DNS wire query | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `dns.dnsbomb.readiness` | DNSBomb Pulsing declaration | `1.0.0` / `ef9bf4bd07dba46b6f4b05e25f0c5e55cfe641bd5a4ef945e4ba6e31448f8020` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `dns.qname_minimization.readiness` | QNAME Minimization declaration | `1.0.0` / `a58368a70e578f6f25e77c7b96bb0573bd66b9e4258c16914bf019cd8e978b63` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `dns.doh_dot_exposure.readiness` | DoH / DoT Endpoint declaration | `1.0.0` / `e21516041d80dd242607144a8df9543e4fe5b6979a9bba144faea8a6b7e16df7` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `dns.tcp_fallback.readiness` | DNS TCP fallback sample | `1.0.1` / `787bfaa1092142397a971a9437cf5bc6102bac3fc51a44f2bd9ca7e504f22dfe` | `dns_wire_query` / `probeDnsWireQuery` | `supported_observation` | Bounded DNS wire query | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `dns.zone_walking.readiness` | DNS Zone-Walking declaration | `1.0.0` / `c6ebf9efe5ba98f356a4650908bf92502cf767908092a5933c6a41f94b6f8240` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.http_get_flood.validation` | GET response sequence | `1.0.1` / `00abe1416fdaa3e46b4f01a323441eeb2edd040f459d0da1b21335963483f9ca` | `rate_limit_sequence` / `probeRateLimitSequence` | `supported_observation` | Small fixed HTTP request sequence | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.http_post_flood.validation` | HTTP POST Limit declaration | `1.0.0` / `97f8f2143b3b6ea5f20a578f272f14fa55b6f5212beb8ad0105f2a8b6eb307ce` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.slowloris.readiness` | Slow-header connection sample | `1.0.1` / `54e90b2a0258f1d27c4411b5f17f1cb7306d7315f844c606666395bb5fb82d25` | `slow_header_probe` / `probeSlowHeaderTimeout` | `supported_observation` | One bounded slow-header timeout sample | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.slow_post.readiness` | Slow Body Client declaration | `1.0.0` / `169da3bd182c96cdfa8e4617d5267a88a67f5cc76b8d07cea5ebf4b965b1ce1d` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.slow_read.readiness` | Slow Read Response declaration | `1.0.0` / `d53acbc0c9dfa1a693e74fe5edddcd66776e3c05eb5d6de82650743083dd7049` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.low_and_slow.readiness` | Low-and-Slow Header Timeout Sample | `1.0.1` / `89919a1ff7b9557d245ae4828a4b809442182f0f680b7091dda1ee772b56df28` | `slow_header_probe` / `probeSlowHeaderTimeout` | `supported_observation` | One bounded slow-header timeout sample | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.large_body_post.readiness` | Large Body Limit declaration | `1.0.0` / `2d1c347cbc350f2ecc128bbcc4fe4beede1f17cfab992ccaf044eae4c8911c5f` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.file_upload_abuse.readiness` | File Upload Abuse declaration | `1.0.0` / `7f81475524e11b15801f0c7033d80e7540c04c0c46ca3bcb5405ffa668f9b848` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.json_xml_bomb.readiness` | Parser Depth Limit declaration | `1.0.0` / `477ea07cd7f54c14e0af6b33f865e6c3970719553d13c50735439288940b6e40` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.search_abuse.validation` | Search-route response sample | `1.0.1` / `82c430bed65caa21000742a5943e6a2b4d29481c58ef972f5bef9314a57a5333` | `rate_limit_sequence` / `probeRateLimitSequence` | `supported_observation` | Small fixed HTTP request sequence | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.export_abuse.validation` | Export-route response sample | `1.0.1` / `31daac699a995d75185b2011d84d1726e6acafa60b149825bba2f69e7db37956` | `rate_limit_sequence` / `probeRateLimitSequence` | `supported_observation` | Small fixed HTTP request sequence | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.batch_api_abuse.validation` | Batch API Limit declaration | `1.0.0` / `ba219e65b0d5271cc5c1884bdc2b718738a34cb34ed5e49f887525ae7288fada` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.oauth_token_abuse.validation` | Token-route response sample | `1.0.1` / `c71ac9335868e7307feaed07be6624047277a8b991b36411bb82b324c69b2a4f` | `rate_limit_sequence` / `probeRateLimitSequence` | `supported_observation` | Small fixed HTTP request sequence | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.checkout_abuse.validation` | Checkout Endpoint Limit declaration | `1.0.0` / `d7346d4aefddf3b06c37d0113d8b0afc50bfec9eeb7ff5507d2e7f91119c9157` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.otp_sms_cost.readiness` | OTP / SMS Cost Guardrail declaration | `1.0.0` / `005c76929127d73b457a30ddb13487b8d16ff4b8b05ef81cd8cff8e30ef7d190` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.signup_registration_abuse.validation` | Signup-route response sample | `1.0.1` / `bc08b2129a819cd8fe54d60f5e66a5558ec8ce9453b56fc873ca98fa63057cc8` | `rate_limit_sequence` / `probeRateLimitSequence` | `supported_observation` | Small fixed HTTP request sequence | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.elasticsearch_abuse.readiness` | Search-Cluster Query Cost declaration | `1.0.0` / `15289f5f016e4ce8a4492107f1974d69814792c5021478a9e97605b85d1366d1` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.health_check_flood.readiness` | Health-Check Flood declaration | `1.0.0` / `148d18ad285ab85f02e5785c4698177d8d275d940eb46040569d5f53eb55a29f` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.wordpress_xmlrpc.readiness` | XML-RPC Endpoint Posture | `1.0.1` / `9a091228609b2e7b1b5131ab1f3054606a5e94806d0612dcdaf01257e2ca0f5b` | `http_head` / `probeHttpHead` | `supported_observation` | One HTTP HEAD response observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.webhook_flood.readiness` | Webhook Callback Limit declaration | `1.0.0` / `3f674d4d86db8dbaa52081e830adb8e535dab76b723d9c4462d79cf6c1d0097d` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.http_pipelining.readiness` | HTTP Pipelining Limit declaration | `1.0.0` / `19c91dfca03f25502613f439b71363e6550ca6884106757bedd0eb72487cb649` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.http_range_abuse.readiness` | Range Request Limit declaration | `1.0.0` / `68adfe99d5cd1046b95ba3c2615bae11aff6a041a0e60fb0886fd7c6e62be234` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.conditional_revalidation.readiness` | Conditional Revalidation Cost declaration | `1.0.0` / `739119d24479191c4a8cadccd1489edf3816d3a1f414bdc6be09058f5a2ea1f8` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.captcha_challenge_abuse.readiness` | Challenge Endpoint Cost declaration | `1.0.0` / `cea85da927fc5cbef3ef479589fbe64fa4ee9f0961ea93fbe91d4e60a2029a5f` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.mqtt_broker_exposure.readiness` | MQTT Broker declaration | `1.0.0` / `3ec56a634722635569cebdbe25ea7981f8d3a61fc51b1e97a54850dbb86c443b` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.redos.readiness` | Regex Complexity declaration | `1.0.0` / `5d1904e602c0d0aa955f9314ebd3e3af6a52ec6bbae819f0d07a5e6d683713f7` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.graphql_batch_abuse.validation` | GraphQL response posture | `1.0.1` / `15b316c2b19b7f2adfae13b814c87636d6654e6483297af03ad676dc78d44d19` | `graphql_posture_probe` / `probeGraphqlPosture` | `supported_observation` | Bounded GraphQL metadata observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `tls.handshake_rate.readiness` | TLS Handshake Rate declaration | `1.0.0` / `a128db4e335bafac1b073aabce093c5b9ab0e8ff4ddc401440df9fa571ac569c` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `tls.renegotiation.readiness` | TLS Renegotiation Posture | `1.0.1` / `4c70dc24b0f65e11f7a858fc7017556568e49e2810a6ecc4bba57a439e4ac5ab` | `tls_session` / `probeTlsSession` | `supported_observation` | One TLS session observation | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `tls.zero_rtt.readiness` | TLS 0-RTT Early Data declaration | `1.0.0` / `a21e109d608d355181475a602d2d9afd15eb339825650c24fd73d4cb238ade6e` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `tls.ocsp_stapling.readiness` | OCSP Stapling Posture | `1.0.1` / `380a123bb302b2e41901adeddc8259ce0a700973e931e1fc2af71cb30319d68b` | `tls_audit` / `probeTlsAudit` | `supported_observation` | One TLS handshake and certificate/configuration inspection | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.http2_rapid_reset.validation` | HTTP/2 reset sample | `1.0.1` / `aba79357fe72b1b6f91104b0c687f5dcd9b3f647a51365b4ea907829ac4afece` | `http2_frame_probe` / `probeHttp2FrameBehavior` | `supported_observation` | Bounded existing HTTP/2 control-frame or SETTINGS sample | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.http2_made_you_reset.readiness` | HTTP/2 control-frame sample | `1.0.1` / `5dd95d3fd3c5e13f7fe72bb5ca4162f1107785ee0c88fd638ce59dbb6a521e9c` | `http2_frame_probe` / `probeHttp2FrameBehavior` | `supported_observation` | Bounded existing HTTP/2 control-frame or SETTINGS sample | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.http2_continuation.readiness` | HTTP/2 control-frame posture | `1.0.1` / `258e36587140f99fea746a18891009e6602066c9596fa66900b82aed9aa23f0d` | `http2_frame_probe` / `probeHttp2FrameBehavior` | `supported_observation` | Bounded existing HTTP/2 control-frame or SETTINGS sample | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.http2_priority_abuse.readiness` | HTTP/2 Priority Abuse declaration | `1.0.0` / `4237087998e0b53b59d7f0e1e3398269179d93bdaa86b45fd9ab6206b4f26031` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.hpack_bomb.readiness` | HTTP/2 advertised header limits | `1.0.1` / `69b980aff353c08515b2726effe303229a22f4b9b1f8a59b7121770a22d4fda4` | `http2_frame_probe` / `probeHttp2FrameBehavior` | `supported_observation` | Bounded existing HTTP/2 control-frame or SETTINGS sample | correlateObservationOnlyVerdict; hpack_limits | inconclusive; readiness-kind excluded |
| `l7.http2_push_promise.readiness` | HTTP/2 Server Push declaration | `1.0.0` / `44c6c01e6b40c27b606b3a4621b6129b38ac1249642851daffe9e4b1b72f8057` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.qpack_bomb.readiness` | QPACK Compression Limit declaration | `1.0.0` / `2343dc48218b1028bffe3d1c035172f7852d92ea42ffb5880ab432eab42e1506` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `protocol.sse_stream.readiness` | SSE Stream Limit declaration | `1.0.0` / `370dc377ef84744e7100e4a2115b327bcba35b9e8ca632237c4a03eb1a0c59fa` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `protocol.http3_control_stream.readiness` | HTTP/3 Alt-Svc Posture Observation | `1.0.1` / `e4b887e50cdef1d867010af217d2bc579861e1dce0abab806676509c2d66b570` | `http3_control_probe` / `probeHttp3ControlStream` | `supported_observation` | HTTP Alt-Svc advertisement observation, not HTTP/3 control traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `protocol.websocket_message_rate.readiness` | WebSocket Message Rate declaration | `1.0.0` / `24f384dc1cef891175296a5317f76dc4f54bb231e65b16bf1c3a9ec1ee5b563b` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `origin.cdn_bypass.readiness` | Declared-host origin observations | `1.0.1` / `91b4580a42e13d805810d08fdf8d90df309cdbf38908c69c2ecb43edb4731816` | `origin_leak_scan` / `probeOriginLeakScan` | `supported_observation` | Bounded declared-host DNS and HTTP observations | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `origin.dns_hostname_bypass.readiness` | DNS Hostname Bypass Sample | `1.0.1` / `f7d828166bc258c57f0c0086e9012fbe1fd0dd729a33764a58f1f90a0ee3f820` | `origin_leak_scan` / `probeOriginLeakScan` | `supported_observation` | Bounded declared-host DNS and HTTP observations | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `pattern.carpet_bombing.readiness` | Carpet Bombing declaration | `1.0.0` / `7d7a36297cf615922eb7b9772548fbe22a73c8cdafa17500de91949967a157e4` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `pattern.pulse_wave.readiness` | Pulse-Wave declaration | `1.0.0` / `8882c88c67715f3fba6f448e8e77136ca3a43acbbbb20fde7128b02d219d8778` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `pattern.spoofed_source.readiness` | Spoofed Source Filtering declaration | `1.0.0` / `377975cea5793a5684b8a20f5d4d0ad8104060e5eaa4a14ab0c42f559606aee7` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `pattern.ransom_ddos.readiness` | Ransom DDoS Runbook declaration | `1.0.0` / `c24ca23ab5979ead1811778c8d4f08a9948ff2a702a05ff396dcac75b4df1255` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `pattern.rate_limit_evasion.readiness` | Rate-Limit Evasion Resistance declaration | `1.0.0` / `0e8c0e80d83f311572565e066a86e1aad3b2d016043e6cf63b114023ccdbe06a` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `pattern.adaptive_evasion.readiness` | Adaptive Evasion Resistance declaration | `1.0.0` / `b1708bd21b8bc53b209d8915330f87c5cf1965de003ccde232d1d0302fe4d7c4` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `pattern.residential_proxy.readiness` | Residential Proxy Resistance declaration | `1.0.0` / `c1a0c841017c4230126a148df814b2acd81a234e87b08f19fc4eba45a9090674` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `ops.autoscaling_cost.readiness` | Autoscaling Cost Guardrail declaration | `1.0.0` / `1591c25d4de3bd8a8c4855e0718c63b9c2ae4f9f17e866c796219ea815ad58be` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `ops.attack_alert_coverage.readiness` | Attack Alert Coverage declaration | `1.0.0` / `8460fc4ca94a2ad297a2b599e389543e00cd6fb2f93f6fe5e061b4425ff6557c` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `reflect.slp_amplification_exposure.safe` | SLP Amplification Exposure | `1.1.0` / `77993c231af9fc9602e695277eed256353710666855abc3464c05e08fc9850ce` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; slp_srvrqst | exposed, inconclusive; readiness-kind excluded |
| `reflect.tp240_amplification_exposure.safe` | TP240 PhoneHome Amplification Exposure | `1.1.0` / `5e8448ea0b1f83c43a5af0c02db6ab9bcf295f3e740a2575911f7e606069cf19` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; tp240_status_request | exposed, inconclusive; readiness-kind excluded |
| `reflect.l2tp_reflection_exposure.safe` | L2TP Reflection Exposure | `1.1.0` / `96dc4d88df59774dd4b87ad0dd053ff50daba5fd8e054fab136fca72d9c6eb8a` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; l2tp_sccrq | exposed, inconclusive; readiness-kind excluded |
| `reflect.natpmp_amplification_exposure.safe` | NAT-PMP Amplification Exposure | `1.1.0` / `9bf61cdbba066165ae6ee89cd40e8282f1a9e25764bdd9a4dbb574bb7a8a1fc0` | `reflection_service_probe` / `probeReflectionService` | `supported_observation` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; natpmp_external_address | exposed, inconclusive; readiness-kind excluded |
| `reflect.ipp_callback_exposure.safe` | IPP callback test unavailable | `1.1.0` / `3450074251c7299bccc96a2f8236c91e159a56ec404c77832f33940afce8989f` | `reflection_service_probe` / `probeReflectionService` | `unsupported_delivery`: `unsupported_or_unapproved_protocol_request` | Bounded labelled service requests without spoofing or amplification | correlateNfwViolation → correlateReflectorExposure; ipp_get_printer_attributes | inconclusive; readiness-kind excluded |
| `dns.multi_question_oversized.safe` | DNS parser response sample | `1.0.1` / `476989d6cbd28e850b48bc0a63ff5b3ce195d5a66da57eb36b2f6a8567cb1eb6` | `dns_wire_query` / `probeDnsWireQuery` | `supported_observation` | Bounded DNS wire query | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.http_method_policy_marker.safe` | HTTP-policy token observation | `1.3.0` / `2b922151a3f4fbbcbae92caf5c74a7b2268a2fb3e6db3202d5512814906ae919` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_observation` | GET inert-token query/path/header placements and benign controls | setup-required inert-token observation; http_method_policy | inconclusive; readiness-kind excluded |
| `waf.request_smuggling_marker.safe` | Request Smuggling token observation | `1.3.0` / `013f71630fe40ea75bcaec9a9f36d8a190775713a2c2bbb3f8008b3edaa9bb52` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_observation` | GET inert-token query/path/header placements and benign controls | setup-required inert-token observation; request_smuggling | inconclusive; readiness-kind excluded |
| `waf.crlf_injection_marker.safe` | CRLF/Response-Splitting token observation | `1.3.0` / `22212bcc9245f84976a5354a3897f60b7512fe113068c8aac97579e39d78203e` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_observation` | GET inert-token query/path/header placements and benign controls | setup-required inert-token observation; crlf | inconclusive; readiness-kind excluded |
| `waf.open_redirect_marker.safe` | Open Redirect / Parameter Policy token observation | `1.3.0` / `ea7c1656c7d3b2ece9ecd57bf5ff0504dcb7b4853c987d50498d16245429c50c` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_observation` | GET inert-token query/path/header placements and benign controls | setup-required inert-token observation; open_redirect | inconclusive; readiness-kind excluded |
| `waf.nosql_injection_marker.safe` | NoSQL Injection token observation | `1.3.0` / `75b78e0978a8ce1035988bac47bdf9fd6959deba91854612f28930fab81cf71f` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_observation` | GET inert-token query/path/header placements and benign controls | setup-required inert-token observation; nosql | inconclusive; readiness-kind excluded |
| `waf.xpath_injection_marker.safe` | XPath/XML Injection token observation | `1.3.0` / `0d8df68ca1711c8a14f78e6ed49ec87342a33aaf6d990df4fa48d171360db106` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_observation` | GET inert-token query/path/header placements and benign controls | setup-required inert-token observation; xpath | inconclusive; readiness-kind excluded |
| `waf.jndi_ldap_marker.safe` | JNDI/LDAP token observation | `1.3.0` / `7c73b40eeb4e0be3a91f4062a2d42e7ed689f340bd4f0e232cc5cf12346b2c4d` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_observation` | GET inert-token query/path/header placements and benign controls | setup-required inert-token observation; ldap | inconclusive; readiness-kind excluded |
| `waf.csv_formula_marker.safe` | CSV/Formula token observation | `1.3.0` / `77c6623fd20cea203d006e518cbd748d315b9d380696e3f136fbb01e27cdca36` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_observation` | GET inert-token query/path/header placements and benign controls | setup-required inert-token observation; csv_injection | inconclusive; readiness-kind excluded |
| `waf.prototype_pollution_marker.safe` | Prototype Pollution token observation | `1.3.0` / `b7a2b59e61e94389956c93af09dbc56ac7240187930856ef0b93c8c017b238b3` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_observation` | GET inert-token query/path/header placements and benign controls | setup-required inert-token observation; prototype_pollution | inconclusive; readiness-kind excluded |
| `waf.deserialization_marker.safe` | Unsafe Deserialization token observation | `1.3.0` / `14b25438ab0d6df9a928e65fbed76f6deba7e84729bd1db982ec25da7bb4cbea` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_observation` | GET inert-token query/path/header placements and benign controls | setup-required inert-token observation; deserialization | inconclusive; readiness-kind excluded |
| `waf.ssrf_marker.safe` | SSRF token observation | `1.3.0` / `7d77e17d06b2fa0421c815140feb77b26c74d94344042c6094749232c4804016` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_observation` | GET inert-token query/path/header placements and benign controls | setup-required inert-token observation; ssrf | inconclusive; readiness-kind excluded |
| `waf.xxe_marker.safe` | XXE token observation | `1.3.0` / `d276edd1844c8589589ed2e31ace4afe6267a9e3ae7c5a7a0511fdb0e6e42701` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_observation` | GET inert-token query/path/header placements and benign controls | setup-required inert-token observation; xxe | inconclusive; readiness-kind excluded |
| `waf.file_upload_marker.safe` | File Upload token observation | `1.3.0` / `456c1962821ac2bf7fa48b3eb8fb6f2c6ee7c07244ff58e5379bbc5accbe7096` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_observation` | GET inert-token query/path/header placements and benign controls | setup-required inert-token observation; file_upload_marker | inconclusive; readiness-kind excluded |
| `waf.jwt_tamper_marker.safe` | JWT Tamper token observation | `1.3.0` / `15121bf9be7941c9b823d48e961ef718927403b61e5b0a96d355e24095fc3ead` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_observation` | GET inert-token query/path/header placements and benign controls | setup-required inert-token observation; jwt_tamper | inconclusive; readiness-kind excluded |
| `waf.entry_path_login_marker.safe` | WAF Declared Login Path Marker | `1.1.0` / `a8f7d6136c02a6de8f1b87b95bfecd7f34913893d279fed56d2e72f5f7074fb7` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_semantic_safe` | GET inert-token query/path/header placements and benign controls | markerComparisonComplete → correlateChallengeRedirectPenalty → correlateClassMarkerVerdict; declared_login_path | protected, exposed, inconclusive; readiness-kind eligible only with exact proof |
| `waf.entry_path_api_marker.safe` | WAF Declared API Path Marker | `1.1.0` / `a83d6edbea662d4b7b81d6a0767383eed2d7b2c55af878f645aac4fe2d1c4648` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_semantic_safe` | GET inert-token query/path/header placements and benign controls | markerComparisonComplete → correlateChallengeRedirectPenalty → correlateClassMarkerVerdict; declared_api_path | protected, exposed, inconclusive; readiness-kind eligible only with exact proof |
| `waf.evasion_unicode_normalization.safe` | Unicode Normalization marker comparison | `1.2.0` / `ea904cb3bbe6d27da3100781808046e6a0033de8679a3b06a03a062c22c542a1` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `supported_semantic_safe` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | protected, exposed, edge_protected, edge_exposed, allowed_as_expected, inconclusive; readiness-kind eligible only with exact proof |
| `waf.evasion_homoglyph.safe` | Homoglyph marker comparison | `1.2.0` / `86b931158b8bdcdd88ca46807d16a09ab1812eacf7319201d3cd92de2894caa9` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `supported_semantic_safe` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | protected, exposed, edge_protected, edge_exposed, allowed_as_expected, inconclusive; readiness-kind eligible only with exact proof |
| `waf.evasion_overlong_utf8.safe` | Overlong Utf8 marker comparison | `1.2.0` / `c44f15b861bfe8227ea5d743ad4ef99d03c7fe3b8571bd4e7d61cace73b30ec2` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `supported_semantic_safe` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | protected, exposed, edge_protected, edge_exposed, allowed_as_expected, inconclusive; readiness-kind eligible only with exact proof |
| `waf.evasion_alt_charset.safe` | ALT Charset test unavailable | `1.2.0` / `7590fff8fa527ffb765c947d72bde9f6d910b85dfa330460d0fa9621f6ca4d09` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_html_entity.safe` | Html Entity marker comparison | `1.2.0` / `be3cb1a05ee159651dd06a533ef17019ab30e28b83c155c445ed33921b264e45` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `supported_semantic_safe` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; xss | protected, exposed, edge_protected, edge_exposed, allowed_as_expected, inconclusive; readiness-kind eligible only with exact proof |
| `waf.evasion_js_escape.safe` | JS Escape marker comparison | `1.2.0` / `3c1c31dcfc0cf4b1d50688b6baa436c42714123ba2baa7ca2a162b3c4f2bb553` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `supported_semantic_safe` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; xss | protected, exposed, edge_protected, edge_exposed, allowed_as_expected, inconclusive; readiness-kind eligible only with exact proof |
| `waf.evasion_json_unicode_escape.safe` | Json Unicode Escape test unavailable | `1.2.0` / `6586a8f95542fd806cca1759ed44451b7f8a5c257216cec84d987d39a5e0ee27` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; xss | inconclusive; readiness-kind excluded |
| `waf.evasion_css_escape.safe` | CSS Escape marker comparison | `1.2.0` / `afeff441ce126bb3acf5ff28c257082ae3aef460e762af773488c8e28751cb68` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `supported_semantic_safe` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; xss | protected, exposed, edge_protected, edge_exposed, allowed_as_expected, inconclusive; readiness-kind eligible only with exact proof |
| `waf.evasion_base64_wrap.safe` | Base64 Wrap marker comparison | `1.2.0` / `a654823857a2e963c60457140d02bef39de09a13e15f9f4a6b6bfa618d5e57e3` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `supported_semantic_safe` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | protected, exposed, edge_protected, edge_exposed, allowed_as_expected, inconclusive; readiness-kind eligible only with exact proof |
| `waf.evasion_numeric_repr.safe` | Numeric Repr marker comparison | `1.2.0` / `f69afcc173d965cb0996f00f64230f838adb31e69fae565de544f2ad023a417d` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `supported_semantic_safe` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | protected, exposed, edge_protected, edge_exposed, allowed_as_expected, inconclusive; readiness-kind eligible only with exact proof |
| `waf.evasion_whitespace.safe` | Whitespace marker comparison | `1.2.0` / `80a231dffcb14da98740c7dc911b244fe4a41c22f0111bd6ebb2ddec1ddb8ba5` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `supported_semantic_safe` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | protected, exposed, edge_protected, edge_exposed, allowed_as_expected, inconclusive; readiness-kind eligible only with exact proof |
| `waf.evasion_lexical_operator.safe` | Lexical Operator test unavailable | `1.2.0` / `60b444741502b01546b0e49a9298ae9839c8e4c6dbaac640d69534f37b26e54e` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_lexical_tautology.safe` | Lexical Tautology test unavailable | `1.2.0` / `9ec9c75bbfab55f632fb6d854fba18035cb8bef67d768854f8438d2d71b87579` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_lexical_literal.safe` | Lexical Literal test unavailable | `1.2.0` / `b7a79e3e725217f3142b1a41af56e64fe3114c56faa781da4716e768a9308175` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_control_char.safe` | Control Char marker comparison | `1.2.0` / `90967dd1dfc6791fa5021942a68e52015a98478f3648b1c13c1fb16747792a4e` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `supported_semantic_safe` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | protected, exposed, edge_protected, edge_exposed, allowed_as_expected, inconclusive; readiness-kind eligible only with exact proof |
| `waf.evasion_path_matrix.safe` | Path Matrix test unavailable | `1.2.0` / `ee02e0f26834aa819070028c886826488b9f6e04a3c1ed0be4bc59353568f2d9` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; path_traversal | inconclusive; readiness-kind excluded |
| `waf.evasion_path_suffix.safe` | Path Suffix test unavailable | `1.2.0` / `33d473e6a88192167242c0a136f921fec620aae2443ccdd07eb0c373dfa93092` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; path_traversal | inconclusive; readiness-kind excluded |
| `waf.evasion_ip_representation.safe` | IP Representation test unavailable | `1.2.0` / `2b20d3a01dbad5bfc5e89c9bfc83695f5c29779d81f3f3c52d993b3572f28cd4` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_parser_hpp.safe` | Parser HPP marker comparison | `1.2.0` / `26c71149f3d621add48e5a1370f966850b694aa16b4696be6f27a5fc77d62845` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `supported_semantic_safe` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | protected, exposed, edge_protected, edge_exposed, allowed_as_expected, inconclusive; readiness-kind eligible only with exact proof |
| `waf.evasion_parser_json_dup.safe` | Parser Json DUP test unavailable | `1.2.0` / `6ad814b07bfc98ce19856254937f62d4fcc237c0673fa969c7fe4e90d4d88c93` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_parser_header_dup.safe` | Parser Header DUP test unavailable | `1.2.0` / `4bf0bb0fc8b8769e7ef57e6e07ce4808ba4a22111fa560aebc74f282e939ad18` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_framing_cl_te.safe` | Framing CL TE test unavailable | `1.2.0` / `2c6a828caf5ac03ebf645026c98ca21c6f5f7af6ba97f2e57d5526ad6201d853` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_framing_transfer_coding.safe` | Framing Transfer Coding test unavailable | `1.2.0` / `763cf49c85ade47bfe4723f0e04147540eb99dda6560411d9f97edff077fb006` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_framing_h2_h1.safe` | Framing H2 H1 test unavailable | `1.2.0` / `86f9a4f7e68b01069b13a1d34a20fc2361aa4522fba63958967d216c69c098f7` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_framing_line_ending.safe` | Framing Line Ending test unavailable | `1.2.0` / `c27be0fc82bf33579a79f49696d800d3e644c63f384ae4659324670665c1ee8b` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_framing_chunk_ext.safe` | Framing Chunk EXT test unavailable | `1.2.0` / `5d9b6565de655f2287bb70435826f0ba7e3dba24153c97f7f05a1919feeb4351` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_body_gzip.safe` | Body Gzip test unavailable | `1.2.0` / `d4e2a0b0f2f619fc10791caee49cb79443f9d6de7c8b4937a10effaf2f4e1d98` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_body_nested_encoding.safe` | Body Nested Encoding test unavailable | `1.2.0` / `aa98615248fb7db963834c8ff1dc819d95f156472e47f8524a1694dd0a8f50f0` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_content_type_binary.safe` | Content Type Binary test unavailable | `1.2.0` / `bf884feca3d7b855a6c564c9eb7b85846fcccbcbc68947503c5067fc3878775f` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_struct_type_confusion.safe` | Struct Type Confusion test unavailable | `1.2.0` / `4d08a592c1786108e5313281db9e6ebfe6f114484e2991d20285d20bcad7a15b` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_struct_deep_nesting.safe` | Struct Deep Nesting test unavailable | `1.2.0` / `e4dafe86ffc2cde8703710decefc8f5c7c7f7fbeb93f18386fac982524b34204` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_parameter_location.safe` | Parameter Location marker comparison | `1.2.0` / `d0f03fe3825168e8359868b530aaff4ef7875a8369286d5e74bcab433d67380e` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `supported_semantic_safe` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | protected, exposed, edge_protected, edge_exposed, allowed_as_expected, inconclusive; readiness-kind eligible only with exact proof |
| `waf.evasion_method_override.safe` | Method Override test unavailable | `1.2.0` / `4b4fa1770c3a3f31af624195cb1e27f5495e827aa7bbf0f87f08e539706826a7` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_protocol_version.safe` | Protocol Version test unavailable | `1.2.0` / `028a74172b50f5e6c60df4aa5fe20e88ed753868a5dc07365073df0e7734cf07` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_protocol_upgrade.safe` | Protocol Upgrade test unavailable | `1.2.0` / `7864cc5f8054f63f4e2d96edef7765596f01e40d1408ab2a33a7c7c82019632f` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; xss | inconclusive; readiness-kind excluded |
| `waf.evasion_benign_padding.safe` | Benign Padding marker comparison | `1.2.0` / `09bd4979de248e42b7692a331491209c43aade1464ee521b7a8f81d31c2821d1` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `supported_semantic_safe` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | protected, exposed, edge_protected, edge_exposed, allowed_as_expected, inconclusive; readiness-kind eligible only with exact proof |
| `waf.evasion_polyglot_content.safe` | Polyglot Content test unavailable | `1.2.0` / `d9cef08c3f85f578b4d6fbe9ff773755a3438718297c10081dca55fd49591179` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; xss | inconclusive; readiness-kind excluded |
| `waf.evasion_protocol_h3_h1.safe` | Protocol H3 H1 test unavailable | `1.2.0` / `2ca7cdfe4f07ae962fb1f974b3c13d4d49703e703a2d777ea1773bc175355ece` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_protocol_qpack_hpack.safe` | Protocol Qpack Hpack test unavailable | `1.2.0` / `e4313a9bee48cc172a277891f7be9785ec930495349bfd81b82e325c2bb12032` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | inconclusive; readiness-kind excluded |
| `waf.evasion_multipart_charset.safe` | Multipart Charset test unavailable | `1.2.0` / `4e17c75849ee58f4776216ec0074deb3a7e7ee1f7b75cd841270e76f68b0a534` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; xss | inconclusive; readiness-kind excluded |
| `waf.evasion_xml_attribute.safe` | XML Attribute test unavailable | `1.2.0` / `416b9078a7d849274c7927b5c248779dc0c0e974b75754bad4e34aa2fea3ae51` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `unsupported_delivery`: `unsupported_evasion_delivery` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; xss | inconclusive; readiness-kind excluded |
| `waf.inspection_limit.safe` | Body inspection unavailable | `1.1.1` / `57cc665a8f366d8ac09312ce0131a7dddf91fccdcfa18ee5cf84b66eb6867323` | `waf_inspection_limit_probe` / `probeWafInspectionLimit` | `unsupported_delivery`: `approved_business_safe_body_endpoint_required` | Unavailable: no approved business-safe body endpoint | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.evasion_cache_key_mismatch.posture` | Cache-key / routing mismatch declaration | `1.0.0` / `1b7da8ffc12db7d155918f385fe61b629c837c578e6b6bf3116cdd2f95bb67d8` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.evasion_reassembly_differential.posture` | IP fragmentation / TCP segmentation differential declaration | `1.0.0` / `522aa39b67334a79124b885929a3b1dde22096fcd8833a08388405a8c67278e3` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.evasion_rule_gap.posture` | Zero-day / rule-gap evasion declaration | `1.0.0` / `a2adee320dab2e726052552207396a8499a98a4936e4f1d274e30748bf5636bb` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.evasion_second_order.posture` | Stored / deferred second-order payload declaration | `1.0.0` / `7f2a69932179f425086fd4cd788f956cc6388c22ebd742dd340e2a27584f2f0d` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.evasion_encrypted_payload.posture` | Application-layer encrypted / opaque payload declaration | `1.0.0` / `ae83e24afe13e4ca1949ea6848bf8e9a3a0baa9bc652fd21cae40963d5f9ed22` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.evasion_signed_structured_data.posture` | Signed but malicious structured data declaration | `1.0.0` / `eb933d52218319835ea8a4f284f0ce2776a2d26c06d122509aef9d387d5923c8` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.evasion_connection_coalescing.posture` | Connection coalescing identity confusion declaration | `1.0.0` / `f8a1e92d0119f157d02f4b13cf503b1c778bd657a18a56e2138d20a5cfa0bd4d` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.evasion_ech_routing_metadata.posture` | Encrypted ClientHello / hidden routing-metadata gap declaration | `1.0.0` / `01225a4314882c6d02d6358a44f3fbfefca8037bfe7406c639a9dc2d24306713` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `l7.compressed_request_decompression.posture` | Compressed-body test unavailable | `1.0.1` / `d590fc4bd376ac99dd7207544f48b2c5db1202155d1f6f3b09855542df2c9854` | `l7_resource_posture_probe` / `probeDelegatedL7ResourcePosture` | `unsupported_delivery`: `approved_business_safe_body_endpoint_required` | Bounded URI/parameter-size observation; body plans unavailable | correlateObservationOnlyVerdict; declared_content_encoding | inconclusive; readiness-kind excluded |
| `l7.request_parser_size.posture` | Request URI / Parameter Size Limit Posture | `1.0.1` / `59439612083f2ad1646da3fe41675ea589ea21fd9dee95b0a9d85104255b6fbe` | `l7_resource_posture_probe` / `probeDelegatedL7ResourcePosture` | `supported_observation` | Bounded URI/parameter-size observation; body plans unavailable | correlateObservationOnlyVerdict; declared_oversize_uri | inconclusive; readiness-kind excluded |
| `waf.http_routing_trust.posture` | WAF HTTP Routing & Proxy-Trust declaration | `1.0.0` / `a8466ca943b972c3bc76d5f205b6362bd58307aa74cf86228c1a7eef9d86d7bb` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.jsonp_css_policy.posture` | WAF JSONP & CSS-Injection Policy declaration | `1.0.0` / `a5c44f68872af16cc4611bfbe2aeec97d8dc97f3850161bdee5153b57de4b46b` | `metadata_marker` / `probeMetadataMarker` | `declaration_only`: `metadata_only_check_has_no_executable_probe` | Stored declaration only; zero target traffic | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.sqli_managed_marker.safe` | SQLi marker comparison | `1.1.0` / `22896a75d1668f1a58ac5a9cb6fdeae380ce30a45bf0b28d19e4291f044f7f86` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_semantic_safe` | GET inert-token query/path/header placements and benign controls | markerComparisonComplete → correlateChallengeRedirectPenalty → correlateClassMarkerVerdict; sqli | protected, exposed, inconclusive; readiness-kind eligible only with exact proof |
| `waf.xss_managed_marker.safe` | XSS marker comparison | `1.1.0` / `f80ec1a67af17f1199ba0a0601099ea5592c9fb5ef1ab779df509ba58f636728` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_semantic_safe` | GET inert-token query/path/header placements and benign controls | markerComparisonComplete → correlateChallengeRedirectPenalty → correlateClassMarkerVerdict; xss | protected, exposed, inconclusive; readiness-kind eligible only with exact proof |
| `waf.path_traversal_managed_marker.safe` | Path-traversal marker comparison | `1.1.0` / `10c2347e6033003f95f48dedef5481e2c107a47c2c3d718763009c710725ca7d` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_semantic_safe` | GET inert-token query/path/header placements and benign controls | markerComparisonComplete → correlateChallengeRedirectPenalty → correlateClassMarkerVerdict; path_traversal | protected, exposed, inconclusive; readiness-kind eligible only with exact proof |
| `waf.ssti_marker.safe` | SSTI token observation | `1.1.0` / `dd0f2c61a638d12f9babc6e2489c1e4bd196efb37ccddb9b73d179bccc60ec67` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_observation` | GET inert-token query/path/header placements and benign controls | setup-required inert-token observation; ssti | inconclusive; readiness-kind excluded |
| `waf.scanner_signature_marker.safe` | Scanner User-Agent marker | `1.1.0` / `665022ab070b7a4b3a84d13cb4d00f371d9c136a3e0cd47633006143892fe580` | `waf_class_marker_probe` / `probeWafClassMarker` | `supported_semantic_safe` | GET inert scanner User-Agent and benign controls | markerComparisonComplete → correlateChallengeRedirectPenalty → correlateClassMarkerVerdict; scanner_user_agent | protected, exposed, inconclusive; readiness-kind eligible only with exact proof |
| `waf.evasion_double_url.safe` | Double URL marker comparison | `1.2.0` / `c735d9cfc18b429d30b40beb5244313a9a4f4f472d6fc4ef132813d8d23587f1` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `supported_semantic_safe` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | protected, exposed, edge_protected, edge_exposed, allowed_as_expected, inconclusive; readiness-kind eligible only with exact proof |
| `waf.evasion_mixed_url.safe` | Mixed URL marker comparison | `1.2.0` / `315901408ab6594a89e74ed2cb6e3a7b608240b1c34e0d14c903c8cde4a3f191` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `supported_semantic_safe` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | protected, exposed, edge_protected, edge_exposed, allowed_as_expected, inconclusive; readiness-kind eligible only with exact proof |
| `waf.evasion_case_fold.safe` | Case Fold marker comparison | `1.2.0` / `882319b5ba2bc6bea8ceeb98093b715695076c8c7a319bb81cc35c7a883b4505` | `waf_evasion_marker_probe` / `probeWafEvasionMarker` | `supported_semantic_safe` | Benign control, plain inert reference and supported transformed marker comparison | correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table; sqli | protected, exposed, edge_protected, edge_exposed, allowed_as_expected, inconclusive; readiness-kind eligible only with exact proof |
| `waf.http_method_policy_enforced.safe` | HTTP method enforcement | `1.2.0` / `7aecef8ad8057946950858c266e686fd224ccdcee695fb3a5da22cf7f149f20e` | `waf_method_policy_probe` / `probeWafMethodPolicy` | `supported_observation` | GET controls and bodyless TRACE/nonstandard-token method comparison | correlateMethodPolicyVerdict (E2 verdict, no readiness); none | protected, exposed, inconclusive; readiness-kind excluded |
| `waf.rate_limit_canary.validation` | WAF Rate-Limit Canary | `1.1.0` / `09822c67a3324bc6e32100e8616f2accc6f0cfa4b111a4d650d0b8006e359395` | `rate_limit_canary_probe` / `probeRateLimitCanary` | `supported_semantic_safe` | Bounded sequence on a declared low-threshold canary route | correlateRateLimitCanary; none | protected, exposed, inconclusive; readiness-kind eligible only with exact proof |
| `waf.body_json_marker.soc` | WAF JSON Body Marker request | `1.0.0` / `e8ac41a073b7e1bf2712f22fc4519b109a5c6021b6cd82c4e9c7a7d0848b2128` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.body_form_marker.soc` | WAF Form Body Marker request | `1.0.0` / `14ee0c6699ab527471c17d8b73e673bf835de5b51387ff2b27fea18237e3e947` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.body_multipart_marker.soc` | WAF Multipart Body Marker request | `1.0.0` / `982d69be7fad530a959795eea8d8a0a4df083cf9ce91eed518224dd9c7ad08f1` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.body_inspection_limit.soc` | WAF Body Inspection Limit request | `1.0.0` / `124a774cff4d0d49664f74a31da30c0b9c2d9a9f9521da2e786a8c24ec69f760` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `waf.response_dlp_canary.soc` | WAF Response DLP Canary request | `1.0.0` / `4bc0a7ea40ed90454cb9c3b684dfb91ed877a53dcdfa7a5a7d886a2d3f1bd531` | `null` / `none` | `soc_request_only`: `soc_gated_check` | Governed request only; no customer probe executor | correlateObservationOnlyVerdict; none | inconclusive; readiness-kind excluded |
| `nfw.declared_deny_tcp.safe` | Declared TCP Deny | `1.0.1` / `aeda167b4cdcd859630bbc9c06601f6151a0b8fe9fdcbf4d737bc304340f7969` | `tcp_connect` / `probeTcpConnect` | `additional_target_input`: `declared_tcp_deny_required` | Bounded TCP connection samples | correlateNfwViolation; none | inconclusive; readiness-kind excluded |
| `nfw.declared_deny_udp.safe` | Declared UDP Deny | `1.0.1` / `d3529c151da1447246aa9490998f45564be633f413a86e5c564eff4c8c8a5d1b` | `udp_probe` / `probeUdpDatagram` | `additional_target_input`: `declared_udp_deny_required` | Bounded UDP service samples | correlateNfwViolation; none | inconclusive; readiness-kind excluded |
| `nfw.management_port_exposure.safe` | Management and Database Port Exposure | `1.0.1` / `76fcb573c37df5c6322e255d7d8c7aa3deadf78bd2bb72e1cf938f9a2a69092a` | `port_scan_bounded` / `probePortScanBounded` | `supported_observation` | Bounded TCP connects to catalogued or declared ports | nfwPortResults → correlateNfwViolation; none | exposed, inconclusive; readiness-kind excluded |
| `nfw.ipv6_parity.safe` | IPv6/IPv4 Policy Parity | `1.0.1` / `ca18e017a9ce24701c40d14e66a152ff96bde6b32247888e1d1873f4fc0d5d10` | `tcp_connect` / `probeTcpConnect` | `supported_observation` | Bounded TCP connection samples | correlateNfwViolation; none | exposed, inconclusive; readiness-kind excluded |
| `nfw.connection_limit.safe` | Per-Source Connection Limit | `1.0.1` / `b1d931b7a25efae9efb2ba3baad77c36477bcd8a23ed2773c6f625e55729fb3b` | `connection_limit_probe` / `probeConnectionLimit` | `supported_observation` | Bounded connection acceptance samples | correlateNfwViolation; none | exposed, inconclusive; readiness-kind excluded |
| `nfw.origin_lockdown.safe` | Origin Lockdown to Declared Binding | `1.1.0` / `e40f6f9663889cc3338ab14b1a21a815d130bf465c33e04e299ca90a8570ad6e` | `host_sni_bypass` / `probeHostSniBypass` | `additional_target_input`: `declared_origin_lockdown_required` | One declared-address HTTP Host/SNI observation | correlateOriginLockdownVerdict; none | inconclusive; readiness-kind excluded |
| `nfw.perspective_allowlist.safe` | Multi-Perspective Allowlist | `1.0.1` / `c9c9f9fa3d4070feddc5d7b7177847d4f9bbb4fff59c2f9a1fa7a4dbb5e24742` | `tcp_connect` / `probeTcpConnect` | `additional_target_input`: `two_perspectives_required` | Bounded TCP connection samples | correlatePerspectiveAllowlist (registered-source override); requires two registered perspectives and declared denied source | inconclusive; readiness-kind excluded |

### Per-ID prerequisites, bounds and evidence

### origin.direct_reachability.safe

- Signed parameters: `{"kind":"host_sni_bypass","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_origin_target","literal_ip_target_for_signed_worker"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateOriginLockdownVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### origin.direct_bypass.safe

- Signed parameters: `{"kind":"host_sni_bypass","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_origin_target","literal_ip_target_for_signed_worker"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateOriginLockdownVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### origin.host_sni_bypass.safe

- Signed parameters: `{"kind":"host_sni_bypass","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_host_sni_target","literal_ip_target_for_signed_worker"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateOriginLockdownVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### origin.leak_scan.safe

- Signed parameters: `{"kind":"origin_leak_scan","max_requests":15,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_apex_domain"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":15,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.firewall_exposure_scan.safe

- Signed parameters: `{"kind":"port_scan_bounded","max_requests":15,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_scan_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":15,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → nfwPortResults → correlateNfwViolation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### path.protected_canary.safe

- Signed parameters: `{"kind":"http_head","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","method":"HEAD","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["full_canary_url_behind_protected_path"]`. Expected behavior: `must_reach_canary`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.forbidden_tcp_port.safe

- Signed parameters: `{"kind":"tcp_connect","max_requests":2,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_forbidden_tcp_port","expected_block_behavior"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.forbidden_udp_port.safe

- Signed parameters: `{"kind":"udp_probe","max_requests":2,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_forbidden_udp_port"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.basic_deny_rule.safe

- Signed parameters: `{"kind":"tcp_connect","max_requests":2,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_deny_rule_target","network_policy"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### dns.authoritative_response.safe

- Signed parameters: `{"kind":"dns_wire_query","max_requests":1,"timeout_ms":5000,"dns_qtype":"SOA","dns_transport":"udp","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_authoritative_zone"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### dns.random_prefix_nxdomain.safe

- Signed parameters: `{"kind":"dns_wire_query","max_requests":1,"timeout_ms":5000,"dns_qtype":"A","dns_transport":"udp","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_zone_for_random_prefix"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### dns.open_recursion_behavior.safe

- Signed parameters: `{"kind":"dns_open_recursion","max_requests":1,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_resolver_target"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.waf_marker_rule.safe

- Signed parameters: `{"kind":"waf_enforcement_probe","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false,"scenario_family":"marker","marker_type":"header","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint"],"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_waf_marker_rule"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.fingerprint.safe

- Signed parameters: `{"kind":"waf_fingerprint_observation","max_requests":4,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_family":"fingerprint","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint"],"follow_redirects":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_fingerprint_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":4,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.marker_rule.safe

- Signed parameters: `{"kind":"waf_enforcement_probe","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false,"scenario_family":"marker","marker_type":"header","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint"],"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_waf_marker_rule"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.origin_bypass.safe

- Signed parameters: `{"kind":"host_sni_bypass","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false,"scenario_family":"origin_bypass","marker_type":"header","expected_action":"block","nonce_hash_only":true,"collect":["status_code"],"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","declared_direct_origin_target","literal_ip_target_for_signed_worker",null]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateOriginLockdownVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.low_rate_limit.safe

- Signed parameters: `{"kind":"rate_limit_sequence","max_requests":5,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false,"scenario_family":"rate_limit_marker","marker_type":"header","expected_action":"rate_limit","nonce_hash_only":true,"collect":["status_code","waf_product_hint"],"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_rate_limit_threshold"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":5,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.http_method_restriction.safe

- Signed parameters: `{"kind":"http_method_matrix","max_requests":2,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["url_target_with_method_policy"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.header_size_boundary.safe

- Signed parameters: `{"kind":"header_size_probe","max_requests":2,"timeout_ms":5000,"oversize_header_bytes":8192,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["url_target"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.low_rate_rate_limit.safe

- Signed parameters: `{"kind":"rate_limit_sequence","max_requests":5,"timeout_ms":5000,"marker":"astranull-safe-marker","http_method":"HEAD","observation_only":true,"readiness_conclusion":false,"probe_path":"/","scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["customer_rate_limit_threshold"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":5,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### tls.profile_exposure.safe

- Signed parameters: `{"kind":"tls_audit","max_requests":1,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["tls_terminated_endpoint"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### protocol.http2_readiness.safe

- Signed parameters: `{"kind":"http2_settings","max_requests":1,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["http2_enabled_endpoint"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### protocol.http3_quic_exposure.safe

- Signed parameters: `{"kind":"quic_reachability","max_requests":1,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_quic_exposure_intent"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result","health_signal"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### ops.alert_workflow_marker.safe

- Signed parameters: `{"kind":"alert_webhook_ping","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["alert_webhook_or_siem_hook","approved_signed_alert_webhook_scope"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### ops.runbook_contact_validation.safe

- Signed parameters: `{"kind":"ops_readiness","max_requests":1,"timeout_ms":5000,"scenario":"runbook_contacts"}`.
- Prerequisites: `[]`. Customer setup: `["current_runbook_artifact","emergency_contact_roster"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result","runbook_version_audit","contact_ack_evidence"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateOpsReadinessVerdict (local declarations) → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### ops.kill_switch_drill.safe

- Signed parameters: `{"kind":"ops_readiness","max_requests":1,"timeout_ms":5000,"scenario":"kill_switch_readiness"}`.
- Prerequisites: `[]`. Customer setup: `["kill_switch_runbook","declared_drill_scope"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result","stop_event_audit"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateOpsReadinessVerdict (local declarations) → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.ipv6_reachability.safe

- Signed parameters: `{"kind":"tcp_connect","max_requests":2,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_ipv6_target","expected_ipv6_protection_behavior"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### dns.amplification_exposure.safe

- Signed parameters: `{"kind":"dns_wire_query","max_requests":1,"timeout_ms":5000,"dns_qtype":"ANY","dns_transport":"udp","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_authoritative_or_resolver_target","customer_amplification_policy_intent"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result","health_signal"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### dns.dnssec_expensive_query.safe

- Signed parameters: `{"kind":"dnssec_posture","max_requests":2,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_dns_query_type","authoritative_or_resolver_target"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### dns.secondary_failover.safe

- Signed parameters: `{"kind":"dns_failover_posture","max_requests":3,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_secondary_dns_targets","failover_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result","health_signal"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### dns.zone_transfer_exposure.safe

- Signed parameters: `{"kind":"dns_axfr_leak","max_requests":5,"timeout_ms":5000,"observation_only":false,"scenario_version":"marker-comparison-v4","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_zone_for_axfr_check","customer_authorizes_axfr_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":5,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateAxfrVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: One confirmed transfer can establish exposure; protection requires every declared nameserver to refuse. No DNS resilience or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.cache_busting.safe

- Signed parameters: `{"kind":"cache_abuse_probe","max_requests":3,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_cache_bust_path","cache_policy_expectation"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":5,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.expensive_endpoint.safe

- Signed parameters: `{"kind":"http_head","max_requests":1,"timeout_ms":5000,"method":"HEAD","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_expensive_endpoint_url","expected_rate_or_challenge_behavior"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.login_abuse_flow.safe

- Signed parameters: `{"kind":"rate_limit_sequence","max_requests":5,"timeout_ms":5000,"marker":"astranull-safe-marker","http_method":"HEAD","observation_only":true,"readiness_conclusion":false,"nonce_hash_only":true,"probe_path":"/","scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_login_probe_path","isolated_synthetic_test_identity","customer_approves_auth_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.password_reset.safe

- Signed parameters: `{"kind":"http_head","max_requests":1,"timeout_ms":5000,"method":"HEAD","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_password_reset_endpoint","isolated_synthetic_test_identity"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.api_quota_exhaustion.safe

- Signed parameters: `{"kind":"rate_limit_sequence","max_requests":5,"timeout_ms":5000,"marker":"astranull-safe-marker","http_method":"GET","observation_only":true,"readiness_conclusion":false,"probe_path":"/","scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_api_probe_path","test_api_identity_or_key_scope"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":5,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.graphql_complexity.safe

- Signed parameters: `{"kind":"graphql_posture_probe","max_requests":1,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"graphql_path":"/graphql","scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_graphql_endpoint","customer_provided_safe_query_descriptor"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.bot_challenge_marker.safe

- Signed parameters: `{"kind":"bot_challenge_probe","max_requests":1,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_protected_url","bot_management_expectation"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### tls.slow_header_body_timeout.safe

- Signed parameters: `{"kind":"slow_header_probe","max_requests":1,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["tls_terminated_endpoint","declared_idle_or_slow_client_policy"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### tls.idle_connection_timeout.safe

- Signed parameters: `{"kind":"tls_session","max_requests":1,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["tls_terminated_endpoint","connection_idle_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result","health_signal"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### protocol.http2_rapid_reset_readiness.safe

- Signed parameters: `{"kind":"http2_settings","max_requests":1,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["http2_enabled_endpoint","rapid_reset_mitigation_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result","health_signal"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### protocol.http2_stream_concurrency.safe

- Signed parameters: `{"kind":"http2_settings","max_requests":1,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["http2_enabled_endpoint","stream_limit_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### protocol.grpc_reflection_stream.safe

- Signed parameters: `{"kind":"grpc_reflection_probe","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_grpc_endpoint","grpc_reflection_policy_intent"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result","health_signal"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### protocol.websocket_connection_controls.safe

- Signed parameters: `{"kind":"websocket_upgrade_posture","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_websocket_endpoint","connection_limit_expectation"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### tls.full_audit.safe

- Signed parameters: `{"kind":"tls_audit","max_requests":1,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["tls_terminated_endpoint"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.api_surface_scan.safe

- Signed parameters: `{"kind":"api_surface_scan","max_requests":8,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_api_base_url"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.cors_posture.safe

- Signed parameters: `{"kind":"cors_posture_probe","max_requests":1,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_api_base_url"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.enforcement.safe

- Signed parameters: `{"kind":"waf_enforcement_probe","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_waf_marker_rule"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.connection_table_exhaustion.request_only

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["soc_authorization_pack","declared_target_group_scope","connection_limit_abort_criteria"]`. Expected behavior: `soc_approval_required`.
- Safety bounds: `{"customer_runnable":false}`. Evidence: `["approval_artifact","provider_telemetry","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### high_scale.dns_high_query.request_only

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["soc_authorization_pack","declared_dns_zone_scope","provider_approval_artifact"]`. Expected behavior: `soc_approval_required`.
- Safety bounds: `{"customer_runnable":false}`. Evidence: `["approval_artifact","provider_telemetry","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### ops.runbook_contact_validation.request_only

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["current_runbook_artifact","emergency_contact_roster","soc_authorization_pack"]`. Expected behavior: `soc_approval_required`.
- Safety bounds: `{"customer_runnable":false}`. Evidence: `["approval_artifact","runbook_version_audit","contact_ack_evidence"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### ops.kill_switch_drill.request_only

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["soc_authorization_pack","kill_switch_runbook","declared_drill_scope"]`. Expected behavior: `soc_approval_required`.
- Safety bounds: `{"customer_runnable":false}`. Evidence: `["approval_artifact","stop_event_audit","adapter_confirmation"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### ops.provider_telemetry.request_only

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["provider_approval_artifact","telemetry_endpoint_declaration","soc_authorization_pack"]`. Expected behavior: `soc_approval_required`.
- Safety bounds: `{"customer_runnable":false}`. Evidence: `["provider_telemetry","approval_artifact","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### high_scale.multi_vector.request_only

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["soc_authorization_pack","multi_vector_scope_declaration","provider_approval_artifact"]`. Expected behavior: `soc_approval_required`.
- Safety bounds: `{"customer_runnable":false}`. Evidence: `["approval_artifact","provider_telemetry","soc_runbook_ack","coordination_audit"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### high_scale.degradation_recovery.request_only

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["soc_authorization_pack","recovery_runbook","declared_degradation_objectives"]`. Expected behavior: `soc_approval_required`.
- Safety bounds: `{"customer_runnable":false}`. Evidence: `["approval_artifact","health_signal","post_test_report","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### high_scale.volumetric.request_only

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["soc_authorization_pack","declared_target_group_scope","provider_approval_artifact"]`. Expected behavior: `soc_approval_required`.
- Safety bounds: `{"customer_runnable":false}`. Evidence: `["approval_artifact","provider_telemetry","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.offensive_sqli.soc

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["waf_offensive_authorization_pack","declared_waf_asset","staging_isolation"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"customer_runnable":false,"max_requests":12}`. Evidence: `["approval_artifact","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.offensive_xss.soc

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["waf_offensive_authorization_pack","declared_waf_asset","staging_isolation"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"customer_runnable":false,"max_requests":12}`. Evidence: `["approval_artifact","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.offensive_rce.soc

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["waf_offensive_authorization_pack","declared_waf_asset","staging_isolation"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"customer_runnable":false,"max_requests":8}`. Evidence: `["approval_artifact","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.offensive_path_traversal.soc

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["waf_offensive_authorization_pack","declared_waf_asset","staging_isolation"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"customer_runnable":false,"max_requests":10}`. Evidence: `["approval_artifact","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.offensive_command_injection.soc

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["waf_offensive_authorization_pack","declared_waf_asset","staging_isolation"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"customer_runnable":false,"max_requests":8}`. Evidence: `["approval_artifact","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.offensive_ldap_injection.soc

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["waf_offensive_authorization_pack","declared_waf_asset","staging_isolation"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"customer_runnable":false,"max_requests":6}`. Evidence: `["approval_artifact","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.offensive_ssti.soc

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["waf_offensive_authorization_pack","declared_waf_asset","staging_isolation"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"customer_runnable":false,"max_requests":6}`. Evidence: `["approval_artifact","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.offensive_combined.soc

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["waf_offensive_authorization_pack","declared_waf_asset","staging_isolation"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"customer_runnable":false,"max_requests":24}`. Evidence: `["approval_artifact","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### high_scale.application.request_only

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["soc_authorization_pack","declared_l7_scope","provider_approval_artifact"]`. Expected behavior: `soc_approval_required`.
- Safety bounds: `{"customer_runnable":false}`. Evidence: `["approval_artifact","provider_telemetry","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.icmp_flood.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["icmp_filtering_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.gre_esp_flood.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["tunnel_protocol_filtering_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.ipv6_volumetric.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["ipv6_protection_parity_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.sip_voip_flood.readiness

- Signed parameters: `{"kind":"udp_probe","max_requests":2,"timeout_ms":5000,"default_port":5060,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_sip_port","sip_filtering_expectation"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.sctp_exposure.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["sctp_filtering_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.multicast_broadcast_storm.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["broadcast_suppression_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.ack_flood.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["stateful_filtering_declaration","pps_budget_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.rst_flood.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["rst_filtering_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.syn_ack_flood.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["syn_ack_filtering_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.tcp_flag_anomaly.readiness

- Signed parameters: `{"kind":"tcp_connect","max_requests":2,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["flag_anomaly_filtering_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The current entry lacks the required declared port or deny policy. No connection-flood validation or protection conclusion. Next: Provide the required declared target and port or deny policy before an explicitly authorized bounded retest.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.out_of_state_tcp.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["stateful_firewall_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.fragmentation_flood.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["fragment_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.syn_flood.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["syn_protection_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.tcp_connection_flood.readiness

- Signed parameters: `{"kind":"tcp_connect","max_requests":2,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["concurrent_connection_budget_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The current entry lacks the required declared port or deny policy. No connection-flood validation or protection conclusion. Next: Provide the required declared target and port or deny policy before an explicitly authorized bounded retest.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.nat_state_table.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["nat_capacity_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.smtp_connection_flood.readiness

- Signed parameters: `{"kind":"tcp_connect","max_requests":2,"timeout_ms":5000,"default_port":25,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_smtp_port","smtp_limits_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.ssh_connection_flood.readiness

- Signed parameters: `{"kind":"tcp_connect","max_requests":2,"timeout_ms":5000,"default_port":22,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_ssh_port","ssh_limits_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.ftp_connection_flood.readiness

- Signed parameters: `{"kind":"tcp_connect","max_requests":2,"timeout_ms":5000,"default_port":21,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_ftp_port","ftp_limits_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l3.ike_ipsec_negotiation.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["ike_rate_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.connection_hoarding.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["app_connection_limits_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### exploit.ping_of_death.posture

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["edge_filtering_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### exploit.teardrop.posture

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["fragment_validation_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### exploit.ip_options.posture

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["ip_options_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### exploit.malformed_quic.posture

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["quic_edge_version_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### exploit.land_attack.posture

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["anti_spoofing_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### exploit.quic_migration.posture

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["quic_migration_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.ssdp_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":3000,"service_port":1900,"payload_profile":"ssdp_msearch","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_ssdp_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `ssdp_msearch`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.snmp_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":3000,"service_port":161,"payload_profile":"snmp_v2c_get_sysdescr","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_snmp_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `snmp_v2c_get_sysdescr`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.chargen_qotd_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":3000,"service_port":19,"payload_profile":"chargen_trigger","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_chargen_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `chargen_trigger`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.mdns_netbios_wsdiscovery_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":4,"timeout_ms":3000,"service_port":5353,"payload_profile":"mdns_ptr_query","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"payload_profiles":["mdns_ptr_query","netbios_nbstat","ws_discovery_probe"],"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_mdns_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":4,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `mdns_ptr_query`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.portmap_service_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":3000,"service_port":111,"payload_profile":"portmap_dump","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_portmap_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `portmap_dump`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.dtls_sip_rdp_tftp_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":4,"timeout_ms":3000,"service_port":69,"payload_profile":"tftp_read_request","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"payload_profiles":["tftp_read_request","dtls_client_hello","sip_options","rdp_udp_syn"],"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_tftp_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":4,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `tftp_read_request`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.quic_reflection_exposure.safe

- Signed parameters: `{"kind":"quic_reachability","max_requests":1,"timeout_ms":3000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_quic_exposure_intent"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.tcp_middlebox_exposure.safe

- Signed parameters: `{"kind":"tcp_connect","max_requests":2,"timeout_ms":3000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_tcp_fingerprint_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The current entry lacks the required declared port or deny policy. No connection-flood validation or protection conclusion. Next: Provide the required declared target and port or deny policy before an explicitly authorized bounded retest.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.mssql_resolver_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":3000,"service_port":1434,"payload_profile":"mssql_resolution_request","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_mssql_resolver_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `mssql_resolution_request`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.jenkins_discovery_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":3000,"service_port":33848,"payload_profile":"jenkins_discovery","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_jenkins_discovery_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `jenkins_discovery`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.coap_iot_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":3000,"service_port":5683,"payload_profile":"coap_get_wellknown","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_coap_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `coap_get_wellknown`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.legacy_device_discovery_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":3000,"service_port":3702,"payload_profile":"ws_discovery_probe","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_ws_discovery_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `ws_discovery_probe`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.stun_turn_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":3000,"service_port":3478,"payload_profile":"stun_binding_request","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_stun_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `stun_binding_request`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.ipmi_bmc_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":3000,"service_port":623,"payload_profile":"ipmi_rmcp_ping","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_ipmi_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `ipmi_rmcp_ping`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.redis_direct_exposure.safe

- Signed parameters: `{"kind":"tcp_connect","max_requests":2,"timeout_ms":3000,"default_port":6379,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_tcp_fingerprint_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.openvpn_wireguard_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":3000,"service_port":1194,"payload_profile":"openvpn_reset","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_openvpn_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `openvpn_reset`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### amp.ntp_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":5000,"service_port":123,"payload_profile":"ntp_mode6_readvar","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_ntp_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `ntp_mode6_readvar`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### amp.cldap_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":5000,"service_port":389,"payload_profile":"cldap_root_dse","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_cldap_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `cldap_root_dse`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### amp.memcached_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":3000,"service_port":11211,"payload_profile":"memcached_udp_stats","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_memcached_udp_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `memcached_udp_stats`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### amp.dns_any_txt_exposure.safe

- Signed parameters: `{"kind":"dns_wire_query","max_requests":2,"timeout_ms":5000,"dns_qtype":"TXT","dns_transport":"udp","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_dns_zone"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### amp.smurf_broadcast_exposure.safe

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["broadcast_filtering_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### amp.authoritative_resolver_exposure.safe

- Signed parameters: `{"kind":"dns_wire_query","max_requests":2,"timeout_ms":5000,"dns_qtype":"NS","dns_transport":"udp","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_dns_zone","rrl_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### dns.laundering.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_dns_zone","resolver_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### dns.garbage_flood.readiness

- Signed parameters: `{"kind":"dns_wire_query","max_requests":3,"timeout_ms":5000,"dns_qtype":"A","dns_transport":"udp","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_dns_zone"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### dns.phantom_domain.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["resolver_timeout_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### dns.domain_lockup.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["resolver_loop_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### dns.nxns_attack.readiness

- Signed parameters: `{"kind":"dns_wire_query","max_requests":2,"timeout_ms":5000,"dns_qtype":"NS","dns_transport":"udp","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_dns_zone"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### dns.dnsbomb.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_dns_zone","dns_telemetry_endpoint_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result","provider_telemetry"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### dns.qname_minimization.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["resolver_qname_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### dns.doh_dot_exposure.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_doh_dot_endpoints"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### dns.tcp_fallback.readiness

- Signed parameters: `{"kind":"dns_wire_query","max_requests":2,"timeout_ms":5000,"dns_qtype":"ANY","dns_transport":"tcp","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_dns_zone"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### dns.zone_walking.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_dns_zone","dnssec_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.http_get_flood.validation

- Signed parameters: `{"kind":"rate_limit_sequence","max_requests":5,"timeout_ms":5000,"http_method":"GET","observation_only":true,"readiness_conclusion":false,"probe_path":"/","scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["rps_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":5,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.http_post_flood.validation

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_post_endpoints","post_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.slowloris.readiness

- Signed parameters: `{"kind":"slow_header_probe","max_requests":1,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["header_timeout_declaration","header_timeout_at_or_below_probe_window"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.slow_post.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["body_timeout_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.slow_read.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["response_timeout_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.low_and_slow.readiness

- Signed parameters: `{"kind":"slow_header_probe","max_requests":1,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["header_timeout_declaration","header_timeout_at_or_below_probe_window"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.large_body_post.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["body_size_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.file_upload_abuse.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_upload_endpoints","upload_limits_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.json_xml_bomb.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["parser_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.search_abuse.validation

- Signed parameters: `{"kind":"rate_limit_sequence","max_requests":5,"timeout_ms":5000,"http_method":"GET","observation_only":true,"readiness_conclusion":false,"probe_path":"/","scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_search_probe_path","search_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":5,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.export_abuse.validation

- Signed parameters: `{"kind":"rate_limit_sequence","max_requests":5,"timeout_ms":5000,"http_method":"GET","observation_only":true,"readiness_conclusion":false,"probe_path":"/","scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_export_probe_path","export_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":5,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.batch_api_abuse.validation

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_batch_endpoints","batch_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.oauth_token_abuse.validation

- Signed parameters: `{"kind":"rate_limit_sequence","max_requests":5,"timeout_ms":5000,"http_method":"HEAD","observation_only":true,"readiness_conclusion":false,"nonce_hash_only":true,"probe_path":"/","scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_token_probe_path","token_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":5,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.checkout_abuse.validation

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_checkout_endpoints","checkout_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.otp_sms_cost.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["otp_budget_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.signup_registration_abuse.validation

- Signed parameters: `{"kind":"rate_limit_sequence","max_requests":5,"timeout_ms":5000,"http_method":"HEAD","observation_only":true,"readiness_conclusion":false,"nonce_hash_only":true,"probe_path":"/","scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_signup_probe_path","signup_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":5,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.elasticsearch_abuse.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["search_cluster_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.health_check_flood.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["health_endpoint_declaration","autoscaling_guardrail_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.wordpress_xmlrpc.readiness

- Signed parameters: `{"kind":"http_head","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","method":"HEAD","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["xmlrpc_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.webhook_flood.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["webhook_budget_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.http_pipelining.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["pipelining_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.http_range_abuse.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["range_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.conditional_revalidation.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["revalidation_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.captcha_challenge_abuse.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["challenge_budget_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.mqtt_broker_exposure.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["mqtt_broker_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.redos.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["regex_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.graphql_batch_abuse.validation

- Signed parameters: `{"kind":"graphql_posture_probe","max_requests":1,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["graphql_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### tls.handshake_rate.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["handshake_budget_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### tls.renegotiation.readiness

- Signed parameters: `{"kind":"tls_session","max_requests":1,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["tls_endpoint_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### tls.zero_rtt.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["early_data_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### tls.ocsp_stapling.readiness

- Signed parameters: `{"kind":"tls_audit","max_requests":1,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["tls_endpoint_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.http2_rapid_reset.validation

- Signed parameters: `{"kind":"http2_frame_probe","max_requests":4,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["http2_enabled_endpoint","rapid_reset_mitigation_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result","health_signal"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.http2_made_you_reset.readiness

- Signed parameters: `{"kind":"http2_frame_probe","max_requests":4,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["http2_enabled_endpoint","flow_control_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result","health_signal"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.http2_continuation.readiness

- Signed parameters: `{"kind":"http2_frame_probe","max_requests":4,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["http2_enabled_endpoint","header_frame_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result","health_signal"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.http2_priority_abuse.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["priority_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.hpack_bomb.readiness

- Signed parameters: `{"kind":"http2_frame_probe","max_requests":1,"timeout_ms":5000,"settings_assertion":"hpack_limits","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["http2_enabled_endpoint","hpack_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":1,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `hpack_limits`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.http2_push_promise.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["push_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.qpack_bomb.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["qpack_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### protocol.sse_stream.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["sse_policy_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### protocol.http3_control_stream.readiness

- Signed parameters: `{"kind":"http3_control_probe","max_requests":1,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["http3_endpoint_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### protocol.websocket_message_rate.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["websocket_rate_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### origin.cdn_bypass.readiness

- Signed parameters: `{"kind":"origin_leak_scan","max_requests":15,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_apex_domain","declared_cdn_hostnames"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":15,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### origin.dns_hostname_bypass.readiness

- Signed parameters: `{"kind":"origin_leak_scan","max_requests":15,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_apex_domain","declared_hostname_inventory"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":15,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### pattern.carpet_bombing.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["scrubbing_coverage_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### pattern.pulse_wave.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["pulse_readiness_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### pattern.spoofed_source.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["ingress_filtering_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### pattern.ransom_ddos.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["extortion_runbook_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### pattern.rate_limit_evasion.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["aggregate_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### pattern.adaptive_evasion.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["behavioral_detection_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### pattern.residential_proxy.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["asn_reputation_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### ops.autoscaling_cost.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["autoscaling_budget_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### ops.attack_alert_coverage.readiness

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false}`.
- Prerequisites: `[]`. Customer setup: `["alert_route_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.slp_amplification_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":3000,"service_port":427,"payload_profile":"slp_srvrqst","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_slp_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `slp_srvrqst`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.tp240_amplification_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":3000,"service_port":10074,"payload_profile":"tp240_status_request","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_tp240_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `tp240_status_request`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.l2tp_reflection_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":3000,"service_port":1701,"payload_profile":"l2tp_sccrq","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_l2tp_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `l2tp_sccrq`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.natpmp_amplification_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":3000,"service_port":5351,"payload_profile":"natpmp_external_address","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_natpmp_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `natpmp_external_address`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### reflect.ipp_callback_exposure.safe

- Signed parameters: `{"kind":"reflection_service_probe","max_requests":1,"timeout_ms":3000,"service_port":631,"payload_profile":"ipp_get_printer_attributes","expected_response_shape":"amplifying_response","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_ipp_responder_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → correlateReflectorExposure → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `ipp_get_printer_attributes`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### dns.multi_question_oversized.safe

- Signed parameters: `{"kind":"dns_wire_query","max_requests":1,"timeout_ms":5000,"dns_qtype":"NS","dns_transport":"tcp","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_zone_for_parser_posture"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":3,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.http_method_policy_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"http_method_policy","marker":"astranull-method-policy-probe-TRACK-inert","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","marker_probes","posture_status"],"observation_only":true,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"assurance_scope":"custom_canary_rule","produces_verdict":false,"readiness_conclusion":false,"setup_required":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → setup-required inert-token observation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `http_method_policy`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: No exact installed-token rule binding exists in current declarations. No attack-method test, installed-rule failure finding or readiness credit. Next: Review the recorded token response. Exact installed-rule validation is unavailable; do not infer failure or configure unrelated controls as a substitute.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.request_smuggling_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"request_smuggling","marker":"astranull-smuggle-probe-CL0TE-inert","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","marker_probes","posture_status"],"observation_only":true,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"assurance_scope":"custom_canary_rule","produces_verdict":false,"readiness_conclusion":false,"setup_required":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → setup-required inert-token observation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `request_smuggling`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: No exact installed-token rule binding exists in current declarations. No attack-method test, installed-rule failure finding or readiness credit. Next: Review the recorded token response. Exact installed-rule validation is unavailable; do not infer failure or configure unrelated controls as a substitute.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.crlf_injection_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"crlf","marker":"astranull-crlf-probe%0d%0aX-Astranull-Probe:inert","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","marker_probes","posture_status"],"observation_only":true,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"assurance_scope":"custom_canary_rule","produces_verdict":false,"readiness_conclusion":false,"setup_required":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → setup-required inert-token observation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `crlf`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: No exact installed-token rule binding exists in current declarations. No attack-method test, installed-rule failure finding or readiness credit. Next: Review the recorded token response. Exact installed-rule validation is unavailable; do not infer failure or configure unrelated controls as a substitute.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.open_redirect_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"open_redirect","marker":"astranull-redirect-marker-inert","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","marker_probes","posture_status"],"observation_only":true,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"assurance_scope":"custom_canary_rule","produces_verdict":false,"readiness_conclusion":false,"setup_required":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → setup-required inert-token observation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `open_redirect`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: No exact installed-token rule binding exists in current declarations. No attack-method test, installed-rule failure finding or readiness credit. Next: Review the recorded token response. Exact installed-rule validation is unavailable; do not infer failure or configure unrelated controls as a substitute.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.nosql_injection_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"nosql","marker":"$ne:astranull-nosql-probe-inert","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","marker_probes","posture_status"],"observation_only":true,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"assurance_scope":"custom_canary_rule","produces_verdict":false,"readiness_conclusion":false,"setup_required":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → setup-required inert-token observation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `nosql`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: No exact installed-token rule binding exists in current declarations. No attack-method test, installed-rule failure finding or readiness credit. Next: Review the recorded token response. Exact installed-rule validation is unavailable; do not infer failure or configure unrelated controls as a substitute.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.xpath_injection_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"xpath","marker":"astranull-xpath-probe' and '1'='0","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","marker_probes","posture_status"],"observation_only":true,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"assurance_scope":"custom_canary_rule","produces_verdict":false,"readiness_conclusion":false,"setup_required":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → setup-required inert-token observation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `xpath`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: No exact installed-token rule binding exists in current declarations. No attack-method test, installed-rule failure finding or readiness credit. Next: Review the recorded token response. Exact installed-rule validation is unavailable; do not infer failure or configure unrelated controls as a substitute.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.jndi_ldap_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"ldap","marker":"astranull-ldap-marker-inert","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","marker_probes","posture_status"],"observation_only":true,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"assurance_scope":"custom_canary_rule","produces_verdict":false,"readiness_conclusion":false,"setup_required":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → setup-required inert-token observation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `ldap`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: No exact installed-token rule binding exists in current declarations. No attack-method test, installed-rule failure finding or readiness credit. Next: Review the recorded token response. Exact installed-rule validation is unavailable; do not infer failure or configure unrelated controls as a substitute.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.csv_formula_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"csv_injection","marker":"astranull-csv-marker-inert","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","marker_probes","posture_status"],"observation_only":true,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"assurance_scope":"custom_canary_rule","produces_verdict":false,"readiness_conclusion":false,"setup_required":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → setup-required inert-token observation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `csv_injection`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: No exact installed-token rule binding exists in current declarations. No attack-method test, installed-rule failure finding or readiness credit. Next: Review the recorded token response. Exact installed-rule validation is unavailable; do not infer failure or configure unrelated controls as a substitute.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.prototype_pollution_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"prototype_pollution","marker":"astranull-prototype-marker-inert","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","marker_probes","posture_status"],"observation_only":true,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"assurance_scope":"custom_canary_rule","produces_verdict":false,"readiness_conclusion":false,"setup_required":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → setup-required inert-token observation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `prototype_pollution`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: No exact installed-token rule binding exists in current declarations. No attack-method test, installed-rule failure finding or readiness credit. Next: Review the recorded token response. Exact installed-rule validation is unavailable; do not infer failure or configure unrelated controls as a substitute.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.deserialization_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"deserialization","marker":"rO0ABQ-astranull-deser-probe-INERT","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","marker_probes","posture_status"],"observation_only":true,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"assurance_scope":"custom_canary_rule","produces_verdict":false,"readiness_conclusion":false,"setup_required":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → setup-required inert-token observation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `deserialization`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: No exact installed-token rule binding exists in current declarations. No attack-method test, installed-rule failure finding or readiness credit. Next: Review the recorded token response. Exact installed-rule validation is unavailable; do not infer failure or configure unrelated controls as a substitute.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.ssrf_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"ssrf","marker":"astranull-ssrf-marker-inert","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","marker_probes","posture_status"],"observation_only":true,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"assurance_scope":"custom_canary_rule","produces_verdict":false,"readiness_conclusion":false,"setup_required":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → setup-required inert-token observation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `ssrf`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: No exact installed-token rule binding exists in current declarations. No attack-method test, installed-rule failure finding or readiness credit. Next: Review the recorded token response. Exact installed-rule validation is unavailable; do not infer failure or configure unrelated controls as a substitute.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.xxe_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"xxe","marker":"astranull-xxe-marker-inert","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","marker_probes","posture_status"],"observation_only":true,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"assurance_scope":"custom_canary_rule","produces_verdict":false,"readiness_conclusion":false,"setup_required":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → setup-required inert-token observation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `xxe`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: No exact installed-token rule binding exists in current declarations. No attack-method test, installed-rule failure finding or readiness credit. Next: Review the recorded token response. Exact installed-rule validation is unavailable; do not infer failure or configure unrelated controls as a substitute.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.file_upload_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"file_upload_marker","marker":"astranull-upload-probe.php.txt","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","marker_probes","posture_status"],"observation_only":true,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"assurance_scope":"custom_canary_rule","produces_verdict":false,"readiness_conclusion":false,"setup_required":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → setup-required inert-token observation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `file_upload_marker`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: No exact installed-token rule binding exists in current declarations. No attack-method test, installed-rule failure finding or readiness credit. Next: Review the recorded token response. Exact installed-rule validation is unavailable; do not infer failure or configure unrelated controls as a substitute.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.jwt_tamper_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"jwt_tamper","marker":"eyJhbGciOiJub25lIiwiYXN0cmFudWxsIjoicCJ9.eyJhc3RyYW51bGwiOiJqd3QtaW5lcnQifQ.astranull-jwt-inert","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","marker_probes","posture_status"],"observation_only":true,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"assurance_scope":"custom_canary_rule","produces_verdict":false,"readiness_conclusion":false,"setup_required":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → setup-required inert-token observation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `jwt_tamper`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: No exact installed-token rule binding exists in current declarations. No attack-method test, installed-rule failure finding or readiness credit. Next: Review the recorded token response. Exact installed-rule validation is unavailable; do not infer failure or configure unrelated controls as a substitute.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.entry_path_login_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"sqli","marker":"astranull' OR '1'='0","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","marker_probes","posture_status"],"entry_path_scenario":"declared_login_path","observation_only":false,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"assurance_scope":"managed_rule_marker","produces_verdict":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe","declared_login_entry_path"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → markerComparisonComplete → correlateChallengeRedirectPenalty → correlateClassMarkerVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `declared_login_path`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.entry_path_api_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"sqli","marker":"astranull' OR '1'='0","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","marker_probes","posture_status"],"entry_path_scenario":"declared_api_path","observation_only":false,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"assurance_scope":"managed_rule_marker","produces_verdict":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe","declared_api_entry_path"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → markerComparisonComplete → correlateChallengeRedirectPenalty → correlateClassMarkerVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `declared_api_path`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_unicode_normalization.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"unicode_normalization","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":false,"scenario_version":"marker-comparison-v4","delivery_supported":true,"requires_complete_comparison":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_homoglyph.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"homoglyph","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":false,"scenario_version":"marker-comparison-v4","delivery_supported":true,"requires_complete_comparison":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_overlong_utf8.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"overlong_utf8","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":false,"scenario_version":"marker-comparison-v4","delivery_supported":true,"requires_complete_comparison":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_alt_charset.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"alt_charset","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_html_entity.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"<astranull-xss-probe/>","evasion_transform":"html_entity","marker_class":"xss","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":false,"scenario_version":"marker-comparison-v4","delivery_supported":true,"requires_complete_comparison":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `xss`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_js_escape.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"<astranull-xss-probe/>","evasion_transform":"js_escape","marker_class":"xss","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":false,"scenario_version":"marker-comparison-v4","delivery_supported":true,"requires_complete_comparison":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `xss`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_json_unicode_escape.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"<astranull-xss-probe/>","evasion_transform":"json_unicode_escape","marker_class":"xss","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `xss`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_css_escape.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"<astranull-xss-probe/>","evasion_transform":"css_escape","marker_class":"xss","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":false,"scenario_version":"marker-comparison-v4","delivery_supported":true,"requires_complete_comparison":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `xss`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_base64_wrap.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"base64_wrap","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":false,"scenario_version":"marker-comparison-v4","delivery_supported":true,"requires_complete_comparison":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_numeric_repr.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"numeric_repr","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":false,"scenario_version":"marker-comparison-v4","delivery_supported":true,"requires_complete_comparison":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_whitespace.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"whitespace","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":false,"scenario_version":"marker-comparison-v4","delivery_supported":true,"requires_complete_comparison":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_lexical_operator.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"lexical_operator","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_lexical_tautology.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"lexical_tautology","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_lexical_literal.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"lexical_literal","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_control_char.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"control_char","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":false,"scenario_version":"marker-comparison-v4","delivery_supported":true,"requires_complete_comparison":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_path_matrix.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"../../astranull-probe","evasion_transform":"path_matrix","marker_class":"path_traversal","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `path_traversal`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_path_suffix.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"../../astranull-probe","evasion_transform":"path_suffix","marker_class":"path_traversal","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `path_traversal`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_ip_representation.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"ip_representation","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_parser_hpp.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"parser_hpp","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":false,"scenario_version":"marker-comparison-v4","delivery_supported":true,"requires_complete_comparison":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_parser_json_dup.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"parser_json_dup","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_parser_header_dup.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"parser_header_dup","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_framing_cl_te.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"framing_cl_te","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_framing_transfer_coding.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"framing_transfer_coding","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_framing_h2_h1.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"framing_h2_h1","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_framing_line_ending.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"framing_line_ending","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_framing_chunk_ext.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"framing_chunk_ext","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_body_gzip.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"body_gzip","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_body_nested_encoding.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"body_nested_encoding","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_content_type_binary.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"content_type_binary","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_struct_type_confusion.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"struct_type_confusion","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_struct_deep_nesting.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"struct_deep_nesting","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_parameter_location.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"parameter_location","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":false,"scenario_version":"marker-comparison-v4","delivery_supported":true,"requires_complete_comparison":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_method_override.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"method_override","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_protocol_version.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"protocol_version","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_protocol_upgrade.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"<astranull-xss-probe/>","evasion_transform":"protocol_upgrade","marker_class":"xss","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `xss`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_benign_padding.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"benign_padding","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":false,"scenario_version":"marker-comparison-v4","delivery_supported":true,"requires_complete_comparison":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_polyglot_content.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"<astranull-xss-probe/>","evasion_transform":"polyglot_content","marker_class":"xss","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `xss`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_protocol_h3_h1.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"protocol_h3_h1","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_protocol_qpack_hpack.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"protocol_qpack_hpack","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_multipart_charset.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"<astranull-xss-probe/>","evasion_transform":"multipart_charset","marker_class":"xss","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `xss`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_xml_attribute.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"<astranull-xss-probe/>","evasion_transform":"xml_attribute","marker_class":"xss","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `xss`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.inspection_limit.safe

- Signed parameters: `{"kind":"waf_inspection_limit_probe","max_requests":6,"timeout_ms":5000,"marker":"astranull-safe-marker","scenario_family":"marker","marker_type":"query","expected_action":"block","http_method":"HEAD","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":6,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_cache_key_mismatch.posture

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker"}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","declared_cache_key_normalization"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":1,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["customer_declaration"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_reassembly_differential.posture

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker"}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","declared_edge_reassembly_policy"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":1,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["customer_declaration"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_rule_gap.posture

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker"}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","declared_managed_ruleset"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":1,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["customer_declaration"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_second_order.posture

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker"}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","declared_stored_content_inspection"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":1,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["customer_declaration"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_encrypted_payload.posture

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker"}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","declared_app_layer_decryption"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":1,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["customer_declaration"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_signed_structured_data.posture

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker"}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","declared_schema_signature_validation"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":1,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["customer_declaration"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_connection_coalescing.posture

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker"}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","declared_per_host_policy"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":1,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["customer_declaration"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_ech_routing_metadata.posture

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker"}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","declared_ech_sni_inspection"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":1,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["customer_declaration"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.compressed_request_decompression.posture

- Signed parameters: `{"kind":"l7_resource_posture_probe","max_requests":2,"timeout_ms":5000,"marker_class":"declared_content_encoding","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":false}`.
- Prerequisites: `[]`. Customer setup: `["http_endpoint","decompression_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":2,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `declared_content_encoding`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: The approved transport cannot deliver this mechanism. No substitute traffic or protection conclusion. Next: Keep untested and seek an approved supported assessment.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### l7.request_parser_size.posture

- Signed parameters: `{"kind":"l7_resource_posture_probe","max_requests":1,"timeout_ms":5000,"marker_class":"declared_oversize_uri","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["http_endpoint","request_size_limit_declaration"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":1,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `declared_oversize_uri`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.http_routing_trust.posture

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker"}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","declared_proxy_trust_boundary"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":1,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["customer_declaration"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.jsonp_css_policy.posture

- Signed parameters: `{"kind":"metadata_marker","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker"}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","declared_content_security_policy"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":1,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["customer_declaration"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Customer-provided operational information is not live enforcement or capacity evidence. Next: Review declared control evidence and its freshness; arrange an authorized assessment if needed.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.sqli_managed_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"sqli","marker":"astranull' OR '1'='0","assurance_scope":"managed_rule_marker","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint"],"observation_only":false,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"produces_verdict":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → markerComparisonComplete → correlateChallengeRedirectPenalty → correlateClassMarkerVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.xss_managed_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"xss","marker":"<astranull-xss-probe/>","assurance_scope":"managed_rule_marker","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint"],"observation_only":false,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"produces_verdict":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → markerComparisonComplete → correlateChallengeRedirectPenalty → correlateClassMarkerVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `xss`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.path_traversal_managed_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"path_traversal","marker":"../../astranull-probe","assurance_scope":"managed_rule_marker","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint"],"observation_only":false,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"produces_verdict":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → markerComparisonComplete → correlateChallengeRedirectPenalty → correlateClassMarkerVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `path_traversal`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.ssti_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"ssti","marker":"astranull-ssti-marker-inert","assurance_scope":"custom_canary_rule","scenario_family":"marker","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint"],"observation_only":true,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"produces_verdict":false,"readiness_conclusion":false,"setup_required":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → setup-required inert-token observation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `ssti`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: No exact installed-token rule binding exists in current declarations. No attack-method test, installed-rule failure finding or readiness credit. Next: Review the recorded token response. Exact installed-rule validation is unavailable; do not infer failure or configure unrelated controls as a substitute.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.scanner_signature_marker.safe

- Signed parameters: `{"kind":"waf_class_marker_probe","max_requests":8,"timeout_ms":5000,"marker_class":"scanner_user_agent","marker":"sqlmap/1.8 (astranull-inert)","assurance_scope":"managed_rule_marker","scenario_family":"marker","marker_type":"user_agent","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint"],"observation_only":false,"scenario_version":"marker-comparison-v5","delivery_supported":true,"requires_complete_comparison":true,"produces_verdict":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → markerComparisonComplete → correlateChallengeRedirectPenalty → correlateClassMarkerVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `scanner_user_agent`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_double_url.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"double_url","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":false,"scenario_version":"marker-comparison-v4","delivery_supported":true,"requires_complete_comparison":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_mixed_url.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"mixed_url","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":false,"scenario_version":"marker-comparison-v4","delivery_supported":true,"requires_complete_comparison":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.evasion_case_fold.safe

- Signed parameters: `{"kind":"waf_evasion_marker_probe","max_requests":4,"timeout_ms":5000,"marker":"astranull' OR '1'='0","evasion_transform":"case_fold","marker_class":"sqli","scenario_family":"marker","marker_type":"query","expected_action":"block","nonce_hash_only":true,"collect":["status_code","waf_product_hint","evasion_bypass_suspected"],"observation_only":false,"scenario_version":"marker-comparison-v4","delivery_supported":true,"requires_complete_comparison":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateChallengeRedirectPenalty → correlateEvasionVerdict → expected-behavior table → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `sqli`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the completed, graded placements on sampled paths are covered; no exploit or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.http_method_policy_enforced.safe

- Signed parameters: `{"kind":"waf_method_policy_probe","max_requests":8,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true,"produces_verdict":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","customer_approves_waf_marker_probe"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateMethodPolicyVerdict (E2 verdict, no readiness) → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: A scoped E2 method-policy verdict is possible; no readiness, exploit or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.rate_limit_canary.validation

- Signed parameters: `{"kind":"rate_limit_canary_probe","max_requests":8,"timeout_ms":5000,"marker":"astranull-safe-marker"}`.
- Prerequisites: `[]`. Customer setup: `["declared_waf_asset","waf.rate_limit_canary"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":8,"max_duration_seconds":120,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateRateLimitCanary → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: only recorded bounded transport activity; missing legacy fields remain unavailable. Limitation: Only the declared route, threshold and observed sequence are covered; no production quota, identity-key or DDoS-capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.body_json_marker.soc

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["waf_offensive_authorization_pack","declared_waf_asset","staging_isolation","canary_sink"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"customer_runnable":false,"max_requests":6}`. Evidence: `["approval_artifact","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.body_form_marker.soc

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["waf_offensive_authorization_pack","declared_waf_asset","staging_isolation","canary_sink"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"customer_runnable":false,"max_requests":6}`. Evidence: `["approval_artifact","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.body_multipart_marker.soc

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["waf_offensive_authorization_pack","declared_waf_asset","staging_isolation","canary_sink"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"customer_runnable":false,"max_requests":6}`. Evidence: `["approval_artifact","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.body_inspection_limit.soc

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["waf_offensive_authorization_pack","declared_waf_asset","staging_isolation","canary_sink"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"customer_runnable":false,"max_requests":8}`. Evidence: `["approval_artifact","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### waf.response_dlp_canary.soc

- Signed parameters: `{}`.
- Prerequisites: `["soc_approval_required"]`. Customer setup: `["waf_offensive_authorization_pack","declared_waf_asset","staging_isolation","canary_sink"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"customer_runnable":false,"max_requests":4}`. Evidence: `["approval_artifact","soc_runbook_ack"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateObservationOnlyVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: A request is not execution, approval, a traffic result or readiness evidence. Next: Request an authorized SOC review; do not execute from this entry.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### nfw.declared_deny_tcp.safe

- Signed parameters: `{"kind":"tcp_connect","max_requests":2,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["network_policy"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":2,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### nfw.declared_deny_udp.safe

- Signed parameters: `{"kind":"udp_probe","max_requests":2,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["network_policy"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":2,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### nfw.management_port_exposure.safe

- Signed parameters: `{"kind":"port_scan_bounded","max_requests":15,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"ports":[22,3389,3306,1433,1521,27017,5432,6379,9200,6443,10250,2379,2375,5900,389],"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_scan_host"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":15,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → nfwPortResults → correlateNfwViolation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### nfw.ipv6_parity.safe

- Signed parameters: `{"kind":"tcp_connect","max_requests":2,"timeout_ms":5000,"address_family":"both","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["declared_ipv6_target","network_policy"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":2,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### nfw.connection_limit.safe

- Signed parameters: `{"kind":"connection_limit_probe","max_requests":12,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["connection_limits"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":12,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateNfwViolation → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: typed protocol/wire facts; no fabricated HTTP exchange. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### nfw.origin_lockdown.safe

- Signed parameters: `{"kind":"host_sni_bypass","max_requests":1,"timeout_ms":5000,"marker":"astranull-safe-marker","observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["origin.lockdown_expected","origin_binding"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":1,"max_duration_seconds":90,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlateOriginLockdownVerdict → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `null`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.

### nfw.perspective_allowlist.safe

- Signed parameters: `{"kind":"tcp_connect","max_requests":2,"timeout_ms":5000,"observation_only":true,"readiness_conclusion":false,"scenario_version":"probe-observation-v3","delivery_supported":true}`.
- Prerequisites: `[]`. Customer setup: `["perspectives","network_policy"]`. Expected behavior: `must_block_before_origin`.
- Safety bounds: `{"max_events":2,"max_duration_seconds":60,"max_concurrent_runs_per_target_group":1}`. Evidence: `["probe_result"]`.
- Evaluation order: admission/setup/governance and signed delivery/refusal → required-input/evidence-gap guards → specialized result-state and attested-I/O guards where applicable → correlatePerspectiveAllowlist (registered-source override) → observation-only/failure/allowlist/expected-behavior fallback as applicable. Override: `requires two registered perspectives and declared denied source`.
- Capture: no target exchange; admission/refusal or local declaration. Limitation: Shows the response from a bounded external sample. A confirmed reply can reveal an exposed service or a declared deny that was not enforced; a timeout or silence cannot prove blocking. No readiness or capacity assurance. Next: Review the recorded response and confirm the endpoint and expected behaviour. Retest only within the approved scope.
- Tests: `tests/unit/check-delivery-catalog.test.mjs (per-ID invocation assertions)`; `tests/unit/catalog-evaluator-truthfulness.test.mjs (named regression branches only)`; `tests/unit/check-delivery-branches.test.mjs (only receipted branches)`. These references name assertions, not proof that all branches ran.


## Historical index 2026-10-09 (not current acceptance)

The following original index is retained verbatim as historical audit input. Its 251-ID counts, old evidence tiers and installed-custom-rule wording are not current claims.

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
