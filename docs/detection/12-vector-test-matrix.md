# Vector Test Matrix

This matrix defines what AstraNull validates from the **outside in**. It describes detection and readiness checks without runnable attack recipes. Agents and environments are out of scope ([ADR-0008](../adr/0008-outside-in-only-targets-first.md)). NFW and truthful WAF grading: [ADR-0029](../adr/0029-violation-only-network-verdicts-and-truthful-waf-grading.md). Category assurance: [rule-coverage.md](rule-coverage.md).

## Safety classes

| Class | Who can run | Description |
|---|---|---|
| S0 Config/Declaration | Customer | No traffic or only metadata validation |
| S1 Single Probe | Customer | One or few labeled packets/requests |
| S2 Low-Rate Safe | Customer with caps | Customer-runnable validation |
| S3 Controlled Scenario | SOC approval | Higher sensitivity, strict ROE |
| S4 High-Scale Simulation | SOC only | Provider/customer authorization and live stop controls required |

Self-serve HTTP never sends a body. Marker, evasion and rate-limit canary probes use GET/HEAD; the method-policy probe additionally sends `TRACE` and the nonstandard token method `ASTRANULLPROBE`, each with no body. Anything with a request body is SOC-reviewed and goes only to a customer-declared HTTPS canary sink. [ADR-0026](../adr/0026-reviewed-safe-execution-lifecycle.md) keeps reviewed worker runtime disabled, so those body checks stay SOC-operator entered.

## Origin bypass vectors

| Vector | Safe validation | High-scale/SOC | Evidence | Done means |
|---|---|---|---|---|
| Direct IP / Host/SNI | One bounded request to a target-bound IP literal with protected Host/SNI | Sustained approved direct-path scenario | `host_sni_bypass` observation (`external-observation-v3`) | `exposed` only on non-CDN 2xx **with application identity** when an origin binding **and** `origin.lockdown_expected` are declared. Timeout stays inconclusive. Never `protected` from silence. |
| Origin lockdown (`nfw.origin_lockdown.safe`) | Same producer, customer-visible | — | Identity + declarations | Missing origin declaration → coverage **Not assessable**. |
| Legacy DNS/origin leak | Bounded DNS/subdomain/IPv6 metadata on declared host | Not typical high-scale | `origin_leak_scan` (does not dial origin) | Observation only. |
| Admin/management exposure | Bounded TCP scan / declared deny | Never high-scale by default | Port-scan / `tcp_connect` | Violation-only. |

FQDN targets cannot acquire a second socket via metadata `direct_ip`. Host/SNI without an IP-literal target is `missing_target_bound_direct_address`.

## L3/L4 vectors

| Vector family | Safe check | SOC/high-scale | Detection signals | UI verdict |
|---|---|---|---|---|
| TCP SYN/state | Two-sample `tcp_connect`, `nfw.declared_deny_tcp.safe` | Approved state-pressure | `tcp_outcome`, ICMP errno, `peer_is_cdn`, `sample_agreement`, `source_perspective` | `exposed` / `inconclusive`. Never `protected`. |
| TCP ACK/RST/FIN | Port-bound connect where executable; else declaration | Approved packet-state scenario | RST vs ICMP reject kept separate | RST is unverified for deny acceptance. |
| UDP | Two-sample `udp_probe`, `nfw.declared_deny_udp.safe` | Approved UDP volume | `udp_outcome` including `validated_reply` / `silent` | Silence is inconclusive. |
| ICMP policy | None | Rare SOC | — | `not_assessable`. |
| Fragmentation | Metadata marker | SOC lab preferred | Declaration | E1 only. |
| GRE/ESP/SCTP | Metadata marker | Provider-approved only | Declaration | E1 only. |
| IPv6 parity | `nfw.ipv6_parity.safe` (`address_family: both`) | Approved IPv6 scenario | `families`, `parity`, per-family `ports_sampled` | Mismatch only when both families were sampled on the same port; an unprobed family is `not_sampled`. Leak still `exposed` per family. |
| QUIC/UDP 443 | HTTPS HEAD Alt-Svc observation | Approved QUIC volume | Alt-Svc metadata | Safe probe does not send UDP/QUIC. |
| Port / management exposure | Bounded vetted scan (≤15 declared ports) | Rare SOC | `open_ports` vs typed deny | Violation-only. |
| Connection table | `nfw.connection_limit.safe` (cap 12) | SOC-gated | `accepted_count` vs `declared_limit`, `peer_is_cdn`, `sample_agreement` | Over-limit `exposed` from a non-CDN peer with agreeing samples; otherwise `inconclusive`. |
| Allowlist / geo | `nfw.perspective_allowlist.safe` | — | ≥2 registered perspectives + egress IPs | Not runnable with one source. |
| Reflection | Validated reflector profiles within budget | Never third-party reflection | `validated_reply`, `exposure_basis` | Protocol-validated reply → `exposed` as an open reflector without a declaration; never claims a firewall deny was violated. Unvalidated replies never expose. |

Firewall-change workflow: reject evidence (ICMP admin-prohibited / host- or net-unreachable `rejected_icmp`) vs silent drop after a reachable baseline (`consistent_with_new_deny_rule`). UDP `port_unreachable` is a closed port and local `EACCES`/`EPERM` is a probe-host error; neither is reject evidence. See [06-l3-l4-vectors.md](06-l3-l4-vectors.md).

## DNS vectors

| Vector family | Safe check | SOC/high-scale | Evidence | Done means |
|---|---|---|---|---|
| Authoritative DNS | Controlled DNS query to declared domain | Approved DNS QPS | DNS status, latency, RCODE | Observation unless a semantic-safe kind concludes. |
| Random-prefix/NXDOMAIN | Small set of random labels | Approved NXDOMAIN scenario | NXDOMAIN ratio | Observation. |
| Open recursion | Query resolver behavior only when target declared as resolver | Not needed | Recursion response | Observation. |
| DNS amplification | Config/behavior metadata | Never reflection amplification | Response size/class | Observation. |
| DNSSEC heavy queries | One bounded DNSKEY wire query | SOC-approved if needed | Key presence is not chain validation | Observation. |
| ANY/TXT | Safe query validation | Never reflection amplification | Response size/class | Observation. |
| Secondary failover | Config / declared failover | Approved failover | Resolver metadata | Observation. |
| Zone transfer | `dns_axfr_leak` against listed NS within budget (max 5) | Not high-scale | AXFR refuse/leak across every NS + `enforcement` | `protected` only when every NS of the zone was queried and refused (`enforcement: enforced`); a leak on any NS is `exposed`; NS left unqueried by the budget is `enforcement: partial` → `inconclusive`. |

## L7 HTTP/API and WAF vectors

| Vector family | Safe check | SOC/high-scale | Evidence | Done means |
|---|---|---|---|---|
| Custom canary rules | 14+ opaque class-marker checks (`assurance_scope: custom_canary_rule`) | — | Per-placement outcomes, trailing control, `enforcement` | Proves a customer rule for AstraNull’s token. Rolled up as one coverage pair. |
| Managed-rule markers | `waf.sqli_managed_marker.safe`, `xss`, `path_traversal` | Offensive suites `.soc` | Plain inert class token | `protected`/`exposed` on graded placements. |
| Evasion / normalization | Supported GET transforms including `double_url`, `mixed_url`, `case_fold` | — | `reference_outcome`, `transform_outcome`, `normalization_gap` | Gap → scoped `exposed`. Observation-only transforms (`base64_wrap`, `numeric_repr`, `homoglyph`) never fail as bypass. |
| Challenge vs block | Shared grader | — | `challenged` outcome | Challenge never satisfies `expected_action: block`; blocked plus challenged legs are `challenged`, never `exposed`. Under `block_or_challenge` a challenge satisfies the action. |
| Unverified vendor signatures | Shared grader | — | `inconclusive_reason: block_suspected_unverified_signature`, `matched_vendor` | Generic proxy/CDN headers with a 403/406 are a suspected block only, never `blocked`. |
| Rate-limit canary | `waf.rate_limit_canary.validation` | — | `threshold`, `requests_sent`, `first_limited_at`, `allowed_before_limit`, `limited_outcome` | Needs declaration. `protected` only when `threshold` requests were allowed and the limit came at `threshold+1`/`threshold+2`; limited at or before `threshold` is inconclusive; never limited past the threshold is `exposed` (low). Generic `rate_limit_sequence` stays observation-only. |
| HTTP flood / POST / cache / expensive endpoint / login / GraphQL / bot | Low-rate observation probes | Approved RPS / app-load | Status, latency, WAF action | Observation unless a semantic-safe kind above applies. |
| Request body (JSON/form/multipart), inspection limit, response DLP | Planner `canary_sink_body_plan` | SOC `.soc` to declared canary sink | SOC-entered results | Self-serve sends no body. |
| Unusual methods | `waf.http_method_policy_enforced.safe` / method matrix | Not high-scale | `method_results[]` | Method policy sends `TRACE` and `ASTRANULLPROBE` with no body and uses no declaration: both refused at the edge → `protected`, either allowed → `exposed`, origin-only 405/501 → `inconclusive`. The method matrix observes only. |
| Slowloris / HTTP/2 rapid reset | Bounded timeout / SETTINGS / frame probes | SOC-controlled | Timeout / protocol metadata | Observation; labelled Edge, not WAF. |

No self-serve RFI, JNDI lookup (`${`), or Spring4Shell property-assignment markers.

## TLS and connection vectors

| Vector | Safe validation | SOC/high-scale | Evidence | Done means |
|---|---|---|---|---|
| TLS handshake load | Bounded handshake / metadata | Approved handshake-rate | Handshake result | Observation or declaration. |
| Slow header/body | Safe timeout boundary | SOC-controlled slow scenario | Timeout behavior | Observation. |
| Connection idle | Small number of short connections | Approved connection count | Connection metadata | Observation. |
| Cipher/protocol | TLS metadata scan of declared target | Not high-scale | TLS version/cipher | Observation. |

## Modern protocol vectors

| Vector | Safe validation | SOC/high-scale | Evidence | Done means |
|---|---|---|---|---|
| HTTP/2 rapid reset / stream / CONTINUATION | Config/low-rate protocol behavior | SOC/provider-approved | Settings, errors, availability | Observation. |
| HTTP/3/QUIC flood | One bounded HTTPS HEAD (Alt-Svc) | Approved UDP/QUIC simulation | `h3` Alt-Svc advertisement | Safe probe does not test UDP reachability or QUIC handshakes. |
| SNI/Host mismatch | Declared Host/SNI on IP-literal target | Approved TLS scenario | TLS/HTTP observation | See origin lockdown. |
| Certificate/SAN leakage | Passive/public check for declared target | Not high-scale | Certificate metadata | Observation. |

## Alerting and operational vectors

| Check | Safe validation | SOC/high-scale | Evidence | Done means |
|---|---|---|---|---|
| Alert fires | Safe marker/test event | Alert during approved simulation | Webhook/manual/SIEM | Alert captured. |
| Runbook exists | Upload/link validation | Live SOC use | Runbook version, owner | Current runbook attached. |
| Emergency contacts | Data validation | Live call bridge/ack | Contact audit | Contacts reachable. |
| Kill switch | Dry-run stop | Live stop if needed | Stop event, adapter confirmation | Stop path audited. `ops_readiness` is verdict-capable on the control plane. |
| Post-test report | Generate sample report | Full report after high-scale | Evidence bundle | Report exportable. |

## Global done criteria for a vector

A vector is complete only when:

1. Check definition exists in the catalog.
2. Safety class is assigned.
3. Prerequisites / `required_customer_setup` / `runnable_requires` are defined.
4. External probe behavior is bounded via signed `probe_profile` (`kind`, `max_requests`, `timeout_ms`) for customer-runnable checks.
5. Evidence requirements name **probe_result** (and declarations where needed). No agent evidence requirement.
6. Correlation truth table is implemented in `correlateExternalOnlyVerdict` (or the check is honestly observation-only / declaration-only / SOC-gated).
7. UI explanation exists and does not claim origin receipt from timeout.
8. Confidence is `external_only` on customer targets.
9. Finding/remediation text exists for `createsFinding` paths; `fix_verified` on complete passing retest.
10. Tests exist.
11. Progress tracker is updated.

## Vector safety policy evidence (release review)

Before promoting detection catalog changes tied to this matrix, run the metadata-only policy evidence utility:

```bash
node scripts/vector-safety-policy-evidence.mjs --validate-only
node scripts/vector-safety-policy-evidence.mjs --out output/vector-safety-policy-evidence.json
```

The utility reads `CHECK_CATALOG` and validates that:

| Policy class | Required metadata | Runnable? |
|---|---|---|
| Customer-runnable (`safe`) | `allowed_payload_type` (`probe_profile.kind`), `max_rate` / `max_duration_seconds`, `approval_level=customer_self_service`, `stop_conditions`, `evidence_required`, signed `probe_profile`, `failure_handling` (remediation/explanation templates) | Yes — customer-runnable probes per catalog profile |
| SOC request marker (`soc_gated`) | `approval_level=soc_request_only`, `stop_conditions`, `evidence_required`, `request_marker`; no `probe_profile` or live probe simulation | No — customer may request; SOC approves and executes |

The emitted manifest lists every customer-runnable policy and SOC request marker with validation gaps (if any). The command exits nonzero when gaps exist so vector matrix release review can block promotion until catalog policy metadata is complete.

Use this artifact alongside unit tests (`tests/unit/vector-safety-policy-evidence.test.mjs` and `tests/unit/vectors.test.mjs`) to confirm matrix rows map to governed catalog entries without introducing unmanaged traffic execution paths.
