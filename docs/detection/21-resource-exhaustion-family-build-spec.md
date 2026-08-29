# Resource-Exhaustion Family Build Specification

Per-family research, current coverage, build plan, and gap analysis for AstraNull DDoS readiness validation.

**Machine-readable:** `src/contracts/resourceExhaustionTaxonomy.mjs` (`FAMILY_BUILD_SPECS`, `ATTACK_VECTOR_REGISTRY`, `NON_DDOS_AVAILABILITY_THREATS`)  
**Validate:** `npm run vector:taxonomy:validate`  
**Tasks:** `PROGRESS.md` §4.1 (DET-016–DET-026, SOC-011)

---

## How to read this document

| Column / section | Meaning |
|---|---|
| **Has today** | Existing `check_id` in `src/contracts/checks.mjs` with live or metadata probe |
| **Build checks** | New catalog entries to add |
| **Build probes** | New `probe_profile.kind` values for signed-worker / capability probes |
| **Build SOC** | Governed high-scale scenario families (SOC-011 adapter) |
| **Build UI** | Portal/SOC surfaces for readiness and evidence |
| **Build telemetry** | Fields in `high_scale` telemetry + report exports |
| **Missing ATT-*** | Registry rows still `pending` or under-covered |

**Research baselines:** AWS *Best Practices for DDoS Resiliency*, Cloudflare DDoS attack coverage & H1 2026 threat report, Microsoft Azure DDoS attack types, USENIX NXNSAttack, DNSBomb, Google/CERT HTTP/2 Rapid Reset & MadeYouReset advisories.

---

## 1. Volumetric (`volumetric`)

**Exhausts:** Internet/link bandwidth · **Metric:** Gbps/Tbps · **Layer:** L3/L4

### What it is

Floods that saturate uplinks, scrubbers, or DDoS mitigation capacity before traffic reaches the application. UDP floods, ICMP floods, GRE/ESP tunnel floods, QUIC/UDP-443 floods, SIP/media floods.

### Has today

| check_id | What it actually does |
|---|---|
| `l3.forbidden_udp_port.safe` | Single UDP datagram |
| `protocol.http3_quic_exposure.safe` | Alt-Svc + one UDP/443 datagram |
| `l3.ipv6_reachability.safe` | One TCP connect on IPv6 (not volumetric) |
| `high_scale.volumetric.request_only` | SOC marker only |

### Must build

| Artifact | Details |
|---|---|
| **Checks** | `l3.icmp_flood.readiness`, `l3.gre_esp_flood.readiness`, `l3.ipv6_volumetric.readiness`, `protocol.quic_flood.validation` |
| **Probes** | `icmp_echo_bounded`, `gre_datagram_bounded`, `quic_initial_flood_profile`, `volumetric_udp_profile`, `volumetric_icmp_profile` |
| **SOC** | Scenario families: `udp_flood`, `icmp_flood`, `gre_flood`, `quic_flood`, `sip_flood` with max Gbps in authorization pack |
| **UI** | Per–target-group Gbps readiness; high-scale scenario picker |
| **Telemetry** | `provider_bps`, `provider_pps`, `scrubber_state`, `interface_drops` |

### Missing registry (ATT-*)

ATT-002 ICMP, ATT-013 GRE, ATT-014 ESP/IPsec, ATT-074 SIP/VoIP, ATT-124 IPv6 volumetric execution

### Tasks

DET-017, DET-023, SOC-011

---

## 2. Packet-processing (`packet_processing`)

**Exhausts:** Routers, firewalls, NICs, CPU at Mpps/Bpps · **Layer:** L3/L4

### What it is

High packet rate with small packets: ACK floods, RST floods, SYN-ACK floods, TCP flag anomalies, out-of-state TCP, IP fragmentation/reassembly load.

### Has today

| check_id | Limitation |
|---|---|
| `l3.firewall_exposure_scan.safe` | Port scan, not PPS stress |
| `l3.basic_deny_rule.safe` | Single TCP connect |

### Must build

| Artifact | Details |
|---|---|
| **Checks** | ACK/RST/SYN-ACK/flag anomaly/out-of-state/fragmentation readiness checks |
| **Probes** | `tcp_flag_probe`, `fragment_policy_probe`, `stateful_lookup_probe` |
| **SOC** | `packet_processing` scenario metadata on volumetric requests |
| **Telemetry** | `mpps`, `firewall_cpu`, `fragment_reasm_errors`, `nic_drops` |

### Missing ATT-*

ATT-004 through ATT-010, ATT-119 IP options abuse

### Tasks

DET-017, DET-023

---

## 3. State exhaustion (`state_exhaustion`)

**Exhausts:** Connection/session tables · **Metric:** CPS, concurrent states · **Layer:** L3/L4/L7

### What it is

SYN floods (half-open), full TCP connection floods, NAT/firewall state exhaustion, application connection slot hoarding (WebSocket, SMTP, custom TCP).

### Has today

| check_id | Limitation |
|---|---|
| `l3.forbidden_tcp_port.safe` | One connect |
| `l3.connection_table_exhaustion.request_only` | SOC marker |
| `tls.idle_connection_timeout.safe` | Idle timeout metadata |

### Must build

| Artifact | Details |
|---|---|
| **Checks** | SYN flood readiness, TCP connection flood, NAT state table, app connection hoarding |
| **Probes** | `tcp_connect_sequence`, `connection_hold_probe` |
| **SOC** | `syn_flood`, `tcp_connection_flood`, `connection_exhaustion` scenarios |
| **Telemetry** | `cps`, `half_open_count`, `nat_table_pct`, `lb_active_connections` |

### Missing ATT-*

ATT-003/008 execution paths, ATT-075 slow-client path, ATT-123 SMTP flood, ATT-125 NAT exhaustion

### Tasks

DET-017, DET-020, SOC-011

---

## 4. Application L7 (`application_l7`)

**Exhausts:** Web/app request capacity · **Metric:** RPS · **Layer:** L7

### What it is

HTTP GET/POST/HEAD floods, cache busting, bot-like bursts, API floods, CDN bypass, webhooks, health-check floods, XML-RPC reflection at app layer.

### Has today

Strongest catalog coverage: rate limits, WAF markers, cache bust (**implemented**), bot marker, CORS, method restriction, origin bypass (**implemented**).

### Must build

| Artifact | Details |
|---|---|
| **Checks** | Dedicated GET/POST flood validation, search/export/batch abuse, webhook flood, health-check flood, WordPress XML-RPC, CDN bypass check_id |
| **Probes** | `http_get_sequence`, `http_post_body_profile`, `api_batch_profile` |
| **SOC** | `http_get_flood`, `http_post_flood`, `cache_bust_at_scale` |
| **UI** | RPS vs limit evidence, origin vs edge on cache-bust runs |
| **Telemetry** | `rps`, `status_codes`, `origin_vs_edge_ratio`, `challenge_rate` |

### Missing ATT-*

ATT-052 POST flood, ATT-073 XML-RPC, ATT-103 CDN dedicated, ATT-104 SSE, ATT-105–109, ATT-122 cert/SAN dedicated

### Tasks

DET-020, DET-023, SOC-011

---

## 5. Computational (`computational`)

**Exhausts:** CPU via crypto or expensive request handling · **Layer:** L7/TLS

### What it is

TLS handshake storms, TLS renegotiation, HTTP/2 Rapid Reset, MadeYouReset (CVE-2025-8671), CONTINUATION floods, HTTP/2 priority abuse, TLS 0-RTT abuse, expensive API endpoints.

### Has today

| check_id | Limitation |
|---|---|
| `tls.full_audit.safe` | Single handshake audit |
| `protocol.http2_rapid_reset_readiness.safe` | SETTINGS read only — **not** reset storm |
| `l7.expensive_endpoint.safe` | Declared endpoint, low rate |

### Must build

| Artifact | Details |
|---|---|
| **Checks** | Handshake rate, renegotiation, Rapid Reset **validation**, MadeYouReset, CONTINUATION, priority abuse, 0-RTT |
| **Probes** | `tls_handshake_burst`, `http2_reset_profile`, `http2_continuation_profile` |
| **SOC** | Governed Rapid Reset / TLS exhaustion scenarios on approved endpoints |
| **Telemetry** | `handshakes_per_sec`, `cpu_pct`, `http2_resets_per_sec` |

### Missing ATT-*

ATT-065, ATT-067 execution, ATT-068, ATT-069, ATT-110, ATT-111

### Tasks

DET-020, DET-021, SOC-011

---

## 6. Memory exhaustion (`memory_exhaustion`)

**Exhausts:** RAM, buffers, connection tables, HTTP/2 streams · **Layer:** L7/TLS

### What it is

Slowloris, Slow POST/RUDY, slow read, large body uploads, HTTP/2 stream/multiplex abuse, WebSocket message floods, SSE long-lived streams.

### Has today

| check_id | Limitation |
|---|---|
| `tls.slow_header_body_timeout.safe` | HEAD timeout — **not** slowloris |
| `protocol.http2_stream_concurrency.safe` | Readiness metadata |
| `protocol.websocket_connection_controls.safe` | Upgrade posture |
| `l7.header_size_boundary.safe` | Header size only |

### Must build

| Artifact | Details |
|---|---|
| **Checks** | Slowloris, slow POST, slow read, large body POST, SSE stream |
| **Probes** | `slow_header_probe`, `slow_body_probe`, `slow_read_probe`, `sse_hold_probe` |
| **SOC** | Slow-client scenarios with hard duration caps + kill switch |
| **Telemetry** | `active_connections`, `worker_queue`, `stall_duration_p99` |

### Missing ATT-*

ATT-060–063, ATT-104 SSE, ATT-113 file upload

### Tasks

DET-020, DET-021, SOC-011

---

## 7. Backend exhaustion (`backend_exhaustion`)

**Exhausts:** DB, cache, internal APIs · **Metric:** queries/sec · **Layer:** L7/app

### What it is

Search floods, report/export generation, batch APIs, GraphQL depth/alias/batch abuse, OAuth/token endpoint abuse, login/OTP flows (partial today).

### Has today

| check_id | Coverage |
|---|---|
| `l7.api_quota_exhaustion.safe` | Quota metadata |
| `l7.graphql_complexity.safe` | Complexity — not batch/alias |
| `l7.login_abuse_flow.safe` | Auth flow |

### Must build

| Artifact | Details |
|---|---|
| **Checks** | Search, export, batch, GraphQL batch, OAuth/token, file upload |
| **Probes** | `search_query_profile`, `export_job_profile`, `graphql_batch_profile` |
| **Telemetry** | `db_pool_pct`, `query_latency_p99`, `cache_miss_rate` |

### Missing ATT-*

ATT-105–107, ATT-112–114

### Tasks

DET-020, SOC-011

---

## 8. DNS exhaustion (`dns_exhaustion`)

**Exhausts:** Authoritative/resolver capacity · **Metric:** QPS · **Layer:** DNS

### What it is

Query floods, NXDOMAIN/random-prefix/water-torture, DNS laundering via recursive resolvers, garbage/malformed queries, phantom domain, domain lock-up, NXNSAttack, DNSBomb pulsing.

### Has today

Best-in-class partial coverage: authoritative, random-prefix, open recursion, DNSSEC expensive query, AXFR, amplification metadata, SOC DNS high-query marker.

### Must build

| Artifact | Details |
|---|---|
| **Checks** | Named checks for laundering, garbage, phantom, lock-up, NXNS, DNSBomb |
| **Probes** | `dns_prefix_sequence`, `dns_tcp_fallback`, `dns_edns_probe` |
| **SOC** | `dns_query_flood`, `water_torture_at_scale` |
| **Telemetry** | `dns_qps`, `nxdomain_ratio`, `resolver_latency` |

### Missing ATT-*

ATT-045–050, ATT-115 ANY/TXT dedicated

### Research notes

Cloudflare H1 2026: DNS flood/amplification ≈ **34.3%** of network-layer attacks; CLDAP amplification **+580%** QoQ — prioritize DET-018 + DET-019.

### Tasks

DET-019, DET-023, SOC-011

---

## 9. Reflection (`reflection`)

**Exhausts:** Victim via unsolicited third-party responses · **Metric:** pps/bps · **Layer:** L3/L4

### What it is

SSDP, SNMP, mDNS, NetBIOS, WS-Discovery, BitTorrent, SIP, RDP, TFTP, CoAP, QUIC reflection, TCP middlebox reflection, MSSQL/Jenkins discovery.

### Has today

**DNS amplification metadata only** — no non-DNS reflector checks.

### Must build

| Artifact | Details |
|---|---|
| **Checks** | Per-protocol **exposure metadata** checks (open UDP service, response size class) — **never** launch reflection |
| **Probes** | `reflector_exposure_metadata`, bounded UDP service fingerprint |
| **UI** | Reflector exposure inventory |

### Missing ATT-*

ATT-020–027, ATT-116–118

### Tasks

DET-018

---

## 10. Amplification (`amplification`)

**Exhausts:** Bandwidth via small request → large response · **Metric:** amplification ratio · **Layer:** L3/L4/DNS

### What it is

DNS, NTP, CLDAP, Memcached, CHARGEN, ANY/TXT, SSDP — attacker sends small spoofed request, victim receives amplified traffic.

### Has today

`dns.amplification_exposure.safe` only.

### Must build

| Artifact | Details |
|---|---|
| **Checks** | NTP, CLDAP, Memcached, CHARGEN, ANY/TXT exposure (config + response class metadata) |
| **Research** | CAIDA amplifier census methods for **detection** not exploitation |

### Missing ATT-*

ATT-017–019, ATT-042, ATT-115

### Tasks

DET-018

---

## 11. Exploit-based DoS (`exploit_dos`)

**Exhausts:** Software bugs · **Layer:** L3/L7

### What it is

Ping of Death, Teardrop, malformed IP options, HTTP/2 parser CVEs, malformed QUIC, embedded device crashes.

### Has today

**Nothing** in catalog.

### Must build

| Artifact | Details |
|---|---|
| **Checks** | Parser/firmware version posture, CVE patch level metadata |
| **SOC** | Lab-only isolated targets with explicit authorization |
| **Scope** | Readiness posture — not exploit delivery |

### Missing ATT-*

ATT-011, ATT-012, ATT-119, ATT-120

### Tasks

DET-017, DET-021, DET-026

---

## 12. Attack delivery patterns (`delivery_pattern`)

**Exhausts:** Cross-cutting · **How** attacks are deployed

### What it is

Direct vs spoofed floods, DRDoS, botnets, carpet bombing, pulse-wave, multi-vector switching, multi-destination, ransom DDoS, adaptive/randomized evasion.

### Has today

| check_id | Role |
|---|---|
| `high_scale.multi_vector.request_only` | SOC marker |
| `high_scale.volumetric.request_only` | SOC marker |
| `high_scale.degradation_recovery.request_only` | Recovery drill |

### Must build

| Artifact | Details |
|---|---|
| **Checks** | Carpet bombing readiness, pulse-wave, spoofed source, ransom DDoS workflow |
| **SOC** | Pattern metadata on every high-scale request: `delivery_pattern[]`, `destination_spread` |
| **UI** | SOC timeline with vector switches; multi-destination heatmap |
| **Telemetry** | `pulse_frequency`, `vector_change_events`, `destination_count` |

### Missing ATT-*

ATT-091, ATT-094, ATT-095, ATT-098 ransom, ATT-121 adaptive

### Research notes

Cloudflare documented **7.3 Tbps** carpet bombing across tens of thousands of ports with multi-vector UDP + reflection.

### Tasks

DET-022, SOC-011

---

## 13. Operational / non-DDoS threats (DET-026)

Tracked in `NON_DDOS_AVAILABILITY_THREATS` — **not** scored in DDoS readiness but affect availability.

| ID | Threat | Build |
|---|---|---|
| ND-004 | Autoscaling cost / health-check flood | ATT-109 + `control_plane.autoscaling.readiness` |
| ND-005 | Alert blind spots | Extend `ops.alert_workflow_marker.safe` + SOC runbook linkage |
| ND-001–003 | BGP/DNS integrity | Monitor-only integrations; out of probe scope |
| ND-006 | Credential stuffing | Partial via `l7.login_abuse_flow.safe`; separate security product boundary |

---

## 14. Botnet / tool names (not attack categories)

Mirai, LOIC, HOIC, HULK, DemonBot — **delivery mechanisms**, not taxonomy rows. SOC telemetry may tag `botnet_signature` metadata without cataloging as checks.

---

## 15. Cross-family build order (recommended)

```text
DET-016 schema
    ├── DET-017 L3/L4 + packet + state
    ├── DET-018 reflection/amplification exposure
    ├── DET-019 advanced DNS
    ├── DET-020 L7 + backend + slow-client
    ├── DET-021 HTTP/2–3 + SSE + gRPC live
    ├── DET-022 delivery patterns
    ├── DET-026 operational threats
    └── DET-024 UI/scoring (parallel once schema exists)
SOC-011 governed execution ──► DET-023 volumetric profiles
DET-025 CI + staging signoff (last)
```

---

## 16. Global gaps still missing from docs and code

| Gap | Where it surfaced | Action |
|---|---|---|
| `exhausted_resource` field on catalog checks | DET-016 | Add to every `CHECK_CATALOG` entry |
| 12-family dashboard heatmap | DET-024 | Replace 5-family `vector-coverage.mjs` |
| Live volumetric execution | SOC-011 | Partner/governed adapter — dry-run only today |
| gRPC live probe | DET-021 | `protocol.grpc_reflection_stream.safe` still `metadata_marker` |
| SSE check | DET-021 | In protocol doc only |
| Control-plane family in `01-vector-catalog.md` | DET-026 | Map to ND-004/ND-005 |
| Staging ATT-* → evidence matrix | DET-025 | One live proof per family minimum |
| WAF offensive suites | WAF SOC checks | SQLi/XSS — **WAF validation**, not DDoS taxonomy (keep separate) |

---

## 17. Validation commands

```bash
npm run vector:taxonomy:validate
node --test tests/unit/resource-exhaustion-taxonomy.test.mjs
```

Output: `output/resource-exhaustion-taxonomy-validation.json` — pending ATT-* list, per-task pending counts, coverage percentages, WAF vulnerability registry (WV-*), and orphan check detection.

---

## 18. Complete ATT-* inventory by family (149 vectors)

Every attack class, exposure, and delivery pattern registered in `ATTACK_VECTOR_REGISTRY`. Status from validator snapshot.

### 18.1 Volumetric (8 ATT-*)

| ID | Vector | Status |
|---|---|---|
| ATT-001 | UDP flood | partial |
| ATT-002 | ICMP / ping flood | pending |
| ATT-013 | GRE flood | pending |
| ATT-015 | QUIC flood | partial |
| ATT-074 | SIP / VoIP flood | pending |
| ATT-124 | IPv6 volumetric (beyond reachability) | partial |
| ATT-135 | SCTP flood | pending |
| ATT-137 | Multicast / broadcast storm | pending |

### 18.2 Packet-processing (7 ATT-*)

ATT-004 ACK · ATT-005 SYN-ACK · ATT-006 RST · ATT-007 TCP flag floods · ATT-009 out-of-state TCP · ATT-010 fragmentation · ATT-014 ESP/IPsec flood

### 18.3 State exhaustion (8 ATT-*)

ATT-003 SYN · ATT-008 TCP connection · ATT-075 app connection · ATT-123 SMTP · ATT-125 NAT/firewall state · ATT-136 IKE/IPsec · ATT-138 SSH · ATT-139 FTP

### 18.4 Application L7 (32 ATT-*)

Core floods: ATT-051 GET · ATT-052 POST · ATT-053 HEAD · ATT-056 API · ATT-058 cache bust (**implemented**) · ATT-070 HTTP/3/QUIC app · ATT-072 gRPC · ATT-073 XML-RPC · ATT-108 webhook · ATT-109 health-check

Origin/edge exposure: ATT-100 direct bypass (**impl**) · ATT-101 leak scan (**impl**) · ATT-102 WAF (**impl**) · ATT-103 CDN bypass · ATT-122 cert/SAN · ATT-126 stale DNS · ATT-127 DNS hostname bypass · ATT-128 canary path · ATT-129 admin exposure · ATT-130 ephemeral ports · ATT-131 WAF-to-origin · ATT-132 TRACE/methods · ATT-170 WAF bypass · ATT-174 CORS · ATT-176 HTTP/2 readiness

Extended HTTP: ATT-140 pipelining · ATT-141 Range · ATT-142 conditional revalidation · ATT-145 CAPTCHA · ATT-153 HTTP/3 SETTINGS · ATT-167 MQTT

### 18.5 Computational (11 ATT-*)

ATT-054 expensive endpoint · ATT-064 TLS handshake · ATT-065 renegotiation · ATT-067 Rapid Reset · ATT-069 MadeYouReset · ATT-110 HTTP/2 priority · ATT-111 TLS 0-RTT · ATT-147 ReDoS · ATT-152 QPACK · ATT-155 OCSP · ATT-156 cipher negotiation

### 18.6 Memory exhaustion (13 ATT-*)

ATT-059 large POST · ATT-060 slowloris · ATT-061 slow POST/RUDY · ATT-062 slow read · ATT-063 generic low-and-slow · ATT-068 CONTINUATION · ATT-071 WebSocket · ATT-104 SSE · ATT-113 file upload · ATT-148 JSON bomb · ATT-149 XML bomb · ATT-150 HPACK bomb · ATT-151 HTTP/2 push promise

### 18.7 Backend exhaustion (12 ATT-*)

ATT-055 DB exhaustion · ATT-057 GraphQL · ATT-105 search · ATT-106 export/report · ATT-107 batch API · ATT-112 OAuth/token · ATT-114 GraphQL batch · ATT-143 checkout/cart · ATT-144 OTP/SMS cost · ATT-157 signup · ATT-158 password reset · ATT-166 Elasticsearch

### 18.8 DNS exhaustion (13 ATT-*)

ATT-041 query flood · ATT-043 NXDOMAIN · ATT-044 water-torture · ATT-045 laundering · ATT-046 garbage · ATT-047 phantom domain · ATT-048 lock-up · ATT-049 NXNSAttack · ATT-050 DNSBomb · ATT-159 DoH/DoT · ATT-160 TCP fallback · ATT-161 zone walking · ATT-162 secondary failover

### 18.9 Reflection (15 ATT-*)

ATT-020 SSDP · ATT-021 SNMP · ATT-022 CHARGEN/QOTD · ATT-023 mDNS/NetBIOS/WS-Discovery · ATT-024 portmap/RIPv1/BitTorrent/Jenkins · ATT-025 DTLS/SIP/RDP/TFTP/ARMS/CoAP · ATT-026 QUIC reflection · ATT-027 TCP middlebox · ATT-116 MSSQL · ATT-117 Jenkins/CI · ATT-118 CoAP IoT · ATT-163 STUN/TURN · ATT-164 IPMI · ATT-165 Redis direct · ATT-168 OpenVPN/WireGuard

### 18.10 Amplification (7 ATT-*)

ATT-016 DNS reflection · ATT-017 NTP · ATT-018 CLDAP · ATT-019 Memcached · ATT-042 authoritative/resolver · ATT-115 ANY/TXT · ATT-134 Smurf/ICMP-broadcast

### 18.11 Exploit-based DoS (6 ATT-*)

ATT-011 Ping of Death · ATT-012 Teardrop · ATT-119 IP options · ATT-120 malformed QUIC · ATT-133 Land attack · ATT-154 QUIC migration abuse

### 18.12 Delivery patterns (17 ATT-*)

ATT-090 direct · ATT-091 spoofed · ATT-092 DRDoS · ATT-093 botnet (soc_only) · ATT-094 carpet bombing · ATT-095 pulse-wave · ATT-096 multi-vector (soc_only) · ATT-097 app-aware · ATT-098 ransom DDoS · ATT-099 multi-destination · ATT-121 adaptive evasion · ATT-146 residential proxy · ATT-169 API scraping · ATT-171 kill-switch/runbook · ATT-172 telemetry blind spot · ATT-173 recovery drill (soc_only) · ATT-175 rate-limit evasion

---

## 19. WAF vulnerability registry (WV-001–008)

Separate from DDoS taxonomy — SOC-only offensive WAF validation (`waf.offensive_*.soc` checks):

WV-001 SQLi · WV-002 XSS · WV-003 RCE · WV-004 path traversal · WV-005 command injection · WV-006 LDAP injection · WV-007 SSTI · WV-008 combined suite

---

## 20. Non-DDoS availability threats (ND-001–009)

ND-001 BGP hijack · ND-002 route leak · ND-003 DNS hijack/poisoning · ND-004 autoscaling cost · ND-005 alert blind spots · ND-006 credential stuffing · ND-007 provider API exhaustion · ND-008 log/SIEM cost · ND-009 CT log noise

---

## 21. Catalog check coverage (all 65 checks mapped)

Every `check_id` in `checks.mjs` maps to at least one ATT-*, ND-*, or WV-* row. Validator fails on orphan checks.

| Prefix | Role | Example ATT mapping |
|---|---|---|
| `origin.*` | Direct-path exposure | ATT-100–103, ATT-126–131 |
| `l3.*` | L3/L4 readiness | ATT-001–010, ATT-124–130 |
| `dns.*` | DNS readiness | ATT-041–050, ATT-115, ATT-159–162 |
| `l7.*` | L7/API readiness | ATT-051–058, ATT-105–114, ATT-140–145 |
| `tls.*` | TLS/connection | ATT-059–065, ATT-155–156 |
| `protocol.*` | HTTP/2–3/gRPC/WS | ATT-066–072, ATT-104, ATT-150–154, ATT-176 |
| `waf.*` (safe) | WAF readiness | ATT-102, ATT-170, ATT-175 |
| `waf.offensive_*.soc` | WAF vuln validation | WV-001–008 |
| `ops.*` / `high_scale.*` | SOC/operational | ATT-171–173, ND-004–005 |
| `path.*` | Canary path | ATT-128 |

---

## 22. Remaining implementation work (all families)

| Family | Pending ATT count | Priority build |
|---|---:|---|
| Reflection | 14/15 | DET-018 exposure metadata checks |
| Exploit DoS | 6/6 | DET-017/021 parser posture |
| Packet-processing | 6/7 | DET-017 TCP flag probes |
| Volumetric execution | 5/8 + SOC | DET-023 + SOC-011 |
| Memory/slow-client | 9/13 | DET-020/021 slow probes |
| L7 floods | 14+/32 | DET-020 POST/search/export |
| DNS advanced | 6/13 | DET-019 NXNS/DNSBomb |
| Delivery patterns | 5/17 + SOC | DET-022 metadata + UI |
| Backend | 8/12 | DET-020 declared endpoints |
| Computational | 8/11 | DET-021 Rapid Reset execution |

**Zero orphan catalog checks.** **149 ATT-* registered.** Implementation remains ~41% mapped (partial+implemented+soc_only); ~59% fully pending execution paths.
