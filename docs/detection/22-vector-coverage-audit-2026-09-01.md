# AstraNull Attack-Vector Coverage Audit — Gaps, Defects, and a Navigable Taxonomy

> **Superseded pre-remediation baseline — not current release accounting.** This audit records the defect-discovery snapshot from before the 2026-09-01 remediation pass. Its 175-check, 356/721, and old status/tier totals are intentionally preserved as historical evidence and must not be quoted as current. Current executable truth comes from `npm run vector:taxonomy:validate`: 249 checks (232 safe, 17 SOC-gated), 680 registry-claimed catalog rows plus 41 explicit outside-in exclusions, 0 unclaimed, and a DDoS-scored distribution of 79 implemented / 84 partial / 86 SOC-only / 0 pending. The appendix's row-level tiers predate authoritative aggregation; current contracts keep APP-003 and NET-016 E4 / SOC-governed despite their supplemental E1 declaration checks.

**Scope:** every row of `one_sheet_global_ddos_waf_attack_vector_catalog_2026-09-01.csv` (721 vectors) reconciled against AstraNull's shipped registries and, critically, against what the probe code *actually executes*.
**Date:** 2026-09-01 · **Status:** analysis only — no code changed. This document is the input for the implementation and remediation passes that follow.
**Reproduce:** `python3 analysis/coverage-report.py` then `python3 analysis/gen-appendices.py` (both read `analysis/vector-map.py`, the curated 721-row mapping; outputs land in the gitignored `output/`).

---

## 0. Correction to the earlier coverage summary

An earlier pass in this workstream reported **94.5% coverage**, with Reflection-Amplification and L7 DDoS at **100%**. Those numbers are wrong and should not be quoted. They came from a keyword matcher that (a) auto-passed every L7 row without testing it, and (b) treated *"a check exists with a similar name"* as coverage without checking whether that check performs any network I/O.

Two claims in that summary are specifically false and worth calling out because they are the kind of thing that ends up in a customer deck:

- **"XXE, SSRF and HTTP Request Smuggling validation"** — AstraNull has no registry entry, no check, and no probe for any of these. `WAF-061`–`WAF-068` and `WAF-007`–`WAF-010` are entirely unmapped.
- **"Reflection & Amplification: 73/73, 0 gaps"** — 18 of 73 have no registry entry, and 45 of the remaining 55 resolve to a single generic UDP datagram that most real reflectors will silently discard (defect D-01).

The corrected figures are in §2. They are lower, and they are defensible.

---

## 1. Method: coverage is measured at the evidence layer, not the catalog layer

The central finding of this audit is that AstraNull has **two different meanings of "covered"** and they are currently reported as one number:

1. *Catalog coverage* — a `check_id` exists in `src/contracts/checks.mjs` and an `ATT-xxx` entry in `src/contracts/resourceExhaustionTaxonomy.mjs` names the vector.
2. *Evidence coverage* — running that check against a real target produces a verdict that can distinguish "protected" from "exposed".

175 checks exist. **35 of them can ever return a verdict other than `inconclusive`.** The other 140 are catalog coverage only.

That is not a hidden bug — the code says so plainly. `src/lib/readinessVerdicts.mjs:21` lists `OBSERVATION_ONLY_PROBE_KINDS`, and `src/services/correlation.mjs:28` short-circuits every one of them to:

```
verdict: 'inconclusive', confidence: 'low', createsFinding: false
```

The engineering is honest. The **reporting layer built on top of it is not**, because the registry's `coverage_status` field collapses "sends a protocol-correct probe and grades the response" and "performs zero network I/O" into the same value, `partial`.

### 1.1 The evidence-tier model used throughout this document

| Tier | Meaning | What a run produces | Count (checks) |
|---|---|---|---|
| **E3 semantic-safe** | Live probe whose response is graded against the check's verdict logic | `protected` / `exposed` / `bypassable` … | **35** |
| **E2 transport-only** | Live packets, but only liveness/transport metadata is recorded | always `inconclusive` | **54** |
| **E1 declared-only** | `metadata_marker`; no socket is opened | always `not_run` → `inconclusive` | **69** |
| **E4 SOC-governed** | No in-repo executor; requires an approved external adapter | nothing until an adapter runs | **17** |
| **E5 monitor-only** | Explicitly declared out of probe scope (`NON_DDOS_AVAILABILITY_THREATS`) | n/a by design | 9 threats |
| **E0 unmapped** | No registry entry at any granularity | n/a | — |

E1 is verifiable directly — `workers/probe-worker.mjs:946` returns
`{ external_result: 'not_run', not_run_reason: 'metadata_only_check_has_no_executable_probe' }`.

### 1.2 Mapping discipline

Each of the 721 catalog rows was assigned by hand to one of three link types, not by string similarity:

- **exact** (167) — AstraNull has a registry entry naming this specific vector.
- **umbrella** (189) — subsumed by a broader entry; real but *not separately identifiable in evidence*. `APP-176`–`APP-184` (nine SIP method floods) all collapse onto `ATT-074`; a customer cannot tell which one was tested.
- **none** (365) — no registry entry at any granularity.

---

## 2. Corrected coverage matrix

### 2.1 By catalog section

| Section | Rows | E3 semantic | E2 transport | E4 SOC | E1 declared | E5 monitor | **E0 unmapped** |
|---|---:|---:|---:|---:|---:|---:|---:|
| Network / L2–L4 Direct | 180 | 4 | 36 | 4 | 52 | 0 | **84** |
| Reflection & Amplification | 73 | 3 | 45 | 0 | 7 | 0 | **18** |
| L7 DDoS | 201 | 36 | 54 | 0 | 34 | 0 | **77** |
| WAF Web Attacks | 176 | 18 | 2 | 30 | 4 | 5 | **117** |
| WAF Evasion | 91 | 15 | 0 | 1 | 6 | 0 | **69** |
| **Total** | **721** | **76** | **137** | **35** | **103** | **5** | **365** |

### 2.2 The three numbers that matter

| Metric | Value | |
|---|---:|---|
| Vectors with **any** registry entry | 356 / 721 | **49.4%** |
| Vectors with an **exact, individually-named** entry | 167 / 721 | **23.2%** |
| Vectors where a customer run yields **gradeable evidence** (E3) | 76 / 721 | **10.5%** |

Add E4 (SOC-governed, adapter required) and the ceiling on demonstrable coverage is **111 / 721 = 15.4%**.

### 2.3 By proposed domain (see §5)

| Domain | Rows | E3 | E2 | E4 | E1 | E0 |
|---|---:|---:|---:|---:|---:|---:|
| A1a IP / Transport Packet Processing | 144 | 4 | 35 | 4 | 50 | 51 |
| A1b LAN / Routing Control Plane † | 22 | 0 | 1 | 0 | 2 | 19 |
| A1c Wireless / RF † | 9 | 0 | 0 | 0 | 0 | 9 |
| A1d Mobile / Telecom Signalling † | 5 | 0 | 0 | 0 | 0 | 5 |
| A2 Reflection & Amplification Exposure | 73 | 3 | 45 | 0 | 7 | 18 |
| A3 DNS Service Exhaustion | 36 | 7 | 15 | 0 | 7 | 7 |
| A4a HTTP / API Application Exhaustion | 98 | 25 | 11 | 0 | 18 | 44 |
| A4b Non-HTTP Application Services | 33 | 1 | 17 | 0 | 3 | 12 |
| A5 Protocol Machinery (H2/H3/QUIC/WS/gRPC/TLS) | 34 | 3 | 11 | 0 | 6 | 14 |
| A7 Web Application Attack Classes | 176 | 18 | 2 | 30 | 4 | 117 |
| A8 Evasion & Delivery Patterns | 91 | 15 | 0 | 1 | 6 | 69 |

† 36 vectors are structurally unreachable from an outside-in SaaS probe (they need L2 adjacency, a routing peer session, RF proximity, or a mobile-core interface). Recommendation in §6.4: declare them **out of scope** in the registry rather than leaving them as silent gaps — a stated exclusion is defensible, an unexplained absence is not.

---

## 3. Defect register — vectors we claim to cover that do not do what they claim

These are correctness problems in *shipped, customer-runnable* checks. Every one was verified by executing the code, not by reading it.

### D-01 · Reflection probes send a payload no reflector will answer — systemic false negative
**Severity: critical.** `src/lib/safeNetworkProbes.mjs:70-73`

```js
function safeUdpPayload(job) {
  const noncePart = String(job.nonce_hash ?? job.nonce ?? 'probe').slice(0, 16);
  return Buffer.from(`${SAFE_UDP_PAYLOAD_PREFIX}${noncePart}`, 'utf8');  // "ASTRANULL:udp:<nonce>"
}
```

All 14 `udp_probe` checks send this ASCII string. SSDP needs `M-SEARCH * HTTP/1.1`; SNMP needs a BER-encoded GetRequest; mDNS/NetBIOS need DNS wire format; STUN needs a binding request with the magic cookie; CoAP, IPMI/RMCP, MSSQL, TFTP, DTLS and OpenVPN each need their own header. A correctly-functioning reflector **drops the datagram silently**, the probe times out, and the result is recorded as `no_udp_response`.

The failure mode is the dangerous direction: **an open, abusable reflector is reported as not exposed.** Affects `ATT-020`–`ATT-025`, `ATT-116`–`ATT-118`, `ATT-163`, `ATT-164`, `ATT-168` — 45 catalog rows in §2.1's Reflection row. (CHARGEN/QOTD/Echo are the accidental exception: they answer any datagram.)

The probe also records `datagram_bytes` and `response_bytes` but never derives an **amplification ratio**, which is the one number an amplification-exposure finding needs.

### D-02 · Six checks execute an HTTPS HEAD instead of their declared protocol
**Severity: critical.** `workers/probe-worker.mjs:1195-1197` and `:352-361`

The worker routes by `vector_family`, not by the declared `probe_profile.kind`:

```js
if (DNS_VECTOR_FAMILIES.has(vectorFamily)) return probeDns(...);      // {'dns'}
if (TCP_VECTOR_FAMILIES.has(vectorFamily)) return probeTcpConnect(...); // {'l3_l4'}
if (HTTP_VECTOR_FAMILIES.has(vectorFamily) || resolveHttpUrl(...)) return probeHttpHead(...);
```

`reflection` and `amplification` are in none of those sets, so they fall through to `resolveHttpUrl`, which returns `https://<host>/` for any fqdn target. Executed against the real worker with instrumented socket factories:

| check_id | declared kind | **actually runs** |
|---|---|---|
| `amp.memcached_exposure.safe` | `tcp_connect` | `http_head` → `https://host/` |
| `amp.dns_any_txt_exposure.safe` | `dns_resolve` | `http_head` |
| `amp.authoritative_resolver_exposure.safe` | `dns_resolve` | `http_head` |
| `reflect.portmap_service_exposure.safe` | `tcp_connect` | `http_head` |
| `reflect.tcp_middlebox_exposure.safe` | `tcp_connect` | `http_head` |
| `reflect.redis_direct_exposure.safe` | `tcp_connect` | `http_head` |

Memcached amplification exposure is determined by an HTTP request to port 443. `amp.dns_any_txt_exposure.safe` — the check backing `ATT-115`, one of the five `implemented` vectors — never issues a DNS query.

### D-03 · No check declares a service port; twelve reflection checks are byte-identical
**Severity: high.** `src/contracts/checks.mjs` (all `probe_profile` objects)

`0 of 175` checks carry a port. `parseNetworkEndpoint` (`src/lib/safeNetworkProbes.mjs:18`) takes the port from `target.port` or a `host:port` string, so **the customer supplies it**. Combined with D-01, these twelve checks are the same job with a different `check_id`:

`reflect.ssdp_exposure.safe`, `reflect.snmp_exposure.safe`, `reflect.chargen_qotd_exposure.safe`, `reflect.mdns_netbios_wsdiscovery_exposure.safe`, `reflect.dtls_sip_rdp_tftp_exposure.safe`, `reflect.mssql_resolver_exposure.safe`, `reflect.jenkins_discovery_exposure.safe`, `reflect.coap_iot_exposure.safe`, `reflect.legacy_device_discovery_exposure.safe`, `reflect.stun_turn_exposure.safe`, `reflect.ipmi_bmc_exposure.safe`, `reflect.openvpn_wireguard_exposure.safe`

— all with `required_customer_setup: ["declared_udp_fingerprint_host"]`. There is no SSDP check; there is one UDP check offered twelve times.

### D-04 · Eight business-logic checks collapse into 5 HEAD requests to `/`
**Severity: high.** `src/lib/capabilityProbes.mjs:764-822`

`probeRateLimitSequence` ignores every check-specific hint and does:

```js
const url = job.target?.value?.startsWith('http') ? job.target.value : baseUrlForHost(apexDomain(job) ?? '');
// … 5 × { method: 'HEAD', redirect: 'manual' } against that one URL
```

Sharing it: `l7.http_get_flood.validation`, `l7.search_abuse.validation`, `l7.export_abuse.validation`, `l7.oauth_token_abuse.validation`, `l7.signup_registration_abuse.validation`, `l7.login_abuse_flow.safe`, `l7.api_quota_exhaustion.safe`, `l7.low_rate_rate_limit.safe`.

A search-abuse verdict and a signup-flood verdict are produced by the same five HEADs to the site root. HEAD cannot exercise a search query, a login POST, or an OAuth token grant. These are E3 (they *do* return a verdict) which makes it worse — the verdict is confidently wrong about what it tested.

### D-05 · Probe kind contradicts the property being tested
**Severity: high.** `src/contracts/checks.mjs`

| check_id | probe | Why it cannot establish its verdict |
|---|---|---|
| `l7.http_method_restriction.safe` | `http_head` (method **HEAD**) | Backs `ATT-132` "HTTP TRACE / unusual method abuse". Cannot send TRACE, PUT, or DELETE. `scripts/vector-safety-policy-evidence.mjs:184` *enforces* that `http_head` uses HEAD, so this is locked in by policy. |
| `l7.header_size_boundary.safe` | `http_head`, 1 req, no oversized header | Never sends a large header. |
| `tls.slow_header_body_timeout.safe` | `http_head` | Cannot measure a slow-header timeout with one complete request. |
| `l7.expensive_endpoint.safe` | `http_head` | HEAD returns no body; response cost is unobservable. |
| `l7.wordpress_xmlrpc.readiness` | `http_head` | XML-RPC requires POST; WordPress answers HEAD `/xmlrpc.php` with 405 regardless of exposure. |
| `l7.http2_rapid_reset.validation` | `http2_settings`, 1 req | Reads the SETTINGS frame. Rapid Reset is a `HEADERS`+`RST_STREAM` loop; nothing about it is observable here. |
| `l7.http2_made_you_reset.readiness` | `http2_settings` | Same. |
| `l7.http2_continuation.readiness` | `http2_settings` | Same; CONTINUATION handling is untested. |
| `protocol.http3_control_stream.readiness` | `quic_reachability` | Alt-Svc parse + one datagram; control-stream behaviour untested. |
| `amp.memcached_exposure.safe` | `tcp_connect` (→ HTTP, per D-02) | Memcached amplification is **UDP**/11211. TCP/11211 liveness does not establish UDP amplification exposure. |

### D-06 · `probeDns` cannot produce DNS evidence
**Severity: high.** `workers/probe-worker.mjs:765-790`

It calls `dns.lookup(name)` — a **system-resolver A/AAAA lookup**. It therefore cannot: query the target's authoritative nameserver directly, set a qtype (`ANY`, `TXT`, `DNSKEY`), read the response size, or measure an amplification ratio. Real DNS wire capability exists in the tree (`src/lib/dnsTcpWire.mjs`, `src/lib/dnsTcpAxfrSession.mjs`) and is used for AXFR, but not here.

Consequences:
- `dns.amplification_exposure.safe` (`ATT-016`, `ATT-042`, `ATT-092`, `ATT-115`) measures nothing about amplification.
- `dns.random_prefix_nxdomain.safe` maps `ENOTFOUND` → `blocked`. A correctly-configured authoritative server returning NXDOMAIN is graded the same as a blocked probe, while a **wildcard-DNS server — the actual water-torture risk — resolves and is graded `connected`.** The polarity is inverted relative to the risk.
- `dns.nxns_attack.readiness`, `dns.tcp_fallback.readiness`, `dns.garbage_flood.readiness` declare `max_requests` 2–3 but `probeDns` always sends exactly one lookup.

### D-07 · The WAF scanner silently drops XSS when a direct origin IP is declared
**Severity: medium-high.** `src/lib/outsideInWafScanner.mjs:663-688`

`outside_in_waf_scan` has `max_requests: 10` (`src/contracts/checks.mjs:52`) but the plan has 13 phases. Verified against `buildOutsideInScanPlan(10, …)`:

| Configuration | Phases dropped |
|---|---|
| no direct IP | `xss_encoded_marker`, `no_user_agent`, `origin_bypass` |
| **direct IP declared** | **`xss_marker`**, `xss_encoded_marker`, `no_user_agent` |

Declaring an origin IP is the normal enterprise configuration, and it is exactly the configuration in which the dedicated XSS phase never runs. XSS survives only inside the `combined_marker` phase, which mixes three payload classes into one request — so a block cannot be attributed to the XSS rule specifically. `waf.fingerprint.safe` backs `ATT-102`/`ATT-170` and 10 catalog XSS rows.

### D-08 · 71 of 72 checks named `*.readiness` are excluded from readiness scoring
**Severity: high (product semantics).** `src/lib/readinessVerdicts.mjs:39-42`

`catalogCheckSupportsReadiness()` returns false for every `OBSERVATION_ONLY_PROBE_KIND`. Of 72 `*.readiness` checks, **only `tls.ocsp_stapling.readiness`** contributes to a readiness score. 57 of them are `metadata_marker` — zero I/O. The naming convention states the opposite of the behaviour, in the customer-visible check id.

### D-09 · The taxonomy validator forbids honest "pending" status
**Severity: medium (governance).** `scripts/validate-resource-exhaustion-taxonomy.mjs:209-212`

```js
if (pendingEntries.length > 0) errors.push(`pending attack vectors remain: …`);
```

`pending` is a defined value in `COVERAGE_STATUS_SEMANTICS` ("no mapped implementation exists yet") and the build fails if any entry uses it. The only way to add a vector is to attach *some* check, so a no-op `metadata_marker` gets attached and the entry is labelled `partial`. That is how the registry arrives at **139 `partial` / 5 `implemented` / 5 `soc_only`** — with 57 of the `partial` entries backed by nothing that opens a socket. The gate is structurally rewarding over-claiming.

### D-10 · 136 of 175 checks are not distinguishable from another check at execution time

| Probe signature | Checks sharing it |
|---|---:|
| `metadata_marker` (identical no-op) | 69 |
| `udp_probe` req=1, no params | 14 |
| `tcp_connect` req=1, no params | 12 |
| `rate_limit_sequence` req=5, no params | 8 |
| `http_head` req=1, method HEAD | 7 |
| `http2_settings` req=1 | 6 |
| `dns_resolve` req=2 / req=1 | 4 / 3 |
| `host_sni_bypass`, `tls_audit`, `quic_reachability` | 3 each |
| `waf_enforcement_probe`, `tls_session` | 2 each |

**39 checks have a genuinely unique execution profile.** The catalog presents 175 distinct capabilities.

### D-11 · SOC and offensive tiers have no in-repo executor
**Severity: informational, but it bounds every "SOC-gated coverage" claim.**

`src/services/executionAdapterStub.mjs:1-3` — *"SOC execution adapter boundary — dry-run metadata only; never generates traffic."* The 29 governed scenario families and the 8 WAF offensive suites are **authorization and evidence-ingest contracts**. The offensive suites carry no payload corpus and no per-CWE test cases — `waf.offensive_sqli.soc` is one `suite_id` with `max_requests: 12` covering the eight distinct SQLi rows `WAF-025`–`WAF-032`. This is a legitimate architecture (it keeps attack tooling out of the repo), but E4 must never be reported as delivered coverage.

---

## 4. Gap analysis — the 365 unmapped vectors

Full enumeration in **Appendix B**. The themes:

### 4.1 AI / LLM / agentic security — 21 vectors, 0 coverage
`WAF-163`–`WAF-176` (14) plus `EVA-087`–`EVA-089` (3) plus `APP-145`, `WAF-174`, and adjacent rows. Prompt injection (direct, indirect, multimodal), system-prompt extraction, tool/function-call parameter injection, agent goal hijacking, memory/retrieval poisoning, cross-agent message injection, unbounded model resource consumption. This is the single largest coherent block and the fastest-moving part of the catalog. AstraNull has no registry entry, no check, and no probe kind for any of it.

### 4.2 Classic OWASP classes with no registry entry at all — ~60 vectors
Not "partially covered" — **absent**:
- **SSRF** `WAF-061`–`WAF-066` (6)
- **XXE** `WAF-067`, `WAF-068` (2; `WAF-069` maps only via the `ATT-149` XML-bomb umbrella)
- **Insecure deserialization** `WAF-055`–`WAF-060` (6)
- **HTTP request smuggling** `WAF-007`–`WAF-010` (4)
- **NoSQL injection** `WAF-033`–`WAF-036` (4)
- **File upload** `WAF-087`–`WAF-093` (7)
- **JWT / token attacks** `WAF-108`–`WAF-111` (4)
- **SAML** `WAF-116`, `WAF-117` (2)
- **Session attacks** `WAF-104`–`WAF-106` (3)
- **BOLA / BFLA / mass assignment / privilege escalation** `WAF-119`–`WAF-136` (12)
- **Business logic** `WAF-138`–`WAF-141` (4)
- **CSRF** `WAF-107`; **open redirect** `WAF-024`; **prototype pollution** `WAF-053`, `WAF-054`; **CRLF injection** `WAF-011`; **JNDI** `WAF-047`; **XPath** `WAF-038`

The 8 offensive suites cover SQLi, XSS, RCE, path traversal, command injection, LDAP, SSTI — that is 7 of the ~40 injection/access-control families in the catalog.

### 4.3 WAF evasion — 69 of 91 unmapped
The scanner implements 5 evasion techniques (double-URL-encode, case variation, comment insertion, single URL-encode, content-type/multipart confusion) and applies them to SQLi/XSS/path traversal only. Unmapped clusters:
- **Encoding & canonicalization** — 10 of 14 (`EVA-004`–`EVA-013`: Unicode normalization, homoglyphs, overlong UTF-8, alternate charset, HTML/JS/JSON/CSS escapes, base64 wrapping, hex/octal)
- **Inspection limits** — all 4 (`EVA-035`–`EVA-038`: oversized-body bypass, field-count bypass, parser-timeout fail-open, late-arriving payload). **This is the highest-value missing cluster** — it tests whether the WAF fails *open*.
- **Rule engine policy** — all 3 (`EVA-067`–`EVA-069`: exclusion abuse, allowlist impersonation, fail-open on WAF error)
- **Message framing / parser differential** — 6 (`EVA-025`–`EVA-031`)
- **Client emulation & identity rotation** — 5 (`EVA-058`–`EVA-062`)
- **Modern protocol** — 4 (`EVA-083`–`EVA-086`: H3→H1 translation differential, QPACK/HPACK inspection gap, connection coalescing, ECH visibility gap)

### 4.4 HTTP/2 and HTTP/3 frame-level vectors — 14 unmapped
`APP-080`–`APP-085`, `APP-090`, `APP-091` (PING flood, SETTINGS flood, empty-frame flood, zero-length header flood, WINDOW_UPDATE flood, stalled flow control, internal buffering, malformed frames), `APP-196`, `APP-197` (H3 header-section and reserved-frame buffering), `APP-187`–`APP-189` (HTTP/2 Bomb, H3→H1 bandwidth and connection amplification), `APP-198` (fragmented ClientHello quadratic reassembly). Compounded by D-05: the six vectors that *are* mapped all resolve to one SETTINGS read.

### 4.5 Application-resource exhaustion primitives — ~25 unmapped
`APP-028` hash-collision DoS, `APP-032`–`APP-037` decompression/image/document/template/deserialization bombs, `APP-039`–`APP-049` (session memory, memory-leak trigger, fd exhaustion, thread-pool exhaustion, lock contention, queue flood, retry storm, cache stampede, autoscaling thrash, recursive call graph), `APP-057` N+1 expansion, `APP-135` denial-of-wallet, `APP-137` object-storage egress, `APP-139` telemetry exhaustion, `APP-143` third-party fan-out, `APP-152` crash/hang trigger.

### 4.6 Non-HTTP application services — 12 unmapped
LDAP bind/search (`APP-119`, `APP-120`), AMQP (`APP-124`, `APP-125`), IMAP/POP (`APP-118`), RDP (`APP-127`), SMB/NFS (`APP-129`), SOAP/RPC (`APP-134`), STOMP (`APP-199`), Redis decoder (`APP-200`), SIP parser exhaustion (`APP-185`, `APP-186`).

### 4.7 Malformed-packet families — ~40 unmapped
`NET-098`–`NET-124` are almost entirely absent: bad checksums (ICMP/TCP/UDP/SCTP/IPv4), header-length anomalies, length-field mismatches, IPv6 extension-header abuse (`NET-025`, `NET-109`–`NET-112`), IPv4/IPv6 interpretation abuse, TCP option overrun, ND/RS/RA/MLD floods (`NET-030`–`NET-034`). AstraNull's `exploit.*.posture` family has six entries and all six are `metadata_marker`.

### 4.8 Reflection protocols with no entry — 18
SLP `AMP-029` (very high amplification ratio, still widely exposed), TP240/Mitel `AMP-046` (record-holder amplification), TCP SYN-ACK reflection `AMP-048`, L2TP `AMP-032`, Kad `AMP-022`, CUPS/IPP `AMP-057`, NAT-PMP `AMP-058`, Sentinel `AMP-045`, TsuKing DNSRetry/DNSChain/DNSLoop `AMP-067`–`AMP-069`, cross-protocol UDP loop `AMP-051`, fastd `AMP-074`, VxWorks `AMP-055`, gateway discovery `AMP-061`, HTTP reflection/fan-out `AMP-072`, attacker-controlled callback `AMP-075`, AWS `UDS_REFLECTION` `AMP-073`.

### 4.9 Structurally out of scope — 36
`A1b` LAN/routing control plane (22: CAM/MAC, STP/BPDU, DHCP starvation, PPPoE, 802.1X/EAPOL, LLDP/CDP, LACP, VRRP/HSRP, PIM, MPLS, BGP, OSPF/IS-IS, BFD, ARP), `A1c` 802.11/RF (9), `A1d` mobile core (5: GTP-U, GTP-C, PFCP, Diameter, attach storms). These need L2 adjacency, a routing peer session, RF proximity, or a mobile-core interface. **Recommendation: declare them out of scope in the registry** (§6.4) rather than leave them as unexplained absences.

### 4.10 Registry ID hygiene
`ATT-028`–`ATT-040` and `ATT-076`–`ATT-089` (27 IDs) are unused. Either they were reserved and never filled, or entries were removed without a tombstone. Either way the registry is not self-describing about its own gaps.

---

## 5. Proposed categorization — four orthogonal axes

721 vectors cannot be navigated as a flat list, and the current UI taxonomy (`apps/web/react/src/lib/vector-coverage.mjs:17` — five families: Origin, L3/L4, DNS, L7/API, Protocol) is far too coarse. The proposal keeps everything that exists and adds two axes.

### Axis A — Attack-surface domain (primary navigation, 11 nodes)

| ID | Domain | Rows | Probe reachable? |
|---|---|---:|---|
| A1a | IP / Transport Packet Processing | 144 | partially (needs a packet-generation tier) |
| A1b | LAN / Routing Control Plane | 22 | **no** — L2 adjacency / peer session |
| A1c | Wireless / RF | 9 | **no** — RF proximity |
| A1d | Mobile / Telecom Signalling | 5 | **no** — core-network interface |
| A2 | Reflection & Amplification Exposure | 73 | yes — needs protocol-correct payloads |
| A3 | DNS Service Exhaustion | 36 | yes — needs a real DNS wire client |
| A4a | HTTP / API Application Exhaustion | 98 | yes |
| A4b | Non-HTTP Application Services | 33 | yes — needs per-protocol clients |
| A5 | Protocol Machinery (H2/H3/QUIC/WS/gRPC/TLS) | 34 | yes — needs a frame-level client |
| A7 | Web Application Attack Classes | 176 | yes (safe markers) / SOC (offensive) |
| A8 | Evasion & Delivery Patterns | 91 | yes — cross-cutting modifiers |

*(A6 is reserved for Edge/Origin Topology & Placement, which today lives inside `origin.*` and `EVA-074`–`EVA-078`; splitting it out is optional.)*

Rationale for the A1 split: it separates "we haven't built this yet" from "this is physically unreachable from a SaaS probe". Those two require completely different answers and today they are one undifferentiated pile.

### Axis B — Exhausted resource (keep as-is)
The 12 existing `EXHAUSTED_RESOURCE_FAMILIES` (volumetric, packet_processing, state_exhaustion, application_l7, computational, memory_exhaustion, backend_exhaustion, dns_exhaustion, reflection, amplification, exploit_dos, delivery_pattern) are sound and already validated. No change. **Extend to WAF vectors**, which currently have `exhausted_resource: null` — add `integrity_attack`, `access_control`, `data_exposure`, `automation_abuse`, `ai_agentic` so the 176 `WAF-*` rows are classifiable on this axis too.

### Axis C — Evidence tier (new; this is the axis that fixes the reporting problem)
`E0 unmapped` · `E1 declared-only` · `E2 transport-only` · `E3 semantic-safe` · `E4 SOC-governed` · `E5 monitor-only` (§1.1).

This **replaces** `coverage_status` (`implemented` / `partial` / `soc_only` / `pending`), whose `partial` bucket currently hides the difference between 45 real UDP datagrams and 57 no-ops. It should be **derived from the probe profile at build time**, not hand-authored, so it cannot drift:

```
E1 ⟸ probe_profile.kind === 'metadata_marker'
E2 ⟸ kind ∈ OBSERVATION_ONLY_PROBE_KINDS  (minus metadata_marker)
E3 ⟸ kind ∉ OBSERVATION_ONLY_PROBE_KINDS
E4 ⟸ no probe_profile (SOC / request_only)
```

### Axis D — Execution class (keep as-is)
`safe` (158) / `soc_gated` (17). Already enforced end-to-end.

### Cross-reference key
Adopt the CSV IDs (`NET-*`, `AMP-*`, `APP-*`, `WAF-*`, `EVA-*`) as the **canonical external vector identifiers** and add to every registry entry:

```js
{ id: 'ATT-020', catalog_vector_ids: ['AMP-008', 'NET-131', 'AMP-040', 'AMP-043', 'AMP-044', 'AMP-052', 'AMP-059'],
  domain: 'A2', evidence_tier: 'E2', … }
```

That makes both directions navigable (catalog → AstraNull, AstraNull → catalog), makes umbrella breadth explicit (`ATT-074` would list nine `APP-*` SIP rows), and lets the validator flag any catalog ID that no entry claims — turning §4 into a build-time check instead of a manual audit.

### Suggested UI grouping
Primary nav on **Axis A** (11 nodes, none over 180 rows) → filter chips on **Axis C** (evidence tier) and **Axis D** → colour the heatmap by **Axis C**, not by "has a check". A cell that is currently green because a `metadata_marker` check exists would render as E1, which is the honest signal.

---

## 6. Recommended work, in priority order

### 6.1 Truth-in-reporting (do first — no new probes, high risk reduction)
1. Add the derived `evidence_tier` field (§5 Axis C) and surface it everywhere `coverage_status` is shown today.
2. Remove the `pending`-is-an-error gate (`scripts/validate-resource-exhaustion-taxonomy.mjs:209`); allow `E0`/`pending` so gaps can be recorded honestly.
3. Rename or re-suffix the 71 non-scoring `*.readiness` checks (D-08) — the id currently contradicts the behaviour.
4. Make the validator assert **declared kind == executed kind** — that alone catches D-02 in CI.

### 6.2 Fix what we already claim (highest defect density per line changed)
5. **D-01/D-03** — add `service_port` + `payload_template` to `probe_profile`; implement protocol-correct probes for SSDP, SNMP, mDNS, NetBIOS, CoAP, STUN, IPMI/RMCP, MSSQL, TFTP, memcached-UDP, DTLS, Portmap. Emit `amplification_ratio = response_bytes / request_bytes`. Unlocks ~45 rows from E2 → E3.
6. **D-02** — route the worker on `probe_profile.kind`, not `vector_family`. Six checks, mechanical fix.
7. **D-06** — replace `dns.lookup` with the existing `dnsTcpWire` client; support qtype, direct-to-authoritative queries, and response-size capture. Also fixes the inverted NXDOMAIN polarity. Unlocks ~15 rows.
8. **D-04** — give `rate_limit_sequence` a per-check `path` / `method` / `body_template` from `required_customer_setup`. Eight checks.
9. **D-07** — raise `outside_in_waf_scan` to 13 requests, or make the XSS phases non-droppable.
10. **D-05** — introduce the probe kinds these checks actually need: `http_method_matrix`, `header_size_probe`, `slow_header_probe`, `http2_frame_probe`, `http3_control_probe`.

### 6.3 Close the biggest gaps (new capability)
11. **AI/LLM/agentic** (§4.1, 21 vectors) — new domain A9, safe marker probes for prompt-injection surfaces, SOC tier for adversarial suites. Largest coherent gap and the fastest-moving.
12. **WAF inspection-limit & fail-open evasion** (§4.3, `EVA-035`–`EVA-038`, `EVA-067`–`EVA-069`) — 7 vectors, high signal, safely testable outside-in. Best value per unit of work in the whole backlog.
13. **OWASP classes with no entry** (§4.2, ~60 vectors) — extend the offensive suite catalog beyond 8 classes; add safe posture markers for SSRF, XXE, deserialization, smuggling, JWT.
14. **H2/H3 frame-level** (§4.4, 14 vectors) — one real frame-level client retires most of §4.4 *and* D-05's protocol rows.

### 6.4 Declare scope explicitly
15. Add an `out_of_scope` registry section for the 36 `A1b`/`A1c`/`A1d` vectors with a stated reason (`requires_l2_adjacency`, `requires_rf_proximity`, `requires_mobile_core_interface`), mirroring how `NON_DDOS_AVAILABILITY_THREATS` already handles BGP hijacking. A stated exclusion is defensible; a silent absence is not.

---

## 7. Registry hygiene notes

- 27 unused `ATT-*` IDs (§4.10) — reserve or tombstone them.
- `ATT-093` carries `(docs: ATT-093)` inside its `name` field — a doc-sync artefact leaking into a customer-visible string.
- `WAF_VULNERABILITY_REGISTRY` has 8 entries for 176 catalog WAF rows; it needs to grow with the offensive suite catalog or be re-scoped as "offensive suite index".
- `EXHAUSTED_RESOURCE_FAMILIES` does not classify WAF vectors (`exhausted_resource: null`) — see §5 Axis B.

---

## Appendix A — Full 721-vector register

Domain codes per §5 Axis A. `Link`: **exact** = individually named in AstraNull; **umbrella** = subsumed by a broader entry, not separately identifiable in evidence; **none** = no entry.

| Vector ID | Canonical vector | Domain | AstraNull registry | Link | Evidence tier |
|---|---|---|---|---|---|
| AMP-001 | Open-recursive DNS reflection/amplification | A2 | ATT-042 | exact | E3 semantic-safe |
| AMP-002 | Authoritative DNS reflection/amplification | A2 | ATT-042 | exact | E3 semantic-safe |
| AMP-003 | DNSSEC response amplification | A2 | ATT-115 | exact | E3 semantic-safe |
| AMP-004 | NTP control-query reflection/amplification | A2 | ATT-017 | exact | E1 declared-only |
| AMP-005 | CLDAP reflection/amplification | A2 | ATT-018 | exact | E1 declared-only |
| AMP-006 | LDAP UDP reflection/amplification | A2 | ATT-018 | umbrella | E1 declared-only |
| AMP-007 | Memcached UDP reflection/amplification | A2 | ATT-019 | exact | E2 transport-only |
| AMP-008 | SSDP reflection/amplification | A2 | ATT-020 | exact | E2 transport-only |
| AMP-009 | SNMPv2 reflection/amplification | A2 | ATT-021 | exact | E2 transport-only |
| AMP-010 | Character Generator reflection/amplification | A2 | ATT-022 | exact | E2 transport-only |
| AMP-011 | Quote of the Day reflection/amplification | A2 | ATT-022 | exact | E2 transport-only |
| AMP-012 | UDP Echo reflection or loop | A2 | ATT-022 | exact | E2 transport-only |
| AMP-013 | Legacy Daytime or Time service reflection | A2 | ATT-024 | umbrella | E2 transport-only |
| AMP-014 | Multicast DNS reflection/amplification | A2 | ATT-023 | exact | E2 transport-only |
| AMP-015 | NetBIOS reflection/amplification | A2 | ATT-023 | exact | E2 transport-only |
| AMP-016 | RPCbind reflection/amplification | A2 | ATT-024 | exact | E2 transport-only |
| AMP-017 | NFS-related RPC reflection/amplification | A2 | ATT-024 | umbrella | E2 transport-only |
| AMP-018 | TFTP reflection/amplification | A2 | ATT-025 | exact | E2 transport-only |
| AMP-019 | RIPv1 reflection/amplification | A2 | ATT-024 | exact | E2 transport-only |
| AMP-020 | WS-Discovery reflection/amplification | A2 | ATT-023 | exact | E2 transport-only |
| AMP-021 | BitTorrent/uTP/DHT reflection/amplification | A2 | ATT-024 | exact | E2 transport-only |
| AMP-022 | Kad peer-to-peer reflection/amplification | A2 | — | none | E0 unmapped |
| AMP-023 | Quake server-query reflection/amplification | A2 | ATT-024 | umbrella | E2 transport-only |
| AMP-024 | Steam Valve Source Engine query reflection/amplification | A2 | ATT-024 | umbrella | E2 transport-only |
| AMP-025 | Unreal Tournament query reflection/amplification | A2 | ATT-024 | umbrella | E2 transport-only |
| AMP-026 | CoAP reflection/amplification | A2 | ATT-118 | exact | E2 transport-only |
| AMP-027 | STUN reflection/amplification | A2 | ATT-163 | exact | E2 transport-only |
| AMP-028 | SIP reflection/amplification | A2 | ATT-025 | exact | E2 transport-only |
| AMP-029 | Service Location Protocol reflection/amplification | A2 | — | none | E0 unmapped |
| AMP-030 | MSSQL resolution-service reflection/amplification | A2 | ATT-116 | exact | E2 transport-only |
| AMP-031 | ISAKMP/IKE reflection/amplification | A2 | ATT-136 | umbrella | E1 declared-only |
| AMP-032 | L2TP reflection/amplification | A2 | — | none | E0 unmapped |
| AMP-033 | OpenVPN reflection/amplification | A2 | ATT-168 | exact | E2 transport-only |
| AMP-034 | RDP reflection/amplification | A2 | ATT-025 | exact | E2 transport-only |
| AMP-035 | Citrix ICA reflection/amplification | A2 | ATT-025 | umbrella | E2 transport-only |
| AMP-036 | Generic DTLS reflection/amplification | A2 | ATT-025 | exact | E2 transport-only |
| AMP-037 | QUIC reflection/amplification from weak address validation | A2 | ATT-026 | exact | E2 transport-only |
| AMP-038 | IPMI reflection/amplification | A2 | ATT-164 | exact | E2 transport-only |
| AMP-039 | BACnet reflection/amplification | A2 | ATT-118 | umbrella | E2 transport-only |
| AMP-040 | Ubiquiti discovery reflection/amplification | A2 | ATT-020 | umbrella | E2 transport-only |
| AMP-041 | ARMS reflection/amplification | A2 | ATT-025 | exact | E2 transport-only |
| AMP-042 | Jenkins reflection/amplification | A2 | ATT-117 | exact | E2 transport-only |
| AMP-043 | Plex Media SSDP reflection/amplification | A2 | ATT-020 | umbrella | E2 transport-only |
| AMP-044 | DVR DHCPDiscover reflection/amplification | A2 | ATT-020 | umbrella | E2 transport-only |
| AMP-045 | Sentinel/SPSS license-server reflection/amplification | A2 | — | none | E0 unmapped |
| AMP-046 | TP240 PhoneHome reflection/amplification | A2 | — | none | E0 unmapped |
| AMP-047 | MBHTTP middlebox reflection/amplification | A2 | ATT-027 | exact | E2 transport-only |
| AMP-048 | TCP SYN-ACK reflection/amplification | A2 | — | none | E0 unmapped |
| AMP-049 | Smurf reflection/amplification | A2 | ATT-134 | exact | E1 declared-only |
| AMP-050 | Fraggle reflection/amplification | A2 | ATT-134 | umbrella | E1 declared-only |
| AMP-051 | Cross-protocol UDP application loop | A2 | — | none | E0 unmapped |
| AMP-052 | Lantronix device-discovery reflection | A2 | ATT-020 | umbrella | E2 transport-only |
| AMP-053 | TeamSpeak 3 reflection or query flood | A2 | ATT-024 | exact | E2 transport-only |
| AMP-055 | VxWorks device reflection or protocol abuse | A2 | — | none | E0 unmapped |
| AMP-056 | Generic UDP error-response reflection | A2 | ATT-092 | umbrella | E2 transport-only |
| AMP-057 | CUPS/IPP callback reflection/amplification | A2 | — | none | E0 unmapped |
| AMP-058 | NAT-PMP reflection/amplification | A2 | — | none | E0 unmapped |
| AMP-059 | SADP device-discovery reflection/amplification | A2 | ATT-020 | umbrella | E2 transport-only |
| AMP-060 | Crestron CIP discovery reflection/amplification | A2 | ATT-118 | umbrella | E2 transport-only |
| AMP-061 | Gateway-discovery protocol reflection/amplification | A2 | — | none | E0 unmapped |
| AMP-062 | Steam Remote Play discovery reflection/amplification | A2 | ATT-024 | umbrella | E2 transport-only |
| AMP-063 | FiveM server-query reflection/amplification | A2 | ATT-024 | umbrella | E2 transport-only |
| AMP-065 | DNSBomb coordinated resolver pulse amplification | A2 | ATT-050 | exact | E1 declared-only |
| AMP-066 | NXNSAttack referral-induced DNS amplification | A2 | ATT-049 | exact | E2 transport-only |
| AMP-067 | TsuKing DNSRetry coordinated amplification | A2 | — | none | E0 unmapped |
| AMP-068 | TsuKing DNSChain coordinated amplification | A2 | — | none | E0 unmapped |
| AMP-069 | TsuKing DNSLoop coordinated amplification | A2 | — | none | E0 unmapped |
| AMP-070 | IPv6 reflection/amplification using UDP application protocols | A2 | ATT-124 | umbrella | E2 transport-only |
| AMP-071 | Censorship or policy-middlebox TCP reflection/amplification | A2 | ATT-027 | exact | E2 transport-only |
| AMP-072 | Generic HTTP reflection or callback fan-out | A2 | — | none | E0 unmapped |
| AMP-073 | AWS UDS_REFLECTION provider-reported vector | A2 | — | none | E0 unmapped |
| AMP-074 | fastd VPN reconnect reflection/amplification | A2 | — | none | E0 unmapped |
| AMP-075 | Attacker-controlled UDP acknowledgement or callback reflection | A2 | — | none | E0 unmapped |
| APP-001 | HTTP GET flood | A4a | ATT-051 | exact | E3 semantic-safe |
| APP-002 | HTTP HEAD flood | A4a | ATT-053 | exact | E2 transport-only |
| APP-003 | HTTP POST flood | A4a | ATT-052 | exact | E1 declared-only |
| APP-004 | HTTP PUT, PATCH, or DELETE flood | A4a | — | none | E0 unmapped |
| APP-005 | Mixed-method HTTP flood | A4a | ATT-051 | umbrella | E3 semantic-safe |
| APP-006 | HTTPS request flood | A4a | ATT-051 | umbrella | E3 semantic-safe |
| APP-007 | Dynamic-page or dynamic-API flood | A4a | ATT-054 | exact | E3 semantic-safe |
| APP-008 | Cache-busting query-string flood | A4a | ATT-058 | exact | E3 semantic-safe |
| APP-009 | Cache-key explosion | A4a | ATT-058 | umbrella | E3 semantic-safe |
| APP-010 | Random URL or nonexistent-path flood | A4a | ATT-058 | umbrella | E3 semantic-safe |
| APP-011 | Expensive endpoint selection | A4a | ATT-097 | exact | E2 transport-only |
| APP-012 | Large-response request flood | A4a | — | none | E0 unmapped |
| APP-013 | HTTP Range request abuse | A4a | ATT-141 | exact | E1 declared-only |
| APP-014 | Large request-body flood | A4a | ATT-059 | exact | E2 transport-only |
| APP-015 | Multipart part-count flood | A4a | ATT-113 | umbrella | E1 declared-only |
| APP-016 | Slowloris or slow-header attack | A4a | ATT-060 | exact | E2 transport-only |
| APP-017 | Slow POST or slow-body attack | A4a | ATT-061 | exact | E1 declared-only |
| APP-018 | Slow Read attack | A4a | ATT-062 | exact | E1 declared-only |
| APP-019 | HTTP keep-alive exhaustion | A4a | ATT-075 | umbrella | E2 transport-only |
| APP-020 | HTTP long-poll exhaustion | A4a | ATT-104 | umbrella | E1 declared-only |
| APP-021 | Server-Sent Events connection exhaustion | A4a | ATT-104 | exact | E1 declared-only |
| APP-022 | HTTP/1.1 pipelining or request-queue flood | A4a | ATT-140 | exact | E1 declared-only |
| APP-023 | HTTP request-smuggling availability attack | A4a | — | none | E0 unmapped |
| APP-024 | Oversized HTTP header flood | A4a | ATT-059 | umbrella | E2 transport-only |
| APP-025 | Excessive query-parameter flood | A4a | — | none | E0 unmapped |
| APP-026 | HTTP error-log flood | A4a | — | none | E0 unmapped |
| APP-027 | Regular Expression Denial of Service | A4a | ATT-147 | exact | E1 declared-only |
| APP-028 | Hash-collision denial of service | A4a | — | none | E0 unmapped |
| APP-029 | Pathological sorting, filtering, or comparison input | A4a | — | none | E0 unmapped |
| APP-030 | Deeply nested JSON exhaustion | A4a | ATT-148 | exact | E1 declared-only |
| APP-031 | XML entity expansion bomb | A4a | ATT-149 | exact | E1 declared-only |
| APP-032 | External entity or resource-fetch exhaustion | A4a | — | none | E0 unmapped |
| APP-033 | Compressed request decompression bomb | A4a | — | none | E0 unmapped |
| APP-034 | Image decompression or transformation bomb | A4a | — | none | E0 unmapped |
| APP-035 | PDF, office document, or archive processing exhaustion | A4a | — | none | E0 unmapped |
| APP-036 | Server-side template rendering exhaustion | A4a | — | none | E0 unmapped |
| APP-037 | Deserialization resource-exhaustion payload | A4a | — | none | E0 unmapped |
| APP-038 | Mass object-binding exhaustion | A4a | — | none | E0 unmapped |
| APP-039 | Session-object memory exhaustion | A4a | — | none | E0 unmapped |
| APP-040 | Unbounded request buffering | A4a | ATT-059 | umbrella | E2 transport-only |
| APP-041 | Memory leak trigger flood | A4a | — | none | E0 unmapped |
| APP-042 | Application socket or file-descriptor exhaustion | A4a | ATT-075 | umbrella | E2 transport-only |
| APP-043 | Worker or thread-pool exhaustion | A4a | ATT-075 | umbrella | E2 transport-only |
| APP-044 | Hot-key or lock-contention attack | A4a | — | none | E0 unmapped |
| APP-045 | Job, message, or task queue flood | A4a | — | none | E0 unmapped |
| APP-046 | Retry storm | A4a | — | none | E0 unmapped |
| APP-047 | Cache stampede or thundering-herd trigger | A4a | — | none | E0 unmapped |
| APP-048 | Autoscaling thrash attack | A4a | — | none | E0 unmapped |
| APP-049 | Recursive or cyclic service-call exhaustion | A4a | — | none | E0 unmapped |
| APP-050 | Database query flood | A4a | ATT-055 | exact | E3 semantic-safe |
| APP-051 | Full-scan or unindexed-filter abuse | A4a | ATT-055 | umbrella | E3 semantic-safe |
| APP-052 | Database connection-pool exhaustion | A4a | ATT-055 | umbrella | E3 semantic-safe |
| APP-053 | Transaction-lock contention flood | A4a | ATT-055 | umbrella | E3 semantic-safe |
| APP-054 | Expensive report or export generation flood | A4a | ATT-106 | exact | E3 semantic-safe |
| APP-055 | Search-engine query flood | A4a | ATT-105 | exact | E3 semantic-safe |
| APP-056 | Aggregation, sort, or facet explosion | A4a | ATT-105 | umbrella | E3 semantic-safe |
| APP-057 | N+1 object-expansion abuse | A4a | — | none | E0 unmapped |
| APP-058 | Login and password-hash exhaustion | A4a | ATT-112 | umbrella | E3 semantic-safe |
| APP-059 | Token-validation exhaustion | A4a | ATT-112 | exact | E3 semantic-safe |
| APP-060 | Federated identity-provider exhaustion | A4a | — | none | E0 unmapped |
| APP-061 | CAPTCHA or bot-challenge cost exhaustion | A4a | ATT-145 | exact | E3 semantic-safe |
| APP-062 | GraphQL depth exhaustion | A4a | ATT-057 | exact | E3 semantic-safe |
| APP-063 | GraphQL breadth or alias explosion | A4a | ATT-114 | exact | E3 semantic-safe |
| APP-064 | GraphQL batching exhaustion | A4a | ATT-114 | exact | E3 semantic-safe |
| APP-065 | GraphQL fragment expansion exhaustion | A4a | ATT-057 | umbrella | E3 semantic-safe |
| APP-066 | GraphQL pagination and filter explosion | A4a | ATT-057 | umbrella | E3 semantic-safe |
| APP-067 | GraphQL subscription exhaustion | A4a | — | none | E0 unmapped |
| APP-068 | gRPC unary request flood | A5 | ATT-072 | exact | E3 semantic-safe |
| APP-069 | gRPC stream exhaustion | A5 | ATT-072 | umbrella | E3 semantic-safe |
| APP-070 | gRPC message flood within streams | A5 | ATT-072 | umbrella | E3 semantic-safe |
| APP-071 | gRPC decompression exhaustion | A5 | — | none | E0 unmapped |
| APP-072 | WebSocket handshake flood | A5 | ATT-071 | exact | E2 transport-only |
| APP-073 | WebSocket connection-hold exhaustion | A5 | ATT-071 | exact | E2 transport-only |
| APP-074 | WebSocket message flood | A5 | ATT-071 | exact | E2 transport-only |
| APP-075 | WebSocket broadcast or room fan-out abuse | A5 | — | none | E0 unmapped |
| APP-076 | WebSocket compression exhaustion | A5 | — | none | E0 unmapped |
| APP-077 | HTTP/2 Rapid Reset | A5 | ATT-067 | exact | E2 transport-only |
| APP-078 | HTTP/2 MadeYouReset | A5 | ATT-069 | exact | E2 transport-only |
| APP-079 | HTTP/2 CONTINUATION frame exhaustion | A5 | ATT-068 | exact | E2 transport-only |
| APP-080 | HTTP/2 stalled flow-control exhaustion | A5 | — | none | E0 unmapped |
| APP-081 | HTTP/2 PING flood | A5 | — | none | E0 unmapped |
| APP-082 | HTTP/2 SETTINGS flood | A5 | — | none | E0 unmapped |
| APP-083 | HTTP/2 empty-frame flood | A5 | — | none | E0 unmapped |
| APP-084 | HTTP/2 zero-length header flood | A5 | — | none | E0 unmapped |
| APP-085 | HTTP/2 internal data buffering exhaustion | A5 | — | none | E0 unmapped |
| APP-086 | HTTP/2 priority or dependency-tree exhaustion | A5 | ATT-110 | exact | E1 declared-only |
| APP-087 | HTTP/2 reset flood | A5 | ATT-067 | umbrella | E2 transport-only |
| APP-088 | HTTP/2 stream-creation flood | A5 | ATT-066 | exact | E2 transport-only |
| APP-089 | HPACK header decompression exhaustion | A5 | ATT-150 | exact | E1 declared-only |
| APP-090 | HTTP/2 WINDOW_UPDATE flood | A5 | — | none | E0 unmapped |
| APP-091 | Malformed HTTP/2 frame or state-machine flood | A5 | — | none | E0 unmapped |
| APP-092 | HTTP/3 request flood | A5 | ATT-070 | exact | E2 transport-only |
| APP-093 | HTTP/3 stream-creation flood | A5 | ATT-070 | umbrella | E2 transport-only |
| APP-094 | QPACK blocked-stream exhaustion | A5 | ATT-152 | umbrella | E1 declared-only |
| APP-095 | QPACK decompression or table-churn exhaustion | A5 | ATT-152 | exact | E1 declared-only |
| APP-096 | HTTP/3 control-frame flood | A5 | ATT-153 | exact | E2 transport-only |
| APP-097 | QUIC connection-ID or migration churn | A5 | ATT-154 | exact | E1 declared-only |
| APP-098 | QUIC 0-RTT replay of expensive operations | A5 | ATT-111 | exact | E1 declared-only |
| APP-099 | Direct DNS query flood | A3 | ATT-041 | exact | E2 transport-only |
| APP-100 | DNS random-subdomain water-torture attack | A3 | ATT-044 | exact | E2 transport-only |
| APP-101 | DNS NXDOMAIN flood | A3 | ATT-043 | exact | E2 transport-only |
| APP-102 | DNS cache-busting query flood | A3 | ATT-046 | umbrella | E2 transport-only |
| APP-103 | Recursive-resolver exhaustion | A3 | ATT-042 | umbrella | E3 semantic-safe |
| APP-104 | DNSSEC validation exhaustion | A3 | — | none | E0 unmapped |
| APP-105 | Online DNSSEC signing exhaustion | A3 | — | none | E0 unmapped |
| APP-106 | Large-record DNS query flood | A3 | ATT-115 | exact | E3 semantic-safe |
| APP-107 | CNAME or delegation-chain exhaustion | A3 | ATT-048 | umbrella | E1 declared-only |
| APP-108 | DNS-over-HTTPS request flood | A3 | ATT-159 | exact | E1 declared-only |
| APP-109 | DNS-over-TLS handshake or query flood | A3 | ATT-159 | exact | E1 declared-only |
| APP-110 | DNS laundering attack | A3 | ATT-045 | exact | E1 declared-only |
| APP-111 | DNS zone-transfer, NOTIFY, or dynamic-update exhaustion | A3 | ATT-161 | umbrella | E3 semantic-safe |
| APP-112 | SIP INVITE flood | A4b | ATT-074 | umbrella | E2 transport-only |
| APP-113 | SIP REGISTER flood | A4b | ATT-074 | umbrella | E2 transport-only |
| APP-114 | SIP OPTIONS or malformed-message flood | A4b | ATT-074 | umbrella | E2 transport-only |
| APP-115 | SMTP connection and greeting flood | A4b | ATT-123 | exact | E2 transport-only |
| APP-116 | SMTP command or recipient explosion | A4b | ATT-123 | umbrella | E2 transport-only |
| APP-117 | Mail queue or backscatter exhaustion | A4b | — | none | E0 unmapped |
| APP-118 | Mailbox authentication or command flood | A4b | — | none | E0 unmapped |
| APP-119 | LDAP bind flood | A4b | — | none | E0 unmapped |
| APP-120 | LDAP expensive-search exhaustion | A4b | — | none | E0 unmapped |
| APP-121 | MQTT CONNECT flood | A4b | ATT-167 | exact | E1 declared-only |
| APP-122 | MQTT subscribe or topic-filter explosion | A4b | ATT-167 | umbrella | E1 declared-only |
| APP-123 | MQTT publish fan-out flood | A4b | ATT-167 | umbrella | E1 declared-only |
| APP-124 | AMQP connection or channel exhaustion | A4b | — | none | E0 unmapped |
| APP-125 | AMQP queue, routing, or message flood | A4b | — | none | E0 unmapped |
| APP-126 | SSH handshake or key-exchange exhaustion | A4b | ATT-138 | exact | E2 transport-only |
| APP-127 | RDP connection or authentication flood | A4b | — | none | E0 unmapped |
| APP-128 | FTP control or data-session exhaustion | A4b | ATT-139 | exact | E2 transport-only |
| APP-129 | File-service operation flood | A4b | — | none | E0 unmapped |
| APP-130 | Native database connection or query flood | A4b | ATT-055 | umbrella | E3 semantic-safe |
| APP-131 | Direct key-value command flood | A4b | ATT-165 | exact | E2 transport-only |
| APP-132 | Media segment or transcode request flood | A4a | — | none | E0 unmapped |
| APP-133 | XML-RPC multicall or pingback exhaustion | A4a | ATT-073 | exact | E2 transport-only |
| APP-134 | SOAP or generic RPC operation flood | A4a | — | none | E0 unmapped |
| APP-135 | Serverless invocation or denial-of-wallet flood | A4a | — | none | E0 unmapped |
| APP-136 | API gateway quota or policy-engine exhaustion | A4a | ATT-056 | exact | E3 semantic-safe |
| APP-137 | Object-storage request-rate or egress flood | A4a | — | none | E0 unmapped |
| APP-138 | Upload storage exhaustion | A4a | ATT-113 | exact | E1 declared-only |
| APP-139 | Log, trace, or telemetry exhaustion | A4a | — | none | E0 unmapped |
| APP-140 | Error-page or exception-generation flood | A4a | — | none | E0 unmapped |
| APP-141 | SMS, voice, email, or push-notification flood | A4a | ATT-144 | exact | E3 semantic-safe |
| APP-142 | Webhook or callback fan-out exhaustion | A4a | ATT-108 | exact | E1 declared-only |
| APP-143 | Third-party API fan-out or quota exhaustion | A4a | — | none | E0 unmapped |
| APP-144 | Payment authorization or fraud-check flood | A4a | ATT-143 | umbrella | E1 declared-only |
| APP-145 | Machine-learning or LLM inference exhaustion | A4a | — | none | E0 unmapped |
| APP-146 | Document, archive, image, or media processing flood | A4a | — | none | E0 unmapped |
| APP-147 | URL preview, crawler, or SSRF fan-out exhaustion | A4a | — | none | E0 unmapped |
| APP-148 | Account-lockout denial attack | A4a | — | none | E0 unmapped |
| APP-149 | Denial of inventory | A4a | ATT-143 | umbrella | E1 declared-only |
| APP-150 | Queue, appointment, or booking-slot exhaustion | A4a | ATT-143 | umbrella | E1 declared-only |
| APP-151 | Scraping or crawler resource exhaustion | A4a | ATT-169 | exact | E3 semantic-safe |
| APP-152 | Application crash, hang, deadlock, or infinite-loop trigger | A4a | — | none | E0 unmapped |
| APP-153 | DNS A query flood | A3 | ATT-041 | umbrella | E2 transport-only |
| APP-154 | DNS AAAA query flood | A3 | ATT-041 | umbrella | E2 transport-only |
| APP-155 | DNS ANY query flood | A3 | ATT-115 | exact | E3 semantic-safe |
| APP-156 | DNS CNAME query flood | A3 | ATT-041 | umbrella | E2 transport-only |
| APP-157 | DNS MX query flood | A3 | ATT-041 | umbrella | E2 transport-only |
| APP-158 | DNS NS query flood | A3 | ATT-041 | umbrella | E2 transport-only |
| APP-159 | DNS PTR query flood | A3 | ATT-041 | umbrella | E2 transport-only |
| APP-160 | DNS SOA query flood | A3 | ATT-041 | umbrella | E2 transport-only |
| APP-161 | DNS SRV query flood | A3 | ATT-041 | umbrella | E2 transport-only |
| APP-162 | DNS TXT query flood | A3 | ATT-115 | exact | E3 semantic-safe |
| APP-163 | DNS AXFR query flood | A3 | ATT-161 | umbrella | E3 semantic-safe |
| APP-164 | DNS IXFR query flood | A3 | ATT-161 | umbrella | E3 semantic-safe |
| APP-165 | DNS unknown/other query flood | A3 | ATT-041 | umbrella | E2 transport-only |
| APP-166 | Malformed DNS message flood | A3 | ATT-046 | exact | E2 transport-only |
| APP-167 | Oversized DNS message flood | A3 | ATT-046 | umbrella | E2 transport-only |
| APP-168 | Multi-question DNS query flood | A3 | — | none | E0 unmapped |
| APP-169 | DNS response flood | A3 | — | none | E0 unmapped |
| APP-170 | DNS phantom-domain resolver attack | A3 | ATT-047 | exact | E1 declared-only |
| APP-171 | KeyTrap DNSSEC validation-complexity attack | A3 | — | none | E0 unmapped |
| APP-172 | DNS-over-QUIC request or stream flood | A3 | — | none | E0 unmapped |
| APP-173 | DoQ or DoH3 connection/stream memory exhaustion | A3 | — | none | E0 unmapped |
| APP-174 | Oversized DNS-over-HTTPS GET decoding exhaustion | A3 | ATT-159 | umbrella | E1 declared-only |
| APP-175 | DNS-over-HTTPS backend queue accumulation | A3 | ATT-159 | umbrella | E1 declared-only |
| APP-176 | SIP ACK flood | A4b | ATT-074 | umbrella | E2 transport-only |
| APP-177 | SIP BYE flood | A4b | ATT-074 | umbrella | E2 transport-only |
| APP-178 | SIP CANCEL flood | A4b | ATT-074 | umbrella | E2 transport-only |
| APP-179 | SIP MESSAGE flood | A4b | ATT-074 | umbrella | E2 transport-only |
| APP-180 | SIP NOTIFY flood | A4b | ATT-074 | umbrella | E2 transport-only |
| APP-181 | SIP PRACK flood | A4b | ATT-074 | umbrella | E2 transport-only |
| APP-182 | SIP PUBLISH flood | A4b | ATT-074 | umbrella | E2 transport-only |
| APP-183 | SIP SUBSCRIBE flood | A4b | ATT-074 | umbrella | E2 transport-only |
| APP-184 | SIP unknown/other flood | A4b | ATT-074 | umbrella | E2 transport-only |
| APP-185 | Malformed SIP message flood | A4b | — | none | E0 unmapped |
| APP-186 | SIP URI-length or field-count exhaustion | A4b | — | none | E0 unmapped |
| APP-187 | HTTP/2 Bomb composite memory-exhaustion attack | A4a | — | none | E0 unmapped |
| APP-188 | HTTP/3-to-HTTP/1.1 bandwidth amplification | A4a | — | none | E0 unmapped |
| APP-189 | HTTP/3-to-HTTP/1.1 connection amplification | A4a | — | none | E0 unmapped |
| APP-190 | HTML5 ping-attribute browser fan-out flood | A4a | — | none | E0 unmapped |
| APP-191 | TLS session-resumption or ticket-validation flood | A4a | — | none | E0 unmapped |
| APP-192 | TLS 1.3 early-data replay of expensive requests | A4a | ATT-111 | exact | E1 declared-only |
| APP-193 | WebSocket control-frame flood | A4a | ATT-071 | umbrella | E2 transport-only |
| APP-194 | Cache purge or invalidation API flood | A4a | — | none | E0 unmapped |
| APP-195 | Conditional revalidation or validator-bypass flood | A4a | ATT-142 | exact | E1 declared-only |
| APP-196 | HTTP/3 unbounded header-field-section memory exhaustion | A5 | — | none | E0 unmapped |
| APP-197 | HTTP/3 reserved-frame declared-length buffering exhaustion | A5 | — | none | E0 unmapped |
| APP-198 | Fragmented TLS ClientHello quadratic reassembly exhaustion | A5 | — | none | E0 unmapped |
| APP-199 | STOMP unbounded-header-count memory exhaustion | A4b | — | none | E0 unmapped |
| APP-200 | Redis unterminated length-line decoder memory exhaustion | A4b | — | none | E0 unmapped |
| APP-201 | Incremental XML frame rescanning or trickle-feed CPU exhaustion | A4a | — | none | E0 unmapped |
| EVA-001 | Single URL percent encoding | A8 | ATT-170 | exact | E3 semantic-safe |
| EVA-002 | Double or recursive URL encoding | A8 | ATT-170 | exact | E3 semantic-safe |
| EVA-003 | Mixed encoding layers | A8 | ATT-170 | umbrella | E3 semantic-safe |
| EVA-004 | Unicode normalization mismatch | A8 | — | none | E0 unmapped |
| EVA-005 | Unicode homoglyph or confusable substitution | A8 | — | none | E0 unmapped |
| EVA-006 | Invalid or overlong UTF-8 handling discrepancy | A8 | — | none | E0 unmapped |
| EVA-007 | Alternate declared character set | A8 | — | none | E0 unmapped |
| EVA-008 | HTML entity encoding | A8 | — | none | E0 unmapped |
| EVA-009 | JavaScript string or Unicode escapes | A8 | — | none | E0 unmapped |
| EVA-010 | JSON Unicode escape encoding | A8 | — | none | E0 unmapped |
| EVA-011 | CSS escape encoding | A8 | — | none | E0 unmapped |
| EVA-012 | Base64 or application-level textual wrapping | A8 | — | none | E0 unmapped |
| EVA-013 | Hexadecimal, octal, or numeric representation | A8 | — | none | E0 unmapped |
| EVA-014 | Case variation and case folding | A8 | ATT-170 | exact | E3 semantic-safe |
| EVA-015 | Whitespace substitution | A8 | — | none | E0 unmapped |
| EVA-016 | Comment insertion or token splitting | A8 | ATT-170 | exact | E3 semantic-safe |
| EVA-017 | Operator and function substitution | A8 | — | none | E0 unmapped |
| EVA-018 | Logical invariant or tautology mutation | A8 | — | none | E0 unmapped |
| EVA-019 | Number and literal shuffling | A8 | — | none | E0 unmapped |
| EVA-020 | Null-byte and control-character insertion | A8 | — | none | E0 unmapped |
| EVA-021 | Alternate path separators and dot segments | A8 | ATT-170 | umbrella | E3 semantic-safe |
| EVA-022 | Matrix parameters and path-parameter ambiguity | A8 | — | none | E0 unmapped |
| EVA-023 | Trailing dot, slash, suffix, or path-info ambiguity | A8 | — | none | E0 unmapped |
| EVA-024 | Alternative IP-address representation | A8 | — | none | E0 unmapped |
| EVA-025 | HTTP parameter pollution | A8 | — | none | E0 unmapped |
| EVA-026 | Duplicate JSON key ambiguity | A8 | — | none | E0 unmapped |
| EVA-027 | Duplicate or conflicting HTTP header ambiguity | A8 | — | none | E0 unmapped |
| EVA-028 | Content-Length versus Transfer-Encoding desynchronization | A8 | — | none | E0 unmapped |
| EVA-029 | Transfer-coding obfuscation | A8 | — | none | E0 unmapped |
| EVA-030 | HTTP/2-to-HTTP/1 request smuggling | A8 | — | none | E0 unmapped |
| EVA-031 | Line-ending and request-splitting discrepancy | A8 | — | none | E0 unmapped |
| EVA-032 | Chunk-extension or trailer ambiguity | A8 | — | none | E0 unmapped |
| EVA-033 | Compressed request-body evasion | A8 | — | none | E0 unmapped |
| EVA-034 | Nested content encoding | A8 | — | none | E0 unmapped |
| EVA-035 | Oversized-body inspection bypass | A8 | — | none | E0 unmapped |
| EVA-036 | High field/part/count bypass | A8 | — | none | E0 unmapped |
| EVA-037 | Parser timeout or resource-budget fail-open | A8 | — | none | E0 unmapped |
| EVA-038 | Streaming or late-arriving payload | A8 | — | none | E0 unmapped |
| EVA-039 | Content-Type switching | A8 | ATT-170 | exact | E3 semantic-safe |
| EVA-040 | Multipart/form-data ambiguity | A8 | ATT-170 | exact | E3 semantic-safe |
| EVA-041 | Binary or protobuf opacity | A8 | — | none | E0 unmapped |
| EVA-042 | GraphQL alias and field multiplication | A8 | ATT-114 | umbrella | E3 semantic-safe |
| EVA-043 | GraphQL batching | A8 | ATT-114 | umbrella | E3 semantic-safe |
| EVA-044 | Type confusion and scalar/object switching | A8 | — | none | E0 unmapped |
| EVA-045 | Deep nesting and sparse-index abuse | A8 | — | none | E0 unmapped |
| EVA-046 | Move input among query, body, cookie, header, path, or trailer | A8 | — | none | E0 unmapped |
| EVA-047 | HTTP method override | A8 | — | none | E0 unmapped |
| EVA-048 | Switch among HTTP/1.1, HTTP/2, and HTTP/3 | A8 | — | none | E0 unmapped |
| EVA-049 | WebSocket upgrade and post-upgrade opacity | A8 | — | none | E0 unmapped |
| EVA-050 | Cache-key and routing mismatch | A8 | — | none | E0 unmapped |
| EVA-051 | IP fragmentation or TCP segmentation differential | A8 | — | none | E0 unmapped |
| EVA-052 | Source IP rotation | A8 | ATT-175 | exact | E3 semantic-safe |
| EVA-053 | IPv6 address rotation | A8 | ATT-175 | umbrella | E3 semantic-safe |
| EVA-054 | Residential, mobile, or ISP proxy use | A8 | ATT-146 | exact | E1 declared-only |
| EVA-055 | Low-and-slow distribution | A8 | ATT-146 | umbrella | E1 declared-only |
| EVA-056 | Randomized timing and jitter | A8 | ATT-121 | exact | E1 declared-only |
| EVA-057 | Pulse or burst threshold gaming | A8 | ATT-095 | umbrella | E1 declared-only |
| EVA-058 | Real-browser automation | A8 | — | none | E0 unmapped |
| EVA-059 | Headless-browser fingerprint masking | A8 | — | none | E0 unmapped |
| EVA-060 | Session and cookie warming | A8 | — | none | E0 unmapped |
| EVA-061 | Account rotation | A8 | — | none | E0 unmapped |
| EVA-062 | Credential, token, or API-key rotation | A8 | — | none | E0 unmapped |
| EVA-063 | Endpoint, parameter, or object rotation | A8 | — | none | E0 unmapped |
| EVA-064 | Polymorphic request mutation | A8 | ATT-121 | umbrella | E1 declared-only |
| EVA-065 | Benign padding and anomaly-score dilution | A8 | — | none | E0 unmapped |
| EVA-066 | Threshold and rule probing | A8 | — | none | E0 unmapped |
| EVA-067 | Rule exclusion or exception abuse | A8 | — | none | E0 unmapped |
| EVA-068 | Allowlist or trusted-client impersonation | A8 | — | none | E0 unmapped |
| EVA-069 | Fail-open on WAF error or outage | A8 | — | none | E0 unmapped |
| EVA-070 | Policy/version drift between WAF nodes or environments | A8 | — | none | E0 unmapped |
| EVA-071 | Zero-day or rule-gap evasion | A8 | — | none | E0 unmapped |
| EVA-072 | Stored or deferred payload execution | A8 | — | none | E0 unmapped |
| EVA-073 | Attack state assembled across requests | A8 | — | none | E0 unmapped |
| EVA-074 | Direct origin access bypassing CDN/WAF | A8 | ATT-100 | exact | E3 semantic-safe |
| EVA-075 | Alternate hostname or domain bypass | A8 | ATT-127 | exact | E1 declared-only |
| EVA-076 | Alternate port or service bypass | A8 | ATT-130 | exact | E3 semantic-safe |
| EVA-077 | Alternate protocol bypass | A8 | — | none | E0 unmapped |
| EVA-078 | SNI, Host, and routing-key mismatch | A8 | ATT-100 | exact | E3 semantic-safe |
| EVA-079 | Application-layer encrypted payload | A8 | — | none | E0 unmapped |
| EVA-080 | Signed but malicious structured data | A8 | — | none | E0 unmapped |
| EVA-081 | Polyglot file or multi-parser content | A8 | — | none | E0 unmapped |
| EVA-082 | Multi-vector or rapid vector switching | A8 | ATT-096 | exact | E4 SOC-governed |
| EVA-083 | HTTP/3-to-HTTP/1.1 translation differential | A8 | — | none | E0 unmapped |
| EVA-084 | QPACK or HPACK normalization and inspection gap | A8 | — | none | E0 unmapped |
| EVA-085 | HTTP/2 or HTTP/3 connection coalescing identity confusion | A8 | — | none | E0 unmapped |
| EVA-086 | Encrypted ClientHello or hidden routing-metadata visibility gap | A8 | — | none | E0 unmapped |
| EVA-087 | AI semantic obfuscation and adversarial suffix evasion | A8 | — | none | E0 unmapped |
| EVA-088 | Multimodal hidden-instruction evasion | A8 | — | none | E0 unmapped |
| EVA-089 | Tool-schema or agent-message boundary confusion | A8 | — | none | E0 unmapped |
| EVA-090 | Multipart per-part charset validation limited to the last part | A8 | — | none | E0 unmapped |
| EVA-091 | XML attribute-value inspection coverage bypass | A8 | — | none | E0 unmapped |
| NET-001 | Generic IP packet flood | A1a | ATT-090 | umbrella | E4 SOC-governed |
| NET-002 | Large-packet bandwidth flood | A1a | ATT-090 | umbrella | E4 SOC-governed |
| NET-003 | Small-packet PPS flood | A1a | ATT-090 | umbrella | E4 SOC-governed |
| NET-004 | Random IP protocol flood | A1a | — | none | E0 unmapped |
| NET-005 | IPv4 Protocol 0 flood | A1a | — | none | E0 unmapped |
| NET-006 | IP null or empty-payload flood | A1a | — | none | E0 unmapped |
| NET-007 | IP options flood | A1a | ATT-119 | exact | E1 declared-only |
| NET-008 | Malformed IP header flood | A1a | ATT-119 | umbrella | E1 declared-only |
| NET-009 | IP fragment flood | A1a | ATT-010 | exact | E1 declared-only |
| NET-010 | Incomplete fragment reassembly exhaustion | A1a | ATT-010 | umbrella | E1 declared-only |
| NET-011 | Overlapping fragment attack | A1a | ATT-012 | exact | E1 declared-only |
| NET-012 | Tiny-fragment flood | A1a | ATT-010 | umbrella | E1 declared-only |
| NET-013 | Fragment identification collision or confusion | A1a | ATT-010 | umbrella | E1 declared-only |
| NET-014 | Oversized reassembled packet | A1a | ATT-011 | umbrella | E1 declared-only |
| NET-015 | LAND attack | A1a | ATT-133 | exact | E1 declared-only |
| NET-016 | ICMP Echo Request flood | A1a | ATT-002 | exact | E1 declared-only |
| NET-017 | ICMP Echo Reply flood | A1a | ATT-002 | umbrella | E1 declared-only |
| NET-018 | ICMP Destination Unreachable flood | A1a | ATT-002 | umbrella | E1 declared-only |
| NET-019 | ICMP Time Exceeded flood | A1a | ATT-002 | umbrella | E1 declared-only |
| NET-020 | ICMP Redirect flood | A1a | — | none | E0 unmapped |
| NET-021 | ICMP Source Quench abuse | A1a | — | none | E0 unmapped |
| NET-022 | ICMP Packet Too Big or Fragmentation Needed spoofing | A1a | — | none | E0 unmapped |
| NET-023 | BlackNurse-style ICMP error flood | A1a | ATT-002 | umbrella | E1 declared-only |
| NET-024 | IPv6 generic packet flood | A1a | ATT-124 | exact | E2 transport-only |
| NET-025 | IPv6 extension-header chain flood | A1a | — | none | E0 unmapped |
| NET-026 | IPv6 fragment flood | A1a | ATT-010 | umbrella | E1 declared-only |
| NET-027 | IPv6 atomic-fragment abuse | A1a | — | none | E0 unmapped |
| NET-028 | ICMPv6 Echo flood | A1a | ATT-002 | umbrella | E1 declared-only |
| NET-029 | ICMPv6 error-message flood | A1a | ATT-002 | umbrella | E1 declared-only |
| NET-030 | Neighbor Solicitation flood | A1b | — | none | E0 unmapped |
| NET-031 | Neighbor Advertisement flood | A1b | — | none | E0 unmapped |
| NET-032 | Router Solicitation flood | A1a | — | none | E0 unmapped |
| NET-033 | Router Advertisement flood | A1a | — | none | E0 unmapped |
| NET-034 | MLD flood | A1a | — | none | E0 unmapped |
| NET-035 | IPv6 neighbor-cache exhaustion by destination scanning | A1a | — | none | E0 unmapped |
| NET-036 | GRE flood | A1a | ATT-013 | exact | E1 declared-only |
| NET-037 | IP-in-IP tunnel flood | A1a | ATT-013 | umbrella | E1 declared-only |
| NET-038 | ESP flood | A1a | ATT-014 | exact | E1 declared-only |
| NET-039 | AH flood | A1a | ATT-014 | umbrella | E1 declared-only |
| NET-040 | TTL-expiry or hop-limit punt flood | A1a | — | none | E0 unmapped |
| NET-041 | Unroutable or exception-path destination flood | A1a | — | none | E0 unmapped |
| NET-042 | BGP session-establishment flood | A1b | — | none | E0 unmapped |
| NET-043 | BGP update or route-churn flood | A1b | — | none | E0 unmapped |
| NET-044 | OSPF, IS-IS, or routing-adjacency flood | A1b | — | none | E0 unmapped |
| NET-045 | Carpet-bombing destination flood | A1a | ATT-094 | exact | E1 declared-only |
| NET-046 | Pulse-wave or multiwave flood | A1a | ATT-095 | exact | E1 declared-only |
| NET-047 | Low-rate shrew or reduction-of-quality attack | A1a | ATT-146 | umbrella | E1 declared-only |
| NET-048 | Generic UDP flood | A1a | ATT-001 | exact | E2 transport-only |
| NET-049 | Large-datagram UDP bandwidth flood | A1a | ATT-001 | umbrella | E2 transport-only |
| NET-050 | Small-datagram UDP PPS flood | A1a | ATT-001 | umbrella | E2 transport-only |
| NET-051 | UDP random-port flood | A1a | ATT-001 | umbrella | E2 transport-only |
| NET-052 | UDP fragment flood | A1a | ATT-010 | umbrella | E1 declared-only |
| NET-053 | UDP conntrack or firewall-state exhaustion | A1a | ATT-125 | exact | E1 declared-only |
| NET-054 | NAT mapping exhaustion | A1a | ATT-125 | exact | E1 declared-only |
| NET-055 | UDP application packet-loop attack | A1a | — | none | E0 unmapped |
| NET-056 | TCP SYN flood | A1a | ATT-003 | exact | E2 transport-only |
| NET-057 | TCP ACK flood | A1a | ATT-004 | exact | E1 declared-only |
| NET-058 | TCP RST flood | A1a | ATT-006 | exact | E1 declared-only |
| NET-059 | TCP SYN-ACK direct flood | A1a | ATT-005 | exact | E1 declared-only |
| NET-060 | TCP FIN flood | A1a | ATT-007 | exact | E2 transport-only |
| NET-061 | TCP PSH or PSH-ACK flood | A1a | ATT-007 | exact | E2 transport-only |
| NET-062 | TCP NULL flag flood | A1a | ATT-007 | exact | E2 transport-only |
| NET-063 | TCP XMAS flag flood | A1a | ATT-007 | exact | E2 transport-only |
| NET-064 | Random or impossible TCP flag-combination flood | A1a | ATT-007 | exact | E2 transport-only |
| NET-065 | TCP full-connection flood | A1a | ATT-008 | exact | E2 transport-only |
| NET-066 | TCP connection-hold or idle-socket exhaustion | A1a | ATT-075 | exact | E2 transport-only |
| NET-067 | TCP reconnect or connection-rate flood | A1a | ATT-008 | umbrella | E2 transport-only |
| NET-068 | Invalid-sequence or out-of-window TCP flood | A1a | ATT-009 | exact | E1 declared-only |
| NET-069 | Tiny-segment or TCP small-packet flood | A1a | — | none | E0 unmapped |
| NET-070 | TCP fragment flood | A1a | ATT-010 | umbrella | E1 declared-only |
| NET-071 | Malformed TCP header or option flood | A1a | — | none | E0 unmapped |
| NET-072 | SCTP INIT flood | A1a | ATT-135 | exact | E1 declared-only |
| NET-073 | SCTP COOKIE-ECHO or association flood | A1a | ATT-135 | umbrella | E1 declared-only |
| NET-074 | DCCP request flood | A1a | — | none | E0 unmapped |
| NET-075 | QUIC Initial flood | A1a | ATT-015 | exact | E2 transport-only |
| NET-076 | QUIC version-negotiation or Retry flood | A1a | ATT-120 | exact | E1 declared-only |
| NET-077 | DTLS handshake flood | A1a | ATT-064 | umbrella | E3 semantic-safe |
| NET-078 | TLS handshake flood | A1a | ATT-064 | exact | E3 semantic-safe |
| NET-079 | TLS renegotiation flood | A1a | ATT-065 | exact | E2 transport-only |
| NET-080 | TLS record-fragmentation or empty-record flood | A1a | — | none | E0 unmapped |
| NET-081 | Client-certificate validation flood | A1a | ATT-155 | umbrella | E3 semantic-safe |
| NET-082 | IKE or ISAKMP negotiation flood | A1a | ATT-136 | exact | E1 declared-only |
| NET-083 | L2TP control-session flood | A1a | — | none | E0 unmapped |
| NET-084 | OpenVPN handshake or session flood | A1a | ATT-168 | umbrella | E2 transport-only |
| NET-085 | WireGuard handshake-initiation flood | A1a | ATT-168 | umbrella | E2 transport-only |
| NET-086 | RDP UDP transport flood | A1a | ATT-025 | umbrella | E2 transport-only |
| NET-087 | Firewall or load-balancer connection-table exhaustion | A1a | ATT-125 | exact | E1 declared-only |
| NET-088 | SNAT ephemeral-port exhaustion | A1a | — | none | E0 unmapped |
| NET-089 | Reverse-proxy upstream connection-pool exhaustion | A1a | ATT-075 | umbrella | E2 transport-only |
| NET-090 | Transport-stack crash or hang exploit | A1a | ATT-011 | umbrella | E1 declared-only |
| NET-091 | ARP request/reply flood | A1b | — | none | E0 unmapped |
| NET-092 | Ethernet broadcast flood | A1b | ATT-137 | umbrella | E1 declared-only |
| NET-093 | Ethernet multicast flood | A1b | ATT-137 | umbrella | E1 declared-only |
| NET-094 | Ethernet source-equals-destination MAC anomaly flood | A1b | — | none | E0 unmapped |
| NET-095 | IGMP flood | A1a | ATT-137 | umbrella | E1 declared-only |
| NET-096 | IGMP fragment flood | A1a | — | none | E0 unmapped |
| NET-097 | Malformed IGMP frame flood | A1a | — | none | E0 unmapped |
| NET-098 | Bad ICMP checksum flood | A1a | — | none | E0 unmapped |
| NET-099 | Malformed ICMP frame flood | A1a | — | none | E0 unmapped |
| NET-100 | ICMP length or oversize anomaly flood | A1a | ATT-011 | umbrella | E1 declared-only |
| NET-101 | Invalid IPv4 version-field flood | A1a | — | none | E0 unmapped |
| NET-102 | Zero or invalid IPv4 TTL flood | A1a | — | none | E0 unmapped |
| NET-103 | IPv4 header-length anomaly flood | A1a | — | none | E0 unmapped |
| NET-104 | IP total-length versus frame-length mismatch flood | A1a | — | none | E0 unmapped |
| NET-105 | Illegal or unknown IPv4 option flood | A1a | ATT-119 | exact | E1 declared-only |
| NET-106 | Invalid IPv6 version or address flood | A1a | — | none | E0 unmapped |
| NET-107 | Low or invalid IPv6 Hop Limit flood | A1a | — | none | E0 unmapped |
| NET-108 | IPv6 payload-length versus frame-length mismatch flood | A1a | — | none | E0 unmapped |
| NET-109 | Duplicate IPv6 extension-header flood | A1a | — | none | E0 unmapped |
| NET-110 | IPv6 extension-header ordering violation flood | A1a | — | none | E0 unmapped |
| NET-111 | Overlong or excessive IPv6 extension-header flood | A1a | — | none | E0 unmapped |
| NET-112 | IPv6 Routing Header Type 0 abuse | A1a | — | none | E0 unmapped |
| NET-113 | IPv4-mapped IPv6 parser or policy abuse | A1a | — | none | E0 unmapped |
| NET-114 | Missing, truncated, or unreachable L4 header flood | A1a | — | none | E0 unmapped |
| NET-115 | Bad TCP checksum flood | A1a | — | none | E0 unmapped |
| NET-116 | TCP header-length anomaly flood | A1a | — | none | E0 unmapped |
| NET-117 | TCP option overrun or unknown-option flood | A1a | — | none | E0 unmapped |
| NET-118 | TCP urgent-pointer anomaly flood | A1a | ATT-007 | umbrella | E2 transport-only |
| NET-119 | Oversized TCP SYN or SYN-with-payload flood | A1a | ATT-003 | umbrella | E2 transport-only |
| NET-120 | TCP zero-window or tiny-window state exhaustion | A1a | ATT-075 | umbrella | E2 transport-only |
| NET-121 | Invalid TCP timestamp or cookie ACK flood | A1a | ATT-009 | umbrella | E1 declared-only |
| NET-122 | Bad UDP checksum flood | A1a | — | none | E0 unmapped |
| NET-123 | Malformed UDP length or header flood | A1a | — | none | E0 unmapped |
| NET-124 | Bad SCTP checksum flood | A1a | — | none | E0 unmapped |
| NET-125 | BFD control-packet flood | A1b | — | none | E0 unmapped |
| NET-126 | Andrew File System service flood | A1a | — | none | E0 unmapped |
| NET-127 | Advanced Disconnect Detection Protocol flood | A1a | — | none | E0 unmapped |
| NET-128 | Crestron CIP discovery or control flood | A1a | ATT-118 | umbrella | E2 transport-only |
| NET-129 | Direct SNMP request flood | A1a | ATT-021 | umbrella | E2 transport-only |
| NET-130 | Direct NTP request flood | A1a | ATT-017 | umbrella | E1 declared-only |
| NET-131 | Direct SSDP request flood | A1a | ATT-020 | umbrella | E2 transport-only |
| NET-132 | Direct mDNS query flood | A1a | ATT-023 | umbrella | E2 transport-only |
| NET-133 | Direct NetBIOS name-service flood | A1a | ATT-023 | umbrella | E2 transport-only |
| NET-134 | Direct RPCbind or portmapper request flood | A1a | ATT-024 | umbrella | E2 transport-only |
| NET-135 | Direct RIPv1 request or update flood | A1b | ATT-024 | umbrella | E2 transport-only |
| NET-136 | Direct TFTP request or session flood | A1a | ATT-025 | umbrella | E2 transport-only |
| NET-137 | Direct WS-Discovery probe flood | A1a | ATT-023 | umbrella | E2 transport-only |
| NET-138 | Direct Echo, CharGEN, QOTD, or Daytime service flood | A1a | ATT-022 | umbrella | E2 transport-only |
| NET-139 | Direct NAT-PMP mapping-request flood | A1a | — | none | E0 unmapped |
| NET-140 | Apple Remote Desktop service flood | A1a | ATT-025 | umbrella | E2 transport-only |
| NET-141 | Sentinel license-manager direct flood | A1a | — | none | E0 unmapped |
| NET-142 | Direct game-server query flood | A1a | ATT-024 | umbrella | E2 transport-only |
| NET-143 | No-listener or service-miss flood | A1a | — | none | E0 unmapped |
| NET-144 | TCP port-sweep or distributed SYN scan flood | A1a | ATT-003 | umbrella | E2 transport-only |
| NET-145 | Bad source-address anomaly flood | A1a | ATT-091 | exact | E1 declared-only |
| NET-146 | Anomalous TCP advertised-window flood | A1a | — | none | E0 unmapped |
| NET-147 | MAC/CAM forwarding-table exhaustion flood | A1b | — | none | E0 unmapped |
| NET-148 | STP/RSTP/MSTP BPDU or topology-change flood | A1b | — | none | E0 unmapped |
| NET-149 | DHCPv4 discovery/request starvation flood | A1b | — | none | E0 unmapped |
| NET-150 | DHCPv6 solicit/request starvation flood | A1b | — | none | E0 unmapped |
| NET-151 | PPPoE discovery or session-establishment flood | A1b | — | none | E0 unmapped |
| NET-152 | 802.1X/EAPOL authentication/control flood | A1b | — | none | E0 unmapped |
| NET-153 | LLDP/CDP neighbor-discovery flood | A1b | — | none | E0 unmapped |
| NET-154 | LACP/PAgP link-aggregation control flood | A1b | — | none | E0 unmapped |
| NET-155 | First-hop redundancy advertisement or state-churn flood | A1b | — | none | E0 unmapped |
| NET-156 | PIM multicast-routing control flood | A1b | — | none | E0 unmapped |
| NET-157 | MPLS RSVP-TE or LDP control-plane flood | A1b | — | none | E0 unmapped |
| NET-158 | GTP-U tunnel data-plane flood | A1d | — | none | E0 unmapped |
| NET-159 | GTP-C session or control-plane flood | A1d | — | none | E0 unmapped |
| NET-160 | VXLAN or Geneve overlay/VTEP flood | A1a | ATT-013 | umbrella | E1 declared-only |
| NET-161 | ICMP fragmented-message flood | A1a | ATT-010 | umbrella | E1 declared-only |
| NET-162 | Generic ICMPv4 packet flood | A1a | ATT-002 | exact | E1 declared-only |
| NET-163 | Generic ICMPv6 packet flood | A1a | ATT-002 | umbrella | E1 declared-only |
| NET-164 | IPv4 header checksum-error flood | A1a | — | none | E0 unmapped |
| NET-165 | IPv6 overlapping-fragment flood | A1a | ATT-012 | umbrella | E1 declared-only |
| NET-166 | IPv6 tiny-fragment flood | A1a | ATT-010 | umbrella | E1 declared-only |
| NET-167 | Single-endpoint aggregate flood | A1a | ATT-090 | umbrella | E4 SOC-governed |
| NET-168 | Single-endpoint service or protocol sweep | A1a | ATT-130 | umbrella | E3 semantic-safe |
| NET-169 | 802.11 association or reassociation flood | A1c | — | none | E0 unmapped |
| NET-170 | 802.11 authentication request flood | A1c | — | none | E0 unmapped |
| NET-171 | 802.11 deauthentication or disassociation flood | A1c | — | none | E0 unmapped |
| NET-172 | 802.11 probe-request flood | A1c | — | none | E0 unmapped |
| NET-173 | 802.11 beacon flood | A1c | — | none | E0 unmapped |
| NET-174 | 802.11 RTS/CTS/NAV virtual-carrier flood | A1c | — | none | E0 unmapped |
| NET-175 | 802.11 PS-Poll or power-save control flood | A1c | — | none | E0 unmapped |
| NET-176 | 802.11 Block ACK control flood | A1c | — | none | E0 unmapped |
| NET-177 | Radio-frequency jamming or interference denial | A1c | — | none | E0 unmapped |
| NET-178 | Diameter signaling flood | A1d | — | none | E0 unmapped |
| NET-179 | PFCP session or control-plane flood | A1d | — | none | E0 unmapped |
| NET-180 | Mobile attach, registration, or session signaling storm | A1d | — | none | E0 unmapped |
| WAF-001 | Disallowed or dangerous HTTP method use | A7 | ATT-132 | exact | E2 transport-only |
| WAF-002 | HTTP method override abuse | A7 | — | none | E0 unmapped |
| WAF-003 | Malformed request-line attack | A7 | — | none | E0 unmapped |
| WAF-004 | Invalid or ambiguous header syntax | A7 | — | none | E0 unmapped |
| WAF-005 | Duplicate or conflicting HTTP headers | A7 | — | none | E0 unmapped |
| WAF-006 | Hop-by-hop header abuse | A7 | — | none | E0 unmapped |
| WAF-007 | Content-Length versus Transfer-Encoding request smuggling | A7 | — | none | E0 unmapped |
| WAF-008 | Obfuscated Transfer-Encoding ambiguity | A7 | — | none | E0 unmapped |
| WAF-009 | HTTP/2 to HTTP/1 desynchronization | A7 | — | none | E0 unmapped |
| WAF-010 | Connection-state and response-queue poisoning | A7 | — | none | E0 unmapped |
| WAF-011 | CRLF injection and HTTP response splitting | A7 | — | none | E0 unmapped |
| WAF-012 | Host header injection | A7 | ATT-100 | umbrella | E3 semantic-safe |
| WAF-013 | Absolute-form or authority mismatch | A7 | — | none | E0 unmapped |
| WAF-014 | Client-IP forwarding header spoofing | A7 | — | none | E0 unmapped |
| WAF-015 | HTTPoxy-style proxy environment injection | A7 | — | none | E0 unmapped |
| WAF-016 | HTTP parameter pollution | A7 | — | none | E0 unmapped |
| WAF-017 | Duplicate JSON key pollution | A7 | — | none | E0 unmapped |
| WAF-018 | Multipart form-data parser differential | A7 | ATT-102 | umbrella | E3 semantic-safe |
| WAF-019 | Content-Type confusion | A7 | ATT-102 | umbrella | E3 semantic-safe |
| WAF-020 | Path normalization and routing ambiguity | A7 | — | none | E0 unmapped |
| WAF-021 | Web cache poisoning | A7 | ATT-058 | umbrella | E3 semantic-safe |
| WAF-022 | Web cache deception | A7 | — | none | E0 unmapped |
| WAF-023 | Byte-range abuse | A7 | ATT-141 | umbrella | E1 declared-only |
| WAF-024 | Open redirect manipulation | A7 | — | none | E0 unmapped |
| WAF-025 | Union-based SQL injection | A7 | WV-001 | exact | E4 SOC-governed |
| WAF-026 | Error-based SQL injection | A7 | WV-001 | exact | E4 SOC-governed |
| WAF-027 | Boolean-based blind SQL injection | A7 | WV-001 | exact | E4 SOC-governed |
| WAF-028 | Time-based blind SQL injection | A7 | WV-001 | exact | E4 SOC-governed |
| WAF-029 | Stacked-query SQL injection | A7 | WV-001 | exact | E4 SOC-governed |
| WAF-030 | Out-of-band SQL injection | A7 | WV-001 | umbrella | E4 SOC-governed |
| WAF-031 | Second-order SQL injection | A7 | WV-001 | umbrella | E4 SOC-governed |
| WAF-032 | SQL injection through dynamic identifiers | A7 | WV-001 | umbrella | E4 SOC-governed |
| WAF-033 | NoSQL operator injection | A7 | — | none | E0 unmapped |
| WAF-034 | NoSQL JavaScript or expression injection | A7 | — | none | E0 unmapped |
| WAF-035 | NoSQL regex injection and ReDoS | A7 | — | none | E0 unmapped |
| WAF-036 | NoSQL aggregation-pipeline injection | A7 | — | none | E0 unmapped |
| WAF-037 | LDAP injection | A7 | WV-006 | exact | E4 SOC-governed |
| WAF-038 | XPath or XQuery injection | A7 | — | none | E0 unmapped |
| WAF-039 | XML injection | A7 | — | none | E0 unmapped |
| WAF-040 | Operating-system command injection | A7 | WV-005 | exact | E4 SOC-governed |
| WAF-041 | Argument injection | A7 | WV-005 | umbrella | E4 SOC-governed |
| WAF-042 | Windows command and PowerShell injection | A7 | WV-005 | umbrella | E4 SOC-governed |
| WAF-043 | Unix shell command injection | A7 | WV-005 | umbrella | E4 SOC-governed |
| WAF-044 | Server-side code injection | A7 | WV-003 | exact | E4 SOC-governed |
| WAF-045 | Server-side template injection | A7 | WV-007 | exact | E4 SOC-governed |
| WAF-046 | Expression-language injection | A7 | WV-007 | umbrella | E4 SOC-governed |
| WAF-047 | JNDI or naming-context injection | A7 | — | none | E0 unmapped |
| WAF-048 | Server-side include injection | A7 | — | none | E0 unmapped |
| WAF-049 | Email header injection | A7 | — | none | E0 unmapped |
| WAF-050 | CSV or formula injection | A7 | — | none | E0 unmapped |
| WAF-051 | Log injection and log forging | A7 | — | none | E0 unmapped |
| WAF-052 | Generic HTTP header value injection | A7 | — | none | E0 unmapped |
| WAF-053 | Prototype pollution | A7 | — | none | E0 unmapped |
| WAF-054 | Property-path or object-graph injection | A7 | — | none | E0 unmapped |
| WAF-055 | Generic insecure deserialization | A7 | — | none | E0 unmapped |
| WAF-056 | Java object deserialization attack | A7 | — | none | E0 unmapped |
| WAF-057 | .NET deserialization attack | A7 | — | none | E0 unmapped |
| WAF-058 | PHP object injection | A7 | — | none | E0 unmapped |
| WAF-059 | Python pickle or language-native object injection | A7 | — | none | E0 unmapped |
| WAF-060 | YAML unsafe object construction | A7 | — | none | E0 unmapped |
| WAF-061 | Basic SSRF | A7 | — | none | E0 unmapped |
| WAF-062 | Blind SSRF | A7 | — | none | E0 unmapped |
| WAF-063 | Cloud metadata service SSRF | A7 | — | none | E0 unmapped |
| WAF-064 | SSRF through alternate URL schemes | A7 | — | none | E0 unmapped |
| WAF-065 | SSRF via redirects or DNS rebinding | A7 | — | none | E0 unmapped |
| WAF-066 | SSRF-driven resource exhaustion | A7 | — | none | E0 unmapped |
| WAF-067 | Classic external entity injection | A7 | — | none | E0 unmapped |
| WAF-068 | Blind or out-of-band XXE | A7 | — | none | E0 unmapped |
| WAF-069 | XML entity expansion denial of service | A7 | ATT-149 | umbrella | E1 declared-only |
| WAF-070 | Reflected XSS | A7 | WV-002 | exact | E4 SOC-governed |
| WAF-071 | Stored XSS | A7 | WV-002 | umbrella | E4 SOC-governed |
| WAF-072 | DOM-based XSS | A7 | WV-002 | umbrella | E4 SOC-governed |
| WAF-073 | Blind XSS | A7 | WV-002 | umbrella | E4 SOC-governed |
| WAF-074 | Mutation XSS | A7 | WV-002 | umbrella | E4 SOC-governed |
| WAF-075 | Attribute-context XSS | A7 | WV-002 | umbrella | E4 SOC-governed |
| WAF-076 | JavaScript-context injection | A7 | WV-002 | umbrella | E4 SOC-governed |
| WAF-077 | URL and URI-scheme XSS | A7 | WV-002 | umbrella | E4 SOC-governed |
| WAF-078 | SVG or MathML active-content XSS | A7 | WV-002 | umbrella | E4 SOC-governed |
| WAF-079 | Rich-text HTML injection | A7 | WV-002 | umbrella | E4 SOC-governed |
| WAF-080 | JSONP callback injection | A7 | — | none | E0 unmapped |
| WAF-081 | CSS injection with active or exfiltration effects | A7 | — | none | E0 unmapped |
| WAF-082 | Directory traversal | A7 | WV-004 | exact | E4 SOC-governed |
| WAF-083 | Local file inclusion | A7 | WV-004 | umbrella | E4 SOC-governed |
| WAF-084 | Remote file inclusion | A7 | — | none | E0 unmapped |
| WAF-085 | Arbitrary file read or download parameter abuse | A7 | WV-004 | umbrella | E4 SOC-governed |
| WAF-086 | Arbitrary file write | A7 | — | none | E0 unmapped |
| WAF-087 | Unrestricted file upload | A7 | — | none | E0 unmapped |
| WAF-088 | Web-shell upload or deployment | A7 | — | none | E0 unmapped |
| WAF-089 | Extension, MIME, or content-sniffing bypass | A7 | — | none | E0 unmapped |
| WAF-090 | Archive path traversal | A7 | — | none | E0 unmapped |
| WAF-091 | Archive decompression bomb | A7 | — | none | E0 unmapped |
| WAF-092 | Image/document parser exploit | A7 | — | none | E0 unmapped |
| WAF-093 | Stored active-content upload | A7 | — | none | E0 unmapped |
| WAF-094 | Null-byte or terminator path truncation | A7 | WV-004 | umbrella | E4 SOC-governed |
| WAF-095 | Symlink or race-based path escape | A7 | — | none | E0 unmapped |
| WAF-096 | Credential stuffing | A7 | ND-006 | exact | E5 monitor-only |
| WAF-097 | Password spraying | A7 | ND-006 | exact | E5 monitor-only |
| WAF-098 | Single-account password brute force | A7 | ND-006 | exact | E5 monitor-only |
| WAF-099 | Username or account enumeration | A7 | — | none | E0 unmapped |
| WAF-100 | MFA or OTP code guessing | A7 | ATT-144 | umbrella | E3 semantic-safe |
| WAF-101 | MFA push fatigue | A7 | — | none | E0 unmapped |
| WAF-102 | OTP or password-reset message bombing | A7 | ATT-158 | exact | E2 transport-only |
| WAF-103 | CAPTCHA defeat and challenge automation | A7 | ATT-145 | umbrella | E3 semantic-safe |
| WAF-104 | Session fixation | A7 | — | none | E0 unmapped |
| WAF-105 | Session-cookie theft or replay | A7 | — | none | E0 unmapped |
| WAF-106 | Cookie tampering | A7 | — | none | E0 unmapped |
| WAF-107 | CSRF against state-changing action | A7 | — | none | E0 unmapped |
| WAF-108 | JWT algorithm confusion or unsigned-token acceptance | A7 | — | none | E0 unmapped |
| WAF-109 | JWT key-selection header abuse | A7 | — | none | E0 unmapped |
| WAF-110 | JWT claim manipulation or validation omission | A7 | — | none | E0 unmapped |
| WAF-111 | Bearer-token or API-key replay | A7 | — | none | E0 unmapped |
| WAF-112 | OAuth redirect URI manipulation | A7 | ATT-112 | umbrella | E3 semantic-safe |
| WAF-113 | OAuth state/nonce or login CSRF attack | A7 | — | none | E0 unmapped |
| WAF-114 | PKCE downgrade or verifier interception | A7 | — | none | E0 unmapped |
| WAF-115 | OAuth token leakage and replay through URLs or logs | A7 | — | none | E0 unmapped |
| WAF-116 | SAML signature wrapping or reference confusion | A7 | — | none | E0 unmapped |
| WAF-117 | SAML assertion replay | A7 | — | none | E0 unmapped |
| WAF-118 | Alternate endpoint, method, or content-type authentication bypass | A7 | — | none | E0 unmapped |
| WAF-119 | Broken object-level authorization | A7 | — | none | E0 unmapped |
| WAF-120 | Broken object-property-level authorization | A7 | — | none | E0 unmapped |
| WAF-121 | Mass assignment | A7 | — | none | E0 unmapped |
| WAF-122 | Broken function-level authorization | A7 | — | none | E0 unmapped |
| WAF-123 | Forced browsing | A7 | ATT-129 | umbrella | E3 semantic-safe |
| WAF-124 | Horizontal privilege escalation | A7 | — | none | E0 unmapped |
| WAF-125 | Vertical privilege escalation | A7 | — | none | E0 unmapped |
| WAF-126 | Cross-tenant isolation failure | A7 | — | none | E0 unmapped |
| WAF-127 | Missing authentication on an endpoint | A7 | ATT-129 | umbrella | E3 semantic-safe |
| WAF-128 | Excessive data exposure | A7 | — | none | E0 unmapped |
| WAF-129 | Unrestricted resource consumption | A7 | ATT-056 | umbrella | E3 semantic-safe |
| WAF-130 | Unrestricted access to sensitive business flows | A7 | — | none | E0 unmapped |
| WAF-131 | Improper API inventory management | A7 | ATT-169 | umbrella | E3 semantic-safe |
| WAF-132 | Unsafe consumption of third-party APIs | A7 | — | none | E0 unmapped |
| WAF-133 | GraphQL introspection exposure | A7 | ATT-057 | umbrella | E3 semantic-safe |
| WAF-134 | GraphQL field-level authorization bypass | A7 | — | none | E0 unmapped |
| WAF-135 | Batch endpoint authorization inconsistency | A7 | ATT-107 | umbrella | E1 declared-only |
| WAF-136 | gRPC method-level authorization gap | A7 | — | none | E0 unmapped |
| WAF-137 | CORS misconfiguration abuse | A7 | ATT-174 | exact | E3 semantic-safe |
| WAF-138 | Parameter tampering | A7 | — | none | E0 unmapped |
| WAF-139 | Workflow step skipping or sequence abuse | A7 | — | none | E0 unmapped |
| WAF-140 | Race condition and double-spend abuse | A7 | — | none | E0 unmapped |
| WAF-141 | Replay of a state-changing request | A7 | — | none | E0 unmapped |
| WAF-142 | Carding | A7 | — | none | E0 unmapped |
| WAF-143 | Token cracking | A7 | — | none | E0 unmapped |
| WAF-144 | Ad fraud | A7 | — | none | E0 unmapped |
| WAF-145 | Fingerprinting | A7 | — | none | E0 unmapped |
| WAF-146 | Scalping | A7 | — | none | E0 unmapped |
| WAF-147 | Expediting | A7 | — | none | E0 unmapped |
| WAF-148 | Credential cracking | A7 | ND-006 | umbrella | E5 monitor-only |
| WAF-149 | Credential stuffing (OWASP OAT-008) | A7 | ND-006 | exact | E5 monitor-only |
| WAF-150 | CAPTCHA defeat | A7 | ATT-145 | umbrella | E3 semantic-safe |
| WAF-151 | Card cracking | A7 | — | none | E0 unmapped |
| WAF-152 | Scraping | A7 | ATT-169 | exact | E3 semantic-safe |
| WAF-153 | Cashing out | A7 | — | none | E0 unmapped |
| WAF-154 | Sniping | A7 | — | none | E0 unmapped |
| WAF-155 | Vulnerability scanning | A7 | — | none | E0 unmapped |
| WAF-156 | Denial of service | A7 | ATT-051 | umbrella | E3 semantic-safe |
| WAF-157 | Skewing | A7 | — | none | E0 unmapped |
| WAF-158 | Spamming | A7 | — | none | E0 unmapped |
| WAF-159 | Footprinting | A7 | ATT-169 | umbrella | E3 semantic-safe |
| WAF-160 | Account creation | A7 | ATT-157 | exact | E3 semantic-safe |
| WAF-161 | Account aggregation | A7 | — | none | E0 unmapped |
| WAF-162 | Denial of inventory | A7 | ATT-143 | umbrella | E1 declared-only |
| WAF-163 | Prompt injection - direct | A7 | — | none | E0 unmapped |
| WAF-164 | Prompt injection - indirect | A7 | — | none | E0 unmapped |
| WAF-165 | System prompt or hidden-context extraction | A7 | — | none | E0 unmapped |
| WAF-166 | AI tool or function-call parameter injection | A7 | — | none | E0 unmapped |
| WAF-167 | Agent goal hijacking | A7 | — | none | E0 unmapped |
| WAF-168 | Agent identity or privilege abuse | A7 | — | none | E0 unmapped |
| WAF-169 | Agentic supply-chain or runtime component poisoning | A7 | — | none | E0 unmapped |
| WAF-170 | Agent memory or retrieval poisoning | A7 | — | none | E0 unmapped |
| WAF-171 | Insecure model output handling | A7 | — | none | E0 unmapped |
| WAF-172 | Multimodal prompt injection | A7 | — | none | E0 unmapped |
| WAF-173 | Semantic or adversarial prompt obfuscation | A7 | — | none | E0 unmapped |
| WAF-174 | Unbounded model or agent resource consumption | A7 | — | none | E0 unmapped |
| WAF-175 | Cross-agent trust and message injection | A7 | — | none | E0 unmapped |
| WAF-176 | Rogue or compromised autonomous agent behavior | A7 | — | none | E0 unmapped |

## Appendix B — Gap register (365 unmapped vectors, grouped by domain and family)

### A1a IP / Transport Packet Processing — 51 unmapped

**Control-plane exhaustion** (2)

- `NET-040` TTL-expiry or hop-limit punt flood
- `NET-041` Unroutable or exception-path destination flood

**Device discovery/control** (1)

- `NET-127` Advanced Disconnect Detection Protocol flood

**Handshake or state exhaustion** (1)

- `NET-074` DCCP request flood

**ICMP control abuse** (3)

- `NET-020` ICMP Redirect flood
- `NET-021` ICMP Source Quench abuse
- `NET-022` ICMP Packet Too Big or Fragmentation Needed spoofing

**IPv4 checksum** (1)

- `NET-164` IPv4 header checksum-error flood

**IPv4 control-plane** (1)

- `NET-102` Zero or invalid IPv4 TTL flood

**IPv4/IPv6 interpretation** (1)

- `NET-113` IPv4-mapped IPv6 parser or policy abuse

**IPv6 control-plane** (1)

- `NET-107` Low or invalid IPv6 Hop Limit flood

**IPv6 extension headers** (4)

- `NET-025` IPv6 extension-header chain flood
- `NET-109` Duplicate IPv6 extension-header flood
- `NET-110` IPv6 extension-header ordering violation flood
- `NET-111` Overlong or excessive IPv6 extension-header flood

**IPv6 fragmentation** (1)

- `NET-027` IPv6 atomic-fragment abuse

**IPv6 routing header** (1)

- `NET-112` IPv6 Routing Header Type 0 abuse

**Legacy distributed file service** (1)

- `NET-126` Andrew File System service flood

**Length-field mismatch** (2)

- `NET-104` IP total-length versus frame-length mismatch flood
- `NET-108` IPv6 payload-length versus frame-length mismatch flood

**License service** (1)

- `NET-141` Sentinel license-manager direct flood

**Listener/state lookup** (1)

- `NET-143` No-listener or service-miss flood

**Malformed ICMP** (2)

- `NET-098` Bad ICMP checksum flood
- `NET-099` Malformed ICMP frame flood

**Malformed IPv4** (2)

- `NET-101` Invalid IPv4 version-field flood
- `NET-103` IPv4 header-length anomaly flood

**Malformed IPv6** (1)

- `NET-106` Invalid IPv6 version or address flood

**Malformed SCTP** (1)

- `NET-124` Bad SCTP checksum flood

**Malformed TCP** (2)

- `NET-115` Bad TCP checksum flood
- `NET-116` TCP header-length anomaly flood

**Malformed UDP** (2)

- `NET-122` Bad UDP checksum flood
- `NET-123` Malformed UDP length or header flood

**Malformed control packet** (1)

- `NET-097` Malformed IGMP frame flood

**Malformed transport** (1)

- `NET-071` Malformed TCP header or option flood

**Missing transport header** (1)

- `NET-114` Missing, truncated, or unreachable L4 header flood

**Multicast Listener Discovery** (1)

- `NET-034` MLD flood

**Multicast control** (1)

- `NET-096` IGMP fragment flood

**NAT control protocol** (1)

- `NET-139` Direct NAT-PMP mapping-request flood

**Neighbor state exhaustion** (1)

- `NET-035` IPv6 neighbor-cache exhaustion by destination scanning

**Port exhaustion** (1)

- `NET-088` SNAT ephemeral-port exhaustion

**Protocol field abuse** (3)

- `NET-004` Random IP protocol flood
- `NET-005` IPv4 Protocol 0 flood
- `NET-006` IP null or empty-payload flood

**Protocol loop** (1)

- `NET-055` UDP application packet-loop attack

**Record and parser exhaustion** (1)

- `NET-080` TLS record-fragmentation or empty-record flood

**Router Discovery** (2)

- `NET-032` Router Solicitation flood
- `NET-033` Router Advertisement flood

**Segment processing** (1)

- `NET-069` Tiny-segment or TCP small-packet flood

**Session establishment** (1)

- `NET-083` L2TP control-session flood

**TCP anomaly** (1)

- `NET-146` Anomalous TCP advertised-window flood

**TCP options** (1)

- `NET-117` TCP option overrun or unknown-option flood


### A1b LAN / Routing Control Plane (out of remote-probe scope) — 19 unmapped

**Access/session control** (1)

- `NET-151` PPPoE discovery or session-establishment flood

**DHCP** (2)

- `NET-149` DHCPv4 discovery/request starvation flood
- `NET-150` DHCPv6 solicit/request starvation flood

**Ethernet switching** (1)

- `NET-147` MAC/CAM forwarding-table exhaustion flood

**First-hop redundancy** (1)

- `NET-155` First-hop redundancy advertisement or state-churn flood

**Interior routing control-plane exhaustion** (1)

- `NET-044` OSPF, IS-IS, or routing-adjacency flood

**L2 neighbor discovery** (1)

- `NET-091` ARP request/reply flood

**Link aggregation** (1)

- `NET-154` LACP/PAgP link-aggregation control flood

**MPLS signaling** (1)

- `NET-157` MPLS RSVP-TE or LDP control-plane flood

**Malformed L2 frame** (1)

- `NET-094` Ethernet source-equals-destination MAC anomaly flood

**Multicast routing** (1)

- `NET-156` PIM multicast-routing control flood

**Neighbor Discovery** (2)

- `NET-030` Neighbor Solicitation flood
- `NET-031` Neighbor Advertisement flood

**Neighbor discovery** (1)

- `NET-153` LLDP/CDP neighbor-discovery flood

**Network admission** (1)

- `NET-152` 802.1X/EAPOL authentication/control flood

**Routing protocol exhaustion** (2)

- `NET-042` BGP session-establishment flood
- `NET-043` BGP update or route-churn flood

**Routing/control protocol** (1)

- `NET-125` BFD control-packet flood

**Spanning tree** (1)

- `NET-148` STP/RSTP/MSTP BPDU or topology-change flood


### A1c Wireless / RF (out of remote-probe scope) — 9 unmapped

**Association/reassociation** (1)

- `NET-169` 802.11 association or reassociation flood

**Authentication** (1)

- `NET-170` 802.11 authentication request flood

**Beacon** (1)

- `NET-173` 802.11 beacon flood

**Block ACK** (1)

- `NET-176` 802.11 Block ACK control flood

**Deauthentication/disassociation** (1)

- `NET-171` 802.11 deauthentication or disassociation flood

**Power-save control** (1)

- `NET-175` 802.11 PS-Poll or power-save control flood

**Probe** (1)

- `NET-172` 802.11 probe-request flood

**RF availability** (1)

- `NET-177` Radio-frequency jamming or interference denial

**Virtual carrier sense** (1)

- `NET-174` 802.11 RTS/CTS/NAV virtual-carrier flood


### A1d Mobile / Telecom Signalling (out of remote-probe scope) — 5 unmapped

**Mobile access signaling** (1)

- `NET-180` Mobile attach, registration, or session signaling storm

**Mobile control plane** (1)

- `NET-159` GTP-C session or control-plane flood

**Mobile user plane** (1)

- `NET-158` GTP-U tunnel data-plane flood

**Mobile user-plane control** (1)

- `NET-179` PFCP session or control-plane flood

**Telecom AAA** (1)

- `NET-178` Diameter signaling flood


### A2 Reflection & Amplification Exposure — 18 unmapped

**Attacker-controlled callback** (1)

- `AMP-075` Attacker-controlled UDP acknowledgement or callback reflection

**CUPS/IPP** (1)

- `AMP-057` CUPS/IPP callback reflection/amplification

**DNS chain amplification** (1)

- `AMP-068` TsuKing DNSChain coordinated amplification

**DNS loop amplification** (1)

- `AMP-069` TsuKing DNSLoop coordinated amplification

**DNS retry amplification** (1)

- `AMP-067` TsuKing DNSRetry coordinated amplification

**Gateway discovery** (1)

- `AMP-061` Gateway-discovery protocol reflection/amplification

**HTTP reflection** (1)

- `AMP-072` Generic HTTP reflection or callback fan-out

**Kad/eMule** (1)

- `AMP-022` Kad peer-to-peer reflection/amplification

**L2TP** (1)

- `AMP-032` L2TP reflection/amplification

**Mitel MiCollab/TP240** (1)

- `AMP-046` TP240 PhoneHome reflection/amplification

**NAT-PMP** (1)

- `AMP-058` NAT-PMP reflection/amplification

**Opaque provider taxonomy** (1)

- `AMP-073` AWS UDS_REFLECTION provider-reported vector

**SLP** (1)

- `AMP-029` Service Location Protocol reflection/amplification

**Sentinel license manager** (1)

- `AMP-045` Sentinel/SPSS license-server reflection/amplification

**TCP** (1)

- `AMP-048` TCP SYN-ACK reflection/amplification

**UDP application protocols** (1)

- `AMP-051` Cross-protocol UDP application loop

**VPN** (1)

- `AMP-074` fastd VPN reconnect reflection/amplification

**VxWorks or embedded management services** (1)

- `AMP-055` VxWorks device reflection or protocol abuse


### A3 DNS Service Exhaustion — 7 unmapped

**DNS parser, resolver, or encrypted DNS** (5)

- `APP-168` Multi-question DNS query flood
- `APP-169` DNS response flood
- `APP-171` KeyTrap DNSSEC validation-complexity attack
- `APP-172` DNS-over-QUIC request or stream flood
- `APP-173` DoQ or DoH3 connection/stream memory exhaustion

**DNSSEC authoritative work** (1)

- `APP-105` Online DNSSEC signing exhaustion

**DNSSEC computation** (1)

- `APP-104` DNSSEC validation exhaustion


### A4a HTTP / API Application Exhaustion — 44 unmapped

**AI and inference** (1)

- `APP-145` Machine-learning or LLM inference exhaustion

**Account controls** (1)

- `APP-148` Account-lockout denial attack

**Algorithmic complexity** (2)

- `APP-028` Hash-collision denial of service
- `APP-029` Pathological sorting, filtering, or comparison input

**Authentication dependency** (1)

- `APP-060` Federated identity-provider exhaustion

**Autoscaling abuse** (1)

- `APP-048` Autoscaling thrash attack

**Cache behavior** (1)

- `APP-047` Cache stampede or thundering-herd trigger

**Data binding** (1)

- `APP-038` Mass object-binding exhaustion

**Decompression** (1)

- `APP-033` Compressed request decompression bomb

**Document processing** (1)

- `APP-035` PDF, office document, or archive processing exhaustion

**Document/image processing** (1)

- `APP-146` Document, archive, image, or media processing flood

**Error handling** (1)

- `APP-140` Error-page or exception-generation flood

**Exploit-triggered availability** (1)

- `APP-152` Application crash, hang, deadlock, or infinite-loop trigger

**GraphQL subscriptions** (1)

- `APP-067` GraphQL subscription exhaustion

**Image/media processing** (1)

- `APP-034` Image decompression or transformation bomb

**Lock contention** (1)

- `APP-044` Hot-key or lock-contention attack

**Logging exhaustion** (1)

- `APP-026` HTTP error-log flood

**Logging/telemetry** (1)

- `APP-139` Log, trace, or telemetry exhaustion

**Memory exhaustion** (1)

- `APP-041` Memory leak trigger flood

**Modern HTTP/TLS/CDN/resource exhaustion** (6)

- `APP-187` HTTP/2 Bomb composite memory-exhaustion attack
- `APP-188` HTTP/3-to-HTTP/1.1 bandwidth amplification
- `APP-189` HTTP/3-to-HTTP/1.1 connection amplification
- `APP-190` HTML5 ping-attribute browser fan-out flood
- `APP-191` TLS session-resumption or ticket-validation flood
- `APP-194` Cache purge or invalidation API flood

**ORM and object expansion** (1)

- `APP-057` N+1 object-expansion abuse

**Object storage** (1)

- `APP-137` Object-storage request-rate or egress flood

**Parser complexity** (1)

- `APP-032` External entity or resource-fetch exhaustion

**Parser exhaustion** (1)

- `APP-025` Excessive query-parameter flood

**Parser/desynchronization** (1)

- `APP-023` HTTP request-smuggling availability attack

**Queue exhaustion** (1)

- `APP-045` Job, message, or task queue flood

**Recursive call graph** (1)

- `APP-049` Recursive or cyclic service-call exhaustion

**Request flood** (1)

- `APP-004` HTTP PUT, PATCH, or DELETE flood

**Response amplification** (1)

- `APP-012` Large-response request flood

**Retry amplification** (1)

- `APP-046` Retry storm

**SOAP/RPC** (1)

- `APP-134` SOAP or generic RPC operation flood

**Serialization** (1)

- `APP-037` Deserialization resource-exhaustion payload

**Serverless** (1)

- `APP-135` Serverless invocation or denial-of-wallet flood

**Session state** (1)

- `APP-039` Session-object memory exhaustion

**Streaming/media** (1)

- `APP-132` Media segment or transcode request flood

**Template/rendering exhaustion** (1)

- `APP-036` Server-side template rendering exhaustion

**Third-party dependency** (1)

- `APP-143` Third-party API fan-out or quota exhaustion

**URL fetch/preview** (1)

- `APP-147` URL preview, crawler, or SSRF fan-out exhaustion

**XML streaming parser** (1)

- `APP-201` Incremental XML frame rescanning or trickle-feed CPU exhaustion


### A4b Non-HTTP Application Services — 12 unmapped

**AMQP** (2)

- `APP-124` AMQP connection or channel exhaustion
- `APP-125` AMQP queue, routing, or message flood

**Database protocol parser** (1)

- `APP-200` Redis unterminated length-line decoder memory exhaustion

**IMAP/POP** (1)

- `APP-118` Mailbox authentication or command flood

**LDAP** (2)

- `APP-119` LDAP bind flood
- `APP-120` LDAP expensive-search exhaustion

**Messaging protocol parser** (1)

- `APP-199` STOMP unbounded-header-count memory exhaustion

**RDP** (1)

- `APP-127` RDP connection or authentication flood

**SIP parser exhaustion** (2)

- `APP-185` Malformed SIP message flood
- `APP-186` SIP URI-length or field-count exhaustion

**SMB/NFS** (1)

- `APP-129` File-service operation flood

**SMTP** (1)

- `APP-117` Mail queue or backscatter exhaustion


### A5 Protocol Machinery (H2/H3/QUIC/WS/gRPC/TLS) — 14 unmapped

**HTTP/2 control frames** (3)

- `APP-081` HTTP/2 PING flood
- `APP-082` HTTP/2 SETTINGS flood
- `APP-083` HTTP/2 empty-frame flood

**HTTP/2 flow control** (3)

- `APP-080` HTTP/2 stalled flow-control exhaustion
- `APP-085` HTTP/2 internal data buffering exhaustion
- `APP-090` HTTP/2 WINDOW_UPDATE flood

**HTTP/2 header processing** (1)

- `APP-084` HTTP/2 zero-length header flood

**HTTP/2 malformed input** (1)

- `APP-091` Malformed HTTP/2 frame or state-machine flood

**HTTP/3 frames** (1)

- `APP-197` HTTP/3 reserved-frame declared-length buffering exhaustion

**HTTP/3 headers** (1)

- `APP-196` HTTP/3 unbounded header-field-section memory exhaustion

**TLS pre-handshake parsing** (1)

- `APP-198` Fragmented TLS ClientHello quadratic reassembly exhaustion

**WebSocket** (2)

- `APP-075` WebSocket broadcast or room fan-out abuse
- `APP-076` WebSocket compression exhaustion

**gRPC** (1)

- `APP-071` gRPC decompression exhaustion


### A7 Web Application Attack Classes — 117 unmapped

**AI/LLM/agentic security** (14)

- `WAF-163` Prompt injection - direct
- `WAF-164` Prompt injection - indirect
- `WAF-165` System prompt or hidden-context extraction
- `WAF-166` AI tool or function-call parameter injection
- `WAF-167` Agent goal hijacking
- `WAF-168` Agent identity or privilege abuse
- `WAF-169` Agentic supply-chain or runtime component poisoning
- `WAF-170` Agent memory or retrieval poisoning
- `WAF-171` Insecure model output handling
- `WAF-172` Multimodal prompt injection
- `WAF-173` Semantic or adversarial prompt obfuscation
- `WAF-174` Unbounded model or agent resource consumption
- `WAF-175` Cross-agent trust and message injection
- `WAF-176` Rogue or compromised autonomous agent behavior

**Access control and API** (12)

- `WAF-119` Broken object-level authorization
- `WAF-120` Broken object-property-level authorization
- `WAF-121` Mass assignment
- `WAF-122` Broken function-level authorization
- `WAF-124` Horizontal privilege escalation
- `WAF-125` Vertical privilege escalation
- `WAF-126` Cross-tenant isolation failure
- `WAF-128` Excessive data exposure
- `WAF-130` Unrestricted access to sensitive business flows
- `WAF-132` Unsafe consumption of third-party APIs
- `WAF-134` GraphQL field-level authorization bypass
- `WAF-136` gRPC method-level authorization gap

**Authentication abuse** (2)

- `WAF-099` Username or account enumeration
- `WAF-101` MFA push fatigue

**Authentication bypass** (1)

- `WAF-118` Alternate endpoint, method, or content-type authentication bypass

**Automated threat - OAT** (13)

- `WAF-142` Carding
- `WAF-143` Token cracking
- `WAF-144` Ad fraud
- `WAF-145` Fingerprinting
- `WAF-146` Scalping
- `WAF-147` Expediting
- `WAF-151` Card cracking
- `WAF-153` Cashing out
- `WAF-154` Sniping
- `WAF-155` Vulnerability scanning
- `WAF-157` Skewing
- `WAF-158` Spamming
- `WAF-161` Account aggregation

**Business logic** (4)

- `WAF-138` Parameter tampering
- `WAF-139` Workflow step skipping or sequence abuse
- `WAF-140` Race condition and double-spend abuse
- `WAF-141` Replay of a state-changing request

**Cross-site request forgery** (1)

- `WAF-107` CSRF against state-changing action

**Cross-site scripting** (2)

- `WAF-080` JSONP callback injection
- `WAF-081` CSS injection with active or exfiltration effects

**File upload** (7)

- `WAF-087` Unrestricted file upload
- `WAF-088` Web-shell upload or deployment
- `WAF-089` Extension, MIME, or content-sniffing bypass
- `WAF-090` Archive path traversal
- `WAF-091` Archive decompression bomb
- `WAF-092` Image/document parser exploit
- `WAF-093` Stored active-content upload

**HTTP cache attacks** (1)

- `WAF-022` Web cache deception

**HTTP header injection** (1)

- `WAF-011` CRLF injection and HTTP response splitting

**HTTP parameter handling** (1)

- `WAF-016` HTTP parameter pollution

**HTTP path handling** (1)

- `WAF-020` Path normalization and routing ambiguity

**HTTP protocol and policy** (5)

- `WAF-002` HTTP method override abuse
- `WAF-003` Malformed request-line attack
- `WAF-004` Invalid or ambiguous header syntax
- `WAF-005` Duplicate or conflicting HTTP headers
- `WAF-006` Hop-by-hop header abuse

**HTTP proxy behavior** (1)

- `WAF-015` HTTPoxy-style proxy environment injection

**HTTP redirect behavior** (1)

- `WAF-024` Open redirect manipulation

**HTTP request smuggling** (4)

- `WAF-007` Content-Length versus Transfer-Encoding request smuggling
- `WAF-008` Obfuscated Transfer-Encoding ambiguity
- `WAF-009` HTTP/2 to HTTP/1 desynchronization
- `WAF-010` Connection-state and response-queue poisoning

**HTTP routing and trust** (2)

- `WAF-013` Absolute-form or authority mismatch
- `WAF-014` Client-IP forwarding header spoofing

**Injection - CSV/spreadsheet** (1)

- `WAF-050` CSV or formula injection

**Injection - Header** (1)

- `WAF-052` Generic HTTP header value injection

**Injection - Log** (1)

- `WAF-051` Log injection and log forging

**Injection - Logging/naming** (1)

- `WAF-047` JNDI or naming-context injection

**Injection - Mail/protocol** (1)

- `WAF-049` Email header injection

**Injection - NoSQL** (4)

- `WAF-033` NoSQL operator injection
- `WAF-034` NoSQL JavaScript or expression injection
- `WAF-035` NoSQL regex injection and ReDoS
- `WAF-036` NoSQL aggregation-pipeline injection

**Injection - Object model** (2)

- `WAF-053` Prototype pollution
- `WAF-054` Property-path or object-graph injection

**Injection - Server-side include** (1)

- `WAF-048` Server-side include injection

**Injection - XML** (1)

- `WAF-039` XML injection

**Injection - XPath/XQuery** (1)

- `WAF-038` XPath or XQuery injection

**OAuth/OIDC** (3)

- `WAF-113` OAuth state/nonce or login CSRF attack
- `WAF-114` PKCE downgrade or verifier interception
- `WAF-115` OAuth token leakage and replay through URLs or logs

**Path and file access** (3)

- `WAF-084` Remote file inclusion
- `WAF-086` Arbitrary file write
- `WAF-095` Symlink or race-based path escape

**SAML** (2)

- `WAF-116` SAML signature wrapping or reference confusion
- `WAF-117` SAML assertion replay

**Server-side request forgery** (6)

- `WAF-061` Basic SSRF
- `WAF-062` Blind SSRF
- `WAF-063` Cloud metadata service SSRF
- `WAF-064` SSRF through alternate URL schemes
- `WAF-065` SSRF via redirects or DNS rebinding
- `WAF-066` SSRF-driven resource exhaustion

**Session attacks** (3)

- `WAF-104` Session fixation
- `WAF-105` Session-cookie theft or replay
- `WAF-106` Cookie tampering

**Structured input handling** (1)

- `WAF-017` Duplicate JSON key pollution

**Token attacks** (4)

- `WAF-108` JWT algorithm confusion or unsigned-token acceptance
- `WAF-109` JWT key-selection header abuse
- `WAF-110` JWT claim manipulation or validation omission
- `WAF-111` Bearer-token or API-key replay

**Unsafe deserialization** (6)

- `WAF-055` Generic insecure deserialization
- `WAF-056` Java object deserialization attack
- `WAF-057` .NET deserialization attack
- `WAF-058` PHP object injection
- `WAF-059` Python pickle or language-native object injection
- `WAF-060` YAML unsafe object construction

**XML external entities** (2)

- `WAF-067` Classic external entity injection
- `WAF-068` Blind or out-of-band XXE


### A8 Evasion & Delivery Patterns — 69 unmapped

**Body decoding** (2)

- `EVA-033` Compressed request-body evasion
- `EVA-034` Nested content encoding

**Cache/proxy differential** (1)

- `EVA-050` Cache-key and routing mismatch

**Chunked and trailer processing** (1)

- `EVA-032` Chunk-extension or trailer ambiguity

**Client emulation** (3)

- `EVA-058` Real-browser automation
- `EVA-059` Headless-browser fingerprint masking
- `EVA-060` Session and cookie warming

**Content-type and parser choice** (1)

- `EVA-041` Binary or protobuf opacity

**Control characters** (1)

- `EVA-020` Null-byte and control-character insertion

**Coverage drift** (1)

- `EVA-070` Policy/version drift between WAF nodes or environments

**Encoding and canonicalization** (10)

- `EVA-004` Unicode normalization mismatch
- `EVA-005` Unicode homoglyph or confusable substitution
- `EVA-006` Invalid or overlong UTF-8 handling discrepancy
- `EVA-007` Alternate declared character set
- `EVA-008` HTML entity encoding
- `EVA-009` JavaScript string or Unicode escapes
- `EVA-010` JSON Unicode escape encoding
- `EVA-011` CSS escape encoding
- `EVA-012` Base64 or application-level textual wrapping
- `EVA-013` Hexadecimal, octal, or numeric representation

**Encrypted/opaque application data** (2)

- `EVA-079` Application-layer encrypted payload
- `EVA-080` Signed but malicious structured data

**File/content ambiguity** (1)

- `EVA-081` Polyglot file or multi-parser content

**Identity rotation** (2)

- `EVA-061` Account rotation
- `EVA-062` Credential, token, or API-key rotation

**Inspection limits** (4)

- `EVA-035` Oversized-body inspection bypass
- `EVA-036` High field/part/count bypass
- `EVA-037` Parser timeout or resource-budget fail-open
- `EVA-038` Streaming or late-arriving payload

**Lexical mutation** (4)

- `EVA-015` Whitespace substitution
- `EVA-017` Operator and function substitution
- `EVA-018` Logical invariant or tautology mutation
- `EVA-019` Number and literal shuffling

**Message framing** (3)

- `EVA-028` Content-Length versus Transfer-Encoding desynchronization
- `EVA-029` Transfer-coding obfuscation
- `EVA-031` Line-ending and request-splitting discrepancy

**Method and routing** (1)

- `EVA-047` HTTP method override

**Modern protocol/AI evasion** (7)

- `EVA-083` HTTP/3-to-HTTP/1.1 translation differential
- `EVA-084` QPACK or HPACK normalization and inspection gap
- `EVA-085` HTTP/2 or HTTP/3 connection coalescing identity confusion
- `EVA-086` Encrypted ClientHello or hidden routing-metadata visibility gap
- `EVA-087` AI semantic obfuscation and adversarial suffix evasion
- `EVA-088` Multimodal hidden-instruction evasion
- `EVA-089` Tool-schema or agent-message boundary confusion

**Multi-request behavior** (1)

- `EVA-073` Attack state assembled across requests

**Multipart parsing** (1)

- `EVA-090` Multipart per-part charset validation limited to the last part

**Network identity encoding** (1)

- `EVA-024` Alternative IP-address representation

**Network reassembly** (1)

- `EVA-051` IP fragmentation or TCP segmentation differential

**Novelty** (1)

- `EVA-071` Zero-day or rule-gap evasion

**Parameter location** (1)

- `EVA-046` Move input among query, body, cookie, header, path, or trailer

**Parser differential** (3)

- `EVA-025` HTTP parameter pollution
- `EVA-026` Duplicate JSON key ambiguity
- `EVA-027` Duplicate or conflicting HTTP header ambiguity

**Path canonicalization** (2)

- `EVA-022` Matrix parameters and path-parameter ambiguity
- `EVA-023` Trailing dot, slash, suffix, or path-info ambiguity

**Payload placement** (1)

- `EVA-065` Benign padding and anomaly-score dilution

**Protocol translation** (1)

- `EVA-030` HTTP/2-to-HTTP/1 request smuggling

**Protocol upgrade** (1)

- `EVA-049` WebSocket upgrade and post-upgrade opacity

**Protocol version** (1)

- `EVA-048` Switch among HTTP/1.1, HTTP/2, and HTTP/3

**Rule discovery** (1)

- `EVA-066` Threshold and rule probing

**Rule engine policy** (3)

- `EVA-067` Rule exclusion or exception abuse
- `EVA-068` Allowlist or trusted-client impersonation
- `EVA-069` Fail-open on WAF error or outage

**Second-order behavior** (1)

- `EVA-072` Stored or deferred payload execution

**Structured data** (2)

- `EVA-044` Type confusion and scalar/object switching
- `EVA-045` Deep nesting and sparse-index abuse

**Target rotation** (1)

- `EVA-063` Endpoint, parameter, or object rotation

**Topology bypass** (1)

- `EVA-077` Alternate protocol bypass

**XML inspection** (1)

- `EVA-091` XML attribute-value inspection coverage bypass

## Appendix C — Weak-coverage register (E1 + E2): which AstraNull entries are load-bearing for how many catalog vectors

Sorted by how many catalog rows depend on an entry that cannot currently produce a gradeable verdict.

| AstraNull ID | AstraNull name | Tier | Mapped checks | Catalog vectors resting on it |
|---|---|---|---|---|
| ATT-024 | Portmap/RIPv1/BitTorrent/Jenkins/TeamSpeak reflectors | E2 transport-only | `reflect.portmap_service_exposure.safe`, `reflect.jenkins_discovery_exposure.safe`, `reflect.legacy_device_discovery_exposure.safe` | 14: NET-134, NET-135, NET-142, AMP-013, AMP-016, AMP-017, AMP-019, AMP-021, AMP-023, AMP-024, AMP-025, AMP-053, AMP-062, AMP-063 |
| ATT-074 | SIP / VoIP flood | E2 transport-only | `l3.sip_voip_flood.readiness`, `high_scale.volumetric.request_only` | 12: APP-112, APP-113, APP-114, APP-176, APP-177, APP-178, APP-179, APP-180, APP-181, APP-182, APP-183, APP-184 |
| ATT-041 | DNS query flood | E2 transport-only | `dns.authoritative_response.safe`, `high_scale.dns_high_query.request_only` | 10: APP-099, APP-153, APP-154, APP-156, APP-157, APP-158, APP-159, APP-160, APP-161, APP-165 |
| ATT-010 | Fragmentation flood | E1 declared-only | `l3.fragmentation_flood.readiness` | 9: NET-009, NET-010, NET-012, NET-013, NET-026, NET-052, NET-070, NET-161, NET-166 |
| ATT-002 | ICMP / ping flood | E1 declared-only | `l3.icmp_flood.readiness`, `high_scale.volumetric.request_only` | 9: NET-016, NET-017, NET-018, NET-019, NET-023, NET-028, NET-029, NET-162, NET-163 |
| ATT-025 | DTLS / SIP / RDP / TFTP / ARMS / CoAP reflection | E2 transport-only | `reflect.dtls_sip_rdp_tftp_exposure.safe` | 9: NET-086, NET-136, NET-140, AMP-018, AMP-028, AMP-034, AMP-035, AMP-036, AMP-041 |
| ATT-020 | SSDP/UPnP and device-discovery reflection | E2 transport-only | `reflect.ssdp_exposure.safe`, `reflect.legacy_device_discovery_exposure.safe` | 7: NET-131, AMP-008, AMP-040, AMP-043, AMP-044, AMP-052, AMP-059 |
| ATT-007 | TCP flag floods (FIN/PSH/URG/NULL/Xmas) | E2 transport-only | `l3.tcp_flag_anomaly.readiness` | 6: NET-060, NET-061, NET-062, NET-063, NET-064, NET-118 |
| ATT-075 | Application connection exhaustion | E2 transport-only | `tls.idle_connection_timeout.safe`, `l3.connection_table_exhaustion.request_only`, `l7.connection_hoarding.readiness` | 6: NET-066, NET-089, NET-120, APP-019, APP-042, APP-043 |
| ATT-023 | mDNS / NetBIOS / WS-Discovery reflection | E2 transport-only | `reflect.mdns_netbios_wsdiscovery_exposure.safe` | 6: NET-132, NET-133, NET-137, AMP-014, AMP-015, AMP-020 |
| ATT-001 | UDP flood | E2 transport-only | `l3.forbidden_udp_port.safe`, `high_scale.volumetric.request_only` | 4: NET-048, NET-049, NET-050, NET-051 |
| ATT-118 | CoAP / IoT device-management reflector abuse | E2 transport-only | `reflect.coap_iot_exposure.safe`, `reflect.legacy_device_discovery_exposure.safe` | 4: NET-128, AMP-026, AMP-039, AMP-060 |
| ATT-022 | CHARGEN/QOTD/Echo reflection | E2 transport-only | `reflect.chargen_qotd_exposure.safe` | 4: NET-138, AMP-010, AMP-011, AMP-012 |
| ATT-071 | WebSocket DDoS | E2 transport-only | `protocol.websocket_connection_controls.safe`, `protocol.websocket_message_rate.readiness` | 4: APP-072, APP-073, APP-074, APP-193 |
| ATT-159 | DNS over HTTPS/TLS (DoH/DoT) query exhaustion | E1 declared-only | `dns.doh_dot_exposure.readiness` | 4: APP-108, APP-109, APP-174, APP-175 |
| ATT-143 | Checkout / cart transaction abuse | E1 declared-only | `l7.checkout_abuse.validation` | 4: APP-144, APP-149, APP-150, WAF-162 |
| ATT-119 | IP options / malformed IP header abuse | E1 declared-only | `exploit.ip_options.posture` | 3: NET-007, NET-008, NET-105 |
| ATT-011 | Ping of Death | E1 declared-only | `exploit.ping_of_death.posture` | 3: NET-014, NET-090, NET-100 |
| ATT-013 | GRE flood | E1 declared-only | `l3.gre_esp_flood.readiness`, `high_scale.volumetric.request_only` | 3: NET-036, NET-037, NET-160 |
| ATT-146 | Distributed low-rate / residential proxy flood | E1 declared-only | `pattern.residential_proxy.readiness` | 3: NET-047, EVA-054, EVA-055 |
| ATT-125 | NAT / firewall state table exhaustion | E1 declared-only | `l3.nat_state_table.readiness` | 3: NET-053, NET-054, NET-087 |
| ATT-003 | SYN flood | E2 transport-only | `l3.forbidden_tcp_port.safe`, `l3.basic_deny_rule.safe`, `l3.syn_flood.readiness`, `l3.connection_table_exhaustion.request_only`, `high_scale.volumetric.request_only` | 3: NET-056, NET-119, NET-144 |
| ATT-168 | OpenVPN / WireGuard reflector exposure | E2 transport-only | `reflect.openvpn_wireguard_exposure.safe` | 3: NET-084, NET-085, AMP-033 |
| ATT-137 | Multicast / broadcast storm | E1 declared-only | `l3.multicast_broadcast_storm.readiness` | 3: NET-092, NET-093, NET-095 |
| ATT-059 | Large-payload POST | E2 transport-only | `l7.header_size_boundary.safe`, `l7.large_body_post.readiness` | 3: APP-014, APP-024, APP-040 |
| ATT-046 | DNS garbage flood | E2 transport-only | `dns.garbage_flood.readiness` | 3: APP-102, APP-166, APP-167 |
| ATT-167 | MQTT broker flood | E1 declared-only | `l7.mqtt_broker_exposure.readiness` | 3: APP-121, APP-122, APP-123 |
| ATT-012 | Teardrop | E1 declared-only | `exploit.teardrop.posture` | 2: NET-011, NET-165 |
| ATT-124 | IPv6 volumetric flood (beyond reachability check) | E2 transport-only | `l3.ipv6_reachability.safe`, `l3.ipv6_volumetric.readiness` | 2: NET-024, AMP-070 |
| ATT-014 | ESP / IPsec flood | E1 declared-only | `l3.gre_esp_flood.readiness` | 2: NET-038, NET-039 |
| ATT-095 | Pulse-wave / burst attacks | E1 declared-only | `pattern.pulse_wave.readiness` | 2: NET-046, EVA-057 |
| ATT-008 | TCP connection flood | E2 transport-only | `l3.connection_table_exhaustion.request_only`, `l3.tcp_connection_flood.readiness` | 2: NET-065, NET-067 |
| ATT-009 | Out-of-state TCP flood | E1 declared-only | `l3.out_of_state_tcp.readiness` | 2: NET-068, NET-121 |
| ATT-135 | SCTP flood | E1 declared-only | `l3.sctp_exposure.readiness` | 2: NET-072, NET-073 |
| ATT-136 | IKE / IPsec negotiation flood | E1 declared-only | `l3.ike_ipsec_negotiation.readiness` | 2: NET-082, AMP-031 |
| ATT-021 | SNMP reflection | E2 transport-only | `reflect.snmp_exposure.safe` | 2: NET-129, AMP-009 |
| ATT-017 | NTP amplification | E1 declared-only | `amp.ntp_exposure.safe` | 2: NET-130, AMP-004 |
| ATT-018 | CLDAP amplification | E1 declared-only | `amp.cldap_exposure.safe` | 2: AMP-005, AMP-006 |
| ATT-027 | TCP middlebox reflection | E2 transport-only | `reflect.tcp_middlebox_exposure.safe` | 2: AMP-047, AMP-071 |
| ATT-134 | Smurf / ICMP-to-broadcast amplification | E1 declared-only | `amp.smurf_broadcast_exposure.safe` | 2: AMP-049, AMP-050 |
| ATT-141 | HTTP Range header abuse | E1 declared-only | `l7.http_range_abuse.readiness` | 2: APP-013, WAF-023 |
| ATT-113 | File upload flood | E1 declared-only | `l7.file_upload_abuse.readiness` | 2: APP-015, APP-138 |
| ATT-104 | SSE long-lived stream exhaustion | E1 declared-only | `protocol.sse_stream.readiness` | 2: APP-020, APP-021 |
| ATT-149 | XML bomb / entity expansion (billion laughs class) | E1 declared-only | `l7.json_xml_bomb.readiness` | 2: APP-031, WAF-069 |
| ATT-067 | HTTP/2 Rapid Reset | E2 transport-only | `protocol.http2_rapid_reset_readiness.safe`, `l7.http2_rapid_reset.validation` | 2: APP-077, APP-087 |
| ATT-070 | HTTP/3 / QUIC application flood | E2 transport-only | `protocol.http3_quic_exposure.safe`, `high_scale.application.request_only` | 2: APP-092, APP-093 |
| ATT-152 | QPACK / HTTP/3 header compression bomb | E1 declared-only | `l7.qpack_bomb.readiness` | 2: APP-094, APP-095 |
| ATT-111 | TLS 0-RTT / early data abuse | E1 declared-only | `tls.zero_rtt.readiness` | 2: APP-098, APP-192 |
| ATT-123 | SMTP / email connection flood | E2 transport-only | `l3.smtp_connection_flood.readiness` | 2: APP-115, APP-116 |
| ATT-121 | Adaptive / randomized flood (entropy evasion) | E1 declared-only | `pattern.adaptive_evasion.readiness` | 2: EVA-056, EVA-064 |
| ATT-133 | Land attack (same src/dst IP) | E1 declared-only | `exploit.land_attack.posture` | 1: NET-015 |
| ATT-094 | Carpet bombing | E1 declared-only | `pattern.carpet_bombing.readiness` | 1: NET-045 |
| ATT-004 | ACK flood | E1 declared-only | `l3.ack_flood.readiness` | 1: NET-057 |
| ATT-006 | RST flood | E1 declared-only | `l3.rst_flood.readiness` | 1: NET-058 |
| ATT-005 | SYN-ACK flood | E1 declared-only | `l3.syn_ack_flood.readiness` | 1: NET-059 |
| ATT-015 | QUIC flood | E2 transport-only | `protocol.http3_quic_exposure.safe`, `high_scale.volumetric.request_only` | 1: NET-075 |
| ATT-120 | Malformed QUIC version / spin bit abuse | E1 declared-only | `exploit.malformed_quic.posture` | 1: NET-076 |
| ATT-065 | TLS renegotiation attacks | E2 transport-only | `tls.renegotiation.readiness` | 1: NET-079 |
| ATT-091 | Spoofed flood | E1 declared-only | `pattern.spoofed_source.readiness` | 1: NET-145 |
| ATT-019 | Memcached amplification | E2 transport-only | `amp.memcached_exposure.safe` | 1: AMP-007 |
| ATT-163 | STUN/TURN reflection | E2 transport-only | `reflect.stun_turn_exposure.safe` | 1: AMP-027 |
| ATT-116 | MSSQL resolver reflection | E2 transport-only | `reflect.mssql_resolver_exposure.safe` | 1: AMP-030 |
| ATT-026 | QUIC reflection | E2 transport-only | `reflect.quic_reflection_exposure.safe` | 1: AMP-037 |
| ATT-164 | IPMI / BMC reflector exposure | E2 transport-only | `reflect.ipmi_bmc_exposure.safe` | 1: AMP-038 |
| ATT-117 | Jenkins / CI discovery reflection | E2 transport-only | `reflect.jenkins_discovery_exposure.safe` | 1: AMP-042 |
| ATT-092 | DRDoS / reflection delivery | E2 transport-only | `dns.amplification_exposure.safe` | 1: AMP-056 |
| ATT-050 | DNSBomb | E1 declared-only | `dns.dnsbomb.readiness` | 1: AMP-065 |
| ATT-049 | NXNSAttack | E2 transport-only | `dns.nxns_attack.readiness` | 1: AMP-066 |
| ATT-053 | HTTP HEAD flood | E2 transport-only | `l7.http_method_restriction.safe` | 1: APP-002 |
| ATT-052 | HTTP POST flood | E1 declared-only | `l7.http_post_flood.validation`, `high_scale.application.request_only` | 1: APP-003 |
| ATT-097 | Application-aware targeting | E2 transport-only | `l7.expensive_endpoint.safe` | 1: APP-011 |
| ATT-060 | Slowloris | E2 transport-only | `tls.slow_header_body_timeout.safe`, `l7.slowloris.readiness` | 1: APP-016 |
| ATT-061 | Slow POST / RUDY | E1 declared-only | `l7.slow_post.readiness` | 1: APP-017 |
| ATT-062 | Slow read | E1 declared-only | `l7.slow_read.readiness` | 1: APP-018 |
| ATT-140 | HTTP pipelining abuse | E1 declared-only | `l7.http_pipelining.readiness` | 1: APP-022 |
| ATT-147 | ReDoS / regex algorithmic complexity | E1 declared-only | `l7.redos.readiness` | 1: APP-027 |
| ATT-148 | JSON bomb / deeply nested payload | E1 declared-only | `l7.json_xml_bomb.readiness` | 1: APP-030 |
| ATT-069 | HTTP/2 MadeYouReset | E2 transport-only | `l7.http2_made_you_reset.readiness` | 1: APP-078 |
| ATT-068 | HTTP/2 CONTINUATION flood | E2 transport-only | `l7.http2_continuation.readiness` | 1: APP-079 |
| ATT-110 | HTTP/2 priority tree abuse | E1 declared-only | `l7.http2_priority_abuse.readiness` | 1: APP-086 |
| ATT-066 | HTTP/2 multiplexing flood | E2 transport-only | `protocol.http2_stream_concurrency.safe` | 1: APP-088 |
| ATT-150 | HPACK decompression bomb | E1 declared-only | `l7.hpack_bomb.readiness` | 1: APP-089 |
| ATT-153 | HTTP/3 control stream / SETTINGS flood | E2 transport-only | `protocol.http3_control_stream.readiness` | 1: APP-096 |
| ATT-154 | QUIC migration / path validation abuse | E1 declared-only | `exploit.quic_migration.posture` | 1: APP-097 |
| ATT-044 | Random-subdomain / water-torture | E2 transport-only | `dns.random_prefix_nxdomain.safe` | 1: APP-100 |
| ATT-043 | NXDOMAIN flood | E2 transport-only | `dns.random_prefix_nxdomain.safe` | 1: APP-101 |
| ATT-048 | DNS domain lock-up | E1 declared-only | `dns.domain_lockup.readiness` | 1: APP-107 |
| ATT-045 | DNS laundering | E1 declared-only | `dns.laundering.readiness` | 1: APP-110 |
| ATT-138 | SSH connection flood | E2 transport-only | `l3.ssh_connection_flood.readiness` | 1: APP-126 |
| ATT-139 | FTP connection flood | E2 transport-only | `l3.ftp_connection_flood.readiness` | 1: APP-128 |
| ATT-165 | Redis direct protocol flood | E2 transport-only | `reflect.redis_direct_exposure.safe` | 1: APP-131 |
| ATT-073 | WordPress XML-RPC / pingback DDoS | E2 transport-only | `l7.wordpress_xmlrpc.readiness` | 1: APP-133 |
| ATT-108 | Webhook / callback flood | E1 declared-only | `l7.webhook_flood.readiness` | 1: APP-142 |
| ATT-047 | Phantom domain attack | E1 declared-only | `dns.phantom_domain.readiness` | 1: APP-170 |
| ATT-142 | HTTP conditional revalidation flood (If-None-Match/IMS) | E1 declared-only | `l7.conditional_revalidation.readiness` | 1: APP-195 |
| ATT-132 | HTTP TRACE / unusual method abuse | E2 transport-only | `l7.http_method_restriction.safe` | 1: WAF-001 |
| ATT-158 | Password reset OTP flood | E2 transport-only | `l7.password_reset.safe` | 1: WAF-102 |
| ATT-107 | Batch API abuse | E1 declared-only | `l7.batch_api_abuse.validation` | 1: WAF-135 |
| ATT-127 | DNS-only hostname bypass | E1 declared-only | `origin.dns_hostname_bypass.readiness` | 1: EVA-075 |

## Appendix D — Per-check execution inventory (all 175 checks)

`actual executor` is what `workers/probe-worker.mjs` runs, which is not always the declared kind (see D-02). `collides with` = number of other checks producing an identical probe (see D-10).

| check_id | class | declared probe kind | actual executor | evidence tier | collides with |
|---|---|---|---|---|---|
| `amp.authoritative_resolver_exposure.safe` | safe | dns_resolve | **`probeHttpHead` (family fallback — MISROUTED)** | E2 transport-only | 3 |
| `amp.cldap_exposure.safe` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `amp.dns_any_txt_exposure.safe` | safe | dns_resolve | **`probeHttpHead` (family fallback — MISROUTED)** | E2 transport-only | 3 |
| `amp.memcached_exposure.safe` | safe | tcp_connect | **`probeHttpHead` (family fallback — MISROUTED)** | E2 transport-only | 11 |
| `amp.ntp_exposure.safe` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `amp.smurf_broadcast_exposure.safe` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `dns.amplification_exposure.safe` | safe | dns_resolve | `probeDns` | E2 transport-only | 2 |
| `dns.authoritative_response.safe` | safe | dns_resolve | `probeDns` | E2 transport-only | 2 |
| `dns.dnsbomb.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `dns.dnssec_expensive_query.safe` | safe | dnssec_posture | capabilityProbes dispatch | E3 semantic-safe | 0 |
| `dns.doh_dot_exposure.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `dns.domain_lockup.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `dns.garbage_flood.readiness` | safe | dns_resolve | `probeDns` | E2 transport-only | 0 |
| `dns.laundering.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `dns.nxns_attack.readiness` | safe | dns_resolve | `probeDns` | E2 transport-only | 3 |
| `dns.open_recursion_behavior.safe` | safe | dns_open_recursion | capabilityProbes dispatch | E3 semantic-safe | 0 |
| `dns.phantom_domain.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `dns.qname_minimization.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `dns.random_prefix_nxdomain.safe` | safe | dns_resolve | `probeDns` | E2 transport-only | 2 |
| `dns.secondary_failover.safe` | safe | dns_failover_posture | capabilityProbes dispatch | E3 semantic-safe | 0 |
| `dns.tcp_fallback.readiness` | safe | dns_resolve | `probeDns` | E2 transport-only | 3 |
| `dns.zone_transfer_exposure.safe` | safe | dns_axfr_leak | capabilityProbes dispatch | E3 semantic-safe | 0 |
| `dns.zone_walking.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `exploit.ip_options.posture` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `exploit.land_attack.posture` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `exploit.malformed_quic.posture` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `exploit.ping_of_death.posture` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `exploit.quic_migration.posture` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `exploit.teardrop.posture` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `high_scale.application.request_only` | soc_gated | (none) | external SOC adapter (no in-repo executor) | E4 SOC-governed | 0 |
| `high_scale.degradation_recovery.request_only` | soc_gated | (none) | external SOC adapter (no in-repo executor) | E4 SOC-governed | 0 |
| `high_scale.dns_high_query.request_only` | soc_gated | (none) | external SOC adapter (no in-repo executor) | E4 SOC-governed | 0 |
| `high_scale.multi_vector.request_only` | soc_gated | (none) | external SOC adapter (no in-repo executor) | E4 SOC-governed | 0 |
| `high_scale.volumetric.request_only` | soc_gated | (none) | external SOC adapter (no in-repo executor) | E4 SOC-governed | 0 |
| `l3.ack_flood.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l3.basic_deny_rule.safe` | safe | tcp_connect | `probeTcpConnect` | E2 transport-only | 11 |
| `l3.connection_table_exhaustion.request_only` | soc_gated | (none) | external SOC adapter (no in-repo executor) | E4 SOC-governed | 0 |
| `l3.firewall_exposure_scan.safe` | safe | port_scan_bounded | capabilityProbes dispatch | E3 semantic-safe | 0 |
| `l3.forbidden_tcp_port.safe` | safe | tcp_connect | `probeTcpConnect` | E2 transport-only | 11 |
| `l3.forbidden_udp_port.safe` | safe | udp_probe | `probeUdpDatagram` | E2 transport-only | 13 |
| `l3.fragmentation_flood.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l3.ftp_connection_flood.readiness` | safe | tcp_connect | `probeTcpConnect` | E2 transport-only | 11 |
| `l3.gre_esp_flood.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l3.icmp_flood.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l3.ike_ipsec_negotiation.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l3.ipv6_reachability.safe` | safe | tcp_connect | `probeTcpConnect` | E2 transport-only | 11 |
| `l3.ipv6_volumetric.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l3.multicast_broadcast_storm.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l3.nat_state_table.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l3.out_of_state_tcp.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l3.rst_flood.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l3.sctp_exposure.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l3.sip_voip_flood.readiness` | safe | udp_probe | `probeUdpDatagram` | E2 transport-only | 13 |
| `l3.smtp_connection_flood.readiness` | safe | tcp_connect | `probeTcpConnect` | E2 transport-only | 11 |
| `l3.ssh_connection_flood.readiness` | safe | tcp_connect | `probeTcpConnect` | E2 transport-only | 11 |
| `l3.syn_ack_flood.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l3.syn_flood.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l3.tcp_connection_flood.readiness` | safe | tcp_connect | `probeTcpConnect` | E2 transport-only | 11 |
| `l3.tcp_flag_anomaly.readiness` | safe | tcp_connect | `probeTcpConnect` | E2 transport-only | 11 |
| `l7.api_quota_exhaustion.safe` | safe | rate_limit_sequence | capabilityProbes dispatch | E3 semantic-safe | 7 |
| `l7.api_surface_scan.safe` | safe | api_surface_scan | capabilityProbes dispatch | E3 semantic-safe | 0 |
| `l7.batch_api_abuse.validation` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.bot_challenge_marker.safe` | safe | bot_challenge_probe | capabilityProbes dispatch | E3 semantic-safe | 0 |
| `l7.cache_busting.safe` | safe | cache_abuse_probe | capabilityProbes dispatch | E3 semantic-safe | 0 |
| `l7.captcha_challenge_abuse.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.checkout_abuse.validation` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.conditional_revalidation.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.connection_hoarding.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.cors_posture.safe` | safe | cors_posture_probe | capabilityProbes dispatch | E3 semantic-safe | 0 |
| `l7.elasticsearch_abuse.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.expensive_endpoint.safe` | safe | http_head | `probeHttpHead` | E2 transport-only | 6 |
| `l7.export_abuse.validation` | safe | rate_limit_sequence | capabilityProbes dispatch | E3 semantic-safe | 7 |
| `l7.file_upload_abuse.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.graphql_batch_abuse.validation` | safe | graphql_posture_probe | capabilityProbes dispatch | E3 semantic-safe | 0 |
| `l7.graphql_complexity.safe` | safe | graphql_posture_probe | capabilityProbes dispatch | E3 semantic-safe | 0 |
| `l7.header_size_boundary.safe` | safe | http_head | `probeHttpHead` | E2 transport-only | 6 |
| `l7.health_check_flood.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.hpack_bomb.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.http2_continuation.readiness` | safe | http2_settings | `probeHttp2Settings` | E2 transport-only | 5 |
| `l7.http2_made_you_reset.readiness` | safe | http2_settings | `probeHttp2Settings` | E2 transport-only | 5 |
| `l7.http2_priority_abuse.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.http2_push_promise.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.http2_rapid_reset.validation` | safe | http2_settings | `probeHttp2Settings` | E2 transport-only | 5 |
| `l7.http_get_flood.validation` | safe | rate_limit_sequence | capabilityProbes dispatch | E3 semantic-safe | 7 |
| `l7.http_method_restriction.safe` | safe | http_head | `probeHttpHead` | E2 transport-only | 6 |
| `l7.http_pipelining.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.http_post_flood.validation` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.http_range_abuse.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.json_xml_bomb.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.large_body_post.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.login_abuse_flow.safe` | safe | rate_limit_sequence | capabilityProbes dispatch | E3 semantic-safe | 7 |
| `l7.low_and_slow.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.low_rate_rate_limit.safe` | safe | rate_limit_sequence | capabilityProbes dispatch | E3 semantic-safe | 7 |
| `l7.mqtt_broker_exposure.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.oauth_token_abuse.validation` | safe | rate_limit_sequence | capabilityProbes dispatch | E3 semantic-safe | 7 |
| `l7.otp_sms_cost.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.password_reset.safe` | safe | http_head | `probeHttpHead` | E2 transport-only | 6 |
| `l7.qpack_bomb.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.redos.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.search_abuse.validation` | safe | rate_limit_sequence | capabilityProbes dispatch | E3 semantic-safe | 7 |
| `l7.signup_registration_abuse.validation` | safe | rate_limit_sequence | capabilityProbes dispatch | E3 semantic-safe | 7 |
| `l7.slow_post.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.slow_read.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.slowloris.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.waf_marker_rule.safe` | safe | waf_enforcement_probe | capabilityProbes dispatch | E3 semantic-safe | 1 |
| `l7.webhook_flood.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `l7.wordpress_xmlrpc.readiness` | safe | http_head | `probeHttpHead` | E2 transport-only | 6 |
| `ops.alert_workflow_marker.safe` | safe | alert_webhook_ping | `probeAlertWebhookPing` | E2 transport-only | 0 |
| `ops.attack_alert_coverage.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `ops.autoscaling_cost.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `ops.kill_switch_drill.request_only` | soc_gated | (none) | external SOC adapter (no in-repo executor) | E4 SOC-governed | 0 |
| `ops.kill_switch_drill.safe` | safe | ops_readiness | `executeOpsReadinessProbe` (in-process) | E3 semantic-safe | 0 |
| `ops.provider_telemetry.request_only` | soc_gated | (none) | external SOC adapter (no in-repo executor) | E4 SOC-governed | 0 |
| `ops.runbook_contact_validation.request_only` | soc_gated | (none) | external SOC adapter (no in-repo executor) | E4 SOC-governed | 0 |
| `ops.runbook_contact_validation.safe` | safe | ops_readiness | `executeOpsReadinessProbe` (in-process) | E3 semantic-safe | 0 |
| `origin.cdn_bypass.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `origin.direct_bypass.safe` | safe | host_sni_bypass | capabilityProbes dispatch | E3 semantic-safe | 2 |
| `origin.direct_reachability.safe` | safe | host_sni_bypass | capabilityProbes dispatch | E3 semantic-safe | 2 |
| `origin.dns_hostname_bypass.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `origin.host_sni_bypass.safe` | safe | host_sni_bypass | capabilityProbes dispatch | E3 semantic-safe | 2 |
| `origin.leak_scan.safe` | safe | origin_leak_scan | capabilityProbes dispatch | E3 semantic-safe | 0 |
| `path.protected_canary.safe` | safe | http_head | `probeHttpHead` | E2 transport-only | 6 |
| `pattern.adaptive_evasion.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `pattern.carpet_bombing.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `pattern.pulse_wave.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `pattern.ransom_ddos.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `pattern.rate_limit_evasion.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `pattern.residential_proxy.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `pattern.spoofed_source.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `protocol.grpc_reflection_stream.safe` | safe | grpc_reflection_probe | capabilityProbes dispatch | E3 semantic-safe | 0 |
| `protocol.http2_rapid_reset_readiness.safe` | safe | http2_settings | `probeHttp2Settings` | E2 transport-only | 5 |
| `protocol.http2_readiness.safe` | safe | http2_settings | `probeHttp2Settings` | E2 transport-only | 5 |
| `protocol.http2_stream_concurrency.safe` | safe | http2_settings | `probeHttp2Settings` | E2 transport-only | 5 |
| `protocol.http3_control_stream.readiness` | safe | quic_reachability | `probeQuicReachability` | E2 transport-only | 2 |
| `protocol.http3_quic_exposure.safe` | safe | quic_reachability | `probeQuicReachability` | E2 transport-only | 2 |
| `protocol.sse_stream.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `protocol.websocket_connection_controls.safe` | safe | websocket_upgrade_posture | `probeWebsocketUpgradePosture` | E2 transport-only | 0 |
| `protocol.websocket_message_rate.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `reflect.chargen_qotd_exposure.safe` | safe | udp_probe | `probeUdpDatagram` | E2 transport-only | 13 |
| `reflect.coap_iot_exposure.safe` | safe | udp_probe | `probeUdpDatagram` | E2 transport-only | 13 |
| `reflect.dtls_sip_rdp_tftp_exposure.safe` | safe | udp_probe | `probeUdpDatagram` | E2 transport-only | 13 |
| `reflect.ipmi_bmc_exposure.safe` | safe | udp_probe | `probeUdpDatagram` | E2 transport-only | 13 |
| `reflect.jenkins_discovery_exposure.safe` | safe | udp_probe | `probeUdpDatagram` | E2 transport-only | 13 |
| `reflect.legacy_device_discovery_exposure.safe` | safe | udp_probe | `probeUdpDatagram` | E2 transport-only | 13 |
| `reflect.mdns_netbios_wsdiscovery_exposure.safe` | safe | udp_probe | `probeUdpDatagram` | E2 transport-only | 13 |
| `reflect.mssql_resolver_exposure.safe` | safe | udp_probe | `probeUdpDatagram` | E2 transport-only | 13 |
| `reflect.openvpn_wireguard_exposure.safe` | safe | udp_probe | `probeUdpDatagram` | E2 transport-only | 13 |
| `reflect.portmap_service_exposure.safe` | safe | tcp_connect | **`probeHttpHead` (family fallback — MISROUTED)** | E2 transport-only | 11 |
| `reflect.quic_reflection_exposure.safe` | safe | quic_reachability | `probeQuicReachability` | E2 transport-only | 2 |
| `reflect.redis_direct_exposure.safe` | safe | tcp_connect | **`probeHttpHead` (family fallback — MISROUTED)** | E2 transport-only | 11 |
| `reflect.snmp_exposure.safe` | safe | udp_probe | `probeUdpDatagram` | E2 transport-only | 13 |
| `reflect.ssdp_exposure.safe` | safe | udp_probe | `probeUdpDatagram` | E2 transport-only | 13 |
| `reflect.stun_turn_exposure.safe` | safe | udp_probe | `probeUdpDatagram` | E2 transport-only | 13 |
| `reflect.tcp_middlebox_exposure.safe` | safe | tcp_connect | **`probeHttpHead` (family fallback — MISROUTED)** | E2 transport-only | 11 |
| `tls.full_audit.safe` | safe | tls_audit | capabilityProbes dispatch | E3 semantic-safe | 2 |
| `tls.handshake_rate.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `tls.idle_connection_timeout.safe` | safe | tls_session | `probeTlsSession` | E2 transport-only | 1 |
| `tls.ocsp_stapling.readiness` | safe | tls_audit | capabilityProbes dispatch | E3 semantic-safe | 2 |
| `tls.profile_exposure.safe` | safe | tls_audit | capabilityProbes dispatch | E3 semantic-safe | 2 |
| `tls.renegotiation.readiness` | safe | tls_session | `probeTlsSession` | E2 transport-only | 1 |
| `tls.slow_header_body_timeout.safe` | safe | http_head | `probeHttpHead` | E2 transport-only | 6 |
| `tls.zero_rtt.readiness` | safe | metadata_marker | `probeMetadataMarker` → `not_run` | E1 declared-only | 68 |
| `waf.enforcement.safe` | safe | waf_enforcement_probe | capabilityProbes dispatch | E3 semantic-safe | 0 |
| `waf.fingerprint.safe` | safe | outside_in_waf_scan | capabilityProbes dispatch | E3 semantic-safe | 0 |
| `waf.low_rate_limit.safe` | safe | rate_limit_sequence | capabilityProbes dispatch | E3 semantic-safe | 0 |
| `waf.marker_rule.safe` | safe | waf_enforcement_probe | capabilityProbes dispatch | E3 semantic-safe | 1 |
| `waf.offensive_combined.soc` | soc_gated | (none) | external SOC adapter (no in-repo executor) | E4 SOC-governed | 0 |
| `waf.offensive_command_injection.soc` | soc_gated | (none) | external SOC adapter (no in-repo executor) | E4 SOC-governed | 0 |
| `waf.offensive_ldap_injection.soc` | soc_gated | (none) | external SOC adapter (no in-repo executor) | E4 SOC-governed | 0 |
| `waf.offensive_path_traversal.soc` | soc_gated | (none) | external SOC adapter (no in-repo executor) | E4 SOC-governed | 0 |
| `waf.offensive_rce.soc` | soc_gated | (none) | external SOC adapter (no in-repo executor) | E4 SOC-governed | 0 |
| `waf.offensive_sqli.soc` | soc_gated | (none) | external SOC adapter (no in-repo executor) | E4 SOC-governed | 0 |
| `waf.offensive_ssti.soc` | soc_gated | (none) | external SOC adapter (no in-repo executor) | E4 SOC-governed | 0 |
| `waf.offensive_xss.soc` | soc_gated | (none) | external SOC adapter (no in-repo executor) | E4 SOC-governed | 0 |
| `waf.origin_bypass.safe` | safe | host_sni_bypass | capabilityProbes dispatch | E3 semantic-safe | 0 |
