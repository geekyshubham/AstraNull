# Check and Detection Gap Analysis — 2026-10-24

This is the gap register behind DET-027–DET-047 (`PROGRESS.md` §4.2). It answers three questions:

1. Which shipped checks do not do what their id, name and verdict claim?
2. Is the WAF/CDN *detection* path correct, and where does it overclaim?
3. Which check families are missing entirely?

It is a findings document. Nothing here is implemented yet; the plan is Part 4.

## Method and evidence standard

- The catalog was loaded programmatically from `src/contracts/checks.mjs` (275 entries) and every
  `probe_profile.kind` was traced to its executor in `workers/probe-worker.mjs` and
  `src/lib/capabilityProbes.mjs`.
- Detection behaviour was read from `src/lib/edgeFingerprint.mjs`,
  `src/lib/edgeDetectionProjection.mjs`, `src/lib/edgeDetectionPresenter.mjs` and
  `src/lib/outsideInWafScanner.mjs`, then exercised with the exported classifiers.
- External coverage was compared against GoTestWAF test sets and encoders, wafw00f detection,
  projectdiscovery/cdncheck, nuclei `dns`/`ssl`/`http/misconfiguration` templates, OWASP CRS
  paranoia levels, the Cloudflare/AWS/Azure/GCP DDoS guidance, and the relevant RFCs.
- Every row cites a file:line or a URL. Rows marked **verified** were reproduced against the code
  during this analysis; rows marked **read** are from static reading and must be re-confirmed by the
  implementing agent before the fix is written.

Severity: **S1** wrong answer shown to a customer, **S2** capability claimed but absent,
**S3** fidelity/duplication, **S4** documentation or governance.

## Part 1 — Correctness defects in shipped checks

### 1.1 Hollow checks

49 of 275 checks are hollow: 34 carry `mechanism_supported: false` and 15 carry
`setup_required: true`. They either send zero requests or send traffic and always discard the result.
All 275 are still offered as selectable because `checkRequiresAdditionalInput()` is a stub returning
`false` (`src/contracts/checks.mjs:4081-4083`) and `isCustomerRunnable()` returns `Boolean(check)`
(`:3844-3846`). **Verified.**

| Severity | Check group | What happens | Where |
|---|---|---|---|
| S1 | 28 `waf.evasion_*.safe` (all but the 16 supported transforms) | Declares 4 requests, sends 0, returns `inconclusive`/`unsupported_evasion_delivery` | `src/lib/vectorProbes/evasionProbes.mjs:339-345` |
| S1 | 15 `waf.*_marker.safe` (method policy, smuggling, CRLF, open redirect, NoSQL, XPath, JNDI, CSV formula, prototype pollution, deserialization, SSRF, XXE, file upload, JWT, SSTI) | Spends up to 8 requests, then forces `setup_required` and maps to `not_run` | `src/lib/capabilityProbes.mjs:3245-3263` |
| S1 | `waf.inspection_limit.safe` | Declares 6 requests, always `not_run` with 0 requests | `src/lib/capabilityProbes.mjs:1989-2004` |
| S1 | `l7.compressed_request_decompression.posture` | Declares 2 requests, `declared_content_encoding` never delivered | `src/lib/vectorProbes/l7ResourceProbes.mjs:146-151` |
| S1 | `reflect.ipp_callback_exposure.safe` | Payload marked unsupported, always `not_run`, but the verdict text claims protocol-validated exposure | `src/lib/safeNetworkProbes.mjs:372-378`, `src/lib/probeEvidenceTiers.mjs:2` |
| S2 | 72 `metadata_marker` checks | Zero I/O; `default_expected_behavior: must_block_before_origin` is never evaluable | `src/contracts/checks.mjs` |

The 72 `metadata_marker` entries are byte-identical at execution time: 139 distinct execution
signatures exist across 275 checks, and 72 checks share one. **Verified.**

### 1.2 Verdicts the probe cannot satisfy

| Severity | Check | Problem |
|---|---|---|
| S1 | `l7.wordpress_xmlrpc.readiness` | No `probe_path`; probes `/`, never `/xmlrpc.php`. WordPress answers HEAD `/xmlrpc.php` with 405 regardless of exposure. |
| S1 | `l7.expensive_endpoint.safe`, `l7.password_reset.safe` | `required_customer_setup` names a declared path but the profile has no `probe_path`; only a manual override is honoured (`src/lib/probeJobs.mjs:47-51,310`). |
| S1 | `l7.search_abuse.validation`, `l7.export_abuse.validation`, `l7.oauth_token_abuse.validation`, `l7.signup_registration_abuse.validation`, `l7.login_abuse_flow.safe`, `l7.api_quota_exhaustion.safe` | `probe_path` hardcoded `"/"`; five HEADs to the site root produce a search, export, OAuth and signup verdict. **Verified** for `search_abuse`. |
| S1 | `tls.ocsp_stapling.readiness` | `probeTlsAudit` never reads OCSP stapling (`src/lib/capabilityProbes.mjs:2551-2600`). |
| S2 | `l7.http2_rapid_reset.validation`, `l7.http2_made_you_reset.readiness`, `l7.http2_continuation.readiness` | All three run one fixed `http2_frame_probe` sequence; the class-specific behaviour is not exercised. |
| S2 | `l7.graphql_complexity.safe`, `l7.graphql_batch_abuse.validation` | One HEAD `/graphql`; neither depth nor batching is tested. |
| S2 | `reflect.legacy_device_discovery_exposure.safe` | Name claims legacy device *and game* discovery; sends only `ws_discovery_probe` on 3702. Lantronix, VxWorks/WDBRPC, TeamSpeak 3 and BitTorrent are claimed in the taxonomy with no payload. **Verified.** |
| S2 | `l3.tcp_flag_anomaly.readiness`, `l3.tcp_connection_flood.readiness`, `reflect.tcp_middlebox_exposure.safe` | `tcp_connect` with no port and no `default_port`; 0 requests unless the customer supplies a port. |

### 1.3 Duplicates

Exact duplicates — identical profile, setup, targets and verdict:

| Pair/group | Kind |
|---|---|
| `origin.direct_reachability.safe` / `origin.direct_bypass.safe` | `host_sni_bypass` |
| `waf.marker_rule.safe` / `waf.enforcement.safe` | `waf_enforcement_probe` |
| `tls.profile_exposure.safe` / `tls.full_audit.safe` | `tls_audit` |
| `l3.forbidden_tcp_port.safe` / `l3.basic_deny_rule.safe` | `tcp_connect` |
| `l7.slowloris.readiness` / `l7.low_and_slow.readiness` | `slow_header_probe` |
| `l7.http_get_flood.validation` / `l7.search_abuse.validation` / `l7.export_abuse.validation` | `rate_limit_sequence` |

Near-duplicates that differ only by gate: `origin.host_sni_bypass.safe`/`nfw.origin_lockdown.safe`,
`origin.leak_scan.safe`/`origin.cdn_bypass.readiness`/`origin.dns_hostname_bypass.readiness`,
`l3.firewall_exposure_scan.safe`/`nfw.management_port_exposure.safe`,
`l3.forbidden_udp_port.safe`/`nfw.declared_deny_udp.safe`,
`l3.ipv6_reachability.safe`/`nfw.ipv6_parity.safe`,
`reflect.redis_direct_exposure.safe`/`reflect.tcp_middlebox_exposure.safe`.

### 1.4 Executor defects

| Severity | Defect | Where |
|---|---|---|
| S1 | `ops_readiness` is absent from `PROBE_KIND_DISPATCH`; a dispatched job returns `unsupported_probe_kind`. It only runs inline from `testRuns`. | `workers/probe-worker.mjs:1293-1307` |
| S2 | `http_head` ignores `probe_profile.method` and hardcodes HEAD. | `workers/probe-worker.mjs:968` |
| S2 | `dns_resolve` ignores `dns_qtype` and `dns_transport`; no catalog check uses the kind. | `workers/probe-worker.mjs:1180-1265` |
| S2 | `http2_settings` and `http2_frame_probe` never assert `settings_assertion`; it is only echoed into metadata. | `src/lib/safeNetworkProbes.mjs:1342-1390`, `src/lib/capabilityProbes.mjs:1922,1946,1958` |
| S2 | `slow_header_probe` ignores `http_method`. | `src/lib/capabilityProbes.mjs:1632-1740` |
| S3 | `MAX_REQUESTS_BY_PROBE_KIND.outside_in_waf_scan = 16` exceeds the documented 15-request ceiling; the fallback `MAX_PROBE_PROFILE_REQUESTS = 10` silently caps every unlisted kind. | `src/contracts/checks.mjs:82,111` |

### 1.5 Governance defects

- **Readiness scoring is dead code.** `catalogCheckSupportsReadiness` / `runVerdictSupportsReadiness`
  are imported by nothing outside their own module. When evaluated, they exclude all 72
  `*.readiness` checks and allow only 24 of 275 checks to score. **Verified.**
- **The validator forbids `pending`.** `scripts/validate-resource-exhaustion-taxonomy.mjs:209-212`
  fails the build on any `pending` row, so a new vector can only be added by attaching a no-op check
  and labelling it `partial`. The registry therefore reports 154 `partial`, 91 `soc_only`, 9
  `implemented` — with 72 of the `partial` rows backed by zero I/O. **Verified.**
- **Offensive suites carry no payload corpus.** `waf.offensive_*` are `suite_id` + `max_requests`
  only (`src/contracts/wafOffensive.mjs:33-116`); `waf.offensive_sqli.soc` is one suite for eight
  distinct SQLi rows.

## Part 2 — WAF/CDN detection defects

### 2.1 Classification

| Severity | Defect | Where |
|---|---|---|
| S1 | Only `cloudfront` and `fastly` are filtered out of the WAF provider list. Every other CDN-only wafw00f plugin stays, so `waf_present` is set from a single CDN header. `Server: KeyCDN`, `x-cdn: maxcdn` and `Server: ECD` each yield `waf_present:true` with `cdn_detected:false`. | `src/lib/edgeFingerprint.mjs:1131-1132,1183` **verified** |
| S1 | `maxcdn`, `limelight`, `cdnns` and `cloudfloordns` have no curated CDN signature at all, and `Server: KeyCDN` / `Server: ECD` have no curated header signature (KeyCDN and Edgecast are only reachable by CNAME), so the CDN is lost rather than merely mislabelled. | `src/lib/edgeFingerprint.mjs:121-151,157-185` |
| S2 | `WAF_ADDRESS_RANGES` contains the whole Cloudflare and ArvanCloud space, so any Cloudflare-fronted zone — including a CDN-only, no-WAF zone — gets `waf_present:true` at `ADDRESS_RANGE_CONFIDENCE 0.7`. | `src/lib/data/edgeSignatureData.mjs` (`WAF_ADDRESS_RANGES`), `src/lib/edgeFingerprint.mjs:1183` **verified** |
| S2 | Generic-WAF detection requires a status-code change, so a vendor-specific block page returned with the baseline status is missed; and it is skipped entirely when any vendor matched, so a weak false positive suppresses it. | `src/lib/outsideInWafScanner.mjs:269-286,649-651` **verified** |
| S2 | `findEdgeProviderMatch` ignores `header_matches`, so a WAF evidenced only by a curated header cannot resolve as a provider. | `src/lib/edgeDetectionProjection.mjs:323-342` |

### 2.2 Confidence

| Severity | Defect | Where |
|---|---|---|
| S1 | `vendorConfidence` sums every matching signal, and each block-page signal adds a full `EXTRA_SIGNAL_CONFIDENCE`. A passive header plus a block-page body reaches 0.95 from one response pair, although they are not independent corroboration. | `src/lib/edgeFingerprint.mjs:584-592` **verified** |
| S1 | Vendor selection is priority order, not strength order: `best = wafVendorMatches[0]` in `WAF_VENDOR_PRIORITY` order, copied straight into `detected_vendor`. One weak signal earlier in the list beats three strong signals later. | `src/lib/edgeFingerprint.mjs:610-649`, `src/lib/outsideInWafScanner.mjs:700-733` |
| S2 | `conflicting_vendor_signals` is computed over all matches including the filtered-out `cloudfront`/`fastly`, so a conflict between two non-WAF CDN plugins still multiplies confidence by 0.65 and nulls the WAF provider. | `src/lib/edgeFingerprint.mjs:1108,1165` **verified** |
| S2 | No minimum-confidence floor before `waf_present`; any single passive corpus signal (0.45) is enough. | `src/lib/edgeFingerprint.mjs:1183` |

### 2.3 Projection and presentation

| Severity | Defect | Where |
|---|---|---|
| **S1** | A fingerprint miss plus blocked markers becomes `unprotected`. `:127` tests `wafPresent === false` before any `blockedCount`, so effectiveness is `no_waf_detected` and the percentage is nulled; `:278` then maps `not_detected` to `unprotected`. Three of three plain markers blocked with no fingerprint still reads "unprotected". | `src/lib/edgeDetectionProjection.mjs:127,156,278` **verified** |
| S2 | Legacy rows rebuild layers from raw `vendor_matches`, which includes the deliberately excluded CloudFront/Fastly, so old rows render "Detected CloudFront" as a WAF layer. | `src/lib/edgeDetectionProjection.mjs:180-186` |
| S2 | The presenter appends "No WAF was detected." while the label list already contains a WAF layer, and says "No WAF or CDN was detected" whenever cloud labels exist even if a CDN layer exists. | `src/lib/edgeDetectionPresenter.mjs:311,314-315` **verified** |
| S3 | Layer provenance is mislabelled: every `vendor_matches` entry is reported as `response_header`, including cookie-only (F5) and block-page-only (PerimeterX) matches. | `src/lib/edgeDetectionPresenter.mjs:95-96` **verified** |
| S2 | Attack-response headers are dropped when a normal response exists but has none: `normal?.headerEntries ?? attack?.headerEntries` — an empty array is not nullish. A normal 200 with no corpus headers plus an attack 403 carrying `x-blocked-by-waf` loses the AWS WAF signal. | `src/lib/edgeFingerprint.mjs:1157` **verified** |

### 2.4 Missing signals

Cheap, safe, and each one currently invisible:

| Signal | Vendor it would catch | Note |
|---|---|---|
| `incapdns.net` CNAME suffix | Imperva/Incapsula | Only `impervadns.net` exists (`edgeFingerprint.mjs:171`) |
| `x-wa-info` | F5 ASM | F5 is invisible on a normal 200 today |
| `x-px-*` headers, `_px` cookies | PerimeterX/HUMAN | Block-page content only today |
| `x-amzn-waf-action` | AWS WAF custom responses | — |
| `x-amzn-requestid` | AWS | Already in the probe allowlist, absent from the corpus |
| `x-akamai-request-id`, `x-akamai-session-info` | Akamai | — |
| `x-msedge-ref` | Azure Front Door | — |
| `x-datadome`, DataDome cookies | DataDome | No entry at all |
| `cf-mitigated` | Cloudflare | Used in marker grading, absent from the corpus |
| `Via: 1.1 varnish` | Fastly | Classic marker |
| `sucuri.net`, `llnwd.net`, `systemcdn.net`, `akamai.net`, `azurefd.us`, `trafficmanager.net`, `azurewebsites.net`, `cloudapp.azure.com` CNAMEs | Sucuri, Limelight, StackPath, Akamai, Azure | — |
| TLS certificate issuer/SAN | Any edge with a distinctive issuer | Documented at `docs/detection/13:39`, never collected (`capabilityProbes.mjs:2117`) |
| Status 429/503 | Rate-limit and edge-generated responses | Listed at `docs/detection/13:42`, no matcher uses them |

### 2.5 Missing anti-false-positive controls

1. No multi-signal requirement for curated headers — one header sets `cdn_detected: true`
   (`edgeFingerprint.mjs:1187`). This is the exact control `docs/detection/13:146` promises.
2. No DNS corroboration before a header-only CDN claim; `cdn_detected` is `true` even when
   `dnsObserved` is false.
3. No origin-echo detection: a non-CDN origin that sets `cf-cache-status` is indistinguishable from
   Cloudflare.
4. Generic cloud ASN is treated as positive `detected`; a bare EC2 box with no edge is "detected"
   (`edgeDetectionProjection.mjs:536-543`).
5. Shared/apex hostnames are treated as edge proof — `vercel.app`, `netlify.app`, `framer.app`,
   `qiniu.com`, `gcore.com`, `bunnycdn.com`, `cloudflare.com`, and especially `akamaihd.net`, which
   is a customer upload domain (`edgeFingerprint.mjs:159-185`).
6. `x-cdn` is curated only for `imperva|incapsula` while the corpus uses `x-cdn: maxcdn`.

### 2.6 Doc/code divergence

| Doc claim | Code |
|---|---|
| `13:62-68` weights: CNAME +0.25, extra headers +0.20, block page +0.25, ASN +0.10 | `CNAME_SUFFIX_CONFIDENCE 0.65`, `EXTRA_SIGNAL_CONFIDENCE 0.2`, `SINGLE_SIGNAL_CONFIDENCE 0.45`, `ADDRESS_RANGE_CONFIDENCE 0.7` |
| `13:67` conflict is `-0.20` | multiplied by 0.65 (−35%) |
| `13:68` direct origin without edge is `-0.25` | no such term exists |
| `13:70` cap confidence to 1.0 | `MAX_VENDOR_CONFIDENCE 0.95` |
| `13:39` TLS issuer/SAN is a signal | never collected |
| `13:41` JS/bot challenge/CAPTCHA labels | four challenge headers only |
| `13:30,170` A/AAAA are not stored as a DNS hint | stored as `dns_resolved_ips` |
| `13:146` requires multiple signals | one is enough |
| `13:166` corpus "ported from AstraNull WAF fingerprint plugin data" | it is wafw00f plugin data |
| `ADR-0005:63` CNAME-only Akamai/CloudFront is `waf` | contradicts its own Addendum 2 |
| `ADR-0005:107` "capped at 13 HTTP + 3 DNS" | one GET |
| `ADR-0005:32` pins cdncheck `dac12984…` | manifest records `a06260a2…` |

## Part 3 — Missing checks

Each row is a bounded observation that fits the existing ceilings (≤15 requests, ≤5000 ms) unless
stated. `NEW` = no coverage; `PARTIAL` = an existing check covers part of it.

### 3.1 WAF

| Proposed id | Status | Observation | Requests | Source |
|---|---|---|---|---|
| `waf.false_positive_corpus.safe` | NEW | 8 benign strings that look like attacks; any block is a false positive | 8 GET | [gotestwaf false-pos](https://github.com/wallarm/gotestwaf/blob/master/testcases/false-pos/texts.yml) |
| `waf.marker_location_cookie.safe` | NEW | Inert marker in a `Cookie:` value against the query/header baseline | 3 GET | [gotestwaf placeholders](https://github.com/wallarm/gotestwaf#how-it-works) |
| `waf.marker_location_soap_xml.safe` | PARTIAL | Marker inside a SOAP envelope | 3 POST | [gotestwaf owasp-api](https://github.com/wallarm/gotestwaf/tree/master/testcases/owasp-api) |
| `waf.marker_location_grpc_metadata.safe` | PARTIAL | Marker in gRPC metadata | 3 calls | same |
| `waf.paranoia_level_probe.safe` | NEW | One PL3-only and one PL4-only CRS class with PL1/PL2 controls | 4 GET | [CRS paranoia levels](https://coreruleset.org/docs/2-how-crs-works/2-2-paranoia_levels/) |
| `waf.behavioral_delta.safe` | NEW | Status/`Server`/body-hash delta between a normal and an attack-looking GET | 2 GET | [wafw00f genericdetect](https://github.com/EnableSecurity/wafw00f/blob/master/wafw00f/main.py) |

`marker_type` is currently `query` (45), `header` (4), `user_agent` (1) — no cookie. **Verified.**

### 3.2 Network firewall / L3–L4

| Proposed id | Status | Observation | Requests | Source |
|---|---|---|---|---|
| `l3.tcp_option_posture.safe` | NEW | SYN-ACK options: MSS, window scale, timestamps, SACK-permitted | 1 connect | [RFC 7323](https://www.rfc-editor.org/rfc/rfc7323.txt) |
| `l3.syn_cookie_indicator.safe` | NEW | ISN spread + option stripping across three connects (heuristic, E2) | 3 connects | [RFC 4987](https://www.rfc-editor.org/rfc/rfc4987.txt) |
| `l3.ecn_negotiation.safe` | NEW | ECN-setup SYN → ECE/CWR in SYN-ACK | 2 connects | [RFC 3168](https://www.rfc-editor.org/rfc/rfc3168.txt) |
| `l3.icmp_type_filter.safe` | NEW | Echo, timestamp, address-mask, dest-unreachable | 4 packets | [Cloudflare attack coverage](https://developers.cloudflare.com/ddos-protection/about/attack-coverage/) |
| `l3.ip_id_policy.safe` | NEW | IP ID sequence across three replies | 3 packets | [RFC 6864](https://www.rfc-editor.org/rfc/rfc6864.txt) |
| `l3.mss_clamp.safe` | NEW | Advertised MSS against path MTU | 1 connect | [RFC 8899](https://www.rfc-editor.org/rfc/rfc8899.txt) |
| `l3.ipv6_extension_header.safe` | NEW | Hop-by-hop header answered or dropped | 2 packets | Cloudflare attack coverage |
| `l3.icmp_unreachable_rate.safe` | PARTIAL | Closed UDP port → ICMP unreachable returned or silent | 3 packets | [RFC 1122 §3.2.2](https://www.rfc-editor.org/rfc/rfc1122.txt) |
| `l3.rpki_roa.safe` | NEW | Public RPKI validator for the target prefix | 1 third-party call | [RFC 6480](https://www.rfc-editor.org/rfc/rfc6480.txt) |
| `l3.anycast_dispersion.safe` | PARTIAL | Same probe from ≥3 worker regions; RTT/edge identity compared | 3 requests | Cloudflare attack coverage |

`port_scan_bounded` is a plain connect scan (`src/lib/capabilityProbes.mjs:1124-1240`); there is no
stateless-ACL probe (bare ACK/FIN/NULL/XMAS), so a stateful firewall and a stateless ACL are
indistinguishable. **Verified.**

### 3.3 DNS

| Proposed id | Status | Observation | Requests | Source |
|---|---|---|---|---|
| `dns.cookie_support.safe` | NEW | COOKIE option echoed with a server cookie | 2 queries | [RFC 7873](https://www.rfc-editor.org/rfc/rfc7873.txt) |
| `dns.wildcard_detection.safe` | NEW | Two random labels under the zone | 2 queries | [nuclei wildcard-dns-detect](https://github.com/projectdiscovery/nuclei-templates/blob/main/dns/wildcard-dns-detect.yaml) |
| `dns.negative_ttl.safe` | NEW | SOA minimum on an NXDOMAIN | 1 query | [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308.txt) |
| `dns.caa_posture.safe` | NEW | CAA RRset presence and issuer tags | 1 query | [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659.txt) |
| `dns.spf_lookup_limit.safe` | NEW | SPF mechanism count against the 10-lookup limit | 1 TXT query | [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208.txt) |
| `dns.dmarc_posture.safe` | NEW | DMARC record and `p=` policy | 1 TXT query | [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489.txt) |
| `dns.nsec3_optout.safe` | PARTIAL | NSEC3PARAM presence and opt-out flag | 1 query | [RFC 5155](https://www.rfc-editor.org/rfc/rfc5155.txt) |
| `dns.lame_delegation.safe` | NEW | Each declared NS queried directly for the apex SOA | ≤4 queries | [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.txt) |
| `dns.private_ip_disclosure.safe` | NEW | A/AAAA resolving to RFC1918 or loopback | 2 queries | [nuclei dns-internal-ip-disclosure](https://github.com/projectdiscovery/nuclei-templates/blob/main/dns/dns-internal-ip-disclosure.yaml) |
| `dns.dnssec_algorithm_posture.safe` | NEW | DNSKEY algorithm/digest set against the deprecated list | 1 query | [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035.txt) |
| `dns.edns_buffer_size.safe` | PARTIAL | Advertised EDNS0 payload size and TC-bit behaviour | 2 queries | [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891.txt) |
| `dns.cname_chain_depth.safe` | PARTIAL | CNAME hop count to resolution | 1 query | [nuclei dns-waf-detect](https://github.com/projectdiscovery/nuclei-templates/blob/main/dns/dns-waf-detect.yaml) |

### 3.4 L7

| Proposed id | Status | Observation | Requests | Source |
|---|---|---|---|---|
| `l7.security_header_posture.safe` | NEW | HSTS, CSP, COOP/COEP, Permissions-Policy, Referrer-Policy, XCTO | 1 GET | [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797.txt) |
| `l7.cacheability_posture.safe` | NEW | `Cache-Control`, `Vary`, `Set-Cookie`, `Age`, cache-status on a static asset | 2 GET | [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.txt) |
| `l7.edge_error_page_posture.safe` | NEW | 429/503 body hash against the origin 200 body | 2 GET | [Cloudflare rule categories](https://developers.cloudflare.com/ddos-protection/managed-rulesets/http/rule-categories/) |
| `l7.retry_after_quality.safe` | PARTIAL | `Retry-After` present and sane on a 429 | 2 GET | [RFC 9110 §10.2.3](https://www.rfc-editor.org/rfc/rfc9110.txt) |
| `l7.request_line_limit.safe` | NEW | URL lengths 2K/4K/8K on a declared path | 3 GET | [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.txt) |
| `l7.parameter_count_limit.safe` | NEW | 1 / 100 / 500 query parameters | 3 GET | [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.txt) |
| `l7.cookie_size_limit.safe` | NEW | 1 / 4K / 8K `Cookie:` header | 3 GET | [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265.txt) |
| `l7.expect_100_continue.safe` | NEW | `Expect: 100-continue` honoured or ignored | 2 requests | [RFC 9110 §10.1.1](https://www.rfc-editor.org/rfc/rfc9110.txt) |
| `l7.absolute_uri_form.safe` | NEW | Absolute-URI request target | 1 GET | [RFC 9112 §3.2.2](https://www.rfc-editor.org/rfc/rfc9112.txt) |
| `l7.connect_method.safe` | NEW | `CONNECT host:443` | 1 request | [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.txt) |
| `l7.http_1_0_no_host.safe` | NEW | HTTP/1.0 without `Host` | 1 GET | [RFC 9112 §3.2](https://www.rfc-editor.org/rfc/rfc9112.txt) |
| `l7.host_header_variants.safe` | NEW | Trailing dot, uppercase, `host:port` | 3 GET | [RFC 9110 §7.2](https://www.rfc-editor.org/rfc/rfc9110.txt) |
| `l7.well_known_posture.safe` | NEW | `/.well-known/security.txt`, `/.well-known/change-password` | 2 GET | [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615.txt) |
| `l7.http2_goaway.safe` | NEW | GOAWAY after one stream; clean close | 1 connection | [RFC 9113 §6.8](https://www.rfc-editor.org/rfc/rfc9113.txt) |
| `l7.grpc_max_message_size.safe` | NEW | `grpc-max-message-size` from SETTINGS | 1 connection | [gRPC spec](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md) |
| `l7.websocket_permessage_deflate.safe` | NEW | `Sec-WebSocket-Extensions` accepted in the 101 | 1 upgrade | [RFC 7692](https://www.rfc-editor.org/rfc/rfc7692.txt) |

### 3.5 TLS and protocol

| Proposed id | Status | Observation | Requests | Source |
|---|---|---|---|---|
| `tls.hello_retry_request.safe` | NEW | Non-preferred key share → HRR returned or not | 1 handshake | [RFC 8446 §4.1.4](https://www.rfc-editor.org/rfc/rfc8446.txt) |
| `tls.certificate_chain_size.safe` | NEW | Chain length and byte size | 1 handshake | [RFC 8446 §4.4](https://www.rfc-editor.org/rfc/rfc8446.txt) |
| `tls.session_resumption.safe` | NEW | Ticket replayed; resumed or full handshake | 2 handshakes | [RFC 8446 §2.2](https://www.rfc-editor.org/rfc/rfc8446.txt) |
| `tls.alpn_posture.safe` | NEW | Offered `h2`/`http/1.1`; selected protocol | 1 handshake | [RFC 7301](https://www.rfc-editor.org/rfc/rfc7301.txt) |
| `tls.record_size_limit.safe` | NEW | `record_size_limit` echoed | 1 handshake | [RFC 8449](https://www.rfc-editor.org/rfc/rfc8449.txt) |
| `tls.must_staple.safe` | PARTIAL | `status_request` and must-staple extension | 1 handshake | [RFC 7633](https://www.rfc-editor.org/rfc/rfc7633.txt) |
| `tls.sct_embedded.safe` | NEW | SCT list in the certificate | 1 handshake | [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962.txt) |
| `tls.cipher_preference_order.safe` | NEW | Two handshakes with reversed cipher order | 2 handshakes | [RFC 8446 App. A](https://www.rfc-editor.org/rfc/rfc8446.txt) |
| `tls.fallback_scsv.safe` | NEW | TLS 1.2 max with `TLS_FALLBACK_SCSV` | 1 handshake | [RFC 7507](https://www.rfc-editor.org/rfc/rfc7507.txt) |
| `tls.compression.safe` | NEW | DEFLATE offered; selected or not | 1 handshake | [RFC 3749](https://www.rfc-editor.org/rfc/rfc3749.txt) |
| `protocol.quic_stateless_reset.safe` | PARTIAL | Short-header packet with a bad DCID | 1 packet | [RFC 9000 §10.3](https://www.rfc-editor.org/rfc/rfc9000.txt) |
| `protocol.http3_alt_svc_downgrade.safe` | NEW | `Alt-Svc` advertised but h3 unreachable | 2 requests | [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.txt) |

### 3.6 Operations

| Proposed id | Status | Observation | Requests | Source |
|---|---|---|---|---|
| `ops.drift_baseline.safe` | PARTIAL | Fixed marker set diffed against the stored baseline | reuses runs | [doc 14](14-waf-effectiveness-drift.md) |
| `ops.provider_test_rule.safe` | NEW | The provider's documented test path/rule fires | 1 request | [Cloudflare rule categories](https://developers.cloudflare.com/ddos-protection/managed-rulesets/http/rule-categories/) |
| `ops.provider_attack_coverage.safe` | NEW | Detected provider's published vector list against declared vectors | 0 requests | [Cloudflare attack coverage](https://developers.cloudflare.com/ddos-protection/about/attack-coverage/) |
| `ops.alert_latency.safe` | PARTIAL | Probe timestamp to alert webhook receipt | 1 probe + webhook | [Cloudflare alerts](https://developers.cloudflare.com/ddos-protection/reference/alerts/) |
| `ops.status_page_feed.safe` | NEW | Provider status feed reachable and current | 1 fetch | [Azure DDoS simulation](https://learn.microsoft.com/en-us/azure/ddos-protection/test-through-simulations) |
| `ops.capacity_headroom.safe` | PARTIAL | Declared headroom against last measured peak | 0 requests | [AWS Shield readiness review](https://docs.aws.amazon.com/waf/latest/developerguide/shield-advanced-readiness-review.html) |
| `ops.runbook_link_validity.safe` | PARTIAL | HTTP status of every URL in the runbook artifact | ≤10 HEAD | Azure DDoS simulation |
| `ops.change_freeze_window.safe` | NEW | Declared freeze window against current time | 0 requests | [GCP Adaptive Protection](https://cloud.google.com/armor/docs/adaptive-protection-overview) |

### 3.7 Genuinely impossible outside-in — keep monitor-only (E5)

`l3.syn_cookie_under_load`, `l3.connection_table_size`, `l3.bgp_anycast_state`, `l3.l2_adjacency`,
`l7.backend_capacity`, `l7.autoscaling_trigger`, `ops.scrubbing_activation`, `ops.real_capacity_gbps`,
`waf.rule_id_and_count`, `l7.cache_hit_ratio`, `l7.real_rps_threshold`, `tls.ticket_key_rotation`.

## Part 4 — Plan

Priority order. P0 rows change an answer a customer already sees; P1 closes a claimed-but-absent
capability; P2 is breadth.

| ID | Pri | Scope | Acceptance |
|---|---|---|---|
| DET-027 | P0 | Make hollow checks honest | `checkRequiresAdditionalInput` returns a reason for `mechanism_supported:false` and `setup_required:true`; the portal marks them "needs setup" instead of offering a run; `GET /v1/checks` exposes the flag; tests per group. |
| DET-028 | P0 | Fix the fingerprint-miss-plus-blocked-markers projection | Blocked markers with no fingerprint yield `present_but_unvalidated` (not `unprotected`); effectiveness keeps its counts and percentage; presenter copy matches; regression test with 3/3 blocked and `waf_present:false`. |
| DET-029 | P0 | Stop reporting CDN-only vendors as WAF | Curated CDN signatures for `maxcdn`, `limelight`, `cdnns`, `cloudfloordns` and header signatures for `keycdn`/`edgecast`; a CDN-only match sets `cdn_detected` and leaves `waf_present` false; table test per vendor. |
| DET-030 | P0 | Multi-signal and corroboration gate | A header-only CDN claim needs a second signal or an observed DNS chain; origin-echo guard; minimum confidence floor; shared-hostname and generic-cloud-ASN downgrade; tests for each false-positive case in §2.5. |
| DET-031 | P0 | Confidence and selection correctness | Confidence counts the matched path, not every signal; block-page signals are not independent corroboration; conflict is an additive penalty; direct-origin term added; vendor chosen by strength; conflict computed over WAF matches only; tests. |
| DET-032 | P0 | Projection and presenter correctness | Legacy layers exclude CloudFront/Fastly; presenter never says "No WAF" beside a WAF label; provenance is the real signal source; `normal`/`attack` header merge keeps attack headers when the normal set is empty; `findEdgeProviderMatch` honours `header_matches`; tests. |
| DET-033 | P1 | Deliver the 28 undelivered evasion transforms | Each transform either sends its variant or is explicitly E2/declaration-only with matching copy; no check declares requests it does not send. |
| DET-034 | P1 | Deliver `waf_inspection_limit_probe` and `declared_content_encoding` | Both send their declared requests against an approved sink; `not_run` only when no sink is declared. |
| DET-035 | P1 | Deliver the IPP reflector payload | `ipp_get_printer_attributes` executes and has a strict identity validator. |
| DET-036 | P1 | Path-dependent checks use their declared path | `wordpress_xmlrpc`, `password_reset`, `expensive_endpoint`, `search_abuse`, `export_abuse`, `oauth_token_abuse`, `signup_registration_abuse`, `login_abuse_flow`, `api_quota_exhaustion` carry `probe_path` from the declaration; a missing declaration is `required_input_missing`, not a silent `/`. |
| DET-037 | P1 | Executor gaps | `ops_readiness` in `PROBE_KIND_DISPATCH`; `http_head` honours `method`; `dns_resolve` honours qtype/transport; `http2_settings`/`http2_frame_probe` assert `settings_assertion`; `slow_header_probe` honours `http_method`; `outside_in_waf_scan` cap reconciled with the 15 ceiling. |
| DET-038 | P1 | Readiness scoring | `catalogCheckSupportsReadiness` is either wired into the assessment or removed; if wired, the 72 `*.readiness` ids are re-tiered so the name matches the behaviour. |
| DET-039 | P1 | Taxonomy validator accepts `pending` | A vector can be added with no check; the validator reports pending counts without failing; the registry is re-audited so no-op checks stop masking pending rows. |
| DET-040 | P1 | De-duplicate the catalog | Each exact-duplicate pair is merged or differentiated; near-duplicates keep one id per distinct gate with a stated difference. |
| DET-041 | P1 | Missing detection signals | Every row in §2.4 added to the corpus or curated table with a regression fixture; TLS issuer/SAN collected in the fingerprint job. |
| DET-042 | P1 | WAF false-positive and marker-location checks | `waf.false_positive_corpus.safe`, `waf.marker_location_cookie.safe`, `waf.marker_location_soap_xml.safe`, `waf.marker_location_grpc_metadata.safe`, `waf.paranoia_level_probe.safe`, `waf.behavioral_delta.safe`. |
| DET-043 | P1 | Network-firewall fingerprint checks | Every `l3.*` row in §3.2; `port_scan_bounded` gains a bare-ACK mode so stateless ACLs are distinguishable. |
| DET-044 | P2 | Reflection fidelity | Split `reflect.legacy_device_discovery_exposure.safe` into Lantronix, VxWorks/WDBRPC, TeamSpeak 3 and BitTorrent DHT; add BACnet, Steam, Plex, Apple Remote Desktop, Ubiquiti, Sentinel, Digiman and Kad. |
| DET-045 | P2 | DNS breadth | Every `dns.*` row in §3.3. |
| DET-046 | P2 | L7, TLS, protocol and ops breadth | Every remaining `l7.*`, `tls.*`, `protocol.*` and `ops.*` row in §3.4–3.6, plus the monitor-only annotations in §3.7. |
| DET-047 | P2 | Reconcile `docs/detection/13` and ADR-0005 with the code | Every row in §2.6 corrected in one pass; the doc stops promising TLS and multi-signal before DET-030/DET-041 land. |

## Part 5 — Done criteria

- No check declares a request count it does not send.
- No check's id, name or verdict names an observation its probe cannot make.
- A CDN-only edge is never reported as a WAF, and a fingerprint miss never overrides blocked markers.
- One spoofable header is never sufficient for a CDN or WAF claim.
- Every new check carries `stop_conditions`, `evidence_required`, `required_customer_setup`, an
  evidence tier and a missing-control entry, and stays inside 15 requests / 5000 ms.
- `npm run vector:taxonomy:validate`, `npm run vector:safety:evidence` and the full unit suite pass.
