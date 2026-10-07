# Protection validation: live staging evidence, 2026-10-06 (PV-09)

Status: bounded live run against one owner-authorized public target. It covers some of the plan's staging scenarios and found product defects that block others (see "Product defects found"). It is **not** a release or provider-certification claim. Every PV row stays `[~]`.

Related: [plan](../implementation/provider-neutral-protection-validation-plan.md) (staging gate, step 10), [rollout notes](protection-validation-rollout.md), [detection/23](../detection/23-application-entry-path-validation.md), [ADR-0016](../adr/0016-demo-tenant-ownership-auto-verify.md), [ADR-0017](../adr/0017-application-entry-path-validation.md).

## Authorization and scope

| Item | Value |
|---|---|
| Target | `aistripped.com`, authorized by the product owner for this run. No other host was contacted. |
| Resolved addresses | A `172.67.216.247`, `104.21.61.235`; AAAA `2606:4700:3036::6815:3deb`, `2606:4700:3032::ac43:d8f7`. All are Cloudflare anycast edges, so **no distinct origin exists**. |
| Window | 2026-10-05 22:47Z to 23:36Z (2026-10-06 IST). |
| Execution path | Dev API (`src/index.mjs`, dev-json, `ASTRANULL_PROBE_MODE=signed-worker`, port 3501, scratch `ASTRANULL_DEV_DATA_DIR`) and the reference worker (`workers/probe-worker.mjs`, worker id `pv09-staging-worker-1`, HMAC secret generated per session and never committed). |
| Feature gate | `ASTRANULL_PROTECTION_VALIDATION_ENABLED_TENANTS={"ten_demo":true}`. |
| Ownership | Sanctioned demo path: `ASTRANULL_DEMO_AUTO_VERIFY_TENANTS=ten_demo` (ADR-0016). Every target was recorded `user_confirmed` / `manual_override` / `{"method":"demo_auto_verify"}` and audited as `target.ownership_demo_auto_verified`. No store or code edit was made to fake verification. This is a demo proof, not a DNS/HTTP ownership proof. |
| Safety | Only catalog safe checks, existing per-check budgets, per-group concurrency of 1, no SOC/high-scale workflow, and no hand-rolled requests beyond one DNS lookup and one `HEAD /` to confirm the site was up. Targets were not split across groups to get around the concurrency limit. |
| Request total | 38 attested probe requests across 16 runs, plus 1 unattested TCP connect (see defect D4) and 1 manual `HEAD`, giving about **40 target-bound requests** against a 300 cap. The worker also made 20 destination-resolver DNS lookups through the local resolver. |

## Declarations

Target group `tg_277918e3c185b3dd` ("PV-09 staging aistripped.com").

| Target id | Kind | Value | Role |
|---|---|---|---|
| `tgt_778b633805f202bc` | fqdn | `aistripped.com` | Anchor, primary route, firewall destination |
| `tgt_0fe7dd4fc2125426` | url | `https://aistripped.com/` | Standalone WAF scan |
| `tgt_b642a40c29535b4f` | ip | `2606:4700:3036::6815:3deb` | IPv6 alternate path |
| `tgt_a509b81dfe2a484b` | ip | `104.21.61.235` | **Negative control**: CDN edge declared as "origin" to exercise the CDN-edge guard |
| `tgt_c3e029185960e470`, `tgt_7c469d51ad6cd7b3`, `tgt_c9fa640663b52e3d` | tcp | `aistripped.com:443`, `:22`, `:3389` | Declared, but no forbidden-port check accepts `tcp` targets (defect D5) |

- **Origin binding:** `obind_e9bf4233d38fe485`, `aistripped.com` → `104.21.61.235`. The server derived host and SNI `aistripped.com` and left port and path `null`.
- **Entry paths on the anchor:**

| Entry path | Relation | Expected behavior | Required layers |
|---|---|---|---|
| `ep_8d5bd2120f581a33` | `primary_route` | `must_be_protected_by_layers` | `waf`, `cdn_edge` |
| `ep_a882ba8c0298c86d` | `alternate_hostname` (IPv6) | `must_be_protected_by_layers` | `waf`, `cdn_edge` |
| `ep_8ebccf3e8bd9f77a` | `origin` (bound) | `must_not_be_reachable` | `network_firewall` |

- **Login/API paths:** none declared. The bounded homepage previews captured by the signed scan (`run_0849db4d44192c3e`) contained no login or API link. Under the no-crawl rule, `waf.entry_path_login_marker.safe` and `waf.entry_path_api_marker.safe` had no eligible path.

## Runs

`P` = attested probe requests and `R` = destination-resolver lookups, both from the signed safety attestation. Times are UTC created/completed. Every run used source perspective `astranull-signed-public-worker`.

| Run | Check @ version | Target | Created → completed | Probe result | P / R | Verdict |
|---|---|---|---|---|---|---|
| `run_0849db4d44192c3e` | `waf.fingerprint.safe@1.2.0` | url | 22:50:55 → 22:52:55 | connected | 13 / 2 | `edge_exposed` |
| `run_4f11fd9c2ea6818c` | `origin.direct_reachability.safe@1.2.0` (bound) | 104.21.61.235 | 22:53:51 → 22:55:51 | error (CDN edge answered 200) | 1 / 0 | `inconclusive` |
| `run_19064a3b45d7f789` | `l3.forbidden_tcp_port.safe@1.0.0` | fqdn | 22:56:46 → 22:57:46 | error `unsupported_target`, `request_not_sent` | 0 / 2 | `inconclusive` |
| `run_7e5d395d0010b018` | `l7.waf_marker_rule.safe@1.1.0` (comparison A) | fqdn | 22:59:16 → 23:04:44 | connected (HEAD 200) | 1 / 2 | `edge_exposed` |
| `run_8cf9b73074a96e49` | `origin.direct_reachability.safe@1.2.0` (comparison A, bound) | 104.21.61.235 | 23:04:44 → 23:06:46 | error (CDN edge) | 1 / 0 | `inconclusive` |
| `run_c2365c3b67cdc743` | `waf.fingerprint.safe@1.2.0` (comparison B) | fqdn | 23:07:11 → 23:09:14 | connected | 13 / 2 | `edge_exposed` |
| `run_1ac03004f3d238bd` | `origin.direct_reachability.safe@1.2.0` (comparison B, bound) | 104.21.61.235 | 23:09:14 → 23:11:17 | error (CDN edge) | 1 / 0 | `inconclusive` |
| `run_991c9f04efdc1090` | `waf.fingerprint.safe@1.2.0` (comparison B) | IPv6 | 23:11:17 → cancelled 23:17:47 | worker crashed, no result (D1) | 0 / 0 | none |
| `run_6bbd7dc731c062f8` | `l3.firewall_exposure_scan.safe@1.0.0`, ports 443/22/3389 | fqdn | 23:18:41 → 23:20:11 | timeout `probe_job_deadline_exceeded` | 2 / 2 | `inconclusive` |
| `run_02dc265f38bf03a1` | `l3.firewall_exposure_scan.safe@1.0.0`, port 443 | fqdn | 23:20:41 → 23:22:11 | connected | 1 / 2 | `edge_exposed` |
| `run_2fe996ed1975808e` | `l3.firewall_exposure_scan.safe@1.0.0`, port 22 | fqdn | 23:22:11 → cancelled 23:26:43 | result rejected 422 (D4) | 1 unattested | none |
| `run_4ec5d9f470ee7713` | `tls.profile_exposure.safe@1.0.0` (baseline) | fqdn | 23:26:54 → 23:28:24 | TLSv1.3 handshake completed (stored as `blocked`) | 1 / 2 | `edge_protected` (D7) |
| `run_cdde9afc469dee08` | `reflect.dtls_sip_rdp_tftp_exposure.safe@1.0.0` (baseline, UDP/69) | fqdn | 23:28:24 → 23:29:25 | timeout, no UDP reply | 1 / 2 | `inconclusive` |
| `run_9eb1f445c6efd1e0` | `tls.profile_exposure.safe@1.0.0` (post) | fqdn | 23:31:02 → 23:32:32 | TLSv1.3 handshake completed | 1 / 2 | `edge_protected` |
| `run_af8903fd9a578019` | `reflect.dtls_sip_rdp_tftp_exposure.safe@1.0.0` (post, UDP/69) | fqdn | 23:32:32 → 23:33:32 | timeout, no UDP reply | 1 / 2 | `inconclusive` |
| `run_a783b2a10b69aa7b` | `l3.firewall_exposure_scan.safe@1.0.0`, port 443 | IPv6 | 23:33:50 → 23:35:21 | connected in 119 ms | 1 / 0 | `edge_exposed` |

## Results

### WAF outside-in scan (`run_0849db4d44192c3e`)

- **Baseline:** `GET /` returned 200.
- **Markers:** all 9 GET markers returned 200 with no block signature: combined, path traversal, 4 SQLi variants, 2 XSS variants, and no-User-Agent. Both POST confusion probes returned 405.
- **Edge detection:**
  - Cloudflare CDN and WAF detected from response header, fingerprint and address range (confidence 0.8).
  - Effectiveness: 8 tested, 0 blocked, 8 passed, 2 inconclusive, giving status `inconclusive` (defect D8).
  - Protection: `inconclusive`, `origin_lockdown_confirmed: false`.
- This matches the research observation that Cloudflare on this zone does not enforce these benign markers. Status codes alone were never treated as denial.

### CDN-edge guard (negative control)

All three bound `origin.direct_reachability.safe` runs reached the Cloudflare anycast IP and received an answer. Each was classified as "A CDN or WAF edge answered the direct-origin request, so it is not an origin observation", with verdict `inconclusive`, no origin-lockdown credit and no bypass claim. The origin read model reports `not_tested` / `no_bound_finalized_evidence`.

### Entry-path comparisons

| Comparison | Scenario | Evaluation | Primary | IPv6 alternate | Origin (CDN edge) | Summary |
|---|---|---|---|---|---|---|
| `epc_fd09b97dde98c9a5` | `marker` | `pvc_db13b99971e33182` (23:06:46Z) | `inconclusive` (`primary_baseline_not_healthy`): marker HEAD 200, `not_enforced` | `skipped` (`target_kind_not_supported`): partial plan | `inconclusive` (`not_applicable`) | 3 total, 0 evaluated, `accepted: false` |
| `epc_eba0cdd44b64669d` | `waf.fingerprint.safe` | `pvc_9c3c171433223358` (23:17:47Z) | `inconclusive` (`blocked_primary_baseline_missing`, `stacked_edges_observed`): healthy baseline, markers not enforced | `skipped` (`run_cancelled`) after the worker crash | `inconclusive` (`not_applicable`) | 3 total, 0 evaluated, `accepted: false` |

Both comparisons were `comparable: true, stale: false`. The following control-path behavior was confirmed live:
- A plan request is passive.
- The same `Idempotency-Key` returns `replayed: true` with the original comparison.
- A wrong digest returns `409 reviewed_plan_mismatch` and starts nothing.
- The run-terminal hook starts the next pending path as soon as the previous run is finalized.

### Firewall change acceptance (no real change)

- **Change:** `PV09-NOCHANGE-20261006`, destination `tgt_778b633805f202bc`, classifier `firewall-acceptance-v2`.
- **Expectations:**

| Expectation | Rule |
|---|---|
| `fwx_171155f1c368f6bb` | TCP 443 allow |
| `fwx_0f3fb85d40958745` | TCP 22 deny |
| `fwx_a78b01300884cfbe` | TCP 3389 deny |
| `fwx_8023020a4afeb894` | service https/443 allow |
| `fwx_4c3a64ac87349d5a` | UDP 69 deny |

- **Baseline** `fwb_b5cfa1fa65fc0c0a`, captured 23:30:55Z, digest `e0932227…15bc1`, from `run_4ec5d9f470ee7713` and `run_cdde9afc469dee08`:
  - TCP 443 and https/443: `service_response_observed` (E3, TLS 1.3 handshake).
  - UDP 69: `udp_silence`.
  - 22 and 3389 could not be baselined: `invalid_comparison_baseline`, "No finalized signed evidence". See D4, D5 and D6.
- **Rejected captures** (gates working):
  - including a cancelled run: `409 evidence_not_finalized`;
  - including a run with no endpoint evidence: `invalid_comparison_baseline`.
- **Full comparison** `fwc_723dd3e68c1b52f3`, post runs `run_9eb1f445c6efd1e0` and `run_af8903fd9a578019`:

| Expectation | Status | Detail |
|---|---|---|
| TCP 443 allow | `matched` | `expectation_met: true` |
| https/443 allow | `matched` | `expectation_met: true` |
| UDP 69 deny | `inconclusive` | `udp_silence_ambiguous`, `observation_unverified` |
| TCP 22 deny | `not_tested` | `not_in_baseline` |
| TCP 3389 deny | `not_tested` | `not_in_baseline` |

  Overall: `accepted: false`, `readiness_effect: none`. The statement keeps rule-table, NAT and capacity equivalence unestablished. An identical request replayed the stored record.
- **Partial comparison** `fwc_1319427b4ff5e1ab`, TLS post run only: 2 matched, 3 not tested. The UDP item is `not_tested` with an empty `reasons` list (minor; see D11).

### Report, matrix and findings

- **Matrix** (`GET /v1/targets/tgt_778b633805f202bc/protection-validation`):
  - 3 paths: 2 inconclusive, 1 skipped.
  - Vendor `detected` on the primary path never set `observed_enforcement`, which stays `inconclusive`.
  - The `ddos` layer carries `not_capacity_assurance`.
  - The banned wording ("DDoS protected", "all controls bypassed") does not appear.
- **Report** (`GET /v1/reports/protection-validation`, JSON and CSV): `passive: true`, `executes_checks: false`, `sends_notifications: false`.
  - 11 conclusions; `unknowns.ignored_for_findings: 12`, `creates_findings: false`, `counts_as_validated: false`.
  - Firewall unit: 2 accepted, 3 not tested.
  - The CSV `ignored_for_findings` column is present.
- **Findings:**
  - Zero protection-validation findings. Every result was inconclusive, skipped, not tested or matched, which is consistent with the rule that results with missing evidence are ignored.
  - Five ordinary verdict findings (`edge_exposed`, medium), from the WAF scans, the marker run and the two 443-only port scans. The latter two are false positives; see D9.

## Staging scenario coverage

| Plan scenario | Covered | Evidence or reason |
|---|---|---|
| Correct allow | **Yes** | TCP 443 and https/443 `matched`, `expectation_met: true` (`fwc_723dd3e68c1b52f3`). |
| Explicit deny | **No** | Cloudflare edges drop 22/3389 silently. No control-specific denial (ICMP 3/13 or refusal after a change) is observable, and no probe can currently record filtered ports (D4, D5, D6). Needs an owned appliance that rejects. |
| Alternate path | **Partial** | The alternate path and the CDN-edge "origin" ran end to end. Outcomes stayed inconclusive because the primary does not enforce markers, so no enforcing baseline exists. Needs a target whose primary path enforces. |
| IPv6 | **Partial** | One IPv6 TCP connect to `[2606:4700:3036::6815:3deb]:443` succeeded (`run_a783b2a10b69aa7b`). The IPv6 WAF comparison leg crashed the worker (D1); `l3.ipv6_reachability.safe` cannot take a port (D5). |
| Application identity | **No** | No nonce-bound canary on the site (plan open question 2). |
| Timeout | **Yes** | UDP/69 silence classified `inconclusive`. The multi-port scan deadline produced `inconclusive` with no protection claim. |
| UDP ambiguity | **Yes** | UDP 69 deny: `udp_silence` before and after, giving `inconclusive` (`udp_silence_ambiguous`). |
| Missing baseline | **Yes** | TCP 22/3389 expectations are active but not in the baseline, so `not_tested` (`not_in_baseline`). |
| Partial plan | **Yes** | The IPv6 path was ineligible for the `marker` scenario and recorded as `skipped` (`target_kind_not_supported`); the partial firewall comparison listed the missing items as `not_tested`. |
| Pre/post regression | **No** (by design) | There was no real change, so `matched` and `inconclusive` were the expected results. A regression needs an owned endpoint whose rule actually changes. |
| Login/API entry paths | **No** | No login or API link in the bounded homepage preview; not declared under the no-crawl rule. |
| Cloud-edge / appliance / custom response classes | **Cloud edge only** | Cloudflare only. No appliance, reverse proxy or custom-response target was available. |

## Product defects found (not fixed here)

| # | Severity | Defect | Reproduction |
|---|---|---|---|
| D1 | High | `outside_in_waf_scan` builds `https://<ipv6>/` without brackets (`baseUrlForHost`, `src/lib/capabilityProbes.mjs`). `new URL` throws `ERR_INVALID_URL`, the exception escapes the job handler, and **the whole worker process exits** (exit 1). The run stays `running` until it is cancelled. | Live: `run_991c9f04efdc1090`; worker log "Invalid URL". Offline: `probeOutsideInWafScan({ target: { kind: 'ip', value: '2001:db8::1' }, … })` throws before any request. |
| D2 | High (destination integrity) | `parseTcpEndpoint` (`workers/probe-worker.mjs`) and `parseNetworkEndpoint` (`src/lib/safeNetworkProbes.mjs`) split an unbracketed IPv6 literal at its last colon. A declared IP target `2606:4700:4700::1:80` is dialled as host `2606:4700:4700::1`, port 80, which is a different, undeclared address. | Offline, with a stubbed `connectFn`: `probeTcpConnect({ target: { kind: 'ip', value: '2606:4700:4700::1:80' } })` connects to `{ host: '2606:4700:4700::1', port: 80 }`. |
| D3 | High | The worker's `sanitizeProbeMetadata` allowlist (`METADATA_ALLOWED_ARRAY_PATHS`) drops `open_ports`, `filtered_ports` and `closed_ports`. Signed `port_scan_bounded` results reach the server with only `exposure_count`, so the PV-05 firewall classifier never sees port evidence (`endpoint_not_sampled`). Unit tests pass because their fixtures bypass the worker sanitizer. | `sanitizeProbeMetadata({ open_ports: [443], filtered_ports: [22], closed_ports: [3389] })` returns `{}`. Live: stored metadata of `run_02dc265f38bf03a1`. |
| D4 | High | Result validation allows the scheduler tolerance only when `external_result === 'timeout'`. An all-filtered `port_scan_bounded` returns `blocked` after using its full 3000 ms per-port timeout (3002 ms observed) and is rejected with `422 safety_attestation_exceeded`. The worker then **exits the process**, the run is stuck, and the SYN that was sent is never attested. | Live: `run_2fe996ed1975808e`. Offline: `validateProbeResultBody` with that job's constraints rejects `blocked` at 3002 ms but accepts `timeout` at 3002 ms and `blocked` at 2990 ms. |
| D5 | High | `l3.forbidden_tcp_port.safe`, `l3.forbidden_udp_port.safe` and `l3.ipv6_reachability.safe` support only `ip`/`fqdn`, but their executors need `host:port` (only the `tcp` kind carries a port), and the run start rejects `tcp` targets for them. They can never send a packet in signed-worker mode. | Live: `run_19064a3b45d7f789`, `request_not_sent`, `unsupported_target`, 0 probe requests. |
| D6 | Medium | `l3.firewall_exposure_scan.safe` signs a whole-job `timeout_ms` of 3000, equal to the per-port connect timeout, so one filtered port ends the scan with `probe_job_deadline_exceeded`. Combined with D3 this loses even ports already found open. The default 15-port list cannot finish against a host that drops traffic. | Live: `run_6bbd7dc731c062f8` (443 connected in about 117 ms, 22 timed out, 3389 never attempted, no port lists stored). |
| D7 | Medium | `tls.profile_exposure.safe` stores a successful TLS 1.3 handshake as `external_result: "blocked"`, and the verdict reads `edge_protected` with "External probe was blocked at the edge; the declared path did not respond as reachable". The explanation contradicts the evidence. | Live: `run_4ec5d9f470ee7713`, `run_9eb1f445c6efd1e0`. |
| D8 | Medium | `assessWafEffectiveness` (`src/lib/edgeDetectionProjection.mjs`) returns `inconclusive` whenever any marker row is inconclusive. Two 405 POST rows void 8 definitive passes, and the summary says "did not produce enough usable marker evidence". The run verdict is `edge_exposed`. Inconclusive rows should be excluded, not allowed to override definitive ones. | Live: target `tgt_0fe7dd4fc2125426` edge detection after `run_0849db4d44192c3e`. |
| D9 | Medium | `port_scan_bounded` maps any open port to `edge_exposed` and an ordinary medium finding, including a customer-selected 443 that a firewall expectation declares `allow`. The executor's `risky_open` list is not used for the verdict. | Live: findings `fnd_106b94a0bceceda1`, `fnd_06e119ac15708b4c`. |
| D10 | Medium | In dev-json signed-worker mode, nothing finalizes a `collecting` run after its observation window. The 30-second comparison tick advances comparisons only, so a comparison stalls until someone reads the run detail or calls `POST /v1/test-runs/:id/finalize`. | Live: `run_7e5d395d0010b018` was still `collecting` 3.5 minutes past its 23:00:46Z deadline; the comparison advanced only after an explicit finalize. |
| D11 | Low | Labeling and reporting gaps: (a) comparison `attempts[]` labels origin paths "Not tested" although a request was sent and the CDN edge answered (reason `not_applicable`); (b) a partial firewall comparison lists the omitted expectation as `not_tested` with empty `reasons`; (c) the report uses the latest firewall evaluation, so a later partial evaluation hides the earlier more complete one (UDP 69 `inconclusive` became `not_tested`); (d) origin bindings are created with `port: null, path: null`. | `epc_fd09b97dde98c9a5`, `fwc_1319427b4ff5e1ab`, `obind_e9bf4233d38fe485`. |

## Follow-up (same day, code only)

D1 to D10 and D11 (a) to (c) were fixed in code with fixture-only regression tests; D11 (d) was closed as working as intended (a null binding port/path means the scheme default). See [rollout "Staging evidence"](protection-validation-rollout.md#staging-evidence-2026-10-06) for the fix list. No traffic was sent to verify the fixes; a live re-run through the signed worker is still required before any PV row can be marked complete.

## Limitations

- One target and one provider (Cloudflare), one source perspective and one worker. No appliance, reverse proxy, custom-response or multi-region evidence.
- Ownership came from the ADR-0016 demo proof, not DNS/HTTP proof. For a real tenant the owner must complete the normal verification flow before any run.
- Dev-json persistence only; the Postgres lifecycle was not exercised live.
- Worker restarts: the worker was restarted twice after D1 and D4. Stuck runs were cancelled through `POST /v1/test-runs/:id/cancel` before each restart, so no job was re-leased into a crash.
- No raw bodies, headers or secrets are recorded here. Response previews were read only to look for login/API links.
