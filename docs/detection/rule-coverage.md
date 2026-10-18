# Rule coverage: what AstraNull can conclude

AstraNull reports WAF and network-firewall coverage by **rule category**, not by a single score. Each category has a catalog `assurance` (the best conclusion the shipped checks can ever support) and, for a target, a `status` derived from the latest fresh verdicts and the declarations that target has stored.

`GET /v1/rule-coverage` is the catalog view. `GET /v1/targets/:id/rule-coverage` overlays that target's latest check verdicts (fresh within the 7-day `protection-profile.coverage.v2` window) and `control_declarations`.

## Assurance levels

| Assurance | Meaning |
|---|---|
| `verdict` | A bounded semantic-safe probe can return scoped `protected` or `exposed` on the probed path. |
| `violation_only` | Outside-in evidence can expose a declared deny that was violated. `protected` is not available from silence or RST. |
| `partial` | Reserved legacy assurance value. Current unbound custom-canary checks are classified as `observation`, not partial installed-rule proof. |
| `observation` | Transport/response facts only. No control verdict. |
| `declaration` | Metadata-marker / customer declaration only. |
| `soc_only` | Only a SOC-gated suite can conclude. Nothing self-serve sends a body or an exploit payload. |
| `missing` | The catalog has no check for this category. |
| `not_assessable` | The outside-in model cannot answer this question (no ICMP probe kind; anti-spoofing), or the category's only probe check can never run (stateful inspection via `l3.tcp_flag_anomaly.readiness`). |
| `out_of_scope` | Requires a vantage AstraNull does not have (egress filtering). |

Per-check derivation (`checkCatalogAssurance` in `src/contracts/ruleCoverage.mjs`), first match wins:

1. SOC-gated or no probe profile → `soc_only`; `metadata_marker` → `declaration`.
2. A probe check the catalog refuses for every target (`mechanism_supported: false`, or `additionalInputRefusal` that cannot be satisfied by any target port or customer declaration) → `not_assessable`, `assurance_reason` "no runnable probe". Target-dependent requirements (such as ports or declarations in `TARGET_DEPENDENT_REQUIREMENTS`) remain declaration-gated: they keep the probe's true assurance level and list `required_declarations`.
3. Network-firewall observation kinds (`nfw.*`, `l3_l4`, reflection, amplification, origin `host_sni_bypass`) → `violation_only`: an unambiguous handshake plus a declared deny, or a validated reflector reply, is `exposed`; timeout is not `protected`.
4. Custom-canary class markers (`assurance_scope: custom_canary_rule`) → `observation` with the unavailable installed-rule setup reason. The managed scanner user-agent check stays in its scanner category, not the custom-token category.
5. Kinds on `VERDICT_CAPABLE_PROBE_KINDS` → `verdict` (e.g. `rate_limiting` via `waf.rate_limit_canary.validation` with a declaration).
6. Anything else, including unknown probe kinds → `observation`. An unknown kind is never `verdict`.

A category takes its `forced_assurance` only when at least one of its checks actually reaches that level; otherwise it takes the best per-check assurance (`connection_limits` and `allowlists_geo` are `violation_only`, with `allowlists_geo` noting it needs ≥2 registered probe perspectives). Each projected category and check carries `assurance_reason` (custom-canary, perspective requirement, never-runnable, not-assessable or out-of-scope text) or `null`.

## Target status

| Status | Meaning |
|---|---|
| `covered_pass` | At least one fresh passing verdict; no fresh fail. |
| `covered_fail` | A fresh `exposed` / fail verdict. |
| `inconclusive` | Fresh result that is neither pass nor fail. |
| `not_run` | No fresh verdict, or fewer than two registered perspectives for allowlists. |
| `needs_declaration` | A required `control_declarations` key is missing. |
| `not_assessable` / `out_of_scope` | Same as catalog assurance. |

## WAF categories and new checks

Custom tokens (`assurance_scope: custom_canary_rule`) cannot currently prove that an exact-token customer rule is installed. `block_signature`, `expected_action` and `marker_paths` are not that binding. Such checks carry `setup_required: true`, `produces_verdict: false`, `observation_only: true`, `readiness_conclusion: false`; blocked/allowed token responses remain observations, never installed-rule failure findings. Categories served only by opaque canaries (`request_smuggling`, `ssrf_xxe_jndi`, `deserialization`, `file_upload`, `ssti`) have no current self-serve installed-rule assurance. The current catalog returns `observation` for those categories. Historical pass/fail text remains available unchanged, but observation-only checks cannot contribute `covered_pass` or `covered_fail` to the current target projection.

Managed-rule markers (SQLi, XSS, path traversal) send the plain inert class token that managed OWASP rulesets recognise. SSTI's marker is an opaque token, so `waf.ssti_marker.safe` is a custom canary, not a managed marker.

Request-body, inspection-limit, and response-DLP checks are SOC-gated (`canary_sink_body_plan`). Nothing self-serve sends a body.

RFI and CVE virtual-patching are `missing`: "Not tested. Remote-file-inclusion and CVE exploit markers could trigger work on a vulnerable server, so AstraNull does not send them. Ask SOC for a manual assessment." URL-fetch, lookup, and property-assignment marker forms are not catalogued as self-serve.

`waf.http_method_policy_enforced.safe` (`waf_method_policy_probe`) and `waf.rate_limit_canary.validation` (`rate_limit_canary_probe`) are worker-executed (`CAPABILITY_PROBE_DISPATCH`). The method-policy check sends `TRACE` and the nonstandard token `ASTRANULLPROBE` with no body and uses no declaration; it is verdict-capable E2 with `produces_verdict: true`, `observation_only: true`, `readiness_conclusion: false`. It does not earn readiness credit. The rate-limit canary needs `waf.rate_limit_canary` and is `protected` only when `threshold` requests were allowed and the limit came at `threshold+1` or `threshold+2`.

## NFW categories and new checks

Every NFW check documents that `protected` is not available from outside-in evidence and that `exposed` requires a declared deny (or a declared origin binding with `origin.lockdown_expected`, or `connection_limits`). Reflector checks are the exception: a protocol-validated reply is direct evidence of an open reflector and is `exposed` without a declaration.

- `nfw.declared_deny_tcp.safe` / `nfw.declared_deny_udp.safe` — two samples against a declared deny.
- `nfw.management_port_exposure.safe` — bounded scan of the vetted management/database list.
- `nfw.ipv6_parity.safe` — A and AAAA (`address_family: both`).
- `nfw.connection_limit.safe` — `connection_limit_probe`, cap 12, requires `connection_limits`.
- `nfw.origin_lockdown.safe` — customer-visible Host/SNI probe against a declared origin binding; `exposed` needs application identity, not a TCP handshake.
- `l3.basic_deny_rule.safe` — runnable for a tcp host:port target or a target that declares a TCP deny; it only probes declared deny ports.
- `nfw.perspective_allowlist.safe` — needs at least two registered perspectives.

ICMP policy is `not_assessable` (no ICMP probe kind). Stateful inspection is `not_assessable`: its only probe check, `l3.tcp_flag_anomaly.readiness`, can never run, and out-of-state handling is a declaration. Egress filtering is `out_of_scope` (needs an inside vantage). Anti-spoofing is `not_assessable`.

## Probe budgets (wave 1)

Per-kind maxima: `tcp_connect`/`udp_probe` 2 (two samples), `reflection_service_probe` 4 (composite profiles), `dns_axfr_leak` 5 (NS lookup plus up to four name servers), `connection_limit_probe` 12. Composite mDNS/NetBIOS/WS-Discovery and DTLS/SIP/RDP/TFTP checks use `payload_profiles` matching `src/lib/reflectorPayloads.mjs`.
