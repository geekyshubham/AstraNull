# ADR-0029: Violation-only network verdicts and truthful WAF grading

Date: 2026-10-13

Status: Accepted

## Context

Detection docs and the pre-remediation correlation path treated “blocked or timeout” as protection and assumed an internal agent could confirm whether a probe reached the origin ([ADR-0008](0008-outside-in-only-targets-first.md) already removed agents). Review F01–F30 (`.foreman/scratch/wafnfw/REVIEW.md`) showed:

- Every NFW probe kind sat on the observation-only list, so a handshake on a forbidden port never became `exposed`, while the firewall-change workflow could still treat the same evidence as a regression.
- Marker requests in sequence could source-ban the probe IP, so later placements looked blocked.
- Opaque class tokens were presented as attack-class protection.
- A Cloudflare (or similar) challenge was graded as a block.
- Vendor signatures were incomplete; several new patterns are still unverified on owned staging endpoints.
- Request bodies never left the self-serve worker. [ADR-0026](0026-reviewed-safe-execution-lifecycle.md) keeps reviewed worker runtime disabled.

Typed declarations and published probe perspectives ([ADR-0028](0028-typed-control-declarations-and-probe-perspectives.md)) make deny/allow, block signatures, rate-limit canaries, origin lockdown, and multi-source allowlists inputs rather than labels.

## Decision

1. **NFW violation-only verdicts.** `correlateExternalOnlyVerdict` may return `exposed` for `tcp_connect`, `udp_probe`, `port_scan_bounded`, `reflection_service_probe`, and `connection_limit_probe` when a typed deny or connection-limit rule is violated by an unambiguous observation: TCP `handshake` or UDP `validated_reply`, non-CDN peer, samples in agreement; or `accepted_count` above a declared connection cap. Those kinds never return `protected`. Timeout, RST, UDP silence, unvalidated replies, CDN peers, and `sample_agreement: disagree` stay `inconclusive`; for `connection_limit_probe` the CDN-peer and disagreeing-sample exclusions run before the cap comparison. Deny checks (`nfw.declared_deny_tcp/udp.safe`, `l3.basic_deny_rule.safe`) resolve a port only from a declared `deny` rule for that protocol, never from an `allow` rule. The same kinds remain on `OBSERVATION_ONLY_PROBE_KINDS` so they stay out of the readiness coverage denominator (ADR-0014) while rule-coverage reports `violation_only`.

   **Reflector exposure is not a firewall violation.** A protocol-validated reply from `reflection_service_probe` is direct evidence of an open reflector, so it is `exposed` without any firewall declaration. The explanation says "Open <protocol> reflector reachable from the internet" and the correlation result carries `metadata.exposure_basis: 'validated_reflector_reply'`; it never claims a declared deny was violated. When a UDP deny is declared for that port, the declared-deny wording is used instead. Unvalidated replies never expose. `exposed` for TCP/UDP deny checks still requires a declared deny.

   **Firewall-change denial bases.** `FIREWALL_DENIAL_BASES` holds explicit remote filter evidence only: ICMP administratively-prohibited and host/net-unreachable (`rejected_icmp`). UDP port-unreachable is a closed port (`closed_port_not_control_specific`), not a deny. `EACCES`/`EPERM` are the probe host's own socket policy: they map to `tcp_outcome`/`udp_outcome: 'error'` with `local_error: true` and keep the item inconclusive. The classifier stays `firewall-acceptance-v4`; stored v4 rows that recorded UDP port-unreachable as a denial are re-read as a closed port.

2. **Challenged is distinct from blocked.** WAF response outcomes are `blocked | challenged | allowed | redirected | inconclusive | error` (`waf-grading.v2`). A challenge never satisfies `expected_action: 'block'`. It satisfies `'challenge'` and `'block_or_challenge'`. Under `block`, challenged legs make enforcement `challenged` (inconclusive) and are never counted as not enforced, so blocked plus challenged legs can never become `exposed`. Under `block_or_challenge`, a challenged leg satisfies the action. A 3xx whose Location differs from the baseline is `redirected` and does not count as allowed. Unsigned 4xx/5xx stay inconclusive.

3. **Trailing control / source-penalized.** After marker legs, class and evasion probes send a trailing benign request. If it is not `allowed`, `source_penalized` is set and correlation is `inconclusive`. Leg order is randomized. Each placement is graded alone.

4. **Custom-canary renaming.** Opaque class-marker checks prove a customer rule for an AstraNull inert token (`assurance_scope: custom_canary_rule`). Managed-rule markers are `sqli`, `xss`, `path_traversal`, and `scanner_user_agent`. Coverage rolls custom canaries to one pair per target. Lookup, external-entity, URL-fetch, template-evaluation, and property-assignment forms stay absent: **no RFI, no JNDI/Log4Shell `${…}` lookups, no Spring4Shell property paths.**

5. **SOC-only request-body tests.** JSON, form, multipart, inspection-limit padding (8/16/64/128 KB), and response-DLP canaries are `.soc` plans against a customer-declared HTTPS `canary_sink` on the verified host. Every self-serve WAF probe is bodyless because ADR-0026 leaves reviewed worker runtime disabled. Marker, evasion, and rate-limit canary probes use GET/HEAD only. The method-policy probe (`waf.http_method_policy_enforced.safe`) additionally sends exactly two methods, `TRACE` and the nonstandard token method `ASTRANULLPROBE`, each with no request body, after a GET baseline and before a trailing GET. It uses no customer declaration. `canarySinkBodyPlan.mjs` is a planner; workers must not import it as a live probe kind. The WAF orchestrator and `startTestRun` both accept these request-only scenarios (for example `rce_marker` → `waf.offensive_rce.soc`); there is no SOC preflight refusal.

6. **Vendor signatures pending live verification.** New corpus entries (`waf-signatures.2026-10-13`) include AWS ALB/API Gateway, Cloud Armor, Azure Front Door, Fastly NGWAF, and ModSecurity/Coraza patterns with `live_verified: false` until tested on AstraNull-owned staging endpoints. An unverified entry grades `blocked` only on a WAF-specific anchor (a block-page phrase or token that only that WAF emits, such as "Request blocked by AWS WAF", "Cloud Armor", an Azure Front Door/Application Gateway WAF block phrase, a Fastly Next-Gen WAF/Signal Sciences token, or the ModSecurity/Coraza block text). Generic proxy/CDN headers (`x-azure-ref`, `via: 1.1 google`, `x-served-by`, `x-amzn-errortype`, a `server` banner) plus a 403/406 are only a suspected block: the leg is `inconclusive` with `inconclusive_reason: 'block_suspected_unverified_signature'` and `matched_vendor`. A customer-declared block header remains the supported identifier for unsigned products and still grades `blocked`.

7. **Readiness and findings.** Freshness is seven days (`protection-profile.coverage.v2`). Positive credit needs `enforcement: enforced` on signed metadata. `accepted_risk` no longer subtracts from the score (counted separately until `review_at`). A complete passing retest of the same check/target/scope/versions moves open findings to `fix_verified`.

## Consequences

- Silence is no longer protection. Customers will see more `inconclusive` and `exposed` rows and fewer green NFW checks.
- Custom canary `protected` is honest: it is a marker-rule proof, not managed SQLi/XSS coverage.
- Allowlist/geo remain ungradeable until two perspectives with published egress IPs are registered.
- Body inspection, real exploit payloads, and high-scale L3/L4 stay SOC-gated.
- Detection docs 03, 04, 05, 06, and 12 describe this model; they no longer document agent observation.
- Customers on WAFs with only generic edge headers see suspected blocks as inconclusive until they declare a block signature or the vendor entry is live-verified.
- Zone-transfer (`dns_axfr_leak`) is `protected` only when every nameserver was queried and refused; a leak on any nameserver is `exposed`; budget-limited coverage is `enforcement: 'partial'` and inconclusive.
- A TCP connection to port 53 is not a zone transfer: `exposed` needs an explicit `axfr_leak` from a completed transfer with attested probe I/O, and `protected` needs per-nameserver refusal rows covering every distinct nameserver. An `enforcement` label alone earns no credit.
- NFW probe kinds with no attested probe I/O, or ending in `error`, `not_run` or `timeout`, are `inconclusive` before any port-level grading. IPv4/IPv6 outcomes that differ are a parity finding, not repeat-sample disagreement; disagreement within one address family stays inconclusive.
- The rate-limit canary is `protected` only when the first `threshold` requests were allowed and the limit came at request `threshold+1` or `threshold+2`.

Implementation: `src/services/correlation.mjs`, `src/lib/probeEvidenceTiers.mjs`, `src/lib/externalObservationOutcomes.mjs`, `src/lib/vectorProbes/*`, `src/lib/networkProbeOutcomes.mjs`, `src/lib/firewallChangeAcceptance.mjs`, `src/lib/protectionCoverage.mjs`, `src/lib/readinessProjection.mjs`, `src/lib/findingLifecycle.mjs`.
