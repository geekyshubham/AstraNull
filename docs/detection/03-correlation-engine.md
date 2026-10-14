# Correlation Engine

## Purpose

The correlation engine turns a **signed external probe result** plus **typed control declarations** into a verdict ([ADR-0008](../adr/0008-outside-in-only-targets-first.md), [ADR-0028](../adr/0028-typed-control-declarations-and-probe-perspectives.md), [ADR-0029](../adr/0029-violation-only-network-verdicts-and-truthful-waf-grading.md)).

It answers:

> Given this outside-in observation, this check, and this target’s declarations, is there control-specific evidence of enforcement or of a declared-policy violation?

There are no customer agents, environments, or internal packet observers. Confidence on customer-target verdicts is `external_only`. Timeout, RST, ICMP silence, and unsigned status codes never become `protected`.

Implementation: `src/services/correlation.mjs` (`correlateExternalOnlyVerdict`).

## Inputs

| Input | Source |
|---|---|
| Signed probe result (`external_result`, `probe_kind`, metadata) | Probe worker / capability producer. |
| Attested I/O (`safety_attestation.probe_requests_sent > 0`) | Probe event. Required before a generic `blocked` result can become edge protection. |
| Typed `control_declarations` | `target.metadata.control_declarations` (copied onto `probe_profile.declarations`). |
| Origin binding | Existing origin-binding record, when present. |
| Expected behavior | Immutable run snapshot (`expected_behavior_json`) or catalog default. |
| Check definition / probe kind | Check catalog. |
| SOC approval events | SOC service for high-scale / `.soc` / `request_only` checks. |

Correlation does **not** consume agent observation, agent no-observation, agent health, or placement diagnostics.

## Correlation keys

| Key | Description |
|---|---|
| `test_run_id` | Parent run. |
| `check_id` / `check_version` | Catalog identity. |
| `grading_version` | `waf-grading.v2` on WAF marker results. |
| `signature_corpus_version` | `waf-signatures.2026-10-13.2` on WAF marker results. |
| `target_id` | Target under test. |
| `nonce_hash` | Run correlation nonce (readiness proof matching). |
| `source_perspective` | `{ id, label }` from the probe-perspective registry. |
| Time / ingestion clocks | Immutable observation and ingestion availability. |

## Probe-kind allowlists

Kinds that may produce a control verdict live in `VERDICT_CAPABLE_PROBE_KINDS` (`src/lib/probeEvidenceTiers.mjs`):

- Semantic-safe: `ops_readiness`, `dns_axfr_leak`, `outside_in_waf_scan`, `waf_class_marker_probe`, `waf_evasion_marker_probe`, `rate_limit_canary_probe`.
- Network / origin (violation-only for NFW and origin lockdown): `tcp_connect`, `udp_probe`, `port_scan_bounded`, `reflection_service_probe`, `connection_limit_probe`, `host_sni_bypass`.

Network kinds above also remain on `OBSERVATION_ONLY_PROBE_KINDS`. Correlation runs the NFW / origin violation path **first**. If that path does not fire, the kind falls through to an observation-only `inconclusive` result. `protected` is never emitted for those NFW kinds.

Any other kind is observation-only or unrecognized and stays `inconclusive`.

## Verdict vocabulary

Customer-target correlation emits only:

| Verdict | Meaning |
|---|---|
| `protected` | Control-specific enforcement matched the check (WAF marker enforced, challenge matched a declared challenge expectation, rate-limit canary limited at `threshold+1`/`threshold+2` after `threshold` allowed requests, method policy refused TRACE and the token method, AXFR refused by every nameserver with `enforcement: enforced`, ops self-check). |
| `exposed` | Declared deny or marker expectation was violated, a protocol-validated open reflector answered, an AXFR transfer leaked, or a normalization gap / origin-lockdown identity match was observed. Creates a finding. |
| `edge_protected` | Generic attested `blocked` on `must_block_before_origin` without an `enforcement: enforced` credit path. |
| `edge_exposed` | Generic attested `connected`/`allowed` on `must_block_before_origin` for a verdict-capable non-NFW kind. Creates a finding. |
| `allowed_as_expected` | `must_reach_canary` and the probe connected. |
| `inconclusive` | Evidence insufficient, observation-only, source-penalized, challenged-when-block-expected, sample disagreement, CDN peer, timeout, error, or not run. |

Legacy labels (`bypassable`, `penetrated`, `misplaced_agent`, `blocked as expected`) are not produced by `correlateExternalOnlyVerdict`.

Ops-readiness (`correlateOpsReadinessVerdict`) is a control-plane self-check with no destination I/O. It reuses `protected` / `inconclusive` and currently stamps confidence `high` / `low`. It never creates a customer-target finding.

## Evaluation order

`correlateExternalOnlyVerdict` applies the first matching step:

1. Evidence-gap outcomes on Host/SNI (`misdirected_request`, `probe_path_error`, `not_applicable`) and marker gap reasons (`authentication_gate_precedes_inspection`, `unattributed_denial`, `block_suspected_unverified_signature`, `baseline_not_available`, `error_not_attributable`). Coverage gaps; no finding. A suspected unverified signature names the `matched_vendor` in the explanation.
2. `nfw.perspective_allowlist.safe`: needs ≥2 registered perspectives; a handshake from a declared denied perspective is `exposed` (medium), everything else `inconclusive`.
3. NFW violation-only path for `tcp_connect`, `udp_probe`, `port_scan_bounded`, `reflection_service_probe`, `connection_limit_probe`.
4. Origin-lockdown path for `host_sni_bypass` when an active origin binding **and** `origin.lockdown_expected` are present.
5. Rate-limit canary (`rate_limit_canary_probe`).
6. WAF trailing-control / challenge / redirect handling, then class-marker or evasion grading (`waf_class_marker_probe`, `waf_evasion_marker_probe`, `outside_in_waf_scan`).
7. Method policy (`waf_method_policy_probe`).
8. Zone transfer (`dns_axfr_leak`): `exposed` on any leaking nameserver, `protected` only with `enforcement: 'enforced'` and attested probe I/O, `enforcement: 'partial'` → `inconclusive`.
9. Observation-only kinds → `inconclusive` (no finding).
10. `error` / `not_run` / `timeout` → `inconclusive` (timeout is never aliased to blocked).
11. Non-allowlisted kind → `inconclusive`.
12. Generic expected-behavior table for remaining verdict-capable kinds (`must_block_before_origin`, `must_reach_canary`).

## WAF grading outcomes

Producers grade each HTTP response as `blocked | challenged | allowed | redirected | inconclusive | error` (`src/lib/externalObservationOutcomes.mjs`, `isBlockedOrChallenged` in `src/lib/outsideInWafScanner.mjs`, wrapped by `gradeMarkerSnapshot` in `src/lib/vectorProbes/wafProbeSupport.mjs`).

| Outcome | Rule |
|---|---|
| `blocked` | Control-specific vendor or customer-declared denial signature, and the signature is not a challenge. |
| `challenged` | Solvable challenge / interstitial (managed challenge, JS challenge, CAPTCHA). Never satisfies `expected_action: 'block'`. Satisfies `'challenge'` and `'block_or_challenge'`. |
| `allowed` | 2xx, or 3xx whose Location matches the baseline. Reason `not_blocked_at_the_edge`. Does not prove the origin handled the request. |
| `redirected` | 3xx whose Location differs from the baseline. Never counted as allowed. Redirected-only legs make posture inconclusive. |
| `inconclusive` | Unsigned 4xx (`block_suspected` only), a suspected block on an unverified vendor signature (`block_suspected_unverified_signature` + `matched_vendor`), 5xx, 401/407/421, unhealthy baseline, unclassifiable status. |
| `error` | Transport error, drop, or abort. |

An unsigned 4xx/5xx stays inconclusive. Status codes alone never establish enforcement. A vendor signature with `live_verified: false` grades `blocked` only on a WAF-specific anchor (block-page phrase or token only that WAF emits). Generic proxy/CDN headers (`x-azure-ref`, `via: 1.1 google`, `x-served-by`, `x-amzn-errortype`, a `server` banner) with a 403/406 are a suspected block only. A customer-declared block signature always grades `blocked`.

### Expected action

`enforcementFromGraded` honours `declarations.waf.expected_action`. Under `block` (default), challenged legs give `enforcement: 'challenged'` (inconclusive) and never count as not enforced, so blocked plus challenged legs are never `exposed`; an allowed leg next to blocked or challenged legs is `partial`. Under `block_or_challenge` or `challenge`, a challenged leg satisfies the action. Correlation also refuses to expose a `partial` record that has no allowed placement.

### Trailing control and source-penalized

Class-marker and evasion probes send a trailing benign request after marker legs. If that request is not `allowed`, metadata sets `source_penalized: true` and `posture_status: source_penalized`. Correlation returns `inconclusive`: a source-level ban makes later legs untrustworthy.

### Per-placement grading

Each placement (query, path, header, or scanner User-Agent) is graded alone. A 404 or unsigned leg is excluded (`isGradedLeg`); it does not void the others. At least one graded leg is required for a complete marker comparison (`marker-comparison-v4`).

Legs are shuffled (`leg_order`). Every request carries cache-buster `an_cb`.

### Custom canary vs managed-rule markers

`assuranceScopeForMarkerClass` (`src/lib/vectorProbes/wafClassProbes.mjs`):

| `assurance_scope` | Marker classes | What a `protected` result proves |
|---|---|---|
| `custom_canary_rule` | Opaque tokens (SSRF, XXE, SSTI, JNDI/LDAP token without `${`, deserialization prefix, smuggling token, …) | A customer rule matched AstraNull’s inert token on the tested placements/paths. |
| `managed_rule_marker` | `sqli`, `xss`, `path_traversal`, `scanner_user_agent` | The plain inert class token that managed OWASP-style rulesets recognise was enforced. |
| `inert_marker_rule_action_only` | Evasion probes | The inspector still blocked the transformed inert marker (or a normalization gap was observed). |

Custom-canary `exposed` is severity `low`. Managed-marker `exposed` is severity `medium`. Partial enforcement is `exposed` at `low` and names unenforced placements.

Lookup, external-entity, URL-fetch, template-evaluation, and property-assignment marker forms are absent. There is no self-serve RFI, Log4Shell `${…}`, or Spring4Shell marker.

### Evasion

Sequence: healthy permitted baseline, plain reference marker, transformed marker, trailing control.

| Flag | Correlation |
|---|---|
| `source_penalized` | `inconclusive`. |
| `reference_not_enforced` | `inconclusive` (run the matching managed-rule marker first). |
| `normalization_gap` (reference blocked **and** transform allowed, comparison complete, transform not observation-only) | `exposed`. Severity `medium` for `sqli`/`xss`/`path_traversal`, else `low`. |
| Observation-only transforms `base64_wrap`, `numeric_repr`, `homoglyph` | Allowed transform stays `inconclusive`; it is not a bypass. |

Supported GET-query transforms include `double_url`, `mixed_url`, `case_fold`. Framing, body, and protocol-translation transforms remain unsupported on this transport.

## NFW violation-only verdicts

For TCP/UDP/port-scan/connection-limit/reflection:

| Condition | Verdict |
|---|---|
| Typed `network_policy` deny **and** `tcp_outcome: handshake` (or port-scan `open_ports`) from a non-CDN peer, samples agree | `exposed` |
| Typed deny **and** `udp_outcome: validated_reply`, non-CDN, samples agree | `exposed` |
| `connection_limit_probe` `accepted_count` greater than declared `max_connections_per_source`, non-CDN peer, samples agree | `exposed` |
| `reflection_service_probe` with a protocol-validated reply (`udp_outcome: validated_reply`), no declaration needed | `exposed` with `metadata.exposure_basis: 'validated_reflector_reply'`; explanation "Open <protocol> reflector reachable from the internet", never a firewall-violation claim |
| `sample_agreement: disagree` | No NFW `exposed` (`connection_limit_probe` returns `inconclusive` with the reason) |
| `peer_is_cdn: true` | Same exclusion (`connection_limit_probe` returns `inconclusive` with the reason) |
| Timeout, `silent`, `refused_rst`, `rejected_icmp`, unvalidated UDP reply, missing deny | `inconclusive`. **`protected` is never returned.** |

Severity is `high` for a set of management/database ports (22, 3389, 445, 3306, …) and `medium` otherwise.

TCP/UDP classes (`src/lib/networkProbeOutcomes.mjs`):

- TCP: `handshake | refused_rst | rejected_icmp | timeout | error`
- UDP: `validated_reply | unvalidated_reply | port_unreachable | rejected_icmp | silent | error`
- ICMP mapping from errno when the connected socket surfaces it (`port_unreachable`, `host_unreachable`, `net_unreachable`). `EACCES`/`EPERM` are the probe host's own socket policy: `tcp_outcome`/`udp_outcome: 'error'`, `local_error: true`, `icmp: null`, never `admin_prohibited`.

Silence and RST are not control-specific denial.

Deny checks (`nfw.declared_deny_tcp/udp.safe`, `l3.basic_deny_rule.safe`) resolve their port from a declared `deny` rule for the protocol (`declaredDenyPorts`, capped at the budget); they never pick an `allow` rule.

### IPv4 / IPv6 parity

Probes may record `families.ipv4` / `families.ipv6` and `parity: match | mismatch | single_family`. The dual-stack port scan spends its budget round-robin per port across families and records `ports_sampled` per family; a family with no probes is `not_sampled: true` and parity is `single_family` (`parity_reason: family_not_sampled`), never `mismatch`. A deny violation on one family still yields `exposed`; the explanation states an IPv6 parity mismatch only when both families were sampled on the leaking port.

### Perspectives

Workers stamp `source_perspective`. Allowlist and geo rules need **at least two registered perspectives** with published egress IPs (`GET /v1/probe-perspectives`, catalog `runnable_requires: ['two_perspectives']` on `nfw.perspective_allowlist.safe`). One source cannot distinguish allow-only-from-X from deny-all. Correlation still applies the same violation-only rule (declared deny + handshake). It does not count the registry itself.

## Origin lockdown

`host_sni_bypass` with an active declared origin binding **and** `origin.lockdown_expected: true`:

`exposed` only when the peer is not a CDN address, the HTTP status is 2xx, **and** the origin answered as the application for the target hostname (`application_bypass_confirmed` or `application_identity_confirmed` / nonce canary). A TCP handshake or bare 2xx is not enough. Timeout, RST, unsigned 4xx, CDN edge answers (`not_applicable`), and 421/407 are inconclusive or evidence gaps. `protected` is unavailable.

See [05-origin-bypass.md](05-origin-bypass.md).

## Rate-limit canary

`rate_limit_canary_probe` needs `waf.rate_limit_canary` `{ path, method GET|HEAD, threshold 1..10, window_seconds 1..60 }`. Cap is `min(threshold+2, max_requests, 12)`.

Metadata keeps `requests_sent`, `first_limited_at`, `limited_outcome`, and `allowed_before_limit`.

- First `threshold` requests allowed and the limit (`blocked`, `challenged`, HTTP 429) at request `threshold+1` or `threshold+2` → `protected`.
- Limited at or before `threshold` → `inconclusive` (`limited_before_threshold`; the route may always be blocked).
- Fewer than `threshold` allowed before the limit, or limited after `threshold+2` → `inconclusive`.
- Never limited with `requests_sent > threshold` → `exposed` (low).
- Never limited without exceeding the threshold → `inconclusive` (`window_expired_before_threshold`).

## Method policy

`waf_method_policy_probe` sends a GET baseline, then `TRACE` and the nonstandard token method `ASTRANULLPROBE` with no request body, then a trailing GET. It uses no declaration. Both methods refused with a control-specific denial and a healthy baseline → `protected`; either allowed through the edge → `exposed` (low); source penalized, incomplete, suspected, or origin-only 405/501 rejection → `inconclusive`.

Generic `rate_limit_sequence` checks remain observation-only.

## What an outside-in probe can prove

- A named WAF signature (vendor or declared header/status) appeared on a marker request from this source.
- A custom canary token was blocked on the tested placements.
- A managed-rule inert token was blocked, or a supported evasion transform was allowed after that token was blocked.
- A declared TCP/UDP deny was violated by a handshake or protocol-validated reply from a non-CDN peer.
- A declared origin binding (with `origin.lockdown_expected`) answered 2xx with application identity from a non-CDN source.
- A declared rate-limit canary allowed `threshold` requests and limited at `threshold+1` or `threshold+2`.
- AXFR was refused by every nameserver of the zone (`enforcement: enforced`) or leaked on at least one.
- A protocol-validated reply came from an open reflector.

## What it cannot prove

- Packets reached or did not reach an origin behind the edge (no internal observer).
- A timeout, drop, or RST is a firewall deny.
- A challenge is a block.
- A redirect to a block page is a block.
- Managed coverage of an attack class from an opaque custom-canary token.
- Allowlist/geo policy from a single perspective.
- Request-body inspection on self-serve GET/HEAD (SOC canary-sink body plans only; [ADR-0026](../adr/0026-reviewed-safe-execution-lifecycle.md) keeps reviewed worker runtime disabled).
- Egress filtering (needs an inside vantage; out of scope).
- ICMP policy (no ICMP probe kind).
- Capacity, SYN-flood absorption, or high-scale resilience (SOC-gated; existing high-scale adapter gates remain).

## Completion criteria

Correlation is complete when every verdict is explainable from signed external evidence and declarations, uses `external_only` confidence on customer targets, and refuses to treat silence as protection.
