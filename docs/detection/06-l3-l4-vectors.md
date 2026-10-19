# L3/L4 Vectors

## Scope

AstraNull validates L3/L4 readiness with **bounded outside-in probes**, **typed network-policy declarations**, and **SOC-gated high-scale** requests ([ADR-0008](../adr/0008-outside-in-only-targets-first.md), [ADR-0028](../adr/0028-typed-control-declarations-and-probe-perspectives.md), [ADR-0029](../adr/0029-violation-only-network-verdicts-and-truthful-waf-grading.md)).

There is no internal flow observer. Verdicts are `external_only`. NFW correlation is **violation-only**: `exposed` when a typed deny (or equivalent declaration) is broken by an unambiguous observation, or when a protocol-validated reply proves an open reflector; **`protected` is never returned** for NFW kinds.

Catalog assurance and per-target status: [rule-coverage.md](rule-coverage.md).

## What an outside-in L3/L4 probe can prove

- A TCP handshake, RST (`refused_rst`), ICMP-class reject (`rejected_icmp`), or timeout occurred from this `source_perspective` to this port and address family.
- A UDP probe received a protocol-validated reply, an unvalidated reply, ICMP port-unreachable / reject, or silence.
- A declared `network_policy` deny was **violated** (handshake or validated UDP reply, non-CDN peer, samples agree).
- An open reflector answered: a protocol-validated reply from `reflection_service_probe` is direct evidence, with or without a firewall declaration.
- IPv4 vs IPv6 outcomes differ (`parity: mismatch`) when both families were sampled on the same port.
- Firewall-change **reject evidence** (ICMP admin-prohibited / host- or net-unreachable `rejected_icmp` from the remote path, on ≥2 post samples from one perspective).
- Firewall-change **silent drop after a previously reachable port** (`consistent_with_new_deny_rule`) as improvement, without proving which rule dropped.

## What it cannot prove

- That timeout, RST, or UDP silence is a deny rule (`protected` is unavailable).
- That UDP port-unreachable is a deny: it is a closed port (`closed_port_not_control_specific`).
- Anything from a local `EACCES`/`EPERM`: that is the probe host's own socket policy (`local_error: true`), not the target's firewall.
- Which firewall rule fired.
- Allowlist or geo policy from a single unpublished source (needs ≥2 registered perspectives with egress IPs).
- IPv6 posture from an A-record-only connect (family selector `both` probes A and AAAA separately when present).
- ICMP policy as a first-class probe (no ICMP probe kind; ICMP is only a side-channel on connected TCP/UDP sockets).
- Egress filtering (inside vantage required; `out_of_scope`).
- Anti-spoofing / BCP38 (not live-tested; `not_assessable`).
- SYN-flood, volumetric, carpet-bombing, or pulse-wave capacity (declarations + SOC high-scale only).
- GRE/ESP/SCTP/IPsec live exposure (declaration-only metadata markers).

## Vector table

| Vector | Safe validation | High-scale / SOC | Outside-in verdict |
|---|---|---|---|
| TCP SYN / handshake | `tcp_connect` two samples (`max_requests: 2`), `nfw.declared_deny_tcp.safe` | SOC SYN / volumetric request | `exposed` only on declared deny + `handshake`. Else inconclusive. |
| TCP ACK/RST/FIN anomalies | Flag-anomaly check is not executable without a port; out-of-state is declaration-only | SOC transport scenario | Declaration or `unsupported_target`. |
| UDP | `udp_probe` two samples, `nfw.declared_deny_udp.safe` | SOC UDP volume | `exposed` only on declared deny + `validated_reply`. Silence is ambiguous. |
| ICMP policy | No ICMP probe kind | Rare SOC | `not_assessable`. |
| IP fragmentation / teardrop | Metadata marker | SOC lab preferred | Declaration-only (E1). |
| GRE/ESP/SCTP | Metadata marker | Provider-approved only | Declaration-only. |
| QUIC / UDP 443 | `quic_reachability`: one HTTPS HEAD over TCP, read Alt-Svc | SOC UDP/QUIC | Observation only. No UDP/QUIC packet is sent. |
| Port exposure | `port_scan_bounded` (vetted list, ≤15 declared ports) | Usually not high-scale | Open ports vs typed deny → `exposed`. |
| Management ports | `nfw.management_port_exposure.safe` | Not high-scale | Same violation-only rule. |
| Reflection / amplification | `reflection_service_probe`; validators where present; composites send `min(profiles, budget)` | Never third-party reflection | Protocol-validated reply → `exposed` as an open reflector (`exposure_basis: validated_reflector_reply`), no declaration needed and no firewall-violation claim. Unvalidated reply is never a verdict. |
| IPv6 parity | `nfw.ipv6_parity.safe`, `address_family: both` | SOC IPv6 scenario | Family buckets + `parity`; port scans round-robin the budget per port across families and mark an unprobed family `not_sampled`. |
| Connection table | `nfw.connection_limit.safe`, cap 12, needs `connection_limits` | SOC `l3.connection_table_exhaustion.request_only` | `exposed` if `accepted_count` > declared limit from a non-CDN peer with agreeing samples. Never `protected`. |
| Origin lockdown | See [05-origin-bypass.md](05-origin-bypass.md) | — | Violation-only. |
| Allowlist / geo | `nfw.perspective_allowlist.safe` | — | Not runnable with one perspective. |

## Network observation fields

From `src/lib/networkProbeOutcomes.mjs` / CONTRACT §3:

```
protocol, port, address, address_family: 4|6
tcp_outcome: handshake | refused_rst | rejected_icmp | timeout | error
udp_outcome: validated_reply | unvalidated_reply | port_unreachable | rejected_icmp | silent | error
icmp: { kind, errno } | null
service_validated, peer_is_cdn
families, parity: match | mismatch | single_family
samples, sample_agreement: agree | disagree | single
source_perspective: { id, label }
```

Port resolution: `profile.port` → target port → matching `network_policy` port → `profile.default_port`. Deny checks (`nfw.declared_deny_tcp/udp.safe`, `l3.basic_deny_rule.safe`) only take a declared `deny` rule for the protocol at the policy step (`declaredDenyPorts`, in declaration order, capped at the budget) and never an `allow` rule. Missing port → `unsupported_target` / `no_port_declared`, zero requests. Several catalog checks set `mechanism_supported: false` until a port exists; some carry `probe_profile.default_port`. `l3.basic_deny_rule.safe` is runnable for a tcp host:port target or a target that declares a TCP deny; otherwise admission refuses it with `port_or_declared_deny_required`.

`EACCES`/`EPERM` map to `tcp_outcome`/`udp_outcome: 'error'`, `icmp: null`, `local_error: true`; port scans record them under `local_error_ports`, not `filtered_ports`.

CDN peer and `sample_agreement: disagree` **exclude** NFW `exposed`, including `connection_limit_probe` (which returns `inconclusive` with the reason before comparing `accepted_count` to `declared_limit`).

### Reflector exposure vs firewall violation

A protocol-validated reflector reply and a declared-deny violation are different findings:

| Evidence | Verdict | Wording |
|---|---|---|
| Validated reflector reply, no UDP deny declared | `exposed` (medium), `metadata.exposure_basis: 'validated_reflector_reply'` | "Open <protocol> reflector reachable from the internet". It never claims a firewall deny was violated. |
| Validated reply on a port with a declared UDP deny | `exposed` | "Declared deny for udp/<port> … was violated". |
| Unvalidated reply, silence, ICMP | `inconclusive` | — |
| TCP handshake without a declared deny | not `exposed` | TCP/UDP deny checks still require a declared deny. |

## Safe L3/L4 check rules

- Low volume; TCP/UDP sample gap `SAMPLE_GAP_MS` (250 ms); max two samples.
- Unique labeled UDP prefix where used (`ASTRANULL:udp:`).
- Declared targets only; no spoofing; no amplification.
- Connection-limit hard cap 12.
- Bounded timeout.
- User-Agent `AstraNull-Probe/1.0 (+https://astranull.io/probe)` on HTTP producers.

## Probe perspectives

Registry: `ASTRANULL_PROBE_PERSPECTIVES` JSON `[{id,label,region,asn,egress_ips}]`. Default: `{ id: "default", label: "Primary", egress_ips: [] }`. Malformed config fails closed at process start.

Allowlist and geo checks need **≥2** registered perspectives. Customers declare `allowlisted_perspective_ids` / `denied_perspective_ids` on the target.

## Firewall-change acceptance

Separate classifier `firewall-acceptance-v4` (`src/lib/firewallChangeAcceptance.mjs`). It compares pre/post signed samples against a typed allow/deny expectation. It does not emit ordinary NFW `protected`.

| Evidence | Treatment |
|---|---|
| ICMP admin-prohibited or host/net-unreachable (`rejected_icmp`) from the remote path on ≥2 post samples from **one** perspective | Control-specific **reject** (`FIREWALL_DENIAL_BASES = ['icmp_admin_prohibited', 'rejected_icmp']`). |
| UDP `port_unreachable` | Closed port, `transport_error` with basis `port_unreachable`; item reason `closed_port_not_control_specific`. Stored v4 rows that recorded it as a denial are re-read the same way. |
| Local `EACCES`/`EPERM` (`local_error: true`) | `transport_error` with basis `local_probe_error`; the item is `inconclusive` with `local_error: true`. |
| RST / `connection_refused` | Unverified (`rst_after_change` / `rst_without_open_baseline`). RST is not a deny basis. |
| Repeated silent drop (`no_response` / `udp_silence`) after a **violated** (reachable) baseline, ≥2 samples | `not_observed`; deny expectation can be `improvement` with reason `consistent_with_new_deny_rule`. Silence without that baseline does not prove a deny. |
| UDP reply after silence | Regression reason `udp_reply_after_silence`. |
| Mixed samples / single sample | `unverified` (`MIN_SAMPLES_FOR_UNAVAILABILITY = 2`). |
| Pre/post source perspective mismatch | Compatibility `source_mismatch`. |

UDP silence stays `udp_silence_ambiguous` unless a later validated reply concludes a regression.

## High-scale L3/L4

During approved high-scale tests, collect external availability, adapter/provider rate metadata, edge/scrubber status if the customer supplies it, and SOC notes. Customer self-service never runs volumetric generators. Existing SOC gates and disabled high-scale adapters remain.

## Completion criteria

L3/L4 detection is complete when safe checks can expose a declared-deny violation, firewall-change can distinguish reject evidence from silent drop, IPv4/IPv6 and perspectives are recorded, and SOC-gated scenarios remain the only path to resilience evidence.

### Customer wording: blocked ports

The network coverage rows are named **Blocked TCP ports** and **Blocked UDP ports**. When the target has no network policy, the row says **Set blocked ports** and links to the existing network controls form. The customer chooses the ports their firewall should block; AstraNull cannot infer intent from a reachable service. A failed connection or silent UDP service alone never proves enforcement. This copy change does not change admission, traffic bounds or verdict rules.
