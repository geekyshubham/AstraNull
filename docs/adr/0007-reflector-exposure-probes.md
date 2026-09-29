# ADR-0007: Reflector/Amplifier Exposure Probes Are Bounded Defensive Checks

## Status

Accepted (2026-09-29). Reflector exposure probes stay in the safe probe family under the enforced
guardrails below. Recorded here to satisfy the `AGENTS.md` requirement that anything near the
"no amplification logic" rule be an explicit decision.

## Context

`src/lib/reflectorPayloads.mjs` defines a reusable set of UDP/TCP request payloads for services that
are commonly abused as DDoS reflectors/amplifiers: SNMP v2c `public` GET, memcached UDP `stats`,
NTP mode 6 readvar, CLDAP root DSE, chargen, SSDP M-SEARCH, mDNS/NetBIOS/WS-Discovery, CoAP, STUN,
IPMI RMCP, MSSQL resolution, TFTP, DTLS ClientHello, portmap dump, OpenVPN reset, Jenkins discovery,
and RIPv1. Each builder produces a bounded request, and `classifyReflection` computes an
`amplification_ratio` (response bytes ÷ request bytes) plus a coarse `response_size_class`.

`AGENTS.md` forbids adding "raw, reusable DDoS attack scripts, amplification logic, or unmanaged
traffic generators." These payloads sit close to that line because they name the same protocols an
amplification attack would use and they measure amplification factor. The product decision is
whether this is defensive exposure testing (keep) or offensive tooling that must be governed
(SOC-gate).

## Why this is a defensive exposure check, not an amplifier

The enforced runtime envelope, not the payload catalog, is what determines intent:

- **Single approved destination.** The probe only targets the job's resolved target host
  (`reflectionEndpoint` + `resolvePinnedDestination` in `src/lib/safeNetworkProbes.mjs`). It never
  fans out to third parties and never spoofs a source address — the reflector abuse primitive
  (spoofed victim source + many reflectors) is structurally absent.
- **At most two packets.** `maxRequests = Math.min(2, …)` in `probeReflectionService`. A UDP profile
  sends one datagram, optionally one retry if no response; TCP sends one payload. This cannot
  generate attack-scale traffic.
- **Ownership-gated egress.** Dispatch to an external worker requires ownership proven to at least
  `dns_verified` (see README security audit 2026-08-01), and every egressing kind must clear the
  probe worker's destination classifier (`vetProbeDestination` in `workers/probe-worker.mjs`) before
  any socket is opened.
- **Bounded payloads.** `MAX_PAYLOAD_BYTES = 512`; builders throw if exceeded.
- **Measurement only.** The output is metadata (`amplification_ratio`, `response_size_class`,
  `reflector_confirmed`) describing whether the customer's own approved host is an exploitable
  reflector. That is the exposure the customer is validating against.

## Decision

Keep the reflector exposure probes in the safe (non-high-scale) probe family, subject to the limits
above remaining enforced in code. They are a defensive "is my approved host an open reflector?"
check, not amplification traffic generation.

## Guardrails that must stay true (regression contract)

1. `maxRequests` for reflection probes stays capped at 2.
2. Reflection probes only ever target the job's single resolved/pinned destination; no source-address
   spoofing, no third-party fan-out.
3. Reflection egress remains behind the ownership gate and the probe-worker destination classifier.
4. `MAX_PAYLOAD_BYTES` stays ≤ 512.
5. Output stays metadata-only (ratio + size class + confirmed flag); no packet capture or payload
   replay tooling is added.

If any of these is relaxed, this ADR must be revisited and the capability moved behind SOC approval.

These are enforced by `tests/unit/reflector-guardrails.test.mjs` (runtime probe behaviour, each
mutation-checked: raising the packet cap, accepting replies from other peers, skipping the
destination policy, or raising the payload cap each fails its guardrail), plus the catalog caps in
`tests/unit/vectors.test.mjs` and `tests/unit/extra-reflector-payloads.test.mjs`, and the live
loopback check in `tests/integration/reflector-service-live.test.mjs`.

## Alternative considered: SOC-gate (restrict)

Move reflector profiles out of the safe family and require SOC approval per ADR-0003. Rejected for
the default posture because the enforced envelope already prevents abuse and SOC-gating a two-packet
owned-host exposure check would add operational cost without reducing real risk. This remains the
fallback if the guardrails above cannot be kept as enforced invariants.

## Consequences

| Positive | Negative |
|---|---|
| Customers can self-serve a real reflector-exposure readiness check. | Payload catalog names the same protocols an attacker would (mitigated by the envelope). |
| No SOC bottleneck for a bounded, owned-host check. | Guardrails must be defended by tests to stay honest. |
| Keeps AstraNull's "evidence over assumptions" promise for this vector. | Requires periodic review that the envelope has not drifted. |
