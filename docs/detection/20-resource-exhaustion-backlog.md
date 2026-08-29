# Resource-Exhaustion Backlog

Tracks implementation of the [resource-exhaustion taxonomy](19-resource-exhaustion-taxonomy.md) against the master attack list (UDP/SYN/ACK floods, DNS laundering, HTTP/2 Rapid Reset, carpet bombing, reflection protocols, etc.).

**Source of truth:** `src/contracts/resourceExhaustionTaxonomy.mjs`  
**Validate:** `npm run vector:taxonomy:validate`  
**Progress tracker:** `PROGRESS.md` §4.1  
**Full family build spec:** [21-resource-exhaustion-family-build-spec.md](21-resource-exhaustion-family-build-spec.md)

## Task summary

| ID | Status | Scope | Acceptance |
|---|---|---|---|
| DET-016 | `[ ]` | Add `exhausted_resource`, `attack_vector_ids[]`, and optional `delivery_patterns[]` to every `CHECK_CATALOG` entry; extend vector heatmap and API `GET /v1/checks` response | All 65 checks mapped; validator requires field; unit tests |
| DET-017 | `[ ]` | L3/L4: ICMP, ACK/SYN-ACK/RST/FIN floods, fragmentation, GRE/ESP, out-of-state TCP, SIP/VoIP | New `check_id` entries + probe profiles or SOC markers per vector; matrix rows in `12-vector-test-matrix.md` |
| DET-018 | `[ ]` | Reflection/amplification: NTP, CLDAP, Memcached, SSDP, SNMP, WS-Discovery, TCP middlebox, etc. | Metadata exposure checks only — no reflection traffic generation |
| DET-019 | `[ ]` | Advanced DNS: laundering, garbage flood, phantom domain, lock-up, NXNSAttack, DNSBomb | Named checks + evidence model; correlate with resolver telemetry where available |
| DET-020 | `[ ]` | L7: HTTP POST flood, Slowloris/RUDY/slow-read, search/export/batch abuse, WordPress XML-RPC | Customer-declared endpoints; volumetric profiles where authorized |
| DET-021 | `[ ]` | HTTP/2–3: CONTINUATION flood, MadeYouReset, true Rapid Reset validation (not readiness-only), gRPC live probe | Protocol probe kinds in `capabilityProbes.mjs`; finish `protocol.grpc_reflection_stream.safe` |
| DET-022 | `[ ]` | Delivery patterns: carpet bombing, pulse-wave, spoofed flood, multi-vector UI | Scenario metadata on high-scale requests; dashboard coverage by pattern |
| DET-023 | `[ ]` | Volumetric probe profiles + signed-worker execution for authorized RPS/Gbps scenarios | Depends on SOC-011; governed caps in `probe_profile`; staging fleet evidence |
| DET-024 | `[ ]` | UI: resource-exhaustion matrix on dashboard/reports; readiness score by exhausted resource | Replace 5-family heatmap with 12-family view; link each cell to checks/findings |
| DET-025 | `[ ]` | CI harness: taxonomy validator in `make verify`; staging matrix maps ATT-* → live evidence | `npm run vector:taxonomy:validate` green; staging signoff artifact |
| DET-026 | `[ ]` | Operational/control-plane: health-check flood, autoscaling cost, alert blind spots, BGP/DNS integrity boundaries | ATT-109, ND-004–006; [Family Build Spec §13](21-resource-exhaustion-family-build-spec.md) |
| SOC-011 | `[ ]` | Governed volumetric execution: UDP/SYN/HTTP/DNS flood scenarios through partner adapter | Authorization pack binds scenario family + max rate; live telemetry ingestion; kill switch proof |

## Per-attack registry

The full ATT-* registry (**149 attack/exposure classes** + **8 WAF WV-*** + **9 ND-***) lives in code. Filter by status:

```bash
npm run vector:taxonomy:validate
node -e "import { ATTACK_VECTOR_REGISTRY } from './src/contracts/resourceExhaustionTaxonomy.mjs'; console.log(ATTACK_VECTOR_REGISTRY.filter(e=>e.coverage_status==='pending').map(e=>e.id+': '+e.name).join('\n'))"
```

## Completed foundation (not full taxonomy)

These DET rows delivered the **65-check defensive catalog** but do **not** close the resource-exhaustion taxonomy:

| ID | Delivers today | Taxonomy gap |
|---|---|---|
| DET-001–011 | Origin, L3/L4, DNS, L7, TLS, protocol readiness checks | Single-probe proxies; no volumetric floods |
| DET-012 | High-scale telemetry model | Telemetry schema; not live flood execution |
| DET-015 | Enterprise catalog expansion | ~40% partial coverage; ~50% pending per validator |

## Definition of done (full taxonomy)

A resource-exhaustion family is **done** when:

1. Every ATT-* row for that family is `implemented` or an explicit `soc_only` marker with governed execution path,
2. Each check declares `exhausted_resource` and evidence requirements,
3. UI/readiness score surfaces protection per resource layer,
4. Staging evidence exists for at least one live scenario per family (customer or SOC),
5. `npm run vector:taxonomy:validate` reports zero `pending` for that family **or** documents accepted SOC-only scope with product signoff.
