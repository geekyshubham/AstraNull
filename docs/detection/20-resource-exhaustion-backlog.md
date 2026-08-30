# Resource-Exhaustion Backlog

Tracks implementation of the [resource-exhaustion taxonomy](19-resource-exhaustion-taxonomy.md) against the master attack list (UDP/SYN/ACK floods, DNS laundering, HTTP/2 Rapid Reset, carpet bombing, reflection protocols, etc.).

**Source of truth:** `src/contracts/resourceExhaustionTaxonomy.mjs`<br>
**Validate:** `npm run vector:taxonomy:validate`<br>
**Progress tracker:** `PROGRESS.md` §4.1<br>
**Full family build spec:** [21-resource-exhaustion-family-build-spec.md](21-resource-exhaustion-family-build-spec.md)

## Task summary

> **Status 2026-08-29:** DET-016–022 and DET-026 have code-level catalog implementations (175-check catalog; zero pending registry vectors). DET-024 has the evidence-bound dashboard matrix but remains open for report/drill-down, bundle, accessibility, and staging parity. DET-025 has local/CI gates but remains open for parent full validation and staging ATT-* evidence. DET-023 + SOC-011 carry the governed scenario contract and authorization-pack binding; live partner execution remains external. See `PROGRESS.md` §4.1 for full notes.

| ID | Status | Scope | Acceptance |
|---|---|---|---|
| DET-016 | `[x]` (code) | Add `exhausted_resource`, `attack_vector_ids[]`, and optional `delivery_patterns[]` to every `CHECK_CATALOG` entry; extend vector heatmap and API `GET /v1/checks` response | All 175 checks mapped via `applyResourceExhaustionMetadata`; validator requires the field; unit tests. **External:** staging catalog signoff |
| DET-017 | `[x]` (code) | L3/L4: ICMP, ACK/SYN-ACK/RST/FIN floods, fragmentation, GRE/ESP, out-of-state TCP, SIP/VoIP | New `check_id` entries with bounded probe profiles or policy metadata per vector; registry rows upgraded. **External:** matrix staging evidence |
| DET-018 | `[x]` (code) | Reflection/amplification: NTP, CLDAP, Memcached, SSDP, SNMP, WS-Discovery, TCP middlebox, etc. | Full exposure inventory — one bounded fingerprint per declared host; no reflection traffic generation. **External:** live-edge validation |
| DET-019 | `[x]` (code) | Advanced DNS: laundering, garbage flood, phantom domain, lock-up, NXNSAttack, DNSBomb | Named checks + evidence model (bounded lookups + policy metadata). **External:** resolver staging evidence |
| DET-020 | `[x]` (code) | L7: HTTP POST flood, Slowloris/RUDY/slow-read, search/export/batch abuse, WordPress XML-RPC | Customer-declared endpoints; bounded low-rate validation profiles (≤5 requests); posture metadata for slow-client/limits. **External:** threshold staging evidence |
| DET-021 | `[x]` (code) | HTTP/2–3: CONTINUATION flood, MadeYouReset, Rapid Reset validation posture, gRPC live probe | New bounded `grpc_reflection_probe` (deferral closed); protocol readiness checks. **External:** protocol staging matrix; reset/handshake execution stays SOC-gated |
| DET-022 | `[x]` (code) | Delivery patterns: carpet bombing, pulse-wave, spoofed flood, multi-vector UI | Governed `delivery_patterns[]` on high-scale requests; pattern readiness checks; resource matrix family. **External:** SOC telemetry-driven timeline |
| DET-023 | `[~]` | Volumetric probe profiles + signed-worker execution for authorized RPS/Gbps scenarios | Governed scenario contract + authorization-pack caps binding delivered; depends on SOC-011 partner execution + staging fleet evidence for `[x]` |
| DET-024 | `[~]` | UI: resource-exhaustion matrix on dashboard/reports; readiness score by exhausted resource | Evidence-referenced 12-family React dashboard matrix and checks-page tabs delivered. **Remaining:** report/drill-down parity, committed bundle check, browser/accessibility matrix, and staging live-data signoff |
| DET-025 | `[~]` | CI harness: taxonomy validator in `make verify`; staging matrix maps ATT-* → live evidence | Code gates cover taxonomy, deterministic check-library output, and edge-corpus parity with zero current orphans/pending ATT entries. **Remaining:** parent full-suite run and staging signoff artifact |
| DET-026 | `[x]` (code) | Operational/control-plane: health-check flood, autoscaling cost, alert blind spots, BGP/DNS integrity boundaries | Health-check/autoscaling/alert-coverage checks; ND-001–003, ND-007–009 `monitor_only` boundaries; not scored in DDoS readiness |
| SOC-011 | `[~]` | Governed volumetric execution: UDP/SYN/HTTP/DNS flood scenarios through partner adapter | Authorization pack binds scenario family + max rate (enforced at SOC approve); telemetry + kill switch wired. **External:** certified partner adapter execution + staging fleet evidence |

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
