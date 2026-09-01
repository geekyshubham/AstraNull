# Resource-Exhaustion DDoS Taxonomy

DDoS is broader than “send lots of traffic.” AstraNull classifies attacks by **what resource they exhaust**, aligned with AWS Layer 3/4 and Layer 7 groupings and modern vectors (QUIC floods, HTTP/2 Rapid Reset, DNS laundering, carpet bombing, reflection protocols).

## Master taxonomy

| Family | What attacker exhausts | Typical metric | Examples |
|---|---|---:|---|
| **Volumetric** | Internet/link bandwidth | Gbps/Tbps | UDP, ICMP, amplification |
| **Packet-processing** | Routers/firewalls/NIC/CPU | Mpps/Bpps | ACK, RST, fragmented packets |
| **State exhaustion** | Connection/session tables | CPS / concurrent states | SYN flood, TCP connection flood |
| **Application L7** | Web/app capacity | RPS | HTTP GET/POST floods |
| **Computational** | CPU | CPU %, RPS | TLS, expensive API requests |
| **Memory exhaustion** | RAM/buffers/queues | connections/streams | Slowloris, HTTP/2 attacks |
| **Backend exhaustion** | DB/cache/internal APIs | queries/sec | Search/API/GraphQL floods |
| **DNS exhaustion** | Authoritative/resolver capacity | QPS | DNS flood, water torture |
| **Reflection** | Victim receives unsolicited traffic | pps/bps | DNS/NTP/CLDAP reflectors |
| **Amplification** | Small request → huge response | amplification ratio | Memcached/DNS/NTP |
| **Exploit-based DoS** | Protocol/software bug | varies | Ping of Death, HTTP/2 flaws |
| **Delivery pattern** | How the attack is deployed | n/a | Carpet bombing, multi-vector |

Machine-readable registry: `src/contracts/resourceExhaustionTaxonomy.mjs`<br>
Validation: `npm run vector:taxonomy:validate`<br>
**Full build spec (all 12 families + gaps):** [Resource-Exhaustion Family Build Spec](21-resource-exhaustion-family-build-spec.md)

## Relationship to the four-axis catalog

The [vector catalog](01-vector-catalog.md) classifies every row on four orthogonal axes: attack-surface domain, exhausted resource, evidence tier, and execution class. This document describes the exhausted-resource axis in detail. It is used for:

- readiness scoring (“which resources are actually protected?”),
- SOC scenario selection,
- gap reporting against industry attack taxonomies.

Every `check_id` in `src/contracts/checks.mjs` carries derived `exhausted_resource` and `exhausted_resources` metadata (DET-016). Registry entries link back to canonical CSV rows through `catalog_vector_ids`, using `NET-*`, `AMP-*`, `APP-*`, `WAF-*`, and `EVA-*` identifiers. Rows that cannot be reached from an outside-in SaaS probe are recorded separately in `OUT_OF_SCOPE_VECTORS` with an auditable boundary reason.

## Evidence-tier model

| Tier | Label | Derivation |
|---|---|---|
| E0 | Unmapped | No mapped check implementation. |
| E1 | Declared only | `probe_profile.kind === 'metadata_marker'`. |
| E2 | Transport only | Probe kind is observation-only, excluding `metadata_marker`. |
| E3 | Semantic safe | A bounded probe kind establishes a protocol/application fact. |
| E4 | SOC governed | Mapped check has no customer probe profile and executes only through SOC governance. |
| E5 | Monitor only | Non-probe operational or provider monitoring evidence. |

Evidence tiers are **derived at build time from the probe profile and never hand-authored** on taxonomy entries. The derived compatibility status is `implemented` for E3, `partial` for E1/E2, `soc_only` for E4, and `pending` for E0. E5 remains monitor-only and outside the probe-derived DDoS readiness result.

`pending` / E0 is a legitimate recorded state. It means the catalog row is accounted for but no implementation establishes its fact yet. It must remain visible rather than being replaced by a no-op metadata check or a fabricated SOC suite.

## Coverage status (validated snapshot)

Run `npm run vector:taxonomy:validate` for the current counts. In the current registry:

| Status | Meaning |
|---|---|
| `implemented` | Dedicated catalog check with live probe |
| `partial` | Readiness proxy or single-probe metadata check |
| `soc_only` | SOC request marker only; no customer flood |
| `pending` | Documented in taxonomy; no catalog check yet |

The DDoS-scored registry currently contains 249 entries: 58 E3 / `implemented`, 82 E1–E2 / `partial`, 9 E4 / `soc_only`, and 100 E0 / `pending`. Five additional ATT entries use non-DDoS exhausted-resource families and are excluded from that scoring summary.

## How to read coverage numbers

Catalog coverage and evidence coverage are separate measurements:

- **Catalog accounting: 721/721 rows (100%)** — 680 are claimed by registry entries and 41 carry explicit outside-in exclusion reasons. There are 0 unclaimed rows and 0 duplicate claims.
- **Evidence coverage: 356/680 claimed rows (52.4%) have non-E0 evidence** — E1: 83 catalog rows, E2: 72, E3: 145, E4: 48, and E5: 8. The remaining 324 claimed rows are E0 / `pending`.

The first number proves every catalog row has an accountable disposition. The second describes what evidence AstraNull can actually produce today; it must not be inferred from the first. Figures are from the 2026-09-01 validation snapshot. See the [vector coverage audit](22-vector-coverage-audit-2026-09-01.md) for the source catalog, methodology, and detailed gap register.

## Task backlog

See [Resource-Exhaustion Backlog](20-resource-exhaustion-backlog.md) and `PROGRESS.md` §4.1 (DET-016–DET-026, SOC-011).
