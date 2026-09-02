# DDoS Vector Catalog

This catalog lists vectors AstraNull should understand for readiness validation. It is defensive: it defines validation intent, expected controls, safe evidence, and SOC-gated handling. It must not become a public unmanaged attack toolkit.

## Four-axis classification

The 721-row external catalog is classified on four independent axes. No single family label is used as a substitute for evidence quality or execution authority.

### Axis A — attack-surface domain

| ID | Domain | Outside-in reachability |
|---|---|---|
| A1a | IP / Transport Packet Processing | Partial; some vectors need governed packet generation. |
| A1b | LAN / Routing Control Plane | No; requires L2 adjacency or a peer session. |
| A1c | Wireless / RF | No; requires RF proximity. |
| A1d | Mobile / Telecom Signalling | No; requires a mobile-core interface. |
| A2 | Reflection & Amplification Exposure | Yes, with bounded protocol-correct requests to declared services. |
| A3 | DNS Service Exhaustion | Yes, with bounded DNS wire queries. |
| A4a | HTTP / API Application Exhaustion | Yes. |
| A4b | Non-HTTP Application Services | Yes, with service-specific clients. |
| A5 | Protocol Machinery | Yes, with H2/H3/QUIC/WebSocket/gRPC/TLS-aware clients. |
| A7 | Web Application Attack Classes | Yes for safe markers; offensive validation is SOC-governed. |
| A8 | Evasion & Delivery Patterns | Cross-cutting modifiers over reachable surfaces. |

A6 remains reserved for a possible future Edge / Origin Topology & Placement domain.

### Axis B — exhausted resource

The DDoS resource families are `volumetric`, `packet_processing`, `state_exhaustion`, `application_l7`, `computational`, `memory_exhaustion`, `backend_exhaustion`, `dns_exhaustion`, `reflection`, `amplification`, `exploit_dos`, and `delivery_pattern`. Web-application rows use the additional non-DDoS families `integrity_attack`, `access_control`, `data_exposure`, `automation_abuse`, and `ai_agentic`.

### Axis C — evidence tier

| Tier | Meaning |
|---|---|
| E0 | Unmapped: no implementation is mapped yet. |
| E1 | Declared only: metadata or a customer declaration, not an observed protocol fact. |
| E2 | Transport only: reachability, handshake, or similarly incomplete semantic evidence. |
| E3 | Semantic safe: a bounded safe probe establishes the relevant protocol/application fact. |
| E4 | SOC governed: evidence is available only through an approved SOC workflow. |
| E5 | Monitor only: evidence comes from monitoring rather than an outside-in probe. |

Tiers are derived at build time from the probe profile and are never hand-authored on registry entries. `pending` / E0 is a legitimate recorded state: it makes missing implementation visible without pretending a declaration or liveness check proves protection.

### Axis D — execution class

| Class | Meaning | Execution owner |
|---|---|---|
| `safe` | Bounded customer-runnable validation. | Authorized customer user. |
| `soc_gated` | Potentially disruptive, high-scale, or offensive validation. | AstraNull SOC after approval and scheduling. |

The current check catalog contains 232 `safe` and 17 `soc_gated` checks (249 total).

### Catalog-ID cross-reference

CSV identifiers (`NET-*`, `AMP-*`, `APP-*`, `WAF-*`, and `EVA-*`) are the canonical external keys. Every machine-readable registry entry lists its claimed rows in `catalog_vector_ids`; physically unreachable rows appear in `OUT_OF_SCOPE_VECTORS` with a reason code. This makes both catalog → AstraNull and AstraNull → catalog navigation deterministic, exposes the breadth of umbrella entries, and lets the validator reject unclaimed or duplicate IDs.

The 41 outside-in exclusions still get an honest **monitor-only detection** annotation in `MONITOR_ONLY_VECTORS` — passive detection only, never a fabricated active probe. The L2-adjacency floods (21) are genuinely agent-observable via local telemetry; the routing-peer (6), wireless-RF (9), and mobile-core (5) families are detection-only-if the customer integrates a routing-session feed, a WIDS/wireless sensor, or a mobile-core signalling tap respectively. See [Resource-Exhaustion Taxonomy → Monitor-only detection tier](19-resource-exhaustion-taxonomy.md#monitor-only-detection-tier-the-41-outside-in-exclusions). This is an annotation layer, so the 41 stay counted once via `OUT_OF_SCOPE_VECTORS`.

## Vector-to-evidence map

| Vector | External evidence | Internal evidence | Verdict focus |
|---|---|---|---|
| Direct origin | Probe response/timeout | Agent saw/did not see nonce | Bypassable vs protected. |
| Forbidden port | Connect/timeout/refused | Agent saw/did not see flow | Exposure vs block. |
| WAF marker | Response action | Agent saw/did not see marker | WAF rule enforcement. |
| Rate limit | Response trend | Agent/log observations | Threshold behavior. |
| DNS exposure | DNS response behavior | DNS logs/agent if configured | Exposure/readiness. |
| High-scale | Provider/adaptor metrics | Agent health + service health | Resilience and mitigation. |

## Catalog implementation (DET-015)

The production-safe catalog in `src/contracts/checks.mjs` maps matrix rows to versioned `check_id` entries. Customer-runnable checks use bounded allowlisted `probe_profile` kinds, from simple `http_head` / `tcp_connect` / `dns_resolve` / `metadata_marker` probes to fixed capability probes such as `host_sni_bypass`, `origin_leak_scan`, `port_scan_bounded`, DNS/TLS/protocol posture probes, and WAF marker/fingerprint probes. Each customer-runnable entry must carry `stop_conditions`, `evidence_required`, and `required_customer_setup`. Disruptive or high-scale matrix rows (connection exhaustion, multi-vector drills, provider telemetry validation, kill-switch drills) are **SOC-gated request markers** without customer probe profiles.

This catalog is defensive metadata: it must not be interpreted as a library of amplification, reflection, spoofing, or unmanaged traffic-generation recipes.

The committed 721-row projection names the source column neutrally as `targeted_resource_or_assumption`. The vector-library contract never turns that catalog target into a result: it publishes no `detects` field. Instead it separates `intended_detection_goal` (marked as intent, not observation), `evidence_capability`, `execution_disposition`, `failure_means`, and `expected_controls`. APP-003 and NET-016 are explicit invariants: both remain E4 / SOC-governed and `soc_gated_only`, while their E1 declaration checks are retained only through `metadata_available` and `metadata_check_ids`. APP-001 is the semantic-safe E3 rate-limit example.

## Resource-exhaustion taxonomy

DDoS attacks are also classified by **what resource they exhaust** (bandwidth, packet-processing, TCP state, DNS QPS, application RPS, etc.). See [Resource-Exhaustion Taxonomy](19-resource-exhaustion-taxonomy.md) and the machine-readable registry in `src/contracts/resourceExhaustionTaxonomy.mjs`. Validate coverage with `npm run vector:taxonomy:validate`.

## How to read coverage numbers

Catalog coverage and evidence coverage answer different questions:

- **Catalog accounting: 721/721 rows (100%)** — 680 rows are claimed by a registry entry and 41 are explicitly out of outside-in scope; 0 are unclaimed and 0 are duplicated.
- **Evidence coverage: 680/680 claimed rows (100%) have non-E0 evidence** — E1: 104, E2: 39, E3: 271, E4: 258, and E5: 8. With the 41 explicit outside-in exclusions, the complete library has E5: 49. Authoritative E4 outranks supplemental E1/E2 evidence, while genuine E3 semantic-safe evidence outranks E4. Execution dispositions are 414 safe-validation available, 258 SOC-gated only, and 49 monitor-only; there are 0 E0 / `pending` rows.

Catalog accounting therefore does not mean that every vector is implemented or empirically validated. These figures are the current 2026-09-01 post-remediation validator snapshot. The [coverage audit](22-vector-coverage-audit-2026-09-01.md) is retained as a clearly labeled pre-remediation baseline for source-catalog methodology and defect history; use the validator, not its historical totals, for release accounting.

## Completion criteria

The vector catalog is complete when every check in the product maps to a vector family, safety class, evidence requirement, stop conditions, and verdict logic.
