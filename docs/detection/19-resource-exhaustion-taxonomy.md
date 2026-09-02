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

Evidence tiers are **derived at build time from the probe profile and never hand-authored** on taxonomy entries. When one registry claim maps multiple checks, authoritative precedence is **E3 > E4 > E2 > E1 > E0**: a genuine semantic-safe result may establish bounded behavior, but an E1/E2 declaration or transport check cannot downgrade an E4 SOC-governed vector into safe validation. Supplemental declaration availability is retained separately as `metadata_available` and `metadata_check_ids`. The derived compatibility status is `implemented` for E3, `partial` for E1/E2, `soc_only` for E4, and `pending` for E0. E5 remains monitor-only and outside the probe-derived DDoS readiness result.

`pending` / E0 is a legitimate recorded state. It means the catalog row is accounted for but no implementation establishes its fact yet. It must remain visible rather than being replaced by a no-op metadata check or a fabricated SOC suite.

## Coverage status (validated snapshot)

Run `npm run vector:taxonomy:validate` for the current counts. In the current registry:

| Status | Meaning |
|---|---|
| `implemented` | Dedicated catalog check with live probe |
| `partial` | Readiness proxy or single-probe metadata check |
| `soc_only` | SOC request marker only; no customer flood |
| `pending` | Documented in taxonomy; no catalog check yet |

The DDoS-scored registry currently contains 249 entries: 79 E3 / `implemented`, 84 E1–E2 / `partial`, 86 E4 / `soc_only`, and 0 E0 / `pending`. Five additional ATT entries use non-DDoS exhausted-resource families and are excluded from that scoring summary.

## How to read coverage numbers

Catalog coverage and evidence coverage are separate measurements:

- **Catalog accounting: 721/721 rows (100%)** — 680 are claimed by registry entries and 41 carry explicit outside-in exclusion reasons. There are 0 unclaimed rows and 0 duplicate claims.
- **Evidence coverage: 680/680 claimed rows (100%) have non-E0 evidence** — E1: 104 catalog rows, E2: 39, E3: 271, E4: 258, and E5: 8. With the 41 explicit outside-in exclusions, the complete 721-row library has E5: 49. Execution dispositions are 414 safe-validation available, 258 SOC-gated only, and 49 monitor-only. There are 0 E0 / `pending` rows.

The first number proves every catalog row has an accountable disposition. The second describes what evidence AstraNull can actually produce today; it must not be inferred from the first. Figures are from the current 2026-09-01 post-remediation validation snapshot. The [vector coverage audit](22-vector-coverage-audit-2026-09-01.md) is retained as a clearly labeled pre-remediation baseline for source-catalog methodology and defect history; its historical totals are not release accounting.

## Monitor-only detection tier (the 41 outside-in exclusions)

The 41 rows in `OUT_OF_SCOPE_VECTORS` cannot be safely **originated** by an outside-in SaaS probe — they need L2 adjacency, an accepted routing peer session, RF proximity, or a mobile-core interface. AstraNull never fabricates an active probe for them. They still receive **honest monitor-only detection coverage** in `MONITOR_ONLY_VECTORS`: passive detection where the customer already runs the right observer. This is an **annotation layer**, not an active test — the 41 rows remain counted exactly once via `OUT_OF_SCOPE_VECTORS`, so `MONITOR_ONLY_VECTORS` adds no catalog claim and no duplicate. Every entry is tagged evidence tier **E5** (monitor-only, outside the probe-derived DDoS readiness result), mirroring the existing `NON_DDOS_AVAILABILITY_THREATS` pattern.

`detection_mode` is one of two values:

- `agent_local_telemetry` — AstraNull's passive, outbound-only on-host agent (`agents/linux/astranull-agent.mjs`) observes the flood in local interface counters, netlink neighbor/route churn, and kernel/syslog. Genuinely useful passive detection.
- `integration_telemetry` — detection depends on a customer-supplied feed or sensor. Where that sensor is uncommon, coverage is honestly **detection-only-if-integrated**.

| Family (reason) | Rows | detection_mode | dependency | Honest coverage statement |
|---|---|---|---|---|
| L2-adjacency (`requires_l2_adjacency`) | 21 | `agent_local_telemetry` | `on_network_agent_required` | Genuinely useful passive detection. ARP/CAM/DHCP/STP/802.1X/ND/IGMP floods show up in local interface counters, netlink tables, and syslog on any host the agent runs on inside the affected L2/broadcast domain. |
| Routing-peer (`requires_routing_peer_session`) | 6 | `integration_telemetry` | `routing_session_feed_required` | Detection-only-if-integrated. BGP/OSPF/BFD/PIM/MPLS control floods are visible only through a routing-session-state feed (router telemetry, BMP export). |
| Wireless-RF (`requires_rf_proximity`) | 9 | `integration_telemetry` | `wireless_sensor_required` | Detection-only-if-integrated. 802.11 management/control-frame floods and RF jamming are detectable **only** where a WIDS / wireless / spectrum sensor is deployed. Most customers lack one; without it these are honestly not covered, because no SaaS probe can hear the RF. |
| Mobile-core (`requires_mobile_core_interface`) | 5 | `integration_telemetry` | `mobile_core_tap_required` | Detection-only-if-integrated, telco deployments only. GTP-U/GTP-C/PFCP/Diameter/attach signalling floods require a mobile-core signalling tap that only carrier operators possess. |

Passive detection is not active testing: it reports what a locally-placed observer sees, never a readiness score derived from an AstraNull-originated attack. The validator (`scripts/validate-resource-exhaustion-taxonomy.mjs`) cross-checks that `MONITOR_ONLY_VECTORS` covers exactly the 41 out-of-scope ids, once each, with the family-correct `detection_mode`/`dependency`, and surfaces the breakdown under `monitor_only` in the validation JSON.

## Task backlog

See [Resource-Exhaustion Backlog](20-resource-exhaustion-backlog.md) and `PROGRESS.md` §4.1 (DET-016–DET-026, SOC-011).
