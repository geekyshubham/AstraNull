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

Machine-readable registry: `src/contracts/resourceExhaustionTaxonomy.mjs`  
Validation: `npm run vector:taxonomy:validate`  
**Full build spec (all 12 families + gaps):** [Resource-Exhaustion Family Build Spec](21-resource-exhaustion-family-build-spec.md)

## Relationship to vector families

The existing [vector catalog](01-vector-catalog.md) groups checks by **protocol/surface** (origin, L3/L4, DNS, L7, TLS, protocol). The resource-exhaustion taxonomy is an **orthogonal axis** used for:

- readiness scoring (“which resources are actually protected?”),
- SOC scenario selection,
- gap reporting against industry attack taxonomies.

Each `check_id` in `src/contracts/checks.mjs` will gain an `exhausted_resource` field (DET-016).

## Coverage status (validated snapshot)

Run `npm run vector:taxonomy:validate` for the current counts. As of the initial registry:

| Status | Meaning |
|---|---|
| `implemented` | Dedicated catalog check with live probe |
| `partial` | Readiness proxy or single-probe metadata check |
| `soc_only` | SOC request marker only; no customer flood |
| `pending` | Documented in taxonomy; no catalog check yet |

Most industry attack classes remain **`pending`** or **`partial`** — the 65-check catalog covers readiness validation, not full volumetric execution of every vector. As of the extended registry: **149 ATT-*** attack/exposure classes, **8 WV-*** WAF vulnerability checks, **9 ND-*** operational threats; validator requires **zero orphan catalog checks**.

## Task backlog

See [Resource-Exhaustion Backlog](20-resource-exhaustion-backlog.md) and `PROGRESS.md` §4.1 (DET-016–DET-026, SOC-011).
