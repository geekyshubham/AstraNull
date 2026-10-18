# AstraNull Efficacy Lab Report: reflector-lab

## Executive Summary

- **Lab ID**: `reflector-lab`
- **Compose Project**: `anl-reflector-lab`
- **Lab Network**: `anl-reflector-lab-net` (`172.31.42.0/24`, `internal: true`)
- **Containers**:
  - `anl-reflector-lab-exposed` (`172.31.42.10`)
  - `anl-reflector-lab-protected` (`172.31.42.20`)
- **Execution State**: RUNNING & HEALTHY (both containers healthy)

## Image Digests

Recorded via `docker image inspect --format '{{.Id}}'`:

- **Lab Service Image (`anl-reflector-lab-server:local`)**:
  `sha256:0c57431bcf66105a36f6ecd8831060ceff46a48a35e2f964233d62c595e05483`
- **Base Image (`node:22-alpine`)**:
  `sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402`

## Services & Planted Conditions

### 1. Exposed Target (`anl-reflector-lab-exposed`, `172.31.42.10`)

Deliberately exposes 4 services matching AstraNull's safe outside-in reflection and cache classifiers without edge filtering:

1. **Redis Cache (TCP 6379)**:
   - Listens on TCP 6379, completes TCP handshakes directly.
   - Satisfies `reflect.redis_direct_exposure.safe` (`tcp_connect` probe).
   - Expected verdict: **`gap`** (`inferredGap('high', ...)` in `src/services/correlation.mjs:771-776`).
2. **CHARGEN Responder (UDP 19)**:
   - Responds to bounded trigger queries with a 62-byte printable ASCII banner ending in `\r\n`.
   - Response: `"RFC864 CHARGEN TEST SERVICE REFLECTOR-LAB ASTRANULL-EFFICACY\r\n"`.
   - Validated against `validateReflectionResponse('chargen_trigger', ...)` in `src/lib/reflectorPayloads.mjs:201-205`.
   - Expected verdict: **`gap`** (`correlateReflectorExposure` in `src/services/correlation.mjs:290-300`).
3. **SSDP / UPnP Responder (UDP 1900)**:
   - Responds to `M-SEARCH * HTTP/1.1` discovery probes with a 105-byte HTTP 200 OK device banner with `ST: upnp:rootdevice` and valid `USN: uuid:...`.
   - Validated against `validateReflectionResponse('ssdp_msearch', ...)` in `src/lib/reflectorPayloads.mjs:177-192`.
   - Expected verdict: **`gap`** (`correlateReflectorExposure` in `src/services/correlation.mjs:290-300`).
4. **STUN Responder (UDP 3478)**:
   - Responds to STUN Binding Requests (`0x0001`, magic cookie `0x2112a442`) with a 20-byte Binding Success response (`0x0101`) echoing the 12-byte Transaction ID.
   - Validated against `validateReflectionResponse('stun_binding_request', ...)` in `src/lib/reflectorPayloads.mjs:102-112`.
   - Expected verdict: **`gap`** (`correlateReflectorExposure` in `src/services/correlation.mjs:290-300`).

### 2. Protected Target (`anl-reflector-lab-protected`, `172.31.42.20`)

Simulates a hardened endpoint where reflection and database/cache ports are not listening and refuse connections:

1. **Redis Cache (TCP 6379)**:
   - Closed port. TCP SYN probe receives TCP RST (`ECONNREFUSED`).
   - Satisfies `tcpExternalResult(outcome) === 'blocked'` in `src/lib/safeNetworkProbes.mjs:562`.
   - Expected verdict: **`protected`** (createsFinding: false).

## Verification Proofs (Throwaway Container)

Executed from a throwaway container attached to `anl-reflector-lab-net`:

```text
=== ASTRANULL EFFICACY LAB: REFLECTOR-LAB VERIFICATION ===
[PASS] Exposed Host Health: HTTP 200 -> {"status":"healthy","service":"anl-reflector-lab-exposed","chargen_udp":19,"ssdp_udp":1900,"stun_udp":3478,"redis_tcp":6379}
[PASS] Protected Host Health: HTTP 200 -> {"status":"healthy","service":"anl-reflector-lab-protected","reflectors_exposed":false}
[PASS] Redis TCP (172.31.42.10:6379): Handshake + PING -> "+PONG\r\n"
[PASS] CHARGEN UDP (172.31.42.10:19): Reply length: 62 bytes, validateReflectionResponse=true, text: "RFC864 CHARGEN TEST SERVICE REFLECTOR-LAB ASTRANULL-EFFICACY\r\n"
[PASS] SSDP UDP (172.31.42.10:1900): Reply length: 105 bytes, validateReflectionResponse=true
[PASS] STUN UDP (172.31.42.10:3478): Reply length: 20 bytes, type=0x101, cookie=0x2112a442, echoTxId=true, validateReflectionResponse=true
[PASS] Protected Host Redis TCP (172.31.42.20:6379): Connection refused as expected (ECONNREFUSED)
=== VERIFICATION SUMMARY ===
Total tests: 7, Passed: 7, Failed: 0
```

## Hard Safety Limit Compliance

| Requirement | Limit | Measured / Observed | Status |
|---|---|---|---|
| Maximum reply size | < 4 KiB (4096 B) | CHARGEN: 62 B, SSDP: 105 B, STUN: 20 B, Redis: 7 B | PASS (All < 110 B) |
| Monlist / Memcached stats | None permitted | Not implemented; `amp.memcached_exposure.safe` marked `not_applicable` | PASS |
| Amplification ratio | No amplifying payloads | 1:1 or sub-1:1 bounded answers only | PASS |
| Spoofed source traffic | Strictly forbidden | Single direct unicast replies to probe source IP | PASS |
| Resource caps | cpus <= 1.0, mem <= 768m | Configured: `cpus: 1.0`, `mem_limit: 768m` on both services | PASS |
| Network isolation | 172.31.0.0/16, internal: true | `172.31.42.0/24`, `internal: true` | PASS |
| Existing resource protection | Never touch `bgp-*` / postgres | Untouched; all resources prefixed `anl-reflector-lab-` | PASS |

## Manifest Expectations & Rationale

| Target | Check ID | Expected | Justification |
|---|---|---|---|
| `172.31.42.10` | `reflect.redis_direct_exposure.safe` | `gap` | Port 6379 accepts TCP handshake from external probe without firewall or authentication |
| `172.31.42.10` | `reflect.chargen_qotd_exposure.safe` | `gap` | Bounded UDP 19 responder answers with ASCII stream matching `validateReflectionResponse` |
| `172.31.42.10` | `reflect.ssdp_exposure.safe` | `gap` | Bounded UDP 1900 responder answers M-SEARCH probe with valid UPnP device banner matching `validateReflectionResponse` |
| `172.31.42.10` | `reflect.stun_turn_exposure.safe` | `gap` | UDP 3478 responder echoes Transaction ID with STUN Binding Success matching `validateReflectionResponse` |
| `172.31.42.10` | `reflect.ipp_callback_exposure.safe` | `not_applicable` | `src/lib/probeEvidenceTiers.mjs:2` explicitly marks `ipp_get_printer_attributes` as unsupported delivery with no approved execution adapter |
| `172.31.42.10` | `amp.memcached_exposure.safe` | `not_applicable` | Requires UDP stats dumps (`src/contracts/checks.mjs:2309`, `src/lib/reflectorPayloads.mjs:117-125`), barred by CONTRACT.md hard safety limits against amplification generators |
| `172.31.42.20` | `reflect.redis_direct_exposure.safe` | `protected` | Port 6379 is closed; TCP connect attempt is refused (`ECONNREFUSED` / RST), confirming edge/host protection |

## Limitations

1. **Host-to-Container Routing on macOS / Colima**:
   The host macOS kernel cannot route traffic directly to Colima's internal Docker bridge network (`172.31.42.0/24`). As prescribed in CONTRACT.md, all verification probes and proofs were conducted using a throwaway container attached to `anl-reflector-lab-net`.
2. **Amplification Prohibitions**:
   Full reflection amplification vectors (e.g., NTP monlist, Memcached UDP large stat dumps) are intentionally not simulated in accordance with defensive safety rules; instead, protocol-validated exposure is verified using exact bounded RFC request/reply structures under 110 bytes.
