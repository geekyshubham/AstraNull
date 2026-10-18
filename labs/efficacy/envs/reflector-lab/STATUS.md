# AstraNull Efficacy Lab Status: reflector-lab

- **Lab ID**: `reflector-lab`
- **Compose Project**: `anl-reflector-lab`
- **Network**: `anl-reflector-lab-net` (Subnet: `172.31.42.0/24`, `internal: true`)
- **Targets**:
  - `anl-reflector-lab-exposed` (`172.31.42.10`)
  - `anl-reflector-lab-protected` (`172.31.42.20`)
- **Status**: RUNNING & VERIFIED

## Progress Log

- [x] Read `labs/efficacy/CONTRACT.md`, `labs/efficacy/briefs/reflector-lab.md`, and referenced source files:
  - `src/lib/reflectorPayloads.mjs`
  - `src/lib/safeNetworkProbes.mjs` (`classifyReflectionReply`)
  - `src/contracts/manifests/network-reflection.manifest.mjs`
  - `src/contracts/checks.mjs`
  - `src/services/correlation.mjs`
- [x] Designed minimal bounded reflection listeners conforming to classifiers:
  - CHARGEN (UDP 19) -> 62-byte bounded ASCII banner (`validateReflectionResponse` confirmed)
  - SSDP (UDP 1900) -> 105-byte HTTP 200 UPnP device banner (`validateReflectionResponse` confirmed)
  - STUN (UDP 3478) -> 20-byte Binding Success response echoing Transaction ID (`validateReflectionResponse` confirmed)
  - Redis (TCP 6379) -> TCP handshake responder (`inferredGap` confirmed)
- [x] Created `server.mjs`, `protected-server.mjs`, and `Dockerfile` in `labs/efficacy/envs/reflector-lab/`.
- [x] Created `docker-compose.yml` with `cpus: 1.0`, `mem_limit: 768m`, static IPs on `anl-reflector-lab-net`.
- [x] Created idempotent `up.sh` and cleanup `down.sh`.
- [x] Launched lab via `up.sh` on `172.31.42.0/24` with `internal: true`. Both containers healthy.
- [x] Ran throwaway container verification on `anl-reflector-lab-net`:
  - Exposed host health check (HTTP 200): PASS
  - Protected host health check (HTTP 200): PASS
  - Redis TCP handshake on exposed host (172.31.42.10:6379): PASS
  - CHARGEN bounded ASCII response (172.31.42.10:19, 62 bytes): PASS
  - SSDP UPnP 200 response (172.31.42.10:1900, 105 bytes): PASS
  - STUN binding success response (172.31.42.10:3478, 20 bytes): PASS
  - Protected host Redis TCP refusal ECONNREFUSED (172.31.42.20:6379): PASS
- [x] Verified all response sizes stay strictly under 4 KiB (max observed: 105 bytes).
- [x] Generated `manifest.json` with ground truth expectations and evidence justifications.
- [x] Generated `REPORT.md` with image IDs, health proofs, and limitations.
