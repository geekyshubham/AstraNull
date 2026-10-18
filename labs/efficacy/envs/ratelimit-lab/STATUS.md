# Efficacy Lab Status: ratelimit-lab

- Initialized: 2026-10-17
- Lab ID: `ratelimit-lab`
- Compose Project: `anl-ratelimit-lab`
- Subnet: `172.31.52.0/24` (internal: true)
- Limited Target: `172.31.52.10:80`
- Unlimited Target: `172.31.52.11:80`

## Progress

- [x] Review CONTRACT.md, lab brief, control-declarations schema, and checks (`waf.low_rate_limit.safe`, `waf.rate_limit_canary.validation`, `l7.low_rate_rate_limit.safe`)
- [x] Implement `html/index.html` (`origin-ok`) and `html/canary` (`canary-ok`)
- [x] Implement `nginx-limited.conf` (`limit_req_zone $binary_remote_addr zone=canary_limit:10m rate=18r/m; burst=2 nodelay; limit_req_status 429;`) with recognizable JSON 429 body
- [x] Implement `nginx-unlimited.conf` without rate limiting
- [x] Create `docker-compose.yml` with CPU (1.0) and memory (768m) caps and static IPv4 allocations
- [x] Create idempotent `up.sh` and `down.sh`
- [x] Stand up environment with `up.sh`: both origins healthy on `172.31.52.10` and `172.31.52.11`
- [x] Run throwaway container verification (`curlimages/curl:latest`) on `anl-ratelimit-lab-net`:
  - Limited origin: requests 1-3 returned 200, request 4 returned 429 with `{"error":"rate_limited","message":"Rate limit exceeded: 3 requests per 10s"}`
  - Unlimited origin: requests 1-4 returned 200
  - Health checks: GET / returned 200 on both origins
- [x] Create `manifest.json` with ground truth declarations and expectations
- [x] Create `REPORT.md` documenting image IDs, configuration, behavioral proof, and limitations
- [x] Lab left running for harness runners
