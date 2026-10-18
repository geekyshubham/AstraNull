# AstraNull Efficacy Lab Report: ratelimit-lab

## Summary

- **Lab ID**: `ratelimit-lab`
- **Compose Project**: `anl-ratelimit-lab`
- **Network**: `anl-ratelimit-lab-net` (Subnet: `172.31.52.0/24`, `internal: true`)
- **Limited Origin**: `172.31.52.10:80` (`anl-ratelimit-lab-limited`)
- **Unlimited Origin**: `172.31.52.11:80` (`anl-ratelimit-lab-unlimited`)
- **Status**: Running and healthy

## Container Images & IDs

Image IDs captured via `docker image inspect --format '{{.Id}}'`:

- **Target Origins (`nginx:1.27-alpine`)**:
  `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`
- **Throwaway Proof Container (`curlimages/curl:latest`)**:
  `sha256:a134550be58ab783810e613ae96fd253c38f7bdd16d9bf9be350700c7a29ac06`

## Planted Conditions & Configuration

### Limited Origin (`172.31.52.10`)
- Configured with `limit_req_zone $binary_remote_addr zone=canary_limit:10m rate=18r/m;`.
  18 requests per minute equals 3 requests per 10 seconds (0.3 r/s).
- Applied on `location /` with `limit_req zone=canary_limit burst=2 nodelay;`.
  A rapid burst allows request 1 (excess 0), request 2 (excess 1 <= burst), request 3 (excess 2 <= burst), and rejects request 4 (excess 3 > burst).
- Configured with `limit_req_status 429;` and `error_page 429 = @rate_limited;` returning:
  `{"error":"rate_limited","message":"Rate limit exceeded: 3 requests per 10s"}`.

### Unlimited Origin (`172.31.52.11`)
- Configured without rate limiting. All requests return 200 OK.

## Ground Truth & Manifest Expectations

### Control Declarations
Declared under target metadata:
```json
{
  "waf": {
    "rate_limit_canary": {
      "path": "/canary",
      "method": "GET",
      "threshold": 3,
      "window_seconds": 10,
      "expected_action": "block"
    }
  }
}
```

### Check Expectations

1. `waf.rate_limit_canary.validation`:
   - **Limited Origin (`172.31.52.10`)**: `expected: "protected"`
     - *Justification*: Threshold is 3. Probe sends bounded requests (up to `min(threshold + 2, 8) = 5`). Requests 1-3 succeed (200), request 4 returns 429. `first_limited_at` is 4 (`threshold < limitedIndex <= threshold + 2`), `allowed_before_limit` is 3 (`>= threshold`). Per `correlateRateLimitCanary` in `src/services/correlation.mjs`, this evaluates to `verdict: 'protected'`.
   - **Unlimited Origin (`172.31.52.11`)**: `expected: "gap"`
     - *Justification*: Origin never throttles. All 5 requests return 200 OK. `requests_sent` (5) > threshold (3) and `allowed_before_limit` (5) > threshold (3). Per `correlateRateLimitCanary` in `src/services/correlation.mjs`, this evaluates to `verdict: 'exposed'` (`createsFinding: true`).

2. `waf.low_rate_limit.safe` & `l7.low_rate_rate_limit.safe`:
   - **Both Origins**: `expected: "inconclusive_expected"`
     - *Justification*: Both checks execute probe kind `rate_limit_sequence`. In `src/lib/probeEvidenceTiers.mjs`, `rate_limit_sequence` is an `OBSERVATION_ONLY_PROBE_KINDS` (E2 observation). In `src/services/correlation.mjs`, all observation-only probes are evaluated by `correlateObservationOnlyVerdict` returning `verdict: 'inconclusive'` ("rate_limit_sequence recorded transport or liveness metadata only; it did not establish this check's verdict logic").

## Verification Evidence (Throwaway Container Probes)

Executed from throwaway container `curlimages/curl:latest` attached to `anl-ratelimit-lab-net`:

### Health Check (GET /)
```
Testing limited origin (172.31.52.10):
HTTP/1.1 200 OK
Server: nginx/1.27.5
Content-Type: text/html
Content-Length: 10

Testing unlimited origin (172.31.52.11):
HTTP/1.1 200 OK
Server: nginx/1.27.5
Content-Type: text/html
Content-Length: 10
```

### Limited Origin Canary Proof (http://172.31.52.10/canary)
```
=== PROOF FOR LIMITED ORIGIN (172.31.52.10) ===
--- Request 1 ---
canary-ok
HTTP_STATUS: 200

--- Request 2 ---
canary-ok
HTTP_STATUS: 200

--- Request 3 ---
canary-ok
HTTP_STATUS: 200

--- Request 4 ---
{"error":"rate_limited","message":"Rate limit exceeded: 3 requests per 10s"}
HTTP_STATUS: 429
```

### Unlimited Origin Canary Proof (http://172.31.52.11/canary)
```
=== PROOF FOR UNLIMITED ORIGIN (172.31.52.11) ===
--- Request 1 ---
canary-ok
HTTP_STATUS: 200

--- Request 2 ---
canary-ok
HTTP_STATUS: 200

--- Request 3 ---
canary-ok
HTTP_STATUS: 200

--- Request 4 ---
canary-ok
HTTP_STATUS: 200
```

## Limitations & Operational Notes

- **Network Isolation**: Lab network `anl-ratelimit-lab-net` is `internal: true` with no internet egress.
- **Leaky Bucket Dynamics**: At 18r/m, 1 request token is replenished every ~3.33 seconds (full 3-token replenishment in 10 seconds). Consecutive probe runs must allow 10 seconds between test executions to observe the full 3-request allowance before 429 throttling.
- **Resource Limits**: Both containers strictly adhere to resource caps (`cpus: 1.0`, `mem_limit: 768m`).
- **Lab State**: The lab remains running as required by CONTRACT.md.
