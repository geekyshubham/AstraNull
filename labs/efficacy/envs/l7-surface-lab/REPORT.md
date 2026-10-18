# Efficacy Lab Report: l7-surface-lab

## Environment Overview

- **Lab ID**: `l7-surface-lab`
- **Location**: `/Users/checkred_admin/Projects/astranull/labs/efficacy/envs/l7-surface-lab/`
- **Compose Project**: `anl-l7-surface-lab`
- **Network**: `anl-l7-surface-lab-net` (`internal: true`)
- **Subnet**: `172.31.53.0/24` (Gateway: `172.31.53.1`)
- **Target**: `172.31.53.10:80` (`anl-l7-surface-lab-target`)
- **Resource Constraints**: `cpus: 1.0` (1,000,000,000 NanoCPUs), `mem_limit: 768m` (805,306,368 bytes)

## Image IDs

| Image | Tag | Inspect ID (`docker image inspect --format '{{.Id}}'`) |
|---|---|---|
| `nginx` | `1.27-alpine` | `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10` |

## Health Proof

The target container was launched using `up.sh` and verified healthy via Docker health check (`wget -q -O /dev/null http://127.0.0.1/api/health`):

```bash
$ docker inspect anl-l7-surface-lab-target --format 'IP: {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}} | Status: {{.State.Status}} (Health: {{.State.Health.Status}})'
IP: 172.31.53.10 | Status: running (Health: healthy)
```

## Planted Conditions & Independent Verification Proofs

All proofs were executed inside isolated throwaway containers (`nginx:1.27-alpine` running `curl`) attached to `anl-l7-surface-lab-net`.

### 1. CORS Posture Gap (`l7.cors_posture.safe`)
- **Planted Behavior**: Preflight `OPTIONS /` request reflects arbitrary request `Origin` in `Access-Control-Allow-Origin` and sets `Access-Control-Allow-Credentials: true`.
- **Proof Command**:
  ```bash
  docker run --rm --network anl-l7-surface-lab-net nginx:1.27-alpine \
    curl -s -i -X OPTIONS \
      -H "Origin: https://probe.invalid.astranull" \
      -H "Access-Control-Request-Method: GET" \
      http://172.31.53.10/
  ```
- **Observed Response**:
  ```http
  HTTP/1.1 204 No Content
  Server: nginx/1.27.5
  Access-Control-Allow-Origin: https://probe.invalid.astranull
  Access-Control-Allow-Credentials: true
  Access-Control-Allow-Methods: GET, HEAD, OPTIONS
  Access-Control-Allow-Headers: DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,x-astranull-marker
  Allow: GET, HEAD, OPTIONS
  Content-Type: text/plain; charset=utf-8
  Content-Length: 0
  ```
- **AstraNull Correlation**: `probeCorsPosture` in `src/lib/capabilityProbes.mjs:2757` detects `access_control_allow_origin === 'https://probe.invalid.astranull'` and `credentials_advertised === true`. Correlation at `src/services/correlation.mjs:791` evaluates this as an inferred missing control yielding `verdict: 'exposed'` (`gap`).

### 2. API Surface Observation (`l7.api_surface_scan.safe`)
- **Planted Behavior**: Valid `/api/health` JSON endpoint responding to GET and HEAD with HTTP 200 and `application/json`.
- **Proof Command**:
  ```bash
  docker run --rm --network anl-l7-surface-lab-net nginx:1.27-alpine \
    curl -s -i http://172.31.53.10/api/health
  ```
- **Observed Response**:
  ```http
  HTTP/1.1 200 OK
  Server: nginx/1.27.5
  Content-Type: application/json
  Content-Length: 43
  Access-Control-Allow-Credentials: true
  Access-Control-Allow-Methods: GET, HEAD, OPTIONS
  Allow: GET, HEAD, OPTIONS

  {"status":"ok","service":"l7-surface-lab"}
  ```
- **AstraNull Correlation**: `probeApiSurfaceScan` in `src/lib/capabilityProbes.mjs:2694` issues HEAD requests to API paths. Because `api_surface_scan` belongs to `OBSERVATION_ONLY_PROBE_KINDS` and does not have an inference rule, correlation in `src/services/correlation.mjs:922` produces `verdict: 'inconclusive'` (`inconclusive_expected`).

### 3. HTTP Method Restriction (`l7.http_method_restriction.safe`)
- **Planted Behavior**: GET and HEAD return HTTP 200; disallowed methods (POST, PUT, DELETE) return HTTP 405 Method Not Allowed; OPTIONS returns HTTP 204 with `Allow: GET, HEAD, OPTIONS`.
- **Proof Commands & Observed Responses**:
  - `GET /` -> `HTTP/1.1 200 OK`
  - `HEAD /` -> `HTTP/1.1 200 OK`
  - `POST /` -> `HTTP/1.1 405 Not Allowed`
  - `PUT /` -> `HTTP/1.1 405 Not Allowed`
  - `DELETE /` -> `HTTP/1.1 405 Not Allowed`
  - `OPTIONS /` with marker -> `HTTP/1.1 204 No Content` with `Allow: GET, HEAD, OPTIONS`
- **AstraNull Correlation**: `probeHttpMethodMatrix` in `src/lib/capabilityProbes.mjs:1458` tests only `HEAD` and `OPTIONS` to extract `Allow` header metadata. It does not send state-changing methods to verify 405 enforcement. As an observation-only probe (`src/lib/probeEvidenceTiers.mjs:18`), correlation in `src/services/correlation.mjs:922` returns `verdict: 'inconclusive'` (`inconclusive_expected`).

## Exclusions & Not Applicable Checks

Per safety rules and contract constraints:
- `l7.login_abuse_flow.safe`: `not_applicable` (no login flow deployed)
- `l7.graphql_complexity.safe`: `not_applicable` (no GraphQL endpoint deployed)
- `l7.webhook_flood.readiness`: `not_applicable` (no webhook listener deployed)
- `l7.slowloris.readiness`: `not_applicable` (slowloris traffic generators strictly forbidden)

## Limitations

- Initial compose up briefly hit `invalid pool request: Pool overlaps with other one on this address space` due to an exited 3-day-old acceptance test network occupying `172.31.0.0/16`. Per safety rules forbidding touching `bgp-*` resources, the agent halted until the network was resolved externally on the host. Once resolved, the lab network `172.31.53.0/24` came up cleanly.
- Colima host routing limitation: The host cannot route directly to `172.31.53.10`. All verification probes were conducted via ephemeral throwaway containers directly attached to `anl-l7-surface-lab-net`.
- Target container is left RUNNING for harness check execution.
