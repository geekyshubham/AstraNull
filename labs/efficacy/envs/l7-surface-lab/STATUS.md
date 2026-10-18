# Status — l7-surface-lab

## 2026-10-17 19:55
- Read CONTRACT.md, lab brief, and repository guidelines.
- Identified target lab specs:
  - Lab ID: `l7-surface-lab`
  - Compose project: `anl-l7-surface-lab`
  - Network: `anl-l7-surface-lab-net` (172.31.53.0/24, internal: true)
  - Target: 172.31.53.10 port 80 (nginx:1.27-alpine)
  - Resources: cpus <= 1.0, mem_limit <= 768m
- Analyzed relevant AstraNull check implementations:
  - `l7.cors_posture.safe`: probes OPTIONS with Origin `https://probe.invalid.astranull`; triggers inferred gap when origin is reflected and `Access-Control-Allow-Credentials: true` is present.
  - `l7.api_surface_scan.safe`: observation-only probe (E2) against doc/API paths; responds to `/api/health` with JSON; returns inconclusive verdict per correlation engine.
  - `l7.http_method_restriction.safe`: observation-only probe (E2) that evaluates HEAD and OPTIONS; does not send disallowed methods; returns inconclusive verdict per correlation engine. Method rejection (405 on POST) planted and verified.
  - Other checks (`l7.login_abuse_flow.safe`, `l7.graphql_complexity.safe`, `l7.webhook_flood.readiness`, `l7.slowloris.readiness`) are marked not_applicable.

## 2026-10-17 20:05
- Created `nginx.conf`, `docker-compose.yml`, `up.sh`, and `down.sh`.
- Started lab via `up.sh`: `anl-l7-surface-lab-target` is up and reporting healthy.
- Verified planted conditions via throwaway containers on `anl-l7-surface-lab-net`:
  - Condition 1 (CORS): `OPTIONS /` reflected Origin `https://probe.invalid.astranull` and set `Access-Control-Allow-Credentials: true`.
  - Condition 2 (API Surface): `GET /api/health` and `HEAD /api/health` returned HTTP 200 with `application/json`.
  - Condition 3 (Method Restriction): `GET /` -> 200, `HEAD /` -> 200, `POST /` -> 405, `PUT /` -> 405, `DELETE /` -> 405, `OPTIONS /` -> 204 with `Allow: GET, HEAD, OPTIONS`.
- Generated `manifest.json` with ground truth expectations and justifications.
- Generated `REPORT.md` with image inspection ID, health proofs, and limitations.
- Lab left running for harness runners.
