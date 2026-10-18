# AstraNull Efficacy Lab Status: waf-crs-block

- **Lab ID**: `waf-crs-block`
- **Compose Project**: `anl-waf-crs-block`
- **Subnet**: `172.31.21.0/24` (internal: true)
- **Target**: `172.31.21.10:80`
- **Origin**: `172.31.21.11:80`
- **Lifecycle State**: RUNNING & Healthy

## Progress Checklist

- [x] Review `CONTRACT.md`, safety guidelines, and `src/lib/inertWafMarkers.mjs`
- [x] Pull pinned images:
  - `owasp/modsecurity-crs:nginx-alpine@sha256:f12da37e72e29d1f06e7e829780f1016606d0799eac2966e58ef3819a3d30a50`
  - `nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`
  - `curlimages/curl:8.10.1@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b`
- [x] Configure origin reverse proxy stack (`origin.conf`, `bypass-low-port.sh`, `docker-compose.yml`)
- [x] Create idempotent `up.sh` and safe `down.sh`
- [x] Launch compose stack `anl-waf-crs-block` with `up.sh`
- [x] Execute live throwaway container proofs on `anl-waf-crs-block-net` at `172.31.21.10:80`:
  - `GET /` returns HTTP 200 `origin-ok`
  - SQLi marker (`astranull' OR '1'='0`) blocked with HTTP 403 Forbidden
  - Path traversal marker (`../../astranull-probe`) blocked with HTTP 403 Forbidden
  - XSS marker (`<astranull-xss-probe/>`) allowed through with HTTP 200 (CRS does not detect inert tag)
  - Scanner UA (`sqlmap/1.8 (astranull-inert)`) blocked with HTTP 403 Forbidden
  - Case-folded SQLi blocked with HTTP 403 Forbidden
  - Double URL-encoded SQLi blocked with HTTP 403 Forbidden
  - Canary tokens (`astranull-ssti-marker-inert`, `astranull-prototype-marker-inert`) return HTTP 200
- [x] Record block signature (`status: 403`, `body_contains: "403 Forbidden"`)
- [x] Create ground truth `manifest.json`
- [x] Document image IDs, health proofs, limitations, and findings in `REPORT.md`
- [x] Lab left RUNNING for harness runners
