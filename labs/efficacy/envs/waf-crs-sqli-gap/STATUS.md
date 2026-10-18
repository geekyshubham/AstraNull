# AstraNull Efficacy Lab Status: waf-crs-sqli-gap

- **Lab ID**: `waf-crs-sqli-gap`
- **Compose Project**: `anl-waf-crs-sqli-gap`
- **Subnet**: `172.31.23.0/24` (internal: true)
- **Target**: `172.31.23.10:80`
- **Origin**: `172.31.23.11:80`
- **Status**: Complete & Verified

## Progress Checklist

- [x] Review `CONTRACT.md`, safety guidelines, and `src/lib/inertWafMarkers.mjs`
- [x] Pull and verify required container images:
  - `owasp/modsecurity-crs:nginx-alpine@sha256:f12da37e72e29d1f06e7e829780f1016606d0799eac2966e58ef3819a3d30a50`
  - `nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`
  - `curlimages/curl:latest@sha256:a134550be58ab783810e613ae96fd253c38f7bdd16d9bf9be350700c7a29ac06`
- [x] Configure origin nginx responding `origin-ok` (`origin.conf`)
- [x] Configure CRS target in blocking mode (`MODSEC_RULE_ENGINE=on`, `BLOCKING_PARANOIA=1`) with REQUEST-942 excluded (`empty-942.conf`, `bypass-low-port.sh`)
- [x] Build and test compose stack on `anl-waf-crs-sqli-gap-net` (`172.31.23.0/24`)
- [x] Execute throwaway container proofs from lab network:
  - `GET /` returns HTTP 200 `origin-ok`
  - Exact SQLi marker (`astranull' OR '1'='0`) returns HTTP 200 `origin-ok` in query, path, and header (SQLi gap proven)
  - Exact XSS marker (`<astranull-xss-probe/>`) returns HTTP 200 `origin-ok` (CRS does not detect inert tag)
  - Path traversal marker (`../../astranull-probe`) returns HTTP 403 Forbidden (other CRS rules active)
  - Scanner UA marker (`sqlmap/1.8 (astranull-inert)`) returns HTTP 403 Forbidden (other CRS rules active)
- [x] Create idempotent `up.sh` and cleanup `down.sh`
- [x] Generate ground truth `manifest.json`
- [x] Document image IDs, health proofs, detection limitation analysis in `REPORT.md`
- [x] Leave environment running for harness runners
