# Lab Status: waf-crs-detect

- [x] Initialized workspace and lab directories (`labs/efficacy/envs/waf-crs-detect/`)
- [x] Inspected repo contracts, inert WAF markers, edge fingerprinting, and check definitions
- [x] Pulled required container images: `owasp/modsecurity-crs:nginx-alpine` and `nginx:1.27-alpine`
- [x] Constructed `docker-compose.yml`, `origin-default.conf`, and `bypass-low-port.sh`
- [x] Stood up environment `anl-waf-crs-detect` on network `anl-waf-crs-detect-net` (subnet: `172.31.22.0/24`) and verified health
- [x] Executed throwaway container proofs for plain `GET /` and exact inert markers (SQLi, XSS, Path Traversal)
- [x] Validated ModSecurity DetectionOnly audit logs and captured rule IDs (`942100`, `949110`, `930100`, `930110`, `920350`)
- [x] Created `up.sh`, `down.sh`, `manifest.json`, and comprehensive `REPORT.md`
- [x] Verified lab remains in running state for harness runner
