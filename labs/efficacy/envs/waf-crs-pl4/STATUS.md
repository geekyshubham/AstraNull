# Lab Status: waf-crs-pl4

- [x] Initialized lab directory and review requirements
- [x] Create origin nginx configuration returning HTTP 200 `origin-ok`
- [x] Create docker-compose.yml with resource limits (cpus: 1.0, mem_limit: 768m) and internal network `anl-waf-crs-pl4-net` (172.31.24.0/24)
- [x] Create bypass-low-port.sh to permit non-root/root port 80 binding
- [x] Start lab with `up.sh` and verify health check (plain GET / returns HTTP 200 origin-ok)
- [x] Verify inert SQLi marker blocking (HTTP 403 Forbidden across query, header, path)
- [x] Verify inert XSS marker blocking (HTTP 403 Forbidden)
- [x] Verify inert path-traversal marker blocking (HTTP 403 Forbidden)
- [x] Verify evasion variants blocking (case-fold, comment, double-URL, scanner UA all return HTTP 403 Forbidden)
- [x] Create manifest.json with ground truth expectations
- [x] Generate comprehensive REPORT.md with image IDs, health proofs, and limitations
