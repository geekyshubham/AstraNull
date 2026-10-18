# Efficacy Lab Status: waf-none

- Initialized: 2026-10-17
- Lab ID: waf-none
- Compose Project: anl-waf-none
- Subnet: 172.31.26.0/24 (internal: true)
- Target: 172.31.26.10:80

## Progress

- [x] Initialized lab directory and STATUS.md
- [x] Create nginx.conf
- [x] Create docker-compose.yml
- [x] Create up.sh and down.sh
- [!] Blocked: Docker daemon refuses network creation with `invalid pool request: Pool overlaps with other one on this address space` due to existing dead network `bgp-fixture-acceptance-20261014101054-60488_default` holding `172.31.0.0/16`. Awaiting user action or explicit authorization per hard safety rule forbidding touching `bgp-*` resources.
- [ ] Launch container and verify health
- [ ] Run throwaway container proofs for plain GET and inert SQLi, XSS, and path traversal markers
- [ ] Create manifest.json with ground truth expectations
- [ ] Generate REPORT.md
