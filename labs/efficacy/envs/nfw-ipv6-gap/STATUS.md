# Efficacy Lab Status: nfw-ipv6-gap

- Initialized: 2026-10-17
- Lab ID: nfw-ipv6-gap
- Compose Project: anl-nfw-ipv6-gap
- Network: anl-nfw-ipv6-gap-net (internal: true, enable_ipv6: true)
- Subnets: 172.31.33.0/24 and fd00:a57a:33::/64
- Target Static IPs: 172.31.33.10 and fd00:a57a:33::10
- Ports:
  - TCP 80: Health endpoint (open on IPv4 and IPv6, returns 200 "healthy\n")
  - TCP 8080: App endpoint under test (dropped on IPv4 by iptables, open on IPv6, returns 200 "app-ok\n")

## Progress

- [x] Verified safety rules, contract, and brief requirements
- [x] Initialized lab directory and STATUS.md
- [x] Implement dual-stack listener and iptables policy dropping chosen TCP port (8080) on IPv4 only
- [x] Configure docker-compose.yml with limits (cpus <= 1.0, mem_limit <= 768m)
- [x] Write up.sh and down.sh scripts
- [x] Launch lab and verify health on both IPv4 and IPv6
- [x] Prove planted condition with throwaway container (single connect each on IPv4 and IPv6)
- [x] Write manifest.json with ground truth expectations
- [x] Generate REPORT.md with image IDs, health proofs, and limitations
