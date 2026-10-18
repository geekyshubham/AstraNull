# Efficacy Lab Status: nfw-router

- Initialized: 2026-10-17
- Lab ID: nfw-router
- Compose Project: anl-nfw-router
- Networks:
  - anl-nfw-router-client (172.31.31.0/24, internal: true)
  - anl-nfw-router-server (172.31.32.0/24, internal: true)
- Router: 172.31.31.2 (client net) / 172.31.32.2 (server net)
- Server: 172.31.32.10 (server net), probe target as seen from client net: 172.31.31.2 (and alias 172.31.31.10)
- Proof Client: 172.31.31.100 (client net)

## Progress

- [x] Initialized lab directory and STATUS.md
- [x] Implement router entrypoint and iptables rules
- [x] Implement multi-port server listener (TCP 80, 22, 8083, 8081, 8082; UDP 8053, 8054)
- [x] Configure docker-compose.yml with static IPs, internal networks, caps and sysctls
- [x] Write up.sh and down.sh scripts
- [x] Stand up anl-nfw-router stack and verify container health
- [x] Plant and execute proofs from client network (< 10 requests, no flood):
  - [x] Allowed TCP port (80) completes handshake (returns 200 origin-ok)
  - [x] Dropped TCP port (8081) times out (DROP after 3s)
  - [x] Rejected TCP port (8082) immediate RST refusal (0s)
  - [x] Allowed UDP port (8053) answers datagram (returns "ok")
  - [x] Dropped UDP port (8054) silent/dropped (times out)
  - [x] Connlimit TCP port (8083) allows 2 then rejects 3rd with ECONNREFUSED
  - [x] Management port (22) SSH banner reachable
- [x] Verify AstraNull check logic against contracts (nfw.declared_deny_tcp.safe, nfw.declared_deny_udp.safe, nfw.connection_limit.safe, nfw.management_port_exposure.safe, l3.basic_deny_rule.safe)
- [x] Write manifest.json with declarations and justified expectations
- [x] Generate comprehensive REPORT.md with image IDs, health proofs, and limitations
