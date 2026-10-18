# dns-lab Implementation Status

## Target
- Lab ID: `dns-lab`
- Compose project: `anl-dns-lab`
- Lab network: `anl-dns-lab-net` (Subnet: `172.31.41.0/24`, `internal: true`)
- Target container IP: `172.31.41.10`
- Authoritative synthetic zone: `lab.efficacy.invalid`
- Running Container: `anl-dns-lab-server` (healthy)

## Progress Log
- [x] Initialized lab directory `labs/efficacy/envs/dns-lab/`
- [x] Configured BIND 9.18.49 authoritative server and synthetic zone file `lab.efficacy.invalid.zone`
- [x] Created Dockerfile and docker-compose.yml with resource caps (`cpus: 1.0`, `mem_limit: 768m`)
- [x] Created `up.sh` (idempotent, health-checked) and `down.sh` cleanup scripts
- [x] Launched `anl-dns-lab-server` container and verified healthy status
- [x] Proved authoritative NOERROR for served names (`app.lab.efficacy.invalid` -> 172.31.41.20, AA=1)
- [x] Proved NXDOMAIN for random prefix inside zone (`random-nonexistent-subdomain.lab.efficacy.invalid` -> NXDOMAIN, AA=1)
- [x] Proved single NS record (`ns1.lab.efficacy.invalid`) demonstrating secondary failover gap
- [x] Proved unauthenticated AXFR zone transfer allowed to clients on lab net (9 records, 321 bytes over TCP 53)
- [x] Proved closed recursion (`example.com +recurse` -> REFUSED, RA=0, no queries leave container)
- [x] Proved minimal ANY response (`minimal-any yes`, 158 bytes, no amplification)
- [x] Created `manifest.json` with ground truth expectations and verification commands
- [x] Documented image digests, health evidence, and daemon pool overlap limitation in `REPORT.md`
