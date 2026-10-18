# AstraNull Efficacy Lab: fault-lab Status

## Metadata
- **Lab ID**: `fault-lab`
- **Compose Project**: `anl-fault-lab`
- **Container**: `anl-fault-lab-target`
- **Container Status**: UP (healthy)
- **Network Mode**: `none`
- **Status**: COMPLETE

## Milestones
- [x] Read and adhered to CONTRACT.md and safety rules.
- [x] Rebuilt Dockerfile from `tests/fixtures/connect-fault-lab/Dockerfile` under `labs/efficacy/envs/fault-lab/`.
- [x] Implemented `server.mjs` with exact tuple DROP rule (`127.0.0.1:40001 -> 127.0.0.1:18080`) and TCP listener on `127.0.0.1:18080`.
- [x] Implemented `healthcheck.mjs` verifying iptables rule presence and local TCP handshake.
- [x] Implemented `prove.mjs` executing two connect tuples and recording iptables counters.
- [x] Configured `docker-compose.yml` with `network_mode: none`, `cpus: 1.0`, `mem_limit: 768m`, capabilities restricted to `NET_ADMIN` and `NET_RAW`.
- [x] Created `manifest.json` marking 9 catalog checks `not_applicable` ("The signed probe worker cannot join network none").
- [x] Executed `up.sh` successfully: built image `anl-fault-lab-target:local`, started container, verified container health.
- [x] Executed proof inside container: Tuple 2 succeeds (handshake complete, 0 drops on DROP rule); Tuple 1 times out (DROP rule incremented by 2 packets / 120 bytes).
- [x] Exported proof artifacts to `/tmp/astranull-lab/fault-lab/proof.json` and `/tmp/astranull-lab/fault-lab/iptables-counters.txt`.
- [x] Generated `REPORT.md` with image IDs, resource caps, verification proofs, and limitations.
- [x] Lab container `anl-fault-lab-target` left running healthy.
