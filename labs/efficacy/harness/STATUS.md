# AstraNull Efficacy Lab Status: harness

- **Lab ID**: harness
- **Compose Project**: `anl-harness`
- **Network**: `anl-harness-net` (subnet: `172.31.10.0/24`, `internal: false`)
- **Holder Container**: `anl-harness-holder` (image: `alpine:3.20`)
- **Status**: Complete & Ready (`labs/efficacy/harness/READY` created)

## Progress

- [x] Review CONTRACT.md, lab brief, control-plane APIs, and signed probe worker design
- [x] Create `docker-compose.yml` for project `anl-harness` (`172.31.10.0/24`)
- [x] Create `up.sh` and `down.sh` with resource prefixes (`anl-harness-*`)
- [x] Bring up harness network and holder container
- [x] Verify local Postgres (`astranull-postgres-local`) on port 54329 with all 84 migrations applied
- [x] Register synthetic tenant `ten_anl_harness` in Postgres `tenants` table without reset/reseed
- [x] Prove host reachability from container on `anl-harness-net` via `host.docker.internal:3011`
- [x] Prove multi-network reachability from probe worker container to target lab network (`anl-waf-none-net`)
- [x] Implement `runner.mjs` with:
  - CLI argument parsing (`--manifest`, `--checks`, `--prefix`, `--out`, `--help`)
  - Ephemeral API control plane lifecycle on `127.0.0.1:3011` with dev auth headers
  - Ephemeral signed probe worker on dual networks (`anl-harness-net` + target lab networks)
  - Target creation and control declarations application (`PUT /v1/targets/:id/control-declarations`)
  - Test run dispatch (`POST /v1/test-runs`) and polling to terminal state
  - Hard safety filter (`skipped_safety`) rejecting volumetric/flood/slowloris checks
  - Grading against manifest expectations with confusion matrix
  - Output generation for `<out>/results.jsonl` and `<out>/summary.md`
- [x] Implement executable `run-checks.sh` wrapper and verify `--help`
- [x] Execute live smoke test against `labs/efficacy/envs/waf-none/manifest.json` (3 detected gaps, 1 inconclusive)
- [x] Create `READY` signal file
- [x] Document image IDs, health proofs, and limitations in `REPORT.md`
