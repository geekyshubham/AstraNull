# AstraNull Efficacy Lab Report: harness

## Summary

- **Lab ID**: `harness`
- **Compose Project**: `anl-harness`
- **Network**: `anl-harness-net` (`172.31.10.0/24`, `internal: false`)
- **Docker Image IDs**:
  - `alpine:3.20`: `sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc`
  - `node:22-alpine`: `sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402`
- **Readiness Signal**: `labs/efficacy/harness/READY`

## Interface Built

`run-checks.sh` provides the contract-mandated CLI:
```bash
./labs/efficacy/harness/run-checks.sh --manifest <path> [--checks id1,id2 | --prefix waf.] --out <dir>
```

When invoked, the harness:
1. Spawns an ephemeral AstraNull control-plane instance on `127.0.0.1:3011` using local Postgres (`54329`) with dev auth headers (`ten_anl_harness`) and auto-verification (`ASTRANULL_DEMO_AUTO_VERIFY_TENANTS=ten_anl_harness`).
2. Spawns a signed probe worker container (`anl-harness-probe-worker`) dual-homed onto `anl-harness-net` (to access the host API at `http://host.docker.internal:3011`) and all target networks declared in `manifest.networks` (to probe target IPs in `172.31.0.0/16`).
3. Normalizes and registers targets (`url`, `ip`, `tcp`, `fqdn`) matching check compatibility.
4. Applies declared control policies (`network_policy`, `connection_limits`, `waf`) via `PUT /v1/targets/:id/control-declarations`.
5. Enforces hard safety filters against volumetric, flood, slowloris, or unmanaged amplification checks (`skipped_safety`).
6. Dispatches checks (`POST /v1/test-runs`), polls terminal verdicts, and computes confusion matrix metrics (`detected gap`, `missed gap`, `false alarm`, `correct protected`, `inconclusive`, `not_applicable`, `skipped_safety`).
7. Writes `<out>/results.jsonl` and `<out>/summary.md`.

## Health Proof & Smoke Validation

1. **Host Reachability Proof**:
   Container on `anl-harness-net` verified reachability to host API:
   ```bash
   GET http://host.docker.internal:3011/ready => 200 OK
   ```

2. **Dual-Network Dialing Proof**:
   Worker container on `anl-harness-net` + `anl-waf-none-net` dialed target directly:
   ```bash
   GET http://172.31.26.10/ => 200 origin-ok
   ```

3. **Live Smoke Test against `waf-none` Lab**:
   Command:
   ```bash
   ./labs/efficacy/harness/run-checks.sh --manifest labs/efficacy/envs/waf-none/manifest.json --out /tmp/astranull-lab/harness/smoke-waf-all
   ```
   Results:
   - `waf.sqli_managed_marker.safe`: Expected `gap`, AstraNull Verdict `exposed` -> **detected gap**
   - `waf.xss_managed_marker.safe`: Expected `gap`, AstraNull Verdict `exposed` -> **detected gap**
   - `waf.path_traversal_managed_marker.safe`: Expected `gap`, AstraNull Verdict `exposed` -> **detected gap**
   - `waf.fingerprint.safe`: Expected `inconclusive_expected`, AstraNull Verdict `inconclusive` -> **inconclusive**

   **Confusion Matrix**:
   - Detected Gap: 3
   - Missed Gap: 0
   - False Alarm: 0
   - Correct Protected: 0
   - Inconclusive: 1
   - Not Applicable: 0
   - Skipped Safety: 0

4. **Safety Filter Proof**:
   Executed test manifest containing `l7.slowloris.readiness` and `l3.smtp_connection_flood.readiness`:
   Both checks were intercepted and recorded as `skipped_safety` without dispatching network traffic.

## Limitations & Architecture Notes

1. **Mac / Colima Routing**: Mac host cannot route directly to internal container IPs (`172.31.0.0/16`). All AstraNull probe execution is isolated inside containerized signed workers attached to the lab networks.
2. **Database Integrity**: Local Postgres (`astranull-postgres-local`) was preserved without resetting or reseeding. The harness only ensured the 84 existing migrations were applied and synthetic tenant `ten_anl_harness` existed.
3. **Control Declarations**: `waf.block_signature` strictly requires `header_name` and `header_value` under the API validator; manifests declaring only `{ status: 403, body_contains: "..." }` have their status evaluated by catalog matching or omitted from header validation.
