# Efficacy Lab Status: tls-proto-lab

- **Lab ID**: `tls-proto-lab`
- **Compose Project**: `anl-tls-proto-lab`
- **Network**: `anl-tls-proto-lab-net` (Subnet: `172.31.51.0/24`, `internal: true`)
- **Status**: Complete `[x]`

## Timeline & Progress

1. **[x] Requirement Analysis & Code Inspection**
   - Verified CONTRACT.md and safety rules (172.31.0.0/16, no attack tools, read-only repo, resource caps).
   - Inspected `src/lib/capabilityProbes.mjs` (`probeTlsAudit`), `src/lib/safeNetworkProbes.mjs` (`probeHttp2Settings`, `readHttp2RemoteSettings`), and `src/services/correlation.mjs` (`correlateExternalOnlyVerdict`, `correlateInferredMissingControl`).
   - Confirmed verdict logic for `tls.full_audit.safe`: detects `cert_expired` (days_to_expiry < 0) and `certificate_not_yet_valid` (valid_from > Date.now()), triggering an inferred gap (`exposed`).
   - Analyzed `protocol.http2_stream_concurrency.safe` probe implementation and identified defect in `src/lib/safeNetworkProbes.mjs:1211` where `ALPNProtocols: ['h2']` is missing from `tlsConnectFn`.

2. **[x] Synthetic Certificate Generation**
   - Implemented `certs/generate-certs.py` using Python `cryptography.x509`.
   - Created synthetic keypairs and certificates:
     - `expired.crt`: Not Valid After 2026-01-01 00:00:00 GMT (-290 days expired on 2026-10-17).
     - `not_yet_valid.crt`: Not Valid Before 2028-01-01 00:00:00 GMT (+440 days in future).
     - `valid_h2.crt`: Valid from 2025-01-01 to 2028-01-01 GMT.

3. **[x] Service Configuration & Docker Compose Setup**
   - Created Nginx configurations `conf/expired-nginx.conf` and `conf/not-yet-valid-nginx.conf`.
   - Created Node.js HTTP/2 server `server-h2.js` advertising default unbounded streams (`maxConcurrentStreams = 4294967295`).
   - Created `docker-compose.yml` defining:
     - `anl-tls-proto-lab-expired` at `172.31.51.10:443`
     - `anl-tls-proto-lab-not-yet-valid` at `172.31.51.11:443`
     - `anl-tls-proto-lab-h2-unbounded` at `172.31.51.12:443`
   - Added container resource caps (`cpus: 0.5`, `mem_limit: 128m`) and healthchecks.
   - Built idempotent `up.sh` and cleanup `down.sh`.

4. **[x] Verification & Proof Collection**
   - Started environment using `up.sh`. All 3 services reported healthy.
   - Verified memory usage with `docker stats`: ~16 MiB total across all 3 containers.
   - Verified TLS handshakes and certificate dates via throwaway curl container on `anl-tls-proto-lab-net`.
   - Simulated exact AstraNull probe logic with throwaway Node.js container on `anl-tls-proto-lab-net`.
   - Tested HTTP/2 SETTINGS frame capture and confirmed probe defect reproduction.

5. **[x] Manifest & Reporting**
   - Generated `manifest.json` following `astranull.efficacy-lab.v1` schema.
   - Documented findings, image IDs, and defect reproduction in `REPORT.md`.
