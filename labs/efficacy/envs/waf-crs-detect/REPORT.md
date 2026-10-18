# AstraNull Efficacy Lab Report: waf-crs-detect

## 1. Environment & Architecture Summary

- **Lab ID**: `waf-crs-detect`
- **Compose Project**: `anl-waf-crs-detect`
- **Network**: `anl-waf-crs-detect-net` (Subnet: `172.31.22.0/24`, `internal: true`)
- **Target**: `172.31.22.10:80`
- **Planted Condition**: ModSecurity Core Rule Set (CRS 4) running in `SecRuleEngine DetectionOnly` mode in front of an Nginx origin returning HTTP 200 `origin-ok` for all paths. The WAF actively inspects traffic and triggers rules, but does not block any request.

### Container Images & IDs
- **ModSecurity CRS WAF Target (`anl-waf-crs-detect-waf`)**:
  - Image: `owasp/modsecurity-crs:nginx-alpine`
  - Digest/ID: `sha256:f12da37e72e29d1f06e7e829780f1016606d0799eac2966e58ef3819a3d30a50`
  - Resource caps: `cpus: 1.0`, `mem_limit: 768m`
- **Backend Origin (`anl-waf-crs-detect-origin`)**:
  - Image: `nginx:1.27-alpine`
  - Digest/ID: `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`
  - Resource caps: `cpus: 1.0`, `mem_limit: 768m`
- **Throwaway Probe Container**:
  - Image: `curlimages/curl:8.10.1`
  - Digest/ID: `sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b`

---

## 2. Health & Planted Condition Proofs

All proofs were executed from a throwaway container attached to `anl-waf-crs-detect-net`.

### Proof 1: Baseline Health Request (`GET /`)
- **Command**:
  ```bash
  docker run --rm --network anl-waf-crs-detect-net curlimages/curl:8.10.1 -i -s http://172.31.22.10/
  ```
- **Observed Response**:
  ```http
  HTTP/1.1 200 OK
  Date: Sat, 17 Oct 2026 14:35:05 GMT
  Content-Type: text/plain
  Content-Length: 10
  Connection: keep-alive
  Server: nginx
  Access-Control-Allow-Headers: *

  origin-ok
  ```

### Proof 2: Exact Inert SQLi Marker (`astranull' OR '1'='0`)
- **Command**:
  ```bash
  docker run --rm --network anl-waf-crs-detect-net curlimages/curl:8.10.1 -i -s "http://172.31.22.10/?astranull_sqli_probe=astranull%27%20OR%20%271%27=%270"
  ```
- **Observed Response**:
  ```http
  HTTP/1.1 200 OK
  Date: Sat, 17 Oct 2026 14:35:09 GMT
  Content-Type: text/plain
  Content-Length: 10
  Connection: keep-alive
  Server: nginx
  Access-Control-Allow-Headers: *

  origin-ok
  ```
  *(Confirmed: request is not blocked; reaches origin and returns HTTP 200 origin-ok)*

- **WAF Detection Audit Log Evidence**:
  - Producer: `"secrules_engine": "DetectionOnly"`, `"components": ["OWASP_CRS/4.30.0"]`
  - Interrupted: `false`
  - Detected Rule IDs:
    - **Rule ID `942100`**: `"SQL Injection Attack Detected via libinjection"`
      - Match detail: `s&sos found within ARGS:astranull_sqli_probe: astranull' OR '1'='0'`
      - Config file: `/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf:46`
    - **Rule ID `949110`**: `"Inbound Anomaly Score Exceeded (Total Score: 8)"`
      - Config file: `/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf:222`
    - **Rule ID `920350`**: `"Host header is a numeric IP address"`
      - Config file: `/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf:756`

### Proof 3: Exact Inert XSS Marker (`<astranull-xss-probe/>`)
- **Command**:
  ```bash
  docker run --rm --network anl-waf-crs-detect-net curlimages/curl:8.10.1 -i -s "http://172.31.22.10/?astranull_xss_probe=%3Castranull-xss-probe/%3E"
  ```
- **Observed Response**: HTTP/1.1 200 OK, body `origin-ok`. Request is permitted through.

### Proof 4: Exact Inert Path Traversal Marker (`../../astranull-probe`)
- **Command**:
  ```bash
  docker run --rm --network anl-waf-crs-detect-net curlimages/curl:8.10.1 -i -s "http://172.31.22.10/?astranull_path_traversal_probe=../../astranull-probe"
  ```
- **Observed Response**: HTTP/1.1 200 OK, body `origin-ok`. Request is permitted through.
- **WAF Detection Audit Log Evidence**:
  - **Rule ID `930100`**: `"Path Traversal Attack (/../) or (/.../)"` (Matched Data: `/../` within `ARGS:astranull_path_traversal_probe`)
  - **Rule ID `930110`**: `"Path Traversal Attack (/../) or (/.../)"` (Matched Data: `../` within `ARGS:astranull_path_traversal_probe`)
  - **Rule ID `949110`**: `"Inbound Anomaly Score Exceeded (Total Score: 23)"`

---

## 3. Catalog Check Expectations Justification

1. `waf.sqli_managed_marker.safe`: **`gap`**
   - Managed SQLi marker probe expects `must_block_before_origin`. In DetectionOnly mode, ModSecurity flags the marker but forwards it to origin; HTTP 200 `origin-ok` is returned. AstraNull `correlateClassMarkerVerdict` maps `not_enforced` to exposed (`gap`).
2. `waf.xss_managed_marker.safe`: **`gap`**
   - Managed XSS marker probe reaches origin and returns HTTP 200 `origin-ok` without interruption (`gap`).
3. `waf.path_traversal_managed_marker.safe`: **`gap`**
   - Managed path traversal marker probe reaches origin and returns HTTP 200 `origin-ok` without interruption (`gap`).
4. `waf.fingerprint.safe`: **`inconclusive_expected`**
   - Check probe kind is `waf_fingerprint_observation`, an observation-only probe registered in `OBSERVATION_ONLY_PROBE_KINDS` (`src/lib/probeEvidenceTiers.mjs`).
   - In `src/services/correlation.mjs`, `correlateObservationOnlyVerdict` unconditionally outputs `verdict: 'inconclusive'`.
   - Furthermore, DetectionOnly CRS returns `Server: nginx` without any ModSecurity block page (which only occurs upon HTTP 403/406 blocks), matching no passive vendor signature in `src/lib/edgeFingerprint.mjs`.

---

## 4. Limitations & Operational Notes

- **Network Isolation**: The network `anl-waf-crs-detect-net` is configured with `internal: true`. There is no outbound internet access.
- **Colima Host Routing**: The macOS host cannot route to container private IPs (172.31.22.x). All probe verification must be performed by attaching containers to `anl-waf-crs-detect-net`.
- **Low Port Binding**: OWASP CRS nginx container runs with `PORT=80` using a mounted bypass for `/docker-entrypoint.d/01-check-low-port.sh` and root privileges (`user: "0:0"`).
- **Project State**: Left running per contract for harness runner execution.
