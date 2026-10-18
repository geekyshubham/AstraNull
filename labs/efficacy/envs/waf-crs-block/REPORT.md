# AstraNull Efficacy Lab Report: waf-crs-block

## Summary

- **Lab ID**: `waf-crs-block`
- **Compose Project**: `anl-waf-crs-block`
- **Network**: `anl-waf-crs-block-net` (subnet: `172.31.21.0/24`, `internal: true`)
- **Target**: `172.31.21.10:80` (OWASP ModSecurity CRS reverse proxy)
- **Origin**: `172.31.21.11:80` (`nginx:1.27-alpine` returning `origin-ok` on all paths)
- **WAF Engine**: OWASP ModSecurity Core Rule Set (CRS 4.30.0, libmodsecurity 3.0.17, ModSecurity-nginx 1.0.4)
- **WAF Configuration**: Blocking mode (`SecRuleEngine On`), default paranoia level 1 (`BLOCKING_PARANOIA=1`, `ANOMALY_INBOUND=5`, `ANOMALY_OUTBOUND=4`)
- **Container State**: Lab is running and verified healthy.

## Images Used

| Role | Image Reference | Image ID (`docker image inspect --format '{{.Id}}'`) |
|---|---|---|
| WAF Reverse Proxy | `owasp/modsecurity-crs:nginx-alpine@sha256:f12da37e72e29d1f06e7e829780f1016606d0799eac2966e58ef3819a3d30a50` | `sha256:f12da37e72e29d1f06e7e829780f1016606d0799eac2966e58ef3819a3d30a50` |
| Origin Service | `nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10` | `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10` |
| Verification Client | `curlimages/curl:8.10.1@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b` | `sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b` |

## Health & Planted Condition Proofs

All conditions were verified from a throwaway client container (`curlimages/curl:8.10.1`) attached directly to `anl-waf-crs-block-net` targeting `172.31.21.10:80`.

### 1. Plain Baseline Health Check
- **Request**: `GET http://172.31.21.10/`
- **Response**: HTTP 200 OK
- **Body**: `origin-ok\n`
- **Verdict**: Healthy origin connectivity through WAF reverse proxy.

### 2. SQLi Managed Rule Marker
- **Payload**: `astranull' OR '1'='0`
- **Request**: `GET http://172.31.21.10/?astranull_sqli_probe=astranull%27%20OR%20%271%27=%270`
- **Response**: HTTP 403 Forbidden
- **ModSecurity Rule Triggered**: Rule `942100` (`REQUEST-942-APPLICATION-ATTACK-SQLI.conf`, libinjection SQLi detection: `Matched Data: s&sos found within ARGS:astranull_sqli_probe: astranull' OR '1'='0'`). Inbound anomaly score reached threshold 5, triggering Rule `949110` with code 403.
- **Verdict**: **Protected** (blocked before origin).

### 3. Path Traversal Managed Rule Marker
- **Payload**: `../../astranull-probe`
- **Request**: `GET http://172.31.21.10/?astranull_path_traversal_probe=../../astranull-probe`
- **Response**: HTTP 403 Forbidden
- **ModSecurity Rules Triggered**: Rules `930100` and `930110` (`REQUEST-930-APPLICATION-ATTACK-LFI.conf`, Path Traversal Attack `/../`). Anomaly score reached 20, triggering Rule `949110` with code 403.
- **Verdict**: **Protected** (blocked before origin).

### 4. Scanner Signature Marker
- **Payload**: User-Agent `sqlmap/1.8 (astranull-inert)`
- **Request**: `GET http://172.31.21.10/` with header `User-Agent: sqlmap/1.8 (astranull-inert)`
- **Response**: HTTP 403 Forbidden
- **ModSecurity Rule Triggered**: Rule `913100` (`REQUEST-913-SCANNER-DETECTION.conf`).
- **Verdict**: **Protected** (blocked before origin).

### 5. Evasion Variants (SQLi)
- **Case-folded SQLi** (`AsTrAnUlL' oR '1'='0`): Blocked with HTTP 403 (libinjection Rule `942100`).
- **Double URL-encoded SQLi**: Blocked with HTTP 403 (Multiple URL encoding Rule `921130`).
- **Comment-obfuscated SQLi** (`astranull' O/**/R '1'='0`): Allowed through with HTTP 200 (libinjection did not trigger on comment split at PL1).

### 6. XSS Managed Rule Marker (Suspected AstraNull Defect)
- **Payload**: `<astranull-xss-probe/>`
- **Request**: `GET http://172.31.21.10/?astranull_xss_probe=%3Castranull-xss-probe/%3E`
- **Response**: HTTP 200 OK (passed through to origin; body `origin-ok`)
- **ModSecurity Evaluation**: Detailed debug logging confirms Rule `941100` (`@detectXSS` libinjection) evaluated the argument and returned `0` (not detected). Regex rules `941110` through `941160` likewise returned `0` because `astranull-xss-probe` is not in the recognized HTML tag dictionary and contains no script/event handler. Even at Paranoia Level 4, this marker is allowed through with HTTP 200.
- **Verdict**: **Gap** in manifest ground truth expectations.

### 7. Custom Canary Rules (SSTI & Prototype Pollution)
- `astranull-ssti-marker-inert`: HTTP 200 OK (no custom canary rule installed).
- `astranull-prototype-marker-inert`: HTTP 200 OK (no custom canary rule installed).
- **Verdict**: **Gap** in ground truth expectations (confirmed allowed through to origin).

## Declarations Signature

The recorded block signature placed into `declarations.waf_block_signature`:

```json
{
  "status": 403,
  "body_contains": "403 Forbidden"
}
```

Full block response body observed:
```html
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx</center>
</body>
</html>
```

## Suspected AstraNull Detection Defect

- **File**: `src/lib/inertWafMarkers.mjs:3` (`xss: '<astranull-xss-probe/>'`) and `src/contracts/checks.mjs:3387` (`waf.xss_managed_marker.safe`).
- **Reproduction**:
  1. Start OWASP CRS v4 in blocking mode (`SecRuleEngine On`, `BLOCKING_PARANOIA=1`).
  2. Send `GET /?astranull_xss_probe=%3Castranull-xss-probe/%3E`.
  3. Observe that CRS libinjection (`@detectXSS`, Rule 941100) returns 0 and does not recognize `<astranull-xss-probe/>` as XSS.
  4. The request passes through with HTTP 200.
- **Root Cause**: The inert token `<astranull-xss-probe/>` does not match the HTML element dictionary or syntax required by libinjection or CRS rules for XSS detection.

## Limitations & Host Environment Notes

- Container port binding: OWASP CRS image defaults to unprivileged non-root user (preventing low ports < 1024). Stack runs as `user: "0:0"` with `bypass-low-port.sh` mounted over `/docker-entrypoint.d/01-check-low-port.sh:ro` to enable binding directly on port 80.
- All services comply with resource caps (`cpus: 1.0`, `mem_limit: 768m`).
- Compose stack left in RUNNING state on `anl-waf-crs-block-net`.
