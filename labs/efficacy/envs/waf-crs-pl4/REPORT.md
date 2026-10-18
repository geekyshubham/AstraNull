# AstraNull Efficacy Lab Report: waf-crs-pl4

## Overview
- **Lab ID**: `waf-crs-pl4`
- **Compose Project**: `anl-waf-crs-pl4`
- **Network**: `anl-waf-crs-pl4-net` (Subnet: `172.31.24.0/24`, `internal: true`)
- **Target Container**: `anl-waf-crs-pl4-target` (`172.31.24.10:80`)
- **Origin Container**: `anl-waf-crs-pl4-origin` (`172.31.24.20:80`)
- **State**: Lab is running and verified healthy.

## Pinned Container Image IDs
- `owasp/modsecurity-crs:nginx-alpine`: `sha256:f12da37e72e29d1f06e7e829780f1016606d0799eac2966e58ef3819a3d30a50`
- `nginx:1.27-alpine`: `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`
- `curlimages/curl:latest` (throwaway verification client): `sha256:a134550be58ab783810e613ae96fd253c38f7bdd16d9bf9be350700c7a29ac06`

## Planted Condition
OWASP ModSecurity Core Rule Set 4 (CRS v4) configured in active blocking mode at Paranoia Level 4 (`BLOCKING_PARANOIA=4`, `DETECTION_PARANOIA=4`, `MODSEC_RULE_ENGINE=on`, inbound anomaly threshold 5). Upstream is `nginx:1.27-alpine` returning HTTP 200 with body `origin-ok` for all valid requests forwarded by the WAF proxy.

## Health Proof & Verification Evidence

All tests were performed using throwaway containers attached to `anl-waf-crs-pl4-net`:

### 1. Plain Health Request (`GET /`)
```text
$ docker run --rm --network anl-waf-crs-pl4-net curlimages/curl:latest -i -s http://172.31.24.10/
HTTP/1.1 200 OK
Date: Sat, 17 Oct 2026 14:34:49 GMT
Content-Type: text/plain
Content-Length: 10
Connection: keep-alive
Server: nginx
Access-Control-Allow-Headers: *

origin-ok
```
*Verdict*: Plain health check succeeds with HTTP 200 OK and `origin-ok`. Paranoia Level 4 does not block the plain root path.

### 2. Inert SQLi Marker (`astranull' OR '1'='0`)
- **Query probe**: `http://172.31.24.10/?astranull_sqli_probe=astranull%27%20OR%20%271%27=%270`
- **Header probe**: `x-astranull-marker: astranull' OR '1'='0`
- **Path probe**: `http://172.31.24.10/astranull'%20OR%20'1'='0`
```text
HTTP/1.1 403 Forbidden
Content-Type: text/html
Content-Length: 146

<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx</center>
</body>
</html>
```
*Matched Rules*: 942100 (SQLi attack), 942432 (Restricted SQL character anomaly detection - args), 949110 (Inbound anomaly score exceeded). Blocked with HTTP 403.

### 3. Inert XSS Marker (`<astranull-xss-probe/>`)
- **Query probe**: `http://172.31.24.10/?astranull_xss_probe=%3Castranull-xss-probe/%3E`
```text
HTTP/1.1 403 Forbidden
Content-Type: text/html
Content-Length: 146
```
*Matched Rules*: 941100 (XSS Filter), 949110. Blocked with HTTP 403.

### 4. Inert Path Traversal Marker (`../../astranull-probe`)
- **Query probe**: `http://172.31.24.10/?astranull_path_traversal_probe=..%2F..%2Fastranull-probe`
```text
HTTP/1.1 403 Forbidden
Content-Type: text/html
Content-Length: 146
```
*Matched Rules*: 930100 (Path Traversal Attack), 930110, 949110. Blocked with HTTP 403.

### 5. Evasion Variants & User-Agent Signatures
- **Case-fold SQLi** (`AsTrAnUlL' oR '1'='0`): Blocked with HTTP 403 Forbidden
- **Comment SQLi** (`astranull' O/**/R '1'='0`): Blocked with HTTP 403 Forbidden
- **Double-URL Encoded SQLi** (`astranull%2527%2520OR%2520%25271%2527%253D%25270`): Blocked with HTTP 403 Forbidden
- **Scanner User-Agent** (`sqlmap/1.8 (astranull-inert)`): Blocked with HTTP 403 Forbidden (Rule 913100)

## Declarations & Ground Truth Expectations
- `declarations.waf_block_signature`:
  - `status`: 403
  - `body_contains`: "403 Forbidden"
- **Manifest Expectations**:
  - `waf.sqli_managed_marker.safe`: `protected`
  - `waf.xss_managed_marker.safe`: `protected`
  - `waf.path_traversal_managed_marker.safe`: `protected`
  - `waf.scanner_signature_marker.safe`: `protected`
  - `waf.evasion_case_fold.safe`: `protected`
  - `waf.evasion_mixed_url.safe`: `protected`
  - `waf.evasion_double_url.safe`: `protected`

## Limitations & Operational Observations
1. **Plain Health Check at PL4**: In OWASP ModSecurity CRS v4, Paranoia Level 4 does not block simple HTTP GET requests to `/` with default curl headers. When accessing via numeric IP host (`Host: 172.31.24.10`), rule 920350 adds 3 to the anomaly score, but the total inbound score remains below the blocking threshold of 5. As a result, no CRS exclusion rule was required for `/`.
2. **Strict Characters at PL4**: At PL4, rule 942432 triggers on any parameter containing 2 or more special characters (such as hyphens). Combined with rule 920350 (numeric IP host score 3), any parameter with hyphens exceeds the threshold of 5 and is blocked.
3. **Colima Daemon Subnet Pre-allocation**: An exited BGP test network had previously consumed `172.31.0.0/16`. Once cleared, the isolated bridge network `anl-waf-crs-pl4-net` was successfully provisioned on `172.31.24.0/24`.
