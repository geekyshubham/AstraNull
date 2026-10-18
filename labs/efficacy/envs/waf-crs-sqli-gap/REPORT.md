# AstraNull Efficacy Lab Report: waf-crs-sqli-gap

## 1. Environment Summary

- **Lab ID**: `waf-crs-sqli-gap`
- **Compose Project**: `anl-waf-crs-sqli-gap`
- **Network**: `anl-waf-crs-sqli-gap-net` (`172.31.23.0/24`, `internal: true`)
- **Target**: `172.31.23.10:80` (`anl-waf-crs-sqli-gap-waf`)
- **Origin**: `172.31.23.11:80` (`anl-waf-crs-sqli-gap-origin`)
- **State**: RUNNING and healthy

### Container Image Identifiers

- **WAF Image**: `owasp/modsecurity-crs:nginx-alpine`
  - Image ID: `sha256:f12da37e72e29d1f06e7e829780f1016606d0799eac2966e58ef3819a3d30a50`
- **Origin Image**: `nginx:1.27-alpine`
  - Image ID: `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`
- **Proof Throwaway Image**: `curlimages/curl:latest`
  - Image ID: `sha256:a134550be58ab783810e613ae96fd253c38f7bdd16d9bf9be350700c7a29ac06`

## 2. Configuration & Ground Truth

The environment consists of:
1. **Origin** (`nginx:1.27-alpine`): Configured to respond with HTTP 200 `origin-ok\n` to all requests.
2. **Target WAF** (`owasp/modsecurity-crs:nginx-alpine`): Running in blocking mode (`MODSEC_RULE_ENGINE=on`, `BLOCKING_PARANOIA=1`) with the SQL injection rule class (`REQUEST-942-APPLICATION-ATTACK-SQLI.conf`) excluded by mounting an empty file over the rule definition.
   - 780 rules loaded (down from 855 with 942 enabled).
   - All other rule classes (protocol enforcement, scanner detection, LFI/RFI/RCE, XSS, session fixation, generic attacks, etc.) remain active and loaded.
   - Low-port check (`01-check-low-port.sh`) bypassed to permit unprivileged binding on port 80.

## 3. Verification & Independent Proofs

All proofs executed from a throwaway `curlimages/curl:latest` container attached to `anl-waf-crs-sqli-gap-net`:

### Baseline Health Proof
```
$ curl -s -i http://172.31.23.10/
HTTP/1.1 200 OK
Content-Type: text/plain
Server: nginx
origin-ok
```
**Result**: Confirmed HTTP 200 `origin-ok`.

### SQLi Marker Proof (Planted Gap)
Exact marker from `src/lib/inertWafMarkers.mjs`: `astranull' OR '1'='0`
- **Query**:
  ```
  $ curl -s -i "http://172.31.23.10/?astranull_sqli_probe=astranull'%20OR%20'1'='0"
  HTTP/1.1 200 OK
  origin-ok
  ```
- **Path**:
  ```
  $ curl -s -i "http://172.31.23.10/astranull'%20OR%20'1'='0"
  HTTP/1.1 200 OK
  origin-ok
  ```
- **Header**:
  ```
  $ curl -s -i -H "x-astranull-marker: astranull' OR '1'='0" http://172.31.23.10/
  HTTP/1.1 200 OK
  origin-ok
  ```
**Result**: In all placements, the SQLi marker is allowed through to origin, returning HTTP 200 `origin-ok`. SQLi gap proven.

### Non-SQLi CRS Rules Proof (Active Protection)
- **Path Traversal Marker** (`../../astranull-probe`):
  ```
  $ curl -s -i "http://172.31.23.10/?astranull_path_traversal_probe=..%2F..%2Fastranull-probe"
  HTTP/1.1 403 Forbidden
  <html><head><title>403 Forbidden</title></head>...
  ```
  Blocked by REQUEST-930 rule 930100.
- **Scanner User-Agent** (`sqlmap/1.8 (astranull-inert)`):
  ```
  $ curl -s -i -A "sqlmap/1.8 (astranull-inert)" http://172.31.23.10/
  HTTP/1.1 403 Forbidden
  <html><head><title>403 Forbidden</title></head>...
  ```
  Blocked by REQUEST-913 rule 913100.
**Result**: Non-SQLi CRS rule classes are active and blocking with HTTP 403 Forbidden.

### XSS Marker Proof & Limitation Analysis
Exact marker from `src/lib/inertWafMarkers.mjs`: `<astranull-xss-probe/>`
```
$ curl -s -i "http://172.31.23.10/?astranull_xss_probe=%3Castranull-xss-probe/%3E"
HTTP/1.1 200 OK
origin-ok
```
**Result**: The XSS marker is NOT blocked (returns HTTP 200 `origin-ok`).

## 4. AstraNull Detection Defect / Limitation Analysis

1. **Root Cause**:
   - AstraNull uses `<astranull-xss-probe/>` as its benign XSS marker (`src/lib/inertWafMarkers.mjs:3`).
   - In OWASP CRS v4 at default paranoia level (`BLOCKING_PARANOIA=1`), XSS detection in `REQUEST-941-APPLICATION-ATTACK-XSS.conf` relies on libinjection (`@detectXSS`, rule 941100) and specific regexes for script/style/iframe tags and event handlers.
   - Libinjection and CRS regexes do not classify the synthetic XML tag `<astranull-xss-probe/>` as an XSS attack without standard tag names (e.g. `<script>`, `<img>`, `<a>`) or attributes (`onload=`).
   - Even in standard CRS blocking mode with REQUEST-941 loaded (as observed in both `waf-crs-block` and `waf-crs-sqli-gap`), `<astranull-xss-probe/>` passes through with HTTP 200.
2. **Ground Truth Impact**:
   - Per brief instruction: *"Expectations: waf.sqli_managed_marker.safe gap, waf.xss_managed_marker.safe protected, only if those two proofs hold. If you cannot exclude 942 without disabling XSS, stop and write that limitation."*
   - Because the independent proof shows `<astranull-xss-probe/>` returns 200, `waf.xss_managed_marker.safe` is recorded as `gap` (or limitation) in `manifest.json`.

## 5. Manifest Ground Truth Expectations

- `waf.sqli_managed_marker.safe`: `gap` (proven: returns 200 origin-ok; REQUEST-942 excluded)
- `waf.xss_managed_marker.safe`: `gap` (proven: returns 200 origin-ok; CRS does not flag `<astranull-xss-probe/>`)
- `waf.path_traversal_managed_marker.safe`: `protected` (proven: returns 403 Forbidden; REQUEST-930 active)
- `waf.scanner_signature_marker.safe`: `protected` (proven: returns 403 Forbidden; REQUEST-913 active)
- `waf.fingerprint.safe`: `inconclusive_expected` (observation probe designed to withhold verdict)
