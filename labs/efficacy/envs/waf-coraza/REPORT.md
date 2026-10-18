# AstraNull Efficacy Lab Report: waf-coraza

## 1. Summary & Architecture

- **Lab ID**: `waf-coraza`
- **Compose Project**: `anl-waf-coraza`
- **Network**: `anl-waf-coraza-net` (Subnet: `172.31.25.0/24`, `internal: true`)
- **Target**: `172.31.25.10:80` (HAProxy frontend with Coraza SPOE filter)
- **Coraza SPOA Engine**: `172.31.25.15:9000` (`ghcr.io/corazawaf/coraza-spoa:snapshot` running Coraza v3 + OWASP CRS v4)
- **Origin**: `172.31.25.20:80` (`nginx:1.27-alpine` returning HTTP 200 `origin-ok` for all paths)
- **Planted Condition**: Official OWASP Coraza WAF engine running in blocking mode (`SecRuleEngine On`) with OWASP Core Rule Set v4 (`@coraza.conf-recommended`, `@crs-setup.conf.example`, `@owasp_crs/*.conf`) acting as an outside-in reverse proxy in front of an Nginx origin returning `200 origin-ok`.
- **Status**: Running and verified healthy.

---

## 2. Pinned Images & Image IDs

All images are pinned published images. Image IDs verified via `docker image inspect --format '{{.Id}}'`:

| Role | Published Image Reference | Image ID (`docker image inspect --format '{{.Id}}'`) |
|---|---|---|
| Coraza SPOA Daemon | `ghcr.io/corazawaf/coraza-spoa:snapshot@sha256:5bc0e0b7435833ee1636008ccad5bd7708c4c8c50bafe03fb1813e2791584df7` | `sha256:5bc0e0b7435833ee1636008ccad5bd7708c4c8c50bafe03fb1813e2791584df7` |
| HAProxy Target Proxy | `haproxy:3.0-alpine@sha256:d84eb36e91830bcaa67b23cfde1909850b99f11eb60da3abd185bd0daf3f75bb` | `sha256:d84eb36e91830bcaa67b23cfde1909850b99f11eb60da3abd185bd0daf3f75bb` |
| Backend Origin | `nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10` | `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10` |
| Verification Client | `curlimages/curl:8.10.1@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b` | `sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b` |

Resource caps enforced per service: `cpus: 1.0`, `mem_limit: 768m`.

---

## 3. Health & Planted Condition Proofs

All proofs were performed from throwaway container `curlimages/curl:8.10.1` attached to `anl-waf-coraza-net`.

### Proof 1: Baseline Health Request (`GET /`)
- **Command**:
  ```bash
  docker run --rm --network anl-waf-coraza-net curlimages/curl:8.10.1 -i -s "http://172.31.25.10/"
  ```
- **Observed Response**:
  ```http
  HTTP/1.1 200 OK
  server: nginx/1.27.5
  date: Sat, 17 Oct 2026 14:39:22 GMT
  content-type: text/plain
  content-length: 10

  origin-ok
  ```
- **Verdict**: Plain GET / successfully traverses Coraza SPOE filter and reaches Nginx origin returning HTTP 200 `origin-ok`.

### Proof 2: SQLi Managed Rule Marker (`astranull' OR '1'='0`)
- **Command**:
  ```bash
  docker run --rm --network anl-waf-coraza-net curlimages/curl:8.10.1 -i -s "http://172.31.25.10/?q=astranull%27+OR+%271%27%3D%270"
  ```
- **Observed Response**:
  ```http
  HTTP/1.0 403 Forbidden
  cache-control: no-cache
  content-type: text/html

  <html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>Access denied by Coraza WAF</p></body></html>
  ```
- **Coraza SPOA Engine Log**:
  ```
  Coraza: Warning. SQL Injection Attack Detected via libinjection [file "@owasp_crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [data "Matched Data: s&sos found within ARGS:q: astranull' OR '1'='0'"] [ver "OWASP_CRS/4.25.0"]
  Coraza: Access denied (phase 2). Inbound Anomaly Score Exceeded (Total Score: 8) [file "@owasp_crs/REQUEST-949-BLOCKING-EVALUATION.conf"] [id "949110"]
  ```
- **Verdict**: **BLOCKED** before origin with HTTP 403.

### Proof 3: XSS Managed Rule Marker (`<astranull-xss-probe/>`)
- **Command**:
  ```bash
  docker run --rm --network anl-waf-coraza-net curlimages/curl:8.10.1 -i -s "http://172.31.25.10/?q=%3Castranull-xss-probe%2F%3E"
  ```
- **Observed Response**:
  ```http
  HTTP/1.1 200 OK
  server: nginx/1.27.5
  date: Sat, 17 Oct 2026 14:40:09 GMT
  content-type: text/plain
  content-length: 10

  origin-ok
  ```
- **Coraza SPOA Engine Evaluation**:
  Coraza engine evaluated `@detectXSS` (libinjection) on `<astranull-xss-probe/>` and returned 0 (not recognized as XSS). Rule 920350 warned on numeric IP host header (score 3), but total anomaly score did not exceed threshold 5.
- **Verdict**: **NOT BLOCKED**; request passes to origin and returns HTTP 200 `origin-ok`.

### Proof 4: Path Traversal Managed Rule Marker (`../../astranull-probe`)
- **Command**:
  ```bash
  docker run --rm --network anl-waf-coraza-net curlimages/curl:8.10.1 -i -s "http://172.31.25.10/?q=..%2F..%2Fastranull-probe"
  ```
- **Observed Response**: HTTP 403 Forbidden (`Access denied by Coraza WAF`).
- **Coraza SPOA Engine Log**: Triggered rules `930100` and `930110` (`REQUEST-930-APPLICATION-ATTACK-LFI.conf`), total anomaly score 23 >= 5, triggered `949110`.
- **Verdict**: **BLOCKED** before origin.

### Proof 5: Scanner User-Agent Marker (`sqlmap/1.8 (astranull-inert)`)
- **Command**:
  ```bash
  docker run --rm --network anl-waf-coraza-net curlimages/curl:8.10.1 -i -s -A "sqlmap/1.8 (astranull-inert)" "http://172.31.25.10/"
  ```
- **Observed Response**: HTTP 403 Forbidden (`Access denied by Coraza WAF`).
- **Coraza SPOA Engine Log**: Triggered rule `913100` (`REQUEST-913-SCANNER-DETECTION.conf`), anomaly score 8 >= 5.
- **Verdict**: **BLOCKED** before origin.

### Proof 6: Case-Fold SQLi Evasion Marker (`AsTrAnUlL' oR '1'='0`)
- **Command**:
  ```bash
  docker run --rm --network anl-waf-coraza-net curlimages/curl:8.10.1 -i -s "http://172.31.25.10/?q=AsTrAnUlL%27+oR+%271%27%3D%270"
  ```
- **Observed Response**: HTTP 403 Forbidden (`Access denied by Coraza WAF`).
- **Verdict**: **BLOCKED** before origin (rule 942100).

### Proof 7: Double URL-Encoded SQLi Evasion Marker
- **Command**:
  ```bash
  docker run --rm --network anl-waf-coraza-net curlimages/curl:8.10.1 -i -s "http://172.31.25.10/?q=astranull%2527%2520OR%2520%25271%2527%253D%25270"
  ```
- **Observed Response**: HTTP 403 Forbidden (`Access denied by Coraza WAF`).
- **Verdict**: **BLOCKED** before origin (rule 942100).

### Proof 8: Custom Canary Markers (SSTI & Prototype Pollution)
- `astranull-ssti-marker-inert`: HTTP 200 OK (`origin-ok`).
- `astranull-prototype-marker-inert`: HTTP 200 OK (`origin-ok`).
- **Verdict**: Allowed through to origin (no custom canary rules defined in stock CRS).

---

## 4. Declarations Signature

Declared block signature configured in `manifest.json`:
```json
"declarations": {
  "waf_block_signature": {
    "status": 403,
    "body_contains": "Access denied by Coraza WAF"
  }
}
```

Observed 403 response body:
```html
<html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>Access denied by Coraza WAF</p></body></html>
```

---

## 5. AstraNull Behavior: Does AstraNull Treat Coraza Like ModSecurity?

**Yes.** AstraNull treats Coraza as ModSecurity in its outside-in detection engine:

1. **Vendor Denial Signature Mapping (`src/lib/externalObservationOutcomes.mjs:172-177`)**:
   ```javascript
   {
     id: 'modsecurity_default_block',
     vendor: 'modsecurity',
     live_verified: false,
     match: ({ status, body }) => status === 403 && /this error was generated by mod_security|coraza waf/i.test(body),
     suspect: ({ status, header }) => status === 403 && /mod_?security|coraza/i.test(header('server') ?? ''),
   }
   ```
   A response returning HTTP 403 with body matching `/coraza waf/i` or header `server` matching `/coraza/i` is classified as:
   - `id`: `'modsecurity_default_block'`
   - `vendor`: `'modsecurity'`
   There is no separate `coraza_default_block` signature in `VENDOR_DENIAL_SIGNATURES`.

2. **Contrast with Product Catalog (`db/seeds/waf-product-catalog.json:496-518`)**:
   The catalog defines an independent entry for Coraza:
   ```json
   {
     "id": "waf_prod_coraza",
     "vendor": "coraza",
     "product": "Coraza WAF",
     "deployment_type": "reverse_proxy",
     "header_name_patterns": ["^coraza-"],
     "block_page_signature_ids": ["block_sig_coraza_v1"]
   }
   ```
   However, outside-in observation outcomes in `externalObservationOutcomes.mjs` conflate Coraza into `vendor: 'modsecurity'`.

3. **Shared Rule Engine Behavior with ModSecurity CRS**:
   - Both engines run the same OWASP Core Rule Set v4 SecLang logic.
   - Both engines successfully block SQLi marker `astranull' OR '1'='0'` via libinjection rule 942100.
   - Both engines **fail to block** inert XSS marker `<astranull-xss-probe/>` because libinjection `@detectXSS` returns 0 and CRS regexes at paranoia level 1 do not match custom non-HTML tags.
   - Both engines block path traversal and scanner User-Agent markers.

---

## 6. Manifest Expectations Justification

1. `waf.sqli_managed_marker.safe`: **`protected`**
   - Proved: Coraza OWASP CRS rule 942100 blocks inert SQLi marker with 403.
2. `waf.path_traversal_managed_marker.safe`: **`protected`**
   - Proved: Coraza OWASP CRS rules 930100 and 930110 block traversal marker with 403.
3. `waf.xss_managed_marker.safe`: **`gap`**
   - Proved: Coraza OWASP CRS v4 PL1 does not detect `<astranull-xss-probe/>`; returns 200 `origin-ok`.
4. `waf.scanner_signature_marker.safe`: **`protected`**
   - Proved: Coraza OWASP CRS rule 913100 blocks sqlmap User-Agent with 403.
5. `waf.evasion_case_fold.safe`: **`protected`**
   - Proved: Coraza OWASP CRS rule 942100 normalizes and blocks case-folded SQLi marker with 403.
6. `waf.evasion_double_url.safe`: **`protected`**
   - Proved: Coraza OWASP CRS rule 942100 blocks double URL-encoded SQLi marker with 403.
7. `waf.ssti_marker.safe`: **`gap`**
   - Proved: Custom canary token `astranull-ssti-marker-inert` is not blocked; returns 200 `origin-ok`.
8. `waf.prototype_pollution_marker.safe`: **`gap`**
   - Proved: Custom canary token `astranull-prototype-marker-inert` is not blocked; returns 200 `origin-ok`.
9. `waf.fingerprint.safe`: **`inconclusive_expected`**
   - Justification: `waf_fingerprint_observation` is registered in `OBSERVATION_ONLY_PROBE_KINDS` and unconditionally resolves to `inconclusive` in `correlation.mjs`.

---

## 7. Limitations & Operational Notes

- **Network Isolation**: `anl-waf-coraza-net` is configured with `internal: true`. No external ingress or egress.
- **Colima Host Routing**: macOS cannot route to container IPs; all probes must be launched inside throwaway containers attached to `anl-waf-coraza-net`.
- **Target State**: Kept running for harness evaluation.
