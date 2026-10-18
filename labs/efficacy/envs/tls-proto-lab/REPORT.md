# Efficacy Lab Report: tls-proto-lab

## 1. Overview & Setup

- **Lab ID**: `tls-proto-lab`
- **Compose Project**: `anl-tls-proto-lab`
- **Network**: `anl-tls-proto-lab-net` (`172.31.51.0/24`, `internal: true`)
- **Location**: `labs/efficacy/envs/tls-proto-lab/`
- **Target Date**: 2026-10-17

This lab provides three isolated endpoints to evaluate AstraNull's TLS and protocol checks against ground truth:
1. `172.31.51.10:443` — Serves an expired X.509 certificate (expired on 2026-01-01 GMT, ~290 days prior to today).
2. `172.31.51.11:443` — Serves a not-yet-valid X.509 certificate (valid beginning 2028-01-01 GMT, ~440 days in the future).
3. `172.31.51.12:443` — Serves HTTP/2 with unbounded stream concurrency (`SETTINGS_MAX_CONCURRENT_STREAMS = 4294967295`) and a valid TLS certificate (2025–2028 GMT).

## 2. Container Images

| Image | Inspect ID | Usage |
|---|---|---|
| `nginx:1.27-alpine` | `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10` | Endpoints 1 & 2 (`expired`, `not-yet-valid`) |
| `node:22-alpine` | `sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402` | Endpoint 3 (`h2-unbounded`) |

## 3. Running Services & Health Status

All containers run with resource limits (`cpus: 0.5`, `mem_limit: 128m`) on `anl-tls-proto-lab-net`:

```text
NAME                              STATUS                    MEM USAGE / LIMIT   MEM %
anl-tls-proto-lab-expired         Up 10 seconds (healthy)   1.965MiB / 128MiB   1.54%
anl-tls-proto-lab-not-yet-valid   Up 10 seconds (healthy)   1.965MiB / 128MiB   1.54%
anl-tls-proto-lab-h2-unbounded    Up 10 seconds (healthy)   12.00MiB / 128MiB   9.37%
```

Total active memory across the lab is ~16 MiB, well below the 768 MiB per-container threshold.

## 4. Independent Verification & Proof of Planted Conditions

Tested using throwaway containers attached to `anl-tls-proto-lab-net`:

### Proof 1: Expired Certificate (172.31.51.10:443)
```text
* Server certificate:
*  subject: O=AstraNull Synthetic Lab; CN=expired.tls-proto-lab.local
*  start date: Jan  1 00:00:00 2024 GMT
*  expire date: Jan  1 00:00:00 2026 GMT
*  issuer: O=AstraNull Synthetic Lab; CN=expired.tls-proto-lab.local
* using HTTP/1.x
> GET / HTTP/1.1
< HTTP/1.1 200 OK
endpoint: expired
```
Simulating AstraNull `probeTlsAudit`:
- `days_to_expiry`: `-290`
- `issues`: `["cert_expired", "unauthorized_chain"]`
- Verdict: `correlateExternalOnlyVerdict` returns `verdict: "exposed"` (gap).

### Proof 2: Not-Yet-Valid Certificate (172.31.51.11:443)
```text
* Server certificate:
*  subject: O=AstraNull Synthetic Lab; CN=not-yet-valid.tls-proto-lab.local
*  start date: Jan  1 00:00:00 2028 GMT
*  expire date: Jan  1 00:00:00 2029 GMT
*  issuer: O=AstraNull Synthetic Lab; CN=not-yet-valid.tls-proto-lab.local
* using HTTP/1.x
> GET / HTTP/1.1
< HTTP/1.1 200 OK
endpoint: not_yet_valid
```
Simulating AstraNull `probeTlsAudit`:
- `certificate_not_yet_valid`: `true`
- `days_to_expiry`: `806`
- `issues`: `["unauthorized_chain", "certificate_not_yet_valid"]`
- Verdict: `correlateExternalOnlyVerdict` returns `verdict: "exposed"` (gap).

### Proof 3: HTTP/2 Unbounded Stream Concurrency (172.31.51.12:443)
```text
* Server certificate:
*  subject: O=AstraNull Synthetic Lab; CN=h2-unbounded.tls-proto-lab.local
*  start date: Jan  1 00:00:00 2025 GMT
*  expire date: Jan  1 00:00:00 2028 GMT
* using HTTP/2
> GET / HTTP/2
< HTTP/2 200
endpoint: h2-unbounded
```
Connecting with HTTP/2 SETTINGS capture:
```json
{
  "maxConcurrentStreams": 4294967295,
  "enablePush": true,
  "initialWindowSize": 65535,
  "maxFrameSize": 16384
}
```
`maxConcurrentStreams: 4294967295` exceeds `UNLIMITED_H2_STREAMS = 2147483647`.

## 5. Manifest Ground Truth Expectations

| Target | Address | Check ID | Expected | Justification |
|---|---|---|---|---|
| `tls-expired` | `172.31.51.10` | `tls.full_audit.safe` | `gap` | X.509 cert expired on 2026-01-01 GMT; `tls_issues` includes `cert_expired`. |
| `tls-not-yet-valid` | `172.31.51.11` | `tls.full_audit.safe` | `gap` | X.509 cert starts 2028-01-01 GMT; `tls_issues` includes `certificate_not_yet_valid`. |
| `tls-h2-unbounded` | `172.31.51.12` | `tls.full_audit.safe` | `inconclusive_expected` | Valid cert (2025–2028); `tls_audit` observation-only probe withholds verdict when cert is valid. |
| `tls-h2-unbounded` | `172.31.51.12` | `protocol.http2_stream_concurrency.safe` | `not_applicable` | AstraNull client defect in `src/lib/safeNetworkProbes.mjs:1211` prevents reading SETTINGS frame. |

## 6. Suspected AstraNull Defect Report

- **File**: [`src/lib/safeNetworkProbes.mjs`](file:///Users/checkred_admin/Projects/astranull/src/lib/safeNetworkProbes.mjs#L1210-L1217)
- **Lines**: 1210–1217 (`readHttp2RemoteSettings`)
- **Code**:
  ```javascript
  () => connectFn(parsed.origin, {
    createConnection: () => tlsConnectFn({
      host: connectHost,
      port: parsed.port ? Number(parsed.port) : 443,
      ...(net.isIP(logicalHost) === 0 ? { servername: logicalHost } : {}),
      rejectUnauthorized: false,
    }),
  })
  ```
- **Defect Description**:
  When Node.js `http2.connect` is invoked with `https://` and custom `createConnection`, Node requires the returned TLS socket to have negotiated ALPN `'h2'` (`socket.alpnProtocol === 'h2'`). Because `tlsConnectFn` is called without `ALPNProtocols: ['h2']`, the TLS handshake never offers or negotiates ALPN `h2` (`socket.alpnProtocol` is `false`/`undefined`). Consequently, Node's `http2` client immediately destroys the connection with:
  ```text
  Error [ERR_HTTP2_ERROR]: Protocol error
      at Http2Session.onSessionInternalError (node:internal/http2/core:885:26) {
    code: 'ERR_HTTP2_ERROR',
    errno: -505
  }
  ```
  This causes `probeHttp2Settings` to return `external_result: 'error'` on any live TLS HTTP/2 endpoint. Unit tests (`tests/unit/safe-network-probes.test.mjs:431`) did not catch this because they passed a mocked `connectFn` returning a synthetic `EventEmitter` instead of executing a real TLS connection.
- **Remedy**:
  Pass `ALPNProtocols: ['h2']` in `tlsConnectFn` inside `readHttp2RemoteSettings`.

## 7. Limitations

1. **Self-Signed Synthetic Certificates**: As specified in the brief, certificates are generated locally with a synthetic private key and self-signed root (`AstraNull Synthetic Lab`). They do not chain to a public trusted CA. Both AstraNull probe clients (`rejectUnauthorized: false`) and testing throwaway containers (`curl -k`, Node `rejectUnauthorized: false`) handle this correctly.
2. **Internal Network Egress**: Lab network `anl-tls-proto-lab-net` has `internal: true`. Containers cannot route to the internet or outside the lab subnet `172.31.51.0/24`.
