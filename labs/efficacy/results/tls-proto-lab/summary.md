# Efficacy Validation Summary: tls-proto-lab

## Manifest Information
- **Lab ID**: `tls-proto-lab`
- **Manifest Path**: `/Users/checkred_admin/Projects/astranull/labs/efficacy/envs/tls-proto-lab/manifest.json`
- **Total Checks Evaluated**: 4

## Confusion Matrix
| Category | Count | Evaluated Checks |
|---|---|---|
| **Detected Gap** | 0 | None |
| **Missed Gap** | 0 | None |
| **False Alarm** | 0 | None |
| **Correct Protected** | 0 | None |
| **Inconclusive** | 3 | `tls.full_audit.safe`, `tls.full_audit.safe`, `tls.full_audit.safe` |
| **Not Applicable** | 1 | `protocol.http2_stream_concurrency.safe` |
| **Skipped Safety** | 0 | None |

## Detailed Results
| Target | Check ID | Expected | Verdict | Grade | Summary |
|---|---|---|---|---|---|
| `tls-expired` | `tls.full_audit.safe` | `gap` | `inconclusive` | **inconclusive** | Tls_audit recorded transport or liveness metadata only; it did not establish this check's verdict logic. |
| `tls-not-yet-valid` | `tls.full_audit.safe` | `gap` | `inconclusive` | **inconclusive** | Tls_audit recorded transport or liveness metadata only; it did not establish this check's verdict logic. |
| `tls-h2-unbounded` | `tls.full_audit.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | Tls_audit recorded transport or liveness metadata only; it did not establish this check's verdict logic. |
| `tls-h2-unbounded` | `protocol.http2_stream_concurrency.safe` | `not_applicable` | `not_applicable` | **not_applicable** | AstraNull probeHttp2Settings in src/lib/safeNetworkProbes.mjs:1211-1216 omits ALPNProtocols: ['h2'] in createConnection tlsConnectFn, causing Node.js http2.connect to fail with ERR_HTTP2_ERROR (-505) protocol error on real TLS endpoints. |
