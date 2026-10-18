# Efficacy Validation Summary: tls-proto-lab

## Manifest Information
- **Lab ID**: `tls-proto-lab`
- **Manifest Path**: `/Users/checkred_admin/Projects/astranull/labs/efficacy/envs/tls-proto-lab/manifest.json`
- **Total Checks Evaluated**: 4

## Confusion Matrix
| Category | Count | Evaluated Checks |
|---|---|---|
| **Detected Gap** | 3 | `tls.full_audit.safe`, `tls.full_audit.safe`, `protocol.http2_stream_concurrency.safe` |
| **Missed Gap** | 0 | None |
| **False Alarm** | 0 | None |
| **Correct Protected** | 0 | None |
| **Inconclusive** | 1 | `tls.full_audit.safe` |
| **Not Applicable** | 0 | None |
| **Skipped Safety** | 0 | None |
| **Execution Error** | 0 | None |

## Detailed Results
| Target | Check ID | Expected | Verdict | Grade | Summary |
|---|---|---|---|---|---|
| `tls-expired` | `tls.full_audit.safe` | `gap` | `exposed` | **detected gap** | The certificate served on this endpoint expired 290 day(s) ago (valid to Jan 1 00:00:00 2026 GMT). |
| `tls-not-yet-valid` | `tls.full_audit.safe` | `gap` | `exposed` | **detected gap** | The certificate served on this endpoint is not yet valid. |
| `tls-h2-unbounded` | `tls.full_audit.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | Tls_audit recorded transport or liveness metadata only; it did not establish this check's verdict logic. |
| `tls-h2-unbounded` | `protocol.http2_stream_concurrency.safe` | `gap` | `exposed` | **detected gap** | The HTTP/2 endpoint advertised no SETTINGS_MAX_CONCURRENT_STREAMS limit, so one client can open an unbounded number of concurrent streams. |
