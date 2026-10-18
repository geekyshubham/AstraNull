# Efficacy Validation Summary: ratelimit-lab

## Manifest Information
- **Lab ID**: `ratelimit-lab`
- **Manifest Path**: `/Users/checkred_admin/Projects/astranull/labs/efficacy/envs/ratelimit-lab/manifest.json`
- **Total Checks Evaluated**: 6

## Confusion Matrix
| Category | Count | Evaluated Checks |
|---|---|---|
| **Detected Gap** | 1 | `waf.rate_limit_canary.validation` |
| **Missed Gap** | 0 | None |
| **False Alarm** | 0 | None |
| **Correct Protected** | 1 | `waf.rate_limit_canary.validation` |
| **Inconclusive** | 4 | `waf.low_rate_limit.safe`, `l7.low_rate_rate_limit.safe`, `waf.low_rate_limit.safe`, `l7.low_rate_rate_limit.safe` |
| **Not Applicable** | 0 | None |
| **Skipped Safety** | 0 | None |

## Detailed Results
| Target | Check ID | Expected | Verdict | Grade | Summary |
|---|---|---|---|---|---|
| `nginx-rate-limited` | `waf.rate_limit_canary.validation` | `protected` | `protected` | **correct protected** | Rate-limit canary allowed the first 3 requests and was limited at request 4, within the declared threshold plus two. |
| `nginx-rate-limited` | `waf.low_rate_limit.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | Rate_limit_sequence recorded transport or liveness metadata only; it did not establish this check's verdict logic. |
| `nginx-rate-limited` | `l7.low_rate_rate_limit.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | Rate_limit_sequence recorded transport or liveness metadata only; it did not establish this check's verdict logic. |
| `nginx-unlimited` | `waf.rate_limit_canary.validation` | `gap` | `exposed` | **detected gap** | Rate-limit canary sent 5 requests, more than the declared threshold of 3, and was never limited. |
| `nginx-unlimited` | `waf.low_rate_limit.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | Rate_limit_sequence recorded transport or liveness metadata only; it did not establish this check's verdict logic. |
| `nginx-unlimited` | `l7.low_rate_rate_limit.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | Rate_limit_sequence recorded transport or liveness metadata only; it did not establish this check's verdict logic. |
