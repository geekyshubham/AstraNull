# Efficacy Validation Summary: l7-surface-lab

## Manifest Information
- **Lab ID**: `l7-surface-lab`
- **Manifest Path**: `/Users/checkred_admin/Projects/astranull/labs/efficacy/envs/l7-surface-lab/manifest.json`
- **Total Checks Evaluated**: 7

## Confusion Matrix
| Category | Count | Evaluated Checks |
|---|---|---|
| **Detected Gap** | 1 | `l7.cors_posture.safe` |
| **Missed Gap** | 0 | None |
| **False Alarm** | 0 | None |
| **Correct Protected** | 0 | None |
| **Inconclusive** | 2 | `l7.api_surface_scan.safe`, `l7.http_method_restriction.safe` |
| **Not Applicable** | 4 | `l7.login_abuse_flow.safe`, `l7.graphql_complexity.safe`, `l7.webhook_flood.readiness`, `l7.slowloris.readiness` |
| **Skipped Safety** | 0 | None |

## Detailed Results
| Target | Check ID | Expected | Verdict | Grade | Summary |
|---|---|---|---|---|---|
| `l7-surface-nginx` | `l7.cors_posture.safe` | `gap` | `exposed` | **detected gap** | This URL reflected AstraNull's unrelated test Origin in Access-Control-Allow-Origin and allowed credentials, so any website can make credentialed requests to it. |
| `l7-surface-nginx` | `l7.api_surface_scan.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | Api_surface_scan recorded transport or liveness metadata only; it did not establish this check's verdict logic. |
| `l7-surface-nginx` | `l7.http_method_restriction.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | Http_method_matrix recorded transport or liveness metadata only; it did not establish this check's verdict logic. |
| `l7-surface-nginx` | `l7.login_abuse_flow.safe` | `not_applicable` | `not_applicable` | **not_applicable** | Target does not implement an authentication/login flow. |
| `l7-surface-nginx` | `l7.graphql_complexity.safe` | `not_applicable` | `not_applicable` | **not_applicable** | Target does not host a GraphQL endpoint. |
| `l7-surface-nginx` | `l7.webhook_flood.readiness` | `not_applicable` | `not_applicable` | **not_applicable** | Target does not implement webhook receivers. |
| `l7-surface-nginx` | `l7.slowloris.readiness` | `not_applicable` | `not_applicable` | **not_applicable** | Slow-request attack tooling is explicitly excluded by safety policy. |
