# Efficacy Validation Summary: waf-none

## Manifest Information
- **Lab ID**: `waf-none`
- **Manifest Path**: `/Users/checkred_admin/Projects/astranull/labs/efficacy/envs/waf-none/manifest.json`
- **Total Checks Evaluated**: 4

## Confusion Matrix
| Category | Count | Evaluated Checks |
|---|---|---|
| **Detected Gap** | 3 | `waf.sqli_managed_marker.safe`, `waf.xss_managed_marker.safe`, `waf.path_traversal_managed_marker.safe` |
| **Missed Gap** | 0 | None |
| **False Alarm** | 0 | None |
| **Correct Protected** | 0 | None |
| **Inconclusive** | 1 | `waf.fingerprint.safe` |
| **Not Applicable** | 0 | None |
| **Skipped Safety** | 0 | None |
| **Execution Error** | 0 | None |

## Detailed Results
| Target | Check ID | Expected | Verdict | Grade | Summary |
|---|---|---|---|---|---|
| `plain-nginx-no-waf` | `waf.sqli_managed_marker.safe` | `gap` | `exposed` | **detected gap** | Managed-rule marker for SQL injection was not enforced: the edge let it through to the origin. |
| `plain-nginx-no-waf` | `waf.xss_managed_marker.safe` | `gap` | `exposed` | **detected gap** | Managed-rule marker for cross-site scripting was not enforced: the edge let it through to the origin. |
| `plain-nginx-no-waf` | `waf.path_traversal_managed_marker.safe` | `gap` | `exposed` | **detected gap** | Managed-rule marker for path traversal was not enforced: the edge let it through to the origin. |
| `plain-nginx-no-waf` | `waf.fingerprint.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | No CDN or WAF provider was identified from HTTP, DNS or address signals on an HTTP 200 response. No WAF was identified: one ordinary GET cannot establish WAF presence or blocking; run the WAF marker check to test enforcement. |
