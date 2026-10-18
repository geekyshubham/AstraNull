# Efficacy Validation Summary: waf-crs-sqli-gap

## Manifest Information
- **Lab ID**: `waf-crs-sqli-gap`
- **Manifest Path**: `/Users/checkred_admin/Projects/astranull/labs/efficacy/envs/waf-crs-sqli-gap/manifest.json`
- **Total Checks Evaluated**: 5

## Confusion Matrix
| Category | Count | Evaluated Checks |
|---|---|---|
| **Detected Gap** | 2 | `waf.sqli_managed_marker.safe`, `waf.xss_managed_marker.safe` |
| **Missed Gap** | 0 | None |
| **False Alarm** | 1 | `waf.path_traversal_managed_marker.safe` |
| **Correct Protected** | 0 | None |
| **Inconclusive** | 2 | `waf.scanner_signature_marker.safe`, `waf.fingerprint.safe` |
| **Not Applicable** | 0 | None |
| **Skipped Safety** | 0 | None |

## Detailed Results
| Target | Check ID | Expected | Verdict | Grade | Summary |
|---|---|---|---|---|---|
| `nginx-behind-crs-sqli-gap` | `waf.sqli_managed_marker.safe` | `gap` | `exposed` | **detected gap** | Managed-rule marker for SQL injection was not enforced: the edge let it through to the origin. |
| `nginx-behind-crs-sqli-gap` | `waf.xss_managed_marker.safe` | `gap` | `exposed` | **detected gap** | Managed-rule marker for cross-site scripting was not enforced: the edge let it through to the origin. |
| `nginx-behind-crs-sqli-gap` | `waf.path_traversal_managed_marker.safe` | `protected` | `exposed` | **false alarm** | Managed-rule marker for path traversal was not enforced: the edge let it through to the origin. |
| `nginx-behind-crs-sqli-gap` | `waf.scanner_signature_marker.safe` | `protected` | `inconclusive` | **inconclusive** | The probe did not establish sufficient external evidence and cannot establish protection or exposure. Review the recorded execution error or incomplete result. |
| `nginx-behind-crs-sqli-gap` | `waf.fingerprint.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | No CDN or WAF provider was identified from HTTP, DNS or address signals on an HTTP 200 response. No WAF was identified: one ordinary GET cannot establish WAF presence or blocking; run the WAF marker check to test enforcement. |
