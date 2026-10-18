# Efficacy Validation Summary: waf-coraza

## Manifest Information
- **Lab ID**: `waf-coraza`
- **Manifest Path**: `/Users/checkred_admin/Projects/astranull/labs/efficacy/envs/waf-coraza/manifest.json`
- **Total Checks Evaluated**: 9

## Confusion Matrix
| Category | Count | Evaluated Checks |
|---|---|---|
| **Detected Gap** | 2 | `waf.sqli_managed_marker.safe`, `waf.xss_managed_marker.safe` |
| **Missed Gap** | 0 | None |
| **False Alarm** | 0 | None |
| **Correct Protected** | 4 | `waf.path_traversal_managed_marker.safe`, `waf.scanner_signature_marker.safe`, `waf.evasion_case_fold.safe`, `waf.evasion_double_url.safe` |
| **Inconclusive** | 3 | `waf.ssti_marker.safe`, `waf.prototype_pollution_marker.safe`, `waf.fingerprint.safe` |
| **Not Applicable** | 0 | None |
| **Skipped Safety** | 0 | None |
| **Execution Error** | 0 | None |

## Detailed Results
| Target | Check ID | Expected | Verdict | Grade | Summary |
|---|---|---|---|---|---|
| `origin-behind-coraza-crs-blocking` | `waf.sqli_managed_marker.safe` | `gap` | `exposed` | **detected gap** | Managed-rule marker for SQL injection was only partially enforced. Unenforced placements: path, header. |
| `origin-behind-coraza-crs-blocking` | `waf.path_traversal_managed_marker.safe` | `protected` | `protected` | **correct protected** | Managed-rule marker was enforced on the tested placements. |
| `origin-behind-coraza-crs-blocking` | `waf.xss_managed_marker.safe` | `gap` | `exposed` | **detected gap** | Managed-rule marker for cross-site scripting was not enforced: the edge let it through to the origin. |
| `origin-behind-coraza-crs-blocking` | `waf.scanner_signature_marker.safe` | `protected` | `protected` | **correct protected** | Managed-rule marker was enforced on the tested placements. |
| `origin-behind-coraza-crs-blocking` | `waf.evasion_case_fold.safe` | `protected` | `protected` | **correct protected** | External probe was blocked by the control under test. |
| `origin-behind-coraza-crs-blocking` | `waf.evasion_double_url.safe` | `protected` | `protected` | **correct protected** | External probe was blocked by the control under test. |
| `origin-behind-coraza-crs-blocking` | `waf.ssti_marker.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | The probe did not establish sufficient external evidence and cannot establish protection or exposure. Review the recorded execution error or incomplete result. |
| `origin-behind-coraza-crs-blocking` | `waf.prototype_pollution_marker.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | The probe did not establish sufficient external evidence and cannot establish protection or exposure. Review the recorded execution error or incomplete result. |
| `origin-behind-coraza-crs-blocking` | `waf.fingerprint.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | No CDN or WAF provider was identified from HTTP, DNS or address signals on an HTTP 200 response. No WAF was identified: one ordinary GET cannot establish WAF presence or blocking; run the WAF marker check to test enforcement. |
