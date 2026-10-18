# Efficacy Validation Summary: waf-crs-block

## Manifest Information
- **Lab ID**: `waf-crs-block`
- **Manifest Path**: `/Users/checkred_admin/Projects/astranull/labs/efficacy/envs/waf-crs-block/manifest.json`
- **Total Checks Evaluated**: 9

## Confusion Matrix
| Category | Count | Evaluated Checks |
|---|---|---|
| **Detected Gap** | 0 | None |
| **Missed Gap** | 0 | None |
| **False Alarm** | 0 | None |
| **Correct Protected** | 0 | None |
| **Inconclusive** | 9 | `waf.sqli_managed_marker.safe`, `waf.path_traversal_managed_marker.safe`, `waf.xss_managed_marker.safe`, `waf.scanner_signature_marker.safe`, `waf.evasion_case_fold.safe`, `waf.evasion_double_url.safe`, `waf.ssti_marker.safe`, `waf.prototype_pollution_marker.safe`, `waf.fingerprint.safe` |
| **Not Applicable** | 0 | None |
| **Skipped Safety** | 0 | None |

## Detailed Results
| Target | Check ID | Expected | Verdict | Grade | Summary |
|---|---|---|---|---|---|
| `nginx-behind-crs-blocking` | `waf.sqli_managed_marker.safe` | `protected` | `inconclusive` | **inconclusive** | Probe observation recorded |
| `nginx-behind-crs-blocking` | `waf.path_traversal_managed_marker.safe` | `protected` | `inconclusive` | **inconclusive** | Probe observation recorded |
| `nginx-behind-crs-blocking` | `waf.xss_managed_marker.safe` | `gap` | `inconclusive` | **inconclusive** | Probe observation recorded |
| `nginx-behind-crs-blocking` | `waf.scanner_signature_marker.safe` | `protected` | `inconclusive` | **inconclusive** | Probe observation recorded |
| `nginx-behind-crs-blocking` | `waf.evasion_case_fold.safe` | `protected` | `inconclusive` | **inconclusive** | Probe observation recorded |
| `nginx-behind-crs-blocking` | `waf.evasion_double_url.safe` | `protected` | `inconclusive` | **inconclusive** | Probe observation recorded |
| `nginx-behind-crs-blocking` | `waf.ssti_marker.safe` | `gap` | `inconclusive` | **inconclusive** | Probe observation recorded |
| `nginx-behind-crs-blocking` | `waf.prototype_pollution_marker.safe` | `gap` | `inconclusive` | **inconclusive** | Probe observation recorded |
| `nginx-behind-crs-blocking` | `waf.fingerprint.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | Probe observation recorded |
