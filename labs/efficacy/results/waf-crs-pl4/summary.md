# Efficacy Validation Summary: waf-crs-pl4

## Manifest Information
- **Lab ID**: `waf-crs-pl4`
- **Manifest Path**: `/Users/checkred_admin/Projects/astranull/labs/efficacy/envs/waf-crs-pl4/manifest.json`
- **Total Checks Evaluated**: 7

## Confusion Matrix
| Category | Count | Evaluated Checks |
|---|---|---|
| **Detected Gap** | 0 | None |
| **Missed Gap** | 0 | None |
| **False Alarm** | 2 | `waf.xss_managed_marker.safe`, `waf.path_traversal_managed_marker.safe` |
| **Correct Protected** | 0 | None |
| **Inconclusive** | 5 | `waf.sqli_managed_marker.safe`, `waf.scanner_signature_marker.safe`, `waf.evasion_case_fold.safe`, `waf.evasion_mixed_url.safe`, `waf.evasion_double_url.safe` |
| **Not Applicable** | 0 | None |
| **Skipped Safety** | 0 | None |

## Detailed Results
| Target | Check ID | Expected | Verdict | Grade | Summary |
|---|---|---|---|---|---|
| `origin-behind-crs-paranoia-level-4` | `waf.sqli_managed_marker.safe` | `protected` | `inconclusive` | **inconclusive** | The probe did not establish sufficient external evidence and cannot establish protection or exposure. Review the recorded execution error or incomplete result. |
| `origin-behind-crs-paranoia-level-4` | `waf.xss_managed_marker.safe` | `protected` | `exposed` | **false alarm** | Managed-rule marker for cross-site scripting was not enforced: the edge let it through to the origin. |
| `origin-behind-crs-paranoia-level-4` | `waf.path_traversal_managed_marker.safe` | `protected` | `exposed` | **false alarm** | Managed-rule marker for path traversal was not enforced: the edge let it through to the origin. |
| `origin-behind-crs-paranoia-level-4` | `waf.scanner_signature_marker.safe` | `protected` | `inconclusive` | **inconclusive** | The probe did not establish sufficient external evidence and cannot establish protection or exposure. Review the recorded execution error or incomplete result. |
| `origin-behind-crs-paranoia-level-4` | `waf.evasion_case_fold.safe` | `protected` | `inconclusive` | **inconclusive** | A complete blocked-baseline comparison was not recorded. Evasion or inspection-limit resistance remains unassessed. |
| `origin-behind-crs-paranoia-level-4` | `waf.evasion_mixed_url.safe` | `protected` | `inconclusive` | **inconclusive** | A complete blocked-baseline comparison was not recorded. Evasion or inspection-limit resistance remains unassessed. |
| `origin-behind-crs-paranoia-level-4` | `waf.evasion_double_url.safe` | `protected` | `inconclusive` | **inconclusive** | A complete blocked-baseline comparison was not recorded. Evasion or inspection-limit resistance remains unassessed. |
