# Efficacy Validation Summary: waf-crs-pl4

## Manifest Information
- **Lab ID**: `waf-crs-pl4`
- **Manifest Path**: `/Users/checkred_admin/Projects/astranull/labs/efficacy/envs/waf-crs-pl4/manifest.json`
- **Total Checks Evaluated**: 7

## Confusion Matrix
| Category | Count | Evaluated Checks |
|---|---|---|
| **Detected Gap** | 1 | `waf.xss_managed_marker.safe` |
| **Missed Gap** | 0 | None |
| **False Alarm** | 0 | None |
| **Correct Protected** | 6 | `waf.sqli_managed_marker.safe`, `waf.path_traversal_managed_marker.safe`, `waf.scanner_signature_marker.safe`, `waf.evasion_case_fold.safe`, `waf.evasion_mixed_url.safe`, `waf.evasion_double_url.safe` |
| **Inconclusive** | 0 | None |
| **Not Applicable** | 0 | None |
| **Skipped Safety** | 0 | None |
| **Execution Error** | 0 | None |

## Detailed Results
| Target | Check ID | Expected | Verdict | Grade | Summary |
|---|---|---|---|---|---|
| `origin-behind-crs-paranoia-level-4` | `waf.sqli_managed_marker.safe` | `protected` | `protected` | **correct protected** | Managed-rule marker was enforced on the tested placements. |
| `origin-behind-crs-paranoia-level-4` | `waf.xss_managed_marker.safe` | `gap` | `exposed` | **detected gap** | Managed-rule marker for cross-site scripting was only partially enforced. Unenforced placements: path. |
| `origin-behind-crs-paranoia-level-4` | `waf.path_traversal_managed_marker.safe` | `protected` | `protected` | **correct protected** | Managed-rule marker was enforced on the tested placements. |
| `origin-behind-crs-paranoia-level-4` | `waf.scanner_signature_marker.safe` | `protected` | `protected` | **correct protected** | Managed-rule marker was enforced on the tested placements. |
| `origin-behind-crs-paranoia-level-4` | `waf.evasion_case_fold.safe` | `protected` | `protected` | **correct protected** | External probe was blocked by the control under test. |
| `origin-behind-crs-paranoia-level-4` | `waf.evasion_mixed_url.safe` | `protected` | `protected` | **correct protected** | External probe was blocked by the control under test. |
| `origin-behind-crs-paranoia-level-4` | `waf.evasion_double_url.safe` | `protected` | `protected` | **correct protected** | External probe was blocked by the control under test. |
