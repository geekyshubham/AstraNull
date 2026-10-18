# Efficacy Validation Summary: nfw-ipv6-gap

## Manifest Information
- **Lab ID**: `nfw-ipv6-gap`
- **Manifest Path**: `/Users/checkred_admin/Projects/astranull/labs/efficacy/envs/nfw-ipv6-gap/manifest.json`
- **Total Checks Evaluated**: 2

## Confusion Matrix
| Category | Count | Evaluated Checks |
|---|---|---|
| **Detected Gap** | 0 | None |
| **Missed Gap** | 0 | None |
| **False Alarm** | 0 | None |
| **Correct Protected** | 0 | None |
| **Inconclusive** | 2 | `nfw.ipv6_parity.safe`, `l3.ipv6_reachability.safe` |
| **Not Applicable** | 0 | None |
| **Skipped Safety** | 0 | None |

## Detailed Results
| Target | Check ID | Expected | Verdict | Grade | Summary |
|---|---|---|---|---|---|
| `nfw-ipv6-gap-target` | `nfw.ipv6_parity.safe` | `gap` | `inconclusive` | **inconclusive** | Probe observation recorded |
| `nfw-ipv6-gap-target` | `l3.ipv6_reachability.safe` | `gap` | `inconclusive` | **inconclusive** | Probe observation recorded |
