# Efficacy Validation Summary: nfw-ipv6-gap

## Manifest Information
- **Lab ID**: `nfw-ipv6-gap`
- **Manifest Path**: `/Users/checkred_admin/Projects/astranull/labs/efficacy/envs/nfw-ipv6-gap/manifest.json`
- **Total Checks Evaluated**: 2

## Confusion Matrix
| Category | Count | Evaluated Checks |
|---|---|---|
| **Detected Gap** | 2 | `nfw.ipv6_parity.safe`, `l3.ipv6_reachability.safe` |
| **Missed Gap** | 0 | None |
| **False Alarm** | 0 | None |
| **Correct Protected** | 0 | None |
| **Inconclusive** | 0 | None |
| **Not Applicable** | 0 | None |
| **Skipped Safety** | 0 | None |
| **Execution Error** | 0 | None |

## Detailed Results
| Target | Check ID | Expected | Verdict | Grade | Summary |
|---|---|---|---|---|---|
| `nfw-ipv6-gap-target` | `nfw.ipv6_parity.safe` | `gap` | `exposed` | **detected gap** | Declared deny for tcp/8080 (ipv6) from astranull-signed-public-worker was violated; denial cannot be proven from outside. IPv6 parity mismatch: ipv6 is the leaking family. |
| `nfw-ipv6-gap-target` | `l3.ipv6_reachability.safe` | `gap` | `exposed` | **detected gap** | Declared deny for tcp/8080 (ipv6) from astranull-signed-public-worker was violated; denial cannot be proven from outside. IPv6 parity mismatch: ipv6 is the leaking family. |
