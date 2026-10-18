# Efficacy Validation Summary: fault-lab

## Manifest Information
- **Lab ID**: `fault-lab`
- **Manifest Path**: `/Users/checkred_admin/Projects/astranull/labs/efficacy/envs/fault-lab/manifest.json`
- **Total Checks Evaluated**: 9

## Confusion Matrix
| Category | Count | Evaluated Checks |
|---|---|---|
| **Detected Gap** | 0 | None |
| **Missed Gap** | 0 | None |
| **False Alarm** | 0 | None |
| **Correct Protected** | 0 | None |
| **Inconclusive** | 0 | None |
| **Not Applicable** | 9 | `l3.firewall_exposure_scan.safe`, `l3.ipv6_reachability.safe`, `l3.smtp_connection_flood.readiness`, `l3.ssh_connection_flood.readiness`, `l3.ftp_connection_flood.readiness`, `reflect.redis_direct_exposure.safe`, `nfw.management_port_exposure.safe`, `nfw.ipv6_parity.safe`, `nfw.connection_limit.safe` |
| **Skipped Safety** | 0 | None |

## Detailed Results
| Target | Check ID | Expected | Verdict | Grade | Summary |
|---|---|---|---|---|---|
| `fault-container-loopback` | `l3.firewall_exposure_scan.safe` | `not_applicable` | `not_applicable` | **not_applicable** | The signed probe worker cannot join network none |
| `fault-container-loopback` | `l3.ipv6_reachability.safe` | `not_applicable` | `not_applicable` | **not_applicable** | The signed probe worker cannot join network none |
| `fault-container-loopback` | `l3.smtp_connection_flood.readiness` | `not_applicable` | `not_applicable` | **not_applicable** | The signed probe worker cannot join network none |
| `fault-container-loopback` | `l3.ssh_connection_flood.readiness` | `not_applicable` | `not_applicable` | **not_applicable** | The signed probe worker cannot join network none |
| `fault-container-loopback` | `l3.ftp_connection_flood.readiness` | `not_applicable` | `not_applicable` | **not_applicable** | The signed probe worker cannot join network none |
| `fault-container-loopback` | `reflect.redis_direct_exposure.safe` | `not_applicable` | `not_applicable` | **not_applicable** | The signed probe worker cannot join network none |
| `fault-container-loopback` | `nfw.management_port_exposure.safe` | `not_applicable` | `not_applicable` | **not_applicable** | The signed probe worker cannot join network none |
| `fault-container-loopback` | `nfw.ipv6_parity.safe` | `not_applicable` | `not_applicable` | **not_applicable** | The signed probe worker cannot join network none |
| `fault-container-loopback` | `nfw.connection_limit.safe` | `not_applicable` | `not_applicable` | **not_applicable** | The signed probe worker cannot join network none |
