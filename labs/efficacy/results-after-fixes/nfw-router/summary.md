# Efficacy Validation Summary: nfw-router

## Manifest Information
- **Lab ID**: `nfw-router`
- **Manifest Path**: `/Users/checkred_admin/Projects/astranull/labs/efficacy/envs/nfw-router/manifest.json`
- **Total Checks Evaluated**: 5

## Confusion Matrix
| Category | Count | Evaluated Checks |
|---|---|---|
| **Detected Gap** | 3 | `nfw.declared_deny_tcp.safe`, `l3.basic_deny_rule.safe`, `nfw.management_port_exposure.safe` |
| **Missed Gap** | 0 | None |
| **False Alarm** | 0 | None |
| **Correct Protected** | 0 | None |
| **Inconclusive** | 2 | `nfw.connection_limit.safe`, `nfw.declared_deny_udp.safe` |
| **Not Applicable** | 0 | None |
| **Skipped Safety** | 0 | None |
| **Execution Error** | 0 | None |

## Detailed Results
| Target | Check ID | Expected | Verdict | Grade | Summary |
|---|---|---|---|---|---|
| `server-behind-nfw-router` | `nfw.declared_deny_tcp.safe` | `gap` | `exposed` | **detected gap** | Declared deny for tcp/22 (ipv4) from astranull-signed-public-worker was violated; denial cannot be proven from outside. |
| `server-behind-nfw-router` | `l3.basic_deny_rule.safe` | `gap` | `exposed` | **detected gap** | Declared deny for tcp/22 (ipv4) from astranull-signed-public-worker was violated; denial cannot be proven from outside. |
| `server-behind-nfw-router` | `nfw.management_port_exposure.safe` | `gap` | `exposed` | **detected gap** | Declared deny for tcp/22 (ipv4) from astranull-signed-public-worker was violated; denial cannot be proven from outside. |
| `server-behind-nfw-router` | `nfw.connection_limit.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | Connection_limit_probe recorded transport or liveness metadata only; it did not establish this check's verdict logic. |
| `server-behind-nfw-router` | `nfw.declared_deny_udp.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | Network firewall probe inconclusive: probe failed with timeout; external denial cannot be verified. |
