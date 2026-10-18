# Efficacy Validation Summary: dns-lab

## Manifest Information
- **Lab ID**: `dns-lab`
- **Manifest Path**: `/Users/checkred_admin/Projects/astranull/labs/efficacy/envs/dns-lab/manifest.json`
- **Total Checks Evaluated**: 6

## Confusion Matrix
| Category | Count | Evaluated Checks |
|---|---|---|
| **Detected Gap** | 2 | `dns.secondary_failover.safe`, `dns.zone_transfer_exposure.safe` |
| **Missed Gap** | 0 | None |
| **False Alarm** | 0 | None |
| **Correct Protected** | 0 | None |
| **Inconclusive** | 3 | `dns.authoritative_response.safe`, `dns.random_prefix_nxdomain.safe`, `dns.open_recursion_behavior.safe` |
| **Not Applicable** | 1 | `dns.amplification_exposure.safe` |
| **Skipped Safety** | 0 | None |
| **Execution Error** | 0 | None |

## Detailed Results
| Target | Check ID | Expected | Verdict | Grade | Summary |
|---|---|---|---|---|---|
| `authoritative-dns-server` | `dns.authoritative_response.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | Dns_wire_query recorded transport or liveness metadata only; it did not establish this check's verdict logic. |
| `authoritative-dns-server` | `dns.random_prefix_nxdomain.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | Dns_wire_query recorded transport or liveness metadata only; it did not establish this check's verdict logic. |
| `authoritative-dns-server` | `dns.secondary_failover.safe` | `gap` | `exposed` | **detected gap** | The zone lab.efficacy.invalid is delegated to a single nameserver (ns1.lab.efficacy.invalid), so there is no secondary to answer if it is overwhelmed. |
| `authoritative-dns-server` | `dns.zone_transfer_exposure.safe` | `gap` | `exposed` | **detected gap** | At least one authoritative nameserver answered a zone transfer (AXFR) request from the internet. Nameservers that allowed the transfer: ns1.lab.efficacy.invalid. |
| `authoritative-dns-server` | `dns.open_recursion_behavior.safe` | `inconclusive_expected` | `inconclusive` | **inconclusive** | Dns_open_recursion recorded transport or liveness metadata only; it did not establish this check's verdict logic. |
| `authoritative-dns-server` | `dns.amplification_exposure.safe` | `not_applicable` | `not_applicable` | **not_applicable** | Minimal ANY responses configured (minimal-any yes); large ANY/TXT responses are intentionally not built to avoid creating an amplifier in accordance with lab safety contract |
