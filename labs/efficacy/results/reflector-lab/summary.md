# Efficacy Validation Summary: reflector-lab

## Manifest Information
- **Lab ID**: `reflector-lab`
- **Manifest Path**: `/Users/checkred_admin/Projects/astranull/labs/efficacy/envs/reflector-lab/manifest.json`
- **Total Checks Evaluated**: 7

## Confusion Matrix
| Category | Count | Evaluated Checks |
|---|---|---|
| **Detected Gap** | 4 | `reflect.redis_direct_exposure.safe`, `reflect.chargen_qotd_exposure.safe`, `reflect.ssdp_exposure.safe`, `reflect.stun_turn_exposure.safe` |
| **Missed Gap** | 0 | None |
| **False Alarm** | 0 | None |
| **Correct Protected** | 0 | None |
| **Inconclusive** | 1 | `reflect.redis_direct_exposure.safe` |
| **Not Applicable** | 2 | `reflect.ipp_callback_exposure.safe`, `amp.memcached_exposure.safe` |
| **Skipped Safety** | 0 | None |

## Detailed Results
| Target | Check ID | Expected | Verdict | Grade | Summary |
|---|---|---|---|---|---|
| `reflector-exposed-services` | `reflect.redis_direct_exposure.safe` | `gap` | `exposed` | **detected gap** | Redis (tcp/6379) accepted a TCP handshake from astranull-signed-public-worker on 2 of 2 samples; Redis should never be reachable from the internet. |
| `reflector-exposed-services` | `reflect.chargen_qotd_exposure.safe` | `gap` | `exposed` | **detected gap** | Open CharGen reflector reachable from the internet: a protocol-validated reply came back on udp/19 to astranull-signed-public-worker. This is direct evidence of an open reflector from the reply itself, independent of any firewall declaration. |
| `reflector-exposed-services` | `reflect.ssdp_exposure.safe` | `gap` | `exposed` | **detected gap** | Open SSDP reflector reachable from the internet: a protocol-validated reply came back on udp/1900 to astranull-signed-public-worker. This is direct evidence of an open reflector from the reply itself, independent of any firewall declaration. |
| `reflector-exposed-services` | `reflect.stun_turn_exposure.safe` | `gap` | `exposed` | **detected gap** | Open STUN reflector reachable from the internet: a protocol-validated reply came back on udp/3478 to astranull-signed-public-worker. This is direct evidence of an open reflector from the reply itself, independent of any firewall declaration. |
| `reflector-exposed-services` | `reflect.ipp_callback_exposure.safe` | `not_applicable` | `not_applicable` | **not_applicable** | src/lib/probeEvidenceTiers.mjs line 2 marks ipp_get_printer_attributes as unsupported_or_unapproved_protocol_request with no approved execution adapter |
| `reflector-exposed-services` | `amp.memcached_exposure.safe` | `not_applicable` | `not_applicable` | **not_applicable** | src/contracts/checks.mjs line 2309 and src/lib/reflectorPayloads.mjs line 117 require memcached stats dump; excluded per CONTRACT.md hard safety rule barring amplification tooling and large stats dumps |
| `reflector-protected-host` | `reflect.redis_direct_exposure.safe` | `protected` | `inconclusive` | **inconclusive** | Tcp_connect recorded transport or liveness metadata only; it did not establish this check's verdict logic. |
