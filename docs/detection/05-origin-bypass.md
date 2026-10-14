# Origin Bypass Validation

## Why this matters

Enterprises place CDN/WAF/DDoS protection in front of apps, and the origin can still be reachable through a direct IP, stale DNS, an alternate hostname, or missing origin authentication. AstraNull validates that question **from the outside in** ([ADR-0008](../adr/0008-outside-in-only-targets-first.md)). There is no internal observer to confirm whether a dropped probe reached the origin.

## What an outside-in origin probe can prove

- A Host/SNI request to a **target-bound IP literal** (or IP-literal URL) completed, and the response was classified under `external-observation-v3`.
- With an active declared origin binding **and** `origin.lockdown_expected`: a **non-CDN** peer returned HTTP **2xx** **and** the origin answered as the application for the target hostname (nonce canary / `application_identity_confirmed`) → correlation `exposed` (`nfw.origin_lockdown.safe` / `host_sni_bypass`). A TCP handshake or bare 2xx is not enough.
- DNS-based leak scans recorded public hostname/address metadata for customer-declared hosts (`origin_leak_scan`). Those scans do not contact the origin socket.
- A CDN/WAF edge answering the “direct” address is `not_applicable` (evidence gap), which withholds a lockdown verdict.

## What it cannot prove

- That a timeout, RST, or silent drop means the origin was never reached.
- That a 2xx without application identity is the same application as the protected hostname.
- Origin lockdown from an unsigned 4xx, 5xx, 401, 407, or 421.
- `protected` from silence or from an explicit denial without a **declared** lockdown signature plus a healthy comparable baseline (`origin_lockdown_confirmed` in `classifyDirectOriginObservation`).
- A second socket destination for an FQDN via `probe_profile.direct_ip`, `target.metadata.direct_origin_ip`, resolver fields, or webhook metadata. Host/SNI signed-worker runs require the verified target itself to be an IP or IP-literal URL; otherwise start fails with `missing_target_bound_direct_address` before queueing. The signed-job builder strips alternate destinations after catalog/request/metadata merges.

## Checks

| Check | Probe kind | What it validates | Verdict capability |
|---|---|---|---|
| Direct IP reachability / direct-origin bypass / Host/SNI bypass | `host_sni_bypass` | One bounded HEAD/GET to the target-bound IP with protected Host/SNI. | Observation-only unless the origin-lockdown path fires. |
| Origin lockdown to declared binding (`nfw.origin_lockdown.safe`) | `host_sni_bypass` | Customer-visible. Needs a declared origin binding **and** `origin.lockdown_expected`. | Violation-only: `exposed` only when the origin answers a non-CDN probe with a 2xx as the application for the target hostname (application identity confirmed, not just a TCP handshake). Never `protected`. |
| Origin leak / DNS hostname / CDN bypass readiness | `origin_leak_scan` | Public DNS/subdomain/IPv6 metadata on declared hosts. | Observation-only. |
| WAF origin bypass (`waf.origin_bypass.safe`) | `host_sni_bypass` | Same Host/SNI producer; catalog hides most origin Host/SNI checks from self-serve except `nfw.origin_lockdown.safe`. | Same as Host/SNI. |

Coverage UI shows origin lockdown as **Not assessable** (`reason: no_origin_declared`) when no origin binding and no `lockdown_expected` exist (`src/lib/protectionValidationReport.mjs`). That is distinct from “not applicable because nothing to do.”

## Safe validation method

Signed-worker Host/SNI sends one bounded request when the verified target is an IP literal or a URL with an IP-literal host. Protected HTTP Host / TLS SNI and path are non-destination metadata; they do not retarget the socket.

Classification: `classifyDirectOriginObservation` (`src/lib/externalObservationOutcomes.mjs`).

| Observation outcome | Meaning |
|---|---|
| `application_identity_confirmed` | 2xx/3xx plus nonce-canary (or marker-echo) header match. |
| `explicit_denial_observed` | Declared lockdown signature or declared mTLS rejection. |
| `response_observed` | HTTP response without identity or declared denial. |
| `not_applicable` | CDN/WAF edge answered. |
| `no_response` / `transport_error` | Silence or transport failure; enforcement unverified. |
| `misdirected_request` (421) / `probe_path_error` (407) | Probe-path artifacts; coverage gaps. |

`peer_is_cdn` on the connected address excludes NFW/origin `exposed`.

## Correlation (origin lockdown)

`correlateOriginLockdownVerdict` returns `exposed` (medium, finding) only when all of:

1. An active origin binding is present **and** `declarations.origin.lockdown_expected === true`.
2. `peer_is_cdn` is not true.
3. HTTP status is 2xx.
4. Application fingerprint matched (`application_bypass_confirmed` or `application_identity_confirmed`).

Otherwise Host/SNI remains observation-only `inconclusive`. The catalog copy for `nfw.origin_lockdown.safe` (version 1.1.0) states the same binding requirement and identity gate.

## Expected customer controls (declaration + evidence)

- Origin ingress restricted to CDN/scrubber ranges.
- Authenticated origin pull / mTLS where the customer can declare a lockdown signature.
- Host/SNI validation on the origin.
- No stale DNS to origin.
- `origin.lockdown_expected` and an origin binding so the check is assessable.

## Completion criteria

Origin-bypass validation is complete when AstraNull can expose a confirmed direct application path, withhold `protected` when the origin is silent, and label missing origin declarations as not assessable.
