# Origin exposure: source associations and authorized validation

Date: 2026-10-16. Decision: [ADR-0032](../adr/0032-origin-associations-and-paired-identity.md). Extends PV-01, PV-04 and PV-07; live acceptance remains open. This document describes the evidence contract, not proof of deployed capability.

## Research and algorithm comparison

The [Trickest workflow page](https://trickest.com/library/cloudflare-origin-ip-finder-waf-bypass), dated 2026-09-03, contains different pipelines. Its prose describes subfinder → DNS → CDN-address filtering → direct comparison. Its embedded graph instead describes fetching `trickest/cloud`, matching certificate CN/SAN fields to a hostname, filtering CDN addresses and comparing direct responses. Public graph annotations were inspected; executable node scripts were not obtained.

The graph assigns certificate-name validity 40 points, title 20, favicon 20, body hash 15 and Server header 5, with 40 labelled confirmed. Elsewhere it requires both certificate and body matches. AstraNull must not copy this inconsistent threshold: shared certificates, defaults and copied pages are not current application identity. CDN certificates also cover customer hostnames.

| Technique / source | Contribution | Limitation |
|---|---|---|
| [trickest/cloud](https://github.com/trickest/cloud) | Externally indexed AWS EC2/GCP IP-to-certificate observations; CN/SAN association | Upstream acquisition includes broad scanning. Consuming supplied records is not permission to scan or probe. Repository update time is not a per-IP observation time. |
| [CloudFlair](https://github.com/christophetd/CloudFlair/blob/master/cloudflair.py) | Censys certificate search → indexed host mapping → exact or structural HTML comparison (>0.9) | Inspected code uses IP URLs plus Host, disables TLS verification and does not explicitly set hostname SNI. Legacy API compatibility/free access is not established. |
| [CloudFail](https://github.com/m0rtem/CloudFail/blob/master/cloudfail.py) | DNSDumpster, legacy Crimeflare mapping and wordlist subdomains | Non-CDN addresses are only clues; no rigorous current application identity confirmation. Do not port wordlist probing or evasion. |
| [DNS-history approach](https://github.com/vincentcox/bypass-firewalls-by-DNS-history) | Historical addresses, subdomains and response similarity | Old servers can be stale replicas or reassigned addresses. Listed provider integrations are not guaranteed current. |
| [hakoriginfinder](https://github.com/hakluke/hakoriginfinder/blob/main/hakoriginfinder.go) | Supplied candidate list, preserved Host and explicit SNI, body edit distance | Disables TLS verification; matching is not authorization. Do not add unbounded quadratic similarity. |
| [Certificate transparency](https://developers.cloudflare.com/ssl/certificate-transparency-monitoring/) | Certificate/name issuance observations | Not an authoritative current hostname-to-IP map. Wildcard/SAN coverage is not ownership. |
| [DNS-only / mail infrastructure](https://developers.cloudflare.com/dns/manage-dns-records/troubleshooting/exposed-ip-address/) | A/AAAA/CNAME associations; MX/SPF clues about shared hosting | Mail often belongs to unrelated service providers. IPv6 divergence and arbitrary headers do not establish origin exposure. |

Broad cloud sweeps, CIDR expansion, port scanning, forced callbacks, SSRF, exploit chains, cloud-account credentials and customer agents are excluded. No passive index service or paid key is required for the core workflow.

## AstraNull gap audit and implemented slice

| Area | Existing behavior found during audit | Local change / remaining boundary |
|---|---|---|
| Public associations | Bounded apex A/AAAA, fixed-prefix DNS and one edge HEAD; no historical/certificate-host origin association store | Added explicitly opted-in append-only DNS/reference/import records. No mandatory live feeds, broad scan or auto-created inventory. |
| CT | Existing descendant-hostname source and explicit child-target workflow | Retained separately. CT does not become an origin-IP feed or implicit probe authorization. |
| Peer evidence | `x-backend-ip` could corroborate address divergence despite being a response header | Only pinned transport identifies the observed peer; headers remain untrusted clues and observed addresses are not confirmed origins. |
| Execution authority | Initial bound-run validation existed, but durable grants did not consistently recheck both sides | Shared memory/PostgreSQL exact binding/target/two-proof checks at grant, with real row-lock contention tests. Archive cancels pending work; general implicit-proof invalidation has no proactive queue sweep. |
| Application comparison | Existing one-HEAD origin observation had no permitted-path baseline; independent jobs could not supply one shared nonce/worker | Added separate reviewed HEAD/GET pairs through the existing comparison lifecycle. Ordinary one-HEAD checks are unchanged. Content-only matches stay supporting; fresh nonce proof is stronger but is not a WAF-rule test. |
| Target workspace | Protected-side bindings could point users to origin-only evidence; exact historical context was incomplete | Both sides resolve the same immutable binding/run evidence. Overview separates source associations, explicit declaration/verification/binding and reviewed execution. |
| Acceptance | E2 observations and violation-only lockdown were not universal mitigation proof | Kept those exclusions. Live owned canary/provider/IPv6/staging acceptance, positive typed lockdown production and fresh source-bound catalog capture remain open. |

## Evidence ladder

1. **Possible association:** a source associates a hostname/address. Unverified; not a target or active destination.
2. **Declared relation:** existing same-tenant protected and independently verified IP targets are explicitly bound to derived Host/SNI/port/path. No traffic or lockdown claim.
3. **Response observed:** a bounded authorized direct request produced a reply. This is not necessarily the expected application.
4. **Application identity:** a static application marker or nonce can support the existing identity outcome, with method and limitations retained. Certificate/content/title/Server similarity alone cannot become nonce proof.
5. **Declared-lockdown violation:** the existing violation-only check requires declared lockdown, an exact eligible binding, non-edge 2xx and application identity. This does not prove a particular WAF rule was bypassed.
6. **Paired nonce-confirmed application path:** the exact fresh healthy baseline and direct observation share nonce, worker, source, scenario, method, Host/path and port. Stronger confirmation retains the existing <=60-second rule. It does not prove all security controls bypassed or DDoS capacity absent.

No response, timeout, refusal, unsigned 403, ordinary TLS error, empty sources and unknown source times are inconclusive. Ordinary E2 origin checks earn no positive readiness credit; origin-lockdown remains violation-only. Historical signed evidence is immutable and never silently upgraded.

## Optional source contract

Only opted-in tenants can collect/import origin associations; the default is off. This is optional enrichment, not automatic inventory discovery. Records are append-only in a dedicated store, separate from signed target observations and hostname-only discovery. Keep source kind/reference/digest, target, associated hostname, candidate IP/family when supplied, source observation time (nullable), import/retrieval time, certificate names and limitations.

Initial collection is bounded DNS for the selected declared FQDN and explicitly selected related declared hosts. CNAME/MX/TXT references are not followed, SPF networks are not expanded and referenced mail providers are not contacted. Source failures remain partial/unknown coverage, never fresh negative assurance. Supplied historical-DNS/certificate-index JSON and documented Trickest CSV are accepted within bounds; references are provenance, not fetch URLs. No default full-dataset download or live Censys/Shodan/SecurityTrails adapter is implied.

Source matching uses canonical public IPv4/IPv6, exact DNS-label boundaries and one-leftmost-label certificate wildcard semantics. Duplicate feeds are not independent proof. CSV records without per-IP observation times retain null timestamps.

The target Overview exposes the source records and a reviewed collection/import action, source coverage, unknown times and evidence limits. Selection and inspection are passive. A clue never creates a target, ownership proof, binding or probe. A user must independently declare/prove/bind an address before reviewing any execution.

## Execution and presentation boundary

Both target proofs, the active binding, target lifecycle and exact immutable scope must be rechecked at execution grant, not just admission. Archive/revocation prevents later grants. Valid historical evidence is shown separately from current execution authorization on both sides of a binding, with exact binding/run/check/target/scope references. Never borrow sibling or cross-binding evidence or select the first of multiple bindings.

A separately reviewed paired scenario must reuse entry-path lifecycle and signed jobs rather than combine unrelated historical jobs. HEAD mode has two requests; optional GET support has two requests with at most 8 KiB per leg. No inferred URLs, redirects, login submissions, extra favicon/assets or hidden retries. Content-only matches remain supporting. New paired HTTPS requests verify TLS; legacy paths that disable verification are labelled unverified and cannot imply trusted TLS. The outstanding typed declared-origin-denial producer and positive-denial acceptance are not completed by this feature.

## Detecting discovery attempts

AstraNull can observe public associations and authorized direct paths externally. Passive third-party history/CT/index queries are generally not visible in origin HTTP logs. DNS queries may leave resolver/authoritative telemetry; do not say all enumeration is invisible. Direct HTTP/TLS confirmation reaches origin-side logs and may be absent from CDN request logs.

Customer-operated detection can correlate actual socket peer, Host/SNI, authenticated CDN transport and trusted CDN identifiers. Headers alone are spoofable. No internal log collector, agent, credential prerequisite or attacker-activity claim is introduced here.

[Cloudflare origin hardening guidance](https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/) recommends source restriction, IP rotation with restrictions, authenticated origin pulls or outbound-only tunnels. [Global AOP](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/) establishes Cloudflare-network origin, not a particular customer account; customer-specific certificates can be more specific. Outside-in silence cannot certify these controls.

## Acceptance

Use deterministic fixtures before any external smoke test. Cover malformed/oversized inputs, exact/wildcard certificate matching, stale/unknown source times, duplicate records, wildcard/shared DNS, third-party MX/SPF, IPv6, source failures, tenant/RBAC/RLS/idempotency, passive reads, zero auto-promotion, revocation between lease and grant, exact-scope evidence projection, signed paired scope and request bounds, cancellation and strict nonce proof. Verify mobile/desktop, light/dark, keyboard, empty/error/disabled states. Record actual results in PROGRESS; local fixtures do not satisfy the separately authorized staging/live gates.
