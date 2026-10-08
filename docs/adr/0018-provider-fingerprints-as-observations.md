# ADR-0018: Provider fingerprints are separate observations

Status: Accepted, 2026-10-08.

## Problem

The live Detect WAF and CDN action queued a signed `waf.fingerprint.safe` job, but that check executed the full marker/evasion scan. On the reported target it captured a healthy HTTP baseline and several marker responses before a later request exhausted the five-second job deadline. The final timeout discarded provider detection. Its raw catalog profile advertised 15 seconds even though normalization and the worker enforce five seconds.

## Decision

- Version `waf.fingerprint.safe` as `2.0.0`, with probe kind `waf_fingerprint_observation`.
- Execute one ordinary, destination-pinned GET and up to three counted CNAME operations. Keep the existing five-second deadline, resolver accounting, ownership/lease/kill-switch checks, and no-redirect policy. No marker, evasion, POST, or direct-origin request is part of provider detection.
- Treat provider detection as E2 observation-only evidence, outside conclusive readiness coverage and readiness-only selection. The user-requested full network assessment includes E2 observations alongside E3 checks, with unchanged execution limits and no E2 scoring. Dedicated marker, evasion, enforcement, and origin checks retain their own scenarios and bounds.
- Keep the legacy `outside_in_waf_scan` executor available for existing signed profiles; do not rewrite historical results or silently upgrade old versions.
- Show the explicit detection action's activity in the Validate tab. An unrun selection must not hide an active run. A cached provider result must not suppress progress/polling for a new detection request.
- Return bounded recorded protocol/port fields and request/response activity. These fields are observations, not new verdict authority. Payload previews remain redacted and bounded.

## Consequences

Provider identification no longer depends on completion of unrelated effectiveness probes. A detected WAF/CDN is not a blocking or capacity claim. A target with previously current fingerprint coverage needs an explicit retest for the new version; its old verdict remains retained history. Other checks can still correctly be inconclusive when a declared protocol endpoint, blocked baseline, or customer setup is absent.

No rate, concurrency, request-volume, SOC, or destination-authorization limit is raised.

## Addendum: independent DNS evidence on an HTTP deadline

Qantas produced completed Akamai DNS evidence but no HTTP response within the same five-second
deadline. A fingerprint-only worker now retains its already-completed, vetted address/CNAME
observation in memory before starting the GET. On a transport deadline it carries that evidence
through the existing signed result, with `partial_provider_observation: true`; no new request,
longer deadline, or earlier durable publication is introduced. WAF presence stays null and no WAF
layer is derived from the unfinished HTTP operation. The overall observation and protection are
inconclusive, while supported CDN/cloud families can be detected independently.

The API and both persistence modes accept such a partial observation only for the fingerprint
profile with actual typed, positive address/CNAME/ASN evidence and observed DNS. Untyped flags,
simulations, unrelated profiles and failures without provider evidence retain the existing failure
behavior. Existing run/result audits, signed operation attestations, and tenant/nonce/lease checks
remain authoritative. This is observation history, never enforcement or readiness evidence.
