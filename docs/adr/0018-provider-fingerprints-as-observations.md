# ADR-0018: Provider fingerprints are separate observations

Status: Accepted, 2026-10-08.

## Problem

The live Detect WAF and CDN action queued a signed `waf.fingerprint.safe` job, but that check executed the full marker/evasion scan. On the reported target it captured a healthy HTTP baseline and several marker responses before a later request exhausted the five-second job deadline. The final timeout discarded provider detection. Its raw catalog profile advertised 15 seconds even though normalization and the worker enforce five seconds.

## Decision

- Version `waf.fingerprint.safe` as `2.0.0`, with probe kind `waf_fingerprint_observation`.
- Execute one ordinary, destination-pinned GET and up to three counted CNAME operations. Keep the existing five-second deadline, resolver accounting, ownership/lease/kill-switch checks, and no-redirect policy. No marker, evasion, POST, or direct-origin request is part of provider detection.
- Treat provider detection as E2 observation-only evidence, outside readiness coverage and the reviewed readiness Run all selection. Dedicated marker, evasion, enforcement, and origin checks retain their own scenarios and bounds.
- Keep the legacy `outside_in_waf_scan` executor available for existing signed profiles; do not rewrite historical results or silently upgrade old versions.
- Show the explicit detection action's activity in the Validate tab. An unrun selection must not hide an active run. A cached provider result must not suppress progress/polling for a new detection request.
- Return bounded recorded protocol/port fields and request/response activity. These fields are observations, not new verdict authority. Payload previews remain redacted and bounded.

## Consequences

Provider identification no longer depends on completion of unrelated effectiveness probes. A detected WAF/CDN is not a blocking or capacity claim. A target with previously current fingerprint coverage needs an explicit retest for the new version; its old verdict remains retained history. Other checks can still correctly be inconclusive when a declared protocol endpoint, blocked baseline, or customer setup is absent.

No rate, concurrency, request-volume, SOC, or destination-authorization limit is raised.
