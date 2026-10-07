# Live detection and activity repair

Scope: the reported target workspace, WAF/CDN detection, worker execution routes, and recorded activity. Credentials and bearer tokens are never included in this record.

## Diagnosis

The live deployment was `58e0e4fd`. The detection button opened a review and returned HTTP 202 when started. Run `run_3e682bdaa384b9a9` on target `tgt_bbcda0fadb91a1b3` captured 58 activity records and 12 attested operations. It observed baseline HTTP 200, combined/SQLi marker HTTP 403, traversal HTTP 404, and XSS marker HTTP 200, then timed out during a subsequent phase with `probe_job_deadline_exceeded`. This was a worker execution failure rather than a broken click handler.

Opening Validate showed the recorded activity; the detection action did not navigate there automatically. An unrun check selection could hide that run, and an existing provider result suppressed retry/polling on a new detection. Final protocol summaries also omitted useful DNS and port observations, and activity search ignored phase/vector/content-type fields.

## Changes

- [ADR-0018](../adr/0018-provider-fingerprints-as-observations.md): provider-only fingerprint with one GET, bounded counted CNAME work, and the unchanged five-second deadline.
- Versioned fingerprint observation excluded from readiness; efficacy checks remain separately runnable.
- Detection opens Validate and selects its own check. Active standalone observations are followed even when excluded from readiness Run all.
- Individually runnable E2 observations remain in the check list; readiness batches and their progress denominator exclude them.
- The console shows recorded transport results neutrally, then the published verdict separately. Missing request counts stay missing; request activity cannot suppress a recorded final result.
- Activity responses from a previously opened target are ignored after navigation.
- An unrun selection falls back to actual active/latest activity; a selection with historical evidence stays pinned.
- Re-detection progress wins over cached provider observations, and polling stops on the new request's terminal state.
- Activity reads request the full existing 256-item bound; the display reports the actual truncated count and searches phases, vectors, and response formats.
- Final result details expose only allowlisted primitive protocol fields and bounded valid port arrays. No unrestricted metadata, credentials, or additional network request is introduced.

## Catalogue validation

The catalogue contains 251 checks. All declared executable probe kinds are mapped to workers; the registry validates 249 vectors and all 721 canonical vector rows. Declaration-only and SOC-governed entries retain their execution boundaries. Tests cover signed request/resolver/duration accounting, destination pinning, protocol executors, correlation, and tenant-scoped persistence.

The [per-check audit](check-execution-audit-2026-10-08.json) records all 251 definitions, execution mappings, bounds, target-kind compatibility, and required setup.

This is an implementation audit, not a claim that every protocol on this web domain is healthy. Unsupported/missing endpoints and missing blocked baselines are reported as exclusions or inconclusive observations. The live group has a 60-runs-per-hour policy; verification does not bypass it or split targets into groups.

## Verification and rollout

Local verification passed: 4,748 unit tests, 459 integration tests (one explicitly opt-in live-DNS test skipped), 21 Node E2E tests, 16 contract tests, and 19 focused browser journeys including dark/light themes and 375–1440px viewports. Typecheck/build, lint, portal lint, safety, schema, tenant-query audit, taxonomy, generated catalogue, and corpus parity passed. Deployment uses the repository's CI-triggered AWS workflow. Exact deployment revision and live retest results will be recorded after rollout. Logs and metadata-only reproduction details are under `/tmp/astranull-live-repair-20261008/`.
