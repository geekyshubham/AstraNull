# Recorded probe execution activity

The target workspace exposes a timestamped activity table and the existing console view. Both show recorded run state, authenticated worker telemetry, and final probe results. Catalog phases, request bounds, and a rotating indicator never produce fabricated requests, timings, provider matches, or HTTP status codes.

## Worker and persistence

`POST /internal/probe/jobs/:id/activity` uses the existing worker HMAC over the method, full path, timestamp, tenant, and raw body. The body is limited to 32 KiB and has only `leased_at` plus up to 16 structured `items`. Each item has an ordinal from 1 to 256, recorded timestamp, fixed stage, and optional allowlisted operation/method/URL/protocol/status/duration/count/header-name fields. Unrestricted bodies, packets, header values, cookies, authorization values, and arbitrary log strings are rejected. At the customer's explicit request, HTTP application payloads have a bounded, redacted preview (up to 2 KiB consumed bytes / 4096 rendered characters). Declared private query values and credentials stay withheld; generated benign query markers can be inspected separately. Preview fields are explicitly marked partial/truncated and never become replay controls.

The tenant, run, target, check, and nonce come from the leased job, never the body. The lease holder and exact lease timestamp must match. The run must be active and the tenant kill switch clear. PostgreSQL ingestion holds the run mutation lock and shares the kill-switch transaction lock. Cancellation revokes both the run and job. Identical event ordinals replay without mutation; conflicting replays return 409. Event identities include the lease timestamp so a reclaimed job cannot overwrite the old attempt.

`probe_activity` events have `producer_kind: signed_probe` and the normal tenant RLS/retention. Migration `0065_probe_activity_provenance.sql` enforces producer provenance; public event ingestion rejects this reserved signal. Telemetry has its own 256-item bound and does not consume the check's verdict-evidence budget, authorize additional probe I/O, enter correlation as a probe result, create evidence-vault proof, or publish a verdict.

The worker reports actual methods, paths, vector/check and phase identity, status codes, observed Content-Type, request/query payload previews, response payload previews, encoding and truncation state. HTTP/1 capture is a transparent transform over only the response bytes the existing probe reads; HTTP/2 observes its already bounded data drain. Neither creates an additional request, clones/refetches a body, or drains beyond the probe's budget. Non-HTTP requests expose recorded DNS/TLS/protocol fields rather than fabricated HTTP methods or status codes. Batches fit the signed 32-KiB limit even with previews and transient failures retry the same immutable ordinals. The worker reports real transport/phase callbacks and polls lease acknowledgments while executing. A stop acknowledgment aborts its cooperative deadline signal and prevents subsequent attempts. An in-flight bounded transport can finish while Stop propagates. Missing activity during a control-plane outage remains missing; the final attested result is independent of telemetry.

## Reads and UX

`GET /v1/test-runs/:id/activity?limit=200` requires `test_run:read`, returns 404 across tenant boundaries, and is passive: it never finalizes a run, advances a scan, leases a job, or dispatches a probe. Its bounded response contains run/check/target IDs, recorded lifecycle status/timestamps, nullable attested operation count, `telemetry_recorded`, latest `items`, `count`, and `truncated`. Simulations remain marked as simulations. Untrusted historical claims do not become worker activity.

The table supports search, info/not-sent/error filtering, pause/resume of display updates, and expandable event details. Pausing updates does not stop execution. The target header exposes **Stop validation** for a batch or **Stop current check** for a standalone run, regardless of the selected tab. An active check also has a scoped Stop action. Stopping one child allows the batch to proceed; stopping validation cancels the active child and prevents the queued steps from starting. Stop uses the existing audited, permission-checked cancel APIs.

Current external inconclusive results remain evaluated coverage. A pending run without a verdict never appears as invalid retained proof. Public detection labels use AstraNull terminology; immutable stored evidence and required source notices are retained.

## Acceptance

- Authenticated, lease-bound activity is immutable, tenant-isolated, bounded, and rejected after cancellation.
- Reads have no execution, finalization, audit, or verdict side effects.
- Actual HTTP method/path/vector/status/format/count observations and readable redacted payload previews are shown without exposing credentials or raw protocol packets.
- All console/table entries have recorded source data; no generated latencies, responses, packet counts, or idle timestamps.
- Stop works for standalone checks and whole scans with the existing audit trail and safety gates.
- Controls, row details, pause, filters, responsive scrolling, light/dark contrast, and keyboard focus work at 375/768/1024/1440 pixels.
- Unit, HTTP integration, real PostgreSQL/RLS, browser, build, lint, schema, and safety checks pass.

## Live verification (2026-10-04)

CI and AWS deployment succeeded for `f4654c3a`. The live `tgt_794d63f6ec7459eb` workspace returned signed worker activity with actual HEAD/POST methods, WAF vector identity, HTTP 200/403/431 statuses, observed HTML MIME types, request/body preview fields, and operation counts. A live POST entry expanded to show its 70-byte request, captured preview and readable explanation. Stop validation and Stop run were visible without canceling the ongoing approved batch. Coverage had 0 partial pairs; current inconclusive results remained evaluated. The batch had completed 109 of 149 checks and preserved queued/deferred safety gates. Headers-only checks explicitly report that their response bodies were not consumed rather than inventing a payload.
