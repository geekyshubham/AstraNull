# Recorded probe execution activity

## Current authority and Inspector contract (2026-10-09)

This section supersedes the earlier signing, latest-slice and Stop wording below for the current engineering tree. See [ADR-0021](../adr/0021-bounded-execution-and-evidence-based-assurance.md). Historical live-verification entries below are prior-release records, not deployment evidence for this remediation.

- Worker `pw2` signs worker identity plus method, full path, timestamp, tenant and raw body. `probe-authority-v2` has immutable issue time, absolute deadline and one execution attempt. `/internal/probe/jobs/:id/execute` must reserve the whole signed allowance before destination I/O; no recovery/reclaim renewal.
- Activity bodies allow `{ leased_at, items, capture }`; capture is bounded `probe-capture.v1` metadata. Up to 256 immutable lease/sequence items, batches of 16 within 32 KiB. Reporter heartbeats and bounded partition grace abort work on persistent/hung reporting failures or revocation. Activity cannot authorize I/O or supply verdict proof.
- Run and scan reads support opaque scoped cursors. Advance only over the returned earliest next prefix; ingestion identity preserves late/reordered observations. Invalid/foreign cursors fail with 400. Complete internal readers are distinct from capped public feeds; compatibility fallbacks expose `input_complete: false` and incomplete capture. Retained-event pagination never silently claims packet-complete capture.
- Accepted Play automatically opens/focuses the exact returned run or scan. Approximately 2.5-second passive polling, bounded reconnect backoff, retained-page dedupe and terminal fetch preserve final events. Historical pins remain pinned; follow-active-child is explicit. Credential rotation rebinds the reader through an opaque credential epoch, without putting raw credentials into reader keys, URLs or logs. Dedicated reviewed starts preserve exact cross-target execution identity; comparison children are bound to the submitted plan, never the newest execution. Missing returned IDs remain explicit. Display pause never changes execution.
- Assessment display bookmarks retain `ev_display=follow|pinned` and, only for a pinned selection, `ev_pin=<exact run ID>`. Legacy bookmarks follow the active child of their exact assessment. Restoration first reads the exact assessment passively and verifies child membership and target scope before child activity/evidence reads. Invalid, missing, foreign or inaccessible pins remain explicitly unavailable; no newer child or assessment is substituted. Display fields never enter `/v1/evidence-context` or grant execution authority. Pin/Follow changes preserve workspace identity and the exact IDs captured by an open Stop confirmation.
- Stop uses existing scoped cancel APIs and separately records `stop_requested`, authenticated same-lease worker acknowledgement, worker unavailable, or absolute deadline elapsed. Database cancellation alone is not packet-stop proof. `/internal/probe/jobs/:id/stop` can acknowledge revocation without sending more traffic. UI distinguishes signed maxima/reservation from actual attested operations and recorded metadata loss.
- Actual approved endpoint/method/path/port/SNI/protocol/source, response facts and bounded redacted previews are shown only when recorded. No invented origin receipt, latencies, internal cloud state or per-packet capture.


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
