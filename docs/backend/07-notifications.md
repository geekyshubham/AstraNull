# Notifications

## Implemented behavior

Customer notification **rules** and a per-event **delivery-attempt ledger** live in the dev JSON store (`notificationRules`, `notificationEvents`) for developer validation and in Postgres through `runtime.services.notifications` when `ASTRANULL_PERSISTENCE_MODE=postgres`. Outbound delivery is **opt-in by default**: no email, Slack, Microsoft Teams, or webhook HTTP traffic is sent unless delivery mode is explicitly enabled. Default mode (`metadata_only`, unset `ASTRANULL_NOTIFICATION_DELIVERY_MODE`) preserves metadata-only `queued_provider_not_configured` for external channels.

### Rule validation

`createNotificationRule` validates and normalizes:

| Field | Rules |
|---|---|
| `channel` | One of `in_app`, `webhook`, `email`, `slack`, `teams`. |
| `triggers` | Non-empty subset of allowed triggers (defaults: `finding.high_severity`, `high_scale.state_change`). |
| `destination` | Required and non-empty for all channels except `in_app`. |
| Webhook `destination` | Must be `https://` in general. `http://127.0.0.1`, `http://localhost`, and hosts ending in `.invalid` are allowed for local/test validation only. |

Invalid `channel` or `trigger` values return `{ error, status: 400 }`. Arbitrary provider secret fields from the request body are not persisted.

### Allowed triggers

| Trigger | Typical use |
|---|---|
| `finding.high_severity` | Critical finding created |
| `agent.offline` | Agent heartbeat loss |
| `safe_test.completed` | Validation test finished |
| `high_scale.state_change` | High-scale workflow state transitions |
| `report.ready` | Report generation complete |
| `bootstrap_token.created` | Bootstrap token issued |
| `bootstrap_token.revoked` | Bootstrap token revoked |

### Emit path and ledger

`emitNotification`:

1. Matches enabled rules for the tenant and trigger.
2. Stores a notification event with **redacted** `subject` and `metadata` (`redactObject` / `redactString`).
3. Appends one **delivery attempt** per matching rule with safe fields only: `id`, `rule_id`, `channel`, `destination_preview`, `status`, `reason`, `created_at`, `attempted_at`, and when applicable retry/DLQ metadata (`attempt_number`, `max_attempts`, `next_retry_at`, `provider_error`, `exhausted`, `provider_status`). No full provider destination URL, tokens, secrets, request bodies, or raw provider logs are stored; only redacted `destination_preview` and safe error/status fields.

Postgres migration [`0006_notification_rule_triggers.sql`](../../db/migrations/0006_notification_rule_triggers.sql) adds `notification_rules.triggers_json` for multi-trigger rules and `notification_events.metadata_json` for redacted event metadata. `notificationRepository` keeps rule/event/attempt reads tenant-scoped under RLS, and `notificationServiceAdapters` owns validation, redaction, metadata-only delivery attempts, and audit writes for `GET/POST /v1/notifications`.

Delivery statuses in this slice:

| Channel | Status | Meaning |
|---|---|---|
| `in_app` | `delivered_in_app` | Recorded in tenant in-app feed (no external send). |
| `webhook`, `email`, `slack`, `teams` | `queued_provider_not_configured` | Default mode: metadata queued; no network send. |
| `webhook` (opt-in) | `delivered_provider` | `ASTRANULL_NOTIFICATION_DELIVERY_MODE=webhook` (or injected `deliveryMode` in tests): HTTPS POST with redacted JSON body succeeded. |
| `webhook` (opt-in) | `provider_retry_scheduled` | Webhook attempt failed with retries remaining (`attempt_number`, `max_attempts`, `next_retry_at`). |
| `webhook` (opt-in) | `provider_failed_dlq` | Webhook attempt failed and retry budget exhausted, or pre-send validation failed (e.g. URL credentials). |
| `email` (opt-in) | `delivered_provider` / `provider_retry_scheduled` / `provider_failed_dlq` | SMTP via `deliverEmail` when `ASTRANULL_NOTIFICATION_DELIVERY_MODE` includes `email` (or `all`). |
| `slack` (opt-in) | `delivered_provider` / `provider_retry_scheduled` / `provider_failed_dlq` | Block Kit JSON via HTTPS webhook when mode includes `slack` (or `all`). |
| `teams` (opt-in) | `delivered_provider` / `provider_retry_scheduled` / `provider_failed_dlq` | Adaptive Card JSON via HTTPS webhook when mode includes `teams` (or `all`). |

Opt-in delivery (`src/lib/notificationDelivery.mjs`) activates per channel when `ASTRANULL_NOTIFICATION_DELIVERY_MODE` includes that channel (comma-separated `webhook,email,slack,teams`, or `all`). Default `metadata_only` keeps all external channels at `queued_provider_not_configured`. Webhook/Slack/Teams sends use HTTPS-only remote destinations (dev/test `http://127.0.0.1`, `http://localhost`, and `*.invalid` allowed per rule validation), reject URL-embedded credentials, do not follow redirects, and use bounded timeout/payload caps. Webhook POST bodies are redacted JSON: `event_id`, `rule_id`, `trigger`, `subject`, `metadata`, `created_at` (no full destination in audit metadata). Email uses redacted HTML only.

### Durable outbox for run and report triggers (Postgres)

`notifications.enqueueNotification(ctx, { trigger, subject, metadata, dedupeKey })` is used by the run-terminal hook (`safe_test.completed`, `finding.high_severity`) and by `report.ready`. It awaits only `notificationRepository.enqueueNotificationEvent`, which inserts the event and initial attempts in one tenant transaction with `INSERT ... ON CONFLICT (tenant_id, dedupe_key) DO NOTHING` (unique index `uniq_notification_events_dedupe`, migration `0060_notification_event_outbox.sql`), plus the idempotent `notification.event_emitted` audit. A failed enqueue throws and leaves no claim, so a replay records it. Each trigger and each finding is enqueued independently, so one failure does not skip the others.

For active provider channels the initial attempt is `provider_retry_scheduled` with reason `outbox_pending_delivery`, `attempt_number` 0, and `next_retry_at` = now + 5 minutes. A bounded in-process worker (concurrency 2, queue 1000; a full queue increments `notification_outbox_queue_full` and leaves the durable row) delivers it and records the outcome through the existing retry/DLQ path. Undelivered attempts are recovered by `processDueNotificationRetries`. Both paths apply the rule lifecycle gate below before each send. The immediate `emitNotification` path (for example high-scale) applies the same gate: it re-gates every rule on its live state right before the send, so a rule disabled or removed after the emit's rule read is never delivered to (see "Immediate emit" below).

### Delivery ownership and recovery (Postgres)

Decision record: [ADR-0010](../adr/0010-notification-delivery-leases-and-outbox-reconciliation.md).

The 5-minute delay only gives the in-process worker the first chance to send. It is not treated as proof that a job was abandoned. Ownership is decided in Postgres (migration `0061_notification_delivery_claims.sql`: `claimed_by`, `claimed_at`, `lease_expires_at`, `superseded_at` on `notification_delivery_attempts`).

- **Claim before I/O.** The in-process worker and recovery both call `claimDeliveryAttempt` before any external send. It is a single tenant-scoped `UPDATE ... WHERE status = 'provider_retry_scheduled' AND superseded_at IS NULL AND (lease_expires_at IS NULL OR lease_expires_at <= clock_timestamp()) RETURNING`. Competing claims serialize on the row lock, so only one sender holds the lease. Recovery also requires `next_retry_at <= as_of`; the in-process worker may claim early. A lost claim sends nothing (`notification_delivery_claim_lost`).
- **Re-check after claiming.** The rule lifecycle gate runs after the claim. `hold` releases the claim without writing. `cancel` records `cancelled_rule_removed` or `cancelled_rule_unsubscribed` (the live rule dropped the trigger).
- **Lease.** `NOTIFICATION_DELIVERY_LEASE_MS` (2 minutes) runs on the database clock and is renewed by a heartbeat that starts immediately after the claim succeeds, so the heartbeat also covers the gate read and the send. A slow but live sender therefore keeps ownership regardless of queue wait or the number of destinations. Each attempt is claimed right before its own send, so queued work is never leased.
- **Ownership holds over the whole send.** The deliver path renews the claim immediately before provider I/O (`renewDeliveryAttemptClaim`); a renewal that cannot be verified as still-owned is treated as lost and the attempt is abandoned without a send (`notification_delivery_lease_lost`). Hold and cancel decisions need no provider I/O and do not revalidate.
- **Complete.** `completeDeliveryAttemptClaim` supersedes the claimed row and appends the outcome attempt in one transaction, only if the claim token still owns the row. A sender whose lease expired and was taken over records nothing (`notification_delivery_lease_lost`). An unexpected error after claiming keeps the lease until expiry, so a send that may have reached the provider is not resent immediately.
- **Process death.** An expired lease becomes reclaimable by the next recovery tick, and the attempt is sent once. Downstream idempotency (`event_id` in the webhook body) still covers the unavoidable case where a provider accepted a send whose acknowledgement was lost.

Recovery (`processDueNotificationRetries` with a claims-capable repository) reads due work directly from the attempt ledger via `listDueDeliveryAttempts`, never from the recent-events feed. It selects live (unsuperseded) `provider_retry_scheduled` attempts with `next_retry_at <= as_of` that are not under an active lease and not held by a turned-off rule. Results are tenant-scoped and ordered by `(next_retry_at, id)`, served by the partial index `idx_notification_delivery_attempts_due`. Each tick drains pages (`pageSize`, default 100) with a keyset cursor until the backlog is empty or the work budget (`maxItems`, default 1000) is spent, so older backlog is always reached first and the next tick continues from the remaining due work. The keyset cursor carries the boundary timestamp at full database precision (`::text`), not a ms-truncated JavaScript `Date` string, so a boundary row whose `next_retry_at` has sub-millisecond precision is not re-served on the next page and cannot burn the tick's budget on the same row forever (the DLQ drain does the same for its `(created_at, id)` cursor). The summary adds `in_flight_count`, `claim_lost_count`, `lease_lost_count`, `pages_read`, `work_budget`, and `budget_exhausted`. Repositories without the claim methods (test stubs) keep the legacy unclaimed path.

Outbox attempts still awaiting their first send (`outbox_pending_delivery`) on a channel the tick cannot deliver are excluded in SQL by `listDueDeliveryAttempts` and counted in `deferred_inactive_channel_count` instead: they would otherwise sit at the head of the `(next_retry_at, id)` order every tick and starve due work behind them. A repository that fails to filter them gets a defensive service check that defers them without charging the work budget — but only when the live gate is still `deliver`. A removed or unsubscribed rule's cancellation needs no channel, so those rows stay in the page and the tick closes them with one terminal write (`cancelled_rule_removed` / `cancelled_rule_unsubscribed`) instead of leaving them pending forever behind an inactive channel.

Limits: recovery of dropped or crash-orphaned attempts depends on `scripts/notification-retry-scheduler.mjs` running for that tenant (it still takes explicit tenant ids). Live-provider delivery drills are outstanding.

### Immediate emit (R01)

The immediate path used by high-scale state changes (`emitNotification`) reads its rule list once and sends synchronously. It re-gates every outbound attempt on the live rule right before the send (`finalizeGatedNotificationDeliveryAttempts` in `src/lib/notificationRetry.mjs`, resolver `getNotificationRuleDeliveryState`), so a rule disabled or removed after the rule read is never delivered to:

- `deliver`: sent with the live rule (a destination changed after the read is used).
- `hold`: nothing is sent; a resumable pending attempt (`provider_retry_scheduled`, `outbox_pending_delivery`, attempt 0) is recorded, so the retry worker delivers it once the rule is re-enabled — the held predicate keeps it out of the due list while the rule stays off.
- `cancel`: the terminal non-sent cancellation attempt is recorded.
- `unknown`: the live rule cannot be resolved — the send is skipped and the initial queued attempt stands (fail closed).

In-app attempts are not gated: recording in the tenant feed is not an outbound send, and a pending in-app row has no worker to resume it. Without a resolver (repositories without `getNotificationRuleDeliveryState`) the snapshot behavior is kept.

### Lifecycle notification reconciliation (Postgres, R03)

The outbox enqueue runs in its own transaction after the domain write (report row; verdict and finding publication). If that enqueue fails, or the process dies between the domain commit and the enqueue, the committed domain row is the durable record that a notification is owed. `src/persistence/postgres/notificationReconciliation.mjs` closes that gap without client replay:

- **Hook.** `registerPostgresNotificationReconciliation({ pool, notifications, audit })` (wired in `runtime.mjs`) registers a pass via `notifications.registerNotificationReconciler`. Every `processDueNotificationRetries` tick runs registered passes first, then drains due attempts, so a reconciled event's pending provider attempt can go out on the same tick. The tick result includes a `reconciliation` summary (`missing_count`, `reconciled_count`, `already_recorded_count`, `no_subscriber_count`, `failed_count`, `by_trigger`, window bounds). A failing pass increments `notification_reconcile_failed` and never blocks delivery recovery.
- **Discovery.** Tenant-scoped anti-join reads (`withTenantContext`) find, oldest first, committed records whose dedupe key has no `notification_events` row: `ready` reports (`report.ready:report:<id>`), verdicted runs with a verdict (`safe_test.completed:run:<id>`), and high/critical findings whose `verdict_id` belongs to a verdicted run and whose creating verdict is itself high (`bypassable`/`penetrated`), so a finding created medium and escalated later is never alerted, matching the live hook (`finding.high_severity:finding:<id>:verdict:<verdict_id>`). Only records created while an enabled, live rule already subscribed to that trigger, in its current state, qualify (`rule.created_at <= record time` and `rule.updated_at IS NULL OR <= record time`). Creating, re-enabling, or re-subscribing a rule therefore never back-fills history (records from a pause are not owed). The trade-off: a rule edited between the record and the pass is not reconciled for that record. The event is addressed only to those eligible rules (`enqueueNotification({ ruleIds })`), never to rules created later. Reconciled pending provider attempts are due by the tick's as-of and are delivered by that tick's claimed drain (`deferToRecovery`), not handed to the in-process worker, so one-shot runners never close the pool under an in-flight send.
- **Window.** Records must be at least `NOTIFICATION_RECONCILE_GRACE_MS` (60s) old, leaving the live emitter the first chance, and within `NOTIFICATION_RECONCILE_LOOKBACK_MS` (24h). At most `NOTIFICATION_RECONCILE_BATCH_LIMIT` (200) records per trigger per pass; the next pass continues. Upgrade floor: records must also be at or after the `schema_migrations.applied_at` of `0062_notification_outbox_reconciliation` (the deploy that introduced the Postgres live emitters), raised further by an optional `reconcileSince` passed to `registerPostgresNotificationReconciliation`. Earlier builds never notified these records, so the first tick after upgrade does not back-fill them. If the floor row is missing or unreadable the pass reads nothing (`floor_unavailable: true`). The tick summary includes `floor`. Migration `0062_notification_outbox_reconciliation.sql` adds `(tenant_id, created_at, id)` indexes on `reports`, `verdicts`, and high/critical `findings`.
- **Exactly once.** Reconciliation enqueues through the same `enqueueNotification` and builds the same payload as the live emitters (`reportReadyNotification`, `safeTestCompletedNotification`, `highSeverityFindingNotification`). The `uniq_notification_events_dedupe` insert collapses a live emitter racing the pass, concurrent passes on several instances, and repeated passes to one event per identity. Nothing is marked done outside the outbox, so a record whose reconcile enqueue fails is found again next pass.
- **Audit.** A pass that records events appends `notification.outbox_reconciled` (counts per trigger, up to 50 event ids), in addition to the per-event `notification.event_emitted`. `dryRun` reports `missing_count` and writes nothing.

Limit: an owed notification is recovered only while the scheduler runs for that tenant within the 24h lookback.

### Audit

- `notification.event_emitted` — once per event (trigger, subject preview, attempt count; no raw metadata or destinations).
- `notification.delivery_attempt_recorded` — once per attempt (event id, rule id, channel, status; no destination or secrets).
- `notification.rule_created` — on rule create (channel and trigger count only).
- `notification.rule_updated` — on `PATCH /v1/notifications/:id` (channel, changed fields, enabled, trigger count, `destination_changed`; never the destination).
- `notification.rule_deleted` — on `DELETE /v1/notifications/:id` (channel only).

`listNotifications` returns tenant-scoped live rules, the 100 most recent events (including attempt metadata) with `events_window`, and `latest_deliveries`: the latest attempt per rule over the full attempt history (Postgres: `listLatestDeliveryAttemptsByRule`, `DISTINCT ON (rule_id)`, served by `idx_notification_delivery_attempts_rule_latest`). Other tenants’ data is never included.

Rule removal is a soft delete (`notification_rules.deleted_at`, migration `0059_notification_rule_lifecycle.sql`) because events and attempts keep composite foreign keys to the rule. Removal disables the rule and clears its stored destination.

### Rule lifecycle gate on delivery (hold / cancel)

Every delivery entry point applies the same rule gate immediately before a send, re-reading the rule per attempt instead of trusting an earlier subscription snapshot: the in-process outbox worker, `processDueNotificationRetries` (via `processDueNotificationRetryBatch`), and DLQ redrive (`processNotificationDlqRedriveBatch`). Postgres reads the current row with `notificationRepository.getNotificationRuleDeliveryState` (tenant-scoped, includes soft-deleted rules); dev JSON reads the live store. The gate is `notificationRuleDeliveryGate` in `src/lib/notificationRetry.mjs`.

| Rule state | Gate | Effect |
|---|---|---|
| Live and enabled | `deliver` | Normal send through the channel adapter. |
| Live, turned off (`enabled: false`) | `hold` | Nothing is sent and **nothing is recorded**: the pending `provider_retry_scheduled` (or `provider_failed_dlq`) row stays latest, so the retry budget is not burned. The retry/redrive summary reports it as `held_rule_disabled` and counts it in `held_count`. Re-enabling the rule resumes delivery on the next retry tick (or the next redrive for DLQ rows); a held DLQ row is not requeued. |
| Removed (`deleted_at` set) | `cancel` | Pending or DLQ work is closed without sending by a terminal attempt `cancelled_rule_removed` (`reason: rule_removed`, `attempted_at: null`, `exhausted: true`), audited as `notification.delivery_attempt_recorded`, counted in `cancelled_count`. It is never retried or redriven. |
| Live and enabled, but the rule no longer lists the event's trigger | `cancel` | Same closing as a removed rule, with status `cancelled_rule_unsubscribed` (`reason: rule_unsubscribed`). The gate receives the event trigger on every path (outbox worker, recovery, DLQ redrive). Cancel was chosen over hold because a trigger edit means the work is no longer owed, which matches reconciliation's refusal to back-fill after a trigger change. Re-adding the trigger does not bring the work back. A rule that is turned off and also unsubscribed holds until it is turned back on, then cancels. Because a cancel is a single terminal write, the list SQL keeps returning these rows (they are not filtered like held rows) and each one is closed on its first visit. |
| Unknown to this tenant | — | Existing not-deliverable handling (`retry_channel_not_supported` for retries, `skipped_count` for redrive). |

A send already in flight when an operator turns a rule off is not interrupted. Dry runs report held/cancelled items without writing.

### Notification retry worker (operator evidence)

`scripts/notification-retry-worker.mjs` is an **operator planning and evidence utility**, not a provider daemon. It does not run inside the API process, does not open outbound webhook/email/Slack/Teams connections, and must be scheduled externally (cron, CI, runbook step) when operators need retry/DLQ evidence from an exported ledger.

| Flag | Purpose |
|---|---|
| `--input` | JSON ledger with `notification_events` / `events` and optional `notification_rules` / `rules`. |
| `--out` | Write a metadata-only JSON plan (`artifact_type: notification_retry_plan`). |
| `--as-of` | ISO timestamp for due-time evaluation (default: now). |
| `--max-attempts` | Default retry budget when attempt rows omit `max_attempts` (defaults to webhook max from `notificationDelivery.mjs`). |
| `--dry-run` | Due attempts summarized as `retry_due` without planning DLQ/reschedule transitions. |

The worker selects delivery attempts in `provider_retry_scheduled` whose `next_retry_at` is on or before `--as-of`. In apply-plan mode (without `--dry-run`), it records the metadata-only next state: `provider_retry_scheduled` when another attempt remains, or `provider_failed_dlq` when the next attempt number would exhaust `max_attempts`. Input and output reject forbidden raw payloads, tokens, secret-bearing fields, and webhook destinations with URL-embedded credentials; output uses safe attempt fields such as `destination_preview` only.

### Service-level retry executor (runtime path)

`src/lib/notificationRetry.mjs` implements due-retry selection and safe next-attempt recording shared by:

- Dev JSON notifications (`src/services/notificationRetry.mjs` → `processDueNotificationRetries`)
- Postgres notifications (`createPostgresNotificationServices().processDueNotificationRetries`)

`scripts/notification-retry-runner.mjs` (`npm run notification:retry:runner`) is an **externally scheduled operator CLI** (not an in-repo daemon). It requires explicit tenant scope (`--tenant-id` or `--tenant-ids-file`), connects in Postgres mode via `runtime.services.notifications.processDueNotificationRetries`, and writes an optional metadata-only summary (`artifact_type: notification_retry_runtime_run`).

| Mode | Behavior |
|---|---|
| Default (`metadata_only`, unset `ASTRANULL_NOTIFICATION_DELIVERY_MODE`) | Due retries append a new delivery attempt with retry/DLQ metadata only; **no outbound provider I/O**. |
| Opt-in webhook (`ASTRANULL_NOTIFICATION_DELIVERY_MODE=webhook`) | Due webhook retries perform a bounded HTTPS POST via `notificationDelivery.mjs` (redacted JSON body, HTTPS-only remote destinations, no URL credentials) and record `delivered_provider`, `provider_retry_scheduled`, or `provider_failed_dlq`. |
| Opt-in email/slack/teams (or combined modes such as `email,webhook`) | Due retries for matching channels perform bounded adapter I/O when that channel is active in the parsed delivery mode; other channels remain metadata-only ledger updates. |
| `--dry-run` | Summarizes due work as `retry_due` without persisting attempts or sending webhooks. |

Retry selection uses the **latest** delivery attempt per event/rule. Successful processing appends a new attempt row and audits `notification.delivery_attempt_recorded` with `metadata.retry: true` (no destinations or secrets).

### Notification retry scheduler (always-on operator loop)

`scripts/notification-retry-scheduler.mjs` (`npm run notification:retry:scheduler`) is the **persistent retry scheduler** for due delivery attempts. It reuses `processDueNotificationRetries` in both dev-json and Postgres modes and processes due retries on a fixed interval (`ASTRANULL_NOTIFICATION_RETRY_INTERVAL_MS`, default `60000`, bounded `5000`–`300000` ms). Use `--once` for cron/Kubernetes CronJob ticks; omit `--once` for a long-running operator loop that sleeps between ticks and exits cleanly on `SIGINT`/`SIGTERM`.

| Surface | Behavior |
|---|---|
| Dev-json mode (default when `ASTRANULL_DATABASE_URL` is unset) | Reads/writes the developer validation JSON store via `src/services/notificationRetry.mjs`. |
| Postgres mode (`ASTRANULL_DATABASE_URL` set) | Reuses one Postgres runtime across loop ticks; tenant discovery uses distinct `notification_events` / `notification_rules` tenant ids when scope is omitted or `--all-tenants` is set. |
| Default (`metadata_only`, unset `ASTRANULL_NOTIFICATION_DELIVERY_MODE`) | Records retry/DLQ ledger transitions only; **no outbound provider I/O**. |
| Opt-in delivery (`ASTRANULL_NOTIFICATION_DELIVERY_MODE=webhook`, `email`, `slack`, `teams`, or `all`) | Performs bounded provider I/O only for channels active in the parsed delivery mode; requires explicit operator configuration and staging evidence before production enablement. |
| `--dry-run` | Summarizes due work as `retry_due` without persisting attempts or sending providers. |
| `--out <path>` | Writes a metadata-only per-tick summary (`artifact_type: notification_retry_scheduler_tick`). |

Tenant scope mirrors other operator runners: `--tenant-id`, `--tenant-ids-file`, or `--all-tenants` (default when scope is omitted). Output uses safe attempt fields only (`destination_preview`, retry/DLQ metadata); destinations, tokens, provider payloads, and database URLs are excluded.

### Operator DLQ and retry visibility

The Notifications page now includes a developer-validation **Delivery operations** panel. It summarizes recent delivery attempts by status, retry-scheduled count, and DLQ (`provider_failed_dlq`) count, and shows only safe DLQ fields: event id, rule id, channel, destination preview, reason, attempt number, and retry budget. It does not render full destinations, provider URLs, request/response bodies, headers, logs, event metadata bodies, tokens, or secrets.

`POST /v1/notifications/retries/process` lets admins process due retries from the UI/API in **metadata-only** mode:

- Requires `notification:write`.
- Accepts `{ dry_run?: boolean, as_of?: string }`.
- Forces `deliveryMode: metadata_only` from the HTTP path, so UI/API callers cannot activate provider network sends.
- Returns the safe retry summary from `processDueNotificationRetries` with internal `delivery_record` objects stripped.
- Postgres mode requires `runtime.services.notifications.processDueNotificationRetries`; otherwise it fails closed with `postgres_route_not_wired`.

This is operator visibility and manual developer validation only. Production still requires externally scheduled retry runners, provider credential custody, always-on monitoring, and staging delivery evidence.

### Operator DLQ redrive (runtime path)

`POST /v1/notifications/dlq/redrive` lets admins requeue selected DLQ (`provider_failed_dlq`) delivery attempts from the UI/API:

- Requires `notification:write`.
- Accepts `{ attempt_ids?: string[], rule_id?: string, dry_run?: boolean }`; HTTP/UI redrive ignores any client-supplied provider-delivery override and is forced metadata-only.
- Appends a metadata-only redrive attempt: `provider_retry_scheduled` with attempt budget reset to `1` and `reason: dlq_redrive_metadata_only` — **no outbound provider I/O**.
- Bounded adapter redrive remains a lower-level operator/runtime capability outside the HTTP/UI route and requires explicit delivery-mode configuration plus staging evidence.
- Returns a redacted summary: `requeued_count`, `skipped_count`, `still_dlq_count`, `held_count`, `cancelled_count`, plus safe `processed` rows with internal `delivery_record` stripped.
- Audits `notification.dlq_redrive` with safe counts/mode only (no destinations, tokens, or provider payloads). Successful apply mode also audits `notification.delivery_attempt_recorded` with `metadata.dlq_redrive: true`.
- Postgres mode requires `runtime.services.notifications.redriveNotificationDlq`; otherwise it fails closed with `postgres_route_not_wired`.

The Notifications **Delivery operations** panel shows per-DLQ-row **Redrive** buttons (metadata-only default) and the last redrive summary. Copy states that production provider redrive requires explicit delivery mode configuration and staging evidence.

#### Claim-aware DLQ redrive (Postgres)

With a claims-capable repository, `redriveNotificationDlq` uses `processClaimedNotificationDlqRedrive` (`src/lib/notificationDlqRedrive.mjs`) and never reads the recent-events feed:

- **Candidates from the ledger.** `listDlqDeliveryAttempts` returns live (unsuperseded) `provider_failed_dlq` rows that are still the latest attempt for their event/rule. It is tenant-scoped, takes optional `rule_id` / `attempt_ids` filters, and is ordered by `(created_at, id)` with a keyset cursor. A DLQ row behind any number of newer events is reachable. Each call drains pages (`pageSize`, default 100) until the backlog is empty or the work budget (`maxItems`, default 1000) is spent.
- **Claim before I/O.** Each row is claimed with `claimDlqDeliveryAttempt`, which uses the same lease columns and clock as `claimDeliveryAttempt` but requires `status = 'provider_failed_dlq'`. A row under another active lease is counted in `in_flight_count`, and a lost claim in `claim_lost_count`. Neither sends.
- **Gate after claim.** The rule lifecycle gate is re-read after claiming. `hold` releases the claim and leaves the DLQ row untouched. `cancel` records `cancelled_rule_removed`. An unknown rule releases the claim and is counted in `skipped_count`.
- **Complete.** The lease is heartbeated during the send. `completeDeliveryAttemptClaim` then supersedes the DLQ row and appends the outcome (a metadata-only requeue or a provider result) in one transaction, so recovery and later redrives no longer see it. A lease lost mid-send records nothing (`lease_lost_count`).
- **Summary.** `still_dlq_count` comes from `countDlqDeliveryAttempts` (the full live DLQ, not a feed slice). The summary and the `notification.dlq_redrive` audit add `in_flight_count`, `claim_lost_count` and `lease_lost_count`, and the summary also includes `pages_read`, `work_budget` and `budget_exhausted`. Dry runs never claim or write.

Repositories without `listDlqDeliveryAttempts` / `claimDlqDeliveryAttempt` (test stubs) and the dev JSON store keep the legacy feed-based batch. Regressions are in `tests/integration/postgres-notification-dlq-redrive.test.mjs`.

## Channels (product intent)

| Channel | Use cases |
|---|---|
| Email | Reports, critical findings, onboarding reminders. |
| Slack | Real-time findings and agent issues. |
| Microsoft Teams | Enterprise team notifications. |
| Webhook | SIEM/SOAR/ticketing automation. |
| In-app | All events and user tasks. |

## Remaining production work

| Item | Notes |
|---|---|
| Provider adapters | Implemented for developer validation (`buildEmailPayload`/`deliverEmail`, `buildSlackPayload`/`deliverSlack`, `buildTeamsPayload`/`deliverTeams`, webhook delivery/retry). **Production blocker:** signed webhook delivery, SMTP AUTH, per-tenant credential vaulting. |
| Provider configuration | Per-tenant encrypted credentials in the secret vault plus channel test / health. |
| Staging evidence | Production webhook/email/Slack/Teams delivery drills and operator runbooks. |
| HTTP API errors | Implemented: `POST /v1/notifications` maps rule validation `{ status: 400 }` results to HTTP 400. |
| Delivery state machine | Opt-in channels record immediate attempt plus retry/DLQ metadata; service-level retry executor, metadata-only HTTP/UI due-retry action (`POST /v1/notifications/retries/process`), metadata-only HTTP/UI DLQ redrive (`POST /v1/notifications/dlq/redrive`), Postgres operator runner (`scripts/notification-retry-runner.mjs`), and always-on scheduler (`scripts/notification-retry-scheduler.mjs` / `npm run notification:retry:scheduler`, default metadata-only, dev-json + Postgres) process due retries when scheduled or invoked. Provider-I/O redrive is limited to governed lower-level operator/runtime execution with explicit delivery-mode configuration and staging evidence; the HTTP/UI route stays metadata-only. Postgres `notification_delivery_attempts` persist retry/DLQ columns via migration `0010`. Operator CLI `scripts/notification-retry-worker.mjs` remains metadata-only evidence planning from exported ledgers. **Production blocker:** staging deployment/signoff for the persistent scheduler, signed webhook delivery, provider credential custody, and staging retry/redrive drill evidence. |

## Completion criteria

Notifications are complete when every high-impact event reaches the correct audience without exposing sensitive evidence to unauthorized users, with audited delivery attempts and governed outbound providers.
