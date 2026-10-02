# ADR-0010: Lease-based notification delivery ownership and outbox reconciliation

## Status

Accepted (2026-10-02). Resolves R01-R04 in `UNCOMMITTED_CHANGES_REVIEW_FOLLOWUP.md` for the Postgres notification path (RUX-015, RUX-017). Builds on the durable outbox in migration `0060_notification_event_outbox.sql`.

## Context

The outbox made each notification event durable and deduplicated, but the review found four gaps:

| ID | Gap |
|---|---|
| R01 | Retry and DLQ redrive used a rule snapshot and still sent for a rule that was turned off. |
| R02 | Recovery read only the newest 500 events, so older pending attempts were never retried. |
| R03 | The outbox enqueue is a separate transaction from the report or run publication. A failed enqueue, or a crash between the two commits, lost the notification. |
| R04 | The in-process outbox worker and the recovery worker could both send the same pending attempt. A 5-minute age was the only sign that a job was abandoned. |

## Decision

1. **Delivery ownership is a lease in Postgres.** Migration `0061_notification_delivery_claims.sql` adds `claimed_by`, `claimed_at`, `lease_expires_at`, and `superseded_at` to `notification_delivery_attempts`. Every sender (outbox worker, `processDueNotificationRetries`, DLQ redrive) claims the attempt with one conditional, tenant-scoped `UPDATE ... RETURNING` before any external I/O. A lost claim sends nothing. The lease (`NOTIFICATION_DELIVERY_LEASE_MS`, 2 minutes) runs on the database clock and is renewed every lease/3 while the send is in flight. `completeDeliveryAttemptClaim` supersedes the claimed row and appends the outcome in one transaction, only while the claim token still owns the row. An expired lease (dead owner) becomes reclaimable.
2. **The 5-minute grace is a first-chance delay, not ownership.** `OUTBOX_RECOVERY_GRACE_MS` only sets the initial `next_retry_at` so the in-process worker usually sends first. The lease decides who sends.
3. **Recovery and redrive read the ledger, not the event feed.** `listDueDeliveryAttempts` and `listDlqDeliveryAttempts` select live (unsuperseded) rows in `(next_retry_at, id)` / `(created_at, id)` order with keyset paging, bounded by a per-call work budget (`pageSize` 100, `maxItems` 1000 by default). The partial index `idx_notification_delivery_attempts_due` serves the due query.
4. **The rule gate runs after the claim, on every attempt.** `notificationRuleDeliveryGate` re-reads the rule (`getNotificationRuleDeliveryState`, which includes soft-deleted rules). A turned-off rule is a **hold**: the claim is released and nothing is written, so no retry budget is used and the DLQ row is untouched. A removed rule is a **cancel**: a terminal `cancelled_rule_removed` attempt is recorded and audited. The immediate `emitNotification` path (high-scale) applies the same gate through `finalizeGatedNotificationDeliveryAttempts`: every outbound attempt is re-gated on the live rule right before its send, a hold records a resumable pending attempt (`outbox_pending_delivery`) instead of a send, and a cancel records the terminal non-sent attempt.
5. **Lost enqueues are recovered by reconciliation, not by a shared transaction.** Putting the outbox write inside the report and verdict/finding publication transactions would have meant restructuring those services. Instead, the committed domain row is treated as the durable record that a notification is owed. `notificationReconciliation.mjs` runs at the start of each recovery tick. It uses tenant-scoped anti-joins to find `ready` reports, verdicted runs, and high/critical findings that have no event for their dedupe key, and enqueues them through the same `enqueueNotification` and payload builders as the live emitters. The existing `uniq_notification_events_dedupe` index keeps it at one event per identity. Only records created while an enabled, live rule subscribed to the trigger qualify, inside a 60-second to 24-hour window, at most 200 per trigger per pass. Migration `0062_notification_outbox_reconciliation.sql` adds the `(tenant_id, created_at, id)` indexes the scans need. A pass that records events is audited as `notification.outbox_reconciled`.
6. **Review-round refinements.** Keyset cursors carry the boundary timestamp at full database precision (`::text`) so sub-microsecond boundary rows are not re-served and cannot burn the tick's budget forever. The lease heartbeat starts immediately after the claim, and the deliver path renews the claim immediately before provider I/O, so ownership is verified over the whole post-claim interval; an unverifiable renewal abandons the send without sending (`notification_delivery_lease_lost`). Outbox pending work on a channel a metadata-only tick cannot deliver is deferred only while the live gate is still `deliver`; removed and unsubscribed rules are closed by any tick because a cancellation needs no channel.

## Consequences

| Positive | Negative |
|---|---|
| One active sender per attempt across the outbox worker, any number of recovery instances, and redrive. | At-least-once delivery remains: a provider can accept a send whose acknowledgement is lost. Downstream idempotency (`event_id` in the webhook body) still covers that case. |
| A slow but live sender keeps ownership however long the queue or destination list is. | An unexpected error after claiming keeps the lease until it expires, which delays the resend by up to 2 minutes. |
| Due work and DLQ rows behind any number of newer events are reachable, oldest first. | Recovery and reconciliation run only for tenants the scheduler is given. Postgres mode still requires explicit tenant ids because RLS forbids cross-tenant enumeration. |
| Turning a rule off stops every delivery path without losing queued work. Turning it back on resumes it. | An owed notification older than the 24-hour lookback is not reconciled. |
| No change to report or run transactions, and no client replay is needed after a failed enqueue. | Reconciliation adds three bounded, indexed anti-join reads to every recovery tick. |

Repositories without the claim methods (unit-test stubs) and the dev JSON store keep the legacy unclaimed path for the recovery and redrive workers; the dev JSON store's immediate emit uses the same live-store gate. Regressions: `tests/integration/postgres-notification-outbox.test.mjs` (R01, R02, R04), `tests/integration/postgres-notification-reconcile.test.mjs` (R03), `tests/integration/postgres-notification-dlq-redrive.test.mjs` (claim-aware redrive), `tests/unit/notification-retry-runtime.test.mjs` (immediate emit gate), and `tests/unit/postgres-notification-deferred-filter.test.mjs` (deferral semantics). Behavior details are in [`docs/backend/07-notifications.md`](../backend/07-notifications.md).
