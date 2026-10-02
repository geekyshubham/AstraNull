-- 0060_notification_event_outbox.sql
-- Notification events become an idempotent outbox for run- and report-driven triggers.
--
-- Emitters record the event (plus pending delivery attempts) durably BEFORE any external send,
-- keyed by a tenant-scoped trigger identity (for example `safe_test.completed:run:<id>` or
-- `finding.high_severity:finding:<finding_id>:verdict:<verdict_id>`). The partial unique index
-- makes a replayed terminal hook, a concurrent invocation, or a second API instance collapse to
-- one event per identity, instead of relying on a process-local set. Delivery then happens off
-- the run/report critical path and is recovered by the existing retry worker.
--
-- Legacy events (dedupe_key NULL) are unaffected. Additive and idempotent only.

ALTER TABLE notification_events ADD COLUMN IF NOT EXISTS dedupe_key TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS uniq_notification_events_dedupe
  ON notification_events (tenant_id, dedupe_key)
  WHERE dedupe_key IS NOT NULL;
