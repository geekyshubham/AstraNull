-- 0061_notification_delivery_claims.sql
-- Shared delivery ownership for pending notification attempts (outbox worker + retry recovery).
--
-- Before this, the in-process outbox worker and the retry/recovery worker both sent a pending
-- `provider_retry_scheduled` attempt without coordinating, and a fixed age ("recovery grace") was
-- the only evidence that a pending job was abandoned. Every sender now atomically CLAIMS the
-- latest pending attempt with a lease before any external I/O:
--
--   UPDATE ... SET claimed_by, claimed_at, lease_expires_at
--   WHERE status = 'provider_retry_scheduled' AND superseded_at IS NULL
--     AND (lease_expires_at IS NULL OR lease_expires_at <= clock_timestamp())
--   RETURNING ...
--
-- Row locking serializes competing claims, so one sender owns an attempt at a time. Completing
-- the send appends the outcome attempt and marks the claimed row `superseded_at` in one tenant
-- transaction. An expired lease (owner process died mid-send) becomes reclaimable. Leases use the
-- database clock so all API instances and schedulers agree.
--
-- The partial index serves the recovery query, which reads due work directly (ordered by due
-- time, then id) instead of scanning the newest events.
--
-- Additive and idempotent. The backfill only marks legacy pending rows that already have a later
-- attempt for the same event/rule (they were never the latest state), so it changes no outcome.

SET LOCAL lock_timeout = '15s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE notification_delivery_attempts ADD COLUMN IF NOT EXISTS claimed_by TEXT;
ALTER TABLE notification_delivery_attempts ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;
ALTER TABLE notification_delivery_attempts ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;
ALTER TABLE notification_delivery_attempts ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMPTZ;

UPDATE notification_delivery_attempts a
SET superseded_at = a.created_at
WHERE a.status = 'provider_retry_scheduled'
  AND a.superseded_at IS NULL
  AND EXISTS (
    SELECT 1
    FROM notification_delivery_attempts s
    WHERE s.tenant_id = a.tenant_id
      AND s.notification_event_id = a.notification_event_id
      AND s.rule_id = a.rule_id
      AND (s.created_at, COALESCE(s.attempt_number, 0), s.id)
        > (a.created_at, COALESCE(a.attempt_number, 0), a.id)
  );

CREATE INDEX IF NOT EXISTS idx_notification_delivery_attempts_due
  ON notification_delivery_attempts (tenant_id, next_retry_at, id)
  WHERE status = 'provider_retry_scheduled' AND superseded_at IS NULL;
