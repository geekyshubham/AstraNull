-- 0059_notification_rule_lifecycle.sql
-- Notification rules gain an audited update/remove lifecycle (PATCH/DELETE /v1/notifications/:id).
--
-- Removal is a soft delete: notification_events and notification_delivery_attempts keep composite
-- foreign keys to notification_rules (tenant_id, id), so delivery history stays intact and
-- attributable after a rule is removed. Removed rules are filtered from reads and never emit.
--
-- The attempts index serves the authoritative "latest delivery per rule" read, which must not
-- depend on the bounded recent-events feed.
--
-- Additive and idempotent only.

ALTER TABLE notification_rules ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;
ALTER TABLE notification_rules ADD COLUMN IF NOT EXISTS updated_by TEXT;
ALTER TABLE notification_rules ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_notification_delivery_attempts_rule_latest
  ON notification_delivery_attempts (tenant_id, rule_id, created_at DESC);
