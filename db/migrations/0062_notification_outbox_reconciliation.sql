-- 0062_notification_outbox_reconciliation.sql
-- Supports the lifecycle-notification reconciliation pass (R03).
--
-- Run/report emitters enqueue the outbox event in a transaction separate from the domain write.
-- If that enqueue fails (or the process dies after the domain commit), the recovery worker's
-- reconciliation pass finds committed reports, verdicts, and high/critical findings inside a
-- bounded lookback window whose notification identity (dedupe key) has no notification_events
-- row, and enqueues it through the same ON CONFLICT (tenant_id, dedupe_key) outbox insert, so the
-- result stays exactly one event per identity. These indexes keep the windowed scans tenant-scoped
-- and ordered by creation time; the anti-join uses uniq_notification_events_dedupe (0060).
--
-- Additive and idempotent only.

CREATE INDEX IF NOT EXISTS idx_reports_tenant_created
  ON reports (tenant_id, created_at, id);

CREATE INDEX IF NOT EXISTS idx_verdicts_tenant_created
  ON verdicts (tenant_id, created_at, id);

CREATE INDEX IF NOT EXISTS idx_findings_tenant_high_created
  ON findings (tenant_id, created_at, id)
  WHERE severity IN ('high', 'critical');
