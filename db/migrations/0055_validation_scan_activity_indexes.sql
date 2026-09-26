-- 0055_validation_scan_activity_indexes.sql
-- Scan activity reads audit rows by metadata scan_id/test_run_id and pages child run events by
-- ingestion order, so late observations with earlier event timestamps are never skipped.

CREATE INDEX IF NOT EXISTS idx_audit_tenant_metadata_scan_id
  ON audit_logs (tenant_id, (metadata_json->>'scan_id'), sequence)
  WHERE (metadata_json->>'scan_id') IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_tenant_metadata_test_run_id
  ON audit_logs (tenant_id, (metadata_json->>'test_run_id'), sequence)
  WHERE (metadata_json->>'test_run_id') IS NOT NULL;

-- Nullable so existing rows keep their event-time ordering; new rows record database ingestion time.
ALTER TABLE events ADD COLUMN IF NOT EXISTS ingested_at TIMESTAMPTZ;
ALTER TABLE events ALTER COLUMN ingested_at SET DEFAULT now();
