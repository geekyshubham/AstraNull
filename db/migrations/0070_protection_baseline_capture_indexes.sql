-- 0070_protection_baseline_capture_indexes.sql
-- Additive: baseline capture reads key on provenance_json capture fields, so index them instead of scanning
-- every retained tenant baseline on each capture read, comparison evaluation, matrix, or report.

CREATE INDEX IF NOT EXISTS idx_protection_comparison_baselines_capture
  ON protection_comparison_baselines (tenant_id, (provenance_json->>'capture_id'));
CREATE INDEX IF NOT EXISTS idx_protection_comparison_baselines_capture_heads
  ON protection_comparison_baselines (tenant_id, kind, created_at DESC, id DESC)
  WHERE (provenance_json->>'capture_index') = '0';
