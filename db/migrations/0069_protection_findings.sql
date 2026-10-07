-- 0069_protection_findings.sql
-- Additive: findings derived from recorded protection-validation evaluations (PV-06) keep their
-- source, dedupe key, class, priority, and comparison provenance; retest lineage keeps comparison context.
-- Existing findings are untouched (all new columns are nullable).

ALTER TABLE findings ADD COLUMN IF NOT EXISTS source TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS dedupe_key TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS finding_class TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS priority TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS protection_validation_json JSONB;

ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_protection_validation_check;
ALTER TABLE findings ADD CONSTRAINT findings_protection_validation_check CHECK (
  (source IS NULL OR source = 'protection_validation')
  AND (source IS NOT DISTINCT FROM 'protection_validation') = (dedupe_key IS NOT NULL)
  AND (dedupe_key IS NULL OR dedupe_key ~ '^pvf_[a-f0-9]{64}$')
  AND (finding_class IS NULL OR finding_class IN (
    'confirmed_exposure', 'observed_enforcement_gap', 'observed_availability_gap', 'suspected_bypass', 'unavailable_evidence'
  ))
  AND (priority IS NULL OR priority IN ('p1', 'p2', 'p3', 'p4'))
  AND (
    protection_validation_json IS NULL
    OR (jsonb_typeof(protection_validation_json) = 'object' AND octet_length(protection_validation_json::text) <= 65536)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_findings_open_protection_dedupe
  ON findings (tenant_id, dedupe_key)
  WHERE dedupe_key IS NOT NULL AND status IN ('open', 'in_progress');

ALTER TABLE finding_retest_lineage ADD COLUMN IF NOT EXISTS comparison_context_json JSONB;

ALTER TABLE finding_retest_lineage DROP CONSTRAINT IF EXISTS finding_retest_lineage_comparison_context_check;
ALTER TABLE finding_retest_lineage ADD CONSTRAINT finding_retest_lineage_comparison_context_check CHECK (
  comparison_context_json IS NULL
  OR (jsonb_typeof(comparison_context_json) = 'object' AND octet_length(comparison_context_json::text) <= 16384)
);

COMMENT ON COLUMN findings.protection_validation_json IS
  'PV-06 provenance for source = protection_validation: comparison context, evidence references, limitations. Never raw traffic.';
COMMENT ON COLUMN finding_retest_lineage.comparison_context_json IS
  'Comparison context and baseline versions retained for protection-validation retests after authorization was rechecked.';
