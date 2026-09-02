-- Durable per-target WAF/CDN edge detection.
--
-- Edge detection previously existed only as test-run event metadata, re-derived on every read,
-- so a target carried no answer to "what WAF/CDN is in front of this hostname". This table keeps
-- exactly one current row per target, refreshed each time a `waf.fingerprint.safe` run resolves.
--
-- Evidence policy: labels only. Per ADR-0005 the classifier never emits raw header values, cookie
-- values, or block-page bodies, and none are stored here. `evidence_json` holds vendor match
-- descriptors, cdncheck address/CNAME provenance, and the resolved chain for the declared target.

-- Parent keys for the exact target/group and run/group/target provenance FKs below. Migration
-- 0046 normally installed the target key already; retain this guard so a clean 0052 contract is
-- self-contained and fails closed instead of silently omitting the required parent relationship.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = 'targets'::regclass
      AND conname = 'targets_tenant_group_id_key'
  ) THEN
    ALTER TABLE targets
      ADD CONSTRAINT targets_tenant_group_id_key
      UNIQUE (tenant_id, target_group_id, id);
  END IF;
END;
$$;

-- The global run primary key already makes every tuple unique; this named composite key makes the
-- exact tenant + run + group + target relationship referencable.
ALTER TABLE test_runs
  ADD CONSTRAINT test_runs_tenant_run_group_target_key
  UNIQUE (tenant_id, id, target_group_id, target_id);

CREATE TABLE IF NOT EXISTS target_edge_detections (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  test_run_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'inconclusive',
  reason TEXT,
  waf_status TEXT NOT NULL DEFAULT 'inconclusive',
  waf_vendor TEXT,
  waf_type TEXT,
  waf_providers TEXT[] NOT NULL DEFAULT '{}',
  cdn_status TEXT NOT NULL DEFAULT 'inconclusive',
  cdn_provider TEXT,
  cdn_type TEXT,
  cdn_providers TEXT[] NOT NULL DEFAULT '{}',
  confidence NUMERIC NOT NULL DEFAULT 0,
  conflicting_vendor_signals BOOLEAN NOT NULL DEFAULT FALSE,
  corpus_version TEXT,
  evidence_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  observed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT target_edge_detections_status_check
    CHECK (status IN ('detected', 'not_detected', 'inconclusive', 'error', 'pending')),
  CONSTRAINT target_edge_detections_waf_status_check
    CHECK (waf_status IN ('detected', 'not_detected', 'inconclusive')),
  CONSTRAINT target_edge_detections_cdn_status_check
    CHECK (cdn_status IN ('detected', 'not_detected', 'inconclusive'))
);

ALTER TABLE target_edge_detections
  DROP CONSTRAINT IF EXISTS target_edge_detections_tenant_id_id_key;
ALTER TABLE target_edge_detections
  ADD CONSTRAINT target_edge_detections_tenant_id_id_key UNIQUE (tenant_id, id);

-- One current detection per target. Re-running detection updates in place.
CREATE UNIQUE INDEX IF NOT EXISTS uniq_target_edge_detection_target
  ON target_edge_detections (tenant_id, target_id);

CREATE INDEX IF NOT EXISTS idx_target_edge_detections_group
  ON target_edge_detections (tenant_id, target_group_id, updated_at DESC);

ALTER TABLE target_edge_detections
  DROP CONSTRAINT IF EXISTS fk_target_edge_detections_target_tenant;
ALTER TABLE target_edge_detections
  ADD CONSTRAINT fk_target_edge_detections_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);

ALTER TABLE target_edge_detections
  DROP CONSTRAINT IF EXISTS fk_target_edge_detections_target_group_tenant;
ALTER TABLE target_edge_detections
  ADD CONSTRAINT fk_target_edge_detections_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);

ALTER TABLE target_edge_detections
  DROP CONSTRAINT IF EXISTS fk_target_edge_detections_test_run_tenant;
ALTER TABLE target_edge_detections
  ADD CONSTRAINT fk_target_edge_detections_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);

-- Coherent provenance: independent existence is insufficient. The target must belong to the exact
-- group, and the run must bind that same target/group tuple.
ALTER TABLE target_edge_detections
  ADD CONSTRAINT fk_target_edge_detections_target_binding
  FOREIGN KEY (tenant_id, target_group_id, target_id)
  REFERENCES targets (tenant_id, target_group_id, id);
ALTER TABLE target_edge_detections
  ADD CONSTRAINT fk_target_edge_detections_run_binding
  FOREIGN KEY (tenant_id, test_run_id, target_group_id, target_id)
  REFERENCES test_runs (tenant_id, id, target_group_id, target_id);

ALTER TABLE target_edge_detections ENABLE ROW LEVEL SECURITY;
ALTER TABLE target_edge_detections FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_target_edge_detections ON target_edge_detections;
CREATE POLICY tenant_isolation_target_edge_detections ON target_edge_detections
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

COMMENT ON TABLE target_edge_detections IS
  'Current WAF/CDN edge fingerprint per target, derived from the pinned wafw00f + cdncheck corpus.';
COMMENT ON COLUMN target_edge_detections.evidence_json IS
  'Signal labels and cdncheck provenance only. Never raw header/cookie values or block-page bodies.';
