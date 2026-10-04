-- 0064_target_observations_origins_lineage.sql
-- Immutable target-layer observations, declared origin bindings, and explicit
-- retest lineage. Additive. Does not rewrite 0063_target_declarations.sql.
--
-- Nullable test_runs stamps are written by the server at run start.
-- findings.closed_at is set only by an authorized lifecycle closure.
-- This migration does not backfill them and does not close findings.

CREATE OR REPLACE FUNCTION astranull_observation_order_before(
  left_observed TIMESTAMPTZ,
  left_completed TIMESTAMPTZ,
  left_id TEXT,
  right_observed TIMESTAMPTZ,
  right_completed TIMESTAMPTZ,
  right_id TEXT
) RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT (
    left_observed,
    COALESCE(left_completed, '-infinity'::timestamptz),
    left_id COLLATE "C"
  ) < (
    right_observed,
    COALESCE(right_completed, '-infinity'::timestamptz),
    right_id COLLATE "C"
  );
$$;

CREATE TABLE IF NOT EXISTS target_observations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_id TEXT NOT NULL,
  target_group_id TEXT NOT NULL,
  family TEXT NOT NULL,
  check_id TEXT NOT NULL,
  test_run_id TEXT,
  source_kind TEXT NOT NULL,
  source_id TEXT,
  corpus_version TEXT,
  scenario_version TEXT,
  check_version TEXT,
  observed_at TIMESTAMPTZ NOT NULL,
  source_completed_at TIMESTAMPTZ,
  outcome TEXT NOT NULL,
  attempt_class TEXT NOT NULL,
  producer_kind TEXT,
  provenance_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  origin_binding_id TEXT,
  nonce TEXT,
  event_id TEXT,
  digest TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT target_observations_family_check
    CHECK (family IN ('waf', 'cdn', 'cloud', 'dns', 'origin_hosting', 'maintenance')),
  CONSTRAINT target_observations_attempt_check
    CHECK (attempt_class IN ('successful', 'failed_attempt', 'retained_noncurrent')),
  CONSTRAINT target_observations_source_check
    CHECK (source_kind IN ('edge_detection', 'validation_run', 'explicit_record')),
  CONSTRAINT target_observations_producer_check
    CHECK (producer_kind IS NULL OR producer_kind IN (
      'live_external', 'signed_probe', 'internal_simulation', 'customer_declaration', 'manual'
    )),
  CONSTRAINT target_observations_provenance_object
    CHECK (jsonb_typeof(provenance_json) = 'object')
);

ALTER TABLE target_observations
  DROP CONSTRAINT IF EXISTS target_observations_tenant_id_id_key;
ALTER TABLE target_observations
  ADD CONSTRAINT target_observations_tenant_id_id_key UNIQUE (tenant_id, id);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_target_observations_nonce
  ON target_observations (tenant_id, nonce) WHERE nonce IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_target_observations_event
  ON target_observations (tenant_id, event_id) WHERE event_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_target_observations_digest
  ON target_observations (tenant_id, digest);
CREATE INDEX IF NOT EXISTS idx_target_observations_history
  ON target_observations (tenant_id, target_id, family, observed_at DESC, id DESC);

ALTER TABLE target_observations
  DROP CONSTRAINT IF EXISTS fk_target_observations_target_tenant;
ALTER TABLE target_observations
  ADD CONSTRAINT fk_target_observations_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE target_observations
  DROP CONSTRAINT IF EXISTS fk_target_observations_group_tenant;
ALTER TABLE target_observations
  ADD CONSTRAINT fk_target_observations_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE target_observations
  DROP CONSTRAINT IF EXISTS fk_target_observations_run_tenant;
ALTER TABLE target_observations
  ADD CONSTRAINT fk_target_observations_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);

CREATE TABLE IF NOT EXISTS target_observation_current (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_id TEXT NOT NULL,
  family TEXT NOT NULL,
  successful_observation_id TEXT,
  successful_observed_at TIMESTAMPTZ,
  successful_source_completed_at TIMESTAMPTZ,
  failed_attempt_observation_id TEXT,
  failed_observed_at TIMESTAMPTZ,
  failed_source_completed_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, target_id, family)
);

ALTER TABLE target_observation_current
  DROP CONSTRAINT IF EXISTS fk_target_observation_current_success;
ALTER TABLE target_observation_current
  ADD CONSTRAINT fk_target_observation_current_success
  FOREIGN KEY (tenant_id, successful_observation_id)
  REFERENCES target_observations (tenant_id, id);
ALTER TABLE target_observation_current
  DROP CONSTRAINT IF EXISTS fk_target_observation_current_failed;
ALTER TABLE target_observation_current
  ADD CONSTRAINT fk_target_observation_current_failed
  FOREIGN KEY (tenant_id, failed_attempt_observation_id)
  REFERENCES target_observations (tenant_id, id);

CREATE TABLE IF NOT EXISTS origin_bindings (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  protected_target_id TEXT NOT NULL,
  protected_target_group_id TEXT NOT NULL,
  origin_target_id TEXT NOT NULL,
  origin_target_group_id TEXT NOT NULL,
  host TEXT NOT NULL,
  sni TEXT NOT NULL,
  port INT,
  path TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  assurance TEXT NOT NULL DEFAULT 'none',
  lockdown TEXT NOT NULL DEFAULT 'not_tested',
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  archived_at TIMESTAMPTZ,
  archived_by TEXT,
  CONSTRAINT origin_bindings_status_check CHECK (status IN ('active', 'archived')),
  CONSTRAINT origin_bindings_distinct_targets CHECK (protected_target_id <> origin_target_id),
  CONSTRAINT origin_bindings_port_check CHECK (port IS NULL OR (port >= 1 AND port <= 65535)),
  CONSTRAINT origin_bindings_assurance_check CHECK (assurance = 'none'),
  CONSTRAINT origin_bindings_lockdown_check CHECK (lockdown = 'not_tested')
);

ALTER TABLE origin_bindings
  DROP CONSTRAINT IF EXISTS origin_bindings_tenant_id_id_key;
ALTER TABLE origin_bindings
  ADD CONSTRAINT origin_bindings_tenant_id_id_key UNIQUE (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_origin_binding_active_pair
  ON origin_bindings (tenant_id, protected_target_id, origin_target_id)
  WHERE status = 'active';

ALTER TABLE origin_bindings
  DROP CONSTRAINT IF EXISTS fk_origin_bindings_protected_target;
ALTER TABLE origin_bindings
  ADD CONSTRAINT fk_origin_bindings_protected_target
  FOREIGN KEY (tenant_id, protected_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE origin_bindings
  DROP CONSTRAINT IF EXISTS fk_origin_bindings_origin_target;
ALTER TABLE origin_bindings
  ADD CONSTRAINT fk_origin_bindings_origin_target
  FOREIGN KEY (tenant_id, origin_target_id) REFERENCES targets (tenant_id, id);

ALTER TABLE target_observations
  DROP CONSTRAINT IF EXISTS fk_target_observations_origin_binding;
ALTER TABLE target_observations
  ADD CONSTRAINT fk_target_observations_origin_binding
  FOREIGN KEY (tenant_id, origin_binding_id) REFERENCES origin_bindings (tenant_id, id);

CREATE TABLE IF NOT EXISTS finding_retest_lineage (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  finding_id TEXT NOT NULL,
  test_run_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  check_id TEXT NOT NULL,
  intent TEXT NOT NULL,
  relation TEXT NOT NULL DEFAULT 'retest',
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT finding_retest_lineage_intent_check CHECK (intent = 'retest'),
  CONSTRAINT finding_retest_lineage_relation_check CHECK (relation = 'retest')
);

ALTER TABLE finding_retest_lineage
  DROP CONSTRAINT IF EXISTS finding_retest_lineage_tenant_id_id_key;
ALTER TABLE finding_retest_lineage
  ADD CONSTRAINT finding_retest_lineage_tenant_id_id_key UNIQUE (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_finding_retest_lineage_pair
  ON finding_retest_lineage (tenant_id, finding_id, test_run_id);

ALTER TABLE finding_retest_lineage
  DROP CONSTRAINT IF EXISTS fk_finding_retest_lineage_finding;
ALTER TABLE finding_retest_lineage
  ADD CONSTRAINT fk_finding_retest_lineage_finding
  FOREIGN KEY (tenant_id, finding_id) REFERENCES findings (tenant_id, id);
ALTER TABLE finding_retest_lineage
  DROP CONSTRAINT IF EXISTS fk_finding_retest_lineage_run;
ALTER TABLE finding_retest_lineage
  ADD CONSTRAINT fk_finding_retest_lineage_run
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE finding_retest_lineage
  DROP CONSTRAINT IF EXISTS fk_finding_retest_lineage_target;
ALTER TABLE finding_retest_lineage
  ADD CONSTRAINT fk_finding_retest_lineage_target
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);

ALTER TABLE test_runs
  ADD COLUMN IF NOT EXISTS check_version TEXT,
  ADD COLUMN IF NOT EXISTS scenario_version TEXT,
  ADD COLUMN IF NOT EXISTS producer_kind TEXT,
  ADD COLUMN IF NOT EXISTS origin_binding_id TEXT,
  ADD COLUMN IF NOT EXISTS retest_of_finding_id TEXT,
  ADD COLUMN IF NOT EXISTS expected_behavior_json JSONB,
  ADD COLUMN IF NOT EXISTS provenance_json JSONB;

ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'test_runs_producer_kind_check'
  ) THEN
    ALTER TABLE test_runs
      ADD CONSTRAINT test_runs_producer_kind_check
      CHECK (producer_kind IS NULL OR producer_kind IN (
        'live_external', 'signed_probe', 'internal_simulation', 'customer_declaration', 'manual'
      ));
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_test_runs_origin_binding'
  ) THEN
    ALTER TABLE test_runs
      ADD CONSTRAINT fk_test_runs_origin_binding
      FOREIGN KEY (tenant_id, origin_binding_id) REFERENCES origin_bindings (tenant_id, id);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_test_runs_retest_finding'
  ) THEN
    ALTER TABLE test_runs
      ADD CONSTRAINT fk_test_runs_retest_finding
      FOREIGN KEY (tenant_id, retest_of_finding_id) REFERENCES findings (tenant_id, id);
  END IF;
END
$$;

CREATE OR REPLACE FUNCTION astranull_reject_observation_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'target_observations are immutable';
END;
$$;

DROP TRIGGER IF EXISTS target_observations_immutable ON target_observations;
CREATE TRIGGER target_observations_immutable
  BEFORE UPDATE OR DELETE ON target_observations
  FOR EACH ROW EXECUTE FUNCTION astranull_reject_observation_mutation();

CREATE OR REPLACE FUNCTION astranull_origin_binding_scope_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.protected_target_id IS DISTINCT FROM OLD.protected_target_id
     OR NEW.origin_target_id IS DISTINCT FROM OLD.origin_target_id
     OR NEW.host IS DISTINCT FROM OLD.host
     OR NEW.sni IS DISTINCT FROM OLD.sni
     OR NEW.port IS DISTINCT FROM OLD.port
     OR NEW.path IS DISTINCT FROM OLD.path
     OR NEW.assurance IS DISTINCT FROM OLD.assurance
     OR NEW.lockdown IS DISTINCT FROM OLD.lockdown
  THEN
    RAISE EXCEPTION 'origin binding scope is immutable';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS origin_bindings_scope_immutable ON origin_bindings;
CREATE TRIGGER origin_bindings_scope_immutable
  BEFORE UPDATE ON origin_bindings
  FOR EACH ROW EXECUTE FUNCTION astranull_origin_binding_scope_immutable();

CREATE OR REPLACE FUNCTION astranull_reject_lineage_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'finding_retest_lineage is immutable';
END;
$$;

DROP TRIGGER IF EXISTS finding_retest_lineage_immutable ON finding_retest_lineage;
CREATE TRIGGER finding_retest_lineage_immutable
  BEFORE UPDATE OR DELETE ON finding_retest_lineage
  FOR EACH ROW EXECUTE FUNCTION astranull_reject_lineage_mutation();

ALTER TABLE target_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE target_observations FORCE ROW LEVEL SECURITY;
ALTER TABLE target_observation_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE target_observation_current FORCE ROW LEVEL SECURITY;
ALTER TABLE origin_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE origin_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE finding_retest_lineage ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_retest_lineage FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_target_observations ON target_observations;
CREATE POLICY tenant_isolation_target_observations ON target_observations
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS tenant_isolation_target_observation_current ON target_observation_current;
CREATE POLICY tenant_isolation_target_observation_current ON target_observation_current
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS tenant_isolation_origin_bindings ON origin_bindings;
CREATE POLICY tenant_isolation_origin_bindings ON origin_bindings
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS tenant_isolation_finding_retest_lineage ON finding_retest_lineage;
CREATE POLICY tenant_isolation_finding_retest_lineage ON finding_retest_lineage
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

COMMENT ON TABLE target_observations IS
  'Immutable accepted target-layer observations. Safe provenance only; no raw headers, cookies, or bodies.';
COMMENT ON TABLE target_observation_current IS
  'Monotonic current successful observation and separate latest failed attempt. Not a history backfill.';
COMMENT ON TABLE origin_bindings IS
  'Declared same-tenant protected hostname to independently verified origin target. Not lockdown or capacity.';
COMMENT ON COLUMN findings.closed_at IS
  'Set only when an authorized lifecycle closure is applied to this finding. Lineage does not set it and does not close siblings.';
COMMENT ON COLUMN test_runs.check_version IS
  'Server-derived catalog version or canonical digest. A request body cannot set it. Null on rows started before the writer.';
COMMENT ON COLUMN test_runs.expected_behavior_json IS
  'Catalog default_expected_behavior captured at run start. Not a later lookup of the target declaration.';
COMMENT ON COLUMN test_runs.provenance_json IS
  'Safe derivation record for the run stamp. No credentials, headers, or raw bodies.';

-- target_edge_detections has observed_at but no source_completed_at.
-- ponytail: order the current edge row by (observed_at, test_run_id). A null
-- observed_at is a legacy unstamped row and may still be overwritten. Upgrade
-- path: add source_completed_at and use the full observation order.
CREATE OR REPLACE FUNCTION astranull_edge_detection_monotonic()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.observed_at IS NULL THEN
    RETURN NEW;
  END IF;
  IF NEW.observed_at IS NULL THEN
    RETURN OLD;
  END IF;
  IF astranull_observation_order_before(
    OLD.observed_at, NULL, COALESCE(OLD.test_run_id, ''),
    NEW.observed_at, NULL, COALESCE(NEW.test_run_id, '')
  ) THEN
    RETURN NEW;
  END IF;
  RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS astranull_edge_detection_monotonic ON target_edge_detections;
CREATE TRIGGER astranull_edge_detection_monotonic
  BEFORE UPDATE ON target_edge_detections
  FOR EACH ROW EXECUTE FUNCTION astranull_edge_detection_monotonic();
