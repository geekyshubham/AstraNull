-- 0071_entry_path_comparison_lifecycle.sql
-- PV-04 Postgres lifecycle: an approved entry-path comparison and its per-path
-- attempts while their runs execute. Additive; does not rewrite 0068.
--
-- The approved scope (reviewed plan digest, scope digest, per-path targets,
-- target scope hashes, checks, and origin bindings) is immutable once written.
-- Terminal comparison and attempt states are final. Runs start only through the
-- signed test-run path; this table only records which run backs which attempt.
-- Attempt status mapping: started -> running, finalized -> completed, and a
-- skipped attempt is cancelled (stop, kill switch, gate off) or failed (other).

CREATE TABLE IF NOT EXISTS entry_path_comparisons (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  anchor_target_id TEXT NOT NULL,
  primary_entry_path_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'running',
  reviewed_plan_digest TEXT NOT NULL,
  scope_digest TEXT NOT NULL,
  expectation_json JSONB NOT NULL,
  approved_scope_json JSONB NOT NULL,
  probe_mode TEXT NOT NULL,
  execution_ctx_json JSONB NOT NULL,
  idempotency_key TEXT,
  cancel_reason TEXT,
  evaluation_json JSONB,
  evaluation_id TEXT,
  lock_version INT NOT NULL DEFAULT 0,
  reconcile_seq BIGINT NOT NULL DEFAULT 0,
  reconciled_seq BIGINT NOT NULL DEFAULT 0,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  started_at TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT entry_path_comparisons_status_check
    CHECK (status IN ('running', 'completed', 'cancelled', 'failed')),
  CONSTRAINT entry_path_comparisons_digest_check
    CHECK (reviewed_plan_digest ~ '^[a-f0-9]{64}$' AND scope_digest ~ '^[a-f0-9]{64}$'),
  CONSTRAINT entry_path_comparisons_running_check
    CHECK (status <> 'running' OR (completed_at IS NULL AND evaluation_json IS NULL AND evaluation_id IS NULL)),
  CONSTRAINT entry_path_comparisons_terminal_check
    CHECK (status NOT IN ('completed', 'cancelled') OR (completed_at IS NOT NULL AND evaluation_json IS NOT NULL)),
  CONSTRAINT entry_path_comparisons_evaluation_link_check
    CHECK (evaluation_id IS NULL OR evaluation_json IS NOT NULL),
  CONSTRAINT entry_path_comparisons_json_bounds
    CHECK (
      jsonb_typeof(expectation_json) = 'object' AND octet_length(expectation_json::text) <= 16384
      AND jsonb_typeof(approved_scope_json) = 'object' AND octet_length(approved_scope_json::text) <= 262144
      AND jsonb_typeof(execution_ctx_json) = 'object' AND octet_length(execution_ctx_json::text) <= 2048
      AND (evaluation_json IS NULL OR (jsonb_typeof(evaluation_json) = 'object' AND octet_length(evaluation_json::text) <= 2097152))
    ),
  CONSTRAINT entry_path_comparisons_text_bounds
    CHECK (
      char_length(probe_mode) BETWEEN 1 AND 32
      AND (idempotency_key IS NULL OR char_length(idempotency_key) BETWEEN 1 AND 200)
      AND (cancel_reason IS NULL OR char_length(cancel_reason) BETWEEN 1 AND 200)
    ),
  CONSTRAINT entry_path_comparisons_sequence_check
    CHECK (lock_version >= 0 AND reconcile_seq >= 0 AND reconciled_seq >= 0)
);

ALTER TABLE entry_path_comparisons
  DROP CONSTRAINT IF EXISTS entry_path_comparisons_tenant_id_id_key;
ALTER TABLE entry_path_comparisons
  ADD CONSTRAINT entry_path_comparisons_tenant_id_id_key UNIQUE (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_entry_path_comparisons_idempotency
  ON entry_path_comparisons (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_entry_path_comparisons_running_plan
  ON entry_path_comparisons (tenant_id, reviewed_plan_digest) WHERE status = 'running';
CREATE INDEX IF NOT EXISTS idx_entry_path_comparisons_list
  ON entry_path_comparisons (tenant_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_entry_path_comparisons_anchor
  ON entry_path_comparisons (tenant_id, anchor_target_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_entry_path_comparisons_running
  ON entry_path_comparisons (tenant_id, created_at, id) WHERE status = 'running';
CREATE INDEX IF NOT EXISTS idx_entry_path_comparisons_unlinked
  ON entry_path_comparisons (tenant_id, completed_at)
  WHERE evaluation_json IS NOT NULL AND evaluation_id IS NULL;

ALTER TABLE entry_path_comparisons
  DROP CONSTRAINT IF EXISTS fk_entry_path_comparisons_anchor_target_tenant;
ALTER TABLE entry_path_comparisons
  ADD CONSTRAINT fk_entry_path_comparisons_anchor_target_tenant
  FOREIGN KEY (tenant_id, anchor_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE entry_path_comparisons
  DROP CONSTRAINT IF EXISTS fk_entry_path_comparisons_evaluation_tenant;
ALTER TABLE entry_path_comparisons
  ADD CONSTRAINT fk_entry_path_comparisons_evaluation_tenant
  FOREIGN KEY (tenant_id, evaluation_id) REFERENCES protection_comparison_evaluations (tenant_id, id);

-- entry_path_id is not a foreign key: a reviewed plan may list ids that are unknown and recorded as skipped.
CREATE TABLE IF NOT EXISTS entry_path_comparison_items (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  comparison_id TEXT NOT NULL,
  entry_path_id TEXT NOT NULL,
  ordinal INT NOT NULL,
  is_primary BOOLEAN NOT NULL DEFAULT FALSE,
  eligible BOOLEAN NOT NULL,
  target_id TEXT,
  target_group_id TEXT,
  check_id TEXT,
  origin_binding_id TEXT,
  target_scope_hash TEXT,
  declaration_digest TEXT,
  status TEXT NOT NULL,
  skip_reason TEXT,
  test_run_id TEXT,
  probe_job_id TEXT,
  attempts INT NOT NULL DEFAULT 0,
  deferred_until TIMESTAMPTZ,
  last_start_error TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, comparison_id, entry_path_id),
  CONSTRAINT entry_path_comparison_items_status_check
    CHECK (status IN ('pending', 'running', 'deferred', 'completed', 'cancelled', 'failed')),
  CONSTRAINT entry_path_comparison_items_eligible_check
    CHECK (eligible OR status IN ('cancelled', 'failed')),
  CONSTRAINT entry_path_comparison_items_skip_reason_check
    CHECK (status NOT IN ('cancelled', 'failed') OR skip_reason IS NOT NULL),
  CONSTRAINT entry_path_comparison_items_completed_check
    CHECK (status <> 'completed' OR test_run_id IS NOT NULL),
  CONSTRAINT entry_path_comparison_items_queued_check
    CHECK (status NOT IN ('pending', 'deferred') OR test_run_id IS NULL),
  CONSTRAINT entry_path_comparison_items_bounds
    CHECK (ordinal BETWEEN 0 AND 63 AND attempts BETWEEN 0 AND 16),
  CONSTRAINT entry_path_comparison_items_digest_check
    CHECK (
      (target_scope_hash IS NULL OR target_scope_hash ~ '^[a-f0-9]{64}$')
      AND (declaration_digest IS NULL OR declaration_digest ~ '^[a-f0-9]{64}$')
    ),
  CONSTRAINT entry_path_comparison_items_text_bounds
    CHECK (
      char_length(entry_path_id) BETWEEN 1 AND 128
      AND (check_id IS NULL OR char_length(check_id) BETWEEN 1 AND 128)
      AND (skip_reason IS NULL OR char_length(skip_reason) BETWEEN 1 AND 200)
      AND (last_start_error IS NULL OR char_length(last_start_error) BETWEEN 1 AND 200)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_entry_path_comparison_items_run
  ON entry_path_comparison_items (tenant_id, test_run_id) WHERE test_run_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_entry_path_comparison_items_ordinal
  ON entry_path_comparison_items (tenant_id, comparison_id, ordinal);
CREATE INDEX IF NOT EXISTS idx_entry_path_comparison_items_open
  ON entry_path_comparison_items (tenant_id, comparison_id, status)
  WHERE status IN ('pending', 'deferred', 'running');

ALTER TABLE entry_path_comparison_items
  DROP CONSTRAINT IF EXISTS fk_entry_path_comparison_items_comparison_tenant;
ALTER TABLE entry_path_comparison_items
  ADD CONSTRAINT fk_entry_path_comparison_items_comparison_tenant
  FOREIGN KEY (tenant_id, comparison_id) REFERENCES entry_path_comparisons (tenant_id, id);
ALTER TABLE entry_path_comparison_items
  DROP CONSTRAINT IF EXISTS fk_entry_path_comparison_items_target_tenant;
ALTER TABLE entry_path_comparison_items
  ADD CONSTRAINT fk_entry_path_comparison_items_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE entry_path_comparison_items
  DROP CONSTRAINT IF EXISTS fk_entry_path_comparison_items_origin_binding_tenant;
ALTER TABLE entry_path_comparison_items
  ADD CONSTRAINT fk_entry_path_comparison_items_origin_binding_tenant
  FOREIGN KEY (tenant_id, origin_binding_id) REFERENCES origin_bindings (tenant_id, id);
ALTER TABLE entry_path_comparison_items
  DROP CONSTRAINT IF EXISTS fk_entry_path_comparison_items_run_tenant;
ALTER TABLE entry_path_comparison_items
  ADD CONSTRAINT fk_entry_path_comparison_items_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE entry_path_comparison_items
  DROP CONSTRAINT IF EXISTS fk_entry_path_comparison_items_probe_job_tenant;
ALTER TABLE entry_path_comparison_items
  ADD CONSTRAINT fk_entry_path_comparison_items_probe_job_tenant
  FOREIGN KEY (tenant_id, probe_job_id) REFERENCES probe_jobs (tenant_id, id);

CREATE OR REPLACE FUNCTION astranull_entry_path_comparison_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION '% rows are retained history and cannot be deleted', TG_TABLE_NAME;
  END IF;
  IF (to_jsonb(NEW) - ARRAY['status', 'cancel_reason', 'evaluation_json', 'evaluation_id', 'lock_version',
        'reconcile_seq', 'reconciled_seq', 'completed_at', 'updated_at'])
     IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['status', 'cancel_reason', 'evaluation_json', 'evaluation_id',
        'lock_version', 'reconcile_seq', 'reconciled_seq', 'completed_at', 'updated_at'])
  THEN
    RAISE EXCEPTION 'entry_path_comparisons approved scope is immutable';
  END IF;
  IF OLD.status <> 'running' THEN
    IF NEW.status IS DISTINCT FROM OLD.status
       OR NEW.cancel_reason IS DISTINCT FROM OLD.cancel_reason
       OR NEW.evaluation_json IS DISTINCT FROM OLD.evaluation_json
       OR NEW.completed_at IS DISTINCT FROM OLD.completed_at
       OR NEW.lock_version IS DISTINCT FROM OLD.lock_version
       OR NEW.reconciled_seq IS DISTINCT FROM OLD.reconciled_seq
       OR (OLD.evaluation_id IS NOT NULL AND NEW.evaluation_id IS DISTINCT FROM OLD.evaluation_id)
    THEN
      RAISE EXCEPTION 'entry_path_comparisons row % is terminal and final', OLD.id;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION astranull_entry_path_comparison_item_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION '% rows are retained history and cannot be deleted', TG_TABLE_NAME;
  END IF;
  IF (to_jsonb(NEW) - ARRAY['status', 'skip_reason', 'test_run_id', 'probe_job_id', 'attempts', 'deferred_until',
        'last_start_error', 'updated_at'])
     IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['status', 'skip_reason', 'test_run_id', 'probe_job_id', 'attempts',
        'deferred_until', 'last_start_error', 'updated_at'])
  THEN
    RAISE EXCEPTION 'entry_path_comparison_items approved attempt scope is immutable';
  END IF;
  IF OLD.status IN ('completed', 'cancelled', 'failed')
     AND (to_jsonb(NEW) - 'updated_at') IS DISTINCT FROM (to_jsonb(OLD) - 'updated_at')
  THEN
    RAISE EXCEPTION 'entry_path_comparison_items attempt %/% is terminal and final', OLD.comparison_id, OLD.entry_path_id;
  END IF;
  IF OLD.test_run_id IS NOT NULL AND NEW.test_run_id IS DISTINCT FROM OLD.test_run_id THEN
    RAISE EXCEPTION 'entry_path_comparison_items linked run cannot change';
  END IF;
  IF OLD.probe_job_id IS NOT NULL AND NEW.probe_job_id IS DISTINCT FROM OLD.probe_job_id THEN
    RAISE EXCEPTION 'entry_path_comparison_items linked probe job cannot change';
  END IF;
  IF NEW.status = 'running' AND OLD.status <> 'running' AND NOT EXISTS (
    SELECT 1 FROM entry_path_comparisons c
    WHERE c.tenant_id = NEW.tenant_id AND c.id = NEW.comparison_id AND c.status = 'running'
  ) THEN
    RAISE EXCEPTION 'entry_path_comparison_items cannot start an attempt of a finished comparison';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS entry_path_comparisons_guard ON entry_path_comparisons;
CREATE TRIGGER entry_path_comparisons_guard
  BEFORE UPDATE OR DELETE ON entry_path_comparisons
  FOR EACH ROW EXECUTE FUNCTION astranull_entry_path_comparison_guard();
DROP TRIGGER IF EXISTS entry_path_comparison_items_guard ON entry_path_comparison_items;
CREATE TRIGGER entry_path_comparison_items_guard
  BEFORE UPDATE OR DELETE ON entry_path_comparison_items
  FOR EACH ROW EXECUTE FUNCTION astranull_entry_path_comparison_item_guard();

ALTER TABLE entry_path_comparisons ENABLE ROW LEVEL SECURITY;
ALTER TABLE entry_path_comparisons FORCE ROW LEVEL SECURITY;
ALTER TABLE entry_path_comparison_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE entry_path_comparison_items FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_entry_path_comparisons ON entry_path_comparisons;
CREATE POLICY tenant_isolation_entry_path_comparisons ON entry_path_comparisons
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS tenant_isolation_entry_path_comparison_items ON entry_path_comparison_items;
CREATE POLICY tenant_isolation_entry_path_comparison_items ON entry_path_comparison_items
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

COMMENT ON TABLE entry_path_comparisons IS
  'Approved entry-path comparisons (PV-04). The reviewed plan and approved scope are immutable; terminal states are final.';
COMMENT ON TABLE entry_path_comparison_items IS
  'Per-path attempt state for an approved comparison: linked run and probe job, deferral, and skip reason. No raw traffic.';
