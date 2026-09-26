-- 0054_validation_scans.sql
-- Customer-runnable validation scans: an ordered plan of check/target steps executed one
-- safe test run at a time, with optional scheduling and daily/weekly/monthly recurrence.

CREATE TABLE IF NOT EXISTS validation_scans (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  target_id TEXT,
  name TEXT,
  status TEXT NOT NULL,
  check_ids JSONB NOT NULL DEFAULT '[]',
  plan_snapshot JSONB NOT NULL DEFAULT '{}',
  scheduled_for TIMESTAMPTZ,
  recurrence JSONB,
  recurrence_series_id TEXT,
  occurrence_key TEXT,
  occurrence_index INTEGER NOT NULL DEFAULT 0,
  previous_scan_id TEXT,
  next_scan_id TEXT,
  dispatched_at TIMESTAMPTZ,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  abort_reason TEXT,
  cancel_reason TEXT,
  cancelled_by TEXT,
  cancelled_by_role TEXT,
  cancelled_at TIMESTAMPTZ,
  created_by TEXT,
  created_by_role TEXT,
  lease_token TEXT,
  lease_owner TEXT,
  lease_expires_at TIMESTAMPTZ,
  next_eligible_at TIMESTAMPTZ,
  revision BIGINT NOT NULL DEFAULT 1,
  summary JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT validation_scans_status_check
    CHECK (status IN ('scheduled', 'pending', 'running', 'completed', 'denied', 'cancelled')),
  CONSTRAINT validation_scans_scheduled_for_check
    CHECK (status <> 'scheduled' OR scheduled_for IS NOT NULL),
  CONSTRAINT validation_scans_lease_check CHECK (
    (lease_token IS NULL AND lease_owner IS NULL AND lease_expires_at IS NULL)
    OR (lease_token IS NOT NULL AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
  ),
  CONSTRAINT validation_scans_recurrence_check CHECK (
    recurrence IS NULL
    OR (jsonb_typeof(recurrence) = 'object'
      AND recurrence->>'cadence' IN ('daily', 'weekly', 'monthly'))
  ),
  CONSTRAINT validation_scans_cancelled_check
    CHECK ((status = 'cancelled') = (cancelled_at IS NOT NULL))
);

ALTER TABLE validation_scans ADD CONSTRAINT validation_scans_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE validation_scans ADD CONSTRAINT fk_validation_scans_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);

CREATE UNIQUE INDEX uniq_validation_scans_occurrence
  ON validation_scans (tenant_id, occurrence_key) WHERE occurrence_key IS NOT NULL;
CREATE INDEX idx_validation_scans_due
  ON validation_scans (tenant_id, scheduled_for, id) WHERE status = 'scheduled';
CREATE INDEX idx_validation_scans_runnable
  ON validation_scans (tenant_id, next_eligible_at, id) WHERE status = 'running';
CREATE INDEX idx_validation_scans_tenant_group_created
  ON validation_scans (tenant_id, target_group_id, created_at DESC);
CREATE UNIQUE INDEX uniq_active_validation_scan_per_group
  ON validation_scans (tenant_id, target_group_id) WHERE status IN ('pending', 'running');

CREATE TABLE IF NOT EXISTS validation_scan_steps (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  scan_id TEXT NOT NULL,
  position INTEGER NOT NULL,
  check_id TEXT NOT NULL,
  check_name TEXT,
  target_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  test_run_id TEXT,
  error_code TEXT,
  skip_reason TEXT,
  eligible_at TIMESTAMPTZ,
  attempts INTEGER NOT NULL DEFAULT 0,
  request_snapshot JSONB NOT NULL DEFAULT '{}',
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT validation_scan_steps_tenant_scan_position_key UNIQUE (tenant_id, scan_id, position),
  CONSTRAINT validation_scan_steps_status_check CHECK (
    status IN ('pending', 'deferred', 'starting', 'running', 'collecting',
      'verdicted', 'denied', 'skipped', 'cancelled')
  )
);

ALTER TABLE validation_scan_steps ADD CONSTRAINT validation_scan_steps_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE validation_scan_steps ADD CONSTRAINT fk_validation_scan_steps_scan_tenant
  FOREIGN KEY (tenant_id, scan_id) REFERENCES validation_scans (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE validation_scan_steps ADD CONSTRAINT fk_validation_scan_steps_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);

CREATE UNIQUE INDEX uniq_validation_scan_steps_run
  ON validation_scan_steps (tenant_id, test_run_id) WHERE test_run_id IS NOT NULL;
CREATE INDEX idx_validation_scan_steps_scan
  ON validation_scan_steps (tenant_id, scan_id, position);

-- Child runs carry their scan binding so a step start is idempotent and auditable.
ALTER TABLE test_runs
  ADD COLUMN scan_id TEXT,
  ADD COLUMN scan_step_id TEXT;
ALTER TABLE test_runs ADD CONSTRAINT fk_test_runs_scan_tenant
  FOREIGN KEY (tenant_id, scan_id) REFERENCES validation_scans (tenant_id, id);

CREATE UNIQUE INDEX uniq_test_runs_scan_step
  ON test_runs (tenant_id, scan_step_id) WHERE scan_step_id IS NOT NULL;

CREATE INDEX idx_audit_tenant_resource
  ON audit_logs (tenant_id, resource_type, resource_id, sequence);

ALTER TABLE validation_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE validation_scans FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS validation_scans_tenant_isolation ON validation_scans;
CREATE POLICY validation_scans_tenant_isolation ON validation_scans
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE validation_scan_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE validation_scan_steps FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS validation_scan_steps_tenant_isolation ON validation_scan_steps;
CREATE POLICY validation_scan_steps_tenant_isolation ON validation_scan_steps
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
