-- 0057_waf_offensive_workflow.sql
-- Durable, tenant-isolated SOC-gated WAF offensive request workflow. This stores only
-- bounded suite metadata and evidence summaries; it does not add an execution engine.

CREATE TABLE IF NOT EXISTS waf_offensive_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_asset_id TEXT NOT NULL,
  target_group_id TEXT NOT NULL,
  objective TEXT NOT NULL,
  requested_suites JSONB NOT NULL DEFAULT '[]'::jsonb,
  emergency_contacts JSONB NOT NULL DEFAULT '[]'::jsonb,
  requested_window JSONB,
  stop_criteria TEXT,
  abort_criteria TEXT,
  staging_only BOOLEAN NOT NULL DEFAULT TRUE,
  scope_confirmation BOOLEAN NOT NULL DEFAULT TRUE,
  state TEXT NOT NULL DEFAULT 'submitted',
  created_by TEXT,
  soc_approvals JSONB NOT NULL DEFAULT '[]'::jsonb,
  artifacts JSONB NOT NULL DEFAULT '[]'::jsonb,
  suite_results JSONB NOT NULL DEFAULT '[]'::jsonb,
  authorization_pack_status JSONB NOT NULL DEFAULT '{}'::jsonb,
  scheduled_window JSONB,
  scope_hash TEXT,
  waf_validation_run_id TEXT,
  rejected_at TIMESTAMPTZ,
  rejected_by TEXT,
  rejection_reason TEXT,
  results_recorded_at TIMESTAMPTZ,
  results_recorded_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT waf_offensive_requests_state_check CHECK (
    state IN ('submitted', 'under_review', 'approved', 'scheduled', 'running', 'stopped', 'closed', 'rejected')
  )
);

CREATE TABLE IF NOT EXISTS waf_offensive_reports (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_offensive_request_id TEXT NOT NULL,
  executive_summary TEXT,
  blocking_verdict TEXT,
  bypass_findings JSONB NOT NULL DEFAULT '[]'::jsonb,
  remediation_notes TEXT,
  suite_results JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_by TEXT,
  updated_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uniq_waf_offensive_report_per_request
    UNIQUE (tenant_id, waf_offensive_request_id)
);

ALTER TABLE waf_offensive_requests
  ADD CONSTRAINT waf_offensive_requests_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_offensive_reports
  ADD CONSTRAINT waf_offensive_reports_tenant_id_id_key UNIQUE (tenant_id, id);

ALTER TABLE waf_validation_runs
  ADD COLUMN execution_class TEXT NOT NULL DEFAULT 'safe',
  ADD COLUMN offensive_request_id TEXT;

ALTER TABLE waf_offensive_requests ADD CONSTRAINT fk_waf_offensive_requests_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_offensive_requests ADD CONSTRAINT fk_waf_offensive_requests_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE waf_offensive_requests ADD CONSTRAINT fk_waf_offensive_requests_validation_run_tenant
  FOREIGN KEY (tenant_id, waf_validation_run_id) REFERENCES waf_validation_runs (tenant_id, id);
ALTER TABLE waf_validation_runs ADD CONSTRAINT fk_waf_validation_runs_offensive_request_tenant
  FOREIGN KEY (tenant_id, offensive_request_id) REFERENCES waf_offensive_requests (tenant_id, id);
ALTER TABLE waf_offensive_reports ADD CONSTRAINT fk_waf_offensive_reports_request_tenant
  FOREIGN KEY (tenant_id, waf_offensive_request_id) REFERENCES waf_offensive_requests (tenant_id, id);

CREATE INDEX idx_waf_offensive_requests_tenant_state_created
  ON waf_offensive_requests (tenant_id, state, created_at DESC);
CREATE UNIQUE INDEX uniq_waf_validation_run_offensive_request
  ON waf_validation_runs (tenant_id, offensive_request_id)
  WHERE offensive_request_id IS NOT NULL;

ALTER TABLE waf_offensive_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_offensive_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS waf_offensive_requests_tenant_isolation ON waf_offensive_requests;
CREATE POLICY waf_offensive_requests_tenant_isolation ON waf_offensive_requests
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE waf_offensive_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_offensive_reports FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS waf_offensive_reports_tenant_isolation ON waf_offensive_reports;
CREATE POLICY waf_offensive_reports_tenant_isolation ON waf_offensive_reports
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
