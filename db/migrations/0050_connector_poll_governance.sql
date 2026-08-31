-- Durable connector cadence, sustained provider admission, and bounded retention support.

SET LOCAL lock_timeout = '15s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE waf_connectors
  ADD COLUMN last_poll_requested_at TIMESTAMPTZ,
  ADD COLUMN next_poll_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0
    CHECK (consecutive_failures >= 0 AND consecutive_failures <= 1000000);

CREATE INDEX idx_waf_connectors_poll_due
  ON waf_connectors (tenant_id, next_poll_at, updated_at, id)
  WHERE secret_id IS NOT NULL AND status NOT IN ('disabled', 'revoked');

CREATE TABLE connector_provider_rate_limits (
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  window_started_at TIMESTAMPTZ NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0 AND request_count <= 20),
  next_allowed_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, provider)
);

ALTER TABLE connector_provider_rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_provider_rate_limits FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_connector_provider_rate_limits ON connector_provider_rate_limits
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE INDEX idx_connector_poll_jobs_retention
  ON connector_poll_jobs (tenant_id, created_at)
  WHERE status IN ('completed', 'failed', 'cancelled');

CREATE INDEX idx_waf_connector_snapshots_retention
  ON waf_connector_snapshots (tenant_id, created_at);
