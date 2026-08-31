-- Durable signed connector provider work. Customer requests enqueue immutable HMAC-bound jobs;
-- only an exact worker lease may publish one generation's result.

SET LOCAL lock_timeout = '15s';
SET LOCAL statement_timeout = '5min';

CREATE TABLE connector_poll_jobs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  connector_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  poll_revision BIGINT NOT NULL CHECK (poll_revision > 0),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'leased', 'completed', 'failed', 'cancelled')),
  envelope_json JSONB NOT NULL,
  job_signature TEXT NOT NULL,
  leased_by TEXT,
  leased_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  error_code TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT connector_poll_jobs_lease_shape CHECK (
    (status = 'leased' AND leased_by IS NOT NULL AND leased_at IS NOT NULL)
    OR status <> 'leased'
  ),
  CONSTRAINT connector_poll_jobs_envelope_binding CHECK (
    envelope_json->>'job_id' = id
    AND envelope_json->>'tenant_id' = tenant_id
    AND envelope_json->>'connector_id' = connector_id
    AND envelope_json->>'provider' = provider
    AND (envelope_json->>'poll_revision')::BIGINT = poll_revision
    AND envelope_json->>'operation' = 'read_only_provider_inventory'
  ),
  CONSTRAINT fk_connector_poll_jobs_connector_tenant
    FOREIGN KEY (tenant_id, connector_id) REFERENCES waf_connectors(tenant_id, id),
  CONSTRAINT uniq_connector_poll_jobs_generation
    UNIQUE (tenant_id, connector_id, poll_revision)
);

CREATE INDEX idx_connector_poll_jobs_worker_queue
  ON connector_poll_jobs(tenant_id, status, created_at)
  WHERE status IN ('pending', 'leased');

ALTER TABLE connector_poll_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_poll_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_connector_poll_jobs ON connector_poll_jobs
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
