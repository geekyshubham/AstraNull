-- Durable WAF policy exceptions (metadata-only; no raw evidence).

CREATE TABLE IF NOT EXISTS waf_exceptions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_asset_id TEXT NOT NULL,
  owner TEXT NOT NULL,
  reason TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  scope_hash TEXT,
  approved_at TIMESTAMPTZ NOT NULL,
  approved_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_waf_exceptions_tenant_expires
  ON waf_exceptions(tenant_id, expires_at);

CREATE INDEX IF NOT EXISTS idx_waf_exceptions_tenant_asset
  ON waf_exceptions(tenant_id, waf_asset_id);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'waf_exceptions_tenant_id_id_key'
  ) THEN
    ALTER TABLE waf_exceptions
      ADD CONSTRAINT waf_exceptions_tenant_id_id_key UNIQUE (tenant_id, id);
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_waf_exceptions_waf_asset_tenant'
  ) THEN
    ALTER TABLE waf_exceptions ADD CONSTRAINT fk_waf_exceptions_waf_asset_tenant
      FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
  END IF;
END $$;

ALTER TABLE waf_exceptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_exceptions FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename = 'waf_exceptions'
      AND policyname = 'tenant_isolation_waf_exceptions'
  ) THEN
    CREATE POLICY tenant_isolation_waf_exceptions ON waf_exceptions
      USING (tenant_id = current_setting('app.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
  END IF;
END $$;
