-- Persist connector feature authority at the database boundary. Provider-derived ownership
-- is current only while the tenant feature is enabled; disablement revokes authority.

SET LOCAL lock_timeout = '15s';
SET LOCAL statement_timeout = '5min';

CREATE TABLE tenant_connector_features (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_by TEXT NOT NULL,
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0)
);

ALTER TABLE tenant_connector_features ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_connector_features FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_tenant_connector_features ON tenant_connector_features
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE OR REPLACE VIEW target_verification_current
WITH (security_invoker = true) AS
  SELECT latest.target_id, latest.tenant_id,
         CASE
           WHEN latest.state = 'provider_verified'
            AND (
              latest.source_kind <> 'provider_account'
              OR feature.enabled IS NOT TRUE
              OR NOT target_provider_verification_is_current(
                latest.tenant_id, latest.target_id, latest.source_ref
              )
            )
             THEN 'pending'
           ELSE latest.state
         END AS state,
         latest.source_kind, latest.source_ref, latest.transitioned_at
  FROM (
    SELECT DISTINCT ON (target_id)
      target_id, tenant_id, state, source_kind, source_ref, transitioned_at
    FROM target_verifications
    WHERE tenant_id = current_setting('app.tenant_id', true)
    ORDER BY target_id, transitioned_at DESC
  ) latest
  LEFT JOIN tenant_connector_features feature
    ON feature.tenant_id = latest.tenant_id;
