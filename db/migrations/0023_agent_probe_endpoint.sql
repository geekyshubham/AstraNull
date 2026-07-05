-- 0023_agent_probe_endpoint.sql
-- AG-016: persist agent-reported probe endpoints and bootstrap token prebind metadata.

ALTER TABLE agents ADD COLUMN IF NOT EXISTS probe_endpoint JSONB;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS probe_endpoint_status TEXT;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS probe_endpoint_error TEXT;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS last_token_validation_at TIMESTAMPTZ;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS last_token_validation_status TEXT;

ALTER TABLE bootstrap_tokens ADD COLUMN IF NOT EXISTS prebind_fqdn TEXT;
ALTER TABLE bootstrap_tokens ADD COLUMN IF NOT EXISTS deployment_packaging TEXT;