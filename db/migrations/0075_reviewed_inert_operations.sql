-- Durable authenticated preflight review. This record alone never grants traffic.
CREATE TABLE reviewed_operations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_id TEXT NOT NULL,
  plan_json JSONB NOT NULL,
  plan_digest TEXT NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
  approved_by TEXT NOT NULL CHECK (char_length(approved_by) BETWEEN 1 AND 128),
  approved_role TEXT NOT NULL CHECK (approved_role IN ('owner', 'admin')),
  approved_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  revoked_by TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, plan_digest),
  CONSTRAINT reviewed_operations_plan_check CHECK ((
    jsonb_typeof(plan_json) = 'object' AND octet_length(plan_json::text) <= 8192
    AND plan_json ?& ARRAY['version', 'tenant_id', 'target_id', 'template', 'semantics', 'side_effects', 'expires_at',
      'endpoint', 'method', 'target_definition_digest', 'check_id', 'check_version', 'check_definition_digest',
      'scenario_version', 'request_schema', 'maximum_body_bytes', 'maximum_probe_operations']
    AND plan_json->>'version' = 'reviewed-inert-operation.v1'
    AND plan_json->>'tenant_id' = tenant_id AND plan_json->>'target_id' = target_id
    AND plan_json->>'template' IN ('marker-query-v1', 'inert-json-v1')
    AND plan_json->>'semantics' = 'inert_diagnostic' AND plan_json->>'side_effects' = 'none'
    AND jsonb_typeof(plan_json->'endpoint') = 'string' AND plan_json->>'endpoint' ~ '^https?://'
    AND jsonb_typeof(plan_json->'target_definition_digest') = 'string' AND plan_json->>'target_definition_digest' ~ '^[a-f0-9]{64}$'
    AND jsonb_typeof(plan_json->'check_definition_digest') = 'string' AND plan_json->>'check_definition_digest' ~ '^[a-f0-9]{64}$'
    AND jsonb_typeof(plan_json->'check_id') = 'string' AND plan_json->>'check_id' ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
    AND jsonb_typeof(plan_json->'check_version') = 'string' AND char_length(plan_json->>'check_version') BETWEEN 1 AND 128
    AND jsonb_typeof(plan_json->'scenario_version') IN ('string', 'null')
    AND plan_json->'maximum_probe_operations' = '4'::jsonb
    AND ((plan_json->>'template' = 'marker-query-v1' AND plan_json->>'method' = 'GET'
      AND plan_json->>'request_schema' = 'fixed-asn-probe-query.v1' AND plan_json->'maximum_body_bytes' = '0'::jsonb)
      OR (plan_json->>'template' = 'inert-json-v1' AND plan_json->>'method' = 'POST'
      AND plan_json->>'request_schema' = 'fixed-asn-marker-json.v1' AND plan_json->'maximum_body_bytes' = '1024'::jsonb))
    AND jsonb_typeof(plan_json->'expires_at') = 'string'
    AND plan_json->>'expires_at' ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$'
    AND (plan_json->>'expires_at')::timestamptz > approved_at
    AND (plan_json->>'expires_at')::timestamptz <= approved_at + INTERVAL '24 hours'
  ) IS TRUE),
  CONSTRAINT reviewed_operations_revocation_check CHECK (
    (revoked_at IS NULL AND revoked_by IS NULL) OR
    (revoked_at IS NOT NULL AND revoked_at >= approved_at AND char_length(revoked_by) BETWEEN 1 AND 128 AND revoked_by IS NOT NULL)
  )
);
ALTER TABLE reviewed_operations ADD CONSTRAINT fk_reviewed_operations_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets(tenant_id, id);
CREATE INDEX idx_reviewed_operations_target ON reviewed_operations(tenant_id, target_id, approved_at DESC, id DESC);
ALTER TABLE reviewed_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE reviewed_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY reviewed_operations_tenant_isolation ON reviewed_operations
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE FUNCTION guard_reviewed_operation_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'reviewed operation history cannot be deleted'; END IF;
  IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL OR
    (to_jsonb(NEW) - ARRAY['revoked_at', 'revoked_by']) IS DISTINCT FROM
    (to_jsonb(OLD) - ARRAY['revoked_at', 'revoked_by']) THEN
    RAISE EXCEPTION 'reviewed operation scope is immutable';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER reviewed_operations_history_guard BEFORE UPDATE OR DELETE ON reviewed_operations
  FOR EACH ROW EXECUTE FUNCTION guard_reviewed_operation_history();
