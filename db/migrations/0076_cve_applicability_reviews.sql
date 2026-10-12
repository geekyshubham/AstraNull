-- Passive authenticated declarations only. Existing matches remain unreviewed; no backfill or execution grant.
ALTER TABLE cve_pipeline_items ADD CONSTRAINT cve_pipeline_items_review_lineage_key
  UNIQUE (tenant_id, id, cve_id);
ALTER TABLE cve_asset_matches ADD CONSTRAINT cve_asset_matches_review_lineage_key
  UNIQUE (tenant_id, id, cve_pipeline_item_id, waf_asset_id);

CREATE FUNCTION valid_cve_review_support(value JSONB) RETURNS BOOLEAN
  LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE entry JSONB;
BEGIN
  IF jsonb_typeof(value) IS DISTINCT FROM 'array' THEN RETURN FALSE; END IF;
  IF jsonb_array_length(value) > 8 THEN RETURN FALSE; END IF;
  FOR entry IN SELECT jsonb_array_elements(value) LOOP
    IF NOT ((jsonb_typeof(entry) = 'object'
      AND entry ?& ARRAY['kind', 'reference_id', 'sha256']
      AND entry - ARRAY['kind', 'reference_id', 'sha256'] = '{}'::jsonb
      AND jsonb_typeof(entry->'kind') = 'string'
      AND entry->>'kind' IN ('sbom', 'cmdb', 'vendor_advisory', 'change_record')
      AND jsonb_typeof(entry->'reference_id') = 'string'
      AND entry->>'reference_id' ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
      AND jsonb_typeof(entry->'sha256') = 'string'
      AND entry->>'sha256' ~ '^[a-f0-9]{64}$') IS TRUE) THEN RETURN FALSE; END IF;
  END LOOP;
  RETURN TRUE;
END;
$$;

CREATE TABLE cve_applicability_reviews (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  cve_pipeline_item_id TEXT NOT NULL,
  cve_id TEXT NOT NULL CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'),
  cve_asset_match_id TEXT NOT NULL,
  waf_asset_id TEXT NOT NULL,
  plan_json JSONB NOT NULL,
  plan_digest TEXT NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
  approved_by TEXT NOT NULL CHECK (approved_by ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  approved_role TEXT NOT NULL CHECK (approved_role IN ('owner', 'admin')),
  approved_at TIMESTAMPTZ NOT NULL CHECK (isfinite(approved_at)),
  revoked_at TIMESTAMPTZ,
  revoked_by TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, plan_digest),
  CONSTRAINT cve_review_plan_check CHECK ((
    jsonb_typeof(plan_json) = 'object' AND octet_length(plan_json::text) <= 8192
    AND plan_json ?& ARRAY['version', 'tenant_id', 'cve_pipeline_item_id', 'cve_id', 'cve_asset_match_id', 'waf_asset_id',
      'component', 'component_version', 'declared_applicability', 'source', 'supporting_metadata',
      'asset_definition_digest', 'item_definition_digest', 'match_definition_digest', 'evidence_classification',
      'external_applicability_verified', 'exposure_claim_allowed', 'observed_enforcement', 'grants_execution', 'execution_available']
    AND plan_json - ARRAY['version', 'tenant_id', 'cve_pipeline_item_id', 'cve_id', 'cve_asset_match_id', 'waf_asset_id',
      'component', 'component_version', 'declared_applicability', 'source', 'supporting_metadata',
      'asset_definition_digest', 'item_definition_digest', 'match_definition_digest', 'evidence_classification',
      'external_applicability_verified', 'exposure_claim_allowed', 'observed_enforcement', 'grants_execution', 'execution_available'] = '{}'::jsonb
    AND plan_json->>'version' = 'cve-component-declaration.v1'
    AND jsonb_typeof(plan_json->'version') = 'string'
    AND plan_json->'tenant_id' = to_jsonb(tenant_id)
    AND plan_json->'cve_pipeline_item_id' = to_jsonb(cve_pipeline_item_id)
    AND plan_json->'cve_id' = to_jsonb(cve_id)
    AND plan_json->'cve_asset_match_id' = to_jsonb(cve_asset_match_id)
    AND plan_json->'waf_asset_id' = to_jsonb(waf_asset_id)
    AND jsonb_typeof(plan_json->'component') = 'string'
    AND plan_json->>'component' ~ '^[A-Za-z0-9@][A-Za-z0-9@._+/-]{0,127}$'
    AND jsonb_typeof(plan_json->'component_version') = 'string'
    AND plan_json->>'component_version' ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$'
    AND jsonb_typeof(plan_json->'declared_applicability') = 'string'
    AND plan_json->>'declared_applicability' IN ('applicable', 'not_applicable', 'unknown')
    AND jsonb_typeof(plan_json->'source') = 'string'
    AND plan_json->>'source' IN ('manual', 'sbom', 'cmdb', 'vendor_advisory')
    AND valid_cve_review_support(plan_json->'supporting_metadata')
    AND jsonb_typeof(plan_json->'asset_definition_digest') = 'string'
    AND plan_json->>'asset_definition_digest' ~ '^[a-f0-9]{64}$'
    AND jsonb_typeof(plan_json->'item_definition_digest') = 'string'
    AND plan_json->>'item_definition_digest' ~ '^[a-f0-9]{64}$'
    AND jsonb_typeof(plan_json->'match_definition_digest') = 'string'
    AND plan_json->>'match_definition_digest' ~ '^[a-f0-9]{64}$'
    AND plan_json->'evidence_classification' = '"customer_declaration"'::jsonb
    AND plan_json->'external_applicability_verified' = 'false'::jsonb
    AND plan_json->'exposure_claim_allowed' = 'false'::jsonb
    AND plan_json->'observed_enforcement' = 'false'::jsonb
    AND plan_json->'grants_execution' = 'false'::jsonb
    AND plan_json->'execution_available' = 'false'::jsonb
  ) IS TRUE),
  CONSTRAINT cve_review_revocation_check CHECK (
    (revoked_at IS NULL AND revoked_by IS NULL) OR
    (revoked_at IS NOT NULL AND isfinite(revoked_at) AND revoked_at >= approved_at AND revoked_by IS NOT NULL
      AND revoked_by ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$')
  )
);
ALTER TABLE cve_applicability_reviews ADD CONSTRAINT fk_cve_review_item_lineage
  FOREIGN KEY (tenant_id, cve_pipeline_item_id, cve_id) REFERENCES cve_pipeline_items(tenant_id, id, cve_id);
ALTER TABLE cve_applicability_reviews ADD CONSTRAINT fk_cve_review_match_lineage
  FOREIGN KEY (tenant_id, cve_asset_match_id, cve_pipeline_item_id, waf_asset_id)
    REFERENCES cve_asset_matches(tenant_id, id, cve_pipeline_item_id, waf_asset_id);
ALTER TABLE cve_applicability_reviews ADD CONSTRAINT fk_cve_review_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets(tenant_id, id);
CREATE INDEX idx_cve_review_match_history ON cve_applicability_reviews(tenant_id, cve_asset_match_id, approved_at DESC, id DESC);
ALTER TABLE cve_applicability_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE cve_applicability_reviews FORCE ROW LEVEL SECURITY;
CREATE POLICY cve_applicability_reviews_tenant_isolation ON cve_applicability_reviews
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE FUNCTION guard_cve_applicability_review_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'CVE review history cannot be deleted'; END IF;
  IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL OR
    (to_jsonb(NEW) - ARRAY['revoked_at', 'revoked_by']) IS DISTINCT FROM
    (to_jsonb(OLD) - ARRAY['revoked_at', 'revoked_by']) THEN
    RAISE EXCEPTION 'CVE review scope is immutable';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER cve_applicability_reviews_history_guard BEFORE UPDATE OR DELETE ON cve_applicability_reviews
  FOR EACH ROW EXECUTE FUNCTION guard_cve_applicability_review_history();
