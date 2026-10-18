-- Optional, tenant-opt-in unverified origin associations. No inventory or execution authority.
CREATE TABLE origin_clue_batches (
  id TEXT PRIMARY KEY,
  recorded_sequence BIGINT GENERATED ALWAYS AS IDENTITY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  request_digest TEXT NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  action TEXT NOT NULL CHECK (action IN ('import', 'collect')),
  created_at TIMESTAMPTZ NOT NULL,
  response_json JSONB NOT NULL CHECK (jsonb_typeof(response_json) = 'object'),
  UNIQUE (tenant_id, target_id, id),
  UNIQUE (tenant_id, target_id, idempotency_key),
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets(tenant_id, id)
);
CREATE TABLE origin_clues (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_id TEXT NOT NULL,
  batch_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL CHECK (fingerprint ~ '^[a-f0-9]{64}$'),
  retrieved_at TIMESTAMPTZ NOT NULL,
  clue_json JSONB NOT NULL CHECK (jsonb_typeof(clue_json) = 'object'),
  UNIQUE (tenant_id, target_id, fingerprint),
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets(tenant_id, id),
  FOREIGN KEY (tenant_id, target_id, batch_id) REFERENCES origin_clue_batches(tenant_id, target_id, id)
    DEFERRABLE INITIALLY DEFERRED,
  CONSTRAINT origin_clues_state CHECK ((clue_json->>'state' = 'possible_origin_association') IS TRUE),
  CONSTRAINT origin_clues_source_kind CHECK ((clue_json->>'source_kind' IN
    ('historical_dns', 'certificate_host', 'trickest_csv', 'dns_a', 'dns_aaaa', 'dns_cname', 'dns_mx', 'dns_txt')) IS TRUE),
  CONSTRAINT origin_clues_provenance CHECK ((
    jsonb_typeof(clue_json->'associated_hostname') = 'string'
    AND length(clue_json->>'associated_hostname') BETWEEN 1 AND 253
    AND jsonb_typeof(clue_json->'source_ref') = 'string'
    AND length(clue_json->>'source_ref') BETWEEN 1 AND 512
    AND clue_json->>'source_digest' = fingerprint
    AND jsonb_typeof(clue_json->'certificate_names') = 'array'
    AND jsonb_array_length(clue_json->'certificate_names') <= 32
    AND jsonb_typeof(clue_json->'limitations') = 'array'
    AND clue_json->>'edge_classification' IN ('known_edge', 'unknown')
  ) IS TRUE),
  CONSTRAINT origin_clues_bounded CHECK (octet_length(clue_json::text) <= 32768)
);
CREATE INDEX origin_clue_batches_latest_idx ON origin_clue_batches(tenant_id, target_id, recorded_sequence DESC);
CREATE INDEX origin_clues_target_page_idx ON origin_clues(tenant_id, target_id, retrieved_at, id COLLATE "C");
CREATE OR REPLACE FUNCTION astranull_origin_clues_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% rows are append-only', TG_TABLE_NAME USING ERRCODE = '23514';
END;
$$;
CREATE TRIGGER origin_clues_immutable BEFORE UPDATE OR DELETE ON origin_clues
  FOR EACH ROW EXECUTE FUNCTION astranull_origin_clues_immutable();
CREATE TRIGGER origin_clue_batches_immutable BEFORE UPDATE OR DELETE ON origin_clue_batches
  FOR EACH ROW EXECUTE FUNCTION astranull_origin_clues_immutable();
ALTER TABLE origin_clues ENABLE ROW LEVEL SECURITY;
ALTER TABLE origin_clues FORCE ROW LEVEL SECURITY;
CREATE POLICY origin_clues_tenant_isolation ON origin_clues
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
ALTER TABLE origin_clue_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE origin_clue_batches FORCE ROW LEVEL SECURITY;
CREATE POLICY origin_clue_batches_tenant_isolation ON origin_clue_batches
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
COMMENT ON TABLE origin_clues IS 'Unverified source associations only. Never ownership, execution permission, or a protection verdict.';
