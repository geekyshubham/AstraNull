-- Personal, bounded definitions only. Computed data and AI commentary are never persisted.
CREATE TABLE assistant_widgets (
  id TEXT PRIMARY KEY CHECK (id ~ '^aw_[a-f0-9]{24}$'),
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  user_id TEXT NOT NULL,
  slot SMALLINT NOT NULL CHECK (slot BETWEEN 1 AND 12),
  config_json JSONB NOT NULL,
  target_id TEXT GENERATED ALWAYS AS (config_json->>'target_id') STORED,
  version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, user_id, slot),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets(tenant_id, id),
  CONSTRAINT assistant_widget_config_check CHECK ((
    jsonb_typeof(config_json) = 'object'
    AND config_json - ARRAY['name', 'question', 'template', 'target_id', 'severity'] = '{}'::jsonb
    AND jsonb_typeof(config_json->'name') = 'string'
    AND length(btrim(config_json->>'name')) BETWEEN 1 AND 80
    AND jsonb_typeof(config_json->'question') = 'string'
    AND length(btrim(config_json->>'question')) BETWEEN 1 AND 500
    AND jsonb_typeof(config_json->'template') = 'string'
    AND config_json->>'template' IN ('summary', 'finding_list')
    AND (NOT config_json ? 'target_id' OR (jsonb_typeof(config_json->'target_id') = 'string'
      AND config_json->>'target_id' ~ '^[A-Za-z0-9_.:-]{1,120}$'))
    AND (NOT config_json ? 'severity' OR (jsonb_typeof(config_json->'severity') = 'string'
      AND config_json->>'severity' IN ('critical', 'high', 'medium', 'low', 'info', 'unknown')))
    AND octet_length(config_json::text) <= 8192
  ) IS TRUE)
);
ALTER TABLE assistant_widgets ENABLE ROW LEVEL SECURITY;
ALTER TABLE assistant_widgets FORCE ROW LEVEL SECURITY;
CREATE POLICY assistant_widgets_personal_isolation ON assistant_widgets
  USING (tenant_id = current_setting('app.tenant_id', true) AND user_id = current_setting('app.user_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true) AND user_id = current_setting('app.user_id', true));
COMMENT ON TABLE assistant_widgets IS 'Personal versioned read-only assistant widget definitions; max12/user via bounded unique slots. No model output or execution authority.';
