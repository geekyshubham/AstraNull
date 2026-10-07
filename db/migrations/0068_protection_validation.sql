-- 0068_protection_validation.sql
-- Provider-neutral protection validation (PV-03): declared application entry
-- paths, versioned behavior expectations, immutable comparison baselines,
-- immutable comparison evaluations, and their evidence references.
-- Field names and enums follow src/contracts/protectionValidation.mjs.
-- Additive. Does not rewrite 0064_target_observations_origins_lineage.sql.
--
-- Declarations never grant probe scope. Origin relations reference an existing
-- origin binding instead of duplicating its authority. No raw traffic, headers,
-- bodies, or credentials are stored; provenance and results are size bounded.

CREATE TABLE IF NOT EXISTS application_entry_paths (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  anchor_target_id TEXT NOT NULL,
  entry_target_id TEXT NOT NULL,
  relation_kind TEXT NOT NULL,
  origin_binding_id TEXT,
  owner TEXT NOT NULL,
  purpose TEXT NOT NULL,
  expected_behavior TEXT NOT NULL,
  required_layers TEXT[] NOT NULL DEFAULT '{}',
  declaration_source TEXT NOT NULL DEFAULT 'explicit',
  declaration_version INT NOT NULL DEFAULT 1,
  declaration_digest TEXT NOT NULL,
  contract_version TEXT NOT NULL,
  provenance_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  idempotency_key TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  archived_at TIMESTAMPTZ,
  archived_by TEXT,
  CONSTRAINT application_entry_paths_relation_kind_check
    CHECK (relation_kind IN (
      'primary_route', 'alternate_hostname', 'declared_api_url',
      'declared_login_url', 'origin', 'fallback_backend_route'
    )),
  CONSTRAINT application_entry_paths_expected_behavior_check
    CHECK (expected_behavior IN (
      'must_be_protected_by_layers', 'intentionally_public', 'must_not_be_reachable'
    )),
  CONSTRAINT application_entry_paths_required_layers_check
    CHECK (
      required_layers <@ ARRAY['waf', 'cdn_edge', 'network_firewall', 'ddos']::TEXT[]
      AND array_position(required_layers, NULL) IS NULL
    ),
  CONSTRAINT application_entry_paths_layers_behavior_check
    CHECK (
      (expected_behavior <> 'must_be_protected_by_layers' OR cardinality(required_layers) > 0)
      AND (expected_behavior <> 'intentionally_public' OR cardinality(required_layers) = 0)
    ),
  CONSTRAINT application_entry_paths_origin_binding_check
    CHECK ((relation_kind = 'origin') = (origin_binding_id IS NOT NULL)),
  CONSTRAINT application_entry_paths_distinct_targets
    CHECK (relation_kind = 'primary_route' OR anchor_target_id <> entry_target_id),
  CONSTRAINT application_entry_paths_declaration_source_check
    CHECK (declaration_source = 'explicit'),
  CONSTRAINT application_entry_paths_declaration_version_check
    CHECK (declaration_version BETWEEN 1 AND 1000000),
  CONSTRAINT application_entry_paths_digest_check
    CHECK (declaration_digest ~ '^[a-f0-9]{64}$'),
  CONSTRAINT application_entry_paths_text_bounds
    CHECK (
      char_length(owner) BETWEEN 1 AND 120
      AND char_length(purpose) BETWEEN 1 AND 500
      AND char_length(contract_version) BETWEEN 1 AND 64
      AND (idempotency_key IS NULL OR char_length(idempotency_key) BETWEEN 1 AND 200)
    ),
  CONSTRAINT application_entry_paths_provenance_object
    CHECK (
      jsonb_typeof(provenance_json) = 'object'
      AND octet_length(provenance_json::text) <= 16384
    ),
  CONSTRAINT application_entry_paths_status_check
    CHECK (status IN ('active', 'archived')),
  CONSTRAINT application_entry_paths_archive_check
    CHECK (
      (status = 'active' AND archived_at IS NULL AND archived_by IS NULL)
      OR (status = 'archived' AND archived_at IS NOT NULL)
    )
);

ALTER TABLE application_entry_paths
  DROP CONSTRAINT IF EXISTS application_entry_paths_tenant_id_id_key;
ALTER TABLE application_entry_paths
  ADD CONSTRAINT application_entry_paths_tenant_id_id_key UNIQUE (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_application_entry_paths_idempotency
  ON application_entry_paths (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_application_entry_paths_active_scope
  ON application_entry_paths (
    tenant_id, anchor_target_id, entry_target_id, relation_kind, COALESCE(origin_binding_id, '')
  )
  WHERE status = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS uniq_application_entry_paths_scope_version
  ON application_entry_paths (
    tenant_id, anchor_target_id, entry_target_id, relation_kind, COALESCE(origin_binding_id, ''),
    declaration_version
  );
CREATE INDEX IF NOT EXISTS idx_application_entry_paths_anchor
  ON application_entry_paths (tenant_id, anchor_target_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_application_entry_paths_entry_target
  ON application_entry_paths (tenant_id, entry_target_id);

ALTER TABLE application_entry_paths
  DROP CONSTRAINT IF EXISTS fk_application_entry_paths_anchor_target_tenant;
ALTER TABLE application_entry_paths
  ADD CONSTRAINT fk_application_entry_paths_anchor_target_tenant
  FOREIGN KEY (tenant_id, anchor_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE application_entry_paths
  DROP CONSTRAINT IF EXISTS fk_application_entry_paths_entry_target_tenant;
ALTER TABLE application_entry_paths
  ADD CONSTRAINT fk_application_entry_paths_entry_target_tenant
  FOREIGN KEY (tenant_id, entry_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE application_entry_paths
  DROP CONSTRAINT IF EXISTS fk_application_entry_paths_origin_binding_tenant;
ALTER TABLE application_entry_paths
  ADD CONSTRAINT fk_application_entry_paths_origin_binding_tenant
  FOREIGN KEY (tenant_id, origin_binding_id) REFERENCES origin_bindings (tenant_id, id);

CREATE TABLE IF NOT EXISTS protection_expectations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  kind TEXT NOT NULL,
  scope_key TEXT NOT NULL,
  expectation_version INT NOT NULL DEFAULT 1,
  expectation_digest TEXT NOT NULL,
  contract_version TEXT NOT NULL,
  anchor_target_id TEXT,
  scenario TEXT,
  layer_outcomes_json JSONB,
  destination_target_id TEXT,
  protocol TEXT,
  port INT,
  service_endpoint_json JSONB,
  expected TEXT,
  source_perspective TEXT,
  change_id TEXT,
  pre_destination_target_id TEXT,
  post_destination_target_id TEXT,
  owner TEXT,
  provenance_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  idempotency_key TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  archived_at TIMESTAMPTZ,
  archived_by TEXT,
  CONSTRAINT protection_expectations_kind_check
    CHECK (kind IN ('path_validation', 'firewall_change')),
  CONSTRAINT protection_expectations_path_shape_check
    CHECK (
      kind <> 'path_validation'
      OR (
        anchor_target_id IS NOT NULL AND scenario IS NOT NULL AND layer_outcomes_json IS NOT NULL
        AND destination_target_id IS NULL AND protocol IS NULL AND port IS NULL
        AND service_endpoint_json IS NULL AND expected IS NULL AND change_id IS NULL
        AND pre_destination_target_id IS NULL AND post_destination_target_id IS NULL
      )
    ),
  CONSTRAINT protection_expectations_firewall_shape_check
    CHECK (
      kind <> 'firewall_change'
      OR (
        destination_target_id IS NOT NULL AND protocol IS NOT NULL AND expected IS NOT NULL
        AND source_perspective IS NOT NULL AND change_id IS NOT NULL
        AND anchor_target_id IS NULL AND scenario IS NULL AND layer_outcomes_json IS NULL
      )
    ),
  CONSTRAINT protection_expectations_protocol_check
    CHECK (protocol IS NULL OR protocol IN ('tcp', 'udp', 'service')),
  CONSTRAINT protection_expectations_endpoint_check
    CHECK (
      protocol IS NULL
      OR (protocol = 'service' AND port IS NULL AND service_endpoint_json IS NOT NULL)
      OR (protocol <> 'service' AND port IS NOT NULL AND service_endpoint_json IS NULL)
    ),
  CONSTRAINT protection_expectations_port_check
    CHECK (port IS NULL OR (port >= 1 AND port <= 65535)),
  CONSTRAINT protection_expectations_service_endpoint_check
    CHECK (
      service_endpoint_json IS NULL
      OR (
        jsonb_typeof(service_endpoint_json) = 'object'
        AND jsonb_typeof(service_endpoint_json -> 'service') = 'string'
        AND jsonb_typeof(service_endpoint_json -> 'port') = 'number'
        AND (service_endpoint_json - ARRAY['service', 'port', 'path']) = '{}'::jsonb
        AND octet_length(service_endpoint_json::text) <= 512
      )
    ),
  CONSTRAINT protection_expectations_expected_check
    CHECK (expected IS NULL OR expected IN ('allow', 'deny')),
  CONSTRAINT protection_expectations_layer_outcomes_check
    CHECK (
      layer_outcomes_json IS NULL
      OR (
        jsonb_typeof(layer_outcomes_json) = 'object'
        AND layer_outcomes_json <> '{}'::jsonb
        AND (layer_outcomes_json - ARRAY['waf', 'cdn_edge', 'network_firewall', 'ddos']) = '{}'::jsonb
        AND NOT jsonb_path_exists(
          layer_outcomes_json,
          '$.* ? (!(@ == "enforce" || @ == "allow" || @ == "not_reachable" || @ == "no_expectation"))'
        )
      )
    ),
  CONSTRAINT protection_expectations_mapping_check
    CHECK (
      (pre_destination_target_id IS NULL) = (post_destination_target_id IS NULL)
      AND (pre_destination_target_id IS NULL OR pre_destination_target_id <> post_destination_target_id)
      AND (
        pre_destination_target_id IS NULL
        OR destination_target_id IN (pre_destination_target_id, post_destination_target_id)
      )
    ),
  CONSTRAINT protection_expectations_version_check
    CHECK (expectation_version BETWEEN 1 AND 1000000),
  CONSTRAINT protection_expectations_digest_check
    CHECK (expectation_digest ~ '^[a-f0-9]{64}$'),
  CONSTRAINT protection_expectations_text_bounds
    CHECK (
      char_length(scope_key) BETWEEN 1 AND 1024
      AND char_length(contract_version) BETWEEN 1 AND 64
      AND (scenario IS NULL OR char_length(scenario) BETWEEN 1 AND 96)
      AND (source_perspective IS NULL OR char_length(source_perspective) BETWEEN 1 AND 64)
      AND (change_id IS NULL OR char_length(change_id) BETWEEN 1 AND 64)
      AND (owner IS NULL OR char_length(owner) BETWEEN 1 AND 120)
      AND (idempotency_key IS NULL OR char_length(idempotency_key) BETWEEN 1 AND 200)
    ),
  CONSTRAINT protection_expectations_provenance_object
    CHECK (
      jsonb_typeof(provenance_json) = 'object'
      AND octet_length(provenance_json::text) <= 16384
    ),
  CONSTRAINT protection_expectations_status_check
    CHECK (status IN ('active', 'archived')),
  CONSTRAINT protection_expectations_archive_check
    CHECK (
      (status = 'active' AND archived_at IS NULL AND archived_by IS NULL)
      OR (status = 'archived' AND archived_at IS NOT NULL)
    )
);

ALTER TABLE protection_expectations
  DROP CONSTRAINT IF EXISTS protection_expectations_tenant_id_id_key;
ALTER TABLE protection_expectations
  ADD CONSTRAINT protection_expectations_tenant_id_id_key UNIQUE (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_protection_expectations_scope_version
  ON protection_expectations (tenant_id, kind, scope_key, expectation_version);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_protection_expectations_active_scope
  ON protection_expectations (tenant_id, kind, scope_key) WHERE status = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS uniq_protection_expectations_idempotency
  ON protection_expectations (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_protection_expectations_list
  ON protection_expectations (tenant_id, kind, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_protection_expectations_destination
  ON protection_expectations (tenant_id, destination_target_id) WHERE destination_target_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_protection_expectations_anchor
  ON protection_expectations (tenant_id, anchor_target_id) WHERE anchor_target_id IS NOT NULL;

ALTER TABLE protection_expectations
  DROP CONSTRAINT IF EXISTS fk_protection_expectations_anchor_target_tenant;
ALTER TABLE protection_expectations
  ADD CONSTRAINT fk_protection_expectations_anchor_target_tenant
  FOREIGN KEY (tenant_id, anchor_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE protection_expectations
  DROP CONSTRAINT IF EXISTS fk_protection_expectations_destination_target_tenant;
ALTER TABLE protection_expectations
  ADD CONSTRAINT fk_protection_expectations_destination_target_tenant
  FOREIGN KEY (tenant_id, destination_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE protection_expectations
  DROP CONSTRAINT IF EXISTS fk_protection_expectations_pre_destination_tenant;
ALTER TABLE protection_expectations
  ADD CONSTRAINT fk_protection_expectations_pre_destination_tenant
  FOREIGN KEY (tenant_id, pre_destination_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE protection_expectations
  DROP CONSTRAINT IF EXISTS fk_protection_expectations_post_destination_tenant;
ALTER TABLE protection_expectations
  ADD CONSTRAINT fk_protection_expectations_post_destination_tenant
  FOREIGN KEY (tenant_id, post_destination_target_id) REFERENCES targets (tenant_id, id);

CREATE TABLE IF NOT EXISTS protection_comparison_baselines (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  kind TEXT NOT NULL,
  target_id TEXT NOT NULL,
  anchor_target_id TEXT,
  entry_path_id TEXT,
  expectation_id TEXT NOT NULL,
  expectation_version INT NOT NULL,
  expectation_digest TEXT NOT NULL,
  declaration_version INT,
  declaration_digest TEXT,
  pre_destination_target_id TEXT,
  post_destination_target_id TEXT,
  captured_at TIMESTAMPTZ NOT NULL,
  freshness_window_seconds INT NOT NULL,
  reference_count INT NOT NULL,
  baseline_digest TEXT NOT NULL,
  contract_version TEXT NOT NULL,
  provenance_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  idempotency_key TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  archived_at TIMESTAMPTZ,
  archived_by TEXT,
  CONSTRAINT protection_comparison_baselines_kind_check
    CHECK (kind IN ('path_validation', 'firewall_change')),
  CONSTRAINT protection_comparison_baselines_path_scope_check
    CHECK (
      kind <> 'path_validation'
      OR (anchor_target_id IS NOT NULL AND entry_path_id IS NOT NULL AND declaration_digest IS NOT NULL)
    ),
  CONSTRAINT protection_comparison_baselines_firewall_scope_check
    CHECK (kind <> 'firewall_change' OR entry_path_id IS NULL),
  CONSTRAINT protection_comparison_baselines_mapping_check
    CHECK (
      (pre_destination_target_id IS NULL) = (post_destination_target_id IS NULL)
      AND (pre_destination_target_id IS NULL OR kind = 'firewall_change')
      AND (pre_destination_target_id IS NULL OR pre_destination_target_id <> post_destination_target_id)
    ),
  CONSTRAINT protection_comparison_baselines_version_check
    CHECK (
      expectation_version BETWEEN 1 AND 1000000
      AND (declaration_version IS NULL OR declaration_version BETWEEN 1 AND 1000000)
      AND (declaration_version IS NULL OR declaration_digest IS NOT NULL)
    ),
  CONSTRAINT protection_comparison_baselines_digest_check
    CHECK (
      expectation_digest ~ '^[a-f0-9]{64}$'
      AND baseline_digest ~ '^[a-f0-9]{64}$'
      AND (declaration_digest IS NULL OR declaration_digest ~ '^[a-f0-9]{64}$')
    ),
  CONSTRAINT protection_comparison_baselines_freshness_check
    CHECK (freshness_window_seconds BETWEEN 3600 AND 15552000),
  CONSTRAINT protection_comparison_baselines_reference_count_check
    CHECK (reference_count BETWEEN 1 AND 64),
  CONSTRAINT protection_comparison_baselines_text_bounds
    CHECK (
      char_length(contract_version) BETWEEN 1 AND 64
      AND (idempotency_key IS NULL OR char_length(idempotency_key) BETWEEN 1 AND 200)
    ),
  CONSTRAINT protection_comparison_baselines_provenance_object
    CHECK (
      jsonb_typeof(provenance_json) = 'object'
      AND octet_length(provenance_json::text) <= 16384
    ),
  CONSTRAINT protection_comparison_baselines_status_check
    CHECK (status IN ('active', 'archived')),
  CONSTRAINT protection_comparison_baselines_archive_check
    CHECK (
      (status = 'active' AND archived_at IS NULL AND archived_by IS NULL)
      OR (status = 'archived' AND archived_at IS NOT NULL)
    )
);

ALTER TABLE protection_comparison_baselines
  DROP CONSTRAINT IF EXISTS protection_comparison_baselines_tenant_id_id_key;
ALTER TABLE protection_comparison_baselines
  ADD CONSTRAINT protection_comparison_baselines_tenant_id_id_key UNIQUE (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_protection_comparison_baselines_digest
  ON protection_comparison_baselines (tenant_id, baseline_digest);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_protection_comparison_baselines_idempotency
  ON protection_comparison_baselines (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_protection_comparison_baselines_list
  ON protection_comparison_baselines (tenant_id, kind, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_protection_comparison_baselines_expectation
  ON protection_comparison_baselines (tenant_id, expectation_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_protection_comparison_baselines_target
  ON protection_comparison_baselines (tenant_id, target_id, created_at DESC, id DESC);

ALTER TABLE protection_comparison_baselines
  DROP CONSTRAINT IF EXISTS fk_protection_comparison_baselines_target_tenant;
ALTER TABLE protection_comparison_baselines
  ADD CONSTRAINT fk_protection_comparison_baselines_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE protection_comparison_baselines
  DROP CONSTRAINT IF EXISTS fk_protection_comparison_baselines_anchor_target_tenant;
ALTER TABLE protection_comparison_baselines
  ADD CONSTRAINT fk_protection_comparison_baselines_anchor_target_tenant
  FOREIGN KEY (tenant_id, anchor_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE protection_comparison_baselines
  DROP CONSTRAINT IF EXISTS fk_protection_comparison_baselines_entry_path_tenant;
ALTER TABLE protection_comparison_baselines
  ADD CONSTRAINT fk_protection_comparison_baselines_entry_path_tenant
  FOREIGN KEY (tenant_id, entry_path_id) REFERENCES application_entry_paths (tenant_id, id);
ALTER TABLE protection_comparison_baselines
  DROP CONSTRAINT IF EXISTS fk_protection_comparison_baselines_expectation_tenant;
ALTER TABLE protection_comparison_baselines
  ADD CONSTRAINT fk_protection_comparison_baselines_expectation_tenant
  FOREIGN KEY (tenant_id, expectation_id) REFERENCES protection_expectations (tenant_id, id);
ALTER TABLE protection_comparison_baselines
  DROP CONSTRAINT IF EXISTS fk_protection_comparison_baselines_pre_destination_tenant;
ALTER TABLE protection_comparison_baselines
  ADD CONSTRAINT fk_protection_comparison_baselines_pre_destination_tenant
  FOREIGN KEY (tenant_id, pre_destination_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE protection_comparison_baselines
  DROP CONSTRAINT IF EXISTS fk_protection_comparison_baselines_post_destination_tenant;
ALTER TABLE protection_comparison_baselines
  ADD CONSTRAINT fk_protection_comparison_baselines_post_destination_tenant
  FOREIGN KEY (tenant_id, post_destination_target_id) REFERENCES targets (tenant_id, id);

CREATE TABLE IF NOT EXISTS protection_comparison_evaluations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  kind TEXT NOT NULL,
  baseline_id TEXT,
  baseline_digest TEXT,
  anchor_target_id TEXT,
  primary_entry_path_id TEXT,
  reviewed_plan_digest TEXT,
  comparable BOOLEAN NOT NULL DEFAULT FALSE,
  stale BOOLEAN NOT NULL DEFAULT FALSE,
  compatibility_reasons TEXT[] NOT NULL DEFAULT '{}',
  total_count INT NOT NULL,
  evaluated_count INT NOT NULL,
  accepted BOOLEAN NOT NULL DEFAULT FALSE,
  items_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  limitations TEXT[] NOT NULL,
  evaluated_at TIMESTAMPTZ NOT NULL,
  evaluation_digest TEXT NOT NULL,
  contract_version TEXT NOT NULL,
  provenance_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  idempotency_key TEXT,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT protection_comparison_evaluations_kind_check
    CHECK (kind IN ('path_validation', 'firewall_change')),
  CONSTRAINT protection_comparison_evaluations_firewall_baseline_check
    CHECK (kind <> 'firewall_change' OR (baseline_id IS NOT NULL AND baseline_digest IS NOT NULL)),
  CONSTRAINT protection_comparison_evaluations_path_scope_check
    CHECK (kind <> 'path_validation' OR anchor_target_id IS NOT NULL),
  CONSTRAINT protection_comparison_evaluations_digest_check
    CHECK (
      evaluation_digest ~ '^[a-f0-9]{64}$'
      AND (baseline_digest IS NULL OR baseline_digest ~ '^[a-f0-9]{64}$')
      AND (reviewed_plan_digest IS NULL OR reviewed_plan_digest ~ '^[a-f0-9]{64}$')
    ),
  CONSTRAINT protection_comparison_evaluations_counts_check
    CHECK (
      total_count BETWEEN 0 AND 200
      AND evaluated_count BETWEEN 0 AND total_count
    ),
  CONSTRAINT protection_comparison_evaluations_accepted_check
    CHECK (
      NOT accepted
      OR (total_count > 0 AND (kind <> 'firewall_change' OR (comparable AND NOT stale)))
    ),
  CONSTRAINT protection_comparison_evaluations_items_check
    CHECK (
      jsonb_typeof(items_json) = 'array'
      AND jsonb_array_length(items_json) = total_count
      AND octet_length(items_json::text) <= 4194304
    ),
  CONSTRAINT protection_comparison_evaluations_summary_check
    CHECK (
      jsonb_typeof(summary_json) = 'object'
      AND octet_length(summary_json::text) <= 16384
    ),
  CONSTRAINT protection_comparison_evaluations_compatibility_reasons_check
    CHECK (
      cardinality(compatibility_reasons) <= 32
      AND array_position(compatibility_reasons, NULL) IS NULL
      AND compatibility_reasons <@ ARRAY[
        'invalid_baseline', 'invalid_candidate', 'contract_version_mismatch', 'kind_mismatch',
        'tenant_mismatch', 'expectation_mismatch', 'expectation_version_mismatch',
        'expectation_digest_mismatch', 'anchor_mismatch', 'entry_path_mismatch',
        'declaration_digest_mismatch', 'declaration_changed', 'destination_mismatch',
        'destination_mapping_missing', 'evidence_missing', 'evidence_not_finalized',
        'source_missing', 'source_mismatch', 'check_mismatch', 'check_version_mismatch',
        'scenario_version_mismatch', 'candidate_not_after_baseline', 'baseline_stale',
        'candidate_stale'
      ]::TEXT[]
    ),
  CONSTRAINT protection_comparison_evaluations_limitations_check
    CHECK (
      array_position(limitations, NULL) IS NULL
      AND limitations <@ ARRAY[
        'external_only', 'sampled_public_ingress_only', 'rule_table_equivalence_not_established',
        'routing_nat_egress_east_west_not_established', 'not_capacity_assurance',
        'appliance_traversal_not_established', 'firewall_traversal_not_established',
        'stacked_layer_attribution_not_established', 'transport_reachability_not_enforcement',
        'udp_silence_ambiguous', 'marker_scope_only', 'vendor_label_not_proof',
        'configuration_evidence_not_behavior', 'untested_paths_not_covered',
        'layer_not_measured_by_scenario'
      ]::TEXT[]
      AND (
        kind <> 'path_validation'
        OR limitations @> ARRAY[
          'external_only', 'not_capacity_assurance', 'firewall_traversal_not_established',
          'stacked_layer_attribution_not_established', 'marker_scope_only',
          'untested_paths_not_covered'
        ]::TEXT[]
      )
      AND (
        kind <> 'firewall_change'
        OR limitations @> ARRAY[
          'external_only', 'sampled_public_ingress_only', 'rule_table_equivalence_not_established',
          'routing_nat_egress_east_west_not_established', 'not_capacity_assurance',
          'appliance_traversal_not_established', 'transport_reachability_not_enforcement'
        ]::TEXT[]
      )
    ),
  CONSTRAINT protection_comparison_evaluations_text_bounds
    CHECK (
      char_length(contract_version) BETWEEN 1 AND 64
      AND (idempotency_key IS NULL OR char_length(idempotency_key) BETWEEN 1 AND 200)
    ),
  CONSTRAINT protection_comparison_evaluations_provenance_object
    CHECK (
      jsonb_typeof(provenance_json) = 'object'
      AND octet_length(provenance_json::text) <= 16384
    )
);

ALTER TABLE protection_comparison_evaluations
  DROP CONSTRAINT IF EXISTS protection_comparison_evaluations_tenant_id_id_key;
ALTER TABLE protection_comparison_evaluations
  ADD CONSTRAINT protection_comparison_evaluations_tenant_id_id_key UNIQUE (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_protection_comparison_evaluations_digest
  ON protection_comparison_evaluations (tenant_id, evaluation_digest);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_protection_comparison_evaluations_idempotency
  ON protection_comparison_evaluations (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_protection_comparison_evaluations_list
  ON protection_comparison_evaluations (tenant_id, kind, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_protection_comparison_evaluations_baseline
  ON protection_comparison_evaluations (tenant_id, baseline_id, created_at DESC, id DESC)
  WHERE baseline_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_protection_comparison_evaluations_anchor
  ON protection_comparison_evaluations (tenant_id, anchor_target_id, created_at DESC, id DESC)
  WHERE anchor_target_id IS NOT NULL;

ALTER TABLE protection_comparison_evaluations
  DROP CONSTRAINT IF EXISTS fk_protection_comparison_evaluations_baseline_tenant;
ALTER TABLE protection_comparison_evaluations
  ADD CONSTRAINT fk_protection_comparison_evaluations_baseline_tenant
  FOREIGN KEY (tenant_id, baseline_id) REFERENCES protection_comparison_baselines (tenant_id, id);
ALTER TABLE protection_comparison_evaluations
  DROP CONSTRAINT IF EXISTS fk_protection_comparison_evaluations_anchor_target_tenant;
ALTER TABLE protection_comparison_evaluations
  ADD CONSTRAINT fk_protection_comparison_evaluations_anchor_target_tenant
  FOREIGN KEY (tenant_id, anchor_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE protection_comparison_evaluations
  DROP CONSTRAINT IF EXISTS fk_protection_comparison_evaluations_primary_entry_path_tenant;
ALTER TABLE protection_comparison_evaluations
  ADD CONSTRAINT fk_protection_comparison_evaluations_primary_entry_path_tenant
  FOREIGN KEY (tenant_id, primary_entry_path_id) REFERENCES application_entry_paths (tenant_id, id);

CREATE TABLE IF NOT EXISTS protection_comparison_evidence_refs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  baseline_id TEXT,
  evaluation_id TEXT,
  item_index INT,
  ordinal INT NOT NULL,
  expectation_id TEXT,
  entry_path_id TEXT,
  test_run_id TEXT NOT NULL,
  check_id TEXT NOT NULL,
  check_version TEXT,
  scenario_version TEXT,
  verdict_id TEXT,
  evidence_ids TEXT[] NOT NULL DEFAULT '{}',
  target_id TEXT NOT NULL,
  origin_binding_id TEXT,
  observed_at TIMESTAMPTZ NOT NULL,
  run_status TEXT,
  source_perspective TEXT,
  worker_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT protection_comparison_evidence_refs_owner_check
    CHECK ((baseline_id IS NULL) <> (evaluation_id IS NULL)),
  CONSTRAINT protection_comparison_evidence_refs_item_index_check
    CHECK (
      (baseline_id IS NOT NULL AND item_index IS NULL)
      OR (evaluation_id IS NOT NULL AND item_index BETWEEN 0 AND 199)
    ),
  CONSTRAINT protection_comparison_evidence_refs_baseline_source_check
    CHECK (baseline_id IS NULL OR (source_perspective IS NOT NULL AND worker_id IS NOT NULL)),
  CONSTRAINT protection_comparison_evidence_refs_ordinal_check
    CHECK (ordinal BETWEEN 0 AND 63),
  CONSTRAINT protection_comparison_evidence_refs_evidence_ids_check
    CHECK (cardinality(evidence_ids) <= 32 AND array_position(evidence_ids, NULL) IS NULL),
  CONSTRAINT protection_comparison_evidence_refs_text_bounds
    CHECK (
      char_length(check_id) BETWEEN 1 AND 128
      AND (check_version IS NULL OR char_length(check_version) <= 128)
      AND (scenario_version IS NULL OR char_length(scenario_version) <= 128)
      AND (run_status IS NULL OR char_length(run_status) <= 64)
      AND (source_perspective IS NULL OR char_length(source_perspective) BETWEEN 1 AND 64)
      AND (worker_id IS NULL OR char_length(worker_id) BETWEEN 1 AND 128)
    )
);

ALTER TABLE protection_comparison_evidence_refs
  DROP CONSTRAINT IF EXISTS protection_comparison_evidence_refs_tenant_id_id_key;
ALTER TABLE protection_comparison_evidence_refs
  ADD CONSTRAINT protection_comparison_evidence_refs_tenant_id_id_key UNIQUE (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_protection_comparison_evidence_refs_baseline
  ON protection_comparison_evidence_refs (tenant_id, baseline_id, ordinal)
  WHERE baseline_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_protection_comparison_evidence_refs_evaluation
  ON protection_comparison_evidence_refs (tenant_id, evaluation_id, item_index, ordinal)
  WHERE evaluation_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_protection_comparison_evidence_refs_run
  ON protection_comparison_evidence_refs (tenant_id, test_run_id);

ALTER TABLE protection_comparison_evidence_refs
  DROP CONSTRAINT IF EXISTS fk_protection_comparison_evidence_refs_baseline_tenant;
ALTER TABLE protection_comparison_evidence_refs
  ADD CONSTRAINT fk_protection_comparison_evidence_refs_baseline_tenant
  FOREIGN KEY (tenant_id, baseline_id) REFERENCES protection_comparison_baselines (tenant_id, id);
ALTER TABLE protection_comparison_evidence_refs
  DROP CONSTRAINT IF EXISTS fk_protection_comparison_evidence_refs_evaluation_tenant;
ALTER TABLE protection_comparison_evidence_refs
  ADD CONSTRAINT fk_protection_comparison_evidence_refs_evaluation_tenant
  FOREIGN KEY (tenant_id, evaluation_id) REFERENCES protection_comparison_evaluations (tenant_id, id);
ALTER TABLE protection_comparison_evidence_refs
  DROP CONSTRAINT IF EXISTS fk_protection_comparison_evidence_refs_expectation_tenant;
ALTER TABLE protection_comparison_evidence_refs
  ADD CONSTRAINT fk_protection_comparison_evidence_refs_expectation_tenant
  FOREIGN KEY (tenant_id, expectation_id) REFERENCES protection_expectations (tenant_id, id);
ALTER TABLE protection_comparison_evidence_refs
  DROP CONSTRAINT IF EXISTS fk_protection_comparison_evidence_refs_entry_path_tenant;
ALTER TABLE protection_comparison_evidence_refs
  ADD CONSTRAINT fk_protection_comparison_evidence_refs_entry_path_tenant
  FOREIGN KEY (tenant_id, entry_path_id) REFERENCES application_entry_paths (tenant_id, id);
ALTER TABLE protection_comparison_evidence_refs
  DROP CONSTRAINT IF EXISTS fk_protection_comparison_evidence_refs_run_tenant;
ALTER TABLE protection_comparison_evidence_refs
  ADD CONSTRAINT fk_protection_comparison_evidence_refs_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE protection_comparison_evidence_refs
  DROP CONSTRAINT IF EXISTS fk_protection_comparison_evidence_refs_verdict_tenant;
ALTER TABLE protection_comparison_evidence_refs
  ADD CONSTRAINT fk_protection_comparison_evidence_refs_verdict_tenant
  FOREIGN KEY (tenant_id, verdict_id) REFERENCES verdicts (tenant_id, id);
ALTER TABLE protection_comparison_evidence_refs
  DROP CONSTRAINT IF EXISTS fk_protection_comparison_evidence_refs_target_tenant;
ALTER TABLE protection_comparison_evidence_refs
  ADD CONSTRAINT fk_protection_comparison_evidence_refs_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE protection_comparison_evidence_refs
  DROP CONSTRAINT IF EXISTS fk_protection_comparison_evidence_refs_origin_binding_tenant;
ALTER TABLE protection_comparison_evidence_refs
  ADD CONSTRAINT fk_protection_comparison_evidence_refs_origin_binding_tenant
  FOREIGN KEY (tenant_id, origin_binding_id) REFERENCES origin_bindings (tenant_id, id);

CREATE OR REPLACE FUNCTION astranull_protection_record_archive_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION '% rows are retained history and cannot be deleted', TG_TABLE_NAME;
  END IF;
  IF OLD.status = 'archived' THEN
    RAISE EXCEPTION '% row % is archived and immutable', TG_TABLE_NAME, OLD.id;
  END IF;
  IF (to_jsonb(NEW) - ARRAY['status', 'archived_at', 'archived_by'])
     IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['status', 'archived_at', 'archived_by'])
  THEN
    RAISE EXCEPTION '% declared scope is immutable; record a new version', TG_TABLE_NAME;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS application_entry_paths_archive_only ON application_entry_paths;
CREATE TRIGGER application_entry_paths_archive_only
  BEFORE UPDATE OR DELETE ON application_entry_paths
  FOR EACH ROW EXECUTE FUNCTION astranull_protection_record_archive_only();
DROP TRIGGER IF EXISTS protection_expectations_archive_only ON protection_expectations;
CREATE TRIGGER protection_expectations_archive_only
  BEFORE UPDATE OR DELETE ON protection_expectations
  FOR EACH ROW EXECUTE FUNCTION astranull_protection_record_archive_only();
DROP TRIGGER IF EXISTS protection_comparison_baselines_archive_only ON protection_comparison_baselines;
CREATE TRIGGER protection_comparison_baselines_archive_only
  BEFORE UPDATE OR DELETE ON protection_comparison_baselines
  FOR EACH ROW EXECUTE FUNCTION astranull_protection_record_archive_only();

CREATE OR REPLACE FUNCTION astranull_reject_protection_comparison_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME;
END;
$$;

DROP TRIGGER IF EXISTS protection_comparison_evaluations_immutable ON protection_comparison_evaluations;
CREATE TRIGGER protection_comparison_evaluations_immutable
  BEFORE UPDATE OR DELETE ON protection_comparison_evaluations
  FOR EACH ROW EXECUTE FUNCTION astranull_reject_protection_comparison_mutation();
DROP TRIGGER IF EXISTS protection_comparison_evidence_refs_immutable ON protection_comparison_evidence_refs;
CREATE TRIGGER protection_comparison_evidence_refs_immutable
  BEFORE UPDATE OR DELETE ON protection_comparison_evidence_refs
  FOR EACH ROW EXECUTE FUNCTION astranull_reject_protection_comparison_mutation();

ALTER TABLE application_entry_paths ENABLE ROW LEVEL SECURITY;
ALTER TABLE application_entry_paths FORCE ROW LEVEL SECURITY;
ALTER TABLE protection_expectations ENABLE ROW LEVEL SECURITY;
ALTER TABLE protection_expectations FORCE ROW LEVEL SECURITY;
ALTER TABLE protection_comparison_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE protection_comparison_baselines FORCE ROW LEVEL SECURITY;
ALTER TABLE protection_comparison_evaluations ENABLE ROW LEVEL SECURITY;
ALTER TABLE protection_comparison_evaluations FORCE ROW LEVEL SECURITY;
ALTER TABLE protection_comparison_evidence_refs ENABLE ROW LEVEL SECURITY;
ALTER TABLE protection_comparison_evidence_refs FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_application_entry_paths ON application_entry_paths;
CREATE POLICY tenant_isolation_application_entry_paths ON application_entry_paths
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS tenant_isolation_protection_expectations ON protection_expectations;
CREATE POLICY tenant_isolation_protection_expectations ON protection_expectations
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS tenant_isolation_protection_comparison_baselines ON protection_comparison_baselines;
CREATE POLICY tenant_isolation_protection_comparison_baselines ON protection_comparison_baselines
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS tenant_isolation_protection_comparison_evaluations ON protection_comparison_evaluations;
CREATE POLICY tenant_isolation_protection_comparison_evaluations ON protection_comparison_evaluations
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS tenant_isolation_protection_comparison_evidence_refs ON protection_comparison_evidence_refs;
CREATE POLICY tenant_isolation_protection_comparison_evidence_refs ON protection_comparison_evidence_refs
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

COMMENT ON TABLE application_entry_paths IS
  'Declared same-tenant application entry-path relations. Not probe authority; origin relations reference an origin binding.';
COMMENT ON TABLE protection_expectations IS
  'Versioned declared behavior expectations. A change is a new expectation_version for the same scope_key; prior versions are retained.';
COMMENT ON TABLE protection_comparison_baselines IS
  'Immutable per-expectation comparison baselines captured from finalized external evidence. Only a one-way archive is permitted.';
COMMENT ON TABLE protection_comparison_evaluations IS
  'Immutable comparison evaluations with bounded per-item results. Zero items is never accepted.';
COMMENT ON TABLE protection_comparison_evidence_refs IS
  'Immutable same-tenant references from baselines and evaluations to finalized runs. References only; no raw traffic.';
