-- AstraNull PostgreSQL schema *contract* — NOT a database build script.
--
-- DO NOT load this file to provision a database. db/migrations/ is the only source of
-- truth and the only thing that is ever executed (see runMigrations in
-- src/persistence/postgres/migrations.mjs; tests provision via tests/helpers/pg-harness.mjs).
-- Nothing in the repo executes this file: it is read only by scripts/validate-db-schema.mjs
-- and scripts/postgres-tenant-query-audit.mjs, and copied into images for reference.
--
-- Loading it directly yields a database that is missing every object added after the
-- migrations it covers — as of migration 0041 that is 6 tables/views and 21 indexes,
-- including the RLS policies on dns_challenges, target_verifications,
-- finding_remediations, and signup_queue_events. A tenant-isolation control that is
-- absent because the wrong file was loaded fails open silently.
--
-- Coverage is therefore deliberately partial and this header is not a completeness claim.
-- Developer validation uses src/store.mjs (JSON).
-- App code must set_config('app.tenant_id', ..., true) inside transactions when using RLS-backed queries.

CREATE TABLE schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE TABLE tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  plan TEXT,
  data_region TEXT,
  status TEXT DEFAULT 'active',
  privacy_settings JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE environments (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL,
  status TEXT DEFAULT 'active',
  timezone TEXT,
  privacy_settings JSONB DEFAULT '{}',
  settings_json JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  email TEXT NOT NULL,
  name TEXT,
  role TEXT NOT NULL,
  mfa_enabled BOOLEAN DEFAULT FALSE,
  status TEXT DEFAULT 'active',
  -- Invite/disable lifecycle metadata (invited_at, disabled_at, disabled_by, disabled_reason)
  -- read/written by the internal-management repository. Parity with
  -- db/migrations/0039_users_metadata_json.sql.
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, email)
);

CREATE TABLE user_credentials (
  user_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  password_hash TEXT NOT NULL,
  password_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  must_change BOOLEAN NOT NULL DEFAULT FALSE,
  failed_attempts INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  last_login_at TIMESTAMPTZ,
  session_generation BIGINT NOT NULL DEFAULT 1,
  mfa_secret_envelope JSONB,
  mfa_enrollment_id TEXT,
  mfa_enrolled_at TIMESTAMPTZ,
  mfa_last_step BIGINT,
  mfa_pending_at TIMESTAMPTZ,
  mfa_disabled_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT user_credentials_session_generation_positive CHECK (session_generation > 0),
  CONSTRAINT user_credentials_mfa_state_consistent CHECK (
    (
      mfa_secret_envelope IS NULL
      AND mfa_enrollment_id IS NULL
      AND mfa_enrolled_at IS NULL
      AND mfa_pending_at IS NULL
      AND mfa_last_step IS NULL
    )
    OR
    (
      jsonb_typeof(mfa_secret_envelope) = 'object'
      AND mfa_enrollment_id IS NOT NULL
      AND (
        (mfa_enrolled_at IS NULL AND mfa_pending_at IS NOT NULL AND mfa_last_step IS NULL)
        OR
        (
          mfa_enrolled_at IS NOT NULL
          AND mfa_pending_at IS NULL
          AND mfa_last_step IS NOT NULL
          AND mfa_last_step >= 0
        )
      )
    )
  )
);

CREATE TABLE user_password_invites (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE user_password_resets (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Password recovery delivery outbox. Recipient and reset token exist only inside envelope.
CREATE TABLE password_recovery_delivery_outbox (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  user_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'password_reset',
  envelope JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  attempt_count INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  next_attempt_at TIMESTAMPTZ DEFAULT NOW(),
  lease_expires_at TIMESTAMPTZ,
  last_error_code TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  delivered_at TIMESTAMPTZ,
  CONSTRAINT password_recovery_delivery_outbox_user_fk
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT password_recovery_delivery_outbox_idempotency
    UNIQUE (tenant_id, kind, idempotency_key),
  CONSTRAINT password_recovery_delivery_outbox_kind_check CHECK (kind = 'password_reset'),
  CONSTRAINT password_recovery_delivery_outbox_envelope_check CHECK (
    jsonb_typeof(envelope) = 'object'
    AND envelope ->> 'algorithm' = 'AES-256-GCM'
    AND envelope ->> 'version' = '1'
    AND jsonb_typeof(envelope -> 'iv') = 'string'
    AND jsonb_typeof(envelope -> 'ciphertext') = 'string'
    AND jsonb_typeof(envelope -> 'auth_tag') = 'string'
    AND NOT (envelope ? 'email')
    AND NOT (envelope ? 'reset_token')
  ),
  CONSTRAINT password_recovery_delivery_outbox_status_check
    CHECK (status IN ('queued', 'leased', 'retry', 'delivered', 'dead')),
  CONSTRAINT password_recovery_delivery_outbox_attempts_check
    CHECK (attempt_count >= 0 AND max_attempts BETWEEN 1 AND 10 AND attempt_count <= max_attempts),
  CONSTRAINT password_recovery_delivery_outbox_error_code_check
    CHECK (last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 128),
  CONSTRAINT password_recovery_delivery_outbox_state_check CHECK (
    (status IN ('queued', 'retry') AND next_attempt_at IS NOT NULL
      AND lease_expires_at IS NULL AND delivered_at IS NULL)
    OR (status = 'leased' AND lease_expires_at IS NOT NULL AND delivered_at IS NULL)
    OR (status = 'delivered' AND next_attempt_at IS NULL
      AND lease_expires_at IS NULL AND delivered_at IS NOT NULL)
    OR (status = 'dead' AND next_attempt_at IS NULL
      AND lease_expires_at IS NULL AND delivered_at IS NULL)
  )
);
CREATE INDEX idx_password_recovery_delivery_outbox_due
  ON password_recovery_delivery_outbox(tenant_id, next_attempt_at, created_at)
  WHERE status IN ('queued', 'retry');
CREATE INDEX idx_password_recovery_delivery_outbox_expired_lease
  ON password_recovery_delivery_outbox(tenant_id, lease_expires_at)
  WHERE status = 'leased';
ALTER TABLE password_recovery_delivery_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_recovery_delivery_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY password_recovery_delivery_outbox_tenant_isolation
  ON password_recovery_delivery_outbox
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE TABLE signup_requests (
  id TEXT PRIMARY KEY,
  organization_name TEXT NOT NULL,
  contact_email TEXT NOT NULL,
  contact_name TEXT NOT NULL,
  email_domain TEXT NOT NULL,
  requested_plan TEXT NOT NULL,
  intended_use TEXT NOT NULL,
  region TEXT NOT NULL,
  high_scale_interest BOOLEAN NOT NULL DEFAULT FALSE,
  state TEXT NOT NULL,
  reviewer_staff_id TEXT,
  decision_reason TEXT,
  customer_notice TEXT,
  provisioned_tenant_id TEXT REFERENCES tenants(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  decided_at TIMESTAMPTZ
);

CREATE TABLE staff_users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT,
  staff_roles TEXT[] NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'active',
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE tenant_accounts (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(id),
  legal_name TEXT,
  support_owner TEXT,
  region TEXT NOT NULL DEFAULT 'us',
  lifecycle_state TEXT NOT NULL DEFAULT 'active',
  contract_reference TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ
);

CREATE TABLE tenant_subscriptions (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(id),
  plan_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  billing_provider_ref TEXT,
  effective_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  renewal_at TIMESTAMPTZ,
  limits_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  feature_entitlements_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ
);

CREATE TABLE entitlement_grants (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  feature TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  limit_value JSONB,
  source TEXT NOT NULL DEFAULT 'staff_override',
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, feature)
);

CREATE TABLE internal_approval_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT REFERENCES tenants(id),
  kind TEXT NOT NULL,
  subject_ref TEXT,
  state TEXT NOT NULL DEFAULT 'submitted',
  assigned_to TEXT,
  decision TEXT,
  reason TEXT,
  evidence_refs TEXT[] NOT NULL DEFAULT '{}',
  reviewer_staff_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  decided_at TIMESTAMPTZ
);

CREATE TABLE internal_audit_log (
  id TEXT PRIMARY KEY,
  tenant_id TEXT REFERENCES tenants(id),
  staff_id TEXT,
  staff_role TEXT,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id TEXT,
  reason TEXT,
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Platform-level break-glass activations: no tenant_id (staff declare these about the
-- platform, not a tenant), so RLS is deliberately not enabled here, consistent with
-- staff_users / signup_requests / platform_metrics. Reporting-only: no authorization path
-- reads this table. See db/migrations/0041_break_glass_activations.sql.
CREATE TABLE break_glass_activations (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'active',
  reason TEXT,
  ticket_reference TEXT NOT NULL,
  activated_by TEXT,
  activated_role TEXT,
  activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  duration_minutes INTEGER NOT NULL
);

CREATE TABLE target_groups (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  environment_id TEXT,
  name TEXT NOT NULL,
  description TEXT,
  criticality TEXT,
  owner_user_id TEXT,
  expected_behavior_default TEXT,
  high_scale_allowed BOOLEAN DEFAULT FALSE,
  timezone TEXT,
  safe_test_windows JSONB DEFAULT '[]',
  safety_policy JSONB DEFAULT '{}',
  settings_json JSONB DEFAULT '{}',
  declaration_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  archived_at TIMESTAMPTZ,
  deleted_at TIMESTAMPTZ,
  deleted_by TEXT,
  validation_mode TEXT DEFAULT 'external_only',
  ownership_status TEXT DEFAULT 'unverified',
  dns_ownership JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT target_groups_declaration_json_object CHECK (jsonb_typeof(declaration_json) = 'object')
);

CREATE TABLE targets (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  normalized_value TEXT NOT NULL,
  expected_behavior TEXT,
  protocol TEXT,
  port INT,
  metadata_json JSONB DEFAULT '{}',
  declaration_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  deleted_at TIMESTAMPTZ,
  deleted_by TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT targets_declaration_json_object CHECK (jsonb_typeof(declaration_json) = 'object')
);

-- Expand/backfill compatibility retained by migration 0044 while the previous release
-- remains a rollback candidate. Current writers supply application-canonical values;
-- previous writers omit normalized_value and receive this conservative fallback.
CREATE OR REPLACE FUNCTION astranull_target_compat_normalized_value(
  target_kind TEXT,
  target_value TEXT
) RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
  normalized_kind TEXT := lower(btrim(target_kind));
  trimmed_value TEXT := btrim(target_value);
BEGIN
  IF normalized_kind IN ('domain', 'hostname', 'fqdn', 'dns_zone') THEN
    RETURN lower(regexp_replace(trimmed_value, '\.+$', ''));
  END IF;
  IF normalized_kind = 'ip' THEN
    BEGIN
      RETURN host(trimmed_value::inet);
    EXCEPTION WHEN invalid_text_representation THEN
      RETURN trimmed_value;
    END;
  END IF;
  RETURN trimmed_value;
END;
$$;

CREATE OR REPLACE FUNCTION astranull_targets_normalized_value_compat_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  writer_omitted_normalized_value BOOLEAN;
BEGIN
  NEW.kind := CASE
    WHEN lower(btrim(NEW.kind)) IN ('domain', 'hostname') THEN 'fqdn'
    ELSE lower(btrim(NEW.kind))
  END;
  writer_omitted_normalized_value := NEW.normalized_value IS NULL;
  IF TG_OP = 'UPDATE' THEN
    writer_omitted_normalized_value :=
      writer_omitted_normalized_value
      OR (
        (NEW.kind IS DISTINCT FROM OLD.kind OR NEW.value IS DISTINCT FROM OLD.value)
        AND NEW.normalized_value IS NOT DISTINCT FROM OLD.normalized_value
      );
  END IF;
  IF writer_omitted_normalized_value THEN
    NEW.normalized_value := astranull_target_compat_normalized_value(NEW.kind, NEW.value);
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER targets_normalized_value_compat
BEFORE INSERT OR UPDATE OF kind, value, normalized_value ON targets
FOR EACH ROW EXECUTE FUNCTION astranull_targets_normalized_value_compat_trigger();

CREATE TABLE dns_challenges (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  target_id TEXT,
  record_name TEXT NOT NULL,
  record_value TEXT NOT NULL,
  ttl_seconds INTEGER NOT NULL DEFAULT 60,
  state TEXT NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending', 'resolved', 'expired', 'revoked')),
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMPTZ,
  last_checked_at TIMESTAMPTZ,
  last_check_result JSONB,
  expires_at TIMESTAMPTZ NOT NULL,
  audit_entry_id TEXT
);

CREATE TABLE target_verifications (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_id TEXT NOT NULL,
  state TEXT NOT NULL
    CHECK (state IN ('unverified', 'pending', 'dns_verified', 'provider_verified', 'agent_verified', 'user_confirmed')),
  source_kind TEXT NOT NULL
    CHECK (source_kind IN ('dns_txt', 'provider_account', 'agent_observation', 'user_attestation', 'manual_override', 'connector_inventory', 'customer_declaration')),
  source_ref JSONB NOT NULL,
  transitioned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  transitioned_by TEXT NOT NULL,
  audit_entry_id TEXT NOT NULL
);

CREATE OR REPLACE VIEW target_verification_current AS
  SELECT DISTINCT ON (target_id)
    target_id, tenant_id, state, source_kind, source_ref, transitioned_at
  FROM target_verifications
  ORDER BY target_id, transitioned_at DESC;

-- Current WAF/CDN edge fingerprint per target, from the pinned wafw00f + cdncheck corpus.
-- Evidence is label-only: no raw header/cookie values and no block-page bodies (ADR-0005).
CREATE TABLE target_edge_detections (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  test_run_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'inconclusive'
    CHECK (status IN ('detected', 'not_detected', 'inconclusive', 'error', 'pending')),
  reason TEXT,
  waf_status TEXT NOT NULL DEFAULT 'inconclusive'
    CHECK (waf_status IN ('detected', 'not_detected', 'inconclusive')),
  waf_vendor TEXT,
  waf_type TEXT,
  waf_providers TEXT[] NOT NULL DEFAULT '{}',
  cdn_status TEXT NOT NULL DEFAULT 'inconclusive'
    CHECK (cdn_status IN ('detected', 'not_detected', 'inconclusive')),
  cdn_provider TEXT,
  cdn_type TEXT,
  cdn_providers TEXT[] NOT NULL DEFAULT '{}',
  cloud_status TEXT NOT NULL DEFAULT 'inconclusive'
    CONSTRAINT target_edge_detections_cloud_status_check
    CHECK (cloud_status IN ('detected', 'not_detected', 'inconclusive')),
  cloud_provider TEXT,
  confidence NUMERIC NOT NULL DEFAULT 0,
  conflicting_vendor_signals BOOLEAN NOT NULL DEFAULT FALSE,
  corpus_version TEXT,
  evidence_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  observed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX uniq_target_edge_detection_target
  ON target_edge_detections (tenant_id, target_id);

CREATE INDEX idx_target_edge_detections_group
  ON target_edge_detections (tenant_id, target_group_id, updated_at DESC);

CREATE TABLE bootstrap_tokens (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT,
  token_hash TEXT NOT NULL,
  token_salt TEXT NOT NULL,
  environment_id TEXT,
  target_group_id TEXT,
  prebind_fqdn TEXT,
  deployment_packaging TEXT,
  allowed_modes TEXT[],
  max_registrations INT NOT NULL DEFAULT 1,
  registrations_used INT NOT NULL DEFAULT 0,
  allowed_cidrs TEXT[],
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agents (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  environment_id TEXT,
  target_group_id TEXT,
  bootstrap_token_id TEXT,
  name TEXT,
  hostname TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  version TEXT,
  placement_type TEXT,
  capabilities TEXT[],
  fingerprint TEXT,
  credential_hash TEXT,
  credential_salt TEXT,
  last_heartbeat_at TIMESTAMPTZ,
  metadata_json JSONB DEFAULT '{}',
  probe_endpoint JSONB,
  probe_endpoint_status TEXT,
  probe_endpoint_error TEXT,
  last_token_validation_at TIMESTAMPTZ,
  last_token_validation_status TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE test_runs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  target_id TEXT,
  policy_id TEXT,
  policy_dispatch_id TEXT,
  scan_id TEXT,
  scan_step_id TEXT,
  check_id TEXT NOT NULL,
  created_by TEXT,
  initiated_by TEXT,
  risk_class TEXT,
  safety_class TEXT,
  vector_family TEXT,
  status TEXT NOT NULL,
  probe_external_result TEXT,
  awaiting_external_probe BOOLEAN NOT NULL DEFAULT FALSE,
  remediation_template TEXT,
  safety_constraints JSONB DEFAULT '{}',
  correlation_json JSONB DEFAULT '{}',
  collection_deadline_at TIMESTAMPTZ,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  summary_json JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE probe_jobs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  test_run_id TEXT NOT NULL,
  target_id TEXT,
  check_id TEXT NOT NULL,
  vector_family TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  nonce_hash TEXT NOT NULL,
  nonce_for_worker TEXT,
  probe_profile JSONB,
  constraints_json JSONB NOT NULL DEFAULT '{}',
  target_descriptor_json JSONB DEFAULT '{}',
  worker_metadata_json JSONB DEFAULT '{}',
  job_signature TEXT,
  leased_at TIMESTAMPTZ,
  leased_by TEXT,
  completed_at TIMESTAMPTZ,
  ownership_verification_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ownership_verifications (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  agent_id TEXT,
  declared_fqdn TEXT,
  status TEXT NOT NULL,
  challenge_nonce_hash TEXT,
  probe_observed BOOLEAN NOT NULL DEFAULT false,
  agent_observed BOOLEAN NOT NULL DEFAULT false,
  verified_at TIMESTAMPTZ,
  confirmed_by_user_id TEXT,
  confirmed_at TIMESTAMPTZ,
  probe_job_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by TEXT
);

CREATE TABLE test_policies (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  target_id TEXT,
  check_id TEXT NOT NULL,
  cadence TEXT NOT NULL DEFAULT 'manual'
    CONSTRAINT test_policies_cadence_check
    CHECK (cadence IN ('manual', 'daily', 'weekly', 'monthly', 'event_driven')),
  expected_verdict TEXT NOT NULL DEFAULT 'pass'
    CHECK (expected_verdict IN ('pass', 'warn', 'fail', 'manual_review')),
  safe_windows JSONB NOT NULL DEFAULT '[]',
  timezone TEXT NOT NULL DEFAULT 'UTC',
  event_trigger JSONB,
  state TEXT NOT NULL DEFAULT 'active'
    CHECK (state IN ('active', 'paused', 'archived')),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  max_concurrent_runs INTEGER NOT NULL DEFAULT 1 CHECK (max_concurrent_runs = 1),
  next_run_at TIMESTAMPTZ,
  last_scheduled_at TIMESTAMPTZ,
  last_dispatched_at TIMESTAMPTZ,
  last_run_id TEXT,
  lease_token TEXT,
  lease_owner TEXT,
  lease_expires_at TIMESTAMPTZ,
  schedule_revision BIGINT NOT NULL DEFAULT 1,
  safety_policy_snapshot JSONB NOT NULL DEFAULT '{}',
  archived_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT test_policies_event_trigger_disabled_check CHECK (
    (cadence = 'event_driven'
      AND event_trigger IS NOT NULL
      AND jsonb_typeof(event_trigger) = 'object'
      AND event_trigger @> '{"migrated_disabled":true}'::jsonb)
    OR (cadence <> 'event_driven' AND event_trigger IS NULL)
  ),
  CONSTRAINT test_policies_event_driven_inert_check CHECK (
    cadence <> 'event_driven'
    OR (
      state = 'paused'
      AND enabled = FALSE
      AND next_run_at IS NULL
      AND lease_token IS NULL
      AND lease_owner IS NULL
      AND lease_expires_at IS NULL
    )
  ),
  CONSTRAINT test_policies_exact_target_check CHECK (
    target_id IS NOT NULL
    OR (
      state IN ('paused', 'archived')
      AND enabled = FALSE
      AND next_run_at IS NULL
      AND lease_token IS NULL
      AND lease_owner IS NULL
      AND lease_expires_at IS NULL
    )
  ),
  CONSTRAINT test_policies_lease_check CHECK (
    (lease_token IS NULL AND lease_owner IS NULL AND lease_expires_at IS NULL)
    OR (lease_token IS NOT NULL AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
  )
);

-- Rollback-window compatibility for the previous release. Current application contracts
-- do not expose event-driven cadence, while this trigger and the independent CHECK above
-- accept old writes only as paused, disabled, non-dispatchable records.
CREATE OR REPLACE FUNCTION astranull_test_policies_event_driven_compat_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'UPDATE'
     AND OLD.cadence = 'event_driven'
     AND NEW.cadence <> 'event_driven' THEN
    -- Previous-release cadence updates did not clear event_trigger. Discard only that
    -- obsolete compatibility payload so the row can satisfy the current contract.
    NEW.event_trigger := NULL;
  ELSIF NEW.cadence = 'event_driven' THEN
    NEW.event_trigger := CASE
      WHEN jsonb_typeof(NEW.event_trigger) = 'object'
        THEN NEW.event_trigger || '{"migrated_disabled":true}'::jsonb
      ELSE '{"migrated_disabled":true}'::jsonb
    END;
    NEW.state := 'paused';
    NEW.enabled := FALSE;
    NEW.next_run_at := NULL;
    NEW.lease_token := NULL;
    NEW.lease_owner := NULL;
    NEW.lease_expires_at := NULL;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER test_policies_event_driven_compat
BEFORE INSERT OR UPDATE ON test_policies
FOR EACH ROW EXECUTE FUNCTION astranull_test_policies_event_driven_compat_trigger();

-- Rolling compatibility for the previous writer, which cannot send target_id. Bind only an
-- unambiguous active target; otherwise keep the policy visible but inert. Bound identity is
-- immutable for both old and current writers.
CREATE OR REPLACE FUNCTION astranull_test_policies_exact_target_compat_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  active_target_count INTEGER;
  resolved_target_id TEXT;
  preserve_archived BOOLEAN;
BEGIN
  preserve_archived := NEW.state = 'archived' OR NEW.archived_at IS NOT NULL;
  IF TG_OP = 'UPDATE' THEN
    preserve_archived := preserve_archived OR OLD.state = 'archived' OR OLD.archived_at IS NOT NULL;
    IF OLD.target_id IS NOT NULL AND NEW.target_id IS DISTINCT FROM OLD.target_id THEN
      RAISE EXCEPTION 'test policy target identity is immutable'
        USING ERRCODE = '23514', CONSTRAINT = 'test_policies_target_identity_immutable';
    END IF;
  END IF;
  IF NEW.target_id IS NULL THEN
    SELECT count(*), min(id) INTO active_target_count, resolved_target_id
    FROM targets
    WHERE tenant_id = NEW.tenant_id
      AND target_group_id = NEW.target_group_id
      AND deleted_at IS NULL;
    IF active_target_count = 1 THEN
      NEW.target_id := resolved_target_id;
    ELSE
      NEW.state := CASE WHEN preserve_archived THEN 'archived' ELSE 'paused' END;
      NEW.enabled := FALSE;
      NEW.next_run_at := NULL;
      NEW.lease_token := NULL;
      NEW.lease_owner := NULL;
      NEW.lease_expires_at := NULL;
    END IF;
  END IF;
  IF preserve_archived THEN
    NEW.state := 'archived';
    NEW.enabled := FALSE;
    NEW.next_run_at := NULL;
    NEW.lease_token := NULL;
    NEW.lease_owner := NULL;
    NEW.lease_expires_at := NULL;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER test_policies_exact_target_compat
BEFORE INSERT OR UPDATE ON test_policies
FOR EACH ROW EXECUTE FUNCTION astranull_test_policies_exact_target_compat_trigger();

CREATE TABLE test_policy_dispatches (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  policy_id TEXT NOT NULL,
  scheduled_for TIMESTAMPTZ NOT NULL,
  idempotency_key TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('leased', 'dispatched', 'skipped', 'failed')),
  lease_token TEXT,
  lease_owner TEXT,
  lease_expires_at TIMESTAMPTZ,
  start_claimed_at TIMESTAMPTZ,
  run_id TEXT,
  error_code TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  UNIQUE (tenant_id, idempotency_key),
  UNIQUE (tenant_id, policy_id, scheduled_for),
  UNIQUE (tenant_id, id),
  CHECK (
    (state = 'leased' AND lease_token IS NOT NULL AND lease_owner IS NOT NULL
      AND lease_expires_at IS NOT NULL AND completed_at IS NULL)
    OR (state <> 'leased' AND lease_token IS NULL AND lease_owner IS NULL
      AND lease_expires_at IS NULL AND completed_at IS NOT NULL
      AND start_claimed_at IS NOT NULL)
  ),
  CHECK (
    (state = 'dispatched' AND run_id IS NOT NULL)
    OR (state <> 'dispatched' AND run_id IS NULL)
  )
);

CREATE TABLE validation_scans (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  target_id TEXT,
  name TEXT,
  status TEXT NOT NULL,
  check_ids JSONB NOT NULL DEFAULT '[]',
  plan_snapshot JSONB NOT NULL DEFAULT '{}',
  scheduled_for TIMESTAMPTZ,
  recurrence JSONB,
  recurrence_series_id TEXT,
  occurrence_key TEXT,
  occurrence_index INTEGER NOT NULL DEFAULT 0,
  previous_scan_id TEXT,
  next_scan_id TEXT,
  dispatched_at TIMESTAMPTZ,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  abort_reason TEXT,
  cancel_reason TEXT,
  cancelled_by TEXT,
  cancelled_by_role TEXT,
  cancelled_at TIMESTAMPTZ,
  created_by TEXT,
  created_by_role TEXT,
  lease_token TEXT,
  lease_owner TEXT,
  lease_expires_at TIMESTAMPTZ,
  next_eligible_at TIMESTAMPTZ,
  revision BIGINT NOT NULL DEFAULT 1,
  summary JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT validation_scans_status_check
    CHECK (status IN ('scheduled', 'pending', 'running', 'completed', 'denied', 'cancelled')),
  CONSTRAINT validation_scans_scheduled_for_check
    CHECK (status <> 'scheduled' OR scheduled_for IS NOT NULL),
  CONSTRAINT validation_scans_lease_check CHECK (
    (lease_token IS NULL AND lease_owner IS NULL AND lease_expires_at IS NULL)
    OR (lease_token IS NOT NULL AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
  ),
  CONSTRAINT validation_scans_recurrence_check CHECK (
    recurrence IS NULL
    OR (jsonb_typeof(recurrence) = 'object'
      AND recurrence->>'cadence' IN ('daily', 'weekly', 'monthly'))
  ),
  CONSTRAINT validation_scans_cancelled_check
    CHECK ((status = 'cancelled') = (cancelled_at IS NOT NULL))
);

CREATE TABLE validation_scan_steps (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  scan_id TEXT NOT NULL,
  position INTEGER NOT NULL,
  check_id TEXT NOT NULL,
  check_name TEXT,
  target_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  test_run_id TEXT,
  error_code TEXT,
  skip_reason TEXT,
  eligible_at TIMESTAMPTZ,
  attempts INTEGER NOT NULL DEFAULT 0,
  request_snapshot JSONB NOT NULL DEFAULT '{}',
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT validation_scan_steps_tenant_scan_position_key UNIQUE (tenant_id, scan_id, position),
  CONSTRAINT validation_scan_steps_status_check CHECK (
    status IN ('pending', 'deferred', 'starting', 'running', 'collecting',
      'verdicted', 'denied', 'skipped', 'cancelled')
  )
);

CREATE TABLE loa_signatures (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'signed'
    CHECK (state IN ('signed', 'revoked', 'expired', 'superseded')),
  signer_name TEXT NOT NULL,
  signer_title TEXT NOT NULL,
  signer_email TEXT NOT NULL,
  signed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ,
  emergency_contact JSONB NOT NULL,
  attested BOOLEAN NOT NULL,
  scope_snapshot JSONB NOT NULL,
  custody_artifact_id TEXT NOT NULL,
  custody_digest_sha256 TEXT NOT NULL,
  soc_countersign_id TEXT,
  soc_countersigned_at TIMESTAMPTZ,
  audit_entry_id TEXT NOT NULL
);

CREATE TABLE agent_jobs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  agent_id TEXT NOT NULL,
  test_run_id TEXT,
  check_id TEXT,
  target_id TEXT,
  type TEXT NOT NULL DEFAULT 'observe_window',
  status TEXT NOT NULL DEFAULT 'pending',
  nonce_hash TEXT,
  nonce_for_agent TEXT,
  payload_json JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  acked_at TIMESTAMPTZ,
  observed_at TIMESTAMPTZ
);

CREATE TABLE events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  event_id TEXT,
  test_run_id TEXT,
  target_id TEXT,
  check_id TEXT,
  agent_id TEXT,
  source TEXT,
  signal_type TEXT,
  producer_kind TEXT NOT NULL DEFAULT 'legacy_untrusted'
    CHECK (producer_kind IN ('legacy_untrusted', 'public_api', 'signed_probe', 'authenticated_agent', 'internal_simulation', 'internal_control_plane')),
  nonce_hash TEXT,
  timestamp TIMESTAMPTZ NOT NULL,
  metadata_json JSONB DEFAULT '{}',
  ingested_at TIMESTAMPTZ DEFAULT now(),
  CONSTRAINT events_reserved_producer_check CHECK (
    signal_type NOT IN ('probe_result', 'agent_observation', 'ownership_observation', 'agent_no_observation')
    OR producer_kind = 'legacy_untrusted'
    OR (signal_type = 'probe_result' AND producer_kind IN ('signed_probe', 'internal_simulation'))
    OR (signal_type = 'agent_observation' AND producer_kind = 'authenticated_agent')
    OR (signal_type = 'ownership_observation' AND producer_kind IN ('signed_probe', 'authenticated_agent'))
    OR (signal_type = 'agent_no_observation' AND producer_kind = 'internal_control_plane')
  ),
  CONSTRAINT events_probe_activity_producer_check CHECK (
    signal_type IS DISTINCT FROM 'probe_activity' OR producer_kind = 'signed_probe'
  )
);

CREATE TABLE verdicts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  test_run_id TEXT NOT NULL,
  target_id TEXT,
  check_id TEXT,
  verdict TEXT NOT NULL,
  confidence TEXT,
  explanation TEXT,
  evidence_ids TEXT[],
  placement_confidence_json JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT,
  target_id TEXT,
  test_run_id TEXT,
  check_id TEXT,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  evidence_ids TEXT[],
  notes TEXT,
  remediation_template TEXT,
  verdict_id TEXT,
  last_verdict_id TEXT,
  assignee TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ
);

CREATE TABLE evidence_vault (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  test_run_id TEXT,
  label TEXT,
  metadata_json JSONB DEFAULT '{}',
  related_event_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE reports (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  kind TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL,
  summary_json JSONB DEFAULT '{}',
  run_ids TEXT[],
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE high_scale_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT,
  requested_by TEXT,
  state TEXT NOT NULL,
  reason TEXT,
  objective TEXT,
  requested_window JSONB DEFAULT '{}',
  emergency_contacts JSONB DEFAULT '[]',
  scope_confirmation BOOLEAN DEFAULT FALSE,
  created_by TEXT,
  audit_trail JSONB DEFAULT '[]',
  artifacts JSONB DEFAULT '[]',
  scope_hash TEXT,
  soc_approvals JSONB DEFAULT '[]',
  provider_approval_checklist JSONB DEFAULT '[]',
  adapter_json JSONB DEFAULT '{}',
  scheduled_window JSONB,
  provider_context_json JSONB DEFAULT '{}',
  risk_review_json JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ
);

CREATE TABLE authorization_artifacts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  high_scale_request_id TEXT NOT NULL,
  type TEXT NOT NULL,
  reference_uri TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  reviewed_by TEXT,
  reviewed_at TIMESTAMPTZ,
  metadata_json JSONB DEFAULT '{}',
  content_sha256 TEXT,
  custody_id TEXT,
  custody_uri TEXT,
  content_type TEXT,
  filename_redacted TEXT,
  upload_envelope TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_authorization_artifacts_tenant_request_created
  ON authorization_artifacts(tenant_id, high_scale_request_id, created_at);

CREATE INDEX idx_authorization_artifacts_tenant_custody
  ON authorization_artifacts(tenant_id, custody_id)
  WHERE custody_id IS NOT NULL;

CREATE TABLE soc_notes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  high_scale_request_id TEXT NOT NULL,
  body TEXT NOT NULL,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE soc_kill_switch (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(id),
  active BOOLEAN NOT NULL DEFAULT FALSE,
  reason TEXT,
  updated_at TIMESTAMPTZ,
  updated_by TEXT
);

CREATE TABLE notification_rules (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  channel TEXT NOT NULL,
  destination TEXT NOT NULL,
  trigger TEXT,
  triggers_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  enabled BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ,
  updated_by TEXT,
  deleted_at TIMESTAMPTZ
);

CREATE TABLE notification_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  rule_id TEXT,
  trigger TEXT,
  subject TEXT,
  metadata_json JSONB DEFAULT '{}'::jsonb,
  delivery_status TEXT DEFAULT 'metadata_only',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  dedupe_key TEXT
);

CREATE TABLE service_accounts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  scopes TEXT[] NOT NULL DEFAULT '{}',
  secret_hash TEXT NOT NULL,
  secret_salt TEXT NOT NULL,
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by TEXT,
  rotated_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ
);

CREATE TABLE encrypted_secrets (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  purpose TEXT NOT NULL,
  name TEXT NOT NULL,
  metadata_json JSONB DEFAULT '{}',
  rotation INT NOT NULL DEFAULT 0,
  envelope_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by TEXT
);

CREATE TABLE agent_update_trust_keys (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL,
  public_key_der_base64 TEXT NOT NULL,
  fingerprint_sha256 TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by TEXT,
  revoked_at TIMESTAMPTZ
);

CREATE TABLE agent_update_releases (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  version TEXT NOT NULL,
  channel TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'active',
  manifest_json JSONB NOT NULL DEFAULT '{}',
  signature TEXT,
  distribution_json JSONB DEFAULT '{}',
  rollout_json JSONB DEFAULT '{}',
  rollback_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by TEXT,
  rollback_requested_at TIMESTAMPTZ
);

CREATE TABLE agent_update_statuses (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  agent_id TEXT NOT NULL,
  release_id TEXT NOT NULL,
  status TEXT NOT NULL,
  action TEXT,
  installed_version TEXT,
  error_code TEXT,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE high_scale_telemetry (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  high_scale_request_id TEXT NOT NULL,
  category TEXT NOT NULL,
  live_status TEXT,
  observed_at TIMESTAMPTZ NOT NULL,
  source TEXT,
  metrics_json JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  recorded_by TEXT
);

CREATE TABLE soc_reports (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  high_scale_request_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by TEXT,
  impact_summary TEXT DEFAULT '',
  recommendations TEXT DEFAULT '',
  customer_summary TEXT DEFAULT '',
  residual_risk TEXT DEFAULT '',
  next_steps TEXT DEFAULT '',
  attachments_json JSONB DEFAULT '[]',
  evidence_ids TEXT[] DEFAULT '{}',
  derived_json JSONB DEFAULT '{}',
  final_state TEXT
);

CREATE TABLE notification_delivery_attempts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  notification_event_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  channel TEXT NOT NULL,
  destination_preview TEXT,
  status TEXT NOT NULL,
  reason TEXT,
  attempt_number INT,
  max_attempts INT,
  next_retry_at TIMESTAMPTZ,
  provider_error TEXT,
  exhausted BOOLEAN,
  provider_status INT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  attempted_at TIMESTAMPTZ,
  claimed_by TEXT,
  claimed_at TIMESTAMPTZ,
  lease_expires_at TIMESTAMPTZ,
  superseded_at TIMESTAMPTZ
);

CREATE TABLE production_release_evidence (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  kind TEXT NOT NULL,
  release_id TEXT,
  status TEXT NOT NULL DEFAULT 'accepted',
  evidence_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  notes TEXT,
  validation_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by TEXT
);

CREATE TABLE external_asset_candidates (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  entity_id TEXT,
  asset_type TEXT NOT NULL,
  asset_value_hash TEXT NOT NULL,
  display_value TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_ref TEXT,
  confidence NUMERIC NOT NULL DEFAULT 0,
  approval_status TEXT NOT NULL DEFAULT 'not_requested',
  approved_target_id TEXT,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  evidence_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE waf_products (
  id TEXT PRIMARY KEY,
  vendor TEXT NOT NULL,
  product TEXT NOT NULL,
  deployment_type TEXT NOT NULL DEFAULT 'unknown',
  fingerprint_version TEXT NOT NULL DEFAULT '1',
  confidence_rules_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  enabled BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE waf_assets (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  target_id TEXT,
  environment_id TEXT,
  canonical_url TEXT NOT NULL,
  asset_kind TEXT NOT NULL DEFAULT 'unknown',
  expected_waf_required BOOLEAN NOT NULL DEFAULT TRUE,
  expected_vendor_hint TEXT,
  business_criticality TEXT NOT NULL DEFAULT 'medium',
  traffic_tier TEXT NOT NULL DEFAULT 'unknown',
  compliance_tags TEXT[] NOT NULL DEFAULT '{}',
  owner_hint TEXT,
  region_code TEXT,
  geography_label TEXT,
  entity_id TEXT,
  owasp_exposure_tags TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE waf_fingerprints (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_asset_id TEXT NOT NULL,
  test_run_id TEXT,
  detected_vendor TEXT,
  detected_product TEXT,
  confidence NUMERIC NOT NULL DEFAULT 0,
  signals_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE waf_validation_runs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  test_run_id TEXT,
  waf_asset_id TEXT NOT NULL,
  mode TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'planned',
  started_at TIMESTAMPTZ,
  finalized_at TIMESTAMPTZ,
  safety_profile_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE waf_scenario_results (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_validation_run_id TEXT NOT NULL,
  scenario_family TEXT NOT NULL,
  test_material_type TEXT NOT NULL DEFAULT 'metadata_only',
  expected_action TEXT NOT NULL,
  observed_action TEXT NOT NULL DEFAULT 'inconclusive',
  passed BOOLEAN,
  confidence NUMERIC NOT NULL DEFAULT 0,
  evidence_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE waf_posture_snapshots (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_asset_id TEXT NOT NULL,
  status TEXT NOT NULL,
  reason_codes TEXT[] NOT NULL DEFAULT '{}',
  detected_vendor TEXT,
  detected_product TEXT,
  coverage_required BOOLEAN NOT NULL DEFAULT TRUE,
  risk_score INT NOT NULL DEFAULT 0,
  risk_factors_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  priority_band TEXT,
  recommended_action TEXT,
  scenario_pass_rate NUMERIC,
  control_bypass_status TEXT,
  confidence NUMERIC NOT NULL DEFAULT 0,
  source_mix_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  is_current BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE waf_coverage_daily_rollups (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  rollup_date DATE NOT NULL,
  total_assets INT NOT NULL DEFAULT 0,
  protected INT NOT NULL DEFAULT 0,
  edge_protected INT NOT NULL DEFAULT 0,
  underprotected INT NOT NULL DEFAULT 0,
  unprotected INT NOT NULL DEFAULT 0,
  unknown INT NOT NULL DEFAULT 0,
  excluded INT NOT NULL DEFAULT 0,
  coverage_ratio NUMERIC NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE waf_scenario_intakes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  pattern_title TEXT NOT NULL,
  advisory_refs TEXT[] NOT NULL DEFAULT '{}',
  proposed_scenario_family TEXT,
  risk_class TEXT NOT NULL DEFAULT 'metadata_only',
  intake_stage TEXT NOT NULL DEFAULT 'intake',
  notes TEXT,
  threat_summary TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE waf_baselines (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_asset_id TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'proposed',
  baseline_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  approved_by TEXT,
  approved_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE waf_exceptions (
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

CREATE TABLE waf_validation_plans (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'manual',
  schedule_interval TEXT,
  custom_cron_expression TEXT,
  scenarios_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  max_concurrent INT NOT NULL DEFAULT 1,
  timeout_ms INT NOT NULL DEFAULT 60000,
  state TEXT NOT NULL DEFAULT 'draft',
  delegated_jobs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  executed_at TIMESTAMPTZ,
  cancelled_at TIMESTAMPTZ,
  execution_lock_token TEXT,
  execution_lock_expires_at TIMESTAMPTZ
);

CREATE TABLE waf_baseline_approvals (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  baseline_id TEXT NOT NULL,
  waf_asset_id TEXT NOT NULL,
  approver TEXT NOT NULL,
  approval_notes TEXT NOT NULL,
  approved_at TIMESTAMPTZ NOT NULL,
  fingerprint_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE waf_retest_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  drift_event_id TEXT NOT NULL,
  waf_asset_id TEXT NOT NULL,
  retest_plan_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  requested_by TEXT NOT NULL,
  priority TEXT NOT NULL DEFAULT 'normal',
  status TEXT NOT NULL DEFAULT 'requested',
  verdict TEXT,
  verdict_reason TEXT,
  delegated_jobs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  execution_lock_token TEXT,
  execution_lock_expires_at TIMESTAMPTZ
);

COMMENT ON COLUMN waf_validation_plans.delegated_jobs_json IS
  'Delegated safe test runs. Each entry may include status pending_start (reserved before startTestRun), starting (startTestRun succeeded, finalize pending), delegated (persisted with test_run_id), or failed (reconciled or start failure). Legacy entries without status are treated as delegated when test_run_id is present.';

COMMENT ON COLUMN waf_retest_requests.delegated_jobs_json IS
  'Delegated retest safe test runs. Each entry may include status pending_start (reserved before startTestRun), starting (startTestRun succeeded, finalize pending), delegated (persisted with test_run_id), or failed (reconciled or start failure). Legacy entries without status are treated as delegated when test_run_id is present.';

CREATE TABLE waf_drift_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_asset_id TEXT NOT NULL,
  baseline_id TEXT,
  drift_type TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'medium',
  before_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  after_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'open',
  finding_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMPTZ
);

CREATE TABLE waf_drift_scan_results (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  scan_type TEXT NOT NULL,
  assets_scanned INT NOT NULL DEFAULT 0,
  drifts_detected INT NOT NULL DEFAULT 0,
  scan_duration_ms INT NOT NULL DEFAULT 0,
  completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  state TEXT NOT NULL DEFAULT 'completed',
  assets_with_connector_snapshots INT,
  drift_check_types TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE waf_connectors (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  provider TEXT NOT NULL,
  name TEXT NOT NULL,
  secret_id TEXT,
  config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'disabled',
  last_success_at TIMESTAMPTZ,
  last_error_at TIMESTAMPTZ,
  poll_revision BIGINT NOT NULL DEFAULT 0,
  last_success_revision BIGINT NOT NULL DEFAULT 0,
  last_poll_requested_at TIMESTAMPTZ,
  next_poll_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  consecutive_failures INTEGER NOT NULL DEFAULT 0
    CHECK (consecutive_failures >= 0 AND consecutive_failures <= 1000000),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE waf_connector_snapshots (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  connector_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  snapshot_kind TEXT NOT NULL,
  resource_ref_hash TEXT NOT NULL,
  display_ref TEXT,
  summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  config_hash TEXT,
  evidence_source TEXT NOT NULL DEFAULT 'manual_metadata'
    CHECK (evidence_source IN ('provider_api', 'manual_metadata')),
  inventory_complete BOOLEAN NOT NULL DEFAULT FALSE,
  inventory_truncated BOOLEAN NOT NULL DEFAULT FALSE,
  poll_revision BIGINT NOT NULL DEFAULT 0,
  observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (NOT inventory_complete OR NOT inventory_truncated)
);

CREATE TABLE tenant_connector_features (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_by TEXT NOT NULL,
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0)
);

CREATE TABLE connector_provider_rate_limits (
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  window_started_at TIMESTAMPTZ NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0 AND request_count <= 20),
  next_allowed_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, provider)
);

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
  lease_token TEXT,
  completed_at TIMESTAMPTZ,
  error_code TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (
    (status = 'leased' AND leased_by IS NOT NULL AND leased_at IS NOT NULL AND lease_token IS NOT NULL)
    OR
    (status <> 'leased' AND leased_by IS NULL AND leased_at IS NULL AND lease_token IS NULL)
  ),
  CHECK (
    envelope_json->>'job_id' = id
    AND envelope_json->>'tenant_id' = tenant_id
    AND envelope_json->>'connector_id' = connector_id
    AND envelope_json->>'provider' = provider
    AND (envelope_json->>'poll_revision')::BIGINT = poll_revision
    AND envelope_json->>'operation' = 'read_only_provider_inventory'
  ),
  UNIQUE (tenant_id, connector_id, poll_revision)
);

CREATE INDEX idx_waf_connectors_poll_due
  ON waf_connectors (tenant_id, next_poll_at, updated_at, id)
  WHERE secret_id IS NOT NULL AND status NOT IN ('disabled', 'revoked');
CREATE INDEX idx_connector_poll_jobs_retention
  ON connector_poll_jobs (tenant_id, created_at)
  WHERE status IN ('completed', 'failed', 'cancelled');
CREATE INDEX idx_waf_connector_snapshots_retention
  ON waf_connector_snapshots (tenant_id, created_at);

CREATE OR REPLACE FUNCTION target_provider_verification_is_current(
  p_tenant_id TEXT,
  p_target_id TEXT,
  p_source_ref JSONB
) RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM targets t
    JOIN waf_connectors c
      ON c.tenant_id = t.tenant_id
     AND c.id = p_source_ref->>'connector_id'
    JOIN waf_connector_snapshots s
      ON s.tenant_id = c.tenant_id
     AND s.connector_id = c.id
     AND s.provider = c.provider
     AND s.snapshot_kind = 'dns_zone'
     AND s.evidence_source = 'provider_api'
     AND s.resource_ref_hash = p_source_ref->>'resource_ref_hash'
     AND s.poll_revision = c.last_success_revision
     AND s.observed_at = c.last_success_at
    WHERE t.tenant_id = p_tenant_id
      AND t.id = p_target_id
      AND t.deleted_at IS NULL
      AND c.provider = p_source_ref->>'provider'
      AND c.provider IN ('cloudflare', 'akamai_edgedns', 'namecheap', 'godaddy', 'ibm_ns1')
      AND c.status IN ('active', 'degraded')
      AND c.secret_id IS NOT NULL
      AND c.last_success_at IS NOT NULL
      AND c.last_success_at <= CURRENT_TIMESTAMP
      AND c.last_success_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
      AND c.last_success_revision > 0
      AND EXISTS (
        SELECT 1
        FROM jsonb_array_elements_text(COALESCE(s.summary_json->'hostnames', '[]'::jsonb)) hostname(value)
        WHERE lower(rtrim(hostname.value, '.')) = lower(rtrim(COALESCE(t.normalized_value, t.value), '.'))
      )
      AND EXISTS (
        SELECT 1
        FROM jsonb_array_elements_text(COALESCE(s.summary_json->'tags', '[]'::jsonb)) tag(value)
        WHERE lower(tag.value) = 'ownership_eligible:true'
      )
      AND EXISTS (
        SELECT 1
        FROM jsonb_array_elements_text(COALESCE(s.summary_json->'tags', '[]'::jsonb)) tag(value)
        WHERE lower(tag.value) = 'resource_status:active'
      )
      AND (
        c.provider <> 'namecheap'
        OR EXISTS (
          SELECT 1
          FROM jsonb_array_elements_text(COALESCE(s.summary_json->'tags', '[]'::jsonb)) tag(value)
          WHERE lower(tag.value) = 'provider_environment:production'
        )
      )
  );
$$;

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

CREATE TABLE cve_pipeline_items (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  cve_id TEXT NOT NULL,
  published_at TIMESTAMPTZ,
  severity TEXT,
  known_exploited BOOLEAN NOT NULL DEFAULT FALSE,
  public_poc_signal BOOLEAN NOT NULL DEFAULT FALSE,
  state TEXT NOT NULL DEFAULT 'ingested',
  triage_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE cve_asset_matches (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  cve_pipeline_item_id TEXT NOT NULL,
  waf_asset_id TEXT NOT NULL,
  match_confidence NUMERIC NOT NULL DEFAULT 0,
  match_sources TEXT[] NOT NULL DEFAULT '{}',
  validation_status TEXT NOT NULL DEFAULT 'pending',
  risk_score INT NOT NULL DEFAULT 0,
  finding_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE waf_rule_recommendations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_asset_id TEXT NOT NULL,
  cve_asset_match_id TEXT,
  vendor TEXT NOT NULL,
  recommendation_type TEXT NOT NULL,
  recommendation_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  approval_status TEXT NOT NULL DEFAULT 'draft',
  ticket_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE discovery_entities (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  entity_type TEXT NOT NULL,
  name TEXT NOT NULL,
  display_name TEXT NOT NULL,
  parent_entity_id TEXT,
  root_domains TEXT[] NOT NULL DEFAULT '{}',
  country TEXT,
  confidence NUMERIC NOT NULL DEFAULT 0,
  source TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE supply_chain_risks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  exposure_type TEXT NOT NULL,
  hostname TEXT NOT NULL,
  evidence_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  confidence NUMERIC NOT NULL DEFAULT 0,
  severity TEXT NOT NULL DEFAULT 'medium',
  state TEXT NOT NULL DEFAULT 'suspected',
  owner_hint TEXT,
  remediation_steps TEXT[] NOT NULL DEFAULT '{}',
  assessment_metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE waf_action_items (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  asset_display TEXT,
  waf_asset_id TEXT,
  owner TEXT,
  severity TEXT NOT NULL DEFAULT 'medium',
  evidence_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  recommended_solution TEXT,
  retest_url TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  primary_reason TEXT,
  cve_pipeline_item_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE audit_logs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  sequence BIGINT NOT NULL,
  prev_hash TEXT,
  entry_hash TEXT NOT NULL,
  actor_user_id TEXT,
  actor_role TEXT,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id TEXT,
  metadata_json JSONB DEFAULT '{}'
);

CREATE TABLE platform_metrics (
  id TEXT PRIMARY KEY DEFAULT 'global',
  counters_json JSONB NOT NULL DEFAULT '{}',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tenant-consistent foreign keys: composite UNIQUE (tenant_id, id) on parents; child FKs use (tenant_id, parent_id).
ALTER TABLE environments ADD CONSTRAINT environments_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE users ADD CONSTRAINT users_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE user_credentials ADD CONSTRAINT fk_user_credentials_user_tenant
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE user_password_invites ADD CONSTRAINT fk_user_password_invites_user_tenant
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE user_password_resets ADD CONSTRAINT fk_user_password_resets_user_tenant
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE target_groups ADD CONSTRAINT target_groups_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE targets ADD CONSTRAINT targets_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE targets ADD CONSTRAINT targets_tenant_group_id_key UNIQUE (tenant_id, target_group_id, id);
ALTER TABLE dns_challenges ADD CONSTRAINT dns_challenges_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE target_verifications ADD CONSTRAINT target_verifications_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE target_edge_detections ADD CONSTRAINT target_edge_detections_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE bootstrap_tokens ADD CONSTRAINT bootstrap_tokens_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE agents ADD CONSTRAINT agents_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE test_runs ADD CONSTRAINT test_runs_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE test_runs ADD CONSTRAINT test_runs_tenant_run_group_target_key
  UNIQUE (tenant_id, id, target_group_id, target_id);
ALTER TABLE test_policies ADD CONSTRAINT test_policies_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE validation_scans ADD CONSTRAINT validation_scans_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE validation_scan_steps ADD CONSTRAINT validation_scan_steps_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE verdicts ADD CONSTRAINT verdicts_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE events ADD CONSTRAINT events_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE high_scale_requests ADD CONSTRAINT high_scale_requests_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE notification_events ADD CONSTRAINT notification_events_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE service_accounts ADD CONSTRAINT service_accounts_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE encrypted_secrets ADD CONSTRAINT encrypted_secrets_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE agent_update_trust_keys ADD CONSTRAINT agent_update_trust_keys_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE agent_update_releases ADD CONSTRAINT agent_update_releases_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE agent_update_statuses ADD CONSTRAINT agent_update_statuses_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE high_scale_telemetry ADD CONSTRAINT high_scale_telemetry_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE soc_reports ADD CONSTRAINT soc_reports_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE notification_delivery_attempts ADD CONSTRAINT notification_delivery_attempts_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE production_release_evidence ADD CONSTRAINT production_release_evidence_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE findings ADD CONSTRAINT findings_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_assets ADD CONSTRAINT waf_assets_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_validation_runs ADD CONSTRAINT waf_validation_runs_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_baselines ADD CONSTRAINT waf_baselines_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_validation_plans ADD CONSTRAINT waf_validation_plans_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_baseline_approvals ADD CONSTRAINT waf_baseline_approvals_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_retest_requests ADD CONSTRAINT waf_retest_requests_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_drift_events ADD CONSTRAINT waf_drift_events_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_drift_scan_results ADD CONSTRAINT waf_drift_scan_results_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_connectors ADD CONSTRAINT waf_connectors_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE cve_pipeline_items ADD CONSTRAINT cve_pipeline_items_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE cve_asset_matches ADD CONSTRAINT cve_asset_matches_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE discovery_entities ADD CONSTRAINT discovery_entities_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE supply_chain_risks ADD CONSTRAINT supply_chain_risks_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_action_items ADD CONSTRAINT waf_action_items_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_coverage_daily_rollups ADD CONSTRAINT waf_coverage_daily_rollups_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_scenario_intakes ADD CONSTRAINT waf_scenario_intakes_tenant_id_id_key UNIQUE (tenant_id, id);

ALTER TABLE target_groups ADD CONSTRAINT fk_target_groups_environment_tenant
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id);
ALTER TABLE target_groups ADD CONSTRAINT fk_target_groups_owner_user_tenant
  FOREIGN KEY (tenant_id, owner_user_id) REFERENCES users (tenant_id, id);
ALTER TABLE targets ADD CONSTRAINT fk_targets_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE dns_challenges ADD CONSTRAINT fk_dns_challenges_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE dns_challenges ADD CONSTRAINT fk_dns_challenges_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE target_verifications ADD CONSTRAINT fk_target_verifications_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE bootstrap_tokens ADD CONSTRAINT fk_bootstrap_tokens_environment_tenant
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id);
ALTER TABLE bootstrap_tokens ADD CONSTRAINT fk_bootstrap_tokens_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE agents ADD CONSTRAINT fk_agents_environment_tenant
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id);
ALTER TABLE agents ADD CONSTRAINT fk_agents_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE agents ADD CONSTRAINT fk_agents_bootstrap_token_tenant
  FOREIGN KEY (tenant_id, bootstrap_token_id) REFERENCES bootstrap_tokens (tenant_id, id);
ALTER TABLE test_runs ADD CONSTRAINT fk_test_runs_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE test_runs ADD CONSTRAINT fk_test_runs_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE test_runs ADD CONSTRAINT fk_test_runs_policy_tenant
  FOREIGN KEY (tenant_id, policy_id) REFERENCES test_policies (tenant_id, id);
ALTER TABLE test_policies ADD CONSTRAINT fk_test_policies_target_binding
  FOREIGN KEY (tenant_id, target_group_id, target_id)
  REFERENCES targets (tenant_id, target_group_id, id);
ALTER TABLE test_runs ADD CONSTRAINT fk_test_runs_policy_dispatch_tenant
  FOREIGN KEY (tenant_id, policy_dispatch_id) REFERENCES test_policy_dispatches (tenant_id, id);
ALTER TABLE test_policy_dispatches ADD CONSTRAINT fk_test_policy_dispatches_policy_tenant
  FOREIGN KEY (tenant_id, policy_id) REFERENCES test_policies (tenant_id, id);
ALTER TABLE test_policy_dispatches ADD CONSTRAINT fk_test_policy_dispatches_run_tenant
  FOREIGN KEY (tenant_id, run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE validation_scans ADD CONSTRAINT fk_validation_scans_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE validation_scan_steps ADD CONSTRAINT fk_validation_scan_steps_scan_tenant
  FOREIGN KEY (tenant_id, scan_id) REFERENCES validation_scans (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE validation_scan_steps ADD CONSTRAINT fk_validation_scan_steps_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE test_runs ADD CONSTRAINT fk_test_runs_scan_tenant
  FOREIGN KEY (tenant_id, scan_id) REFERENCES validation_scans (tenant_id, id);
ALTER TABLE loa_signatures ADD CONSTRAINT fk_loa_signatures_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id)
  REFERENCES target_groups (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE agent_jobs ADD CONSTRAINT fk_agent_jobs_agent_tenant
  FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id);
ALTER TABLE agent_jobs ADD CONSTRAINT fk_agent_jobs_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE agent_jobs ADD CONSTRAINT fk_agent_jobs_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE events ADD CONSTRAINT fk_events_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE events ADD CONSTRAINT fk_events_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE events ADD CONSTRAINT fk_events_agent_tenant
  FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id);
ALTER TABLE verdicts ADD CONSTRAINT fk_verdicts_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE verdicts ADD CONSTRAINT fk_verdicts_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE findings ADD CONSTRAINT fk_findings_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE findings ADD CONSTRAINT fk_findings_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE findings ADD CONSTRAINT fk_findings_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE findings ADD CONSTRAINT fk_findings_verdict_tenant
  FOREIGN KEY (tenant_id, verdict_id) REFERENCES verdicts (tenant_id, id);
ALTER TABLE findings ADD CONSTRAINT fk_findings_last_verdict_tenant
  FOREIGN KEY (tenant_id, last_verdict_id) REFERENCES verdicts (tenant_id, id);
ALTER TABLE evidence_vault ADD CONSTRAINT fk_evidence_vault_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE evidence_vault ADD CONSTRAINT fk_evidence_vault_related_event_tenant
  FOREIGN KEY (tenant_id, related_event_id) REFERENCES events (tenant_id, id);
ALTER TABLE high_scale_requests ADD CONSTRAINT fk_high_scale_requests_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE authorization_artifacts ADD CONSTRAINT fk_authorization_artifacts_high_scale_request_tenant
  FOREIGN KEY (tenant_id, high_scale_request_id) REFERENCES high_scale_requests (tenant_id, id);
ALTER TABLE soc_notes ADD CONSTRAINT fk_soc_notes_high_scale_request_tenant
  FOREIGN KEY (tenant_id, high_scale_request_id) REFERENCES high_scale_requests (tenant_id, id);
ALTER TABLE notification_events ADD CONSTRAINT fk_notification_events_rule_tenant
  FOREIGN KEY (tenant_id, rule_id) REFERENCES notification_rules (tenant_id, id);
ALTER TABLE agent_update_statuses ADD CONSTRAINT fk_agent_update_statuses_agent_tenant
  FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id);
ALTER TABLE agent_update_statuses ADD CONSTRAINT fk_agent_update_statuses_release_tenant
  FOREIGN KEY (tenant_id, release_id) REFERENCES agent_update_releases (tenant_id, id);
ALTER TABLE high_scale_telemetry ADD CONSTRAINT fk_high_scale_telemetry_high_scale_request_tenant
  FOREIGN KEY (tenant_id, high_scale_request_id) REFERENCES high_scale_requests (tenant_id, id);
ALTER TABLE soc_reports ADD CONSTRAINT fk_soc_reports_high_scale_request_tenant
  FOREIGN KEY (tenant_id, high_scale_request_id) REFERENCES high_scale_requests (tenant_id, id);
ALTER TABLE notification_delivery_attempts ADD CONSTRAINT fk_notification_delivery_attempts_event_tenant
  FOREIGN KEY (tenant_id, notification_event_id) REFERENCES notification_events (tenant_id, id);
ALTER TABLE notification_delivery_attempts ADD CONSTRAINT fk_notification_delivery_attempts_rule_tenant
  FOREIGN KEY (tenant_id, rule_id) REFERENCES notification_rules (tenant_id, id);
ALTER TABLE external_asset_candidates ADD CONSTRAINT fk_external_asset_candidates_approved_target_tenant
  FOREIGN KEY (tenant_id, approved_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE external_asset_candidates ADD CONSTRAINT fk_external_asset_candidates_entity
  FOREIGN KEY (tenant_id, entity_id) REFERENCES discovery_entities (tenant_id, id);
ALTER TABLE waf_assets ADD CONSTRAINT fk_waf_assets_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE waf_assets ADD CONSTRAINT fk_waf_assets_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE waf_assets ADD CONSTRAINT fk_waf_assets_environment_tenant
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id);
ALTER TABLE waf_assets ADD CONSTRAINT fk_waf_assets_entity_tenant
  FOREIGN KEY (tenant_id, entity_id) REFERENCES discovery_entities (tenant_id, id);
ALTER TABLE target_edge_detections ADD CONSTRAINT fk_target_edge_detections_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE target_edge_detections ADD CONSTRAINT fk_target_edge_detections_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE target_edge_detections ADD CONSTRAINT fk_target_edge_detections_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);

LOCK TABLE target_edge_detections, test_runs, targets IN SHARE ROW EXCLUSIVE MODE;
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM target_edge_detections edge
    LEFT JOIN targets target
      ON target.tenant_id = edge.tenant_id
     AND target.target_group_id = edge.target_group_id
     AND target.id = edge.target_id
    LEFT JOIN test_runs run
      ON run.tenant_id = edge.tenant_id
     AND run.id = edge.test_run_id
     AND run.target_group_id = edge.target_group_id
     AND run.target_id = edge.target_id
    WHERE edge.test_run_id IS NULL
       OR target.id IS NULL
       OR run.id IS NULL
  ) THEN
    RAISE EXCEPTION 'preexisting target edge detection provenance is malformed'
      USING ERRCODE = '23514',
            CONSTRAINT = 'target_edge_detections_provenance_binding';
  END IF;
END;
$$;

ALTER TABLE target_edge_detections ADD CONSTRAINT fk_target_edge_detections_target_binding
  FOREIGN KEY (tenant_id, target_group_id, target_id)
  REFERENCES targets (tenant_id, target_group_id, id);
ALTER TABLE target_edge_detections ADD CONSTRAINT fk_target_edge_detections_run_binding
  FOREIGN KEY (tenant_id, test_run_id, target_group_id, target_id)
  REFERENCES test_runs (tenant_id, id, target_group_id, target_id);
ALTER TABLE waf_fingerprints ADD CONSTRAINT fk_waf_fingerprints_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_fingerprints ADD CONSTRAINT fk_waf_fingerprints_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE waf_validation_runs ADD CONSTRAINT fk_waf_validation_runs_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE waf_validation_runs ADD CONSTRAINT fk_waf_validation_runs_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_scenario_results ADD CONSTRAINT fk_waf_scenario_results_waf_validation_run_tenant
  FOREIGN KEY (tenant_id, waf_validation_run_id) REFERENCES waf_validation_runs (tenant_id, id);
ALTER TABLE waf_posture_snapshots ADD CONSTRAINT fk_waf_posture_snapshots_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_baselines ADD CONSTRAINT fk_waf_baselines_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_exceptions ADD CONSTRAINT waf_exceptions_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_exceptions ADD CONSTRAINT fk_waf_exceptions_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_validation_plans ADD CONSTRAINT fk_waf_validation_plans_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE waf_baseline_approvals ADD CONSTRAINT fk_waf_baseline_approvals_baseline_tenant
  FOREIGN KEY (tenant_id, baseline_id) REFERENCES waf_baselines (tenant_id, id);
ALTER TABLE waf_baseline_approvals ADD CONSTRAINT fk_waf_baseline_approvals_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_retest_requests ADD CONSTRAINT fk_waf_retest_requests_drift_event_tenant
  FOREIGN KEY (tenant_id, drift_event_id) REFERENCES waf_drift_events (tenant_id, id);
ALTER TABLE waf_retest_requests ADD CONSTRAINT fk_waf_retest_requests_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_drift_events ADD CONSTRAINT fk_waf_drift_events_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_drift_events ADD CONSTRAINT fk_waf_drift_events_baseline_tenant
  FOREIGN KEY (tenant_id, baseline_id) REFERENCES waf_baselines (tenant_id, id);
ALTER TABLE waf_drift_events ADD CONSTRAINT fk_waf_drift_events_finding_tenant
  FOREIGN KEY (tenant_id, finding_id) REFERENCES findings (tenant_id, id);
ALTER TABLE waf_connectors ADD CONSTRAINT fk_waf_connectors_secret_tenant
  FOREIGN KEY (tenant_id, secret_id) REFERENCES encrypted_secrets (tenant_id, id);
ALTER TABLE waf_connector_snapshots ADD CONSTRAINT fk_waf_connector_snapshots_connector_tenant
  FOREIGN KEY (tenant_id, connector_id) REFERENCES waf_connectors (tenant_id, id);
ALTER TABLE connector_poll_jobs ADD CONSTRAINT fk_connector_poll_jobs_connector_tenant
  FOREIGN KEY (tenant_id, connector_id) REFERENCES waf_connectors (tenant_id, id);
ALTER TABLE cve_asset_matches ADD CONSTRAINT fk_cve_asset_matches_cve_pipeline_item_tenant
  FOREIGN KEY (tenant_id, cve_pipeline_item_id) REFERENCES cve_pipeline_items (tenant_id, id);
ALTER TABLE cve_asset_matches ADD CONSTRAINT fk_cve_asset_matches_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE cve_asset_matches ADD CONSTRAINT fk_cve_asset_matches_finding_tenant
  FOREIGN KEY (tenant_id, finding_id) REFERENCES findings (tenant_id, id);
ALTER TABLE waf_rule_recommendations ADD CONSTRAINT fk_waf_rule_recommendations_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_rule_recommendations ADD CONSTRAINT fk_waf_rule_recommendations_cve_asset_match_tenant
  FOREIGN KEY (tenant_id, cve_asset_match_id) REFERENCES cve_asset_matches (tenant_id, id);
ALTER TABLE waf_action_items ADD CONSTRAINT fk_waf_action_items_cve_pipeline_item_tenant
  FOREIGN KEY (tenant_id, cve_pipeline_item_id) REFERENCES cve_pipeline_items (tenant_id, id);
ALTER TABLE waf_action_items ADD CONSTRAINT fk_waf_action_items_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);

CREATE INDEX idx_environments_tenant ON environments(tenant_id);
CREATE UNIQUE INDEX uniq_signup_requests_active_domain ON signup_requests(email_domain) WHERE state <> 'rejected';
CREATE UNIQUE INDEX uniq_signup_requests_active_org ON signup_requests(lower(organization_name)) WHERE state <> 'rejected';
CREATE INDEX idx_signup_requests_state_created ON signup_requests(state, created_at DESC);
CREATE INDEX idx_internal_approval_requests_queue ON internal_approval_requests(state, kind, created_at DESC);
CREATE INDEX idx_internal_audit_log_tenant_created ON internal_audit_log(tenant_id, created_at DESC);
CREATE INDEX idx_internal_audit_log_staff_created ON internal_audit_log(staff_id, created_at DESC);
CREATE INDEX idx_break_glass_activations_activated_at ON break_glass_activations(activated_at DESC);
CREATE UNIQUE INDEX idx_break_glass_activations_single_active ON break_glass_activations(status)
  WHERE status = 'active';
CREATE INDEX idx_target_groups_tenant ON target_groups(tenant_id);
CREATE UNIQUE INDEX uniq_target_groups_active_name
  ON target_groups(tenant_id, COALESCE(environment_id, ''), lower(name))
  WHERE deleted_at IS NULL AND archived_at IS NULL;
CREATE INDEX idx_ownership_verifications_tenant_target ON ownership_verifications(tenant_id, target_group_id);
CREATE INDEX idx_test_policies_tenant_active ON test_policies(tenant_id, target_group_id) WHERE archived_at IS NULL;
CREATE UNIQUE INDEX uniq_test_policies_active_group_target_check
  ON test_policies(tenant_id, target_group_id, target_id, check_id)
  WHERE archived_at IS NULL AND target_id IS NOT NULL;
CREATE INDEX idx_test_policies_due ON test_policies(tenant_id, next_run_at, id)
  WHERE archived_at IS NULL AND state = 'active' AND enabled = TRUE AND next_run_at IS NOT NULL;
CREATE INDEX idx_test_policies_expired_lease ON test_policies(tenant_id, lease_expires_at)
  WHERE lease_expires_at IS NOT NULL;
CREATE INDEX idx_test_policy_dispatches_policy
  ON test_policy_dispatches(tenant_id, policy_id, scheduled_for DESC);
CREATE INDEX idx_test_policy_dispatches_expired_lease
  ON test_policy_dispatches(tenant_id, lease_expires_at) WHERE state = 'leased';
CREATE UNIQUE INDEX uniq_test_policy_dispatches_run
  ON test_policy_dispatches(tenant_id, run_id) WHERE run_id IS NOT NULL;
CREATE UNIQUE INDEX uniq_test_runs_policy_dispatch
  ON test_runs(tenant_id, policy_dispatch_id) WHERE policy_dispatch_id IS NOT NULL;
CREATE UNIQUE INDEX uniq_test_runs_scan_step
  ON test_runs(tenant_id, scan_step_id) WHERE scan_step_id IS NOT NULL;
CREATE UNIQUE INDEX uniq_validation_scans_occurrence
  ON validation_scans(tenant_id, occurrence_key) WHERE occurrence_key IS NOT NULL;
CREATE INDEX idx_validation_scans_due
  ON validation_scans(tenant_id, scheduled_for, id) WHERE status = 'scheduled';
CREATE INDEX idx_validation_scans_runnable
  ON validation_scans(tenant_id, next_eligible_at, id) WHERE status = 'running';
CREATE INDEX idx_validation_scans_tenant_group_created
  ON validation_scans(tenant_id, target_group_id, created_at DESC);
CREATE UNIQUE INDEX uniq_validation_scan_steps_run
  ON validation_scan_steps(tenant_id, test_run_id) WHERE test_run_id IS NOT NULL;
CREATE INDEX idx_validation_scan_steps_scan
  ON validation_scan_steps(tenant_id, scan_id, position);
CREATE INDEX loa_signatures_active_tenant_group
  ON loa_signatures(tenant_id, target_group_id) WHERE state = 'signed';
CREATE INDEX loa_signatures_expiring
  ON loa_signatures(expires_at) WHERE state = 'signed' AND expires_at IS NOT NULL;
CREATE INDEX dns_challenges_by_group
  ON dns_challenges(tenant_id, target_group_id, state);
CREATE INDEX dns_challenges_by_target
  ON dns_challenges(tenant_id, target_id) WHERE target_id IS NOT NULL;
CREATE INDEX dns_challenges_expiring
  ON dns_challenges(state, expires_at) WHERE state = 'pending';
CREATE INDEX target_verifications_latest
  ON target_verifications(target_id, transitioned_at DESC);
CREATE INDEX target_verifications_tenant
  ON target_verifications(tenant_id, state);
CREATE INDEX idx_targets_tenant_group ON targets(tenant_id, target_group_id);
CREATE UNIQUE INDEX uniq_targets_active_canonical
  ON targets(tenant_id, target_group_id, kind, normalized_value) WHERE deleted_at IS NULL;
CREATE INDEX idx_targets_tenant_group_active
  ON targets(tenant_id, target_group_id, created_at) WHERE deleted_at IS NULL;
CREATE INDEX idx_agents_tenant_heartbeat ON agents(tenant_id, last_heartbeat_at);
CREATE INDEX idx_agents_tenant_group ON agents(tenant_id, target_group_id);
CREATE INDEX idx_test_runs_tenant ON test_runs(tenant_id, target_group_id);
CREATE INDEX idx_test_runs_tenant_policy ON test_runs(tenant_id, policy_id) WHERE policy_id IS NOT NULL;
CREATE INDEX idx_agent_jobs ON agent_jobs(tenant_id, agent_id, status, created_at);
CREATE INDEX idx_probe_jobs_status_leased ON probe_jobs(status, leased_at, created_at);
CREATE INDEX idx_probe_jobs_tenant_run ON probe_jobs(tenant_id, test_run_id);
CREATE UNIQUE INDEX uniq_verdict_per_test_run ON verdicts(test_run_id);
CREATE UNIQUE INDEX uniq_active_test_run ON test_runs(tenant_id, target_id)
  WHERE target_id IS NOT NULL AND status IN ('planned', 'running', 'collecting');
CREATE UNIQUE INDEX uniq_active_unbound_test_run ON test_runs(tenant_id, target_group_id)
  WHERE target_id IS NULL AND status IN ('planned', 'running', 'collecting');
CREATE INDEX idx_events_correlation ON events(tenant_id, test_run_id, signal_type, nonce_hash, timestamp);
CREATE UNIQUE INDEX uniq_events_tenant_event_id ON events(tenant_id, event_id) WHERE event_id IS NOT NULL;
CREATE INDEX idx_findings_tenant_status ON findings(tenant_id, status, severity);
CREATE UNIQUE INDEX uniq_audit_tenant_sequence ON audit_logs(tenant_id, sequence);
CREATE INDEX idx_audit_tenant_time ON audit_logs(tenant_id, timestamp);
CREATE INDEX idx_audit_tenant_resource ON audit_logs(tenant_id, resource_type, resource_id, sequence);
CREATE INDEX idx_audit_tenant_metadata_scan_id ON audit_logs(tenant_id, (metadata_json->>'scan_id'), sequence)
  WHERE (metadata_json->>'scan_id') IS NOT NULL;
CREATE INDEX idx_audit_tenant_metadata_test_run_id ON audit_logs(tenant_id, (metadata_json->>'test_run_id'), sequence)
  WHERE (metadata_json->>'test_run_id') IS NOT NULL;
CREATE INDEX idx_hs_requests_tenant_state ON high_scale_requests(tenant_id, state);
CREATE INDEX idx_service_accounts_tenant_role ON service_accounts(tenant_id, role);
CREATE INDEX idx_agent_update_releases_tenant_state ON agent_update_releases(tenant_id, state);
CREATE INDEX idx_agent_update_statuses_tenant_agent ON agent_update_statuses(tenant_id, agent_id, recorded_at);
CREATE UNIQUE INDEX uniq_active_agent_update_trust_key_fingerprint
  ON agent_update_trust_keys(tenant_id, fingerprint_sha256) WHERE status = 'active';
CREATE INDEX idx_high_scale_telemetry_request_observed
  ON high_scale_telemetry(tenant_id, high_scale_request_id, observed_at);
CREATE UNIQUE INDEX uniq_soc_report_per_high_scale_request ON soc_reports(tenant_id, high_scale_request_id);
CREATE INDEX idx_notification_delivery_attempts_event ON notification_delivery_attempts(tenant_id, notification_event_id);
CREATE INDEX idx_notification_delivery_attempts_rule_latest ON notification_delivery_attempts(tenant_id, rule_id, created_at DESC);
CREATE INDEX idx_notification_delivery_attempts_due ON notification_delivery_attempts(tenant_id, next_retry_at, id)
  WHERE status = 'provider_retry_scheduled' AND superseded_at IS NULL;
CREATE UNIQUE INDEX uniq_notification_events_dedupe ON notification_events(tenant_id, dedupe_key) WHERE dedupe_key IS NOT NULL;
-- Lifecycle-notification reconciliation windows (0062_notification_outbox_reconciliation.sql).
CREATE INDEX idx_reports_tenant_created ON reports(tenant_id, created_at, id);
CREATE INDEX idx_verdicts_tenant_created ON verdicts(tenant_id, created_at, id);
CREATE INDEX idx_findings_tenant_high_created ON findings(tenant_id, created_at, id)
  WHERE severity IN ('high', 'critical');
CREATE INDEX idx_production_release_evidence_tenant_kind_created
  ON production_release_evidence(tenant_id, kind, created_at DESC);
CREATE INDEX idx_test_runs_tenant_created ON test_runs(tenant_id, created_at DESC);
CREATE INDEX idx_test_runs_tenant_group_created ON test_runs(tenant_id, target_group_id, created_at DESC);
CREATE INDEX idx_events_tenant_run_time ON events(tenant_id, test_run_id, timestamp);
CREATE INDEX idx_evidence_vault_tenant_run_created ON evidence_vault(tenant_id, test_run_id, created_at DESC);
CREATE INDEX idx_evidence_vault_tenant_related_event ON evidence_vault(tenant_id, related_event_id);
CREATE UNIQUE INDEX uniq_findings_open_target_check ON findings(tenant_id, target_group_id, target_id, check_id) WHERE status = 'open';
CREATE INDEX idx_user_password_invites_token_hash ON user_password_invites(token_hash);
CREATE UNIQUE INDEX idx_user_password_resets_token_hash ON user_password_resets(token_hash);
-- Target-detail findings keyset page: (tenant_id, target_id) equality then the
-- (created_at DESC, id DESC) sort tuple. See db/migrations/0040_findings_created_at_index.sql.
CREATE INDEX idx_findings_tenant_target_created ON findings(tenant_id, target_id, created_at DESC, id DESC);
CREATE UNIQUE INDEX uniq_probe_result_per_run_nonce ON events(tenant_id, test_run_id, signal_type, nonce_hash) WHERE signal_type = 'probe_result' AND nonce_hash IS NOT NULL;
CREATE INDEX idx_waf_assets_tenant_group_url ON waf_assets(tenant_id, target_group_id, canonical_url);
CREATE INDEX idx_external_asset_candidates_approval_queue ON external_asset_candidates(tenant_id, approval_status, confidence DESC);
CREATE UNIQUE INDEX uniq_waf_posture_snapshot_current ON waf_posture_snapshots(tenant_id, waf_asset_id) WHERE is_current = TRUE;
CREATE INDEX idx_waf_posture_snapshots_dashboard ON waf_posture_snapshots(tenant_id, status, created_at DESC);
CREATE INDEX idx_waf_drift_events_queue ON waf_drift_events(tenant_id, drift_type, status, created_at DESC);
CREATE INDEX idx_waf_drift_scan_results_latest ON waf_drift_scan_results(tenant_id, completed_at DESC);

CREATE UNIQUE INDEX uniq_waf_drift_events_open_asset_type
  ON waf_drift_events(tenant_id, waf_asset_id, drift_type)
  WHERE status = 'open';
CREATE UNIQUE INDEX uniq_waf_coverage_daily_rollups_tenant_date ON waf_coverage_daily_rollups(tenant_id, rollup_date);
CREATE INDEX idx_waf_coverage_daily_rollups_tenant_date ON waf_coverage_daily_rollups(tenant_id, rollup_date DESC);
CREATE INDEX idx_waf_validation_plans_tenant_state ON waf_validation_plans(tenant_id, state, created_at DESC);
CREATE INDEX idx_waf_validation_plans_scheduled ON waf_validation_plans(tenant_id, created_at DESC) WHERE state = 'scheduled';
CREATE INDEX idx_waf_retest_requests_drift ON waf_retest_requests(tenant_id, drift_event_id, created_at DESC);
CREATE INDEX idx_waf_validation_plans_execution_lock ON waf_validation_plans(tenant_id, execution_lock_expires_at) WHERE execution_lock_token IS NOT NULL;
CREATE INDEX idx_waf_retest_requests_execution_lock ON waf_retest_requests(tenant_id, execution_lock_expires_at) WHERE execution_lock_token IS NOT NULL;
CREATE INDEX idx_waf_baseline_approvals_baseline ON waf_baseline_approvals(tenant_id, baseline_id, created_at DESC);
CREATE INDEX idx_waf_exceptions_tenant_expires ON waf_exceptions(tenant_id, expires_at);
CREATE INDEX idx_waf_exceptions_tenant_asset ON waf_exceptions(tenant_id, waf_asset_id);
CREATE INDEX idx_waf_connector_snapshots_history ON waf_connector_snapshots(tenant_id, connector_id, provider, observed_at DESC);
CREATE INDEX idx_connector_poll_jobs_worker_queue
  ON connector_poll_jobs(tenant_id, status, created_at)
  WHERE status IN ('pending', 'leased');
CREATE INDEX idx_cve_pipeline_items_lookup ON cve_pipeline_items(tenant_id, cve_id);
CREATE UNIQUE INDEX uniq_cve_asset_matches_dedupe ON cve_asset_matches(tenant_id, cve_pipeline_item_id, waf_asset_id);
CREATE INDEX idx_supply_chain_risks_lookup ON supply_chain_risks(tenant_id, state, severity);
CREATE INDEX idx_waf_action_items_status ON waf_action_items(tenant_id, status, severity);
CREATE INDEX idx_discovery_entities_lookup ON discovery_entities(tenant_id, entity_type);
CREATE UNIQUE INDEX uniq_supply_chain_risks_dedupe ON supply_chain_risks(tenant_id, hostname, exposure_type);
CREATE UNIQUE INDEX uniq_waf_action_items_dedupe ON waf_action_items(tenant_id, waf_asset_id, primary_reason);

-- Row level security: app code must set app.tenant_id via set_config inside each transaction
-- once the Postgres adapter exists. Empty/unset setting denies tenant-scoped rows (fail closed).
-- FORCE RLS applies policies even to table owners; runtime role must be non-owner and not BYPASSRLS.


-- Exact target and archival serialization guards for live run/job creation.
CREATE OR REPLACE FUNCTION astranull_test_runs_exact_active_target_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  policy_target_id TEXT;
BEGIN
  PERFORM 1
  FROM target_groups tg
  JOIN targets t ON t.tenant_id = tg.tenant_id AND t.target_group_id = tg.id
  WHERE tg.tenant_id = NEW.tenant_id
    AND tg.id = NEW.target_group_id
    AND tg.deleted_at IS NULL
    AND tg.archived_at IS NULL
    AND t.id = NEW.target_id
    AND t.deleted_at IS NULL
  FOR KEY SHARE OF tg, t;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'test run target must be active and belong to its tenant/group'
      USING ERRCODE = '23514', CONSTRAINT = 'test_runs_exact_active_target';
  END IF;
  IF NEW.policy_id IS NOT NULL THEN
    SELECT p.target_id INTO policy_target_id
    FROM test_policies p
    WHERE p.tenant_id = NEW.tenant_id
      AND p.id = NEW.policy_id
      AND p.target_group_id = NEW.target_group_id
      AND p.archived_at IS NULL
    FOR KEY SHARE;
    IF NOT FOUND OR policy_target_id IS DISTINCT FROM NEW.target_id THEN
      RAISE EXCEPTION 'test run target must match its exact policy target'
        USING ERRCODE = '23514', CONSTRAINT = 'test_runs_policy_target_binding';
    END IF;
  END IF;
  IF NEW.policy_dispatch_id IS NOT NULL THEN
    IF NEW.policy_id IS NULL THEN
      RAISE EXCEPTION 'policy dispatch requires a matching policy binding'
        USING ERRCODE = '23514', CONSTRAINT = 'test_runs_policy_dispatch_binding';
    END IF;
    PERFORM 1 FROM test_policy_dispatches d
    WHERE d.tenant_id = NEW.tenant_id
      AND d.id = NEW.policy_dispatch_id
      AND d.policy_id = NEW.policy_id
    FOR KEY SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'test run dispatch must match its policy binding'
        USING ERRCODE = '23514', CONSTRAINT = 'test_runs_policy_dispatch_binding';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER test_runs_exact_active_target
BEFORE INSERT OR UPDATE OF tenant_id, target_group_id, target_id, policy_id, policy_dispatch_id
ON test_runs
FOR EACH ROW EXECUTE FUNCTION astranull_test_runs_exact_active_target_trigger();

CREATE OR REPLACE FUNCTION astranull_probe_jobs_exact_active_target_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  run_target_id TEXT;
  run_status TEXT;
BEGIN
  IF NEW.check_id = 'ownership.challenge' OR NEW.ownership_verification_id IS NOT NULL THEN
    RETURN NEW;
  END IF;

  PERFORM 1
  FROM targets t
  JOIN target_groups tg ON tg.tenant_id = t.tenant_id AND tg.id = t.target_group_id
  WHERE t.tenant_id = NEW.tenant_id
    AND t.id = NEW.target_id
    AND t.deleted_at IS NULL
    AND tg.deleted_at IS NULL
    AND tg.archived_at IS NULL
  FOR KEY SHARE OF t, tg;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'probe job target must remain active'
      USING ERRCODE = '23514', CONSTRAINT = 'probe_jobs_exact_active_target';
  END IF;
  IF NEW.test_run_id IS NOT NULL THEN
    SELECT tr.target_id, tr.status INTO run_target_id, run_status
    FROM test_runs tr
    WHERE tr.tenant_id = NEW.tenant_id AND tr.id = NEW.test_run_id
    FOR KEY SHARE;
    IF NOT FOUND
       OR run_target_id IS DISTINCT FROM NEW.target_id
       OR run_status NOT IN ('planned', 'running', 'collecting') THEN
      RAISE EXCEPTION 'probe job target must match an active test run'
        USING ERRCODE = '23514', CONSTRAINT = 'probe_jobs_test_run_target_binding';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER probe_jobs_exact_active_target
BEFORE INSERT OR UPDATE OF id, tenant_id, test_run_id, target_id, check_id,
  ownership_verification_id, nonce_hash, target_descriptor_json
ON probe_jobs
FOR EACH ROW EXECUTE FUNCTION astranull_probe_jobs_exact_active_target_trigger();

LOCK TABLE ownership_verifications, probe_jobs IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM ownership_verifications ov
    LEFT JOIN probe_jobs j
      ON j.tenant_id = ov.tenant_id AND j.id = ov.probe_job_id
    WHERE ov.probe_job_id IS NOT NULL
      AND (
        j.id IS NULL
        OR j.ownership_verification_id IS DISTINCT FROM ov.id
        OR j.test_run_id IS DISTINCT FROM ov.id
        OR j.target_id IS DISTINCT FROM ov.agent_id
        OR j.check_id IS DISTINCT FROM 'ownership.challenge'
        OR j.nonce_hash IS DISTINCT FROM ov.challenge_nonce_hash
        OR j.target_descriptor_json->>'kind' IS DISTINCT FROM 'fqdn'
        OR lower(btrim(j.target_descriptor_json->>'value'))
             IS DISTINCT FROM lower(btrim(ov.declared_fqdn))
      )
  ) OR EXISTS (
    SELECT 1
    FROM probe_jobs j
    LEFT JOIN ownership_verifications ov
      ON ov.tenant_id = j.tenant_id AND ov.id = j.ownership_verification_id
    WHERE (j.check_id = 'ownership.challenge' OR j.ownership_verification_id IS NOT NULL)
      AND (
        ov.id IS NULL
        OR ov.probe_job_id IS DISTINCT FROM j.id
        OR j.test_run_id IS DISTINCT FROM ov.id
        OR j.target_id IS DISTINCT FROM ov.agent_id
        OR j.check_id IS DISTINCT FROM 'ownership.challenge'
        OR j.nonce_hash IS DISTINCT FROM ov.challenge_nonce_hash
        OR j.target_descriptor_json->>'kind' IS DISTINCT FROM 'fqdn'
        OR lower(btrim(j.target_descriptor_json->>'value'))
             IS DISTINCT FROM lower(btrim(ov.declared_fqdn))
      )
  ) THEN
    RAISE EXCEPTION 'preexisting ownership verification/probe job binding is malformed'
      USING ERRCODE = '23514',
            CONSTRAINT = 'ownership_verifications_probe_job_binding';
  END IF;
END;
$$;

ALTER TABLE probe_jobs
  ADD CONSTRAINT probe_jobs_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE ownership_verifications
  ADD CONSTRAINT ownership_verifications_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE ownership_verifications
  ADD CONSTRAINT fk_ownership_verifications_probe_job_tenant
  FOREIGN KEY (tenant_id, probe_job_id)
  REFERENCES probe_jobs (tenant_id, id)
  DEFERRABLE INITIALLY DEFERRED
  NOT VALID;
ALTER TABLE probe_jobs
  ADD CONSTRAINT fk_probe_jobs_ownership_verification_tenant
  FOREIGN KEY (tenant_id, ownership_verification_id)
  REFERENCES ownership_verifications (tenant_id, id)
  DEFERRABLE INITIALLY DEFERRED
  NOT VALID;
ALTER TABLE ownership_verifications
  VALIDATE CONSTRAINT fk_ownership_verifications_probe_job_tenant;
ALTER TABLE probe_jobs
  VALIDATE CONSTRAINT fk_probe_jobs_ownership_verification_tenant;

CREATE OR REPLACE FUNCTION astranull_ownership_verifications_reciprocal_probe_job_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  current_probe_job_id TEXT;
BEGIN
  SELECT ov.probe_job_id
    INTO current_probe_job_id
  FROM ownership_verifications ov
  WHERE ov.tenant_id = NEW.tenant_id AND ov.id = NEW.id
  FOR KEY SHARE;
  IF NOT FOUND THEN
    RETURN NEW;
  END IF;

  PERFORM 1
  FROM probe_jobs j
  WHERE j.tenant_id = NEW.tenant_id
    AND j.ownership_verification_id = NEW.id
    AND j.id IS DISTINCT FROM current_probe_job_id
  FOR KEY SHARE;
  IF FOUND THEN
    RAISE EXCEPTION 'ownership verification cannot leave a one-sided ownership challenge job'
      USING ERRCODE = '23514',
            CONSTRAINT = 'ownership_verifications_probe_job_binding';
  END IF;

  IF current_probe_job_id IS NULL THEN
    RETURN NEW;
  END IF;

  PERFORM 1
  FROM ownership_verifications ov
  JOIN probe_jobs j
    ON j.tenant_id = ov.tenant_id AND j.id = ov.probe_job_id
  WHERE ov.tenant_id = NEW.tenant_id
    AND ov.id = NEW.id
    AND j.ownership_verification_id = ov.id
    AND j.test_run_id = ov.id
    AND j.target_id = ov.agent_id
    AND j.check_id = 'ownership.challenge'
    AND j.nonce_hash = ov.challenge_nonce_hash
    AND j.target_descriptor_json->>'kind' = 'fqdn'
    AND lower(btrim(j.target_descriptor_json->>'value')) = lower(btrim(ov.declared_fqdn))
  FOR KEY SHARE OF ov, j;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ownership verification must reciprocally match its exact ownership challenge job'
      USING ERRCODE = '23514',
            CONSTRAINT = 'ownership_verifications_probe_job_binding';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION astranull_probe_jobs_reciprocal_ownership_verification_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  current_check_id TEXT;
  current_ownership_verification_id TEXT;
BEGIN
  SELECT j.check_id, j.ownership_verification_id
    INTO current_check_id, current_ownership_verification_id
  FROM probe_jobs j
  WHERE j.tenant_id = NEW.tenant_id AND j.id = NEW.id;
  IF NOT FOUND THEN
    RETURN NEW;
  END IF;

  IF current_check_id <> 'ownership.challenge'
     AND current_ownership_verification_id IS NULL THEN
    PERFORM 1
    FROM ownership_verifications ov
    WHERE ov.tenant_id = NEW.tenant_id AND ov.probe_job_id = NEW.id;
    IF FOUND THEN
      RAISE EXCEPTION 'ordinary probe job cannot be referenced as an ownership challenge job'
        USING ERRCODE = '23514',
              CONSTRAINT = 'probe_jobs_ownership_challenge_binding';
    END IF;
    RETURN NEW;
  END IF;

  PERFORM 1
  FROM ownership_verifications ov
  WHERE ov.tenant_id = NEW.tenant_id
    AND ov.probe_job_id = NEW.id
    AND ov.id IS DISTINCT FROM current_ownership_verification_id
  FOR KEY SHARE;
  IF FOUND THEN
    RAISE EXCEPTION 'ownership challenge job cannot leave a one-sided verification reference'
      USING ERRCODE = '23514',
            CONSTRAINT = 'probe_jobs_ownership_challenge_binding';
  END IF;

  PERFORM 1
  FROM probe_jobs j
  JOIN ownership_verifications ov
    ON ov.tenant_id = j.tenant_id AND ov.id = j.ownership_verification_id
  WHERE j.tenant_id = NEW.tenant_id
    AND j.id = NEW.id
    AND ov.probe_job_id = j.id
    AND j.test_run_id = ov.id
    AND j.target_id = ov.agent_id
    AND j.check_id = 'ownership.challenge'
    AND j.nonce_hash = ov.challenge_nonce_hash
    AND j.target_descriptor_json->>'kind' = 'fqdn'
    AND lower(btrim(j.target_descriptor_json->>'value')) = lower(btrim(ov.declared_fqdn))
  FOR KEY SHARE OF j, ov;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ownership challenge job must reciprocally match its exact verification'
      USING ERRCODE = '23514',
            CONSTRAINT = 'probe_jobs_ownership_challenge_binding';
  END IF;
  RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER ownership_verifications_reciprocal_probe_job
AFTER INSERT OR UPDATE
ON ownership_verifications
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION astranull_ownership_verifications_reciprocal_probe_job_trigger();

CREATE CONSTRAINT TRIGGER probe_jobs_reciprocal_ownership_verification
AFTER INSERT OR UPDATE
ON probe_jobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION astranull_probe_jobs_reciprocal_ownership_verification_trigger();

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE environments FORCE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE user_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE user_password_invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_password_invites FORCE ROW LEVEL SECURITY;
ALTER TABLE user_password_resets ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_password_resets FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_accounts FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_subscriptions FORCE ROW LEVEL SECURITY;
ALTER TABLE entitlement_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE internal_approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE internal_approval_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE internal_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE internal_audit_log FORCE ROW LEVEL SECURITY;
ALTER TABLE target_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE target_groups FORCE ROW LEVEL SECURITY;
ALTER TABLE targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE targets FORCE ROW LEVEL SECURITY;
ALTER TABLE dns_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE dns_challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE target_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE target_verifications FORCE ROW LEVEL SECURITY;
ALTER TABLE target_edge_detections ENABLE ROW LEVEL SECURITY;
ALTER TABLE target_edge_detections FORCE ROW LEVEL SECURITY;
ALTER TABLE bootstrap_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE bootstrap_tokens FORCE ROW LEVEL SECURITY;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents FORCE ROW LEVEL SECURITY;
ALTER TABLE test_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE test_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE probe_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE probe_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE ownership_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE ownership_verifications FORCE ROW LEVEL SECURITY;
ALTER TABLE test_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE test_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE test_policy_dispatches ENABLE ROW LEVEL SECURITY;
ALTER TABLE test_policy_dispatches FORCE ROW LEVEL SECURITY;
ALTER TABLE validation_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE validation_scans FORCE ROW LEVEL SECURITY;
ALTER TABLE validation_scan_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE validation_scan_steps FORCE ROW LEVEL SECURITY;
ALTER TABLE loa_signatures ENABLE ROW LEVEL SECURITY;
ALTER TABLE loa_signatures FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE events FORCE ROW LEVEL SECURITY;
ALTER TABLE verdicts ENABLE ROW LEVEL SECURITY;
ALTER TABLE verdicts FORCE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
ALTER TABLE evidence_vault ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_vault FORCE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports FORCE ROW LEVEL SECURITY;
ALTER TABLE high_scale_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE high_scale_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE authorization_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorization_artifacts FORCE ROW LEVEL SECURITY;
ALTER TABLE soc_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE soc_notes FORCE ROW LEVEL SECURITY;
ALTER TABLE soc_kill_switch ENABLE ROW LEVEL SECURITY;
ALTER TABLE soc_kill_switch FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_rules FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_events FORCE ROW LEVEL SECURITY;
ALTER TABLE service_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_accounts FORCE ROW LEVEL SECURITY;
ALTER TABLE encrypted_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE encrypted_secrets FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_update_trust_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_update_trust_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_update_releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_update_releases FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_update_statuses ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_update_statuses FORCE ROW LEVEL SECURITY;
ALTER TABLE high_scale_telemetry ENABLE ROW LEVEL SECURITY;
ALTER TABLE high_scale_telemetry FORCE ROW LEVEL SECURITY;
ALTER TABLE soc_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE soc_reports FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_delivery_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_delivery_attempts FORCE ROW LEVEL SECURITY;
ALTER TABLE production_release_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE production_release_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;
ALTER TABLE external_asset_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_asset_candidates FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_assets FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_fingerprints FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_validation_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_validation_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_scenario_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_scenario_results FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_posture_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_posture_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_baselines FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_exceptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_exceptions FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_validation_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_validation_plans FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_baseline_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_baseline_approvals FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_retest_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_retest_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_drift_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_drift_events FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_drift_scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_drift_scan_results FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_connectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_connectors FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_connector_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_connector_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant_connector_features ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_connector_features FORCE ROW LEVEL SECURITY;
ALTER TABLE connector_provider_rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_provider_rate_limits FORCE ROW LEVEL SECURITY;
ALTER TABLE connector_poll_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_poll_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE cve_pipeline_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE cve_pipeline_items FORCE ROW LEVEL SECURITY;
ALTER TABLE cve_asset_matches ENABLE ROW LEVEL SECURITY;
ALTER TABLE cve_asset_matches FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_rule_recommendations ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_rule_recommendations FORCE ROW LEVEL SECURITY;
ALTER TABLE discovery_entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_entities FORCE ROW LEVEL SECURITY;
ALTER TABLE supply_chain_risks ENABLE ROW LEVEL SECURITY;
ALTER TABLE supply_chain_risks FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_action_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_action_items FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_coverage_daily_rollups ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_coverage_daily_rollups FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_tenants ON tenants
  USING (id = current_setting('app.tenant_id', true))
  WITH CHECK (id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_environments ON environments
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_users ON users
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY user_credentials_tenant_isolation ON user_credentials
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY user_password_invites_tenant_isolation ON user_password_invites
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY user_password_invites_token_lookup ON user_password_invites
  FOR SELECT
  USING (
    coalesce(current_setting('app.tenant_id', true), '') = ''
    AND token_hash = current_setting('app.password_invite_token_hash', true)
  );
CREATE POLICY user_password_resets_tenant_isolation ON user_password_resets
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY user_password_resets_token_lookup ON user_password_resets
  FOR SELECT
  USING (
    coalesce(current_setting('app.tenant_id', true), '') = ''
    AND token_hash = current_setting('app.password_reset_token_hash', true)
  );
CREATE POLICY tenant_isolation_target_groups ON target_groups
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_targets ON targets
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY dns_challenges_tenant_isolation ON dns_challenges
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY target_verifications_tenant_isolation ON target_verifications
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_target_edge_detections ON target_edge_detections
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_bootstrap_tokens ON bootstrap_tokens
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_agents ON agents
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_test_runs ON test_runs
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_probe_jobs ON probe_jobs
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_ownership_verifications ON ownership_verifications
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_test_policies ON test_policies
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_test_policy_dispatches ON test_policy_dispatches
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY validation_scans_tenant_isolation ON validation_scans
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY validation_scan_steps_tenant_isolation ON validation_scan_steps
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY loa_signatures_tenant_isolation ON loa_signatures
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_agent_jobs ON agent_jobs
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_events ON events
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_verdicts ON verdicts
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_findings ON findings
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_evidence_vault ON evidence_vault
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_reports ON reports
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_high_scale_requests ON high_scale_requests
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_authorization_artifacts ON authorization_artifacts
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_soc_notes ON soc_notes
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_soc_kill_switch ON soc_kill_switch
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_notification_rules ON notification_rules
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_notification_events ON notification_events
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_service_accounts ON service_accounts
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_encrypted_secrets ON encrypted_secrets
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_agent_update_trust_keys ON agent_update_trust_keys
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_agent_update_releases ON agent_update_releases
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_agent_update_statuses ON agent_update_statuses
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_high_scale_telemetry ON high_scale_telemetry
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_soc_reports ON soc_reports
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_notification_delivery_attempts ON notification_delivery_attempts
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_production_release_evidence ON production_release_evidence
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_audit_logs ON audit_logs
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_external_asset_candidates ON external_asset_candidates
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_assets ON waf_assets
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_fingerprints ON waf_fingerprints
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_validation_runs ON waf_validation_runs
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_scenario_results ON waf_scenario_results
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_posture_snapshots ON waf_posture_snapshots
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_baselines ON waf_baselines
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_exceptions ON waf_exceptions
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_validation_plans ON waf_validation_plans
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_baseline_approvals ON waf_baseline_approvals
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_retest_requests ON waf_retest_requests
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_drift_events ON waf_drift_events
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_drift_scan_results ON waf_drift_scan_results
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_connectors ON waf_connectors
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_connector_snapshots ON waf_connector_snapshots
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_tenant_connector_features ON tenant_connector_features
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_connector_provider_rate_limits ON connector_provider_rate_limits
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_connector_poll_jobs ON connector_poll_jobs
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_cve_pipeline_items ON cve_pipeline_items
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_cve_asset_matches ON cve_asset_matches
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_rule_recommendations ON waf_rule_recommendations
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_discovery_entities ON discovery_entities
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_supply_chain_risks ON supply_chain_risks
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_action_items ON waf_action_items
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_coverage_daily_rollups ON waf_coverage_daily_rollups
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
ALTER TABLE waf_scenario_intakes ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_scenario_intakes FORCE ROW LEVEL SECURITY;
CREATE INDEX idx_waf_scenario_intakes_tenant_created ON waf_scenario_intakes(tenant_id, created_at DESC);
CREATE POLICY tenant_isolation_waf_scenario_intakes ON waf_scenario_intakes
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- Internal management tenant isolation (parity with db/migrations/0021_internal_management.sql).
-- internal_approval_requests / internal_audit_log allow tenant_id IS NULL for platform-level
-- (pre-tenant) records.
CREATE POLICY tenant_accounts_isolation ON tenant_accounts
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_subscriptions_isolation ON tenant_subscriptions
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY entitlement_grants_isolation ON entitlement_grants
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY internal_approval_requests_isolation ON internal_approval_requests
  USING (tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY internal_audit_log_isolation ON internal_audit_log
  USING (tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true));

-- Staff-console platform scope (parity with db/migrations/0038_platform_scope_internal_reads.sql).
-- Additive SELECT-only permissive policies OR-ed with the tenant_isolation_* policies above.
-- Requires the transaction-local app.platform_scope marker AND an unset app.tenant_id, so a
-- tenant-scoped connection can never acquire platform scope and writes stay tenant-governed.
CREATE POLICY platform_scope_read_tenants ON tenants
  FOR SELECT
  USING (
    coalesce(current_setting('app.platform_scope', true) = 'on', false)
    AND coalesce(current_setting('app.tenant_id', true), '') = ''
  );
CREATE POLICY platform_scope_read_users ON users
  FOR SELECT
  USING (
    coalesce(current_setting('app.platform_scope', true) = 'on', false)
    AND coalesce(current_setting('app.tenant_id', true), '') = ''
  );
CREATE POLICY platform_scope_read_tenant_accounts ON tenant_accounts
  FOR SELECT
  USING (
    coalesce(current_setting('app.platform_scope', true) = 'on', false)
    AND coalesce(current_setting('app.tenant_id', true), '') = ''
  );
CREATE POLICY platform_scope_read_tenant_subscriptions ON tenant_subscriptions
  FOR SELECT
  USING (
    coalesce(current_setting('app.platform_scope', true) = 'on', false)
    AND coalesce(current_setting('app.tenant_id', true), '') = ''
  );
CREATE POLICY platform_scope_read_internal_approval_requests ON internal_approval_requests
  FOR SELECT
  USING (
    coalesce(current_setting('app.platform_scope', true) = 'on', false)
    AND coalesce(current_setting('app.tenant_id', true), '') = ''
  );
CREATE POLICY platform_scope_read_internal_audit_log ON internal_audit_log
  FOR SELECT
  USING (
    coalesce(current_setting('app.platform_scope', true) = 'on', false)
    AND coalesce(current_setting('app.tenant_id', true), '') = ''
  );
-- Staff SOC cross-tenant high-scale queue (parity with db/migrations/0056_platform_scope_soc_high_scale_reads.sql).
CREATE POLICY platform_scope_read_high_scale_requests ON high_scale_requests
  FOR SELECT
  USING (
    coalesce(current_setting('app.platform_scope', true) = 'on', false)
    AND coalesce(current_setting('app.tenant_id', true), '') = ''
  );

-- Contract for 0057_waf_offensive_workflow.sql. Executed DDL remains in db/migrations/.
CREATE TABLE waf_offensive_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_asset_id TEXT NOT NULL,
  target_group_id TEXT NOT NULL,
  objective TEXT NOT NULL,
  requested_suites JSONB NOT NULL DEFAULT '[]'::jsonb,
  emergency_contacts JSONB NOT NULL DEFAULT '[]'::jsonb,
  requested_window JSONB,
  stop_criteria TEXT,
  abort_criteria TEXT,
  staging_only BOOLEAN NOT NULL DEFAULT TRUE,
  scope_confirmation BOOLEAN NOT NULL DEFAULT TRUE,
  state TEXT NOT NULL DEFAULT 'submitted',
  created_by TEXT,
  soc_approvals JSONB NOT NULL DEFAULT '[]'::jsonb,
  artifacts JSONB NOT NULL DEFAULT '[]'::jsonb,
  suite_results JSONB NOT NULL DEFAULT '[]'::jsonb,
  authorization_pack_status JSONB NOT NULL DEFAULT '{}'::jsonb,
  scheduled_window JSONB,
  scope_hash TEXT,
  waf_validation_run_id TEXT,
  rejected_at TIMESTAMPTZ,
  rejected_by TEXT,
  rejection_reason TEXT,
  results_recorded_at TIMESTAMPTZ,
  results_recorded_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT waf_offensive_requests_state_check CHECK (
    state IN ('submitted', 'under_review', 'approved', 'scheduled', 'running', 'stopped', 'closed', 'rejected')
  )
);

CREATE TABLE waf_offensive_reports (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_offensive_request_id TEXT NOT NULL,
  executive_summary TEXT,
  blocking_verdict TEXT,
  bypass_findings JSONB NOT NULL DEFAULT '[]'::jsonb,
  remediation_notes TEXT,
  suite_results JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_by TEXT,
  updated_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uniq_waf_offensive_report_per_request
    UNIQUE (tenant_id, waf_offensive_request_id)
);

ALTER TABLE waf_offensive_requests
  ADD CONSTRAINT waf_offensive_requests_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_offensive_reports
  ADD CONSTRAINT waf_offensive_reports_tenant_id_id_key UNIQUE (tenant_id, id);

ALTER TABLE waf_validation_runs
  ADD COLUMN execution_class TEXT NOT NULL DEFAULT 'safe',
  ADD COLUMN offensive_request_id TEXT;

ALTER TABLE waf_offensive_requests ADD CONSTRAINT fk_waf_offensive_requests_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_offensive_requests ADD CONSTRAINT fk_waf_offensive_requests_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE waf_offensive_requests ADD CONSTRAINT fk_waf_offensive_requests_validation_run_tenant
  FOREIGN KEY (tenant_id, waf_validation_run_id) REFERENCES waf_validation_runs (tenant_id, id);
ALTER TABLE waf_validation_runs ADD CONSTRAINT fk_waf_validation_runs_offensive_request_tenant
  FOREIGN KEY (tenant_id, offensive_request_id) REFERENCES waf_offensive_requests (tenant_id, id);
ALTER TABLE waf_offensive_reports ADD CONSTRAINT fk_waf_offensive_reports_request_tenant
  FOREIGN KEY (tenant_id, waf_offensive_request_id) REFERENCES waf_offensive_requests (tenant_id, id);

CREATE INDEX idx_waf_offensive_requests_tenant_state_created
  ON waf_offensive_requests (tenant_id, state, created_at DESC);
CREATE UNIQUE INDEX uniq_waf_validation_run_offensive_request
  ON waf_validation_runs (tenant_id, offensive_request_id)
  WHERE offensive_request_id IS NOT NULL;

ALTER TABLE waf_offensive_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_offensive_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY waf_offensive_requests_tenant_isolation ON waf_offensive_requests
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE waf_offensive_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_offensive_reports FORCE ROW LEVEL SECURITY;
CREATE POLICY waf_offensive_reports_tenant_isolation ON waf_offensive_reports
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- Additive sync of db/migrations/0064_target_observations_origins_lineage.sql.
-- Fresh installs create these tables here; existing databases use migration 0064.
-- Target observations are immutable, tenant-RLS retained history plus monotonic
-- current pointers. Origin bindings join declared same-tenant targets only.
-- Retest lineage is explicit and immutable. No history backfill and no closure.

CREATE OR REPLACE FUNCTION astranull_observation_order_before(
  left_observed TIMESTAMPTZ,
  left_completed TIMESTAMPTZ,
  left_id TEXT,
  right_observed TIMESTAMPTZ,
  right_completed TIMESTAMPTZ,
  right_id TEXT
) RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT (
    left_observed,
    COALESCE(left_completed, '-infinity'::timestamptz),
    left_id COLLATE "C"
  ) < (
    right_observed,
    COALESCE(right_completed, '-infinity'::timestamptz),
    right_id COLLATE "C"
  );
$$;

CREATE TABLE target_observations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_id TEXT NOT NULL,
  target_group_id TEXT NOT NULL,
  family TEXT NOT NULL,
  check_id TEXT NOT NULL,
  test_run_id TEXT,
  source_kind TEXT NOT NULL,
  source_id TEXT,
  corpus_version TEXT,
  scenario_version TEXT,
  check_version TEXT,
  observed_at TIMESTAMPTZ NOT NULL,
  source_completed_at TIMESTAMPTZ,
  outcome TEXT NOT NULL,
  attempt_class TEXT NOT NULL,
  producer_kind TEXT,
  provenance_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  origin_binding_id TEXT,
  nonce TEXT,
  event_id TEXT,
  digest TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT target_observations_family_check
    CHECK (family IN ('waf', 'cdn', 'cloud', 'dns', 'origin_hosting', 'maintenance')),
  CONSTRAINT target_observations_attempt_check
    CHECK (attempt_class IN ('successful', 'failed_attempt', 'retained_noncurrent')),
  CONSTRAINT target_observations_source_check
    CHECK (source_kind IN ('edge_detection', 'validation_run', 'explicit_record')),
  CONSTRAINT target_observations_producer_check
    CHECK (producer_kind IS NULL OR producer_kind IN (
      'live_external', 'signed_probe', 'internal_simulation', 'customer_declaration', 'manual'
    )),
  CONSTRAINT target_observations_provenance_object
    CHECK (jsonb_typeof(provenance_json) = 'object'),
  CONSTRAINT target_observations_tenant_id_id_key UNIQUE (tenant_id, id)
);

CREATE UNIQUE INDEX uniq_target_observations_nonce
  ON target_observations (tenant_id, nonce) WHERE nonce IS NOT NULL;
CREATE UNIQUE INDEX uniq_target_observations_event
  ON target_observations (tenant_id, event_id) WHERE event_id IS NOT NULL;
CREATE UNIQUE INDEX uniq_target_observations_digest
  ON target_observations (tenant_id, digest);
CREATE INDEX idx_target_observations_history
  ON target_observations (tenant_id, target_id, family, observed_at DESC, id DESC);

ALTER TABLE target_observations
  ADD CONSTRAINT fk_target_observations_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE target_observations
  ADD CONSTRAINT fk_target_observations_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE target_observations
  ADD CONSTRAINT fk_target_observations_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);

CREATE TABLE target_observation_current (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_id TEXT NOT NULL,
  family TEXT NOT NULL,
  successful_observation_id TEXT,
  successful_observed_at TIMESTAMPTZ,
  successful_source_completed_at TIMESTAMPTZ,
  failed_attempt_observation_id TEXT,
  failed_observed_at TIMESTAMPTZ,
  failed_source_completed_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, target_id, family)
);

ALTER TABLE target_observation_current
  ADD CONSTRAINT fk_target_observation_current_success
  FOREIGN KEY (tenant_id, successful_observation_id)
  REFERENCES target_observations (tenant_id, id);
ALTER TABLE target_observation_current
  ADD CONSTRAINT fk_target_observation_current_failed
  FOREIGN KEY (tenant_id, failed_attempt_observation_id)
  REFERENCES target_observations (tenant_id, id);

CREATE TABLE origin_bindings (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  protected_target_id TEXT NOT NULL,
  protected_target_group_id TEXT NOT NULL,
  origin_target_id TEXT NOT NULL,
  origin_target_group_id TEXT NOT NULL,
  host TEXT NOT NULL,
  sni TEXT NOT NULL,
  port INT,
  path TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  assurance TEXT NOT NULL DEFAULT 'none',
  lockdown TEXT NOT NULL DEFAULT 'not_tested',
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  archived_at TIMESTAMPTZ,
  archived_by TEXT,
  CONSTRAINT origin_bindings_status_check CHECK (status IN ('active', 'archived')),
  CONSTRAINT origin_bindings_distinct_targets CHECK (protected_target_id <> origin_target_id),
  CONSTRAINT origin_bindings_port_check CHECK (port IS NULL OR (port >= 1 AND port <= 65535)),
  CONSTRAINT origin_bindings_assurance_check CHECK (assurance = 'none'),
  CONSTRAINT origin_bindings_lockdown_check CHECK (lockdown = 'not_tested'),
  CONSTRAINT origin_bindings_tenant_id_id_key UNIQUE (tenant_id, id)
);

CREATE UNIQUE INDEX uniq_origin_binding_active_pair
  ON origin_bindings (tenant_id, protected_target_id, origin_target_id)
  WHERE status = 'active';

ALTER TABLE origin_bindings
  ADD CONSTRAINT fk_origin_bindings_protected_target
  FOREIGN KEY (tenant_id, protected_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE origin_bindings
  ADD CONSTRAINT fk_origin_bindings_origin_target
  FOREIGN KEY (tenant_id, origin_target_id) REFERENCES targets (tenant_id, id);

ALTER TABLE target_observations
  ADD CONSTRAINT fk_target_observations_origin_binding
  FOREIGN KEY (tenant_id, origin_binding_id) REFERENCES origin_bindings (tenant_id, id);

CREATE TABLE finding_retest_lineage (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  finding_id TEXT NOT NULL,
  test_run_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  check_id TEXT NOT NULL,
  intent TEXT NOT NULL,
  relation TEXT NOT NULL DEFAULT 'retest',
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT finding_retest_lineage_intent_check CHECK (intent = 'retest'),
  CONSTRAINT finding_retest_lineage_relation_check CHECK (relation = 'retest'),
  CONSTRAINT finding_retest_lineage_tenant_id_id_key UNIQUE (tenant_id, id)
);

CREATE UNIQUE INDEX uniq_finding_retest_lineage_pair
  ON finding_retest_lineage (tenant_id, finding_id, test_run_id);

ALTER TABLE finding_retest_lineage
  ADD CONSTRAINT fk_finding_retest_lineage_finding
  FOREIGN KEY (tenant_id, finding_id) REFERENCES findings (tenant_id, id);
ALTER TABLE finding_retest_lineage
  ADD CONSTRAINT fk_finding_retest_lineage_run
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE finding_retest_lineage
  ADD CONSTRAINT fk_finding_retest_lineage_target
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'test_runs_producer_kind_check'
  ) THEN
    ALTER TABLE test_runs
      ADD CONSTRAINT test_runs_producer_kind_check
      CHECK (producer_kind IS NULL OR producer_kind IN (
        'live_external', 'signed_probe', 'internal_simulation', 'customer_declaration', 'manual'
      ));
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_test_runs_origin_binding'
  ) THEN
    ALTER TABLE test_runs
      ADD CONSTRAINT fk_test_runs_origin_binding
      FOREIGN KEY (tenant_id, origin_binding_id) REFERENCES origin_bindings (tenant_id, id);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_test_runs_retest_finding'
  ) THEN
    ALTER TABLE test_runs
      ADD CONSTRAINT fk_test_runs_retest_finding
      FOREIGN KEY (tenant_id, retest_of_finding_id) REFERENCES findings (tenant_id, id);
  END IF;
END
$$;

ALTER TABLE test_runs
  ADD COLUMN IF NOT EXISTS check_version TEXT,
  ADD COLUMN IF NOT EXISTS scenario_version TEXT,
  ADD COLUMN IF NOT EXISTS producer_kind TEXT,
  ADD COLUMN IF NOT EXISTS origin_binding_id TEXT,
  ADD COLUMN IF NOT EXISTS retest_of_finding_id TEXT,
  ADD COLUMN IF NOT EXISTS expected_behavior_json JSONB,
  ADD COLUMN IF NOT EXISTS provenance_json JSONB;

ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ;

CREATE OR REPLACE FUNCTION astranull_reject_observation_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'target_observations are immutable';
END;
$$;

CREATE TRIGGER target_observations_immutable
  BEFORE UPDATE OR DELETE ON target_observations
  FOR EACH ROW EXECUTE FUNCTION astranull_reject_observation_mutation();

CREATE OR REPLACE FUNCTION astranull_origin_binding_scope_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.protected_target_id IS DISTINCT FROM OLD.protected_target_id
     OR NEW.origin_target_id IS DISTINCT FROM OLD.origin_target_id
     OR NEW.host IS DISTINCT FROM OLD.host
     OR NEW.sni IS DISTINCT FROM OLD.sni
     OR NEW.port IS DISTINCT FROM OLD.port
     OR NEW.path IS DISTINCT FROM OLD.path
     OR NEW.assurance IS DISTINCT FROM OLD.assurance
     OR NEW.lockdown IS DISTINCT FROM OLD.lockdown
  THEN
    RAISE EXCEPTION 'origin binding scope is immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER origin_bindings_scope_immutable
  BEFORE UPDATE ON origin_bindings
  FOR EACH ROW EXECUTE FUNCTION astranull_origin_binding_scope_immutable();

CREATE OR REPLACE FUNCTION astranull_reject_lineage_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'finding_retest_lineage is immutable';
END;
$$;

CREATE TRIGGER finding_retest_lineage_immutable
  BEFORE UPDATE OR DELETE ON finding_retest_lineage
  FOR EACH ROW EXECUTE FUNCTION astranull_reject_lineage_mutation();

ALTER TABLE target_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE target_observations FORCE ROW LEVEL SECURITY;
ALTER TABLE target_observation_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE target_observation_current FORCE ROW LEVEL SECURITY;
ALTER TABLE origin_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE origin_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE finding_retest_lineage ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_retest_lineage FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_target_observations ON target_observations
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_target_observation_current ON target_observation_current
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_origin_bindings ON origin_bindings
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_finding_retest_lineage ON finding_retest_lineage
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

COMMENT ON TABLE target_observations IS
  'Immutable accepted target-layer observations. Safe provenance only; no raw headers, cookies, or bodies.';
COMMENT ON TABLE target_observation_current IS
  'Monotonic current successful observation and separate latest failed attempt. Not a history backfill.';
COMMENT ON TABLE origin_bindings IS
  'Declared same-tenant protected hostname to independently verified origin target. Not lockdown or capacity.';
COMMENT ON COLUMN findings.closed_at IS
  'Set only when an authorized lifecycle closure is applied to this finding. Lineage does not set it and does not close siblings.';
COMMENT ON COLUMN test_runs.check_version IS
  'Server-derived catalog version or canonical digest. A request body cannot set it. Null on rows started before the writer.';
COMMENT ON COLUMN test_runs.expected_behavior_json IS
  'Catalog default_expected_behavior captured at run start. Not a later lookup of the target declaration.';
COMMENT ON COLUMN test_runs.provenance_json IS
  'Safe derivation record for the run stamp. No credentials, headers, or raw bodies.';

-- target_edge_detections has observed_at but no source_completed_at. Order the
-- current edge row by (observed_at, test_run_id). A null observed_at is a legacy
-- unstamped row and may still be overwritten. Upgrade path: add
-- source_completed_at and use the full observation order.
CREATE OR REPLACE FUNCTION astranull_edge_detection_monotonic()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.observed_at IS NULL THEN
    RETURN NEW;
  END IF;
  IF NEW.observed_at IS NULL THEN
    RETURN OLD;
  END IF;
  IF astranull_observation_order_before(
    OLD.observed_at, NULL, COALESCE(OLD.test_run_id, ''),
    NEW.observed_at, NULL, COALESCE(NEW.test_run_id, '')
  ) THEN
    RETURN NEW;
  END IF;
  RETURN OLD;
END;
$$;

CREATE TRIGGER astranull_edge_detection_monotonic
  BEFORE UPDATE ON target_edge_detections
  FOR EACH ROW EXECUTE FUNCTION astranull_edge_detection_monotonic();

-- Additive sync of db/migrations/0068_protection_validation.sql.
-- Fresh installs create these tables here; existing databases use migration 0068.
-- Entry paths and expectations are archive-only versioned declarations; baselines
-- allow a one-way archive; evaluations and evidence references are immutable.

CREATE TABLE application_entry_paths (
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
  ADD CONSTRAINT application_entry_paths_tenant_id_id_key UNIQUE (tenant_id, id);
CREATE UNIQUE INDEX uniq_application_entry_paths_idempotency
  ON application_entry_paths (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX uniq_application_entry_paths_active_scope
  ON application_entry_paths (
    tenant_id, anchor_target_id, entry_target_id, relation_kind, COALESCE(origin_binding_id, '')
  )
  WHERE status = 'active';
CREATE UNIQUE INDEX uniq_application_entry_paths_scope_version
  ON application_entry_paths (
    tenant_id, anchor_target_id, entry_target_id, relation_kind, COALESCE(origin_binding_id, ''),
    declaration_version
  );
CREATE INDEX idx_application_entry_paths_anchor
  ON application_entry_paths (tenant_id, anchor_target_id, created_at DESC, id DESC);
CREATE INDEX idx_application_entry_paths_entry_target
  ON application_entry_paths (tenant_id, entry_target_id);

ALTER TABLE application_entry_paths
  ADD CONSTRAINT fk_application_entry_paths_anchor_target_tenant
  FOREIGN KEY (tenant_id, anchor_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE application_entry_paths
  ADD CONSTRAINT fk_application_entry_paths_entry_target_tenant
  FOREIGN KEY (tenant_id, entry_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE application_entry_paths
  ADD CONSTRAINT fk_application_entry_paths_origin_binding_tenant
  FOREIGN KEY (tenant_id, origin_binding_id) REFERENCES origin_bindings (tenant_id, id);

CREATE TABLE protection_expectations (
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
  ADD CONSTRAINT protection_expectations_tenant_id_id_key UNIQUE (tenant_id, id);
CREATE UNIQUE INDEX uniq_protection_expectations_scope_version
  ON protection_expectations (tenant_id, kind, scope_key, expectation_version);
CREATE UNIQUE INDEX uniq_protection_expectations_active_scope
  ON protection_expectations (tenant_id, kind, scope_key) WHERE status = 'active';
CREATE UNIQUE INDEX uniq_protection_expectations_idempotency
  ON protection_expectations (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX idx_protection_expectations_list
  ON protection_expectations (tenant_id, kind, created_at DESC, id DESC);
CREATE INDEX idx_protection_expectations_destination
  ON protection_expectations (tenant_id, destination_target_id) WHERE destination_target_id IS NOT NULL;
CREATE INDEX idx_protection_expectations_anchor
  ON protection_expectations (tenant_id, anchor_target_id) WHERE anchor_target_id IS NOT NULL;

ALTER TABLE protection_expectations
  ADD CONSTRAINT fk_protection_expectations_anchor_target_tenant
  FOREIGN KEY (tenant_id, anchor_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE protection_expectations
  ADD CONSTRAINT fk_protection_expectations_destination_target_tenant
  FOREIGN KEY (tenant_id, destination_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE protection_expectations
  ADD CONSTRAINT fk_protection_expectations_pre_destination_tenant
  FOREIGN KEY (tenant_id, pre_destination_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE protection_expectations
  ADD CONSTRAINT fk_protection_expectations_post_destination_tenant
  FOREIGN KEY (tenant_id, post_destination_target_id) REFERENCES targets (tenant_id, id);

CREATE TABLE protection_comparison_baselines (
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
  ADD CONSTRAINT protection_comparison_baselines_tenant_id_id_key UNIQUE (tenant_id, id);
CREATE UNIQUE INDEX uniq_protection_comparison_baselines_digest
  ON protection_comparison_baselines (tenant_id, baseline_digest);
CREATE UNIQUE INDEX uniq_protection_comparison_baselines_idempotency
  ON protection_comparison_baselines (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX idx_protection_comparison_baselines_list
  ON protection_comparison_baselines (tenant_id, kind, created_at DESC, id DESC);
CREATE INDEX idx_protection_comparison_baselines_expectation
  ON protection_comparison_baselines (tenant_id, expectation_id, created_at DESC, id DESC);
CREATE INDEX idx_protection_comparison_baselines_target
  ON protection_comparison_baselines (tenant_id, target_id, created_at DESC, id DESC);

ALTER TABLE protection_comparison_baselines
  ADD CONSTRAINT fk_protection_comparison_baselines_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE protection_comparison_baselines
  ADD CONSTRAINT fk_protection_comparison_baselines_anchor_target_tenant
  FOREIGN KEY (tenant_id, anchor_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE protection_comparison_baselines
  ADD CONSTRAINT fk_protection_comparison_baselines_entry_path_tenant
  FOREIGN KEY (tenant_id, entry_path_id) REFERENCES application_entry_paths (tenant_id, id);
ALTER TABLE protection_comparison_baselines
  ADD CONSTRAINT fk_protection_comparison_baselines_expectation_tenant
  FOREIGN KEY (tenant_id, expectation_id) REFERENCES protection_expectations (tenant_id, id);
ALTER TABLE protection_comparison_baselines
  ADD CONSTRAINT fk_protection_comparison_baselines_pre_destination_tenant
  FOREIGN KEY (tenant_id, pre_destination_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE protection_comparison_baselines
  ADD CONSTRAINT fk_protection_comparison_baselines_post_destination_tenant
  FOREIGN KEY (tenant_id, post_destination_target_id) REFERENCES targets (tenant_id, id);

CREATE TABLE protection_comparison_evaluations (
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
  ADD CONSTRAINT protection_comparison_evaluations_tenant_id_id_key UNIQUE (tenant_id, id);
CREATE UNIQUE INDEX uniq_protection_comparison_evaluations_digest
  ON protection_comparison_evaluations (tenant_id, evaluation_digest);
CREATE UNIQUE INDEX uniq_protection_comparison_evaluations_idempotency
  ON protection_comparison_evaluations (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX idx_protection_comparison_evaluations_list
  ON protection_comparison_evaluations (tenant_id, kind, created_at DESC, id DESC);
CREATE INDEX idx_protection_comparison_evaluations_baseline
  ON protection_comparison_evaluations (tenant_id, baseline_id, created_at DESC, id DESC)
  WHERE baseline_id IS NOT NULL;
CREATE INDEX idx_protection_comparison_evaluations_anchor
  ON protection_comparison_evaluations (tenant_id, anchor_target_id, created_at DESC, id DESC)
  WHERE anchor_target_id IS NOT NULL;

ALTER TABLE protection_comparison_evaluations
  ADD CONSTRAINT fk_protection_comparison_evaluations_baseline_tenant
  FOREIGN KEY (tenant_id, baseline_id) REFERENCES protection_comparison_baselines (tenant_id, id);
ALTER TABLE protection_comparison_evaluations
  ADD CONSTRAINT fk_protection_comparison_evaluations_anchor_target_tenant
  FOREIGN KEY (tenant_id, anchor_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE protection_comparison_evaluations
  ADD CONSTRAINT fk_protection_comparison_evaluations_primary_entry_path_tenant
  FOREIGN KEY (tenant_id, primary_entry_path_id) REFERENCES application_entry_paths (tenant_id, id);

CREATE TABLE protection_comparison_evidence_refs (
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
  ADD CONSTRAINT protection_comparison_evidence_refs_tenant_id_id_key UNIQUE (tenant_id, id);
CREATE UNIQUE INDEX uniq_protection_comparison_evidence_refs_baseline
  ON protection_comparison_evidence_refs (tenant_id, baseline_id, ordinal)
  WHERE baseline_id IS NOT NULL;
CREATE UNIQUE INDEX uniq_protection_comparison_evidence_refs_evaluation
  ON protection_comparison_evidence_refs (tenant_id, evaluation_id, item_index, ordinal)
  WHERE evaluation_id IS NOT NULL;
CREATE INDEX idx_protection_comparison_evidence_refs_run
  ON protection_comparison_evidence_refs (tenant_id, test_run_id);

ALTER TABLE protection_comparison_evidence_refs
  ADD CONSTRAINT fk_protection_comparison_evidence_refs_baseline_tenant
  FOREIGN KEY (tenant_id, baseline_id) REFERENCES protection_comparison_baselines (tenant_id, id);
ALTER TABLE protection_comparison_evidence_refs
  ADD CONSTRAINT fk_protection_comparison_evidence_refs_evaluation_tenant
  FOREIGN KEY (tenant_id, evaluation_id) REFERENCES protection_comparison_evaluations (tenant_id, id);
ALTER TABLE protection_comparison_evidence_refs
  ADD CONSTRAINT fk_protection_comparison_evidence_refs_expectation_tenant
  FOREIGN KEY (tenant_id, expectation_id) REFERENCES protection_expectations (tenant_id, id);
ALTER TABLE protection_comparison_evidence_refs
  ADD CONSTRAINT fk_protection_comparison_evidence_refs_entry_path_tenant
  FOREIGN KEY (tenant_id, entry_path_id) REFERENCES application_entry_paths (tenant_id, id);
ALTER TABLE protection_comparison_evidence_refs
  ADD CONSTRAINT fk_protection_comparison_evidence_refs_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE protection_comparison_evidence_refs
  ADD CONSTRAINT fk_protection_comparison_evidence_refs_verdict_tenant
  FOREIGN KEY (tenant_id, verdict_id) REFERENCES verdicts (tenant_id, id);
ALTER TABLE protection_comparison_evidence_refs
  ADD CONSTRAINT fk_protection_comparison_evidence_refs_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
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

CREATE TRIGGER application_entry_paths_archive_only
  BEFORE UPDATE OR DELETE ON application_entry_paths
  FOR EACH ROW EXECUTE FUNCTION astranull_protection_record_archive_only();
CREATE TRIGGER protection_expectations_archive_only
  BEFORE UPDATE OR DELETE ON protection_expectations
  FOR EACH ROW EXECUTE FUNCTION astranull_protection_record_archive_only();
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

CREATE TRIGGER protection_comparison_evaluations_immutable
  BEFORE UPDATE OR DELETE ON protection_comparison_evaluations
  FOR EACH ROW EXECUTE FUNCTION astranull_reject_protection_comparison_mutation();
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

CREATE POLICY tenant_isolation_application_entry_paths ON application_entry_paths
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_protection_expectations ON protection_expectations
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_protection_comparison_baselines ON protection_comparison_baselines
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_protection_comparison_evaluations ON protection_comparison_evaluations
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
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

-- Additive sync of db/migrations/0069_protection_findings.sql.
ALTER TABLE findings ADD COLUMN source TEXT;
ALTER TABLE findings ADD COLUMN dedupe_key TEXT;
ALTER TABLE findings ADD COLUMN finding_class TEXT;
ALTER TABLE findings ADD COLUMN priority TEXT;
ALTER TABLE findings ADD COLUMN protection_validation_json JSONB;

ALTER TABLE findings ADD CONSTRAINT findings_protection_validation_check CHECK (
  (source IS NULL OR source = 'protection_validation')
  AND (source IS NOT DISTINCT FROM 'protection_validation') = (dedupe_key IS NOT NULL)
  AND (dedupe_key IS NULL OR dedupe_key ~ '^pvf_[a-f0-9]{64}$')
  AND (finding_class IS NULL OR finding_class IN (
    'confirmed_exposure', 'observed_enforcement_gap', 'observed_availability_gap', 'suspected_bypass', 'unavailable_evidence'
  ))
  AND (priority IS NULL OR priority IN ('p1', 'p2', 'p3', 'p4'))
  AND (
    protection_validation_json IS NULL
    OR (jsonb_typeof(protection_validation_json) = 'object' AND octet_length(protection_validation_json::text) <= 65536)
  )
);

CREATE UNIQUE INDEX uniq_findings_open_protection_dedupe
  ON findings (tenant_id, dedupe_key)
  WHERE dedupe_key IS NOT NULL AND status IN ('open', 'in_progress');

ALTER TABLE finding_retest_lineage ADD COLUMN comparison_context_json JSONB;

ALTER TABLE finding_retest_lineage ADD CONSTRAINT finding_retest_lineage_comparison_context_check CHECK (
  comparison_context_json IS NULL
  OR (jsonb_typeof(comparison_context_json) = 'object' AND octet_length(comparison_context_json::text) <= 16384)
);

COMMENT ON COLUMN findings.protection_validation_json IS
  'PV-06 provenance for source = protection_validation: comparison context, evidence references, limitations. Never raw traffic.';
COMMENT ON COLUMN finding_retest_lineage.comparison_context_json IS
  'Comparison context and baseline versions retained for protection-validation retests after authorization was rechecked.';

-- Additive sync of db/migrations/0070_protection_baseline_capture_indexes.sql.
CREATE INDEX idx_protection_comparison_baselines_capture
  ON protection_comparison_baselines (tenant_id, (provenance_json->>'capture_id'));
CREATE INDEX idx_protection_comparison_baselines_capture_heads
  ON protection_comparison_baselines (tenant_id, kind, created_at DESC, id DESC)
  WHERE (provenance_json->>'capture_index') = '0';

-- Additive sync of db/migrations/0071_entry_path_comparison_lifecycle.sql.
CREATE TABLE entry_path_comparisons (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  anchor_target_id TEXT NOT NULL,
  primary_entry_path_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'running',
  reviewed_plan_digest TEXT NOT NULL,
  scope_digest TEXT NOT NULL,
  expectation_json JSONB NOT NULL,
  approved_scope_json JSONB NOT NULL,
  probe_mode TEXT NOT NULL,
  execution_ctx_json JSONB NOT NULL,
  idempotency_key TEXT,
  cancel_reason TEXT,
  evaluation_json JSONB,
  evaluation_id TEXT,
  lock_version INT NOT NULL DEFAULT 0,
  reconcile_seq BIGINT NOT NULL DEFAULT 0,
  reconciled_seq BIGINT NOT NULL DEFAULT 0,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  started_at TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT entry_path_comparisons_status_check
    CHECK (status IN ('running', 'completed', 'cancelled', 'failed')),
  CONSTRAINT entry_path_comparisons_digest_check
    CHECK (reviewed_plan_digest ~ '^[a-f0-9]{64}$' AND scope_digest ~ '^[a-f0-9]{64}$'),
  CONSTRAINT entry_path_comparisons_running_check
    CHECK (status <> 'running' OR (completed_at IS NULL AND evaluation_json IS NULL AND evaluation_id IS NULL)),
  CONSTRAINT entry_path_comparisons_terminal_check
    CHECK (status NOT IN ('completed', 'cancelled') OR (completed_at IS NOT NULL AND evaluation_json IS NOT NULL)),
  CONSTRAINT entry_path_comparisons_evaluation_link_check
    CHECK (evaluation_id IS NULL OR evaluation_json IS NOT NULL),
  CONSTRAINT entry_path_comparisons_json_bounds
    CHECK (
      jsonb_typeof(expectation_json) = 'object' AND octet_length(expectation_json::text) <= 16384
      AND jsonb_typeof(approved_scope_json) = 'object' AND octet_length(approved_scope_json::text) <= 262144
      AND jsonb_typeof(execution_ctx_json) = 'object' AND octet_length(execution_ctx_json::text) <= 2048
      AND (evaluation_json IS NULL OR (jsonb_typeof(evaluation_json) = 'object' AND octet_length(evaluation_json::text) <= 2097152))
    ),
  CONSTRAINT entry_path_comparisons_text_bounds
    CHECK (
      char_length(probe_mode) BETWEEN 1 AND 32
      AND (idempotency_key IS NULL OR char_length(idempotency_key) BETWEEN 1 AND 200)
      AND (cancel_reason IS NULL OR char_length(cancel_reason) BETWEEN 1 AND 200)
    ),
  CONSTRAINT entry_path_comparisons_sequence_check
    CHECK (lock_version >= 0 AND reconcile_seq >= 0 AND reconciled_seq >= 0)
);

ALTER TABLE entry_path_comparisons
  ADD CONSTRAINT entry_path_comparisons_tenant_id_id_key UNIQUE (tenant_id, id);
CREATE UNIQUE INDEX uniq_entry_path_comparisons_idempotency
  ON entry_path_comparisons (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX uniq_entry_path_comparisons_running_plan
  ON entry_path_comparisons (tenant_id, reviewed_plan_digest) WHERE status = 'running';
CREATE INDEX idx_entry_path_comparisons_list
  ON entry_path_comparisons (tenant_id, created_at DESC, id DESC);
CREATE INDEX idx_entry_path_comparisons_anchor
  ON entry_path_comparisons (tenant_id, anchor_target_id, created_at DESC, id DESC);
CREATE INDEX idx_entry_path_comparisons_running
  ON entry_path_comparisons (tenant_id, created_at, id) WHERE status = 'running';
CREATE INDEX idx_entry_path_comparisons_unlinked
  ON entry_path_comparisons (tenant_id, completed_at)
  WHERE evaluation_json IS NOT NULL AND evaluation_id IS NULL;

ALTER TABLE entry_path_comparisons
  ADD CONSTRAINT fk_entry_path_comparisons_anchor_target_tenant
  FOREIGN KEY (tenant_id, anchor_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE entry_path_comparisons
  ADD CONSTRAINT fk_entry_path_comparisons_evaluation_tenant
  FOREIGN KEY (tenant_id, evaluation_id) REFERENCES protection_comparison_evaluations (tenant_id, id);

-- entry_path_id is not a foreign key: a reviewed plan may list ids that are unknown and recorded as skipped.
CREATE TABLE entry_path_comparison_items (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  comparison_id TEXT NOT NULL,
  entry_path_id TEXT NOT NULL,
  ordinal INT NOT NULL,
  is_primary BOOLEAN NOT NULL DEFAULT FALSE,
  eligible BOOLEAN NOT NULL,
  target_id TEXT,
  target_group_id TEXT,
  check_id TEXT,
  origin_binding_id TEXT,
  target_scope_hash TEXT,
  declaration_digest TEXT,
  status TEXT NOT NULL,
  skip_reason TEXT,
  test_run_id TEXT,
  probe_job_id TEXT,
  attempts INT NOT NULL DEFAULT 0,
  deferred_until TIMESTAMPTZ,
  last_start_error TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, comparison_id, entry_path_id),
  CONSTRAINT entry_path_comparison_items_status_check
    CHECK (status IN ('pending', 'running', 'deferred', 'completed', 'cancelled', 'failed')),
  CONSTRAINT entry_path_comparison_items_eligible_check
    CHECK (eligible OR status IN ('cancelled', 'failed')),
  CONSTRAINT entry_path_comparison_items_skip_reason_check
    CHECK (status NOT IN ('cancelled', 'failed') OR skip_reason IS NOT NULL),
  CONSTRAINT entry_path_comparison_items_completed_check
    CHECK (status <> 'completed' OR test_run_id IS NOT NULL),
  CONSTRAINT entry_path_comparison_items_queued_check
    CHECK (status NOT IN ('pending', 'deferred') OR test_run_id IS NULL),
  CONSTRAINT entry_path_comparison_items_bounds
    CHECK (ordinal BETWEEN 0 AND 63 AND attempts BETWEEN 0 AND 16),
  CONSTRAINT entry_path_comparison_items_digest_check
    CHECK (
      (target_scope_hash IS NULL OR target_scope_hash ~ '^[a-f0-9]{64}$')
      AND (declaration_digest IS NULL OR declaration_digest ~ '^[a-f0-9]{64}$')
    ),
  CONSTRAINT entry_path_comparison_items_text_bounds
    CHECK (
      char_length(entry_path_id) BETWEEN 1 AND 128
      AND (check_id IS NULL OR char_length(check_id) BETWEEN 1 AND 128)
      AND (skip_reason IS NULL OR char_length(skip_reason) BETWEEN 1 AND 200)
      AND (last_start_error IS NULL OR char_length(last_start_error) BETWEEN 1 AND 200)
    )
);

CREATE UNIQUE INDEX uniq_entry_path_comparison_items_run
  ON entry_path_comparison_items (tenant_id, test_run_id) WHERE test_run_id IS NOT NULL;
CREATE UNIQUE INDEX uniq_entry_path_comparison_items_ordinal
  ON entry_path_comparison_items (tenant_id, comparison_id, ordinal);
CREATE INDEX idx_entry_path_comparison_items_open
  ON entry_path_comparison_items (tenant_id, comparison_id, status)
  WHERE status IN ('pending', 'deferred', 'running');

ALTER TABLE entry_path_comparison_items
  ADD CONSTRAINT fk_entry_path_comparison_items_comparison_tenant
  FOREIGN KEY (tenant_id, comparison_id) REFERENCES entry_path_comparisons (tenant_id, id);
ALTER TABLE entry_path_comparison_items
  ADD CONSTRAINT fk_entry_path_comparison_items_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE entry_path_comparison_items
  ADD CONSTRAINT fk_entry_path_comparison_items_origin_binding_tenant
  FOREIGN KEY (tenant_id, origin_binding_id) REFERENCES origin_bindings (tenant_id, id);
ALTER TABLE entry_path_comparison_items
  ADD CONSTRAINT fk_entry_path_comparison_items_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE entry_path_comparison_items
  ADD CONSTRAINT fk_entry_path_comparison_items_probe_job_tenant
  FOREIGN KEY (tenant_id, probe_job_id) REFERENCES probe_jobs (tenant_id, id);

CREATE OR REPLACE FUNCTION astranull_entry_path_comparison_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION '% rows are retained history and cannot be deleted', TG_TABLE_NAME;
  END IF;
  IF (to_jsonb(NEW) - ARRAY['status', 'cancel_reason', 'evaluation_json', 'evaluation_id', 'lock_version',
        'reconcile_seq', 'reconciled_seq', 'completed_at', 'updated_at'])
     IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['status', 'cancel_reason', 'evaluation_json', 'evaluation_id',
        'lock_version', 'reconcile_seq', 'reconciled_seq', 'completed_at', 'updated_at'])
  THEN
    RAISE EXCEPTION 'entry_path_comparisons approved scope is immutable';
  END IF;
  IF OLD.status <> 'running' THEN
    IF NEW.status IS DISTINCT FROM OLD.status
       OR NEW.cancel_reason IS DISTINCT FROM OLD.cancel_reason
       OR NEW.evaluation_json IS DISTINCT FROM OLD.evaluation_json
       OR NEW.completed_at IS DISTINCT FROM OLD.completed_at
       OR NEW.lock_version IS DISTINCT FROM OLD.lock_version
       OR NEW.reconciled_seq IS DISTINCT FROM OLD.reconciled_seq
       OR (OLD.evaluation_id IS NOT NULL AND NEW.evaluation_id IS DISTINCT FROM OLD.evaluation_id)
    THEN
      RAISE EXCEPTION 'entry_path_comparisons row % is terminal and final', OLD.id;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION astranull_entry_path_comparison_item_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION '% rows are retained history and cannot be deleted', TG_TABLE_NAME;
  END IF;
  IF (to_jsonb(NEW) - ARRAY['status', 'skip_reason', 'test_run_id', 'probe_job_id', 'attempts', 'deferred_until',
        'last_start_error', 'updated_at'])
     IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['status', 'skip_reason', 'test_run_id', 'probe_job_id', 'attempts',
        'deferred_until', 'last_start_error', 'updated_at'])
  THEN
    RAISE EXCEPTION 'entry_path_comparison_items approved attempt scope is immutable';
  END IF;
  IF OLD.status IN ('completed', 'cancelled', 'failed')
     AND (to_jsonb(NEW) - 'updated_at') IS DISTINCT FROM (to_jsonb(OLD) - 'updated_at')
  THEN
    RAISE EXCEPTION 'entry_path_comparison_items attempt %/% is terminal and final', OLD.comparison_id, OLD.entry_path_id;
  END IF;
  IF OLD.test_run_id IS NOT NULL AND NEW.test_run_id IS DISTINCT FROM OLD.test_run_id THEN
    RAISE EXCEPTION 'entry_path_comparison_items linked run cannot change';
  END IF;
  IF OLD.probe_job_id IS NOT NULL AND NEW.probe_job_id IS DISTINCT FROM OLD.probe_job_id THEN
    RAISE EXCEPTION 'entry_path_comparison_items linked probe job cannot change';
  END IF;
  IF NEW.status = 'running' AND OLD.status <> 'running' AND NOT EXISTS (
    SELECT 1 FROM entry_path_comparisons c
    WHERE c.tenant_id = NEW.tenant_id AND c.id = NEW.comparison_id AND c.status = 'running'
  ) THEN
    RAISE EXCEPTION 'entry_path_comparison_items cannot start an attempt of a finished comparison';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER entry_path_comparisons_guard
  BEFORE UPDATE OR DELETE ON entry_path_comparisons
  FOR EACH ROW EXECUTE FUNCTION astranull_entry_path_comparison_guard();
CREATE TRIGGER entry_path_comparison_items_guard
  BEFORE UPDATE OR DELETE ON entry_path_comparison_items
  FOR EACH ROW EXECUTE FUNCTION astranull_entry_path_comparison_item_guard();

ALTER TABLE entry_path_comparisons ENABLE ROW LEVEL SECURITY;
ALTER TABLE entry_path_comparisons FORCE ROW LEVEL SECURITY;
ALTER TABLE entry_path_comparison_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE entry_path_comparison_items FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_entry_path_comparisons ON entry_path_comparisons
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_entry_path_comparison_items ON entry_path_comparison_items
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

COMMENT ON TABLE entry_path_comparisons IS
  'Approved entry-path comparisons (PV-04). The reviewed plan and approved scope are immutable; terminal states are final.';
COMMENT ON TABLE entry_path_comparison_items IS
  'Per-path attempt state for an approved comparison: linked run and probe job, deferral, and skip reason. No raw traffic.';

-- Authorizations may cover disjoint domains on the same retained execution policy.
-- Serialize writes and reject overlap so concurrent signatures cannot approve the same domain twice.
CREATE OR REPLACE FUNCTION guard_loa_target_scope() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.state <> 'signed' THEN RETURN NEW; END IF;
  PERFORM pg_advisory_xact_lock(hashtext(NEW.tenant_id));
  IF EXISTS (
    SELECT 1 FROM loa_signatures existing
    WHERE existing.tenant_id = NEW.tenant_id AND existing.target_group_id = NEW.target_group_id
      AND existing.id <> NEW.id AND existing.state = 'signed'
      AND (existing.expires_at IS NULL OR existing.expires_at > now())
      AND EXISTS (
        SELECT 1 FROM jsonb_array_elements(existing.scope_snapshot->'targets') old_target
        JOIN jsonb_array_elements(NEW.scope_snapshot->'targets') new_target
          ON COALESCE(old_target->>'target_id', old_target #>> '{}') = COALESCE(new_target->>'target_id', new_target #>> '{}')
      )
  ) THEN
    RAISE EXCEPTION 'Active authorization already covers a selected target' USING ERRCODE = '23505';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER loa_signatures_target_scope_guard
  BEFORE INSERT OR UPDATE ON loa_signatures
  FOR EACH ROW EXECUTE FUNCTION guard_loa_target_scope();

CREATE UNIQUE INDEX uniq_active_validation_scan_per_group ON validation_scans(tenant_id, target_group_id)
  WHERE status IN ('pending', 'running') AND target_id IS NULL
    AND (plan_snapshot->'target_ids' IS NULL OR plan_snapshot->'target_ids' = '[]'::jsonb);

CREATE TABLE validation_scan_target_slots (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_id TEXT NOT NULL,
  scan_id TEXT NOT NULL,
  PRIMARY KEY (tenant_id, target_id),
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets(tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, scan_id) REFERENCES validation_scans(tenant_id, id) ON DELETE CASCADE
);
ALTER TABLE validation_scan_target_slots ENABLE ROW LEVEL SECURITY;
ALTER TABLE validation_scan_target_slots FORCE ROW LEVEL SECURITY;
CREATE POLICY validation_scan_target_slots_tenant_isolation ON validation_scan_target_slots
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

INSERT INTO validation_scan_target_slots(tenant_id, target_id, scan_id)
SELECT DISTINCT step.tenant_id, step.target_id, step.scan_id FROM validation_scan_steps step
JOIN validation_scans scan ON scan.tenant_id = step.tenant_id AND scan.id = step.scan_id
WHERE scan.status IN ('pending', 'running');

CREATE FUNCTION reserve_validation_scan_targets() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE selected TEXT; incumbent TEXT;
BEGIN
  DELETE FROM validation_scan_target_slots WHERE tenant_id = NEW.tenant_id AND scan_id = NEW.id;
  IF NEW.status NOT IN ('pending', 'running') THEN RETURN NEW; END IF;
  FOR selected IN
    SELECT DISTINCT value FROM (
      SELECT jsonb_array_elements_text(CASE WHEN jsonb_typeof(NEW.plan_snapshot->'target_ids') = 'array'
        THEN NEW.plan_snapshot->'target_ids' ELSE '[]'::jsonb END) AS value
      UNION SELECT NEW.target_id WHERE NEW.target_id IS NOT NULL
      UNION SELECT target_id FROM validation_scan_steps WHERE tenant_id = NEW.tenant_id AND scan_id = NEW.id
    ) scope ORDER BY value
  LOOP
    PERFORM pg_advisory_xact_lock(hashtextextended('target_execution:' || NEW.tenant_id || ':' || selected, 0));
    IF EXISTS (SELECT 1 FROM test_runs WHERE tenant_id = NEW.tenant_id AND target_id = selected
      AND status IN ('planned', 'running', 'collecting') AND scan_id IS DISTINCT FROM NEW.id) THEN
      RAISE EXCEPTION 'Target already has an active run' USING ERRCODE = '23505', CONSTRAINT = 'uniq_active_validation_scan_target';
    END IF;
    INSERT INTO validation_scan_target_slots(tenant_id, target_id, scan_id) VALUES (NEW.tenant_id, selected, NEW.id)
      ON CONFLICT (tenant_id, target_id) DO NOTHING;
    SELECT scan_id INTO incumbent FROM validation_scan_target_slots WHERE tenant_id = NEW.tenant_id AND target_id = selected;
    IF incumbent IS DISTINCT FROM NEW.id THEN
      RAISE EXCEPTION 'Target already has an active scan' USING ERRCODE = '23505', CONSTRAINT = 'uniq_active_validation_scan_target';
    END IF;
  END LOOP;
  RETURN NEW;
END;
$$;
CREATE TRIGGER validation_scans_target_slots AFTER INSERT OR UPDATE OF status, target_id, plan_snapshot ON validation_scans
  FOR EACH ROW EXECUTE FUNCTION reserve_validation_scan_targets();

CREATE FUNCTION guard_run_target_slot() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.target_id IS NULL OR NEW.status NOT IN ('planned', 'running', 'collecting') THEN RETURN NEW; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('target_execution:' || NEW.tenant_id || ':' || NEW.target_id, 0));
  IF EXISTS (SELECT 1 FROM validation_scan_target_slots WHERE tenant_id = NEW.tenant_id AND target_id = NEW.target_id
    AND scan_id IS DISTINCT FROM NEW.scan_id) THEN
    RAISE EXCEPTION 'Target reserved by another validation scan' USING ERRCODE = '23505', CONSTRAINT = 'uniq_active_test_run';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER test_runs_target_slot_guard BEFORE INSERT OR UPDATE OF status ON test_runs
  FOR EACH ROW EXECUTE FUNCTION guard_run_target_slot();

CREATE TABLE target_initial_edge_detections (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'leased', 'dispatched', 'cancelled')),
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  blocked_reason TEXT,
  test_run_id TEXT,
  lease_token TEXT,
  lease_expires_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, target_id),
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets(tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs(tenant_id, id)
);
CREATE INDEX idx_initial_edge_detection_due ON target_initial_edge_detections(tenant_id, next_attempt_at, target_id)
  WHERE status IN ('queued', 'leased');
ALTER TABLE target_initial_edge_detections ENABLE ROW LEVEL SECURITY;
ALTER TABLE target_initial_edge_detections FORCE ROW LEVEL SECURITY;
CREATE POLICY target_initial_edge_detections_tenant_isolation ON target_initial_edge_detections
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE FUNCTION queue_initial_target_edge_detection() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.kind IN ('fqdn', 'url') THEN
    INSERT INTO target_initial_edge_detections(tenant_id, target_id, requested_at, next_attempt_at)
      VALUES (NEW.tenant_id, NEW.id, COALESCE(NEW.created_at, now()), now()) ON CONFLICT DO NOTHING;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER targets_queue_initial_edge_detection AFTER INSERT ON targets
  FOR EACH ROW EXECUTE FUNCTION queue_initial_target_edge_detection();

-- Existing domains without an accepted edge observation also receive an initial request.
INSERT INTO target_initial_edge_detections(tenant_id, target_id)
SELECT target.tenant_id, target.id FROM targets target
WHERE target.kind IN ('fqdn', 'url') AND target.deleted_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM target_edge_detections edge WHERE edge.tenant_id = target.tenant_id AND edge.target_id = target.id)
ON CONFLICT DO NOTHING;

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

-- Migration 0076: durable passive CVE component-applicability declaration reviews.
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

-- Preserve existing history; new transitions serialize and remain distinct in millisecond bindings.
CREATE OR REPLACE FUNCTION advance_target_verification_clock()
RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  previous_at timestamptz;
  invalid_history boolean;
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id', true)
     OR NEW.transitioned_at IS NULL OR NOT isfinite(NEW.transitioned_at)
     OR abs(extract(epoch FROM NEW.transitioned_at) * 1000) > 8640000000000000 THEN
    RAISE EXCEPTION 'Invalid ownership transition scope or clock' USING ERRCODE = '23514';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext(NEW.tenant_id));
  PERFORM 1 FROM targets
    WHERE tenant_id = NEW.tenant_id AND id = NEW.target_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Ownership transition target is unavailable' USING ERRCODE = '23503';
  END IF;
  SELECT max(transitioned_at), bool_or(NOT isfinite(transitioned_at)
      OR abs(extract(epoch FROM transitioned_at) * 1000) > 8640000000000000)
    INTO previous_at, invalid_history FROM target_verifications
    WHERE tenant_id = NEW.tenant_id AND target_id = NEW.target_id;
  IF invalid_history THEN
    RAISE EXCEPTION 'Existing ownership transition clock is invalid' USING ERRCODE = '23514';
  END IF;
  NEW.transitioned_at := date_trunc('milliseconds', NEW.transitioned_at);
  IF previous_at IS NOT NULL THEN
    NEW.transitioned_at := greatest(NEW.transitioned_at,
      date_trunc('milliseconds', previous_at) + interval '1 millisecond');
  END IF;
  IF abs(extract(epoch FROM NEW.transitioned_at) * 1000) > 8640000000000000 THEN
    RAISE EXCEPTION 'Ownership transition clock cannot advance' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER target_verification_advance_clock
BEFORE INSERT ON target_verifications
FOR EACH ROW EXECUTE FUNCTION advance_target_verification_clock();

-- Neither strength nor row identity establishes chronology for equal-time legacy history.
CREATE OR REPLACE VIEW target_verification_current
WITH (security_invoker = true) AS
  WITH ranked AS (
    SELECT target_id, tenant_id, state, source_kind, source_ref, transitioned_at,
           dense_rank() OVER (PARTITION BY tenant_id, target_id ORDER BY transitioned_at DESC) AS position,
           bool_or(NOT isfinite(transitioned_at)
      OR abs(extract(epoch FROM transitioned_at) * 1000) > 8640000000000000) OVER (PARTITION BY tenant_id, target_id) AS invalid_history
    FROM target_verifications
    WHERE tenant_id = current_setting('app.tenant_id', true)
  ), latest AS (
    SELECT target_id, tenant_id, transitioned_at,
           min(state) AS state, min(source_kind) AS source_kind,
           (jsonb_agg(source_ref)->0) AS source_ref,
           count(DISTINCT jsonb_build_array(state, source_kind, source_ref)) > 1
             OR bool_or(invalid_history) AS ambiguous
    FROM ranked WHERE position = 1
    GROUP BY target_id, tenant_id, transitioned_at
  )
  SELECT latest.target_id, latest.tenant_id,
         CASE
           WHEN latest.ambiguous OR NOT isfinite(latest.transitioned_at) THEN 'pending'
           WHEN latest.state = 'provider_verified'
            AND (
              latest.source_kind <> 'provider_account'
              OR feature.enabled IS NOT TRUE
              OR NOT target_provider_verification_is_current(
                latest.tenant_id, latest.target_id, latest.source_ref
              )
            ) THEN 'pending'
           ELSE latest.state
         END AS state,
         CASE WHEN latest.ambiguous THEN 'ownership_ambiguous' ELSE latest.source_kind END AS source_kind,
         CASE WHEN latest.ambiguous THEN '{}'::jsonb ELSE latest.source_ref END AS source_ref,
         latest.transitioned_at
  FROM latest
  LEFT JOIN tenant_connector_features feature ON feature.tenant_id = latest.tenant_id;

-- Internal at-most-once prerequisite only; does not enable reviewed reservation or execution.
ALTER TABLE probe_jobs ADD CONSTRAINT probe_jobs_grant_job_run_key UNIQUE (tenant_id, id, test_run_id);
ALTER TABLE reviewed_operations ADD CONSTRAINT reviewed_operations_grant_plan_key UNIQUE (tenant_id, id, target_id, plan_digest);

CREATE FUNCTION reviewed_grant_utc_millis(value JSONB) RETURNS BOOLEAN LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
  RETURN (jsonb_typeof(value) = 'string' AND value #>> '{}' ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$'
    AND isfinite((value #>> '{}')::timestamptz)
    AND to_char((value #>> '{}')::timestamptz AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') = value #>> '{}') IS TRUE;
EXCEPTION WHEN OTHERS THEN RETURN FALSE;
END;
$$;

CREATE FUNCTION valid_reviewed_grant_json(e JSONB, r JSONB, p JSONB) RETURNS BOOLEAN LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE a JSONB := e->'authority'; b JSONB := e->'budgets'; j JSONB; c JSONB; binding JSONB; k TEXT; dns JSONB;
BEGIN
  IF octet_length(e::text) > 262144 OR octet_length(r::text) > 16384 OR octet_length(p::text) > 262144 THEN RETURN FALSE; END IF;
  FOR k IN SELECT unnest(ARRAY['version', 'purpose', 'content_canonicalization', 'algorithm', 'key_reference',
    'public_key_fingerprint_sha256', 'tenant_id', 'original_job_payload', 'original_job_signature_sha256']) LOOP
    IF jsonb_typeof(e->k) IS DISTINCT FROM 'string' THEN RETURN FALSE; END IF;
  END LOOP;
  j := (e->>'original_job_payload')::jsonb; c := j->'constraints'; binding := c->'reviewed_operation_binding';
  FOR k IN SELECT unnest(ARRAY['id', 'tenant_id', 'test_run_id', 'check_id', 'nonce_hash']) LOOP
    IF jsonb_typeof(j->k) IS DISTINCT FROM 'string' THEN RETURN FALSE; END IF;
  END LOOP;
  IF NOT ((jsonb_typeof(j->'target') = 'object' AND jsonb_typeof(j->'target'->'id') = 'string'
    AND jsonb_typeof(j->'probe_profile') = 'object' AND jsonb_typeof(c) = 'object'
    AND jsonb_typeof(e->'job') = 'object' AND jsonb_typeof(e->'worker') = 'object'
    AND jsonb_typeof(e->'worker'->'id') = 'string'
    AND jsonb_typeof(a) = 'object' AND a ?& ARRAY['issued_at', 'original_not_after', 'not_after', 'grant_issued_at']
    AND a - ARRAY['issued_at', 'original_not_after', 'not_after', 'grant_issued_at'] = '{}'::jsonb
    AND jsonb_typeof(b) = 'object' AND b ?& ARRAY['max_probe_requests', 'max_destination_resolver_attempts', 'max_total_operations', 'execution_attempts', 'timeout_ms']
    AND b - ARRAY['max_probe_requests', 'max_destination_resolver_attempts', 'max_total_operations', 'execution_attempts', 'timeout_ms'] = '{}'::jsonb
    AND jsonb_typeof(r) = 'object' AND r ?& ARRAY['version', 'id', 'worker_id', 'leased_at', 'reserved_at', 'not_after',
      'max_probe_requests', 'max_destination_resolver_attempts', 'max_total_operations', 'state', 'reviewed_operation']
    AND r - ARRAY['version', 'id', 'worker_id', 'leased_at', 'reserved_at', 'not_after',
      'max_probe_requests', 'max_destination_resolver_attempts', 'max_total_operations', 'state', 'reviewed_operation'] = '{}'::jsonb
    AND jsonb_typeof(r->'reviewed_operation') = 'object'
    AND r->'reviewed_operation' ?& ARRAY['binding_version', 'review_id', 'plan_version', 'plan_digest']
    AND (r->'reviewed_operation') - ARRAY['binding_version', 'review_id', 'plan_version', 'plan_digest'] = '{}'::jsonb
    AND jsonb_typeof(binding->'authority') = 'object'
    AND binding->'authority' ?& ARRAY['issued_at', 'original_not_after', 'not_after']
    AND (binding->'authority') - ARRAY['issued_at', 'original_not_after', 'not_after'] = '{}'::jsonb
  ) IS TRUE) THEN RETURN FALSE; END IF;
  FOR k IN SELECT unnest(ARRAY['version', 'id', 'worker_id', 'state']) LOOP
    IF jsonb_typeof(r->k) IS DISTINCT FROM 'string' THEN RETURN FALSE; END IF;
  END LOOP;
  FOR k IN SELECT unnest(ARRAY['binding_version', 'review_id', 'plan_version', 'plan_digest']) LOOP
    IF jsonb_typeof(r->'reviewed_operation'->k) IS DISTINCT FROM 'string' THEN RETURN FALSE; END IF;
  END LOOP;
  FOR k IN SELECT unnest(ARRAY['version', 'review_id', 'plan_digest']) LOOP
    IF jsonb_typeof(binding->k) IS DISTINCT FROM 'string' THEN RETURN FALSE; END IF;
  END LOOP;
  IF NOT ((binding->>'version' = 'reviewed-operation-binding.v1'
    AND jsonb_typeof(binding->'plan'->'version') = 'string'
    AND binding->'plan'->>'version' = 'reviewed-inert-operation.v1'
    AND r->'reviewed_operation' = jsonb_build_object('binding_version', binding->>'version',
      'review_id', binding->>'review_id', 'plan_version', binding->'plan'->>'version', 'plan_digest', binding->>'plan_digest')) IS TRUE)
    THEN RETURN FALSE; END IF;
  FOR k IN SELECT unnest(ARRAY['issued_at', 'original_not_after', 'not_after', 'grant_issued_at']) LOOP
    IF NOT reviewed_grant_utc_millis(a->k) THEN RETURN FALSE; END IF;
  END LOOP;
  FOR k IN SELECT unnest(ARRAY['leased_at', 'reserved_at', 'not_after']) LOOP
    IF NOT reviewed_grant_utc_millis(r->k) THEN RETURN FALSE; END IF;
  END LOOP;
  FOR k IN SELECT unnest(ARRAY['max_probe_requests', 'max_destination_resolver_attempts', 'max_total_operations', 'execution_attempts', 'timeout_ms']) LOOP
    IF jsonb_typeof(b->k) IS DISTINCT FROM 'number' OR b->>k !~ '^(0|[1-9][0-9]*)$'
      OR b->k IS DISTINCT FROM c->k THEN RETURN FALSE; END IF;
  END LOOP;
  FOR k IN SELECT unnest(ARRAY['max_probe_requests', 'max_destination_resolver_attempts', 'max_total_operations']) LOOP
    IF jsonb_typeof(r->k) IS DISTINCT FROM 'number' OR r->k IS DISTINCT FROM b->k THEN RETURN FALSE; END IF;
  END LOOP;
  dns := p->'dns_proof'->'source_ref'->'dns_target_binding';
  FOR k IN SELECT unnest(ARRAY['version', 'tenant_id', 'target_group_id', 'target_id', 'definition_digest']) LOOP
    IF jsonb_typeof(dns->k) IS DISTINCT FROM 'string' THEN RETURN FALSE; END IF;
  END LOOP;
  FOR k IN SELECT unnest(ARRAY['id', 'tenant_id', 'target_id', 'state', 'source_kind', 'transitioned_at']) LOOP
    IF jsonb_typeof(p->'dns_proof'->k) IS DISTINCT FROM 'string' THEN RETURN FALSE; END IF;
  END LOOP;
  RETURN ((b->>'max_probe_requests')::numeric BETWEEN 1 AND 4 AND (b->>'max_destination_resolver_attempts')::numeric IN (0, 2)
    AND (b->>'max_total_operations')::numeric = (b->>'max_probe_requests')::numeric + (b->>'max_destination_resolver_attempts')::numeric
    AND b->'execution_attempts' = '1'::jsonb AND (b->>'timeout_ms')::numeric BETWEEN 1 AND 5000
    AND c->'max_requests' = b->'max_total_operations' AND c->'min_destination_resolver_attempts' = b->'max_destination_resolver_attempts'
    AND c->>'authority_version' = 'probe-authority-v2'
    AND a->'issued_at' = c->'issued_at' AND a->'not_after' = c->'not_after'
    AND a - 'grant_issued_at' = binding->'authority'
    AND reviewed_grant_utc_millis(binding->'plan'->'expires_at')
    AND (a->>'original_not_after')::timestamptz > (a->>'issued_at')::timestamptz
    AND (a->>'original_not_after')::timestamptz <= (a->>'issued_at')::timestamptz + interval '120 seconds'
    AND (a->>'not_after')::timestamptz = LEAST((a->>'original_not_after')::timestamptz, (binding->'plan'->>'expires_at')::timestamptz)
    AND (r->>'reserved_at')::timestamptz >= (r->>'leased_at')::timestamptz
    AND (r->>'reserved_at')::timestamptz <= (a->>'grant_issued_at')::timestamptz
    AND (r->>'reserved_at')::timestamptz < (a->>'not_after')::timestamptz
    AND jsonb_typeof(p->'assurance_scope') = 'object' AND jsonb_typeof(p->'assurance_scope'->'version') = 'string'
    AND jsonb_typeof(p->'assurance_scope'->'target') = 'object'
    AND jsonb_typeof(p->'assurance_scope'->'target'->'id') = 'string'
    AND jsonb_typeof(p->'assurance_scope'->'target'->'definition_digest') = 'string'
    AND p->'assurance_scope'->'target'->>'definition_digest' ~ '^[a-f0-9]{64}$'
    AND dns - ARRAY['version', 'tenant_id', 'target_group_id', 'target_id', 'definition_digest'] = '{}'::jsonb
    AND dns->>'tenant_id' = e->>'tenant_id' AND dns->>'target_id' = e->'job'->>'target_id'
    AND dns->>'definition_digest' = p->'assurance_scope'->'target'->>'definition_digest'
    AND jsonb_typeof(p->'ownership_history_sha256') = 'string') IS TRUE;
EXCEPTION WHEN OTHERS THEN RETURN FALSE;
END;
$$;

CREATE TABLE reviewed_execution_grant_issuances (
  id TEXT PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  probe_job_id TEXT NOT NULL,
  test_run_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  check_id TEXT NOT NULL,
  reservation_id TEXT NOT NULL,
  review_id TEXT NOT NULL,
  plan_digest TEXT NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
  worker_id TEXT NOT NULL CHECK (worker_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  leased_at TIMESTAMPTZ NOT NULL CHECK (isfinite(leased_at)),
  original_job_payload TEXT NOT NULL CHECK (octet_length(original_job_payload) BETWEEN 1 AND 131072),
  original_job_payload_sha256 TEXT NOT NULL,
  original_job_signature TEXT NOT NULL CHECK (original_job_signature ~ '^[a-f0-9]{64}$'),
  original_job_signature_sha256 TEXT NOT NULL,
  reservation_json JSONB NOT NULL,
  provenance_json JSONB NOT NULL,
  envelope_json JSONB NOT NULL,
  envelope_canonical TEXT NOT NULL CHECK (octet_length(envelope_canonical) BETWEEN 1 AND 262144),
  envelope_sha256 TEXT NOT NULL,
  completion_token_hash TEXT NOT NULL CHECK (completion_token_hash ~ '^[a-f0-9]{64}$'),
  claimed_at TIMESTAMPTZ NOT NULL CHECK (isfinite(claimed_at)),
  state TEXT NOT NULL DEFAULT 'signing_unknown' CHECK (state IN ('signing_unknown', 'issued', 'closed_unknown')),
  finished_at TIMESTAMPTZ,
  failure_code TEXT,
  grant_signature TEXT,
  UNIQUE (tenant_id, probe_job_id),
  UNIQUE (tenant_id, test_run_id),
  UNIQUE (tenant_id, reservation_id),
  CONSTRAINT reviewed_grant_outcome_check CHECK ((
    (state = 'signing_unknown' AND finished_at IS NULL AND failure_code IS NULL AND grant_signature IS NULL)
    OR (state = 'issued' AND isfinite(finished_at) AND finished_at >= claimed_at
      AND finished_at = date_trunc('milliseconds', finished_at)
      AND finished_at < (envelope_json->'authority'->>'not_after')::timestamptz AND failure_code IS NULL
      AND grant_signature ~ '^[A-Za-z0-9+/]{86}==$')
    OR (state = 'closed_unknown' AND isfinite(finished_at) AND finished_at >= claimed_at AND grant_signature IS NULL
      AND failure_code ~ '^[a-z0-9_]{1,128}$')
  ) IS TRUE),
  CONSTRAINT reviewed_grant_integrity_check CHECK ((
    valid_reviewed_grant_json(envelope_json, reservation_json, provenance_json)
    AND envelope_canonical::jsonb = envelope_json
    AND envelope_sha256 = encode(sha256(convert_to(envelope_canonical, 'UTF8')), 'hex')
    AND original_job_payload_sha256 = encode(sha256(convert_to(original_job_payload, 'UTF8')), 'hex')
    AND original_job_signature_sha256 = encode(sha256(convert_to(original_job_signature, 'UTF8')), 'hex')
    AND jsonb_typeof(envelope_json) = 'object'
    AND envelope_json ?& ARRAY['version', 'purpose', 'content_canonicalization', 'algorithm', 'key_reference',
      'public_key_fingerprint_sha256', 'tenant_id', 'job', 'original_job_payload', 'original_job_signature_sha256',
      'worker', 'reservation', 'budgets', 'authority']
    AND envelope_json - ARRAY['version', 'purpose', 'content_canonicalization', 'algorithm', 'key_reference',
      'public_key_fingerprint_sha256', 'tenant_id', 'job', 'original_job_payload', 'original_job_signature_sha256',
      'worker', 'reservation', 'budgets', 'authority'] = '{}'::jsonb
    AND envelope_json->>'version' = 'reviewed-execution-grant-envelope.v1'
    AND envelope_json->>'purpose' = 'astranull.reviewed-operation.execution-grant'
    AND envelope_json->>'algorithm' = 'ed25519'
    AND envelope_json->>'content_canonicalization' = 'json-key-sorted-v1'
    AND envelope_json->>'key_reference' ~ '^key://[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$'
    AND envelope_json->>'public_key_fingerprint_sha256' ~ '^[a-f0-9]{64}$'
    AND envelope_json->>'tenant_id' = tenant_id
    AND envelope_json->'job' = jsonb_build_object('id', probe_job_id, 'test_run_id', test_run_id, 'check_id', check_id,
      'target_id', target_id, 'nonce_hash', original_job_payload::jsonb->>'nonce_hash')
    AND envelope_json->>'original_job_payload' = original_job_payload
    AND envelope_json->>'original_job_signature_sha256' = original_job_signature_sha256
    AND envelope_json->'worker' = jsonb_build_object('id', worker_id, 'leased_at',
      to_char(leased_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
    AND leased_at = date_trunc('milliseconds', leased_at) AND claimed_at = date_trunc('milliseconds', claimed_at)
    AND envelope_json->'authority'->>'grant_issued_at' = to_char(claimed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
    AND claimed_at >= leased_at
    AND (envelope_json->'authority'->>'issued_at')::timestamptz <= leased_at
    AND (envelope_json->'authority'->>'not_after')::timestamptz > claimed_at
    AND (envelope_json->'authority'->>'not_after')::timestamptz <= (envelope_json->'authority'->>'original_not_after')::timestamptz
    AND jsonb_typeof(original_job_payload::jsonb) = 'object'
    AND original_job_payload::jsonb ?& ARRAY['check_id', 'constraints', 'id', 'nonce_hash', 'probe_profile', 'target', 'tenant_id', 'test_run_id']
    AND original_job_payload::jsonb - ARRAY['check_id', 'constraints', 'id', 'nonce_hash', 'probe_profile', 'target', 'tenant_id', 'test_run_id'] = '{}'::jsonb
    AND original_job_payload::jsonb->>'id' = probe_job_id AND original_job_payload::jsonb->>'tenant_id' = tenant_id
    AND original_job_payload::jsonb->>'test_run_id' = test_run_id AND original_job_payload::jsonb->>'check_id' = check_id
    AND original_job_payload::jsonb->'target'->>'id' = target_id
    AND original_job_payload::jsonb->>'nonce_hash' ~ '^[a-f0-9]{64}$'
    AND original_job_payload::jsonb->'constraints'->'reviewed_operation_binding'->>'review_id' = review_id
    AND original_job_payload::jsonb->'constraints'->'reviewed_operation_binding'->>'plan_digest' = plan_digest
    AND envelope_json->'authority'->>'issued_at' = original_job_payload::jsonb->'constraints'->>'issued_at'
    AND envelope_json->'authority'->>'not_after' = original_job_payload::jsonb->'constraints'->>'not_after'
    AND jsonb_typeof(reservation_json) = 'object' AND octet_length(reservation_json::text) <= 16384
    AND reservation_json->>'version' = 'execution-reservation.v1' AND reservation_json->>'id' = reservation_id
    AND reservation_json->>'state' = 'reserved_unknown' AND reservation_json->>'worker_id' = worker_id
    AND reservation_json->>'leased_at' = envelope_json->'worker'->>'leased_at'
    AND reservation_json->>'not_after' = envelope_json->'authority'->>'not_after'
    AND reservation_json->'reviewed_operation'->>'review_id' = review_id
    AND reservation_json->'reviewed_operation'->>'plan_digest' = plan_digest
    AND envelope_json->'reservation' = reservation_json
    AND envelope_json->'budgets'->'execution_attempts' = '1'::jsonb
    AND envelope_json->'budgets'->'max_probe_requests' = reservation_json->'max_probe_requests'
    AND envelope_json->'budgets'->'max_destination_resolver_attempts' = reservation_json->'max_destination_resolver_attempts'
    AND envelope_json->'budgets'->'max_total_operations' = reservation_json->'max_total_operations'
    AND jsonb_typeof(provenance_json) = 'object' AND octet_length(provenance_json::text) <= 262144
    AND provenance_json ?& ARRAY['assurance_scope', 'dns_proof', 'ownership_history_sha256']
    AND provenance_json - ARRAY['assurance_scope', 'dns_proof', 'ownership_history_sha256'] = '{}'::jsonb
    AND provenance_json->'assurance_scope'->>'version' = 'assurance-scope.v3'
    AND provenance_json->'assurance_scope'->'target'->>'id' = target_id
    AND provenance_json->'dns_proof'->>'tenant_id' = tenant_id
    AND provenance_json->'dns_proof'->>'target_id' = target_id
    AND provenance_json->'dns_proof'->>'state' = 'dns_verified'
    AND provenance_json->'dns_proof'->>'source_kind' = 'dns_txt'
    AND provenance_json->'dns_proof'->'source_ref'->'dns_target_binding'->>'version' = 'dns-ownership-target.v2'
    AND provenance_json->>'ownership_history_sha256' ~ '^[a-f0-9]{64}$'
  ) IS TRUE)
);
ALTER TABLE reviewed_execution_grant_issuances ADD CONSTRAINT fk_reviewed_grant_job_run_tenant
  FOREIGN KEY (tenant_id, probe_job_id, test_run_id) REFERENCES probe_jobs(tenant_id, id, test_run_id);
ALTER TABLE reviewed_execution_grant_issuances ADD CONSTRAINT fk_reviewed_grant_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs(tenant_id, id);
ALTER TABLE reviewed_execution_grant_issuances ADD CONSTRAINT fk_reviewed_grant_review_plan_tenant
  FOREIGN KEY (tenant_id, review_id, target_id, plan_digest) REFERENCES reviewed_operations(tenant_id, id, target_id, plan_digest);
ALTER TABLE reviewed_execution_grant_issuances ENABLE ROW LEVEL SECURITY;
ALTER TABLE reviewed_execution_grant_issuances FORCE ROW LEVEL SECURITY;
CREATE POLICY reviewed_execution_grant_issuances_tenant_isolation ON reviewed_execution_grant_issuances
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE FUNCTION guard_reviewed_execution_grant_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'signing_unknown' THEN RAISE EXCEPTION 'reviewed grant must start consumed unknown'; END IF;
    RETURN NEW;
  END IF;
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'reviewed grant history cannot be deleted'; END IF;
  IF OLD.state <> 'signing_unknown' OR NEW.state NOT IN ('issued', 'closed_unknown') OR
    (to_jsonb(NEW) - ARRAY['state', 'finished_at', 'failure_code', 'grant_signature']) IS DISTINCT FROM
    (to_jsonb(OLD) - ARRAY['state', 'finished_at', 'failure_code', 'grant_signature']) THEN
    RAISE EXCEPTION 'reviewed grant claim and terminal history are immutable';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER reviewed_execution_grant_issuances_history_guard BEFORE INSERT OR UPDATE OR DELETE ON reviewed_execution_grant_issuances
  FOR EACH ROW EXECUTE FUNCTION guard_reviewed_execution_grant_history();

-- Additive sync of db/migrations/0080_finding_system_summary_and_risk_acceptance.sql.
ALTER TABLE findings ADD COLUMN system_summary TEXT;
ALTER TABLE findings ADD COLUMN risk_acceptance JSONB;
ALTER TABLE findings ADD CONSTRAINT findings_risk_acceptance_shape_check CHECK (
  risk_acceptance IS NULL OR (
    jsonb_typeof(risk_acceptance) = 'object'
    AND risk_acceptance ?& ARRAY['reason', 'review_at', 'accepted_by', 'accepted_at']
    AND jsonb_typeof(risk_acceptance->'reason') = 'string'
    AND char_length(risk_acceptance->>'reason') BETWEEN 20 AND 2000
  )
);

-- Additive sync of db/migrations/0081_finding_fix_verified.sql.
ALTER TABLE findings ADD COLUMN verifying_run_id TEXT;
ALTER TABLE findings ADD COLUMN check_version TEXT;
ALTER TABLE findings ADD COLUMN grading_version TEXT;

-- Additive sync of db/migrations/0082_finding_verification_basis.sql.
ALTER TABLE findings ADD COLUMN verification_basis TEXT;

-- Additive sync of db/migrations/0083_origin_clues.sql.
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

-- Additive sync of db/migrations/0084_origin_clue_retention.sql.
-- Origin source metadata lifecycle, not whole-tenant/governance erasure.
-- The application authenticates humans; this role only enforces bounded, audited DB transitions.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'astranull_origin_lifecycle') THEN
    CREATE ROLE astranull_origin_lifecycle NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
      JOIN pg_catalog.pg_roles r ON r.oid = m.roleid WHERE r.rolname = 'astranull_origin_lifecycle') THEN
    RAISE EXCEPTION 'origin lifecycle role must have no members';
  END IF;
END;
$$;
ALTER ROLE astranull_origin_lifecycle NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO astranull_origin_lifecycle;
GRANT SELECT, DELETE ON public.origin_clues, public.origin_clue_batches TO astranull_origin_lifecycle;
GRANT UPDATE (response_json) ON public.origin_clue_batches TO astranull_origin_lifecycle;
GRANT SELECT ON public.tenants, public.audit_logs TO astranull_origin_lifecycle;
GRANT UPDATE (privacy_settings) ON public.tenants TO astranull_origin_lifecycle;

CREATE FUNCTION public.astranull_origin_clue_lifecycle_plan(p_tenant TEXT, p_cutoff TIMESTAMPTZ, p_erase BOOLEAN)
RETURNS JSONB LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
  WITH doomed AS (
    SELECT id, target_id FROM public.origin_clues
    WHERE tenant_id = p_tenant AND (p_erase OR retrieved_at < p_cutoff)
  ), flags AS (
    SELECT b.id,
      p_erase OR (b.created_at < p_cutoff AND NOT EXISTS (
        SELECT 1 FROM public.origin_clues c WHERE c.tenant_id = p_tenant AND c.target_id = b.target_id
          AND c.batch_id = b.id AND NOT (c.id IN (SELECT id FROM doomed))
      )) AS remove_batch,
      (b.created_at < p_cutoff OR EXISTS (
        SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(b.response_json->'items') = 'array'
          THEN b.response_json->'items' ELSE '[]'::jsonb END) item
        JOIN doomed d ON d.id = item->>'id' AND d.target_id = b.target_id
      )) AND b.response_json <> '{"error":"origin_clue_response_expired","expired":true}'::jsonb AS scrub_response
    FROM public.origin_clue_batches b WHERE b.tenant_id = p_tenant
  ), ids AS (
    SELECT
      COALESCE((SELECT jsonb_agg(id ORDER BY id COLLATE "C") FROM doomed), '[]'::jsonb) AS clues,
      COALESCE((SELECT jsonb_agg(id ORDER BY id COLLATE "C") FROM flags WHERE remove_batch), '[]'::jsonb) AS batches,
      COALESCE((SELECT jsonb_agg(id ORDER BY id COLLATE "C") FROM flags WHERE NOT remove_batch AND scrub_response), '[]'::jsonb) AS responses
  )
  SELECT jsonb_build_object('clue_ids', clues, 'batch_ids', batches, 'response_ids', responses,
    'counts', jsonb_build_object('originClues', jsonb_array_length(clues), 'originClueBatches', jsonb_array_length(batches),
      'originClueResponses', jsonb_array_length(responses)),
    'plan_digest', md5(jsonb_build_array(clues, batches, responses)::text)) FROM ids;
$$;
REVOKE ALL ON FUNCTION public.astranull_origin_clue_lifecycle_plan(TEXT, TIMESTAMPTZ, BOOLEAN) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.astranull_origin_clue_lifecycle_plan(TEXT, TIMESTAMPTZ, BOOLEAN) TO astranull_origin_lifecycle;

CREATE OR REPLACE FUNCTION public.astranull_origin_clues_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF current_user = 'astranull_origin_lifecycle' AND OLD.tenant_id = current_setting('app.tenant_id', true) THEN
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    IF TG_TABLE_NAME = 'origin_clue_batches'
      AND NEW.response_json = '{"error":"origin_clue_response_expired","expired":true}'::jsonb
      AND (to_jsonb(NEW) - 'response_json') = (to_jsonb(OLD) - 'response_json') THEN RETURN NEW; END IF;
  END IF;
  RAISE EXCEPTION '% rows are append-only', TG_TABLE_NAME USING ERRCODE = '23514';
END;
$$;

-- Lifecycle audits must survive even a same-transaction application-role delete/update attempt.
CREATE FUNCTION public.astranull_origin_lifecycle_audit_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF OLD.action IN ('privacy.retention_purged', 'privacy.retention_legal_hold',
      'privacy.origin_clues_erased', 'privacy.origin_clues_erasure_blocked') THEN
    RAISE EXCEPTION 'lifecycle audit is immutable' USING ERRCODE = '23514';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER origin_lifecycle_audit_immutable BEFORE UPDATE OR DELETE ON public.audit_logs
FOR EACH ROW EXECUTE FUNCTION public.astranull_origin_lifecycle_audit_immutable();

CREATE FUNCTION public.astranull_apply_origin_clue_lifecycle(p_tenant TEXT, p_audit TEXT, p_mode TEXT, p_at TIMESTAMPTZ)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog SET row_security = on AS $$
DECLARE
  privacy JSONB; policy_days INTEGER; cutoff TIMESTAMPTZ; plan JSONB; evidence RECORD;
  actual_clues INTEGER; actual_batches INTEGER; actual_responses INTEGER;
BEGIN
  IF p_tenant IS NULL OR p_tenant = '' OR p_tenant IS DISTINCT FROM current_setting('app.tenant_id', true)
    OR p_mode IS NULL OR p_mode NOT IN ('expiry', 'erase') OR p_at IS NULL
    OR p_at > clock_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'invalid origin lifecycle authority' USING ERRCODE = '42501';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext(p_tenant));
  SELECT privacy_settings INTO privacy FROM public.tenants WHERE id = p_tenant FOR UPDATE;
  IF NOT FOUND OR COALESCE(privacy #> '{evidence_retention,legal_hold}', 'false'::jsonb) <> 'false'::jsonb THEN
    RAISE EXCEPTION 'origin lifecycle legal hold or missing tenant' USING ERRCODE = '42501';
  END IF;
  policy_days := CASE WHEN jsonb_typeof(privacy->'metadata_retention_days') = 'number'
    THEN LEAST(3650, GREATEST(1, trunc((privacy->>'metadata_retention_days')::numeric)))::integer ELSE 365 END;
  cutoff := p_at - policy_days * interval '24 hours';
  plan := public.astranull_origin_clue_lifecycle_plan(p_tenant, cutoff, p_mode = 'erase');
  SELECT a.*, a.xmin = pg_current_xact_id()::xid AS inserted_here INTO evidence
    FROM public.audit_logs a WHERE a.tenant_id = p_tenant AND a.id = p_audit;
  IF NOT FOUND OR NOT evidence.inserted_here
    OR evidence.action IS DISTINCT FROM (CASE WHEN p_mode = 'erase' THEN 'privacy.origin_clues_erased' ELSE 'privacy.retention_purged' END)
    OR evidence.resource_type IS DISTINCT FROM 'tenant' OR evidence.resource_id IS DISTINCT FROM p_tenant
    OR (p_mode = 'erase' AND (evidence.actor_role IS NULL OR evidence.actor_role NOT IN ('owner', 'admin')))
    OR evidence.metadata_json #> '{origin_lifecycle,counts}' IS DISTINCT FROM plan->'counts'
    OR evidence.metadata_json #>> '{origin_lifecycle,plan_digest}' IS DISTINCT FROM plan->>'plan_digest'
    OR evidence.metadata_json #>> '{origin_lifecycle,mode}' IS DISTINCT FROM p_mode
    OR (evidence.metadata_json #>> '{origin_lifecycle,at}')::timestamptz IS DISTINCT FROM p_at
    OR evidence.metadata_json #>> '{policy_snapshot,tenant_id}' IS DISTINCT FROM p_tenant
    OR (evidence.metadata_json #>> '{policy_snapshot,metadata_retention_days}')::integer IS DISTINCT FROM policy_days
    OR (p_mode = 'erase' AND (evidence.metadata_json->>'confirmation_tenant_id' IS DISTINCT FROM p_tenant
      OR length(btrim(COALESCE(evidence.metadata_json->>'reason', ''))) NOT BETWEEN 1 AND 500)) THEN
    RAISE EXCEPTION 'origin lifecycle requires exact same-transaction audit' USING ERRCODE = '42501';
  END IF;
  IF EXISTS (SELECT 1 FROM jsonb_each(plan->'counts') c
      WHERE evidence.metadata_json->'deleted'->c.key IS DISTINCT FROM c.value) THEN
    RAISE EXCEPTION 'origin lifecycle audit count mismatch' USING ERRCODE = '42501';
  END IF;
  UPDATE public.origin_clue_batches SET response_json = '{"error":"origin_clue_response_expired","expired":true}'::jsonb
    WHERE tenant_id = p_tenant AND id IN (SELECT jsonb_array_elements_text(plan->'response_ids'));
  GET DIAGNOSTICS actual_responses = ROW_COUNT;
  DELETE FROM public.origin_clues WHERE tenant_id = p_tenant AND id IN (SELECT jsonb_array_elements_text(plan->'clue_ids'));
  GET DIAGNOSTICS actual_clues = ROW_COUNT;
  DELETE FROM public.origin_clue_batches WHERE tenant_id = p_tenant AND id IN (SELECT jsonb_array_elements_text(plan->'batch_ids'));
  GET DIAGNOSTICS actual_batches = ROW_COUNT;
  IF plan->'counts' <> jsonb_build_object('originClues', actual_clues, 'originClueBatches', actual_batches, 'originClueResponses', actual_responses) THEN
    RAISE EXCEPTION 'origin lifecycle concurrent plan change' USING ERRCODE = '40001';
  END IF;
  RETURN plan->'counts';
END;
$$;
REVOKE ALL ON FUNCTION public.astranull_apply_origin_clue_lifecycle(TEXT, TEXT, TEXT, TIMESTAMPTZ) FROM PUBLIC;
GRANT CREATE ON SCHEMA public TO astranull_origin_lifecycle;
ALTER FUNCTION public.astranull_apply_origin_clue_lifecycle(TEXT, TEXT, TEXT, TIMESTAMPTZ) OWNER TO astranull_origin_lifecycle;
REVOKE CREATE ON SCHEMA public FROM astranull_origin_lifecycle;
CREATE INDEX origin_clues_retention_idx ON public.origin_clues(tenant_id, retrieved_at);
CREATE INDEX origin_clue_batches_retention_idx ON public.origin_clue_batches(tenant_id, created_at);
