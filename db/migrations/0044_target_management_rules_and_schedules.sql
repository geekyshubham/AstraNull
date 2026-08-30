-- 0044_target_management_rules_and_schedules.sql
-- Production target lifecycle and per-group validation rule scheduling.
--
-- Expand/backfill/contract order is deliberate. normalized_value is first nullable, a
-- compatibility trigger is installed for the previous release (which inserts kind/value
-- only), legacy rows are backfilled, and only then is NOT NULL enforced. The trigger must
-- remain until that previous release is outside the rollback window; a later contract
-- migration may remove it after every writer supplies application-canonical values.

ALTER TABLE targets
  ADD COLUMN IF NOT EXISTS normalized_value TEXT,
  ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS deleted_by TEXT;

-- PostgreSQL cannot exactly reproduce the application's WHATWG URL and IDNA routines.
-- Current writers therefore remain authoritative when they provide normalized_value.
-- For legacy rows/writers, use a conservative, non-throwing value: canonicalize DNS and
-- valid IP literals where PostgreSQL is reliable, and trim URL/TCP/canary values without
-- changing case-sensitive URL paths or rejecting historical input.
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

DROP TRIGGER IF EXISTS targets_normalized_value_compat ON targets;
CREATE TRIGGER targets_normalized_value_compat
BEFORE INSERT OR UPDATE OF kind, value, normalized_value ON targets
FOR EACH ROW EXECUTE FUNCTION astranull_targets_normalized_value_compat_trigger();

UPDATE targets
SET kind = CASE
      WHEN lower(btrim(kind)) IN ('domain', 'hostname') THEN 'fqdn'
      ELSE lower(btrim(kind))
    END,
    normalized_value = astranull_target_compat_normalized_value(kind, value)
WHERE normalized_value IS NULL;

ALTER TABLE targets ALTER COLUMN normalized_value SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uniq_target_groups_active_name
  ON target_groups (tenant_id, COALESCE(environment_id, ''), lower(name))
  WHERE deleted_at IS NULL AND archived_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uniq_targets_active_canonical
  ON targets (tenant_id, target_group_id, kind, normalized_value)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_targets_tenant_group_active
  ON targets (tenant_id, target_group_id, created_at)
  WHERE deleted_at IS NULL;

ALTER TABLE test_policies
  ADD COLUMN IF NOT EXISTS timezone TEXT NOT NULL DEFAULT 'UTC',
  ADD COLUMN IF NOT EXISTS event_trigger JSONB,
  ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN IF NOT EXISTS max_concurrent_runs INTEGER NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS next_run_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_scheduled_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_dispatched_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_run_id TEXT,
  ADD COLUMN IF NOT EXISTS lease_token TEXT,
  ADD COLUMN IF NOT EXISTS lease_owner TEXT,
  ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS schedule_revision BIGINT NOT NULL DEFAULT 1;

UPDATE test_policies
SET timezone = COALESCE(NULLIF(safe_windows -> 0 ->> 'timezone', ''), 'UTC'),
    enabled = CASE WHEN state = 'active' THEN TRUE ELSE FALSE END
WHERE timezone = 'UTC' OR enabled IS TRUE;

UPDATE test_policies
SET state = 'paused',
    enabled = FALSE,
    event_trigger = '{"event_type":"target.changed","filters":{},"migrated_disabled":true}'::jsonb
WHERE cadence = 'event_driven' AND event_trigger IS NULL;

ALTER TABLE test_policies DROP CONSTRAINT IF EXISTS test_policies_state_check;
ALTER TABLE test_policies
  ADD CONSTRAINT test_policies_state_check CHECK (state IN ('active', 'paused', 'archived')),
  ADD CONSTRAINT test_policies_max_concurrent_runs_check CHECK (max_concurrent_runs = 1),
  ADD CONSTRAINT test_policies_event_trigger_check CHECK (
    (cadence = 'event_driven' AND event_trigger IS NOT NULL AND jsonb_typeof(event_trigger) = 'object')
    OR (cadence <> 'event_driven' AND event_trigger IS NULL)
  ),
  ADD CONSTRAINT test_policies_lease_check CHECK (
    (lease_token IS NULL AND lease_owner IS NULL AND lease_expires_at IS NULL)
    OR (lease_token IS NOT NULL AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
  );

ALTER TABLE test_policies
  ADD CONSTRAINT test_policies_tenant_id_id_key UNIQUE (tenant_id, id);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_test_policies_active_group_check
  ON test_policies (tenant_id, target_group_id, check_id)
  WHERE archived_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_test_policies_due
  ON test_policies (tenant_id, next_run_at, id)
  WHERE archived_at IS NULL AND state = 'active' AND enabled = TRUE AND next_run_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_test_policies_expired_lease
  ON test_policies (tenant_id, lease_expires_at)
  WHERE lease_expires_at IS NOT NULL;

ALTER TABLE test_runs ADD COLUMN IF NOT EXISTS policy_id TEXT;
ALTER TABLE test_runs
  ADD CONSTRAINT fk_test_runs_policy_tenant
  FOREIGN KEY (tenant_id, policy_id)
  REFERENCES test_policies (tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_test_runs_tenant_policy
  ON test_runs (tenant_id, policy_id)
  WHERE policy_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS test_policy_dispatches (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  scheduled_for TIMESTAMPTZ NOT NULL,
  idempotency_key TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('leased', 'dispatched', 'skipped', 'failed')),
  lease_token TEXT,
  lease_owner TEXT,
  lease_expires_at TIMESTAMPTZ,
  run_id TEXT,
  error_code TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  CONSTRAINT test_policy_dispatches_policy_fk
    FOREIGN KEY (tenant_id, policy_id) REFERENCES test_policies (tenant_id, id),
  CONSTRAINT test_policy_dispatches_run_fk
    FOREIGN KEY (tenant_id, run_id) REFERENCES test_runs (tenant_id, id),
  CONSTRAINT test_policy_dispatches_idempotency UNIQUE (tenant_id, idempotency_key),
  CONSTRAINT test_policy_dispatches_occurrence UNIQUE (tenant_id, policy_id, scheduled_for),
  CONSTRAINT test_policy_dispatches_lease_check CHECK (
    (state = 'leased' AND lease_token IS NOT NULL AND lease_owner IS NOT NULL
      AND lease_expires_at IS NOT NULL AND completed_at IS NULL)
    OR (state <> 'leased' AND lease_token IS NULL AND lease_owner IS NULL
      AND lease_expires_at IS NULL AND completed_at IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_test_policy_dispatches_policy
  ON test_policy_dispatches (tenant_id, policy_id, scheduled_for DESC);
CREATE INDEX IF NOT EXISTS idx_test_policy_dispatches_expired_lease
  ON test_policy_dispatches (tenant_id, lease_expires_at)
  WHERE state = 'leased';

ALTER TABLE test_policy_dispatches ENABLE ROW LEVEL SECURITY;
ALTER TABLE test_policy_dispatches FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS test_policy_dispatches_tenant_isolation ON test_policy_dispatches;
CREATE POLICY test_policy_dispatches_tenant_isolation ON test_policy_dispatches
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE target_verifications DROP CONSTRAINT IF EXISTS target_verifications_source_kind_check;
ALTER TABLE target_verifications
  ADD CONSTRAINT target_verifications_source_kind_check CHECK (
    source_kind IN (
      'dns_txt', 'agent_observation', 'user_attestation', 'manual_override',
      'connector_inventory', 'customer_declaration'
    )
  );
