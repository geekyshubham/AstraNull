-- 0045_ownership_and_policy_dispatch_hardening.sql
-- Correct legacy LOA tenant constraints and make scheduled validation start at-most-once.

-- 0027 used a single-column FK and a global target_group_id active index. Add and
-- validate the tenant-consistent replacements before removing the legacy controls so
-- existing inconsistent data fails the migration rather than being silently re-scoped.
ALTER TABLE loa_signatures
  ADD CONSTRAINT fk_loa_signatures_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id)
  REFERENCES target_groups (tenant_id, id)
  ON DELETE CASCADE
  NOT VALID;
ALTER TABLE loa_signatures
  VALIDATE CONSTRAINT fk_loa_signatures_target_group_tenant;

UPDATE loa_signatures
SET state = 'expired'
WHERE state = 'signed' AND expires_at IS NOT NULL AND expires_at <= now();

CREATE UNIQUE INDEX loa_signatures_active_tenant_group
  ON loa_signatures (tenant_id, target_group_id)
  WHERE state = 'signed';

DROP INDEX loa_signatures_active;
ALTER TABLE loa_signatures
  DROP CONSTRAINT loa_signatures_target_group_id_fkey;

-- No durable event-bus consumer exists for event-driven policies. Keep the literal
-- cadence only as a rollback-window write contract for the previous release. Existing
-- rows and every subsequent previous-release write are forced inert; current application
-- contracts still reject/omit this cadence, and the scheduler selects periodic cadences
-- only. Remove this compatibility trigger and cadence branch after the rollback window.
UPDATE test_policies
SET event_trigger = CASE
      WHEN jsonb_typeof(event_trigger) = 'object'
        THEN event_trigger || '{"migrated_disabled":true}'::jsonb
      ELSE '{"migrated_disabled":true}'::jsonb
    END,
    state = 'paused',
    enabled = FALSE,
    next_run_at = NULL,
    lease_token = NULL,
    lease_owner = NULL,
    lease_expires_at = NULL,
    schedule_revision = schedule_revision + 1,
    updated_at = now()
WHERE cadence = 'event_driven';

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

DROP TRIGGER IF EXISTS test_policies_event_driven_compat ON test_policies;
CREATE TRIGGER test_policies_event_driven_compat
BEFORE INSERT OR UPDATE ON test_policies
FOR EACH ROW EXECUTE FUNCTION astranull_test_policies_event_driven_compat_trigger();

ALTER TABLE test_policies
  DROP CONSTRAINT test_policies_cadence_check,
  DROP CONSTRAINT test_policies_event_trigger_check;
ALTER TABLE test_policies
  ADD CONSTRAINT test_policies_cadence_check
    CHECK (cadence IN ('manual', 'daily', 'weekly', 'monthly', 'event_driven')),
  ADD CONSTRAINT test_policies_event_trigger_disabled_check CHECK (
    (cadence = 'event_driven'
      AND event_trigger IS NOT NULL
      AND jsonb_typeof(event_trigger) = 'object'
      AND event_trigger @> '{"migrated_disabled":true}'::jsonb)
    OR (cadence <> 'event_driven' AND event_trigger IS NULL)
  ),
  ADD CONSTRAINT test_policies_event_driven_inert_check CHECK (
    cadence <> 'event_driven'
    OR (
      state = 'paused'
      AND enabled = FALSE
      AND next_run_at IS NULL
      AND lease_token IS NULL
      AND lease_owner IS NULL
      AND lease_expires_at IS NULL
    )
  );

-- A worker claims the right to invoke startTestRun before crossing that side-effect
-- boundary. Expired leases may be reassigned only while this timestamp is NULL; once
-- claimed, settlement remains valid for the same token even if the lease clock expires.
ALTER TABLE test_policy_dispatches
  ADD COLUMN start_claimed_at TIMESTAMPTZ;

UPDATE test_policy_dispatches
SET start_claimed_at = COALESCE(completed_at, updated_at, created_at)
WHERE state <> 'leased' AND start_claimed_at IS NULL;

UPDATE test_policy_dispatches
SET state = 'failed',
    error_code = COALESCE(error_code, 'missing_run_id'),
    run_id = NULL
WHERE state = 'dispatched' AND run_id IS NULL;

UPDATE test_policy_dispatches
SET run_id = NULL
WHERE state IN ('skipped', 'failed') AND run_id IS NOT NULL;

ALTER TABLE test_policy_dispatches
  DROP CONSTRAINT test_policy_dispatches_lease_check;
ALTER TABLE test_policy_dispatches
  ADD CONSTRAINT test_policy_dispatches_lease_check CHECK (
    (state = 'leased' AND lease_token IS NOT NULL AND lease_owner IS NOT NULL
      AND lease_expires_at IS NOT NULL AND completed_at IS NULL)
    OR (state <> 'leased' AND lease_token IS NULL AND lease_owner IS NULL
      AND lease_expires_at IS NULL AND completed_at IS NOT NULL
      AND start_claimed_at IS NOT NULL)
  ),
  ADD CONSTRAINT test_policy_dispatches_run_binding_check CHECK (
    (state = 'dispatched' AND run_id IS NOT NULL)
    OR (state <> 'dispatched' AND run_id IS NULL)
  );

CREATE UNIQUE INDEX uniq_test_policy_dispatches_run
  ON test_policy_dispatches (tenant_id, run_id)
  WHERE run_id IS NOT NULL;


-- Bind every scheduled run to exactly one durable dispatch occurrence. The tenant-qualified
-- key keeps the circular run/dispatch references tenant-consistent, while nullable columns
-- preserve manual runs.
ALTER TABLE test_policy_dispatches
  ADD CONSTRAINT test_policy_dispatches_tenant_id_id_key UNIQUE (tenant_id, id);

ALTER TABLE test_runs
  ADD COLUMN policy_dispatch_id TEXT,
  ADD CONSTRAINT fk_test_runs_policy_dispatch_tenant
    FOREIGN KEY (tenant_id, policy_dispatch_id)
    REFERENCES test_policy_dispatches (tenant_id, id);

CREATE UNIQUE INDEX uniq_test_runs_policy_dispatch
  ON test_runs (tenant_id, policy_dispatch_id)
  WHERE policy_dispatch_id IS NOT NULL;
