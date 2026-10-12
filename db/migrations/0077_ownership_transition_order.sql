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
