-- Enforce the ownership challenge <-> probe job relationship in both directions.
-- 0046 bound a job to its verification, but did not require the verification's durable
-- probe_job_id to point back to that exact job. Keep this as an additive replacement so
-- already-applied migrations remain immutable and clean installs execute the same final guard.

CREATE OR REPLACE FUNCTION astranull_probe_jobs_exact_active_target_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  run_target_id TEXT;
  run_status TEXT;
BEGIN
  -- Ownership rows form a circular relationship and may be inserted in either order.
  -- Their complete structural/classification check is deferred until transaction commit below.
  IF NEW.check_id = 'ownership.challenge' OR NEW.ownership_verification_id IS NOT NULL THEN
    RETURN NEW;
  END IF;

  PERFORM 1
  FROM targets t
  JOIN target_groups tg
    ON tg.tenant_id = t.tenant_id
   AND tg.id = t.target_group_id
  WHERE t.tenant_id = NEW.tenant_id
    AND t.id = NEW.target_id
    AND t.deleted_at IS NULL
    AND tg.deleted_at IS NULL
    AND tg.archived_at IS NULL
  FOR KEY SHARE OF t, tg;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'probe job target must remain active'
      USING ERRCODE = '23514',
            CONSTRAINT = 'probe_jobs_exact_active_target';
  END IF;

  IF NEW.test_run_id IS NOT NULL THEN
    SELECT tr.target_id, tr.status
      INTO run_target_id, run_status
    FROM test_runs tr
    WHERE tr.tenant_id = NEW.tenant_id
      AND tr.id = NEW.test_run_id
    FOR KEY SHARE;

    IF NOT FOUND
       OR run_target_id IS DISTINCT FROM NEW.target_id
       OR run_status NOT IN ('planned', 'running', 'collecting') THEN
      RAISE EXCEPTION 'probe job target must match an active test run'
        USING ERRCODE = '23514',
              CONSTRAINT = 'probe_jobs_test_run_target_binding';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS probe_jobs_exact_active_target ON probe_jobs;
CREATE TRIGGER probe_jobs_exact_active_target
BEFORE INSERT OR UPDATE OF id, tenant_id, test_run_id, target_id, check_id,
  ownership_verification_id, nonce_hash, target_descriptor_json
ON probe_jobs
FOR EACH ROW EXECUTE FUNCTION astranull_probe_jobs_exact_active_target_trigger();

-- Prevent writes from racing the one-time upgrade validation. Nullable probe_job_id rows are
-- inert legacy/developer records; every row that claims either side of an ownership-job binding
-- must already satisfy the complete reciprocal tuple before the new trust boundary is installed.
LOCK TABLE ownership_verifications, probe_jobs IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM ownership_verifications ov
    LEFT JOIN probe_jobs j
      ON j.tenant_id = ov.tenant_id
     AND j.id = ov.probe_job_id
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
      ON ov.tenant_id = j.tenant_id
     AND ov.id = j.ownership_verification_id
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

-- Both edges are deferred so verification-first and job-first writers can construct the same
-- legitimate circular pair in one transaction. Validation still occurs before COMMIT succeeds.
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
  -- A later update in the same transaction may have moved or deleted this row. Validate the
  -- current durable tuple, not the stale row image captured when the deferred event was queued.
  SELECT ov.probe_job_id
    INTO current_probe_job_id
  FROM ownership_verifications ov
  WHERE ov.tenant_id = NEW.tenant_id
    AND ov.id = NEW.id
  FOR KEY SHARE;
  IF NOT FOUND THEN
    RETURN NEW;
  END IF;

  -- A null edge is valid only when no job claims the verification. The same reverse-edge scan
  -- prevents A -> B relinks from stranding an unchanged A -> verification claim.
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
    ON j.tenant_id = ov.tenant_id
   AND j.id = ov.probe_job_id
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
  WHERE j.tenant_id = NEW.tenant_id
    AND j.id = NEW.id;
  IF NOT FOUND THEN
    RETURN NEW;
  END IF;

  IF current_check_id <> 'ownership.challenge'
     AND current_ownership_verification_id IS NULL THEN
    PERFORM 1
    FROM ownership_verifications ov
    WHERE ov.tenant_id = NEW.tenant_id
      AND ov.probe_job_id = NEW.id;
    IF FOUND THEN
      RAISE EXCEPTION 'ordinary probe job cannot be referenced as an ownership challenge job'
        USING ERRCODE = '23514',
              CONSTRAINT = 'probe_jobs_ownership_challenge_binding';
    END IF;
    RETURN NEW;
  END IF;

  -- The selected verification must be the only verification that points at this job. Without
  -- this reverse check, reassigning the job could strand an unchanged former verification.
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
    ON ov.tenant_id = j.tenant_id
   AND ov.id = j.ownership_verification_id
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

DROP TRIGGER IF EXISTS ownership_verifications_reciprocal_probe_job ON ownership_verifications;
CREATE CONSTRAINT TRIGGER ownership_verifications_reciprocal_probe_job
AFTER INSERT OR UPDATE
ON ownership_verifications
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION astranull_ownership_verifications_reciprocal_probe_job_trigger();

DROP TRIGGER IF EXISTS probe_jobs_reciprocal_ownership_verification ON probe_jobs;
CREATE CONSTRAINT TRIGGER probe_jobs_reciprocal_ownership_verification
AFTER INSERT OR UPDATE
ON probe_jobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION astranull_probe_jobs_reciprocal_ownership_verification_trigger();
