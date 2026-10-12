-- Dedicated bounded reviewed branch. Ordinary reservation SQL remains unchanged.
CREATE TABLE reviewed_execution_reservations (
  id TEXT PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  probe_job_id TEXT NOT NULL, test_run_id TEXT NOT NULL, target_id TEXT NOT NULL,
  review_id TEXT NOT NULL, plan_digest TEXT NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
  worker_id TEXT NOT NULL CHECK (worker_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  leased_at TIMESTAMPTZ NOT NULL, reserved_at TIMESTAMPTZ NOT NULL, not_after TIMESTAMPTZ NOT NULL,
  reservation_json JSONB NOT NULL,
  UNIQUE (tenant_id, probe_job_id), UNIQUE (tenant_id, test_run_id), UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, id, probe_job_id, test_run_id),
  FOREIGN KEY (tenant_id, probe_job_id, test_run_id) REFERENCES probe_jobs(tenant_id, id, test_run_id),
  FOREIGN KEY (tenant_id, review_id, target_id, plan_digest) REFERENCES reviewed_operations(tenant_id, id, target_id, plan_digest),
  CHECK ((isfinite(leased_at) AND isfinite(reserved_at) AND isfinite(not_after)
    AND leased_at = date_trunc('milliseconds', leased_at) AND reserved_at = date_trunc('milliseconds', reserved_at)
    AND not_after = date_trunc('milliseconds', not_after) AND reserved_at >= leased_at AND not_after > reserved_at
    AND not_after <= leased_at + interval '120 seconds'
    AND jsonb_typeof(reservation_json) = 'object' AND octet_length(reservation_json::text) < 16384
    AND reservation_json->>'id' = id AND reservation_json->>'version' = 'execution-reservation.v1'
    AND reservation_json->>'state' = 'reserved_unknown' AND reservation_json->>'worker_id' = worker_id
    AND reservation_json->'max_probe_requests' = '3'::jsonb
    AND reservation_json->'max_destination_resolver_attempts' = '2'::jsonb
    AND reservation_json->'max_total_operations' = '5'::jsonb
    AND reservation_json->'reviewed_operation'->>'review_id' = review_id
    AND reservation_json->'reviewed_operation'->>'plan_digest' = plan_digest
    AND reviewed_grant_utc_millis(reservation_json->'reserved_at')
    AND reviewed_grant_utc_millis(reservation_json->'leased_at') AND reviewed_grant_utc_millis(reservation_json->'not_after')
    AND (reservation_json->>'reserved_at')::timestamptz = reserved_at
    AND (reservation_json->>'leased_at')::timestamptz = leased_at
    AND (reservation_json->>'not_after')::timestamptz = not_after) IS TRUE)
);
ALTER TABLE reviewed_execution_grant_issuances ADD CONSTRAINT reviewed_grant_claim_lineage_key
  UNIQUE (tenant_id, id, probe_job_id, test_run_id, reservation_id);
CREATE TABLE reviewed_execution_claims (
  id TEXT PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  tenant_id TEXT NOT NULL REFERENCES tenants(id), probe_job_id TEXT NOT NULL, test_run_id TEXT NOT NULL,
  reservation_id TEXT NOT NULL, issuance_id TEXT NOT NULL,
  worker_id TEXT NOT NULL CHECK (worker_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  leased_at TIMESTAMPTZ NOT NULL, claimed_at TIMESTAMPTZ NOT NULL, not_after TIMESTAMPTZ NOT NULL,
  grant_digest TEXT NOT NULL CHECK (grant_digest ~ '^[a-f0-9]{64}$'),
  challenge_hash TEXT NOT NULL CHECK (challenge_hash ~ '^[a-f0-9]{64}$'),
  UNIQUE (tenant_id, probe_job_id), UNIQUE (tenant_id, test_run_id), UNIQUE (tenant_id, reservation_id),
  UNIQUE (tenant_id, id, probe_job_id, test_run_id),
  FOREIGN KEY (tenant_id, reservation_id, probe_job_id, test_run_id)
    REFERENCES reviewed_execution_reservations(tenant_id, id, probe_job_id, test_run_id),
  FOREIGN KEY (tenant_id, issuance_id, probe_job_id, test_run_id, reservation_id)
    REFERENCES reviewed_execution_grant_issuances(tenant_id, id, probe_job_id, test_run_id, reservation_id),
  CHECK (isfinite(leased_at) AND isfinite(claimed_at) AND isfinite(not_after)
    AND leased_at = date_trunc('milliseconds', leased_at) AND claimed_at = date_trunc('milliseconds', claimed_at)
    AND not_after = date_trunc('milliseconds', not_after) AND claimed_at >= leased_at AND claimed_at < not_after
    AND not_after <= leased_at + interval '120 seconds')
);
CREATE TABLE reviewed_execution_acceptances (
  tenant_id TEXT NOT NULL REFERENCES tenants(id), probe_job_id TEXT NOT NULL, test_run_id TEXT NOT NULL,
  claim_id TEXT NOT NULL, event_id TEXT NOT NULL, body_digest TEXT NOT NULL CHECK (body_digest ~ '^[a-f0-9]{64}$'),
  receipt_json JSONB NOT NULL, accepted_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, probe_job_id), UNIQUE (tenant_id, test_run_id), UNIQUE (tenant_id, event_id),
  FOREIGN KEY (tenant_id, claim_id, probe_job_id, test_run_id) REFERENCES reviewed_execution_claims(tenant_id, id, probe_job_id, test_run_id),
  FOREIGN KEY (tenant_id, event_id) REFERENCES events(tenant_id, id),
  CHECK ((isfinite(accepted_at) AND accepted_at = date_trunc('milliseconds', accepted_at)
    AND jsonb_typeof(receipt_json) = 'object' AND octet_length(receipt_json::text) < 16384
    AND receipt_json->>'version' = 'accepted-reviewed-probe-execution.v1'
    AND receipt_json->>'digest' ~ '^[a-f0-9]{64}$') IS TRUE)
);
CREATE FUNCTION preserve_reviewed_execution_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'reviewed execution history is immutable; cannot be updated or deleted'; END;
$$;
CREATE TRIGGER reviewed_reservation_immutable BEFORE UPDATE OR DELETE ON reviewed_execution_reservations
  FOR EACH ROW EXECUTE FUNCTION preserve_reviewed_execution_history();
CREATE TRIGGER reviewed_claim_immutable BEFORE UPDATE OR DELETE ON reviewed_execution_claims
  FOR EACH ROW EXECUTE FUNCTION preserve_reviewed_execution_history();
CREATE TRIGGER reviewed_acceptance_immutable BEFORE UPDATE OR DELETE ON reviewed_execution_acceptances
  FOR EACH ROW EXECUTE FUNCTION preserve_reviewed_execution_history();
CREATE FUNCTION preserve_reviewed_accepted_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.metadata_json->'execution_receipt'->>'version' = 'accepted-reviewed-probe-execution.v1' THEN
    RAISE EXCEPTION 'accepted reviewed event is immutable';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;
CREATE TRIGGER reviewed_accepted_event_immutable BEFORE UPDATE OR DELETE ON events
  FOR EACH ROW EXECUTE FUNCTION preserve_reviewed_accepted_event();
ALTER TABLE reviewed_execution_reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE reviewed_execution_reservations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON reviewed_execution_reservations USING (tenant_id = current_setting('app.tenant_id', true)) WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
ALTER TABLE reviewed_execution_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE reviewed_execution_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON reviewed_execution_claims USING (tenant_id = current_setting('app.tenant_id', true)) WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
ALTER TABLE reviewed_execution_acceptances ENABLE ROW LEVEL SECURITY;
ALTER TABLE reviewed_execution_acceptances FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON reviewed_execution_acceptances USING (tenant_id = current_setting('app.tenant_id', true)) WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
