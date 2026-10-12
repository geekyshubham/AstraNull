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
