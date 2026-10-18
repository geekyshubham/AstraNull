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
