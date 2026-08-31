-- 0046_exact_target_provider_onboarding.sql
-- Bind scheduled checks to one immutable target and make provider-backed domain imports
-- auditable without treating client metadata or manual snapshots as ownership proof.

-- Deployment runner executes each migration in one transaction. Bound lock waits so an open
-- dashboard/query transaction fails this deploy cleanly for retry instead of wedging rollout.
SET LOCAL lock_timeout = '15s';
SET LOCAL statement_timeout = '5min';

-- A three-column parent key lets policy bindings prove tenant + group + target consistency.
ALTER TABLE targets
  ADD CONSTRAINT targets_tenant_group_id_key UNIQUE (tenant_id, target_group_id, id);

ALTER TABLE test_policies ADD COLUMN target_id TEXT;

-- Keep this trigger through the previous release's rollback window. That writer cannot
-- send target_id yet: bind only an unambiguous active target and make every empty or
-- ambiguous binding inert. A later contract migration may replace this with an
-- immutability-only trigger once all supported writers send target_id. Once bound,
-- target identity is immutable.
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
        USING ERRCODE = '23514',
              CONSTRAINT = 'test_policies_target_identity_immutable';
    END IF;
  END IF;

  IF NEW.target_id IS NULL THEN
    SELECT count(*), min(id)
      INTO active_target_count, resolved_target_id
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

  -- Previous-release writes must never revive an archived row, even when a formerly
  -- empty group has since become unambiguous.
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

DROP TRIGGER IF EXISTS test_policies_exact_target_compat ON test_policies;
CREATE TRIGGER test_policies_exact_target_compat
BEFORE INSERT OR UPDATE ON test_policies
FOR EACH ROW EXECUTE FUNCTION astranull_test_policies_exact_target_compat_trigger();

-- Only the unambiguous legacy case is safe to backfill. Never pick an arbitrary target
-- from a multi-target group.
WITH single_active_target AS (
  SELECT tenant_id, target_group_id, min(id) AS target_id
  FROM targets
  WHERE deleted_at IS NULL
  GROUP BY tenant_id, target_group_id
  HAVING count(*) = 1
)
UPDATE test_policies policy
SET target_id = candidate.target_id
FROM single_active_target candidate
WHERE policy.tenant_id = candidate.tenant_id
  AND policy.target_group_id = candidate.target_group_id
  AND policy.target_id IS NULL;

-- Ambiguous and empty legacy policies remain visible but can never dispatch.
UPDATE test_policies
SET state = CASE
      WHEN state = 'archived' OR archived_at IS NOT NULL THEN 'archived'
      ELSE 'paused'
    END,
    enabled = FALSE,
    next_run_at = NULL,
    lease_token = NULL,
    lease_owner = NULL,
    lease_expires_at = NULL,
    schedule_revision = schedule_revision + 1,
    updated_at = now()
WHERE target_id IS NULL;

ALTER TABLE test_policies
  ADD CONSTRAINT fk_test_policies_target_binding
    FOREIGN KEY (tenant_id, target_group_id, target_id)
    REFERENCES targets (tenant_id, target_group_id, id),
  ADD CONSTRAINT test_policies_exact_target_check CHECK (
    target_id IS NOT NULL
    OR (
      state IN ('paused', 'archived')
      AND enabled = FALSE
      AND next_run_at IS NULL
      AND lease_token IS NULL
      AND lease_owner IS NULL
      AND lease_expires_at IS NULL
    )
  );

DROP INDEX IF EXISTS uniq_test_policies_active_group_check;
CREATE UNIQUE INDEX uniq_test_policies_active_group_target_check
  ON test_policies (tenant_id, target_group_id, target_id, check_id)
  WHERE archived_at IS NULL AND target_id IS NOT NULL;

-- Serialize live run/job creation with target or group archival. The trigger locks the active
-- scope rows inside the INSERT transaction, so archival either observes the committed run and
-- refuses, or wins first and makes the new run fail closed. It also makes the policy target
-- binding a database invariant rather than relying only on service-layer revalidation.
CREATE OR REPLACE FUNCTION astranull_test_runs_exact_active_target_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  policy_target_id TEXT;
BEGIN
  PERFORM 1
  FROM target_groups tg
  JOIN targets t
    ON t.tenant_id = tg.tenant_id
   AND t.target_group_id = tg.id
  WHERE tg.tenant_id = NEW.tenant_id
    AND tg.id = NEW.target_group_id
    AND tg.deleted_at IS NULL
    AND tg.archived_at IS NULL
    AND t.id = NEW.target_id
    AND t.deleted_at IS NULL
  FOR KEY SHARE OF tg, t;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'test run target must be active and belong to its tenant/group'
      USING ERRCODE = '23514',
            CONSTRAINT = 'test_runs_exact_active_target';
  END IF;

  IF NEW.policy_id IS NOT NULL THEN
    SELECT p.target_id
      INTO policy_target_id
    FROM test_policies p
    WHERE p.tenant_id = NEW.tenant_id
      AND p.id = NEW.policy_id
      AND p.target_group_id = NEW.target_group_id
      AND p.archived_at IS NULL
    FOR KEY SHARE;

    IF NOT FOUND OR policy_target_id IS DISTINCT FROM NEW.target_id THEN
      RAISE EXCEPTION 'test run target must match its exact policy target'
        USING ERRCODE = '23514',
              CONSTRAINT = 'test_runs_policy_target_binding';
    END IF;
  END IF;

  IF NEW.policy_dispatch_id IS NOT NULL THEN
    IF NEW.policy_id IS NULL THEN
      RAISE EXCEPTION 'policy dispatch requires a matching policy binding'
        USING ERRCODE = '23514',
              CONSTRAINT = 'test_runs_policy_dispatch_binding';
    END IF;
    PERFORM 1
    FROM test_policy_dispatches d
    WHERE d.tenant_id = NEW.tenant_id
      AND d.id = NEW.policy_dispatch_id
      AND d.policy_id = NEW.policy_id
    FOR KEY SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'test run dispatch must match its policy binding'
        USING ERRCODE = '23514',
              CONSTRAINT = 'test_runs_policy_dispatch_binding';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS test_runs_exact_active_target ON test_runs;
CREATE TRIGGER test_runs_exact_active_target
BEFORE INSERT OR UPDATE OF tenant_id, target_group_id, target_id, policy_id, policy_dispatch_id
ON test_runs
FOR EACH ROW EXECUTE FUNCTION astranull_test_runs_exact_active_target_trigger();


-- Ownership challenge jobs intentionally bind their synthetic run/target fields to the
-- verification and agent. The exact-binding trigger below validates both job classes, so the
-- unconditional regular-run/target foreign keys must not reject the ownership branch first.
ALTER TABLE probe_jobs DROP CONSTRAINT IF EXISTS fk_probe_jobs_test_run_tenant;
ALTER TABLE probe_jobs DROP CONSTRAINT IF EXISTS fk_probe_jobs_target_tenant;
CREATE OR REPLACE FUNCTION astranull_probe_jobs_exact_active_target_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  run_target_id TEXT;
  run_status TEXT;
BEGIN
  IF NEW.ownership_verification_id IS NOT NULL THEN
    PERFORM 1
    FROM ownership_verifications ov
    JOIN target_groups tg
      ON tg.tenant_id = ov.tenant_id AND tg.id = ov.target_group_id
    JOIN agents a
      ON a.tenant_id = ov.tenant_id AND a.id = ov.agent_id
    JOIN targets t
      ON t.tenant_id = ov.tenant_id AND t.target_group_id = ov.target_group_id
     AND t.deleted_at IS NULL AND t.kind = 'fqdn'
     AND COALESCE(t.normalized_value, lower(btrim(t.value))) = lower(btrim(ov.declared_fqdn))
    WHERE ov.tenant_id = NEW.tenant_id
      AND ov.id = NEW.ownership_verification_id
      AND ov.status = 'challenge_sent'
      AND tg.deleted_at IS NULL AND tg.archived_at IS NULL
      AND a.target_group_id = ov.target_group_id
      AND a.status = 'online'
      AND COALESCE(a.last_token_validation_status, 'valid') <> 'invalid'
      AND NEW.test_run_id = ov.id
      AND NEW.target_id = ov.agent_id
      AND NEW.nonce_hash = ov.challenge_nonce_hash
      AND NEW.target_descriptor_json->>'kind' = 'fqdn'
      AND lower(btrim(NEW.target_descriptor_json->>'value')) = lower(btrim(ov.declared_fqdn))
    FOR KEY SHARE OF ov, tg, a, t;

    IF NOT FOUND THEN
      RAISE EXCEPTION 'ownership probe job must match an open exact-target challenge'
        USING ERRCODE = '23514',
              CONSTRAINT = 'probe_jobs_ownership_challenge_binding';
    END IF;
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
BEFORE INSERT OR UPDATE OF tenant_id, test_run_id, target_id, ownership_verification_id,
  nonce_hash, target_descriptor_json
ON probe_jobs
FOR EACH ROW EXECUTE FUNCTION astranull_probe_jobs_exact_active_target_trigger();

-- Historical public ingestion could assert reserved signal names. Mark every pre-upgrade row
-- untrusted; new signed-worker, authenticated-agent, simulation, and public paths stamp their
-- immutable producer kind explicitly.
ALTER TABLE events
  ADD COLUMN producer_kind TEXT NOT NULL DEFAULT 'legacy_untrusted',
  ADD CONSTRAINT events_producer_kind_check CHECK (
    producer_kind IN (
      'legacy_untrusted',
      'public_api',
      'signed_probe',
      'authenticated_agent',
      'internal_simulation',
      'internal_control_plane'
    )
  ),
  ADD CONSTRAINT events_reserved_producer_check CHECK (
    signal_type NOT IN ('probe_result', 'agent_observation', 'ownership_observation', 'agent_no_observation')
    -- Previous-release writers omit producer_kind during a rolling deploy. Keep those rows
    -- quarantined as legacy_untrusted; current public_api forgeries still fail this constraint,
    -- and trust correlation never consumes legacy_untrusted reserved rows.
    OR producer_kind = 'legacy_untrusted'
    OR (signal_type = 'probe_result' AND producer_kind IN ('signed_probe', 'internal_simulation'))
    OR (signal_type = 'agent_observation' AND producer_kind = 'authenticated_agent')
    OR (signal_type = 'ownership_observation' AND producer_kind IN ('signed_probe', 'authenticated_agent'))
    OR (signal_type = 'agent_no_observation' AND producer_kind = 'internal_control_plane')
  ) NOT VALID;

-- Provider account inventory is an exact-target ownership source only when a successful,
-- vault-backed read-only API poll produced the persisted zone snapshot.
ALTER TABLE target_verifications
  DROP CONSTRAINT target_verifications_state_check,
  DROP CONSTRAINT target_verifications_source_kind_check;
ALTER TABLE target_verifications
  ADD CONSTRAINT target_verifications_state_check
    CHECK (state IN ('unverified', 'pending', 'dns_verified', 'provider_verified', 'agent_verified', 'user_confirmed')),
  ADD CONSTRAINT target_verifications_source_kind_check
    CHECK (source_kind IN ('dns_txt', 'provider_account', 'agent_observation', 'user_attestation', 'manual_override', 'connector_inventory', 'customer_declaration'));

ALTER TABLE waf_connectors
  ADD COLUMN poll_revision BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN last_success_revision BIGINT NOT NULL DEFAULT 0;

ALTER TABLE waf_connector_snapshots
  ADD COLUMN evidence_source TEXT NOT NULL DEFAULT 'manual_metadata',
  ADD COLUMN inventory_complete BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN inventory_truncated BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN poll_revision BIGINT NOT NULL DEFAULT 0,
  ADD CONSTRAINT waf_connector_snapshots_evidence_source_check
    CHECK (evidence_source IN ('provider_api', 'manual_metadata')),
  ADD CONSTRAINT waf_connector_snapshots_inventory_state_check
    CHECK (NOT inventory_complete OR NOT inventory_truncated);

-- Current verification reads must not expose immutable historical provider_verified rows after
-- the connector's authoritative generation no longer contains the exact active zone.
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

CREATE OR REPLACE VIEW target_verification_current AS
  SELECT target_id, tenant_id,
         CASE
           WHEN state = 'provider_verified'
            AND source_kind = 'provider_account'
            AND NOT target_provider_verification_is_current(tenant_id, target_id, source_ref)
             THEN 'pending'
           ELSE state
         END AS state,
         source_kind, source_ref, transitioned_at
  FROM (
    SELECT DISTINCT ON (target_id)
      target_id, tenant_id, state, source_kind, source_ref, transitioned_at
    FROM target_verifications
    ORDER BY target_id, transitioned_at DESC
  ) latest;

-- Cached readiness predates immutable producer provenance. Force recomputation so legacy reserved
-- events (and vault rows linked to them) cannot continue granting coverage or freshness.
UPDATE tenants
SET dashboard_rollup = NULL
WHERE dashboard_rollup IS NOT NULL;

-- Collapse historical concurrent open drift duplicates before enforcing one open event per
-- tenant/asset/type. Keep the highest-severity row and preserve the earliest observed creation.
WITH ranked AS (
  SELECT
    id,
    tenant_id,
    waf_asset_id,
    drift_type,
    MIN(created_at) OVER (
      PARTITION BY tenant_id, waf_asset_id, drift_type
    ) AS earliest_created_at,
    FIRST_VALUE(id) OVER (
      PARTITION BY tenant_id, waf_asset_id, drift_type
      ORDER BY
        CASE severity
          WHEN 'critical' THEN 4
          WHEN 'high' THEN 3
          WHEN 'medium' THEN 2
          WHEN 'low' THEN 1
          ELSE 0
        END DESC,
        created_at ASC,
        id ASC
    ) AS keeper_id,
    ROW_NUMBER() OVER (
      PARTITION BY tenant_id, waf_asset_id, drift_type
      ORDER BY
        CASE severity
          WHEN 'critical' THEN 4
          WHEN 'high' THEN 3
          WHEN 'medium' THEN 2
          WHEN 'low' THEN 1
          ELSE 0
        END DESC,
        created_at ASC,
        id ASC
    ) AS row_number
  FROM waf_drift_events
  WHERE status = 'open'
), preserved AS (
  UPDATE waf_drift_events event
  SET created_at = ranked.earliest_created_at
  FROM ranked
  WHERE event.id = ranked.id
    AND ranked.row_number = 1
  RETURNING event.id
), repointed_retests AS (
  UPDATE waf_retest_requests request
  SET drift_event_id = ranked.keeper_id
  FROM ranked
  WHERE ranked.row_number > 1
    AND request.tenant_id = ranked.tenant_id
    AND request.drift_event_id = ranked.id
  RETURNING request.id
)
DELETE FROM waf_drift_events event
USING ranked
WHERE event.id = ranked.id
  AND ranked.row_number > 1;

CREATE UNIQUE INDEX uniq_waf_drift_events_open_asset_type
  ON waf_drift_events (tenant_id, waf_asset_id, drift_type)
  WHERE status = 'open';

-- Agents are optional evidence enhancers. Preserve every existing group's explicit mode,
-- but make new groups external-only unless the caller deliberately opts into assistance.
ALTER TABLE target_groups ALTER COLUMN validation_mode SET DEFAULT 'external_only';

-- External edge blocking is evidence, but it is not full protected coverage without matching
-- agent/origin corroboration. Keep it in a distinct rollup bucket.
ALTER TABLE waf_coverage_daily_rollups
  ADD COLUMN IF NOT EXISTS edge_protected INT NOT NULL DEFAULT 0;


-- Rebuild the portal summary so edge-only evidence is visible without increasing full
-- protected coverage. No application query depends on the materialized-view column order.
DROP MATERIALIZED VIEW IF EXISTS waf_coverage_summary;
CREATE MATERIALIZED VIEW waf_coverage_summary AS
WITH asset_posture AS (
  SELECT
    a.tenant_id,
    a.id AS asset_id,
    CASE
      WHEN ps.status = 'protected' THEN 'protected'
      WHEN ps.status = 'edge_protected' THEN 'edge_protected'
      WHEN ps.status IN ('underprotected', 'unprotected', 'drift') THEN 'underprotected'
      ELSE 'unknown'
    END AS posture_class,
    ps.detected_vendor AS vendor
  FROM waf_assets a
  LEFT JOIN waf_posture_snapshots ps
    ON ps.tenant_id = a.tenant_id
   AND ps.waf_asset_id = a.id
   AND ps.is_current = TRUE
),
tenant_rollups AS (
  SELECT
    tenant_id,
    COUNT(*)::int AS assets_total,
    COUNT(*) FILTER (WHERE posture_class = 'protected')::int AS protected,
    COUNT(*) FILTER (WHERE posture_class = 'edge_protected')::int AS edge_protected,
    COUNT(*) FILTER (WHERE posture_class = 'underprotected')::int AS underprotected,
    COUNT(*) FILTER (WHERE posture_class = 'unknown')::int AS unknown,
    ROUND((COUNT(*) FILTER (WHERE posture_class = 'protected')::numeric / NULLIF(COUNT(*), 0)) * 100, 2)::double precision AS coverage_pct
  FROM asset_posture
  GROUP BY tenant_id
),
vendor_rollups AS (
  SELECT
    tenant_id,
    COALESCE(NULLIF(TRIM(vendor), ''), 'generic') AS vendor,
    COUNT(*)::int AS assets,
    COUNT(*) FILTER (WHERE posture_class = 'protected')::int AS protected,
    COUNT(*) FILTER (WHERE posture_class = 'edge_protected')::int AS edge_protected
  FROM asset_posture
  GROUP BY tenant_id, COALESCE(NULLIF(TRIM(vendor), ''), 'generic')
),
vendor_json AS (
  SELECT
    tenant_id,
    jsonb_object_agg(
      vendor,
      jsonb_build_object(
        'assets', assets,
        'protected', protected,
        'edge_protected', edge_protected
      )
    ) AS by_vendor
  FROM vendor_rollups
  GROUP BY tenant_id
),
connector_counts AS (
  SELECT
    tenant_id,
    COUNT(*) FILTER (WHERE status = 'active')::int AS connectors_active,
    COUNT(*) FILTER (WHERE status IN ('error', 'degraded'))::int AS connectors_degraded,
    COUNT(*) FILTER (WHERE status = 'disabled')::int AS connectors_disabled
  FROM waf_connectors
  GROUP BY tenant_id
)
SELECT
  tr.tenant_id,
  tr.assets_total,
  tr.protected,
  tr.edge_protected,
  tr.underprotected,
  tr.unknown,
  tr.coverage_pct,
  COALESCE(vj.by_vendor, '{}'::jsonb) AS by_vendor,
  COALESCE(cc.connectors_active, 0) AS connectors_active,
  COALESCE(cc.connectors_degraded, 0) AS connectors_degraded,
  COALESCE(cc.connectors_disabled, 0) AS connectors_disabled,
  now() AS refreshed_at
FROM tenant_rollups tr
LEFT JOIN vendor_json vj ON vj.tenant_id = tr.tenant_id
LEFT JOIN connector_counts cc ON cc.tenant_id = tr.tenant_id;

CREATE UNIQUE INDEX waf_coverage_summary_tenant
  ON waf_coverage_summary(tenant_id);
