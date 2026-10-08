DROP INDEX loa_signatures_active_tenant_group;
CREATE INDEX loa_signatures_active_tenant_group
  ON loa_signatures(tenant_id, target_group_id) WHERE state = 'signed';

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
