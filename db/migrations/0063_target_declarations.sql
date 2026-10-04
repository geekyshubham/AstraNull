-- 0063_target_declarations.sql
-- Typed customer declarations for targets and target groups.
--
-- purpose, service_roles, owner_label, and criticality live here. They are not
-- metadata and they do not grant probe scope. Existing tenant_isolation policies
-- on targets and target_groups already constrain every column, including this one,
-- to app.tenant_id. Empty object is the unassigned declaration.
--
-- Additive. Does not rewrite 0061 or 0062.

ALTER TABLE targets
  ADD COLUMN IF NOT EXISTS declaration_json JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE target_groups
  ADD COLUMN IF NOT EXISTS declaration_json JSONB NOT NULL DEFAULT '{}'::jsonb;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'targets_declaration_json_object'
  ) THEN
    ALTER TABLE targets
      ADD CONSTRAINT targets_declaration_json_object
      CHECK (jsonb_typeof(declaration_json) = 'object');
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'target_groups_declaration_json_object'
  ) THEN
    ALTER TABLE target_groups
      ADD CONSTRAINT target_groups_declaration_json_object
      CHECK (jsonb_typeof(declaration_json) = 'object');
  END IF;
END
$$;
