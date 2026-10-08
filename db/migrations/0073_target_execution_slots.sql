-- Direct domains share policy settings, not an execution slot.
DROP INDEX uniq_active_test_run;
CREATE UNIQUE INDEX uniq_active_test_run ON test_runs(tenant_id, target_id)
  WHERE target_id IS NOT NULL AND status IN ('planned', 'running', 'collecting');
CREATE UNIQUE INDEX uniq_active_unbound_test_run ON test_runs(tenant_id, target_group_id)
  WHERE target_id IS NULL AND status IN ('planned', 'running', 'collecting');
DROP INDEX uniq_active_validation_scan_per_group;
-- Retain conservative serialization for legacy active records with no exact target scope.
CREATE UNIQUE INDEX uniq_active_validation_scan_per_group ON validation_scans(tenant_id, target_group_id)
  WHERE status IN ('pending', 'running') AND target_id IS NULL
    AND (plan_snapshot->'target_ids' IS NULL OR plan_snapshot->'target_ids' = '[]'::jsonb);

CREATE TABLE validation_scan_target_slots (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_id TEXT NOT NULL,
  scan_id TEXT NOT NULL,
  PRIMARY KEY (tenant_id, target_id),
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets(tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, scan_id) REFERENCES validation_scans(tenant_id, id) ON DELETE CASCADE
);
ALTER TABLE validation_scan_target_slots ENABLE ROW LEVEL SECURITY;
ALTER TABLE validation_scan_target_slots FORCE ROW LEVEL SECURITY;
CREATE POLICY validation_scan_target_slots_tenant_isolation ON validation_scan_target_slots
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

INSERT INTO validation_scan_target_slots(tenant_id, target_id, scan_id)
SELECT DISTINCT step.tenant_id, step.target_id, step.scan_id FROM validation_scan_steps step
JOIN validation_scans scan ON scan.tenant_id = step.tenant_id AND scan.id = step.scan_id
WHERE scan.status IN ('pending', 'running');

CREATE FUNCTION reserve_validation_scan_targets() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE selected TEXT; incumbent TEXT;
BEGIN
  DELETE FROM validation_scan_target_slots WHERE tenant_id = NEW.tenant_id AND scan_id = NEW.id;
  IF NEW.status NOT IN ('pending', 'running') THEN RETURN NEW; END IF;
  FOR selected IN
    SELECT DISTINCT value FROM (
      SELECT jsonb_array_elements_text(CASE WHEN jsonb_typeof(NEW.plan_snapshot->'target_ids') = 'array'
        THEN NEW.plan_snapshot->'target_ids' ELSE '[]'::jsonb END) AS value
      UNION SELECT NEW.target_id WHERE NEW.target_id IS NOT NULL
      UNION SELECT target_id FROM validation_scan_steps WHERE tenant_id = NEW.tenant_id AND scan_id = NEW.id
    ) scope ORDER BY value
  LOOP
    PERFORM pg_advisory_xact_lock(hashtextextended('target_execution:' || NEW.tenant_id || ':' || selected, 0));
    IF EXISTS (SELECT 1 FROM test_runs WHERE tenant_id = NEW.tenant_id AND target_id = selected
      AND status IN ('planned', 'running', 'collecting') AND scan_id IS DISTINCT FROM NEW.id) THEN
      RAISE EXCEPTION 'Target already has an active run' USING ERRCODE = '23505', CONSTRAINT = 'uniq_active_validation_scan_target';
    END IF;
    INSERT INTO validation_scan_target_slots(tenant_id, target_id, scan_id) VALUES (NEW.tenant_id, selected, NEW.id)
      ON CONFLICT (tenant_id, target_id) DO NOTHING;
    SELECT scan_id INTO incumbent FROM validation_scan_target_slots WHERE tenant_id = NEW.tenant_id AND target_id = selected;
    IF incumbent IS DISTINCT FROM NEW.id THEN
      RAISE EXCEPTION 'Target already has an active scan' USING ERRCODE = '23505', CONSTRAINT = 'uniq_active_validation_scan_target';
    END IF;
  END LOOP;
  RETURN NEW;
END;
$$;
CREATE TRIGGER validation_scans_target_slots AFTER INSERT OR UPDATE OF status, target_id, plan_snapshot ON validation_scans
  FOR EACH ROW EXECUTE FUNCTION reserve_validation_scan_targets();

CREATE FUNCTION guard_run_target_slot() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.target_id IS NULL OR NEW.status NOT IN ('planned', 'running', 'collecting') THEN RETURN NEW; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('target_execution:' || NEW.tenant_id || ':' || NEW.target_id, 0));
  IF EXISTS (SELECT 1 FROM validation_scan_target_slots WHERE tenant_id = NEW.tenant_id AND target_id = NEW.target_id
    AND scan_id IS DISTINCT FROM NEW.scan_id) THEN
    RAISE EXCEPTION 'Target reserved by another validation scan' USING ERRCODE = '23505', CONSTRAINT = 'uniq_active_test_run';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER test_runs_target_slot_guard BEFORE INSERT OR UPDATE OF status ON test_runs
  FOR EACH ROW EXECUTE FUNCTION guard_run_target_slot();
