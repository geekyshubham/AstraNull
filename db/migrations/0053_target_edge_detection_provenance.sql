-- Bind every durable edge detection to one coherent tenant + run + target + group tuple.
--
-- 0052 originally installed only independent tenant-scoped foreign keys. Those keys proved that
-- each referenced row existed, but not that the target belonged to the recorded group or that the
-- run was for that exact target/group. This additive migration hardens databases that already
-- applied that version. It never rewrites or deletes historical rows: malformed provenance aborts
-- the migration and leaves both data and trust constraints unchanged.

SET LOCAL lock_timeout = '15s';
SET LOCAL statement_timeout = '5min';

LOCK TABLE target_edge_detections, test_runs, targets IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM target_edge_detections edge
    LEFT JOIN targets target
      ON target.tenant_id = edge.tenant_id
     AND target.target_group_id = edge.target_group_id
     AND target.id = edge.target_id
    LEFT JOIN test_runs run
      ON run.tenant_id = edge.tenant_id
     AND run.id = edge.test_run_id
     AND run.target_group_id = edge.target_group_id
     AND run.target_id = edge.target_id
    WHERE edge.test_run_id IS NULL
       OR target.id IS NULL
       OR run.id IS NULL
  ) THEN
    RAISE EXCEPTION 'preexisting target edge detection provenance is malformed'
      USING ERRCODE = '23514',
            CONSTRAINT = 'target_edge_detections_provenance_binding';
  END IF;
END;
$$;

ALTER TABLE target_edge_detections
  ALTER COLUMN test_run_id SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = 'targets'::regclass
      AND conname = 'targets_tenant_group_id_key'
  ) THEN
    ALTER TABLE targets
      ADD CONSTRAINT targets_tenant_group_id_key
      UNIQUE (tenant_id, target_group_id, id);
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = 'test_runs'::regclass
      AND conname = 'test_runs_tenant_run_group_target_key'
  ) THEN
    ALTER TABLE test_runs
      ADD CONSTRAINT test_runs_tenant_run_group_target_key
      UNIQUE (tenant_id, id, target_group_id, target_id);
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = 'target_edge_detections'::regclass
      AND conname = 'fk_target_edge_detections_target_binding'
  ) THEN
    ALTER TABLE target_edge_detections
      ADD CONSTRAINT fk_target_edge_detections_target_binding
      FOREIGN KEY (tenant_id, target_group_id, target_id)
      REFERENCES targets (tenant_id, target_group_id, id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = 'target_edge_detections'::regclass
      AND conname = 'fk_target_edge_detections_run_binding'
  ) THEN
    ALTER TABLE target_edge_detections
      ADD CONSTRAINT fk_target_edge_detections_run_binding
      FOREIGN KEY (tenant_id, test_run_id, target_group_id, target_id)
      REFERENCES test_runs (tenant_id, id, target_group_id, target_id)
      NOT VALID;
  END IF;
END;
$$;

ALTER TABLE target_edge_detections
  VALIDATE CONSTRAINT fk_target_edge_detections_target_binding;
ALTER TABLE target_edge_detections
  VALIDATE CONSTRAINT fk_target_edge_detections_run_binding;
