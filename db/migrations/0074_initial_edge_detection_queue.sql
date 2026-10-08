CREATE TABLE target_initial_edge_detections (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'leased', 'dispatched', 'cancelled')),
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  blocked_reason TEXT,
  test_run_id TEXT,
  lease_token TEXT,
  lease_expires_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, target_id),
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets(tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs(tenant_id, id)
);
CREATE INDEX idx_initial_edge_detection_due ON target_initial_edge_detections(tenant_id, next_attempt_at, target_id)
  WHERE status IN ('queued', 'leased');
ALTER TABLE target_initial_edge_detections ENABLE ROW LEVEL SECURITY;
ALTER TABLE target_initial_edge_detections FORCE ROW LEVEL SECURITY;
CREATE POLICY target_initial_edge_detections_tenant_isolation ON target_initial_edge_detections
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE FUNCTION queue_initial_target_edge_detection() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.kind IN ('fqdn', 'url') THEN
    INSERT INTO target_initial_edge_detections(tenant_id, target_id, requested_at, next_attempt_at)
      VALUES (NEW.tenant_id, NEW.id, COALESCE(NEW.created_at, now()), now()) ON CONFLICT DO NOTHING;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER targets_queue_initial_edge_detection AFTER INSERT ON targets
  FOR EACH ROW EXECUTE FUNCTION queue_initial_target_edge_detection();

-- Existing domains without an accepted edge observation also receive an initial request.
INSERT INTO target_initial_edge_detections(tenant_id, target_id)
SELECT target.tenant_id, target.id FROM targets target
WHERE target.kind IN ('fqdn', 'url') AND target.deleted_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM target_edge_detections edge WHERE edge.tenant_id = target.tenant_id AND edge.target_id = target.id)
ON CONFLICT DO NOTHING;
