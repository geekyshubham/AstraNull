-- Informational telemetry is isolated from verdict evidence and is worker-only.
ALTER TABLE events ADD CONSTRAINT events_probe_activity_producer_check CHECK (
  signal_type IS DISTINCT FROM 'probe_activity' OR producer_kind = 'signed_probe'
);
