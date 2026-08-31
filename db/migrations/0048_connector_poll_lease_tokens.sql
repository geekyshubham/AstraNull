-- Replace round-tripped timestamptz lease identity with an opaque database-issued token.
-- Existing live leases cannot safely cross this protocol boundary, so cancel them fail-closed.

SET LOCAL lock_timeout = '15s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE connector_poll_jobs
  ADD COLUMN IF NOT EXISTS lease_token TEXT;

UPDATE connector_poll_jobs
SET status = 'cancelled',
    completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP),
    error_code = COALESCE(error_code, 'lease_protocol_upgraded'),
    leased_by = NULL,
    leased_at = NULL,
    lease_token = NULL,
    updated_at = CURRENT_TIMESTAMP
WHERE status = 'leased';

UPDATE connector_poll_jobs
SET leased_by = NULL,
    leased_at = NULL,
    lease_token = NULL
WHERE status <> 'leased'
  AND (leased_by IS NOT NULL OR leased_at IS NOT NULL OR lease_token IS NOT NULL);

ALTER TABLE connector_poll_jobs
  DROP CONSTRAINT IF EXISTS connector_poll_jobs_lease_shape;

ALTER TABLE connector_poll_jobs
  ADD CONSTRAINT connector_poll_jobs_lease_shape CHECK (
    (status = 'leased' AND leased_by IS NOT NULL AND leased_at IS NOT NULL AND lease_token IS NOT NULL)
    OR
    (status <> 'leased' AND leased_by IS NULL AND leased_at IS NULL AND lease_token IS NULL)
  );
