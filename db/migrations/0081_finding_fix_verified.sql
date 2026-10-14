-- Fix-verified findings record the verifying run and the versions that closed them.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS verifying_run_id TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS check_version TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS grading_version TEXT;

COMMENT ON COLUMN findings.verifying_run_id IS
  'Test run that moved an open/in_progress finding to fix_verified. Null until a complete passing retest.';
