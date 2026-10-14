-- Fix-verified findings record the verification basis for why the finding was verified closed.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS verification_basis TEXT;

COMMENT ON COLUMN findings.verification_basis IS
  'Basis on which a finding was verified closed (e.g. violation_not_reproduced).';
