-- 0039_users_metadata_json.sql
-- Add the missing users.metadata_json column.
--
-- Defect found while adding live-DB coverage for signup approval provisioning: the Postgres
-- internal-management repository has always written and read users.metadata_json
--   * INSERT INTO users (..., metadata_json, ...)   (tenant provisioning from signup)
--   * UPDATE users SET status='invited',  metadata_json = $3::jsonb   (resend owner invite)
--   * UPDATE users SET status='disabled', metadata_json = $3::jsonb   (disable tenant user)
--   * mapUser() reads metadata_json.invited_at / metadata_json.disabled_at
-- but no migration (and not db/schema.sql) ever created the column, so every one of those
-- statements failed with 42703 "column metadata_json of relation users does not exist".
-- Postgres-mode tenant provisioning from an approved signup could therefore never complete.
--
-- Additive and idempotent: JSONB defaulting to '{}' matches how mapUser() treats a missing
-- object, so existing rows read back exactly as before.

ALTER TABLE users ADD COLUMN IF NOT EXISTS metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb;
