-- 0042_user_password_credentials.sql
-- Password credentials and one-time setup invites for customer portal users.
--
-- Passwords are stored only as encoded scrypt hashes. Invite tokens are high-entropy secrets
-- returned once; only their SHA-256 digest is persisted. Both tables are tenant scoped and FORCE
-- RLS. The extra composite foreign keys make tenant_id agree with the referenced users row rather
-- than trusting application code to maintain that invariant.
--
-- Invite redemption begins before a tenant is known. The additive SELECT policy exposes only the
-- row whose token_hash exactly matches the transaction-local lookup hash; it does not expose
-- credential rows or provide any write authority. Ordinary reads and every mutation still require
-- app.tenant_id through the tenant-isolation policies below.

CREATE TABLE IF NOT EXISTS user_credentials (
  user_id              TEXT PRIMARY KEY,
  tenant_id            TEXT NOT NULL REFERENCES tenants(id),
  password_hash        TEXT NOT NULL,
  password_updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  must_change          BOOLEAN NOT NULL DEFAULT FALSE,
  failed_attempts      INT NOT NULL DEFAULT 0,
  locked_until         TIMESTAMPTZ,
  last_login_at        TIMESTAMPTZ,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_password_invites (
  id           TEXT PRIMARY KEY,
  tenant_id    TEXT NOT NULL REFERENCES tenants(id),
  user_id      TEXT NOT NULL,
  token_hash   TEXT NOT NULL,
  expires_at   TIMESTAMPTZ NOT NULL,
  consumed_at  TIMESTAMPTZ,
  created_by   TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_user_credentials_user_tenant'
  ) THEN
    ALTER TABLE user_credentials ADD CONSTRAINT fk_user_credentials_user_tenant
      FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_user_password_invites_user_tenant'
  ) THEN
    ALTER TABLE user_password_invites ADD CONSTRAINT fk_user_password_invites_user_tenant
      FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_user_password_invites_token_hash
  ON user_password_invites(token_hash);

ALTER TABLE user_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE user_password_invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_password_invites FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS user_credentials_tenant_isolation ON user_credentials;
CREATE POLICY user_credentials_tenant_isolation ON user_credentials
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS user_password_invites_tenant_isolation ON user_password_invites;
CREATE POLICY user_password_invites_tenant_isolation ON user_password_invites
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS user_password_invites_token_lookup ON user_password_invites;
CREATE POLICY user_password_invites_token_lookup ON user_password_invites
  FOR SELECT
  USING (
    coalesce(current_setting('app.tenant_id', true), '') = ''
    AND token_hash = current_setting('app.password_invite_token_hash', true)
  );
