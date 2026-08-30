-- 0043_password_resets_and_mfa.sql
-- BE-019 closeout: self-service password resets and TOTP conditional access.
--
-- Password reset tokens are high-entropy one-time secrets; only their SHA-256 digest is
-- persisted. TOTP seeds are persisted only as authenticated secret envelopes produced by
-- src/lib/secrets.mjs (or its KMS-backed replacement), never as plaintext. session_generation
-- is incremented whenever password or MFA state changes so locally minted password sessions can
-- be rejected after a credential mutation.

ALTER TABLE user_credentials
  ADD COLUMN IF NOT EXISTS session_generation   BIGINT NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS mfa_secret_envelope  JSONB,
  ADD COLUMN IF NOT EXISTS mfa_enrollment_id    TEXT,
  ADD COLUMN IF NOT EXISTS mfa_enrolled_at      TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS mfa_last_step        BIGINT,
  ADD COLUMN IF NOT EXISTS mfa_pending_at       TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS mfa_disabled_at      TIMESTAMPTZ;

-- An earlier local-only draft used this plaintext column. If it exists, invalidate affected
-- credentials before discarding it. Password recovery or a staff-issued invitation is then
-- required; silently downgrading an enrolled account to password-only would fail open.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'user_credentials'
      AND column_name = 'mfa_secret'
  ) THEN
    EXECUTE $cleanup$
      UPDATE user_credentials
      SET must_change = TRUE,
          session_generation = session_generation + 1,
          mfa_secret_envelope = NULL,
          mfa_enrollment_id = NULL,
          mfa_enrolled_at = NULL,
          mfa_last_step = NULL,
          mfa_pending_at = NULL,
          mfa_disabled_at = NOW()
      WHERE mfa_secret IS NOT NULL
    $cleanup$;
  END IF;
END $$;

ALTER TABLE user_credentials DROP COLUMN IF EXISTS mfa_secret;

-- If the unreleased plaintext draft was exercised locally, dropping its seed leaves unusable
-- enrollment metadata behind. Invalidate those credentials before enforcing the invariant.
UPDATE user_credentials
SET must_change = TRUE,
    session_generation = session_generation + 1,
    mfa_enrollment_id = NULL,
    mfa_enrolled_at = NULL,
    mfa_last_step = NULL,
    mfa_pending_at = NULL,
    mfa_disabled_at = NOW()
WHERE mfa_secret_envelope IS NULL
  AND (
    mfa_enrollment_id IS NOT NULL
    OR mfa_enrolled_at IS NOT NULL
    OR mfa_last_step IS NOT NULL
    OR mfa_pending_at IS NOT NULL
  );

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'user_credentials_session_generation_positive'
  ) THEN
    ALTER TABLE user_credentials ADD CONSTRAINT user_credentials_session_generation_positive
      CHECK (session_generation > 0);
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'user_credentials_mfa_state_consistent'
  ) THEN
    ALTER TABLE user_credentials ADD CONSTRAINT user_credentials_mfa_state_consistent CHECK (
      (
        mfa_secret_envelope IS NULL
        AND mfa_enrollment_id IS NULL
        AND mfa_enrolled_at IS NULL
        AND mfa_pending_at IS NULL
        AND mfa_last_step IS NULL
      )
      OR
      (
        jsonb_typeof(mfa_secret_envelope) = 'object'
        AND mfa_enrollment_id IS NOT NULL
        AND (
          (mfa_enrolled_at IS NULL AND mfa_pending_at IS NOT NULL AND mfa_last_step IS NULL)
          OR
          (
            mfa_enrolled_at IS NOT NULL
            AND mfa_pending_at IS NULL
            AND mfa_last_step IS NOT NULL
            AND mfa_last_step >= 0
          )
        )
      )
    );
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS user_password_resets (
  id           TEXT PRIMARY KEY,
  tenant_id    TEXT NOT NULL REFERENCES tenants(id),
  user_id      TEXT NOT NULL,
  token_hash   TEXT NOT NULL,
  expires_at   TIMESTAMPTZ NOT NULL,
  consumed_at  TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_user_password_resets_user_tenant'
  ) THEN
    ALTER TABLE user_password_resets ADD CONSTRAINT fk_user_password_resets_user_tenant
      FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE;
  END IF;
END $$;

DROP INDEX IF EXISTS idx_user_password_resets_token_hash;
CREATE UNIQUE INDEX idx_user_password_resets_token_hash
  ON user_password_resets(token_hash);

ALTER TABLE user_password_resets ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_password_resets FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS user_password_resets_tenant_isolation ON user_password_resets;
CREATE POLICY user_password_resets_tenant_isolation ON user_password_resets
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- Additive pre-tenant lookup: exposes only the row whose token_hash exactly matches the
-- transaction-local lookup hash. No credential rows and no write authority.
DROP POLICY IF EXISTS user_password_resets_token_lookup ON user_password_resets;
CREATE POLICY user_password_resets_token_lookup ON user_password_resets
  FOR SELECT
  USING (
    coalesce(current_setting('app.tenant_id', true), '') = ''
    AND token_hash = current_setting('app.password_reset_token_hash', true)
  );


-- Delivery is a transactional outbox: only an authenticated AES-256-GCM envelope is stored.
-- Plaintext recipient addresses and reset tokens must never be columns or query parameters.
CREATE TABLE IF NOT EXISTS password_recovery_delivery_outbox (
  id                TEXT PRIMARY KEY,
  tenant_id         TEXT NOT NULL REFERENCES tenants(id),
  user_id           TEXT NOT NULL,
  idempotency_key   TEXT NOT NULL,
  kind              TEXT NOT NULL DEFAULT 'password_reset',
  envelope          JSONB NOT NULL,
  status            TEXT NOT NULL DEFAULT 'queued',
  attempt_count     INTEGER NOT NULL DEFAULT 0,
  max_attempts      INTEGER NOT NULL DEFAULT 5,
  next_attempt_at   TIMESTAMPTZ DEFAULT NOW(),
  lease_expires_at  TIMESTAMPTZ,
  last_error_code   TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  delivered_at      TIMESTAMPTZ,
  CONSTRAINT password_recovery_delivery_outbox_user_fk
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT password_recovery_delivery_outbox_idempotency
    UNIQUE (tenant_id, kind, idempotency_key),
  CONSTRAINT password_recovery_delivery_outbox_kind_check
    CHECK (kind = 'password_reset'),
  CONSTRAINT password_recovery_delivery_outbox_envelope_check CHECK (
    jsonb_typeof(envelope) = 'object'
    AND envelope ->> 'algorithm' = 'AES-256-GCM'
    AND envelope ->> 'version' = '1'
    AND jsonb_typeof(envelope -> 'iv') = 'string'
    AND jsonb_typeof(envelope -> 'ciphertext') = 'string'
    AND jsonb_typeof(envelope -> 'auth_tag') = 'string'
    AND NOT (envelope ? 'email')
    AND NOT (envelope ? 'reset_token')
  ),
  CONSTRAINT password_recovery_delivery_outbox_status_check
    CHECK (status IN ('queued', 'leased', 'retry', 'delivered', 'dead')),
  CONSTRAINT password_recovery_delivery_outbox_attempts_check
    CHECK (attempt_count >= 0 AND max_attempts BETWEEN 1 AND 10 AND attempt_count <= max_attempts),
  CONSTRAINT password_recovery_delivery_outbox_error_code_check
    CHECK (last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 128),
  CONSTRAINT password_recovery_delivery_outbox_state_check CHECK (
    (status IN ('queued', 'retry') AND next_attempt_at IS NOT NULL
      AND lease_expires_at IS NULL AND delivered_at IS NULL)
    OR (status = 'leased' AND lease_expires_at IS NOT NULL AND delivered_at IS NULL)
    OR (status = 'delivered' AND next_attempt_at IS NULL
      AND lease_expires_at IS NULL AND delivered_at IS NOT NULL)
    OR (status = 'dead' AND next_attempt_at IS NULL
      AND lease_expires_at IS NULL AND delivered_at IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_password_recovery_delivery_outbox_due
  ON password_recovery_delivery_outbox(tenant_id, next_attempt_at, created_at)
  WHERE status IN ('queued', 'retry');
CREATE INDEX IF NOT EXISTS idx_password_recovery_delivery_outbox_expired_lease
  ON password_recovery_delivery_outbox(tenant_id, lease_expires_at)
  WHERE status = 'leased';

ALTER TABLE password_recovery_delivery_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_recovery_delivery_outbox FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS password_recovery_delivery_outbox_tenant_isolation
  ON password_recovery_delivery_outbox;
CREATE POLICY password_recovery_delivery_outbox_tenant_isolation
  ON password_recovery_delivery_outbox
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
