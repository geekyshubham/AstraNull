-- 0041_break_glass_activations.sql
-- Durable break-glass activation state.
--
-- Problem: activations lived only in module-level process memory (src/services/breakGlass.mjs),
-- so an emergency-access declaration vanished on restart and was invisible to every other
-- worker/instance. Two workers could each report "no active break-glass" while an operator
-- believed one was open, and the status endpoint answered from whichever process happened to
-- serve the request.
--
-- Platform-level, NOT tenant-scoped: a break-glass activation is declared by staff about the
-- platform, has no owning tenant, and therefore carries no tenant_id. Consistent with the
-- other platform tables (staff_users, signup_requests, platform_metrics), RLS is deliberately
-- NOT enabled: there is no tenant column to isolate on, and per-tenant policies keyed to a
-- non-existent column would be meaningless. Reads/writes go through withPlatformScope(), which
-- pins app.tenant_id empty, so no tenant-scoped request path touches this table.
--
-- Reporting-only: rows here are an audit/reporting record of a declared emergency. Nothing in
-- the authorization path consults this table, and no column grants elevated access.
--
-- The partial unique index enforces the supersede invariant (at most one 'active' row) in the
-- database rather than trusting application sequencing: two concurrent activations that both
-- try to insert an 'active' row cannot both commit.

CREATE TABLE IF NOT EXISTS break_glass_activations (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'active',
  reason TEXT,
  ticket_reference TEXT NOT NULL,
  activated_by TEXT,
  activated_role TEXT,
  activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  duration_minutes INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_break_glass_activations_activated_at
  ON break_glass_activations(activated_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_break_glass_activations_single_active
  ON break_glass_activations(status)
  WHERE status = 'active';
