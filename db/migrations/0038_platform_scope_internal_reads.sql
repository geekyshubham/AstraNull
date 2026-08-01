-- 0038_platform_scope_internal_reads.sql
-- Staff-console (platform-scope) reads of internal management tables.
--
-- Problem: staff-scope reads (listInternalAudit, listTenants, getInternalOverview)
-- query FORCE-RLS tables with no app.tenant_id set. current_setting('app.tenant_id', true)
-- returns NULL, so `tenant_id = NULL` is NULL (not true) and every tenant-attributed row is
-- dropped. The staff console therefore showed an incomplete audit trail, zero tenants, and
-- zero/undercounted overview metrics.
--
-- Fix: an explicit, transaction-local `app.platform_scope` setting honoured by additive
-- SELECT-only permissive policies. Set only by withPlatformScope() via
-- set_config('app.platform_scope', 'on', true) so it can never outlive its transaction or
-- leak across pooled connections.
--
-- Fail-closed and tenant-exclusive by construction:
--   * unset setting -> coalesce(... = 'on', false) -> false -> no extra rows.
--   * the policy additionally requires app.tenant_id to be UNSET, so a tenant-scoped
--     connection can never gain platform scope even if the setting were somehow present.
--     withTenantContext() always sets a non-empty app.tenant_id, so tenant-scoped request
--     paths are structurally excluded.
--   * SELECT-only: writes remain governed solely by the existing tenant-isolation policies,
--     so platform scope grants no write amplification.
--
-- These policies are PERMISSIVE and therefore OR-ed with the existing tenant_isolation_*
-- policies. Tenant isolation is unchanged: with platform scope absent the new policies
-- contribute nothing.

DROP POLICY IF EXISTS platform_scope_read_tenants ON tenants;
CREATE POLICY platform_scope_read_tenants ON tenants
  FOR SELECT
  USING (
    coalesce(current_setting('app.platform_scope', true) = 'on', false)
    AND coalesce(current_setting('app.tenant_id', true), '') = ''
  );

DROP POLICY IF EXISTS platform_scope_read_users ON users;
CREATE POLICY platform_scope_read_users ON users
  FOR SELECT
  USING (
    coalesce(current_setting('app.platform_scope', true) = 'on', false)
    AND coalesce(current_setting('app.tenant_id', true), '') = ''
  );

DROP POLICY IF EXISTS platform_scope_read_tenant_accounts ON tenant_accounts;
CREATE POLICY platform_scope_read_tenant_accounts ON tenant_accounts
  FOR SELECT
  USING (
    coalesce(current_setting('app.platform_scope', true) = 'on', false)
    AND coalesce(current_setting('app.tenant_id', true), '') = ''
  );

DROP POLICY IF EXISTS platform_scope_read_tenant_subscriptions ON tenant_subscriptions;
CREATE POLICY platform_scope_read_tenant_subscriptions ON tenant_subscriptions
  FOR SELECT
  USING (
    coalesce(current_setting('app.platform_scope', true) = 'on', false)
    AND coalesce(current_setting('app.tenant_id', true), '') = ''
  );

DROP POLICY IF EXISTS platform_scope_read_internal_approval_requests ON internal_approval_requests;
CREATE POLICY platform_scope_read_internal_approval_requests ON internal_approval_requests
  FOR SELECT
  USING (
    coalesce(current_setting('app.platform_scope', true) = 'on', false)
    AND coalesce(current_setting('app.tenant_id', true), '') = ''
  );

DROP POLICY IF EXISTS platform_scope_read_internal_audit_log ON internal_audit_log;
CREATE POLICY platform_scope_read_internal_audit_log ON internal_audit_log
  FOR SELECT
  USING (
    coalesce(current_setting('app.platform_scope', true) = 'on', false)
    AND coalesce(current_setting('app.tenant_id', true), '') = ''
  );
