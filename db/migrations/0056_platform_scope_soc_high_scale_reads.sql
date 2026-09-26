-- 0056_platform_scope_soc_high_scale_reads.sql
-- Staff SOC console lists governed high-scale requests across tenants (GET /internal/admin/soc/high-scale-requests).
-- Same fail-closed contract as 0038: SELECT-only, requires transaction-local app.platform_scope=on and an unset app.tenant_id.

DROP POLICY IF EXISTS platform_scope_read_high_scale_requests ON high_scale_requests;
CREATE POLICY platform_scope_read_high_scale_requests ON high_scale_requests
  FOR SELECT
  USING (
    coalesce(current_setting('app.platform_scope', true) = 'on', false)
    AND coalesce(current_setting('app.tenant_id', true), '') = ''
  );
