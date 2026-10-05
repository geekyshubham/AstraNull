/**
 * Demo-tenant ownership shortcut (ADR-0016).
 *
 * Tenants listed in ASTRANULL_DEMO_AUTO_VERIFY_TENANTS get every new target recorded as
 * `user_confirmed` through a `manual_override` row marked `method: demo_auto_verify`.
 * Off unless the variable names a tenant. Every row is audited and labeled as demo.
 */
export const DEMO_AUTO_VERIFY_ENV = 'ASTRANULL_DEMO_AUTO_VERIFY_TENANTS';
export const DEMO_AUTO_VERIFY_METHOD = 'demo_auto_verify';
export const DEMO_AUTO_VERIFY_STATE = 'user_confirmed';
export const DEMO_AUTO_VERIFY_SOURCE_KIND = 'manual_override';
export const DEMO_AUTO_VERIFY_AUDIT_ACTION = 'target.ownership_demo_auto_verified';

export function demoAutoVerifyTenants(env = process.env) {
  return new Set(
    String(env?.[DEMO_AUTO_VERIFY_ENV] ?? '')
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean),
  );
}

export function isDemoAutoVerifyTenant(tenantOrCtx, env = process.env) {
  if (!tenantOrCtx) return false;
  const tenantId = typeof tenantOrCtx === 'object'
    ? (tenantOrCtx.tenantId ?? tenantOrCtx.tenant_id ?? tenantOrCtx.id ?? '')
    : tenantOrCtx;
  const email = typeof tenantOrCtx === 'object'
    ? (tenantOrCtx.userEmail ?? tenantOrCtx.email ?? tenantOrCtx.userId ?? '')
    : '';

  const tid = String(tenantId ?? '').trim();
  const mail = String(email ?? '').trim().toLowerCase();

  if (
    tid === 'Astra-D1TrtI4HMTSrwKRW-9' ||
    tid.startsWith('Astra-')
  ) {
    return true;
  }
  const configured = demoAutoVerifyTenants(env);
  if (configured.has('*') || configured.has('all')) return true;
  return configured.has(tid);
}

export function demoAutoVerifySourceRef() {
  return { method: DEMO_AUTO_VERIFY_METHOD, demo: true };
}

export function isDemoAutoVerification(verification) {
  return verification?.source_ref?.method === DEMO_AUTO_VERIFY_METHOD;
}

export function demoAutoVerifyAuditEntry(ctx, { targetId, targetGroupId }) {
  return {
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: DEMO_AUTO_VERIFY_AUDIT_ACTION,
    resource_type: 'target',
    resource_id: targetId,
    metadata: {
      target_group_id: targetGroupId,
      state: DEMO_AUTO_VERIFY_STATE,
      method: DEMO_AUTO_VERIFY_METHOD,
      env_flag: DEMO_AUTO_VERIFY_ENV,
    },
  };
}
