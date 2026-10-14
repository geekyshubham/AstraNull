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

export const DEMO_ACCOUNT_TENANT_ID = 'Astra-D1TrtI4HMTSrwKRW-9';
export const DEMO_ADMIN_EMAIL = 'admin@demo.astranull.local';
export const DEMO_ADMIN_USER_ID = 'usr_admin';

export function matchesDemoAccount(tenantOrCtx, env = process.env) {
  if (!tenantOrCtx) return false;
  if (typeof tenantOrCtx === 'string') {
    const s = tenantOrCtx.trim();
    return s === DEMO_ACCOUNT_TENANT_ID || s === DEMO_ADMIN_EMAIL;
  }
  if (typeof tenantOrCtx === 'object') {
    const tid = String(tenantOrCtx.tenantId ?? tenantOrCtx.tenant_id ?? tenantOrCtx.id ?? '').trim();
    if (tid === DEMO_ACCOUNT_TENANT_ID) return true;
    const uid = String(tenantOrCtx.userId ?? tenantOrCtx.user_id ?? '').trim();
    if (uid === DEMO_ADMIN_EMAIL || uid === DEMO_ACCOUNT_TENANT_ID) return true;
    const email = String(tenantOrCtx.email ?? tenantOrCtx.user?.email ?? tenantOrCtx.principal?.email ?? '').trim();
    if (email === DEMO_ADMIN_EMAIL) return true;
    if (uid === DEMO_ADMIN_USER_ID && (!tid || tid === 'ten_demo' || demoAutoVerifyTenants(env).has(tid))) return true;
  }
  return false;
}

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
  if (typeof tenantOrCtx === 'number') return false;
  if (matchesDemoAccount(tenantOrCtx)) return true;
  const tenantId = typeof tenantOrCtx === 'object'
    ? (tenantOrCtx.tenantId ?? tenantOrCtx.tenant_id ?? tenantOrCtx.id ?? '')
    : tenantOrCtx;
  const tid = String(tenantId ?? '').trim();
  if (!tid) return false;
  const configured = demoAutoVerifyTenants(env);
  if (configured.has('*') || configured.has('all')) return true;
  return configured.has(tid);
}

export function isExplicitDemoTenant(tenantOrCtx, env = process.env) {
  if (!tenantOrCtx) return false;
  if (typeof tenantOrCtx === 'number') return false;
  if (matchesDemoAccount(tenantOrCtx)) return true;
  const tenantId = typeof tenantOrCtx === 'object'
    ? (tenantOrCtx.tenantId ?? tenantOrCtx.tenant_id ?? tenantOrCtx.id ?? '')
    : tenantOrCtx;
  const tid = String(tenantId ?? '').trim();
  if (!tid || tid === '*' || tid === 'all') return false;
  return demoAutoVerifyTenants(env).has(tid);
}

export function warnIfDemoAutoVerifyWildcard(env = process.env, logger = console) {
  const configured = demoAutoVerifyTenants(env);
  if (configured.has('*') || configured.has('all')) {
    logger?.warn?.(
      `[demoAutoVerify] Wildcard configured in ${DEMO_AUTO_VERIFY_ENV}; only ownership/subscription bypasses will apply globally, new demo gates require explicit tenant IDs`,
    );
    return true;
  }
  return false;
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

// Hourly safe-run cap for demo tenants (ADR-0016 amendment - dropped by default).
export const DEMO_MAX_RUNS_PER_HOUR_ENV = 'ASTRANULL_DEMO_MAX_RUNS_PER_HOUR';
export const DEFAULT_DEMO_MAX_RUNS_PER_HOUR = Infinity;
export const MAX_DEMO_MAX_RUNS_PER_HOUR = 5000;

export function demoMaxRunsPerHour(env = process.env) {
  const raw = env?.[DEMO_MAX_RUNS_PER_HOUR_ENV];
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return DEFAULT_DEMO_MAX_RUNS_PER_HOUR;
  }
  const parsed = Number.parseInt(String(raw).trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return DEFAULT_DEMO_MAX_RUNS_PER_HOUR;
  }
  return Math.min(parsed, MAX_DEMO_MAX_RUNS_PER_HOUR);
}

