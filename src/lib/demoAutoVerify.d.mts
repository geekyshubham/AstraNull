export declare const DEMO_AUTO_VERIFY_ENV: string;
export declare const DEMO_AUTO_VERIFY_METHOD: string;
export declare const DEMO_AUTO_VERIFY_STATE: string;
export declare const DEMO_AUTO_VERIFY_SOURCE_KIND: string;
export declare const DEMO_AUTO_VERIFY_AUDIT_ACTION: string;
export declare const DEMO_ACCOUNT_TENANT_ID: string;
export declare const DEMO_ADMIN_EMAIL: string;
export declare const DEMO_LOGIN_TENANT_ID: string;
export declare const DEMO_LOGIN_USER_ID: string;
export declare const DEMO_MAX_RUNS_PER_HOUR_ENV: string;
export declare const DEFAULT_DEMO_MAX_RUNS_PER_HOUR: number;
export declare const MAX_DEMO_MAX_RUNS_PER_HOUR: number;

type DemoIdentity = string | {
  tenantId?: string;
  tenant_id?: string;
  id?: string;
  userId?: string;
  user_id?: string;
  email?: string;
  user?: { email?: string };
  principal?: string | { email?: string };
} | null | undefined;

export declare function matchesDemoAccount(tenantOrCtx: DemoIdentity): boolean;
export declare function demoAutoVerifyTenants(env?: Record<string, string | undefined>): Set<string>;
export declare function isDemoAutoVerifyTenant(tenantOrCtx: DemoIdentity, env?: Record<string, string | undefined>): boolean;
export declare function isExplicitDemoTenant(tenantOrCtx: DemoIdentity, env?: Record<string, string | undefined>): boolean;
export declare function warnIfDemoAutoVerifyWildcard(
  env?: Record<string, string | undefined>,
  logger?: { warn?: (message: string) => void },
): boolean;
export declare function demoAutoVerifySourceRef(): { method: string; demo: boolean };
export declare function isDemoAutoVerification(verification: { source_ref?: { method?: string } } | null | undefined): boolean;
export declare function demoAutoVerifyAuditEntry(
  ctx: { tenantId?: string; userId?: string; role?: string },
  input: { targetId: string; targetGroupId: string },
): Record<string, unknown>;
export declare function demoMaxRunsPerHour(env?: Record<string, string | undefined>): number;
