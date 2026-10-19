import { isExplicitDemoTenant, matchesDemoAccount } from '../lib/demoAutoVerify.mjs';
import { originCluesEnabledFor } from '../lib/originClues.mjs';
import {
  connectorsEnabledFor,
  externalDiscoveryEnabledFor,
  protectionValidationEnabledFor,
  wafPostureEnabledFor,
} from '../lib/tenantFeatureAccess.mjs';

// Tenant-scoped deployment feature flags for authenticated portal UI.
export function getTenantDeploymentFeatures(ctx, runtimeConfig) {
  const isDemo = isExplicitDemoTenant(ctx);
  return {
    demo_tenant: isDemo,
    all_checks_customer_runnable: matchesDemoAccount(ctx),
    waf_posture: wafPostureEnabledFor(runtimeConfig, ctx?.tenantId),
    external_discovery: externalDiscoveryEnabledFor(runtimeConfig, ctx?.tenantId),
    connectors: connectorsEnabledFor(runtimeConfig, ctx?.tenantId),
    protection_validation: protectionValidationEnabledFor(runtimeConfig, ctx?.tenantId),
    origin_clues: originCluesEnabledFor(runtimeConfig, ctx?.tenantId),
  };
}

// Entry-path validation and firewall change acceptance; the global off switch also covers demo tenants.
export function isProtectionValidationEnabled(ctx, runtimeConfig) {
  return protectionValidationEnabledFor(runtimeConfig, ctx?.tenantId);
}
