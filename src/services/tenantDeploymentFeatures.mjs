import { isExplicitDemoTenant } from '../lib/demoAutoVerify.mjs';
import {
  connectorsEnabledFor,
  externalDiscoveryEnabledFor,
  protectionValidationEnabledFor,
  wafPostureEnabledFor,
} from '../lib/tenantFeatureAccess.mjs';

// Tenant-scoped deployment feature flags for authenticated portal UI.
export function getTenantDeploymentFeatures(ctx, runtimeConfig) {
  const isDemo = isExplicitDemoTenant(ctx?.tenantId);
  return {
    demo_tenant: isDemo,
    waf_posture: wafPostureEnabledFor(runtimeConfig, ctx?.tenantId),
    external_discovery: externalDiscoveryEnabledFor(runtimeConfig, ctx?.tenantId),
    connectors: connectorsEnabledFor(runtimeConfig, ctx?.tenantId),
    protection_validation: protectionValidationEnabledFor(runtimeConfig, ctx?.tenantId),
  };
}

// Entry-path validation and firewall change acceptance; the global off switch also covers demo tenants.
export function isProtectionValidationEnabled(ctx, runtimeConfig) {
  return protectionValidationEnabledFor(runtimeConfig, ctx?.tenantId);
}
