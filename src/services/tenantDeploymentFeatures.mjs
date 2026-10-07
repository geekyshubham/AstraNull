import { isConnectorsEnabledForTenant, isProtectionValidationEnabledForTenant } from '../config.mjs';
import { isDemoAutoVerifyTenant } from '../lib/demoAutoVerify.mjs';

/**
 * Tenant-scoped deployment feature flags for authenticated portal UI.
 * @param {{ tenantId?: string | null }} ctx
 * @param {import('../config.mjs').RuntimeConfig} runtimeConfig
 */
export function getTenantDeploymentFeatures(ctx, runtimeConfig) {
  const isDemo = isDemoAutoVerifyTenant(ctx?.tenantId);
  return {
    waf_posture: isDemo || runtimeConfig.featureFlags?.wafPostureEnabled === true,
    external_discovery: isDemo || runtimeConfig.featureFlags?.externalDiscoveryEnabled === true,
    connectors: isDemo || isConnectorsEnabledForTenant(runtimeConfig, ctx?.tenantId),
    protection_validation: isProtectionValidationEnabled(ctx, runtimeConfig),
  };
}

/** Entry-path validation and firewall change acceptance; the global off switch also covers demo tenants. */
export function isProtectionValidationEnabled(ctx, runtimeConfig) {
  if (runtimeConfig?.featureFlags?.protectionValidationEnabled === false) return false;
  const tenantId = String(ctx?.tenantId ?? '').trim();
  if (Object.hasOwn(runtimeConfig?.featureFlags?.protectionValidationEnabledTenants ?? {}, tenantId)) {
    return isProtectionValidationEnabledForTenant(runtimeConfig, tenantId);
  }
  return isDemoAutoVerifyTenant(ctx?.tenantId) || isProtectionValidationEnabledForTenant(runtimeConfig, ctx?.tenantId);
}
