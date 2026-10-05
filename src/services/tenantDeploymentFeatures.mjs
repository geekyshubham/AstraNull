import { isConnectorsEnabledForTenant } from '../config.mjs';
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
  };
}