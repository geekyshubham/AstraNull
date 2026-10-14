import { isConnectorsEnabledForTenant, loadRuntimeConfig } from '../config.mjs';
import { isExplicitDemoTenant } from './demoAutoVerify.mjs';

function resolveTenantId(tenantOrCtx) {
  if (!tenantOrCtx) return '';
  if (typeof tenantOrCtx === 'object') {
    return String(tenantOrCtx.tenantId ?? tenantOrCtx.tenant_id ?? tenantOrCtx.id ?? '').trim();
  }
  return String(tenantOrCtx ?? '').trim();
}

function resolveFeatureFlags(runtimeConfigOrFlags, env = process.env) {
  if (runtimeConfigOrFlags?.featureFlags && typeof runtimeConfigOrFlags.featureFlags === 'object') {
    return runtimeConfigOrFlags.featureFlags;
  }
  if (runtimeConfigOrFlags && typeof runtimeConfigOrFlags === 'object' && (
    'wafPostureEnabled' in runtimeConfigOrFlags
    || 'externalDiscoveryEnabled' in runtimeConfigOrFlags
    || 'connectorsEnabled' in runtimeConfigOrFlags
    || 'connectorsEnabledDefault' in runtimeConfigOrFlags
    || 'protectionValidationEnabled' in runtimeConfigOrFlags
    || 'protectionValidationEnabledDefault' in runtimeConfigOrFlags
    || 'wafPostureEnabledTenants' in runtimeConfigOrFlags
    || 'connectorsEnabledTenants' in runtimeConfigOrFlags
    || 'externalDiscoveryEnabledTenants' in runtimeConfigOrFlags
    || 'protectionValidationEnabledTenants' in runtimeConfigOrFlags
  )) {
    return runtimeConfigOrFlags;
  }
  return loadRuntimeConfig(env).featureFlags ?? {};
}

function resolveRuntimeConfig(runtimeConfigOrFlags, env = process.env) {
  if (runtimeConfigOrFlags?.featureFlags && typeof runtimeConfigOrFlags.featureFlags === 'object') {
    return runtimeConfigOrFlags;
  }
  if (runtimeConfigOrFlags && typeof runtimeConfigOrFlags === 'object' && (
    'connectorsEnabled' in runtimeConfigOrFlags
    || 'connectorsEnabledDefault' in runtimeConfigOrFlags
    || 'connectorsEnabledTenants' in runtimeConfigOrFlags
    || 'wafPostureEnabled' in runtimeConfigOrFlags
    || 'externalDiscoveryEnabled' in runtimeConfigOrFlags
    || 'protectionValidationEnabled' in runtimeConfigOrFlags
    || 'protectionValidationEnabledDefault' in runtimeConfigOrFlags
    || 'wafPostureEnabledTenants' in runtimeConfigOrFlags
    || 'externalDiscoveryEnabledTenants' in runtimeConfigOrFlags
    || 'protectionValidationEnabledTenants' in runtimeConfigOrFlags
  )) {
    return { featureFlags: runtimeConfigOrFlags };
  }
  return loadRuntimeConfig(env);
}

export function wafPostureEnabledFor(runtimeConfigOrFlags, tenantOrCtx, env = process.env) {
  const tid = resolveTenantId(tenantOrCtx);
  if (isExplicitDemoTenant(tid, env)) return true;
  const flags = resolveFeatureFlags(runtimeConfigOrFlags, env);
  if (flags.wafPostureEnabled === true) return true;
  const overrides = flags.wafPostureEnabledTenants;
  if (Array.isArray(overrides) && tid && overrides.includes(tid)) return true;
  if (overrides && typeof overrides === 'object' && tid && overrides[tid] === true) return true;
  return false;
}

export function connectorsEnabledFor(runtimeConfigOrFlags, tenantOrCtx, env = process.env) {
  const tid = resolveTenantId(tenantOrCtx);
  if (isExplicitDemoTenant(tid, env)) return true;
  const cfg = resolveRuntimeConfig(runtimeConfigOrFlags, env);
  const flags = cfg.featureFlags ?? {};
  if (flags.connectorsEnabled === true) return true;
  const overrides = flags.connectorsEnabledTenants;
  if (Array.isArray(overrides) && tid && overrides.includes(tid)) return true;
  return isConnectorsEnabledForTenant(cfg, tid);
}

export function externalDiscoveryEnabledFor(runtimeConfigOrFlags, tenantOrCtx, env = process.env) {
  const tid = resolveTenantId(tenantOrCtx);
  if (isExplicitDemoTenant(tid, env)) return true;
  const flags = resolveFeatureFlags(runtimeConfigOrFlags, env);
  if (flags.externalDiscoveryEnabled === true) return true;
  const overrides = flags.externalDiscoveryEnabledTenants;
  if (Array.isArray(overrides) && tid && overrides.includes(tid)) return true;
  if (overrides && typeof overrides === 'object' && tid && overrides[tid] === true) return true;
  return false;
}

export function protectionValidationEnabledFor(runtimeConfigOrFlags, tenantOrCtx, env = process.env) {
  const flags = resolveFeatureFlags(runtimeConfigOrFlags, env);
  if (flags.protectionValidationEnabled === false) return false;
  const tid = resolveTenantId(tenantOrCtx);
  const tenantOverrides = flags.protectionValidationEnabledTenants ?? {};
  if (Array.isArray(tenantOverrides) && tid && tenantOverrides.includes(tid)) return true;
  if (tid && Object.prototype.hasOwnProperty.call(tenantOverrides, tid)) {
    return tenantOverrides[tid] === true;
  }
  if (isExplicitDemoTenant(tid, env)) return true;
  if (flags.protectionValidationEnabledDefault !== undefined) return flags.protectionValidationEnabledDefault === true;
  return flags.protectionValidationEnabled === true;
}
