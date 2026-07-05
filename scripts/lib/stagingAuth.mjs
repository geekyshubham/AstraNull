import { mintBundledStagingOidcJwt } from '../../src/lib/bundledStagingOidc.mjs';
import {
  DEFAULT_LOCAL_STAGING_ADMIN_ROLE,
  DEFAULT_LOCAL_STAGING_ADMIN_USER_ID,
  DEFAULT_LOCAL_STAGING_TENANT_ID,
} from './localStaging.mjs';
import { buildDevHeaders, stagingFetch } from '../local-staging-smoke.mjs';

/**
 * OIDC issuer is tied to ASTRANULL_PUBLIC_BASE_URL on the server (primary domain),
 * which may differ from the ingress URL used for API calls.
 *
 * @param {string} apiBaseUrl
 */
export function resolveOidcMintBaseUrl(apiBaseUrl) {
  const explicit = String(process.env.ASTRANULL_STAGING_OIDC_BASE_URL ?? '').trim().replace(/\/$/, '');
  if (explicit) return explicit;
  const normalizedApi = String(apiBaseUrl ?? '').trim().replace(/\/$/, '');
  if (normalizedApi.includes('ondigitalocean.app')) {
    return 'https://astranull.site';
  }
  return normalizedApi;
}

/**
 * @param {string} baseUrl
 */
function buildOidcMintEnv(baseUrl) {
  const mintBaseUrl = resolveOidcMintBaseUrl(baseUrl);
  return {
    ...process.env,
    ASTRANULL_HOSTED_STAGING_BASE_URL: mintBaseUrl,
    ASTRANULL_PUBLIC_BASE_URL: mintBaseUrl,
  };
}

/**
 * @param {{
 *   tenantId?: string,
 *   userId?: string,
 *   role?: string,
 *   baseUrl?: string,
 * }} [params]
 */
export function buildOidcAuthHeaders(params = {}) {
  const mintEnv = params.baseUrl ? buildOidcMintEnv(params.baseUrl) : process.env;
  const token = mintBundledStagingOidcJwt({
    tenantId: params.tenantId ?? DEFAULT_LOCAL_STAGING_TENANT_ID,
    userId: params.userId ?? DEFAULT_LOCAL_STAGING_ADMIN_USER_ID,
    role: params.role ?? DEFAULT_LOCAL_STAGING_ADMIN_ROLE,
  }, mintEnv);
  return {
    authorization: `Bearer ${token}`,
    accept: 'application/json',
  };
}

/**
 * @param {string} baseUrl
 * @param {{ role?: string, userId?: string, tenantId?: string, authMode?: string }} [options]
 */
export async function resolveStagingAuthHeaders(baseUrl, options = {}) {
  let authMode = options.authMode;
  if (!authMode) {
    const ready = await stagingFetch(baseUrl, '/ready');
    authMode = ready.json?.auth_mode ?? process.env.ASTRANULL_AUTH_MODE ?? 'dev-headers';
  }
  if (authMode === 'oidc-jwt') {
    return buildOidcAuthHeaders({ ...options, baseUrl });
  }
  return buildDevHeaders(
    options.tenantId ?? DEFAULT_LOCAL_STAGING_TENANT_ID,
    options.userId ?? DEFAULT_LOCAL_STAGING_ADMIN_USER_ID,
    options.role ?? DEFAULT_LOCAL_STAGING_ADMIN_ROLE,
  );
}