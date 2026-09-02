import { validateHmacSecretEntropy } from '../../src/lib/evidenceSigning.mjs';

export const HOSTED_STAGING_ENVIRONMENT = 'staging';
export const HOSTED_STAGING_RELEASE_ID = 'rel-hosted-staging-2026-07-03';
export const DEFAULT_HOSTED_STAGING_TENANT_ID = 'ten_demo';
export const LOCAL_ONLY_STAGING_PROBE_WORKER_SECRET_HEX =
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';

export function isHostedStagingEnvironment(value) {
  if (value === null || value === undefined) return false;
  return String(value).trim().toLowerCase() === HOSTED_STAGING_ENVIRONMENT;
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function resolveHostedStagingBaseUrl(env = process.env) {
  const explicit = String(env.ASTRANULL_HOSTED_STAGING_BASE_URL ?? '').trim().replace(/\/$/, '');
  if (explicit) return explicit;
  const local = String(env.ASTRANULL_LOCAL_STAGING_BASE_URL ?? '').trim().replace(/\/$/, '');
  if (local) return local;
  return '';
}

/**
 * @param {string} baseUrl
 * @param {NodeJS.ProcessEnv} [env]
 */
export function isHostedStagingBaseUrl(baseUrl, env = process.env) {
  const hosted = resolveHostedStagingBaseUrl(env);
  if (hosted && String(baseUrl).trim().replace(/\/$/, '') === hosted) return true;
  return !/^https?:\/\/(127\.0\.0\.1|localhost)(:\d+)?(?:\/|$)/i.test(String(baseUrl ?? '').trim());
}

/**
 * @param {string} [baseUrl]
 * @param {NodeJS.ProcessEnv} [env]
 */
export function resolveStagingProbeWorkerSecret(baseUrl = '', env = process.env) {
  const explicit = String(env.ASTRANULL_PROBE_WORKER_SECRET ?? '').trim();
  if (!explicit) {
    if (isHostedStagingBaseUrl(baseUrl, env)) {
      throw new Error(
        'ASTRANULL_PROBE_WORKER_SECRET is required for non-loopback hosted staging.',
      );
    }
    return LOCAL_ONLY_STAGING_PROBE_WORKER_SECRET_HEX;
  }
  const validated = validateHmacSecretEntropy(explicit);
  if (!validated.ok) {
    throw new Error(
      `ASTRANULL_PROBE_WORKER_SECRET failed entropy validation (${validated.error}).`,
    );
  }
  return validated.secret;
}