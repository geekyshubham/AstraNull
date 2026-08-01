import { createHash, createPrivateKey, createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_FIXTURE_PATH = path.resolve(__dirname, '../../ops/staging/bundled-oidc-fixture.json');

/**
 * SHA-256 of the RSA modulus of the fixture key that was committed to this repo until
 * 2026-08-01. The repo is public, so `git log -p` keeps that key recoverable forever:
 * anyone can mint a valid admin token with it. Untracking the file cannot undo that, so
 * the key is treated as permanently burned and refused outright.
 *
 * This is a fingerprint of *public* key material — safe to store in source, and it is the
 * only way to catch a stale fixture being redeployed from an old checkout, a cached image
 * layer, or a copy-pasted secret.
 */
const BURNED_KEY_MODULUS_SHA256 =
  '15cf684e4a87c50221e687b7f189e04c05bc31c974e970bae8f9a72e60075f2e';

/** Cache keyed by source, so a different env in the same process cannot read a stale key. */
const fixtureCache = new Map();

function assertNotBurned(fixture, source) {
  const modulus = fixture?.public_jwk?.n;
  if (typeof modulus !== 'string' || modulus === '') return;
  const fingerprint = createHash('sha256').update(modulus).digest('hex');
  if (fingerprint !== BURNED_KEY_MODULUS_SHA256) return;
  throw new Error(
    'Refusing to start: the bundled staging OIDC fixture is the key that was published in '
    + `this repository's git history (source: ${source}). It can no longer authenticate anyone `
    + 'safely — anybody can mint an admin token with it. Generate a replacement with '
    + '`npm run oidc:fixture:generate` and deliver it out-of-band via '
    + 'ASTRANULL_BUNDLED_STAGING_OIDC_FIXTURE_JSON.',
  );
}

/**
 * Resolves the fixture from, in order: inline JSON in the environment (how deployments
 * inject it, since the file is gitignored and therefore absent from the image), an
 * explicit path, then the default local path used by dev and tests.
 */
function loadFixture(env = process.env) {
  const inline = String(env.ASTRANULL_BUNDLED_STAGING_OIDC_FIXTURE_JSON ?? '').trim();
  const explicitPath = String(env.ASTRANULL_BUNDLED_STAGING_OIDC_FIXTURE ?? '').trim();
  const source = inline
    ? 'env:ASTRANULL_BUNDLED_STAGING_OIDC_FIXTURE_JSON'
    : (explicitPath || DEFAULT_FIXTURE_PATH);
  const cached = fixtureCache.get(source);
  if (cached) return cached;

  let raw;
  if (inline) {
    raw = inline;
  } else {
    try {
      raw = readFileSync(source, 'utf8');
    } catch (err) {
      if (err?.code !== 'ENOENT') throw err;
      // The fixture is a signing trust root, so it is gitignored and absent from fresh
      // clones and built images by design. Say how to supply it instead of surfacing ENOENT.
      throw new Error(
        `Bundled staging OIDC is enabled but no fixture was found at ${source}. This file is `
        + 'gitignored because it holds the token-signing private key. For local use run '
        + '`npm run oidc:fixture:generate`; for a deployment set '
        + 'ASTRANULL_BUNDLED_STAGING_OIDC_FIXTURE_JSON to the fixture JSON.',
      );
    }
  }

  let fixture;
  try {
    fixture = JSON.parse(raw);
  } catch {
    throw new Error(`Bundled staging OIDC fixture at ${source} is not valid JSON.`);
  }
  if (typeof fixture?.private_key_pem !== 'string' || !fixture.private_key_pem.includes('PRIVATE KEY')) {
    throw new Error(`Bundled staging OIDC fixture at ${source} is missing private_key_pem.`);
  }
  assertNotBurned(fixture, source);
  fixtureCache.set(source, fixture);
  return fixture;
}

/** Test seam: drops memoized fixtures so a regenerated key is picked up in-process. */
export function resetBundledStagingOidcFixtureCache() {
  fixtureCache.clear();
}

/**
 * Forces the fixture to load at startup so a missing or burned signing key refuses the boot.
 *
 * Without this, startup succeeds and the failure surfaces per-request: `/.well-known/jwks.json`
 * and every token mint throw, so the deployment looks healthy while nobody can authenticate.
 * Failing during startup instead means the platform's health check fails the deploy and the
 * previous revision keeps serving, which is the safer outcome for an auth trust root.
 *
 * Issuer, audience, and JWKS URL are pinned in deployment config, so none of the other code
 * paths here touch the fixture during config load — this check has to be explicit.
 *
 * @param {NodeJS.ProcessEnv} [env]
 */
export function assertBundledStagingOidcFixtureUsable(env = process.env) {
  if (!isBundledStagingOidcEnabled(env)) return;
  loadFixture(env);
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function isBundledStagingOidcEnabled(env = process.env) {
  return env.ASTRANULL_BUNDLED_STAGING_OIDC === '1';
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function resolvePublicBaseUrl(env = process.env) {
  const explicit = String(
    env.ASTRANULL_PUBLIC_BASE_URL ?? env.ASTRANULL_HOSTED_STAGING_BASE_URL ?? '',
  ).trim().replace(/\/$/, '');
  if (explicit) return explicit;
  for (const key of ['APP_URL', 'DIGITALOCEAN_APP_URL']) {
    const platformUrl = String(env[key] ?? '').trim().replace(/\/$/, '');
    if (platformUrl) return platformUrl;
  }
  const railwayStatic = String(env.RAILWAY_STATIC_URL ?? env.RAILWAY_SERVICE_CONTROL_PLANE_URL ?? '').trim().replace(/\/$/, '');
  if (railwayStatic) return railwayStatic;
  const railwayDomain = String(env.RAILWAY_PUBLIC_DOMAIN ?? '').trim();
  if (railwayDomain) return `https://${railwayDomain.replace(/^https?:\/\//, '')}`;
  const port = String(env.PORT ?? '3000').trim();
  const nodeEnv = String(env.NODE_ENV ?? 'development');
  if (nodeEnv === 'production') {
    throw new Error(
      'ASTRANULL_PUBLIC_BASE_URL or Railway public domain is required for bundled staging OIDC in production.',
    );
  }
  return `http://127.0.0.1:${port}`;
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function resolveBundledStagingOidcIssuer(env = process.env) {
  const explicit = String(env.ASTRANULL_OIDC_ISSUER ?? '').trim();
  if (explicit) return explicit;
  const fixture = loadFixture(env);
  return `${resolvePublicBaseUrl(env)}${fixture.issuer_suffix}`;
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function resolveBundledStagingOidcAudience(env = process.env) {
  return String(env.ASTRANULL_OIDC_AUDIENCE ?? loadFixture(env).audience).trim();
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function resolveBundledStagingOidcJwksUrl(env = process.env) {
  const explicit = String(env.ASTRANULL_OIDC_JWKS_URL ?? '').trim();
  if (explicit) return explicit;
  return `${resolvePublicBaseUrl(env)}/.well-known/jwks.json`;
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function getBundledStagingJwksDocument(env = process.env) {
  const fixture = loadFixture(env);
  return { keys: [fixture.public_jwk] };
}

function base64UrlJson(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

/**
 * @param {{
 *   role: string,
 *   tenantId?: string,
 *   userId?: string,
 *   exp?: number,
 *   extraClaims?: Record<string, unknown>,
 *   roleClaimKey?: string,
 *   tenantClaimKey?: string,
 *   userClaimKey?: string,
 * }} params
 * @param {NodeJS.ProcessEnv} [env]
 */
export function mintBundledStagingOidcJwt(params, env = process.env) {
  const fixture = loadFixture(env);
  const privateKey = createPrivateKey(fixture.private_key_pem);
  const header = { alg: 'RS256', typ: 'JWT', kid: fixture.kid };
  const roleClaimKey = params.roleClaimKey ?? 'role';
  const tenantClaimKey = params.tenantClaimKey ?? 'tenant_id';
  const userClaimKey = params.userClaimKey ?? 'sub';
  const payload = {
    iss: resolveBundledStagingOidcIssuer(env),
    aud: resolveBundledStagingOidcAudience(env),
    exp: params.exp ?? Math.floor(Date.now() / 1000) + 3600,
    amr: ['mfa', 'otp'],
    ...(params.extraClaims ?? {}),
  };
  payload[userClaimKey] = params.userId ?? 'usr_oidc_hosted';
  payload[tenantClaimKey] = params.tenantId ?? 'ten_demo';
  payload[roleClaimKey] = params.role;
  const signingInput = `${base64UrlJson(header)}.${base64UrlJson(payload)}`;
  const sig = createSign('RSA-SHA256').update(signingInput, 'utf8').sign(privateKey);
  return `${signingInput}.${sig.toString('base64url')}`;
}

/**
 * Apply bundled staging OIDC defaults to env for startup when enabled.
 * @param {NodeJS.ProcessEnv} env
 */
export function applyBundledStagingOidcEnvDefaults(env) {
  if (!isBundledStagingOidcEnabled(env)) return;
  if (!String(env.ASTRANULL_AUTH_MODE ?? '').trim()) {
    env.ASTRANULL_AUTH_MODE = 'oidc-jwt';
  }
  if (!String(env.ASTRANULL_OIDC_ISSUER ?? '').trim()) {
    env.ASTRANULL_OIDC_ISSUER = resolveBundledStagingOidcIssuer(env);
  }
  if (!String(env.ASTRANULL_OIDC_AUDIENCE ?? '').trim()) {
    env.ASTRANULL_OIDC_AUDIENCE = resolveBundledStagingOidcAudience(env);
  }
  if (!String(env.ASTRANULL_OIDC_JWKS_URL ?? '').trim()) {
    env.ASTRANULL_OIDC_JWKS_URL = resolveBundledStagingOidcJwksUrl(env);
  }
  if (!String(env.ASTRANULL_DEPLOYMENT_PROFILE ?? '').trim()) {
    env.ASTRANULL_DEPLOYMENT_PROFILE = 'hosted-staging';
  }
}