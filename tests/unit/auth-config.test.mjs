import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import { afterEach, describe, it } from 'node:test';
import { loadRuntimeConfig, resolvePersistenceMode, resolveAuthMode } from '../../src/config.mjs';
import { mintSignedSessionToken, verifySignedSessionToken } from '../../src/context.mjs';

const TEST_SECRET = 'test-session-secret-at-least-32-chars!!';
const TEST_ENC_KEY = randomBytes(32).toString('base64');
const TEST_PROBE_SECRET = 'test-probe-worker-secret-32-chars!!';
const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

afterEach(() => {
  restoreEnv();
});

describe('runtime auth config', () => {
  it('defaults to dev-headers when NODE_ENV is not production', () => {
    delete process.env.ASTRANULL_AUTH_MODE;
    delete process.env.ASTRANULL_NO_PERSIST;
    process.env.NODE_ENV = 'test';
    assert.equal(resolveAuthMode(), 'dev-headers');
    const cfg = loadRuntimeConfig();
    assert.equal(cfg.authMode, 'dev-headers');
    assert.equal(cfg.sessionSecret, null);
    assert.equal(cfg.maxJsonBodyBytes, 65536);
    assert.equal(cfg.shutdownGraceMs, 30000);
    assert.equal(cfg.persistenceMode, 'dev-json');
    assert.equal(cfg.probeMode, 'simulation');
    assert.equal(cfg.probeWorkerSecretConfigured, false);
    assert.equal(cfg.rateLimit.windowMs, 60000);
    assert.equal(cfg.rateLimit.maxRequests, 600);
    assert.equal(cfg.rateLimit.disabled, false);
    assert.equal(cfg.rateLimit.trustProxyHeaders, false);
    assert.equal(cfg.secretEncryptionConfigured, false);
    assert.deepEqual(cfg.featureFlags, {
      wafPostureEnabled: false,
      externalDiscoveryEnabled: false,
      connectorsEnabledDefault: false,
      connectorsEnabledTenants: {},
    });
  });

  it('enables WAF feature flags only when explicitly set to 1', () => {
    process.env.NODE_ENV = 'test';
    delete process.env.ASTRANULL_WAF_POSTURE_ENABLED;
    delete process.env.ASTRANULL_EXTERNAL_DISCOVERY_ENABLED;
    assert.equal(loadRuntimeConfig().featureFlags.wafPostureEnabled, false);

    process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
    process.env.ASTRANULL_EXTERNAL_DISCOVERY_ENABLED = '1';
    const enabled = loadRuntimeConfig();
    assert.equal(enabled.featureFlags.wafPostureEnabled, true);
    assert.equal(enabled.featureFlags.externalDiscoveryEnabled, true);

    process.env.ASTRANULL_WAF_POSTURE_ENABLED = '0';
    assert.equal(loadRuntimeConfig().featureFlags.wafPostureEnabled, false);
  });

  it('rejects invalid WAF feature flag boolean env values', () => {
    process.env.NODE_ENV = 'test';
    process.env.ASTRANULL_WAF_POSTURE_ENABLED = 'yes';
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_WAF_POSTURE_ENABLED must be 1 or 0/);

    delete process.env.ASTRANULL_WAF_POSTURE_ENABLED;
    process.env.ASTRANULL_EXTERNAL_DISCOVERY_ENABLED = 'on';
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_EXTERNAL_DISCOVERY_ENABLED must be 1 or 0/);
  });

  it('allows production startup with WAF flags off without cloud credentials', () => {
    process.env.NODE_ENV = 'production';
    process.env.ASTRANULL_AUTH_MODE = 'oidc-jwt';
    process.env.ASTRANULL_OIDC_ISSUER = 'https://idp.example';
    process.env.ASTRANULL_OIDC_AUDIENCE = 'astranull-api';
    process.env.ASTRANULL_OIDC_JWKS_URL = 'https://idp.example/jwks';
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY;
    process.env.ASTRANULL_DATABASE_URL = 'postgres://astranull:test@127.0.0.1:5432/astranull';
    process.env.ASTRANULL_PROBE_WORKER_SECRET = TEST_PROBE_SECRET;
    delete process.env.ASTRANULL_WAF_POSTURE_ENABLED;
    delete process.env.ASTRANULL_EXTERNAL_DISCOVERY_ENABLED;

    const cfg = loadRuntimeConfig();
    assert.equal(cfg.featureFlags.wafPostureEnabled, false);
    assert.equal(cfg.featureFlags.externalDiscoveryEnabled, false);
  });

  it('parses operability env overrides with bounds', () => {
    process.env.NODE_ENV = 'test';
    process.env.ASTRANULL_MAX_JSON_BODY_BYTES = '262144';
    process.env.ASTRANULL_SHUTDOWN_GRACE_MS = '5000';
    process.env.ASTRANULL_NO_PERSIST = '1';
    const cfg = loadRuntimeConfig();
    assert.equal(cfg.maxJsonBodyBytes, 262144);
    assert.equal(cfg.shutdownGraceMs, 5000);
    assert.equal(cfg.persistenceMode, 'memory');
  });

  it('parses rate limit env overrides with bounds', () => {
    process.env.NODE_ENV = 'test';
    process.env.ASTRANULL_RATE_LIMIT_WINDOW_MS = '5000';
    process.env.ASTRANULL_RATE_LIMIT_MAX_REQUESTS = '42';
    const cfg = loadRuntimeConfig();
    assert.equal(cfg.rateLimit.windowMs, 5000);
    assert.equal(cfg.rateLimit.maxRequests, 42);
  });

  it('enables trustProxyHeaders when ASTRANULL_TRUST_PROXY_HEADERS=1', () => {
    process.env.NODE_ENV = 'test';
    delete process.env.ASTRANULL_TRUST_PROXY_HEADERS;
    assert.equal(loadRuntimeConfig().rateLimit.trustProxyHeaders, false);
    process.env.ASTRANULL_TRUST_PROXY_HEADERS = '1';
    assert.equal(loadRuntimeConfig().rateLimit.trustProxyHeaders, true);
  });

  /**
   * The hop count decides which `x-forwarded-for` entry becomes the rate-limit bucket key.
   *
   * Too high reaches into caller-supplied entries and makes the limiter spoofable, so the default
   * is the conservative 1 and the value is bounded. See deriveClientKey for the full reasoning.
   */
  it('defaults trustedProxyHops to one and bounds ASTRANULL_TRUSTED_PROXY_HOPS', () => {
    process.env.NODE_ENV = 'test';
    delete process.env.ASTRANULL_TRUSTED_PROXY_HOPS;
    assert.equal(loadRuntimeConfig().rateLimit.trustedProxyHops, 1);

    process.env.ASTRANULL_TRUSTED_PROXY_HOPS = '2';
    assert.equal(loadRuntimeConfig().rateLimit.trustedProxyHops, 2);

    // Rejected rather than silently clamped: a wrong hop count is a security-relevant
    // misconfiguration, and quietly substituting a different one would hide it.
    for (const bad of ['0', '-1', '11', '1.5', 'two']) {
      process.env.ASTRANULL_TRUSTED_PROXY_HOPS = bad;
      assert.throws(
        () => loadRuntimeConfig(),
        /ASTRANULL_TRUSTED_PROXY_HOPS/,
        `ASTRANULL_TRUSTED_PROXY_HOPS=${bad} must be refused`,
      );
    }
  });

  it('allows disabling rate limit outside production', () => {
    process.env.NODE_ENV = 'test';
    process.env.ASTRANULL_RATE_LIMIT_DISABLED = '1';
    const cfg = loadRuntimeConfig();
    assert.equal(cfg.rateLimit.disabled, true);
  });

  it('rejects ASTRANULL_RATE_LIMIT_DISABLED in production', () => {
    process.env.NODE_ENV = 'production';
    process.env.ASTRANULL_AUTH_MODE = 'oidc-jwt';
    process.env.ASTRANULL_OIDC_ISSUER = 'https://idp.example';
    process.env.ASTRANULL_OIDC_AUDIENCE = 'astranull-api';
    process.env.ASTRANULL_OIDC_JWKS_URL = 'https://idp.example/jwks';
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY;
    process.env.ASTRANULL_RATE_LIMIT_DISABLED = '1';
    assert.throws(
      () => loadRuntimeConfig(),
      /ASTRANULL_RATE_LIMIT_DISABLED=1 is not permitted when NODE_ENV=production/,
    );
  });

  it('exposes secretEncryptionConfigured when a valid key is set', () => {
    process.env.NODE_ENV = 'test';
    process.env.ASTRANULL_NO_PERSIST = '1';
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY;
    const cfg = loadRuntimeConfig();
    assert.equal(cfg.secretEncryptionConfigured, true);
    assert.equal(cfg.secretEncryptionKey?.length, 32);
  });

  it('rejects invalid ASTRANULL_MAX_JSON_BODY_BYTES', () => {
    process.env.NODE_ENV = 'test';
    process.env.ASTRANULL_MAX_JSON_BODY_BYTES = '0';
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_MAX_JSON_BODY_BYTES/);
  });

  it('defaults to oidc-jwt when NODE_ENV is production', () => {
    delete process.env.ASTRANULL_AUTH_MODE;
    process.env.NODE_ENV = 'production';
    assert.equal(resolveAuthMode(), 'oidc-jwt');
  });

  it('fails closed when production uses dev-headers', () => {
    process.env.NODE_ENV = 'production';
    process.env.ASTRANULL_AUTH_MODE = 'dev-headers';
    assert.throws(
      () => loadRuntimeConfig(),
      /ASTRANULL_AUTH_MODE must be oidc-jwt when NODE_ENV=production/,
    );
  });

  it('fails closed when production uses signed-session', () => {
    process.env.NODE_ENV = 'production';
    process.env.ASTRANULL_AUTH_MODE = 'signed-session';
    process.env.ASTRANULL_SESSION_SECRET = TEST_SECRET;
    assert.throws(
      () => loadRuntimeConfig(),
      /ASTRANULL_AUTH_MODE must be oidc-jwt when NODE_ENV=production/,
    );
  });

  it('requires session secret for signed-session mode', () => {
    process.env.NODE_ENV = 'development';
    process.env.ASTRANULL_AUTH_MODE = 'signed-session';
    delete process.env.ASTRANULL_SESSION_SECRET;
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_SESSION_SECRET/);
  });

  it('requires OIDC settings for oidc-jwt mode', () => {
    process.env.NODE_ENV = 'test';
    process.env.ASTRANULL_AUTH_MODE = 'oidc-jwt';
    delete process.env.ASTRANULL_OIDC_ISSUER;
    delete process.env.ASTRANULL_OIDC_AUDIENCE;
    delete process.env.ASTRANULL_OIDC_JWKS_URL;
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_OIDC_ISSUER/);

    process.env.ASTRANULL_OIDC_ISSUER = 'https://idp.example';
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_OIDC_AUDIENCE/);

    process.env.ASTRANULL_OIDC_AUDIENCE = 'astranull';
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_OIDC_JWKS_URL/);
  });

  it('exposes oidc runtime config with defaults and bounded JWKS cache TTL', () => {
    process.env.NODE_ENV = 'test';
    process.env.ASTRANULL_AUTH_MODE = 'oidc-jwt';
    process.env.ASTRANULL_OIDC_ISSUER = 'https://idp.example';
    process.env.ASTRANULL_OIDC_AUDIENCE = 'astranull-api';
    process.env.ASTRANULL_OIDC_JWKS_URL = 'https://idp.example/jwks';
    delete process.env.ASTRANULL_OIDC_TENANT_CLAIM;
    delete process.env.ASTRANULL_OIDC_ROLE_CLAIM;
    delete process.env.ASTRANULL_OIDC_USER_CLAIM;
    delete process.env.ASTRANULL_OIDC_JWKS_CACHE_TTL_MS;

    const cfg = loadRuntimeConfig();
    assert.equal(cfg.authMode, 'oidc-jwt');
    assert.equal(cfg.sessionSecret, null);
    assert.deepEqual(cfg.oidc, {
      issuer: 'https://idp.example',
      audience: 'astranull-api',
      jwksUrl: 'https://idp.example/jwks',
      tenantClaim: 'tenant_id',
      roleClaim: 'role',
      userClaim: 'sub',
      requireMfa: false,
      mfaClaim: 'amr',
      mfaValues: ['mfa', 'otp', 'webauthn', 'fido', 'fido2', 'phishing_resistant'],
      jwksCacheTtlMs: 300_000,
      jwksFetchTimeoutMs: 5000,
      rolePrefix: null,
      roleMap: {},
      requireExplicitRoleMap: false,
    });

    process.env.ASTRANULL_OIDC_JWKS_CACHE_TTL_MS = '120000';
    assert.equal(loadRuntimeConfig().oidc.jwksCacheTtlMs, 120_000);

    process.env.ASTRANULL_OIDC_JWKS_CACHE_TTL_MS = '5000';
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_OIDC_JWKS_CACHE_TTL_MS/);
    delete process.env.ASTRANULL_OIDC_JWKS_CACHE_TTL_MS;

    delete process.env.ASTRANULL_OIDC_JWKS_FETCH_TIMEOUT_MS;
    assert.equal(loadRuntimeConfig().oidc.jwksFetchTimeoutMs, 5000);

    process.env.ASTRANULL_OIDC_JWKS_FETCH_TIMEOUT_MS = '10000';
    assert.equal(loadRuntimeConfig().oidc.jwksFetchTimeoutMs, 10_000);

    process.env.ASTRANULL_OIDC_JWKS_FETCH_TIMEOUT_MS = '500';
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_OIDC_JWKS_FETCH_TIMEOUT_MS/);

    process.env.ASTRANULL_OIDC_JWKS_FETCH_TIMEOUT_MS = '99999';
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_OIDC_JWKS_FETCH_TIMEOUT_MS/);
  });

  it('requires OIDC MFA by default in production and accepts explicit policy values', () => {
    process.env.NODE_ENV = 'production';
    process.env.ASTRANULL_AUTH_MODE = 'oidc-jwt';
    process.env.ASTRANULL_OIDC_ISSUER = 'https://idp.example';
    process.env.ASTRANULL_OIDC_AUDIENCE = 'astranull-api';
    process.env.ASTRANULL_OIDC_JWKS_URL = 'https://idp.example/jwks';
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY;
    process.env.ASTRANULL_DATABASE_URL = 'postgres://astranull:test@127.0.0.1:5432/astranull';
    process.env.ASTRANULL_PROBE_WORKER_SECRET = TEST_PROBE_SECRET;

    const cfg = loadRuntimeConfig();
    assert.equal(cfg.oidc.requireExplicitRoleMap, true);
    assert.equal(cfg.oidc.requireMfa, true);
    assert.equal(cfg.oidc.mfaClaim, 'amr');
    assert.deepEqual(cfg.oidc.mfaValues, [
      'mfa',
      'otp',
      'webauthn',
      'fido',
      'fido2',
      'phishing_resistant',
    ]);

    process.env.ASTRANULL_OIDC_REQUIRE_MFA = '0';
    process.env.ASTRANULL_OIDC_MFA_CLAIM = 'acr';
    process.env.ASTRANULL_OIDC_MFA_VALUES = 'urn:mfa, phishing_resistant,URN:MFA';
    const override = loadRuntimeConfig();
    assert.equal(override.oidc.requireMfa, false);
    assert.equal(override.oidc.mfaClaim, 'acr');
    assert.deepEqual(override.oidc.mfaValues, ['urn:mfa', 'phishing_resistant']);
  });

  it('parses optional OIDC role prefix and role map env values', () => {
    process.env.NODE_ENV = 'test';
    baseOidcEnv();
    process.env.ASTRANULL_OIDC_JWKS_URL = 'https://idp.example/jwks';
    process.env.ASTRANULL_OIDC_ROLE_PREFIX = 'astranull-';
    process.env.ASTRANULL_OIDC_ROLE_MAP = 'Corp-Admin:admin, corp-viewer : viewer ';

    const cfg = loadRuntimeConfig();
    assert.equal(cfg.oidc.rolePrefix, 'astranull-');
    assert.deepEqual(cfg.oidc.roleMap, {
      'corp-admin': 'admin',
      'corp-viewer': 'viewer',
    });

    process.env.ASTRANULL_OIDC_ROLE_MAP = 'bad-entry';
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_OIDC_ROLE_MAP/);
  });

  /**
   * The hosted-staging profile no longer exempts production from explicit role mapping.
   *
   * That exemption let the bundled fixture's self-asserted claims resolve with no map configured.
   * It applied to `staff_role` as well, so an attacker-chosen claim became platform staff authority
   * over /internal/admin. Closing the mint stopped new staff tokens being issued, but ones minted
   * earlier still verified, because pickStaffRole accepted the raw claim. With this enabled and no
   * staff role map configured, staff role resolution fails closed and those tokens stop verifying.
   *
   * The deployed spec is exactly NODE_ENV=production + ASTRANULL_DEPLOYMENT_PROFILE=hosted-staging,
   * which is the combination the old condition exempted — so it is the one worth pinning.
   */
  it('requires explicit role mapping in production even under the hosted-staging profile', () => {
    process.env.NODE_ENV = 'production';
    baseOidcEnv();
    process.env.ASTRANULL_OIDC_JWKS_URL = 'https://idp.example/jwks';
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY;
    process.env.ASTRANULL_DATABASE_URL = 'postgres://astranull:test@127.0.0.1:5432/astranull';
    process.env.ASTRANULL_PROBE_WORKER_SECRET = TEST_PROBE_SECRET;
    process.env.ASTRANULL_DEPLOYMENT_PROFILE = 'hosted-staging';

    assert.equal(loadRuntimeConfig().oidc.requireExplicitRoleMap, true);

    // Unchanged: production with no profile already required it.
    delete process.env.ASTRANULL_DEPLOYMENT_PROFILE;
    assert.equal(loadRuntimeConfig().oidc.requireExplicitRoleMap, true);

    // Non-production stays permissive so local runs and E2E keep working without a map.
    process.env.NODE_ENV = 'development';
    process.env.ASTRANULL_DEPLOYMENT_PROFILE = 'hosted-staging';
    assert.equal(loadRuntimeConfig().oidc.requireExplicitRoleMap, false);
  });

  /**
   * The persistence fail-closed gate keys on NODE_ENV OR the deployment profile.
   *
   * It used to key on NODE_ENV alone and early-return otherwise. That left a misconfiguration path
   * where ASTRANULL_DEPLOYMENT_PROFILE=production with an unset or non-production NODE_ENV skipped
   * every check, and resolvePersistenceMode() defaults to dev-json off production — so the process
   * booted on the local JSON file store, losing tenant data on restart and bypassing RLS entirely,
   * with no error. Latent rather than live (both Dockerfiles that pin NODE_ENV do pin production),
   * so this pins the misconfiguration path shut.
   *
   * resolvePersistenceMode is intentionally left keyed on NODE_ENV: the gate rejects the unsafe
   * default rather than silently redefining it, which is the fail-closed half of the behaviour.
   */
  it('enforces production persistence under a production profile with non-production NODE_ENV', () => {
    process.env.NODE_ENV = 'test';
    baseOidcEnv();
    process.env.ASTRANULL_OIDC_JWKS_URL = 'https://idp.example/jwks';
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY;
    process.env.ASTRANULL_PROBE_WORKER_SECRET = TEST_PROBE_SECRET;
    delete process.env.ASTRANULL_PERSISTENCE_MODE;
    delete process.env.ASTRANULL_NO_PERSIST;
    delete process.env.ASTRANULL_DATABASE_URL;
    process.env.ASTRANULL_DEPLOYMENT_PROFILE = 'production';

    // The unsafe default is still what gets resolved; the gate is what refuses it.
    assert.equal(resolvePersistenceMode(), 'dev-json');
    assert.throws(() => loadRuntimeConfig(), /persistence mode "dev-json" is not permitted/);

    process.env.ASTRANULL_PERSISTENCE_MODE = 'memory';
    assert.throws(() => loadRuntimeConfig(), /persistence mode "memory" is not permitted/);

    // Postgres without a database URL is equally unusable, and equally silent before this.
    process.env.ASTRANULL_PERSISTENCE_MODE = 'postgres';
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_DATABASE_URL must be set/);

    process.env.ASTRANULL_DATABASE_URL = 'postgres://astranull:test@127.0.0.1:5432/astranull';
    assert.equal(loadRuntimeConfig().persistenceMode, 'postgres');
  });

  it('leaves non-production profiles free to run the dev-json store', () => {
    process.env.NODE_ENV = 'test';
    delete process.env.ASTRANULL_PERSISTENCE_MODE;
    delete process.env.ASTRANULL_NO_PERSIST;

    // hosted-staging keeps booting on dev-json: widening the gate must not sweep in the profiles
    // that legitimately run without Postgres (local dev, E2E, the bundled staging fixture).
    for (const profile of ['local-staging', 'hosted-staging']) {
      process.env.ASTRANULL_DEPLOYMENT_PROFILE = profile;
      assert.equal(loadRuntimeConfig().persistenceMode, 'dev-json');
    }
  });

  it('rejects malformed OIDC MFA policy env values', () => {
    process.env.NODE_ENV = 'test';
    baseOidcEnv();
    process.env.ASTRANULL_OIDC_JWKS_URL = 'https://idp.example/jwks';
    process.env.ASTRANULL_OIDC_REQUIRE_MFA = 'yes';
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_OIDC_REQUIRE_MFA/);

    process.env.ASTRANULL_OIDC_REQUIRE_MFA = '1';
    process.env.ASTRANULL_OIDC_MFA_VALUES = ' , ';
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_OIDC_MFA_VALUES/);
  });

  function baseOidcEnv() {
    process.env.ASTRANULL_AUTH_MODE = 'oidc-jwt';
    process.env.ASTRANULL_OIDC_ISSUER = 'https://idp.example';
    process.env.ASTRANULL_OIDC_AUDIENCE = 'astranull-api';
  }

  it('rejects invalid ASTRANULL_OIDC_JWKS_URL strings', () => {
    process.env.NODE_ENV = 'test';
    baseOidcEnv();
    process.env.ASTRANULL_OIDC_JWKS_URL = 'not-a-url';
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_OIDC_JWKS_URL/);
  });

  it('rejects non-HTTPS JWKS URL in production', () => {
    process.env.NODE_ENV = 'production';
    baseOidcEnv();
    process.env.ASTRANULL_OIDC_JWKS_URL = 'http://idp.example/jwks';
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY;
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_OIDC_JWKS_URL/);
  });

  it('accepts HTTPS JWKS URL in production', () => {
    process.env.NODE_ENV = 'production';
    baseOidcEnv();
    process.env.ASTRANULL_OIDC_JWKS_URL = 'https://idp.example/jwks';
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY;
    let err;
    try {
      loadRuntimeConfig();
    } catch (e) {
      err = e;
    }
    assert.ok(!err || !/ASTRANULL_OIDC_JWKS_URL/.test(err.message));
  });

  it('accepts local HTTP JWKS URL outside production', () => {
    process.env.NODE_ENV = 'test';
    baseOidcEnv();
    process.env.ASTRANULL_OIDC_JWKS_URL = 'http://127.0.0.1:8765/jwks';
    const cfg = loadRuntimeConfig();
    assert.equal(cfg.oidc.jwksUrl, 'http://127.0.0.1:8765/jwks');

    process.env.ASTRANULL_OIDC_JWKS_URL = 'http://localhost/jwks';
    assert.equal(loadRuntimeConfig().oidc.jwksUrl, 'http://localhost/jwks');
  });
});

describe('signed session tokens', () => {
  it('mints and verifies a valid token', () => {
    const token = mintSignedSessionToken(
      { tenantId: 'ten_a', userId: 'usr_1', role: 'engineer' },
      TEST_SECRET,
    );
    const ctx = verifySignedSessionToken(token, TEST_SECRET);
    assert.equal(ctx.tenantId, 'ten_a');
    assert.equal(ctx.userId, 'usr_1');
    assert.equal(ctx.role, 'engineer');
  });

  it('rejects tampered payload', () => {
    const token = mintSignedSessionToken(
      { tenantId: 'ten_a', userId: 'usr_1', role: 'viewer' },
      TEST_SECRET,
    );
    const parts = token.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    payload.role = 'admin';
    parts[1] = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const tampered = parts.join('.');
    assert.equal(verifySignedSessionToken(tampered, TEST_SECRET).error, 'invalid_token');
  });

  it('rejects expired tokens', () => {
    const token = mintSignedSessionToken(
      { tenantId: 'ten_a', userId: 'usr_1', role: 'viewer', exp: Math.floor(Date.now() / 1000) - 60 },
      TEST_SECRET,
    );
    assert.equal(verifySignedSessionToken(token, TEST_SECRET).error, 'expired');
  });

  it('rejects invalid role in payload', () => {
    const payloadB64 = Buffer.from(
      JSON.stringify({
        tenantId: 'ten_a',
        userId: 'usr_1',
        role: 'superuser',
        exp: Math.floor(Date.now() / 1000) + 3600,
      }),
      'utf8',
    ).toString('base64url');
    const sig = createHmac('sha256', TEST_SECRET)
      .update(`asn1.${payloadB64}`, 'utf8')
      .digest('base64url');
    const token = `asn1.${payloadB64}.${sig}`;
    assert.equal(verifySignedSessionToken(token, TEST_SECRET).error, 'invalid_role');
  });
});
