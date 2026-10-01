import '../helpers/dev-data-dir.mjs';

/**
 * What the unauthenticated bundled-fixture login is allowed to mint.
 *
 * `POST /v1/auth/bundled-staging-login` is a public route: src/lib/staffAuth.mjs classifies it as
 * such and src/server.mjs dispatches public routes before any auth resolution runs. So the request
 * body is attacker-controlled and these gates are the only thing standing between an anonymous
 * caller and a signed bearer token.
 *
 * The staff branch used to be gated by nothing but `bundledStagingOidc`, and defaulted `staff_role`
 * to `internal_admin`. With the fixture enabled on a NODE_ENV=production spec, an anonymous POST to
 * the live deployment returned a platform-staff bearer that then read /internal/admin successfully.
 * The CUSTOMER branch shared the same single flag, so the same production spec also minted
 * credential-free owner/admin sessions for ten_demo (PUBLIC-AUTH-01). Both branches now have their
 * own gate — `bundledStagingStaffLogin` and `bundledStagingCustomerLogin` — and neither arms under
 * NODE_ENV=production, while `bundledStagingOidc` stays enabled as the OIDC trust root so token
 * verification and the password lane keep working. These tests cover the service refusing to mint
 * without each flag, and the config refusing to arm either flag in production at all.
 */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import { loginBundledStagingPrincipal } from '../../src/services/bundledStagingAuth.mjs';
import { rejectsPasswordlessProtectedStagingSession } from '../../src/server.mjs';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { getPublicSiteConfig } from '../../src/services/publicSite.mjs';

const TEST_SECRET_ENCRYPTION_KEY = randomBytes(32).toString('hex');
const TEST_PROBE_WORKER_SECRET = randomBytes(32).toString('base64url');

/** Fixture on, both mints on — the shape a dev/staging deployment resolves to. */
const STAGING = {
  bundledStagingOidc: true,
  bundledStagingStaffLogin: true,
  bundledStagingCustomerLogin: true,
};
/** Fixture on, staff mint off, customer mint on — staging with only the staff hole closed. */
const STAFF_CLOSED = {
  bundledStagingOidc: true,
  bundledStagingStaffLogin: false,
  bundledStagingCustomerLogin: true,
};
/** Fixture on, both mints off — the shape production resolves to (trust root stays on). */
const PRODUCTION_SHAPE = {
  bundledStagingOidc: true,
  bundledStagingStaffLogin: false,
  bundledStagingCustomerLogin: false,
};

test('bundled staging customer login mints access token', () => {
  const result = loginBundledStagingPrincipal(
    { principal: 'customer', tenant_id: 'ten_demo', user_id: 'usr_admin', role: 'admin' },
    STAGING,
  );
  assert.equal(result.error, undefined);
  assert.match(result.access_token, /^eyJ/);
  assert.equal(result.principal, 'customer');
  assert.equal(result.role, 'admin');
});



test('password-protected accessibility identity cannot mint a bundled customer token', () => {
  for (const userId of [
    'accessibility-runner@astranull.invalid',
    'ACCESSIBILITY-RUNNER@ASTRANULL.INVALID',
    '  accessibility-runner@astranull.invalid  ',
  ]) {
    const result = loginBundledStagingPrincipal(
      { principal: 'customer', tenant_id: 'ten_demo', user_id: userId, role: 'admin' },
      STAFF_CLOSED,
    );
    assert.equal(result.error, 'password_required');
    assert.equal(result.status, 403);
    assert.equal(result.access_token, undefined, 'no bearer may be minted');
  }
});

test('account-specific password guard does not disable other bundled staging customers', () => {
  const result = loginBundledStagingPrincipal(
    {
      principal: 'customer',
      tenant_id: 'ten_demo',
      user_id: 'accessibility-runner-neighbor@astranull.invalid',
      role: 'viewer',
    },
    STAFF_CLOSED,
  );
  assert.equal(result.error, undefined);
  assert.match(result.access_token, /^eyJ/);
  assert.equal(result.user_id, 'accessibility-runner-neighbor@astranull.invalid');
});

test('preexisting passwordless tokens for the protected identity are rejected centrally', () => {
  const runtimeConfig = { bundledStagingOidc: true };
  const protectedCtx = {
    tenantId: 'ten_demo',
    userId: 'accessibility-runner@astranull.invalid',
  };

  assert.equal(
    rejectsPasswordlessProtectedStagingSession(runtimeConfig, protectedCtx, null),
    true,
  );
  assert.equal(
    rejectsPasswordlessProtectedStagingSession(runtimeConfig, protectedCtx, {
      tagged: true,
      valid: true,
      generation: 1,
    }),
    false,
  );
  assert.equal(
    rejectsPasswordlessProtectedStagingSession(
      runtimeConfig,
      { ...protectedCtx, userId: 'neighbor@astranull.invalid' },
      null,
    ),
    false,
  );
  assert.equal(
    rejectsPasswordlessProtectedStagingSession(
      { bundledStagingOidc: false },
      protectedCtx,
      null,
    ),
    false,
  );
});

test('bundled staging staff login mints access token when explicitly enabled', () => {
  const result = loginBundledStagingPrincipal(
    { principal: 'staff', staff_id: 'staff_admin', staff_role: 'internal_admin' },
    STAGING,
  );
  assert.equal(result.error, undefined);
  assert.match(result.access_token, /^eyJ/);
  assert.equal(result.principal, 'staff');
  assert.equal(result.staff_role, 'internal_admin');
});

test('bundled staging login refused when fixture disabled', () => {
  const result = loginBundledStagingPrincipal(
    { principal: 'customer' },
    { bundledStagingOidc: false, bundledStagingStaffLogin: false },
  );
  assert.equal(result.error, 'login_disabled');
  assert.equal(result.status, 403);
});

test('staff mint is refused when the staff flag is off, even with the fixture on', () => {
  // The exact live-deployment shape. No token may come back for any staff body.
  for (const body of [
    { principal: 'staff' },
    { principal: 'staff', staff_role: 'internal_admin' },
    { principal: 'staff', staff_role: 'support_engineer', staff_id: 'staff_x' },
    { principal: 'STAFF' },
    { principal: ' staff ' },
  ]) {
    const result = loginBundledStagingPrincipal(body, PRODUCTION_SHAPE);
    assert.equal(result.error, 'staff_login_disabled', `leaked for ${JSON.stringify(body)}`);
    assert.equal(result.status, 403);
    assert.equal(result.access_token, undefined, 'no bearer may be minted');
  }
});

test('staff refusal does not depend on the request body being well formed', () => {
  // Refuse before reading staff_role, so a caller cannot probe for a shape that slips past. An
  // unknown staff_role would otherwise 400 (validation_failed) and reveal that the branch is live.
  const result = loginBundledStagingPrincipal(
    { principal: 'staff', staff_role: 'not_a_real_role' },
    PRODUCTION_SHAPE,
  );
  assert.equal(result.error, 'staff_login_disabled', 'must not report a validation error instead');
  assert.equal(result.access_token, undefined);
});

test('customer login still works while only the staff mint is disabled', () => {
  // In staging the customer branch is ten_demo-scoped and is the portal's working login; closing
  // the staff hole alone must not take it down. (In production BOTH mints are off — see below.)
  const result = loginBundledStagingPrincipal({ principal: 'customer' }, STAFF_CLOSED);
  assert.equal(result.error, undefined);
  assert.match(result.access_token, /^eyJ/);
  assert.equal(result.principal, 'customer');
});

test('customer mint is refused when the customer flag is off, even with the fixture on', () => {
  // PUBLIC-AUTH-01: the production shape. No password-less customer bearer may come back for any
  // customer body — including the owner/admin role picker values the live bypass accepted.
  for (const body of [
    { principal: 'customer' },
    { principal: 'customer', tenant_id: 'ten_demo', user_id: 'usr_admin', role: 'owner' },
    { principal: 'customer', tenant_id: 'ten_demo', user_id: 'usr_admin', role: 'admin' },
    { principal: 'customer', tenant_id: 'ten_demo', user_id: 'usr_qa_swarm_probe', role: 'viewer' },
    { principal: 'CUSTOMER' },
    {},
    { principal: 'customer', tenant_id: 'ten_other' },
  ]) {
    const result = loginBundledStagingPrincipal(body, PRODUCTION_SHAPE);
    assert.equal(result.error, 'customer_login_disabled', `leaked for ${JSON.stringify(body)}`);
    assert.equal(result.status, 403);
    assert.equal(result.access_token, undefined, 'no bearer may be minted');
  }
});

test('customer refusal does not depend on the request body being well formed', () => {
  // Refuse before validating tenant_id/user_id, so a caller cannot probe for a shape that slips
  // past. An out-of-scope tenant would otherwise 400 (validation_failed) and reveal the live branch.
  const result = loginBundledStagingPrincipal(
    { principal: 'customer', tenant_id: 'ten_not_demo' },
    PRODUCTION_SHAPE,
  );
  assert.equal(result.error, 'customer_login_disabled', 'must not report a validation error instead');
  assert.equal(result.access_token, undefined);
});

/** Minimum env a production config load needs, independent of what is under test. */
function productionEnv(overrides = {}) {
  return {
    ASTRANULL_BUNDLED_STAGING_OIDC: '1',
    ASTRANULL_AUTH_MODE: 'oidc-jwt',
    ASTRANULL_OIDC_ISSUER: 'https://astranull.example/staging-oidc',
    ASTRANULL_OIDC_AUDIENCE: 'astranull-hosted-staging',
    ASTRANULL_OIDC_JWKS_URL: 'https://astranull.example/jwks.json',
    ASTRANULL_SECRET_ENCRYPTION_KEY: TEST_SECRET_ENCRYPTION_KEY,
    ASTRANULL_DATABASE_URL: 'postgres://u:p@h:5432/d',
    ASTRANULL_PROBE_WORKER_SECRET: TEST_PROBE_WORKER_SECRET,
    ASTRANULL_METRICS_TOKEN: 'm'.repeat(40),
    NODE_ENV: 'production',
    ...overrides,
  };
}

test('production never arms the staff mint, even when the fixture is enabled', () => {
  const config = loadRuntimeConfig(productionEnv());
  assert.equal(config.bundledStagingOidc, true, 'the OIDC trust root stays enabled');
  assert.equal(
    config.bundledStagingStaffLogin,
    false,
    'production must not mint staff principals from the bundled fixture',
  );
});

test('production has no env escape hatch for the staff mint', () => {
  // Deliberately no opt-in: staff authority is not demo-tenant-scoped, so in production it has to
  // come from the configured IdP. A future env var that re-enables this would reopen the hole.
  for (const value of ['1', 'true', 'yes', 'TRUE']) {
    const config = loadRuntimeConfig(
      productionEnv({ ASTRANULL_BUNDLED_STAGING_STAFF_LOGIN: value }),
    );
    assert.equal(
      config.bundledStagingStaffLogin,
      false,
      `ASTRANULL_BUNDLED_STAGING_STAFF_LOGIN=${value} must not re-enable staff mint in production`,
    );
  }
});

test('non-production arms the staff mint but still honours an explicit opt-out', () => {
  const dev = loadRuntimeConfig(productionEnv({ NODE_ENV: 'development' }));
  assert.equal(dev.bundledStagingStaffLogin, true, 'staging/dev keeps the staff login usable');

  const optedOut = loadRuntimeConfig(
    productionEnv({ NODE_ENV: 'development', ASTRANULL_BUNDLED_STAGING_STAFF_LOGIN: '0' }),
  );
  assert.equal(optedOut.bundledStagingStaffLogin, false, 'operators can disable it anywhere');
});

test('disabling the fixture entirely also disables the staff mint', () => {
  const config = loadRuntimeConfig(
    productionEnv({ NODE_ENV: 'development', ASTRANULL_BUNDLED_STAGING_OIDC: '0' }),
  );
  assert.equal(config.bundledStagingOidc, false);
  assert.equal(config.bundledStagingStaffLogin, false, 'staff mint cannot outlive its trust root');
});

// --- PUBLIC-AUTH-01: customer mint gate -----------------------------------------------------

test('production keeps the trust root and password lane but disables the customer mint', () => {
  const config = loadRuntimeConfig(productionEnv());
  assert.equal(config.bundledStagingOidc, true, 'the OIDC trust root stays enabled');
  assert.equal(
    config.passwordLoginEnabled,
    true,
    'the password lane stays enabled (it defaults on when oidc-jwt + bundledStagingOidc)',
  );
  assert.equal(
    config.bundledStagingCustomerLogin,
    false,
    'production must not mint anonymous customer principals from the bundled fixture',
  );
});

test('production has no env escape hatch for the customer mint', () => {
  // Symmetric with the staff mint: no opt-in exists, so a future env var cannot reopen PUBLIC-AUTH-01.
  for (const value of ['1', 'true', 'yes', 'TRUE']) {
    const config = loadRuntimeConfig(
      productionEnv({ ASTRANULL_BUNDLED_STAGING_CUSTOMER_LOGIN: value }),
    );
    assert.equal(
      config.bundledStagingCustomerLogin,
      false,
      `ASTRANULL_BUNDLED_STAGING_CUSTOMER_LOGIN=${value} must not re-enable the customer mint in production`,
    );
  }
});

test('non-production arms the customer mint but still honours an explicit opt-out', () => {
  const dev = loadRuntimeConfig(productionEnv({ NODE_ENV: 'development' }));
  assert.equal(dev.bundledStagingCustomerLogin, true, 'staging/dev keeps the customer login usable');

  const optedOut = loadRuntimeConfig(
    productionEnv({ NODE_ENV: 'development', ASTRANULL_BUNDLED_STAGING_CUSTOMER_LOGIN: '0' }),
  );
  assert.equal(optedOut.bundledStagingCustomerLogin, false, 'operators can disable it anywhere');
});

test('disabling the fixture entirely also disables the customer mint', () => {
  const config = loadRuntimeConfig(
    productionEnv({ NODE_ENV: 'development', ASTRANULL_BUNDLED_STAGING_OIDC: '0' }),
  );
  assert.equal(config.bundledStagingOidc, false);
  assert.equal(config.bundledStagingCustomerLogin, false, 'customer mint cannot outlive its trust root');
});

test('site-config reports the customer-mint capability, not the trust root', () => {
  // The login page keys the "Staging role bypass" disclosure off this flag; in production it must be
  // false even though the trust root is on, so the credential-free role picker does not render.
  const prod = getPublicSiteConfig(loadRuntimeConfig(productionEnv()));
  assert.equal(prod.bundled_staging_login_enabled, false, 'production hides the staging bypass');
  assert.equal(prod.password_login_enabled, true, 'password login stays advertised in production');

  const dev = getPublicSiteConfig(loadRuntimeConfig(productionEnv({ NODE_ENV: 'development' })));
  assert.equal(dev.bundled_staging_login_enabled, true, 'non-prod still exposes the staging bypass');
});
