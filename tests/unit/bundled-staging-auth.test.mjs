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
 * These tests cover both halves of the fix: the service refusing to mint staff without the separate
 * flag, and the config refusing to arm that flag in production at all.
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import { loginBundledStagingPrincipal } from '../../src/services/bundledStagingAuth.mjs';
import { rejectsPasswordlessProtectedStagingSession } from '../../src/server.mjs';
import { loadRuntimeConfig } from '../../src/config.mjs';

/** Fixture on, staff mint on — the shape a dev/staging deployment resolves to. */
const STAGING = { bundledStagingOidc: true, bundledStagingStaffLogin: true };
/** Fixture on, staff mint off — the shape production resolves to. */
const PRODUCTION_SHAPE = { bundledStagingOidc: true, bundledStagingStaffLogin: false };

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
      PRODUCTION_SHAPE,
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
    PRODUCTION_SHAPE,
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

test('customer login still works while staff mint is disabled', () => {
  // The customer branch is ten_demo-scoped and is currently the portal's only working login;
  // closing the staff hole must not take the site down with it.
  const result = loginBundledStagingPrincipal({ principal: 'customer' }, PRODUCTION_SHAPE);
  assert.equal(result.error, undefined);
  assert.match(result.access_token, /^eyJ/);
  assert.equal(result.principal, 'customer');
});

/** Minimum env a production config load needs, independent of what is under test. */
function productionEnv(overrides = {}) {
  return {
    ASTRANULL_BUNDLED_STAGING_OIDC: '1',
    ASTRANULL_AUTH_MODE: 'oidc-jwt',
    ASTRANULL_OIDC_ISSUER: 'https://astranull.example/staging-oidc',
    ASTRANULL_OIDC_AUDIENCE: 'astranull-hosted-staging',
    ASTRANULL_OIDC_JWKS_URL: 'https://astranull.example/jwks.json',
    ASTRANULL_SECRET_ENCRYPTION_KEY: '7f'.repeat(32),
    ASTRANULL_DATABASE_URL: 'postgres://u:p@h:5432/d',
    ASTRANULL_PROBE_WORKER_SECRET: 'q'.repeat(48),
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
