import { ROLES } from '../contracts/roles.mjs';
import { STAFF_ROLES } from '../contracts/staffRoles.mjs';
import { mintBundledStagingOidcJwt } from '../lib/bundledStagingOidc.mjs';

const BUNDLED_STAGING_DEMO_TENANT = 'ten_demo';
const PASSWORD_PROTECTED_CUSTOMER_IDS = new Set([
  'accessibility-runner@astranull.invalid',
]);

export function isPasswordProtectedBundledStagingCustomerId(userId) {
  return PASSWORD_PROTECTED_CUSTOMER_IDS.has(String(userId ?? '').trim().toLowerCase());
}

/**
 * Mint a bundled-fixture principal for demo/staging sign-in.
 *
 * This is reached from an UNAUTHENTICATED public route: `POST /v1/auth/bundled-staging-login` is
 * classified public in src/lib/staffAuth.mjs and dispatched before any auth resolution runs. So
 * every gate that limits what this can hand out has to live here, and the request body is
 * attacker-controlled — `role` and `staff_role` below are inputs, not assertions.
 *
 * The two branches are gated differently on purpose. Customer tokens are pinned to the ten_demo
 * tenant and require `bundledStagingCustomerLogin`, which never arms under NODE_ENV=production;
 * explicitly protected customer IDs are refused below and must use the credentialed password lane.
 * Staff tokens carry platform authority over /internal/admin (tenants, signup approvals, subscriptions),
 * which is not scoped to a demo tenant — so the staff branch requires `bundledStagingStaffLogin`, which
 * also never arms under NODE_ENV=production. Before those gates existed, an anonymous POST to the live
 * deployment returned usable `owner`/`internal_admin` bearers because both branches shared
 * `bundledStagingOidc`, which must stay enabled in production as the OIDC trust root.
 *
 * @param {unknown} body
 * @param {{ bundledStagingOidc?: boolean, bundledStagingStaffLogin?: boolean, bundledStagingCustomerLogin?: boolean }} runtimeConfig
 */
export function loginBundledStagingPrincipal(body, runtimeConfig) {
  if (!runtimeConfig.bundledStagingOidc) {
    return {
      error: 'login_disabled',
      status: 403,
      message: 'Bundled staging login is not enabled on this deployment.',
    };
  }

  const principal = String(body?.principal ?? 'customer').trim().toLowerCase();
  const expiresIn = 3600;

  if (principal === 'staff') {
    // Checked before reading staff_role: the refusal must not depend on anything in the body, so a
    // caller cannot probe for a shape that slips through.
    if (!runtimeConfig.bundledStagingStaffLogin) {
      return {
        error: 'staff_login_disabled',
        status: 403,
        message:
          'Bundled staging staff login is disabled on this deployment. Staff principals must be '
          + 'issued by the configured identity provider.',
      };
    }
    const staffRole = String(body?.staff_role ?? 'internal_admin').trim().toLowerCase();
    if (!STAFF_ROLES.includes(staffRole)) {
      return { error: 'validation_failed', status: 400, fields: ['staff_role'] };
    }
    const staffId = String(body?.staff_id ?? 'staff_admin').trim() || 'staff_admin';
    const accessToken = mintBundledStagingOidcJwt({
      role: staffRole,
      userId: staffId,
      tenantId: BUNDLED_STAGING_DEMO_TENANT,
      extraClaims: { staff_role: staffRole },
      roleClaimKey: 'role',
    });
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      principal: 'staff',
      staff_id: staffId,
      staff_role: staffRole,
    };
  }

  const tenantId = String(body?.tenant_id ?? BUNDLED_STAGING_DEMO_TENANT).trim();
  // Checked before reading any other customer field: the customer branch mints a password-less
  // session, so on a production deployment (where this flag is always false) it must be refused
  // regardless of body shape. `bundledStagingOidc` stays true in production to keep the OIDC trust
  // root and the password lane working, so the customer mint needs its own gate — see
  // bundledStagingCustomerLogin in src/config.mjs (PUBLIC-AUTH-01).
  if (!runtimeConfig.bundledStagingCustomerLogin) {
    return {
      error: 'customer_login_disabled',
      status: 403,
      message:
        'Bundled staging customer login is disabled on this deployment. Customer principals must '
        + 'sign in with their password or the configured identity provider.',
    };
  }
  if (tenantId !== BUNDLED_STAGING_DEMO_TENANT) {
    return { error: 'validation_failed', status: 400, fields: ['tenant_id'] };
  }
  const userId = String(body?.user_id ?? 'usr_admin').trim() || 'usr_admin';
  if (isPasswordProtectedBundledStagingCustomerId(userId)) {
    return {
      error: 'password_required',
      status: 403,
      message: 'This account must sign in with its password.',
    };
  }
  let role = String(body?.role ?? 'admin').trim().toLowerCase();
  if (!ROLES.includes(role)) role = 'viewer';

  const accessToken = mintBundledStagingOidcJwt({
    role,
    userId,
    tenantId,
  });

  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: expiresIn,
    principal: 'customer',
    tenant_id: tenantId,
    user_id: userId,
    role,
  };
}