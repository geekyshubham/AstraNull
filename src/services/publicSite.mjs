import { SUBSCRIPTION_PLANS } from '../contracts/subscriptions.mjs';

export function getPublicSiteConfig(runtimeConfig) {
  const defaultLogin = runtimeConfig.bundledStagingOidc ? '/login' : '/app';
  const loginUrl = (runtimeConfig.publicSite?.loginUrl ?? defaultLogin).trim() || defaultLogin;
  const signupEnabled = runtimeConfig.publicSite?.signupEnabled !== false;
  return {
    product_name: 'AstraNull',
    promise: 'No-access-first DDoS readiness validation for customer-declared targets.',
    login_url: loginUrl,
    signup_enabled: signupEnabled,
    signup_path: '/signup',
    customer_portal_path: '/app',
    auth_mode: runtimeConfig.authMode ?? 'dev-headers',
    // The UI capability that renders the staging role picker / "Staging role bypass" disclosure.
    // It must track the CUSTOMER mint gate (bundledStagingCustomerLogin, always false in
    // production), NOT the OIDC trust root (bundledStagingOidc, which stays true in production to
    // keep token verification and the password lane working). Reporting the trust root here is what
    // shipped PUBLIC-AUTH-01: the production login page rendered the credential-free role picker.
    bundled_staging_login_enabled: runtimeConfig.bundledStagingCustomerLogin === true,
    password_login_enabled: runtimeConfig.passwordLoginEnabled === true,
    feature_flags: {
      waf_posture: runtimeConfig.featureFlags?.wafPostureEnabled === true,
      external_discovery: runtimeConfig.featureFlags?.externalDiscoveryEnabled === true,
      connectors_default: runtimeConfig.featureFlags?.connectorsEnabledDefault === true,
    },
    plans: Object.values(SUBSCRIPTION_PLANS).map((p) => ({
      id: p.id,
      name: p.name,
      limits: p.limits,
      feature_entitlements: p.feature_entitlements,
    })),
    safety_framing: {
      no_default_cloud_access: true,
      no_ip_inventory_discovery: true,
      no_self_service_high_scale_attack_tooling: true,
      soc_gated_high_scale: true,
    },
  };
}