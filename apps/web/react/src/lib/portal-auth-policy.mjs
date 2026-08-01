/**
 * Portal auth decisions that must fail closed.
 *
 * Plain `.mjs` (with a sibling `.d.mts` so `api.ts` can import it under
 * `allowJs: false`) because `node --test` cannot load TypeScript. The alternative — and what
 * `tests/unit/react-portal-auth.test.mjs` used to do — is to re-implement these helpers inside
 * the test file. Those copies pass no matter what the shipped portal does, so the two defects
 * below were "covered" by tests that could not observe a regression in them.
 *
 * Both functions are pure so the real shipped logic is directly testable.
 */

/** Auth mode could not be established. Treated as unauthenticated, never as dev. */
export const AUTH_MODE_UNKNOWN = 'unknown';

/** @param {Record<string, unknown> | null | undefined} source */
function readAuthMode(source) {
  return String(source?.auth_mode ?? '').trim();
}

/**
 * Resolve how a deployment authenticates, preferring `/ready` over public site config.
 *
 * Falls back to `AUTH_MODE_UNKNOWN`, never to `dev-headers`. Defaulting to `dev-headers` here is
 * what let a failed config fetch mint an unauthenticated admin session: the caller treats
 * `dev-headers` as "bootstrap a local identity", so any network blip became a full admin login.
 * `/ready` reports `auth_mode` in its 503 body as well as its 200 body, so a degraded control
 * plane still yields the real mode rather than falling through to this default.
 *
 * @param {Record<string, unknown> | null | undefined} ready
 * @param {Record<string, unknown> | null | undefined} siteConfig
 * @returns {string}
 */
export function resolveAuthMode(ready, siteConfig) {
  return readAuthMode(ready) || readAuthMode(siteConfig) || AUTH_MODE_UNKNOWN;
}

/**
 * True for statuses meaning "this credential is no longer usable", so the caller clears the
 * stored session and stops sending a revoked bearer token.
 *
 * 401 always qualifies. 403 qualifies only for `staff_forbidden` — a principal/role mismatch a
 * new sign-in can fix. A plain `forbidden` from the RBAC layer is an authorization denial for a
 * perfectly valid session (a viewer opening an admin route); clearing the session there would
 * log operators out merely for browsing.
 *
 * @param {number} status
 * @param {unknown} payload
 * @returns {boolean}
 */
export function isAuthFailure(status, payload) {
  if (status === 401) return true;
  if (status !== 403) return false;
  const code =
    payload && typeof payload === 'object'
      ? String(/** @type {{ error?: unknown }} */ (payload).error ?? '').trim()
      : '';
  return code === 'staff_forbidden';
}

/**
 * @typedef {import('./types').Session} Session
 * @typedef {import('./types').PortalConfig} PortalConfig
 */

/** @param {Pick<PortalConfig, 'authMode'>} config */
export function isOidcJwtMode(config) {
  return config.authMode === 'oidc-jwt';
}

/** @param {string} url */
export function isExternalAuthUrl(url) {
  return /^https?:\/\//i.test(String(url).trim());
}

/**
 * Derive the portal auth surface from the browser pathname.
 *
 * @param {string} pathname
 * @returns {'customer' | 'staff'}
 */
export function portalSurface(pathname) {
  const path = String(pathname).replace(/\/+$/, '') || '/';
  if (path === '/internal/admin' || path.startsWith('/internal/admin/')) return 'staff';
  if (path === '/internal/soc' || path.startsWith('/internal/soc/')) return 'staff';
  return 'customer';
}

/**
 * When oidc-jwt is active without bundled staging login, send the operator to the configured
 * enterprise IdP. Only absolute http(s) URLs qualify — a relative path is our own page.
 *
 * @param {PortalConfig} config
 * @param {'customer' | 'staff'} [surface]
 * @returns {string | null}
 */
export function resolveOidcLoginRedirect(config, surface = 'customer') {
  if (!isOidcJwtMode(config) || config.bundledLoginEnabled) return null;
  const loginUrl = surface === 'staff' ? config.staffLoginPath : config.loginUrl;
  return isExternalAuthUrl(loginUrl) ? loginUrl : null;
}

/**
 * Where to send an unauthenticated operator.
 *
 * Deployments without a dedicated sign-in page report the PORTAL path itself as `login_url`
 * (getPublicSiteConfig defaults to `/app` unless bundled staging login is on). Redirecting `/app`
 * to `/app` navigates forever, so any candidate resolving to the page we are already on falls
 * back to `/login`, which always renders a sign-in form. Query and hash are ignored when
 * comparing, since `/app?x=1` is still the same page.
 *
 * @param {string | null | undefined} candidate
 * @param {string} pathname
 * @returns {string}
 */
export function resolveLoginDestination(candidate, pathname) {
  const target = String(candidate ?? '').trim() || '/login';
  // An enterprise IdP lives on another origin; it cannot loop against our path.
  if (isExternalAuthUrl(target)) return target;
  const absolute = target.startsWith('/') ? target : `/${target}`;
  const normalize = (value) => value.split(/[?#]/)[0].replace(/\/+$/, '') || '/';
  return normalize(absolute) === normalize(pathname) ? '/login' : absolute;
}

/**
 * @param {Record<string, unknown>} loginResponse
 * @param {number} [now] Injectable clock so expiry math is testable.
 * @returns {Session}
 */
export function sessionFromLoginResponse(loginResponse, now = Date.now()) {
  const expiresIn = Number(loginResponse.expires_in ?? 3600);
  return {
    mode: 'oidc',
    access_token: String(loginResponse.access_token ?? ''),
    principal: String(loginResponse.principal ?? 'customer'),
    tenant_id: loginResponse.tenant_id != null ? String(loginResponse.tenant_id) : undefined,
    user_id: loginResponse.user_id != null ? String(loginResponse.user_id) : undefined,
    role: loginResponse.role != null ? String(loginResponse.role) : undefined,
    staff_id: loginResponse.staff_id != null ? String(loginResponse.staff_id) : undefined,
    staff_role: loginResponse.staff_role != null ? String(loginResponse.staff_role) : undefined,
    expires_at: now + expiresIn * 1000,
  };
}

/**
 * True when the session carries an `expires_at` that has already passed.
 *
 * A missing or unparseable `expires_at` is NOT treated as expired: dev-headers sessions carry no
 * expiry at all, and failing closed here would lock local development out entirely. The bearer
 * path is what needs the guard, and it always has a real expiry.
 *
 * @param {Session | null | undefined} session
 * @param {number} [now]
 */
export function isSessionExpired(session, now = Date.now()) {
  if (!session) return true;
  const expiresAt = Number(session.expires_at ?? 0);
  if (!Number.isFinite(expiresAt) || expiresAt <= 0) return false;
  return now > expiresAt;
}

/** Operational staff SOC roles — must match STAFF_SOC_ROLES in route-access. */
export const STAFF_SOC_ROLES = new Set(['soc_analyst', 'soc_lead']);

/** @param {Session} session */
export function isStaffSocRole(session) {
  return STAFF_SOC_ROLES.has(String(session.staff_role ?? '').trim().toLowerCase());
}

/**
 * Build request headers for the active session.
 *
 * The expiry guard is the point: an expired token is worse than no token, because it keeps a
 * revoked credential in flight and turns every call into a 401 instead of a clean re-auth. When
 * the session has expired the Authorization header is omitted entirely.
 *
 * @param {PortalConfig} config
 * @param {Session} session
 * @param {number} [now]
 * @returns {Record<string, string>}
 */
export function buildApiHeaders(config, session, now = Date.now()) {
  /** @type {Record<string, string>} */
  const headers = { 'Content-Type': 'application/json', accept: 'application/json' };
  if (config.authMode === 'dev-headers') {
    if (session.principal === 'staff') {
      headers['x-principal-type'] = 'staff';
      headers['x-staff-id'] = String(session.staff_id ?? session.user_id ?? 'staff_dev');
      headers['x-staff-role'] = String(session.staff_role ?? session.role ?? 'support_engineer');
      return headers;
    }
    headers['x-tenant-id'] = String(session.tenant_id ?? 'ten_demo');
    headers['x-user-id'] = String(session.user_id ?? 'usr_admin');
    headers['x-role'] = String(session.role ?? 'admin');
    return headers;
  }
  if (isSessionExpired(session, now)) return headers;
  const token = String(session.access_token ?? '').trim();
  if (token) headers.authorization = `Bearer ${token}`;
  return headers;
}

/**
 * Staff SOC surface impersonating a tenant SOC role for governed execution routes.
 *
 * - dev-headers: rewrite to tenant + `x-role: soc`, but never silently pick `ten_demo` for a
 *   staff principal with no tenant — that would run a governed action against the wrong tenant.
 * - oidc-jwt: staff cannot spoof SOC claims, so this throws rather than degrading to a header
 *   the server would reject anyway.
 *
 * @param {PortalConfig} config
 * @param {Session} session
 * @param {string} [tenantId]
 * @param {number} [now]
 * @returns {Record<string, string>}
 */
export function buildSocCustomerHeaders(config, session, tenantId, now = Date.now()) {
  const resolvedTenant = String(tenantId ?? session.tenant_id ?? '').trim();
  const headers = buildApiHeaders(config, session, now);
  if (config.authMode === 'dev-headers') {
    if (session.principal === 'staff' && !resolvedTenant) {
      throw new Error(
        'Select an execution tenant before running staff SOC actions. Cross-tenant Open links pass ?tenant=…, or set a tenant on the SOC console.',
      );
    }
    const tenant = resolvedTenant || 'ten_demo';
    delete headers['x-principal-type'];
    delete headers['x-staff-id'];
    delete headers['x-staff-role'];
    headers['x-tenant-id'] = tenant;
    headers['x-user-id'] = String(session.staff_id ?? session.user_id ?? 'staff_soc');
    headers['x-role'] = 'soc';
    return headers;
  }
  if (session.principal === 'staff') {
    throw new Error(
      'Staff SOC tenant impersonation is not available in oidc-jwt mode. Use a tenant SOC session or local dev-headers for governed execution.',
    );
  }
  return headers;
}
