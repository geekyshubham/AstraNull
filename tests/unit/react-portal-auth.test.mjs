import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { canAccessRoute } from '../../apps/web/react/src/lib/route-access.mjs';
// Every helper below is imported from the REAL module that api.ts uses — never a local copy.
// This file used to re-implement them, so the tests passed regardless of what shipped, and the
// local `portalSurface` copy had already drifted: it was missing the `/internal/soc` branch that
// actually ships, so staff-surface detection for the SOC console was silently uncovered.
import {
  AUTH_MODE_UNKNOWN,
  buildApiHeaders,
  buildSocCustomerHeaders,
  isAuthFailure,
  isExternalAuthUrl,
  isSessionExpired,
  isStaffSocRole,
  portalSurface,
  resolveAuthMode,
  resolveLoginDestination,
  resolveOidcLoginRedirect,
  sessionFromLoginResponse,
} from '../../apps/web/react/src/lib/portal-auth-policy.mjs';

describe('portal auth mode resolution (shipped module)', () => {
  it('prefers the /ready auth mode over public site config', () => {
    assert.equal(
      resolveAuthMode({ auth_mode: 'oidc-jwt' }, { auth_mode: 'dev-headers' }),
      'oidc-jwt',
    );
  });

  it('falls back to site config when /ready omits the mode', () => {
    assert.equal(resolveAuthMode({}, { auth_mode: 'oidc-jwt' }), 'oidc-jwt');
    assert.equal(resolveAuthMode({ auth_mode: '   ' }, { auth_mode: 'oidc-jwt' }), 'oidc-jwt');
  });

  // The audit finding: a failed config fetch used to resolve to dev-headers, and the caller
  // treats dev-headers as "bootstrap a local identity" — so a network blip minted an
  // unauthenticated admin session.
  it('fails closed to unknown — never to dev-headers — when discovery yields nothing', () => {
    for (const [ready, site] of [
      [null, null],
      [undefined, undefined],
      [{}, {}],
      [{ auth_mode: '' }, { auth_mode: '   ' }],
    ]) {
      const mode = resolveAuthMode(ready, site);
      assert.equal(mode, AUTH_MODE_UNKNOWN);
      assert.notEqual(mode, 'dev-headers');
    }
  });

  it('never reports dev-headers unless a discovery endpoint actually said so', () => {
    assert.equal(resolveAuthMode({ auth_mode: 'dev-headers' }, {}), 'dev-headers');
    assert.notEqual(resolveAuthMode({ auth_mode: 'signed-session' }, {}), 'dev-headers');
  });
});

describe('portal auth failure detection (shipped module)', () => {
  it('treats 401 as a dead credential regardless of payload', () => {
    for (const payload of [null, undefined, {}, { error: 'anything' }, 'text', 42]) {
      assert.equal(isAuthFailure(401, payload), true);
    }
  });

  it('treats 403 staff_forbidden as re-authenticable', () => {
    assert.equal(isAuthFailure(403, { error: 'staff_forbidden' }), true);
    assert.equal(isAuthFailure(403, { error: '  staff_forbidden  ' }), true);
  });

  // A plain RBAC denial is a VALID session hitting a route it lacks permission for. Clearing it
  // would log operators out merely for browsing.
  it('leaves the session intact on a plain RBAC forbidden', () => {
    assert.equal(isAuthFailure(403, { error: 'forbidden' }), false);
    assert.equal(isAuthFailure(403, {}), false);
    assert.equal(isAuthFailure(403, null), false);
  });

  it('ignores non-auth statuses', () => {
    for (const status of [200, 204, 400, 404, 409, 429, 500, 503]) {
      assert.equal(isAuthFailure(status, { error: 'staff_forbidden' }), false);
    }
  });

  it('does not throw on non-object payloads', () => {
    for (const payload of ['forbidden', 0, false, [], () => {}]) {
      assert.equal(isAuthFailure(403, payload), false);
    }
  });
});

describe('react portal auth helpers', () => {
  it('detects external enterprise login URLs', () => {
    assert.equal(isExternalAuthUrl('https://idp.example/oauth2/authorize'), true);
    assert.equal(isExternalAuthUrl('/login'), false);
    assert.equal(isExternalAuthUrl('/app'), false);
  });

  it('redirects oidc-jwt deployments to configured IdP URLs when bundled login is disabled', () => {
    const config = {
      authMode: 'oidc-jwt',
      bundledLoginEnabled: false,
      loginUrl: 'https://idp.example/oauth2/authorize',
      staffLoginPath: '/internal/admin/login',
    };
    assert.equal(resolveOidcLoginRedirect(config, 'customer'), 'https://idp.example/oauth2/authorize');
    assert.equal(resolveOidcLoginRedirect(config, 'staff'), null);
  });

  it('keeps bundled staging login on the local login surface', () => {
    const config = {
      authMode: 'oidc-jwt',
      bundledLoginEnabled: true,
      loginUrl: '/login',
      staffLoginPath: '/internal/admin/login',
    };
    assert.equal(resolveOidcLoginRedirect(config, 'customer'), null);
  });

  it('maps bundled staging login responses into bearer sessions', () => {
    const session = sessionFromLoginResponse({
      access_token: 'jwt.example',
      expires_in: 120,
      principal: 'customer',
      tenant_id: 'ten_demo',
      user_id: 'usr_admin',
      role: 'admin',
    });
    assert.equal(session.mode, 'oidc');
    assert.equal(session.access_token, 'jwt.example');
    assert.equal(session.principal, 'customer');
    assert.equal(session.tenant_id, 'ten_demo');
    assert.ok(session.expires_at > Date.now());
  });

  it('builds Authorization bearer headers from stored access tokens', () => {
    const config = { authMode: 'oidc-jwt' };
    const headers = buildApiHeaders(config, { access_token: '  token-value  ' });
    assert.equal(headers.authorization, 'Bearer token-value');
    assert.equal(buildApiHeaders(config, {}).authorization, undefined);
  });

  it('derives staff surface from internal admin and SOC paths', () => {
    assert.equal(portalSurface('/internal/admin'), 'staff');
    assert.equal(portalSurface('/internal/admin/'), 'staff');
    assert.equal(portalSurface('/internal/admin/login'), 'staff');
    // The old local mirror omitted this branch entirely.
    assert.equal(portalSurface('/internal/soc'), 'staff');
    assert.equal(portalSurface('/internal/soc/'), 'staff');
    assert.equal(portalSurface('/internal/soc/queue'), 'staff');
    assert.equal(portalSurface('/app'), 'customer');
    assert.equal(portalSurface('/login'), 'customer');
    assert.equal(portalSurface('/'), 'customer');
  });
});

describe('session expiry (shipped module)', () => {
  it('treats a missing session as expired', () => {
    assert.equal(isSessionExpired(null), true);
    assert.equal(isSessionExpired(undefined), true);
  });

  it('compares expires_at against the injected clock', () => {
    assert.equal(isSessionExpired({ expires_at: 1_000 }, 999), false);
    assert.equal(isSessionExpired({ expires_at: 1_000 }, 1_000), false);
    assert.equal(isSessionExpired({ expires_at: 1_000 }, 1_001), true);
  });

  // dev-headers sessions carry no expiry. Failing closed here would lock local development out.
  it('does not treat a missing or unparseable expiry as expired', () => {
    for (const session of [{}, { expires_at: 0 }, { expires_at: 'soon' }, { expires_at: -1 }]) {
      assert.equal(isSessionExpired(session, 9_999_999), false);
    }
  });
});

describe('api header construction (shipped module)', () => {
  const oidc = { authMode: 'oidc-jwt' };
  const dev = { authMode: 'dev-headers' };

  it('always sends JSON content negotiation', () => {
    const headers = buildApiHeaders(oidc, {});
    assert.equal(headers['Content-Type'], 'application/json');
    assert.equal(headers.accept, 'application/json');
  });

  // The audit defect: an expired token keeps a revoked credential in flight and turns every
  // call into a 401 instead of a clean re-auth.
  it('omits the bearer token once the session has expired', () => {
    const session = { access_token: 'jwt.example', expires_at: 5_000 };
    assert.equal(buildApiHeaders(oidc, session, 4_999).authorization, 'Bearer jwt.example');
    assert.equal(buildApiHeaders(oidc, session, 5_001).authorization, undefined);
  });

  it('sends dev-headers identity only in dev-headers mode', () => {
    const headers = buildApiHeaders(dev, { tenant_id: 'ten_a', user_id: 'usr_a', role: 'engineer' });
    assert.equal(headers['x-tenant-id'], 'ten_a');
    assert.equal(headers['x-user-id'], 'usr_a');
    assert.equal(headers['x-role'], 'engineer');
    assert.equal(headers.authorization, undefined);
    // An oidc-jwt session must never carry spoofable identity headers.
    const oidcHeaders = buildApiHeaders(oidc, { tenant_id: 'ten_a', access_token: 't' });
    assert.equal(oidcHeaders['x-tenant-id'], undefined);
    assert.equal(oidcHeaders['x-role'], undefined);
  });

  it('sends staff dev-headers for a staff principal', () => {
    const headers = buildApiHeaders(dev, {
      principal: 'staff',
      staff_id: 'staff_1',
      staff_role: 'internal_admin',
    });
    assert.equal(headers['x-principal-type'], 'staff');
    assert.equal(headers['x-staff-id'], 'staff_1');
    assert.equal(headers['x-staff-role'], 'internal_admin');
    assert.equal(headers['x-tenant-id'], undefined);
  });

  it('ignores an expired dev-headers session (no token is involved)', () => {
    const headers = buildApiHeaders(dev, { tenant_id: 'ten_a', expires_at: 1 }, 9_999);
    assert.equal(headers['x-tenant-id'], 'ten_a');
  });
});

describe('staff SOC impersonation (shipped module)', () => {
  const oidc = { authMode: 'oidc-jwt' };
  const dev = { authMode: 'dev-headers' };

  it('identifies operational SOC staff roles only', () => {
    assert.equal(isStaffSocRole({ staff_role: 'soc_analyst' }), true);
    assert.equal(isStaffSocRole({ staff_role: '  SOC_LEAD  ' }), true);
    assert.equal(isStaffSocRole({ staff_role: 'internal_admin' }), false);
    assert.equal(isStaffSocRole({}), false);
  });

  // Silently defaulting to ten_demo would run a governed action against the wrong tenant.
  it('refuses a staff SOC action with no execution tenant', () => {
    assert.throws(
      () => buildSocCustomerHeaders(dev, { principal: 'staff', staff_id: 'staff_1' }),
      /Select an execution tenant/,
    );
  });

  it('rewrites staff dev-headers to the chosen tenant with the soc role', () => {
    const headers = buildSocCustomerHeaders(dev, { principal: 'staff', staff_id: 'staff_1' }, 'ten_b');
    assert.equal(headers['x-tenant-id'], 'ten_b');
    assert.equal(headers['x-user-id'], 'staff_1');
    assert.equal(headers['x-role'], 'soc');
    // Staff markers must be stripped, or the server sees a staff principal AND a tenant role.
    assert.equal(headers['x-principal-type'], undefined);
    assert.equal(headers['x-staff-id'], undefined);
    assert.equal(headers['x-staff-role'], undefined);
  });

  // Staff cannot mint SOC claims under oidc-jwt, so this must throw rather than quietly send a
  // request the server will reject.
  it('refuses staff SOC impersonation under oidc-jwt', () => {
    assert.throws(
      () => buildSocCustomerHeaders(oidc, { principal: 'staff', access_token: 'jwt' }, 'ten_b'),
      /not available in oidc-jwt mode/,
    );
  });

  it('passes a tenant SOC session through unchanged under oidc-jwt', () => {
    const headers = buildSocCustomerHeaders(
      oidc,
      { principal: 'customer', access_token: 'jwt', expires_at: 9_000 },
      'ten_b',
      1_000,
    );
    assert.equal(headers.authorization, 'Bearer jwt');
    assert.equal(headers['x-role'], undefined);
  });
});

describe('login destination (shipped module)', () => {
  // getPublicSiteConfig reports the PORTAL path as login_url when there is no dedicated sign-in
  // page, so redirecting /app to /app would navigate forever.
  it('breaks the redirect loop when the candidate is the current page', () => {
    assert.equal(resolveLoginDestination('/app', '/app'), '/login');
    assert.equal(resolveLoginDestination('/app/', '/app'), '/login');
    assert.equal(resolveLoginDestination('/app?next=1', '/app'), '/login');
    assert.equal(resolveLoginDestination('/app#top', '/app'), '/login');
  });

  it('keeps a distinct in-app destination', () => {
    assert.equal(resolveLoginDestination('/login', '/app'), '/login');
    assert.equal(resolveLoginDestination('signin', '/app'), '/signin');
  });

  it('passes an external IdP URL through untouched', () => {
    const idp = 'https://idp.example/oauth2/authorize?client_id=x';
    assert.equal(resolveLoginDestination(idp, '/app'), idp);
  });

  it('defaults to /login when no candidate is supplied', () => {
    assert.equal(resolveLoginDestination(null, '/app'), '/login');
    assert.equal(resolveLoginDestination('   ', '/app'), '/login');
  });
});

describe('react portal route access', () => {
  it('hides notifications for viewer without notification:read', () => {
    assert.equal(canAccessRoute('viewer', 'notifications'), false);
    assert.equal(canAccessRoute('auditor', 'notifications'), true);
    assert.equal(canAccessRoute('engineer', 'notifications'), true);
    assert.equal(canAccessRoute('admin', 'notifications'), true);
  });

  it('shows audit for auditor roles allowed by backend RBAC', () => {
    assert.equal(canAccessRoute('auditor', 'audit'), true);
    assert.equal(canAccessRoute('viewer', 'audit'), false);
    assert.equal(canAccessRoute('auditor', 'reports'), true);
    assert.equal(canAccessRoute('viewer', 'reports'), true);
  });

  it('restricts staff SOC console to staff principals with SOC staff roles', () => {
    assert.equal(canAccessRoute('soc', 'internal-soc', { principal: 'customer' }), false);
    assert.equal(canAccessRoute('admin', 'internal-soc', { principal: 'customer' }), false);
    assert.equal(canAccessRoute('viewer', 'internal-soc', { principal: 'customer' }), false);
    assert.equal(canAccessRoute('admin', 'internal-soc', { principal: 'staff', staffRole: 'soc_analyst' }), true);
    assert.equal(canAccessRoute('admin', 'internal-soc', { principal: 'staff', staffRole: 'support_engineer' }), false);
  });

  it('shows staff SOC surface only for staff principals with SOC staff roles', () => {
    assert.equal(canAccessRoute('admin', 'internal-soc', { principal: 'staff', staffRole: 'soc_analyst' }), true);
    assert.equal(canAccessRoute('admin', 'internal-soc', { principal: 'staff', staffRole: 'support_engineer' }), false);
    assert.equal(canAccessRoute('soc', 'internal-soc', { principal: 'customer' }), false);
  });

  it('keeps broadly readable routes visible to viewer', () => {
    assert.equal(canAccessRoute('viewer', 'dashboard'), true);
    assert.equal(canAccessRoute('viewer', 'findings'), true);
    assert.equal(canAccessRoute('viewer', 'settings'), true);
  });

  it('aligns staff SOC route gate with operational SOC roles only', () => {
    assert.equal(canAccessRoute('admin', 'internal-soc', { principal: 'staff', staffRole: 'admin' }), false);
    assert.equal(canAccessRoute('admin', 'internal-soc', { principal: 'staff', staffRole: 'internal_admin' }), false);
    assert.equal(canAccessRoute('admin', 'internal-soc', { principal: 'staff', staffRole: 'soc_lead' }), true);
  });

  it('allows customers to open queue-detail for authorization pack completion', () => {
    assert.equal(canAccessRoute('engineer', 'queue-detail', { principal: 'customer' }), true);
    assert.equal(canAccessRoute('viewer', 'queue-detail', { principal: 'customer' }), true);
    assert.equal(canAccessRoute('admin', 'queue-detail', { principal: 'staff', staffRole: 'support_engineer' }), true);
  });

  it('narrows release-evidence to the auditor role (docs/ux/14 §3.1)', () => {
    assert.equal(canAccessRoute('viewer', 'release-evidence'), false);
    assert.equal(canAccessRoute('engineer', 'release-evidence'), false);
    assert.equal(canAccessRoute('auditor', 'release-evidence'), true);
    // release_evidence:read still covers owner/admin/soc, but the customer surface is auditor-only.
    assert.equal(canAccessRoute('admin', 'release-evidence'), false);
    assert.equal(canAccessRoute('owner', 'release-evidence'), false);
    assert.equal(canAccessRoute('soc', 'release-evidence'), false);
  });
});
