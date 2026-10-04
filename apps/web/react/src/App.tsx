import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AppShell } from './components/layout/app-shell';
import { EvidenceInspectorHost } from './components/evidence/evidence-inspector';
import {
  clearSession,
  EMPTY_PORTAL_DATA,
  ensurePortalSession,
  fetchPortalData,
  fetchPortalDatasets,
  isStaffSocRole,
  loadSession,
  portalSurface,
  REAUTH_REQUIRED_EVENT,
  resetReauthGuard,
  resolveLoginDestination,
  saveSession,
  sessionIdentity
} from './lib/api';
import { getRouteFromLocation, ROUTE_BY_ID } from './lib/navigation';
import { staffHomeRoute, isSessionExpired } from './lib/portal-auth-policy.mjs';
import { createPayloadCommitGate, runGenerationKeyedPayload } from './lib/payload-commit-generation.mjs';
import { canAccessRoute } from './lib/route-access';
import { getRouteTenantId } from './lib/route-params';
import { ConfirmModalProvider } from './lib/crud-ui';
import { clearNavState, navScopeKey } from './lib/nav-state.mjs';
import type { PortalConfig, PortalData, PortalDataset, RouteId, Session } from './lib/types';
import {
  buildLoginReturnUrl,
  LoginPage,
  PortalUnavailablePage,
  PublicLandingPage,
  SetPasswordPage,
  SignupPage,
  SignupStatusPage,
  StaffLoginPage
} from './pages/public-pages';
import { RouteView } from './pages/router';

/**
 * Boot handoff: render nothing until config resolves.
 *
 * The HTML shell (apps/web/index.html) paints a branded overlay before this
 * module even downloads, and tears it down on React's first commit into #root.
 * Rendering a second React spinner here meant every visitor saw two different
 * loaders back to back. Committing an empty tree keeps #root childless, so the
 * shell overlay stays up — one loader, one handoff, straight into the page.
 */
function LoadingScreen() {
  return null;
}

function isPublicOnlyPath(path: string) {
  return ['/', '/landing.html', '/login', '/login.html', '/signup', '/signup.html', '/signup-status', '/set-password', '/internal/admin/login', '/staff-login.html'].includes(path);
}

function sessionForRoute(session: Session, route: RouteId): Session {
  if (
    session.principal !== 'staff' ||
    !isStaffSocRole(session) ||
    (route !== 'internal-soc' && route !== 'queue-detail')
  ) {
    return session;
  }
  const tenantId = getRouteTenantId(session.tenant_id ?? '').trim();
  return { ...session, tenant_id: tenantId || undefined };
}

function fallbackRouteForSession(session: Pick<Session, 'principal' | 'staff_role'>): RouteId {
  return session.principal === 'staff' ? staffHomeRoute(session) : 'dashboard';
}

function routeAllowedFor(session: Pick<Session, 'principal' | 'role' | 'staff_role'> | null | undefined, route: RouteId) {
  return canAccessRoute(session?.role, route, { principal: session?.principal, staffRole: session?.staff_role });
}

/**
 * Sign-in address for a customer portal redirect. The intended route survives only through the
 * public sanitizer (`buildLoginReturnUrl`), which keeps route-scoped safe parameters and drops
 * tokens, free text and staff routes. External identity providers own their own return flow.
 */
function loginDestinationWithIntent(candidate: string | undefined, reason: 'session_expired' | null) {
  const dest = resolveLoginDestination(candidate, window.location.pathname);
  if (!dest.startsWith('/') || dest.startsWith('//')) return dest;
  if (portalSurface(window.location.pathname) === 'staff') return dest;
  return buildLoginReturnUrl(dest, { hash: window.location.hash, reason });
}

export default function App() {
  const [route, setRoute] = useState<RouteId>(() => getRouteFromLocation());
  const [path, setPath] = useState(() => window.location.pathname);
  const [config, setConfig] = useState<PortalConfig | null>(null);
  const [session, setSession] = useState<Session | null>(() => loadSession());
  const [data, setData] = useState<PortalData>(EMPTY_PORTAL_DATA);
  const [loading, setLoading] = useState(true);
  const [hydratingRoute, setHydratingRoute] = useState<RouteId | null>(null);
  const bootStarted = useRef(false);
  const lastHydratedRoute = useRef<RouteId | null>(null);
  const payloadCommitGate = useRef(createPayloadCommitGate(route));
  payloadCommitGate.current.activate(route);

  const activeSession = useMemo(() => session ?? {}, [session]);
  const navScope = navScopeKey(session);

  // Saved list return state belongs to one tenant, user and role; drop every other scope.
  useEffect(() => {
    clearNavState(navScope);
  }, [navScope]);

  // A denied route stays on its own address and shows a persistent access-denied page; nothing
  // from it is hydrated, and no healthy fallback page is substituted.
  const routeAllowed = routeAllowedFor(session, route);

  const refresh = useCallback(async (
    nextConfig: PortalConfig | null,
    nextSession: Session,
    nextRoute: RouteId,
    options: { datasets?: readonly PortalDataset[]; force?: boolean } = {}
  ) => {
    if (!nextConfig) return;
    const scopedSession = sessionForRoute(nextSession, nextRoute);
    await runGenerationKeyedPayload({
      gate: payloadCommitGate.current,
      routeKey: nextRoute,
      load: (isCurrent) => options.datasets
        ? fetchPortalDatasets(nextConfig, scopedSession, options.datasets, isCurrent)
        : fetchPortalData(nextConfig, scopedSession, {
          route: nextRoute,
          force: options.force,
          shouldCommitCache: isCurrent
        }),
      onCommit: (payload) => setData(payload),
      onError: (error) => setData((current) => ({
        ...current,
        loaded: true,
        error: error instanceof Error ? error.message : 'Could not load workspace data.'
      })),
      onSettled: () => setHydratingRoute((current) => current === nextRoute ? null : current),
    });
  }, []);

  /**
   * Leave the authenticated surface for the sign-in page of the current surface.
   *
   * Discards the dead credential first, so nothing can keep sending it. Public
   * pages return early: they are already unauthenticated, and redirecting from
   * one to itself is how a bounce loop starts.
   */
  const goToLogin = useCallback(() => {
    clearSession();
    setSession(null);
    if (isPublicOnlyPath(window.location.pathname)) return;
    const candidate = portalSurface(window.location.pathname) === 'staff'
      ? config?.staffLoginPath
      : config?.loginUrl;
    const dest = loginDestinationWithIntent(candidate, 'session_expired');
    if (dest.startsWith('/') && !dest.startsWith('//')) {
      window.history.replaceState(null, '', dest);
      setPath(window.location.pathname);
      return;
    }
    window.location.replace(dest);
  }, [config]);

  // An expired or revoked session surfaces as 401 (or a staff-role 403) on
  // whichever calls happen to be in flight. lib/api clears storage and dispatches
  // this event ONCE for the whole burst, so the portal re-authenticates a single
  // time instead of once per failed request.
  useEffect(() => {
    function onReauthRequired() {
      goToLogin();
    }
    window.addEventListener(REAUTH_REQUIRED_EVENT, onReauthRequired);
    return () => window.removeEventListener(REAUTH_REQUIRED_EVENT, onReauthRequired);
  }, [goToLogin]);

  useEffect(() => {
    if (bootStarted.current) return;
    bootStarted.current = true;
    async function boot() {
      const gate = await ensurePortalSession(portalSurface(window.location.pathname));
      if (gate.redirectToLogin && !isPublicOnlyPath(window.location.pathname)) {
        // Deployments without a dedicated sign-in page report the portal path
        // itself as login_url, so this must never resolve to the current page.
        const dest = loginDestinationWithIntent(gate.loginUrl, null);
        if (dest.startsWith('/') && !dest.startsWith('//')) {
          history.replaceState(null, '', dest);
          setPath(window.location.pathname);
        } else {
          window.location.replace(dest);
          return;
        }
      }
      const nextConfig = gate.config;
      const nextSession = gate.session;
      // Defense-in-depth: honor our own stored `expires_at` before rendering the authenticated
      // shell, instead of waiting for an API 401. A missing/unparseable expiry (dev-headers) is
      // not treated as expired, so local development is unaffected (RBAC-02).
      if (nextSession && isSessionExpired(nextSession) && !isPublicOnlyPath(window.location.pathname)) {
        clearSession();
        setSession(null);
        const candidate = portalSurface(window.location.pathname) === 'staff'
          ? nextConfig?.staffLoginPath
          : nextConfig?.loginUrl;
        window.location.replace(loginDestinationWithIntent(candidate, 'session_expired'));
        return;
      }
      setConfig(nextConfig);
      setSession(nextSession);
      // Re-arm the one-shot re-auth latch for this newly established session, so
      // a later expiry can still trigger its own single redirect.
      if (nextSession) resetReauthGuard();
      if (!isPublicOnlyPath(window.location.pathname) && nextSession) {
        const bootRoute = getRouteFromLocation();
        setRoute(bootRoute);
        if (routeAllowedFor(nextSession, bootRoute)) {
          await refresh(nextConfig, nextSession, bootRoute);
          lastHydratedRoute.current = bootRoute;
        }
      }
      setLoading(false);
    }
    boot().catch((error) => {
      setData({
        ...EMPTY_PORTAL_DATA,
        loaded: true,
        error: error instanceof Error ? error.message : 'Could not initialize the portal.'
      });
      setLoading(false);
    });
  }, [refresh]);

  useEffect(() => {
    function onHashChange() {
      const nextRoute = getRouteFromLocation();
      const stored = loadSession();
      const accessSession = {
        role: stored?.role ?? activeSession.role,
        principal: stored?.principal ?? activeSession.principal,
        staff_role: stored?.staff_role ?? activeSession.staff_role,
      };
      payloadCommitGate.current.activate(nextRoute);
      if (routeAllowedFor(accessSession, nextRoute) && lastHydratedRoute.current !== nextRoute) setHydratingRoute(nextRoute);
      setRoute(nextRoute);
      setPath(window.location.pathname);
    }
    window.addEventListener('hashchange', onHashChange);
    window.addEventListener('popstate', onHashChange);
    return () => {
      window.removeEventListener('hashchange', onHashChange);
      window.removeEventListener('popstate', onHashChange);
    };
  }, [activeSession.principal, activeSession.role, activeSession.staff_role]);

  useEffect(() => {
    function onInternalLinkClick(e: MouseEvent) {
      if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      const anchor = (e.target as HTMLElement)?.closest('a');
      if (!anchor) return;
      const href = anchor.getAttribute('href');
      if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:') || anchor.target === '_blank') return;
      if (href.startsWith('/') && !href.startsWith('//')) {
        e.preventDefault();
        const currentFull = window.location.pathname + window.location.search + window.location.hash;
        if (currentFull !== href) {
          window.history.pushState(null, '', href);
          setPath(window.location.pathname);
          setRoute(getRouteFromLocation());
        }
      }
    }
    document.addEventListener('click', onInternalLinkClick);
    return () => document.removeEventListener('click', onInternalLinkClick);
  }, []);

  useEffect(() => {
    if (!config || loading) return;
    const stored = loadSession();
    if (!stored) return;
    if (sessionIdentity(stored) === sessionIdentity(session)) return;
    setSession(stored);
    if (routeAllowedFor(stored, route)) void refresh(config, stored, route, { force: true });
  }, [route, path, config, loading, refresh, session]);

  useEffect(() => {
    if (loading || !config || !session) return;
    if (isPublicOnlyPath(path)) return;
    if (!routeAllowedFor(session, route)) return;
    if (lastHydratedRoute.current === route) return;
    lastHydratedRoute.current = route;
    setHydratingRoute(route);
    void refresh(config, session, route);
  }, [route, loading, config, session, path, refresh]);

  function handleRouteChange(nextRoute: RouteId) {
    payloadCommitGate.current.activate(nextRoute);
    if (nextRoute !== route && lastHydratedRoute.current !== nextRoute && routeAllowedFor(session, nextRoute)) {
      setHydratingRoute(nextRoute);
    }
    setRoute(nextRoute);
  }

  function handleRoleChange(role: string) {
    // Role switcher is a local dev-headers convenience only — never elevate OIDC sessions.
    if (config?.authMode !== 'dev-headers') return;
    const next = {
      ...activeSession,
      mode: 'dev-headers',
      principal: 'customer',
      role
    };
    saveSession(next);
    setSession(next);
    if (routeAllowedFor(next, route)) void refresh(config, next, route, { force: true });
  }

  /** Always re-read sessionStorage so SOC execution-tenant updates are not stale. */
  const handleRefresh = useCallback(async (datasets?: readonly PortalDataset[]) => {
    if (!config) return;
    const stored = loadSession();
    // loadSession() returns null once it has purged an expired session. Falling
    // back to the in-memory session here resurrected exactly the credential that
    // was just discarded and kept sending its stale token on every refresh.
    if (!stored) {
      goToLogin();
      return;
    }
    if (sessionIdentity(stored) !== sessionIdentity(session)) {
      setSession(stored);
    }
    if (!routeAllowedFor(stored, route)) return;
    await refresh(config, stored, route, datasets ? { datasets } : { force: true });
  }, [config, session, refresh, route, goToLogin]);

  if (loading || !config) return <LoadingScreen />;

  if (path === '/' || path === '/landing.html') return <PublicLandingPage config={config} />;
  if (path === '/login' || path === '/login.html') return <LoginPage config={config} />;
  if (path === '/signup' || path === '/signup.html') return <SignupPage config={config} />;
  if (path === '/signup-status') return <SignupStatusPage config={config} />;
  if (path === '/set-password') return <SetPasswordPage config={config} />;
  if (path === '/internal/admin/login' || path === '/staff-login.html') return <StaffLoginPage config={config} />;

  return (
    <ConfirmModalProvider>
    <AppShell
      route={route}
      session={activeSession}
      data={data}
      onRouteChange={handleRouteChange}
      onRoleChange={handleRoleChange}
      onRefresh={() => void handleRefresh()}
      showRoleSwitcher={config.authMode === 'dev-headers' && activeSession.principal !== 'staff'}
    >
      {routeAllowed ? (
        <RouteView
          route={route}
          data={data}
          config={config}
          session={activeSession}
          onRefresh={handleRefresh}
          hydrating={hydratingRoute === route}
        />
      ) : (
        <PortalUnavailablePage
          kind="access-denied"
          requestedLabel={ROUTE_BY_ID.get(route)?.label}
          role={(activeSession.principal === 'staff' ? activeSession.staff_role : activeSession.role) ?? ''}
          homeHref={`#${fallbackRouteForSession(activeSession)}`}
          homeLabel={`Go to ${ROUTE_BY_ID.get(fallbackRouteForSession(activeSession))?.label ?? 'home'}`}
        />
      )}
    </AppShell>
    {session ? (
      <EvidenceInspectorHost config={config} session={activeSession} data={data} locationKey={`${path}|${route}`} />
    ) : null}
    </ConfirmModalProvider>
  );
}
