import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AppShell } from './components/layout/app-shell';
import {
  clearSession,
  EMPTY_PORTAL_DATA,
  ensurePortalSession,
  fetchPortalData,
  fetchPortalDatasets,
  loadSession,
  portalSurface,
  REAUTH_REQUIRED_EVENT,
  resetReauthGuard,
  resolveLoginDestination,
  saveSession,
  sessionIdentity
} from './lib/api';
import { getRouteFromLocation } from './lib/navigation';
import { canAccessRoute } from './lib/route-access';
import type { PortalConfig, PortalData, PortalDataset, RouteId, Session } from './lib/types';
import { LoginPage, PublicLandingPage, SignupPage, SignupStatusPage, StaffLoginPage } from './pages/public-pages';
import { RouteView } from './pages/router';

function LoadingScreen() {
  return (
    <div className="loading-screen">
      <div className="loading-card">
        <div className="spinner" />
        <strong>Loading AstraNull</strong>
        <p>Preparing the readiness console.</p>
      </div>
    </div>
  );
}

function isPublicOnlyPath(path: string) {
  return ['/', '/landing.html', '/login', '/login.html', '/signup', '/signup.html', '/signup-status', '/internal/admin/login', '/staff-login.html'].includes(path);
}

export default function App() {
  const [route, setRoute] = useState<RouteId>(() => getRouteFromLocation());
  const [path, setPath] = useState(() => window.location.pathname);
  const [config, setConfig] = useState<PortalConfig | null>(null);
  const [session, setSession] = useState<Session | null>(() => loadSession());
  const [data, setData] = useState<PortalData>(EMPTY_PORTAL_DATA);
  const [loading, setLoading] = useState(true);
  const bootStarted = useRef(false);
  const lastHydratedRoute = useRef<RouteId | null>(null);

  const activeSession = useMemo(() => session ?? {}, [session]);

  const refresh = useCallback(async (
    nextConfig: PortalConfig | null,
    nextSession: Session,
    nextRoute: RouteId,
    options: { datasets?: readonly PortalDataset[]; force?: boolean } = {}
  ) => {
    if (!nextConfig) return;
    try {
      const payload = options.datasets
        ? await fetchPortalDatasets(nextConfig, nextSession, options.datasets)
        : await fetchPortalData(nextConfig, nextSession, { route: nextRoute, force: options.force });
      setData(payload);
    } catch (error) {
      setData((current) => ({
        ...current,
        loaded: true,
        error: error instanceof Error ? error.message : 'Could not load workspace data.'
      }));
    }
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
    window.location.replace(resolveLoginDestination(candidate, window.location.pathname));
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
        window.location.replace(resolveLoginDestination(gate.loginUrl, window.location.pathname));
        return;
      }
      const nextConfig = gate.config;
      const nextSession = gate.session;
      setConfig(nextConfig);
      setSession(nextSession);
      // Re-arm the one-shot re-auth latch for this newly established session, so
      // a later expiry can still trigger its own single redirect.
      if (nextSession) resetReauthGuard();
      if (!isPublicOnlyPath(window.location.pathname) && nextSession) {
        const bootRoute = getRouteFromLocation();
        await refresh(nextConfig, nextSession, bootRoute);
        lastHydratedRoute.current = bootRoute;
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
      const role = stored?.role ?? activeSession.role;
      const accessContext = {
        principal: stored?.principal ?? activeSession.principal,
        staffRole: stored?.staff_role ?? activeSession.staff_role,
      };
      if (!canAccessRoute(role, nextRoute, accessContext)) {
        window.location.replace(`${window.location.pathname}${window.location.search}#dashboard`);
        setRoute('dashboard');
      } else {
        setRoute(nextRoute);
      }
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
    if (!config || loading) return;
    const stored = loadSession();
    if (!stored) return;
    if (sessionIdentity(stored) === sessionIdentity(session)) return;
    setSession(stored);
    void refresh(config, stored, route, { force: true });
  }, [route, path, config, loading, refresh, session]);

  useEffect(() => {
    if (loading || !config) return;
    const role = activeSession.role;
    if (!canAccessRoute(role, route, {
      principal: activeSession.principal,
      staffRole: activeSession.staff_role,
    })) {
      window.location.replace(`${window.location.pathname}${window.location.search}#dashboard`);
      setRoute('dashboard');
    }
  }, [loading, config, route, activeSession.principal, activeSession.role, activeSession.staff_role]);

  useEffect(() => {
    if (loading || !config || !session) return;
    if (isPublicOnlyPath(path)) return;
    if (lastHydratedRoute.current === route) return;
    lastHydratedRoute.current = route;
    void refresh(config, session, route);
  }, [route, loading, config, session, path, refresh]);

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
    void refresh(config, next, route, { force: true });
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
    await refresh(config, stored, route, datasets ? { datasets } : { force: true });
  }, [config, session, refresh, route, goToLogin]);

  if (loading || !config) return <LoadingScreen />;

  if (path === '/' || path === '/landing.html') return <PublicLandingPage config={config} />;
  if (path === '/login' || path === '/login.html') return <LoginPage config={config} />;
  if (path === '/signup' || path === '/signup.html') return <SignupPage config={config} />;
  if (path === '/signup-status') return <SignupStatusPage />;
  if (path === '/internal/admin/login' || path === '/staff-login.html') return <StaffLoginPage config={config} />;

  return (
    <AppShell
      route={route}
      session={activeSession}
      data={data}
      onRouteChange={setRoute}
      onRoleChange={handleRoleChange}
      onRefresh={() => void handleRefresh()}
      showRoleSwitcher={config.authMode === 'dev-headers' && activeSession.principal !== 'staff'}
    >
      <RouteView route={route} data={data} config={config} session={activeSession} onRefresh={handleRefresh} />
    </AppShell>
  );
}
