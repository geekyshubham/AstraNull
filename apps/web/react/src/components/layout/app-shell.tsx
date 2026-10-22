import { Globe, LogOut, Menu, Moon, PanelLeftClose, PanelLeftOpen, ShieldUser, Sun, UserRound, X } from 'lucide-react';
import type { MouseEvent, ReactNode, Ref } from 'react';
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { clearSession } from '../../lib/api';
import { NAV_GROUP_LABELS, NAV_ITEMS, ROUTE_BY_ID, routeCrumb, type RouteCrumb } from '../../lib/navigation';
import { canAccessRoute } from '../../lib/route-access';
import type { NavItem, PortalData, RouteId, Session } from '../../lib/types';
import { cn } from '../../lib/utils';
import { AnchorButton, Button } from '../ui/button';
import { RouteTransition } from '../ui/motion';
import { Select } from '../ui/select';
import { Brand } from './brand';
import { DETAIL_LIST_LINKS } from './detail-back-link';

type AppShellProps = {
  route: RouteId;
  session: Session;
  data: PortalData;
  onRouteChange: (route: RouteId) => void;
  onRoleChange: (role: string) => void;
  onRefresh: () => void;
  /** Dev-headers only: show role switcher for local RBAC previews. */
  showRoleSwitcher?: boolean;
  accessNotice?: string;
  onDismissAccessNotice?: () => void;
  /** Page-level actions shown in the topbar, such as AI insights. */
  topbarActions?: ReactNode;
  children: ReactNode;
};

const roles = [
  { value: 'admin', label: 'admin', description: 'Full developer validation access' },
  { value: 'engineer', label: 'engineer', description: 'Runs and declared domains' },
  { value: 'soc', label: 'soc', description: 'SOC-gated workflow preview' },
  { value: 'auditor', label: 'auditor', description: 'Evidence and audit visibility' },
  { value: 'viewer', label: 'viewer', description: 'Read-only workspace' },
  { value: 'owner', label: 'owner', description: 'Tenant owner access' }
];

type ShellIconButtonProps = {
  label: string;
  onClick: () => void;
  className?: string;
  variant?: 'ghost' | 'secondary';
  buttonRef?: Ref<HTMLButtonElement>;
  expanded?: boolean;
  controls?: string;
  children: ReactNode;
};

function ShellIconButton({ label, onClick, className, variant = 'ghost', buttonRef, expanded, controls, children }: ShellIconButtonProps) {
  return (
    <Button
      ref={buttonRef}
      type="button"
      variant={variant}
      size="icon"
      className={className}
      onClick={onClick}
      aria-label={label}
      aria-expanded={expanded}
      aria-controls={controls}
      title={label}
    >
      {children}
    </Button>
  );
}

const NAV_PARENT_ROUTE: Partial<Record<string, RouteId>> = {
  'target-detail': 'targets',
  'scan-detail': 'targets',
  'run-detail': 'targets',
  runs: 'targets',
  'check-detail': 'checks',
  'policy-detail': 'test-policies',
  'finding-detail': 'findings',
  'finding-group-detail': 'findings',
  'evidence-detail': 'findings',
  'report-detail': 'reports',
  'tenant-detail': 'admin',
  'queue-detail': 'internal-soc'
};

type EntityTitleState = { route: RouteId; title: string } | null;

const EntityTitleContext = createContext<(title: string | null) => void>(() => {});

/** Names the open record in the document title (e.g. "checkout.acme.com · Targets · AstraNull") while a detail view is mounted. */
export function useEntityDocumentTitle(title?: string) {
  const setEntityTitle = useContext(EntityTitleContext);
  const text = title?.trim() ?? '';
  useEffect(() => {
    setEntityTitle(text || null);
    return () => setEntityTitle(null);
  }, [setEntityTitle, text]);
}

function sentenceStart(text: string) {
  return text ? `${text.charAt(0).toUpperCase()}${text.slice(1)}` : text;
}

function roleLabelFor(role?: string) {
  return sentenceStart(String(role ?? '').trim().replaceAll('_', ' '));
}

function accountInitials(label: string) {
  const words = label.replace(/^ten_/i, '').split(/[\s_.-]+/).filter(Boolean);
  const letters = words.length > 1 ? `${words[0][0]}${words[1][0]}` : (words[0] ?? '').slice(0, 2);
  return letters.toUpperCase();
}

function documentTitleFor(route: RouteId, crumb: RouteCrumb, entityTitle: string | null) {
  const groupLabel = NAV_GROUP_LABELS[crumb.group];
  if (!entityTitle) return `${crumb.label} · ${groupLabel} · AstraNull`;
  const listLabel = DETAIL_LIST_LINKS[route]?.label;
  return `${entityTitle} · ${listLabel ? sentenceStart(listLabel) : groupLabel} · AstraNull`;
}

function NavLink({
  item,
  active,
  current = 'page',
  onClick,
  buttonRef
}: {
  item: NavItem;
  active: boolean;
  current?: 'page' | 'true';
  onClick: () => void;
  buttonRef?: Ref<HTMLButtonElement>;
}) {
  const Icon = item.icon;
  return (
    <button
      ref={buttonRef}
      type="button"
      className={cn('nav-item', active && 'active', active && 'is-active')}
      onClick={onClick}
      aria-label={item.label}
      aria-current={active ? current : undefined}
      title={item.label}
    >
      <Icon size={16} aria-hidden="true" focusable="false" />
      <span>{item.label}</span>
      {item.count ? <span className="nav-count">{item.count}</span> : null}
    </button>
  );
}

function ThemeToggle({ theme, onToggle }: { theme: 'light' | 'dark'; onToggle: () => void }) {
  const isDark = theme === 'dark';
  const label = isDark ? 'Switch to light theme' : 'Switch to dark theme';
  return (
    <ShellIconButton label={label} onClick={onToggle} className="theme-toggle">
      {isDark ? <Sun size={18} aria-hidden="true" focusable="false" /> : <Moon size={18} aria-hidden="true" focusable="false" />}
    </ShellIconButton>
  );
}

export function AppShell({
  route,
  session,
  data,
  onRouteChange,
  onRoleChange,
  onRefresh,
  showRoleSwitcher = false,
  accessNotice = '',
  onDismissAccessNotice,
  topbarActions,
  children
}: AppShellProps) {
  const [theme, setTheme] = useState<'light' | 'dark'>(() =>
    document.documentElement.dataset.theme === 'light' ? 'light' : 'dark'
  );
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [topbarScrolled, setTopbarScrolled] = useState(false);
  const sidebarRef = useRef<HTMLElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const mainRef = useRef<HTMLElement>(null);
  const activeNavRef = useRef<HTMLButtonElement>(null);
  const routeArrivedRef = useRef(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try {
      return window.localStorage.getItem('astranull.react.sidebar.collapsed') === '1';
    } catch {
      return false;
    }
  });
  const current = route === 'not-found'
    ? { id: 'not-found', label: 'Not found', group: 'overview' as const }
    : ROUTE_BY_ID.get(route) ?? NAV_ITEMS[0];
  const crumb = routeCrumb(current, session.principal);
  const tenantId = session.tenant_id ?? data.state?.tenant_id ?? 'unknown';
  const tenantName = typeof data.tenant?.name === 'string' ? data.tenant.name.trim() : '';
  const isStaffPrincipal = session.principal === 'staff';
  const [entityTitleState, setEntityTitleState] = useState<EntityTitleState>(null);
  const entityTitle = entityTitleState?.route === route ? entityTitleState.title : null;
  const setEntityTitle = useCallback(
    (title: string | null) => setEntityTitleState(title ? { route, title } : null),
    [route],
  );
  const activeNavId = NAV_PARENT_ROUTE[route] ?? route;
  const environment = (data.state as { environment?: string } | null)?.environment ?? '';
  const visibleNavItems = useMemo(() => {
    const role = session.role ?? 'admin';
    return NAV_ITEMS.filter((item) => {
      if (item.id.endsWith('-detail')) {
        return false;
      }
      return canAccessRoute(role, item.id, {
        principal: session.principal,
        staffRole: session.staff_role,
      });
    });
  }, [session.principal, session.role, session.staff_role]);

  const grouped = useMemo(() => {
    return visibleNavItems.reduce<Record<string, NavItem[]>>((acc, item) => {
      const { group } = routeCrumb(item, session.principal);
      acc[group] = [...(acc[group] ?? []), item];
      return acc;
    }, {});
  }, [visibleNavItems, session.principal]);

  // The topbar is sticky: it only earns a separating hairline once page content
  // has actually moved underneath it.
  useEffect(() => {
    function onScroll() {
      setTopbarScrolled(window.scrollY > 4);
    }
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  useEffect(() => {
    if (!sidebarOpen || !window.matchMedia('(max-width: 1120px)').matches) return undefined;
    const previousFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : menuButtonRef.current;
    const sidebar = sidebarRef.current;
    const focusableSelector = [
      'a[href]',
      'button:not([disabled])',
      'input:not([disabled])',
      'select:not([disabled])',
      'textarea:not([disabled])',
      '[tabindex]:not([tabindex="-1"])'
    ].join(',');
    closeButtonRef.current?.focus();

    function onDrawerKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        if (event.defaultPrevented) return;
        event.preventDefault();
        setSidebarOpen(false);
        return;
      }
      if (event.key !== 'Tab' || !sidebar) return;
      const focusable = Array.from(sidebar.querySelectorAll<HTMLElement>(focusableSelector))
        .filter((element) => element.getClientRects().length > 0);
      if (focusable.length === 0) {
        event.preventDefault();
        sidebar.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }

    // While the drawer is modal, the page behind it is neither scrollable nor reachable by
    // assistive tech (aria-modal alone is not honoured by every screen reader).
    const main = mainRef.current;
    document.body.classList.add('nav-drawer-open');
    if (main) main.inert = true;

    document.addEventListener('keydown', onDrawerKeyDown);
    return () => {
      document.removeEventListener('keydown', onDrawerKeyDown);
      document.body.classList.remove('nav-drawer-open');
      if (main) main.inert = false;
      previousFocus?.focus();
    };
  }, [sidebarOpen]);

  // Widening past the drawer breakpoint while it is open would leave a desktop sidebar
  // announced as a modal dialog, so the drawer closes itself at that boundary.
  useEffect(() => {
    if (!sidebarOpen) return undefined;
    const drawerQuery = window.matchMedia('(max-width: 1120px)');
    function onViewportChange(event: MediaQueryListEvent) {
      if (!event.matches) setSidebarOpen(false);
    }
    drawerQuery.addEventListener('change', onViewportChange);
    return () => drawerQuery.removeEventListener('change', onViewportChange);
  }, [sidebarOpen]);

  /**
   * Announce the current location to assistive tech and browser history the same way a
   * multi-page app would: a route-specific title, and focus moved to the content region
   * on arrival so keyboard users do not restart from the top of the navigation.
   */
  const documentTitle = documentTitleFor(route, crumb, entityTitle);
  useEffect(() => {
    document.title = documentTitle;
  }, [documentTitle]);

  // The nav list scrolls once enough routes are visible for a role, and the
  // selected row could sit outside it — leaving only a sliver of the accent fill
  // at the clipped edge, which reads as a stray bar rather than "you are here".
  useEffect(() => {
    activeNavRef.current?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }, [route, visibleNavItems]);

  useEffect(() => {
    if (!routeArrivedRef.current) {
      // Skip the initial mount so a fresh page load keeps the document's natural focus.
      routeArrivedRef.current = true;
      return;
    }
    mainRef.current?.focus({ preventScroll: true });
  }, [route]);

  function navigate(next: RouteId) {
    window.location.hash = next;
    onRouteChange(next);
    setSidebarOpen(false);
  }

  function logout() {
    const staff = session.principal === 'staff';
    clearSession();
    window.location.href = staff
      ? (typeof window !== 'undefined' && session.staff_login_path
        ? session.staff_login_path
        : '/internal/admin/login')
      : '/login';
  }

  function toggleTheme() {
    const next = theme === 'dark' ? 'light' : 'dark';
    if (next === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
    document.getElementById('theme-color-meta')?.setAttribute('content', getComputedStyle(document.documentElement).getPropertyValue('--bg').trim());
    try {
      localStorage.setItem('astranull.theme', next);
    } catch {
      // Best-effort preference persistence only.
    }
    setTheme(next);
  }

  function skipToMain(event: MouseEvent<HTMLAnchorElement>) {
    event.preventDefault();
    mainRef.current?.focus();
  }

  function toggleSidebarCollapsed() {
    setSidebarCollapsed((currentValue) => {
      const next = !currentValue;
      try {
        window.localStorage.setItem('astranull.react.sidebar.collapsed', next ? '1' : '0');
      } catch {
        // Best-effort preference persistence only.
      }
      return next;
    });
  }

  const collapseLabel = sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar';
  const CollapseIcon = sidebarCollapsed ? PanelLeftOpen : PanelLeftClose;
  const roleLabel = roleLabelFor(isStaffPrincipal ? session.staff_role : session.role)
    || (isStaffPrincipal ? 'Staff' : 'Role not recorded');
  const workspaceLabel = tenantName || tenantId;
  const signedInAs = isStaffPrincipal ? session.staff_id ?? session.user_id : session.user_id;
  const accountTitle = [
    isStaffPrincipal ? 'Staff session' : `Workspace ${tenantName ? `${tenantName} (${tenantId})` : tenantId}`,
    signedInAs ? `Signed in as ${signedInAs}` : '',
    `Role ${roleLabel}`,
    environment ? `Environment ${environment}` : ''
  ].filter(Boolean).join(' · ');
  const avatarInitials = !isStaffPrincipal && (tenantName || tenantId !== 'unknown') ? accountInitials(workspaceLabel) : '';

  return (
    <div className={cn('app-shell', sidebarCollapsed && 'sidebar-collapsed')}>
      <a className="skip-link" href="#portal-main" onClick={skipToMain}>Skip to main content</a>
      <aside
        id="portal-navigation"
        ref={sidebarRef}
        className={cn('sidebar', sidebarOpen && 'open')}
        role={sidebarOpen ? 'dialog' : undefined}
        aria-modal={sidebarOpen ? true : undefined}
        aria-label={sidebarOpen ? 'Portal navigation' : undefined}
        tabIndex={sidebarOpen ? -1 : undefined}
      >
        <div className="sidebar-head">
          <Brand />
          <div className="sidebar-head-actions">
            <ShellIconButton label="Close navigation" className="sidebar-close" buttonRef={closeButtonRef} onClick={() => setSidebarOpen(false)}>
              <X size={17} aria-hidden="true" focusable="false" />
            </ShellIconButton>
          </div>
        </div>
        <nav className="nav-scroll" aria-label="Portal">
          {(Object.keys(grouped) as Array<keyof typeof NAV_GROUP_LABELS>)
            .filter((group) => (grouped[group]?.length ?? 0) > 0)
            .map((group) => (
            <div className="nav-group" key={group}>
              <p>{NAV_GROUP_LABELS[group]}</p>
              {grouped[group]?.map((item) => (
                <NavLink
                  key={item.id}
                  item={item}
                  active={item.id === activeNavId}
                  current={item.id === route ? 'page' : 'true'}
                  buttonRef={item.id === activeNavId ? activeNavRef : undefined}
                  onClick={() => navigate(item.id)}
                />
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="sidebar-account" title={accountTitle}>
            <span className="sidebar-avatar" aria-hidden="true">
              {isStaffPrincipal ? (
                <ShieldUser size={16} aria-hidden="true" focusable="false" />
              ) : avatarInitials || <UserRound size={16} aria-hidden="true" focusable="false" />}
            </span>
            <span className="sidebar-account-copy">
              {isStaffPrincipal ? (
                <span className="sidebar-account-name">Staff session</span>
              ) : (
                <b className="sidebar-account-name" title={tenantId}>{tenantName || tenantId}</b>
              )}
              <span className="sidebar-account-meta">
                {roleLabel}
                {environment ? <> · {environment}</> : null}
              </span>
            </span>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="sidebar-foot-btn sidebar-signout"
              onClick={logout}
              aria-label="Sign out"
              title="Sign out"
            >
              <LogOut size={16} aria-hidden="true" focusable="false" />
            </Button>
          </div>
          {showRoleSwitcher ? (
            <Select
              label="Role (dev)"
              className="sidebar-role"
              value={session.role ?? 'admin'}
              options={roles}
              onChange={onRoleChange}
            />
          ) : null}
          <div className="sidebar-foot-actions">
            <AnchorButton
              href="/"
              variant="ghost"
              size="sm"
              className="sidebar-foot-btn sidebar-foot-link"
              aria-label="Public site"
              title="Public site"
            >
              <Globe size={16} aria-hidden="true" focusable="false" />
              <span>Public site</span>
            </AnchorButton>
            <ShellIconButton
              label={collapseLabel}
              className="sidebar-foot-btn sidebar-collapse"
              onClick={toggleSidebarCollapsed}
            >
              <CollapseIcon size={16} aria-hidden="true" focusable="false" />
            </ShellIconButton>
          </div>
        </div>
      </aside>
      <div className={cn('scrim', sidebarOpen && 'open')} onClick={() => setSidebarOpen(false)} aria-hidden="true" />
      <main
        className="main"
        id="portal-main"
        ref={mainRef}
        tabIndex={-1}
        aria-label={`${crumb.label} workspace`}
      >
        <header className={cn('topbar', topbarScrolled && 'is-scrolled')}>
          <ShellIconButton label="Open navigation" className="menu-btn" buttonRef={menuButtonRef} expanded={sidebarOpen} controls="portal-navigation" onClick={() => setSidebarOpen(true)}>
            <Menu size={18} aria-hidden="true" focusable="false" />
          </ShellIconButton>
          <nav className="crumbs" aria-label="Breadcrumb">
            <span className="crumbs-group">{NAV_GROUP_LABELS[crumb.group]}</span>
            <span className="sep" aria-hidden="true">
              ›
            </span>
            <b aria-current="page">{crumb.label}</b>
          </nav>
          <div className="topbar-spacer" aria-hidden="true" />
          {topbarActions}
          <ThemeToggle theme={theme} onToggle={toggleTheme} />
        </header>
        {data.error ? (
          <div className="portal-load-error" role="alert">
            <div className="portal-load-error-body">
              <strong>Could not load some workspace data</strong>
              <p>{data.error}</p>
            </div>
            <Button type="button" variant="secondary" size="sm" onClick={onRefresh}>
              Retry
            </Button>
          </div>
        ) : null}
        {accessNotice ? (
          <div className="form-banner info route-access-notice" role="status" aria-live="polite">
            <span>{accessNotice}</span>
            {onDismissAccessNotice ? (
              <Button type="button" variant="ghost" size="sm" onClick={onDismissAccessNotice}>
                Dismiss
              </Button>
            ) : null}
          </div>
        ) : null}
        <EntityTitleContext.Provider value={setEntityTitle}>
          <RouteTransition routeKey={route}>{children}</RouteTransition>
        </EntityTitleContext.Provider>
      </main>
    </div>
  );
}