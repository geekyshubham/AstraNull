import { ChevronLeft, ChevronRight, Menu, Moon, Sun, X } from 'lucide-react';
import type { ReactNode, Ref } from 'react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { clearSession } from '../../lib/api';
import { NAV_GROUP_LABELS, NAV_ITEMS, ROUTE_BY_ID } from '../../lib/navigation';
import { canAccessRoute } from '../../lib/route-access';
import type { NavItem, PortalData, RouteId, Session } from '../../lib/types';
import { cn } from '../../lib/utils';
import { Button } from '../ui/button';
import { Select } from '../ui/select';
import { Brand } from './brand';

type AppShellProps = {
  route: RouteId;
  session: Session;
  data: PortalData;
  onRouteChange: (route: RouteId) => void;
  onRoleChange: (role: string) => void;
  onRefresh: () => void;
  /** Dev-headers only: show role switcher for local RBAC previews. */
  showRoleSwitcher?: boolean;
  children: ReactNode;
};

const roles = [
  { value: 'admin', label: 'admin', description: 'Full developer validation access' },
  { value: 'engineer', label: 'engineer', description: 'Runs, agents, target groups' },
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

function NavLink({ item, active, onClick }: { item: NavItem; active: boolean; onClick: () => void }) {
  const Icon = item.icon;
  return (
    <button
      type="button"
      className={cn('nav-item', active && 'active', active && 'is-active')}
      onClick={onClick}
      aria-label={item.label}
      aria-current={active ? 'page' : undefined}
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
      {isDark ? <Moon size={18} aria-hidden="true" focusable="false" /> : <Sun size={18} aria-hidden="true" focusable="false" />}
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
  children
}: AppShellProps) {
  const [theme, setTheme] = useState<'light' | 'dark'>(() =>
    document.documentElement.dataset.theme === 'light' ? 'light' : 'dark'
  );
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const sidebarRef = useRef<HTMLElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try {
      return window.localStorage.getItem('astranull.react.sidebar.collapsed') === '1';
    } catch {
      return false;
    }
  });
  const current = ROUTE_BY_ID.get(route) ?? NAV_ITEMS[0];
  const tenantId = session.tenant_id ?? data.state?.tenant_id ?? 'unknown';
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
      acc[item.group] = [...(acc[item.group] ?? []), item];
      return acc;
    }, {});
  }, [visibleNavItems]);

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

    document.addEventListener('keydown', onDrawerKeyDown);
    return () => {
      document.removeEventListener('keydown', onDrawerKeyDown);
      previousFocus?.focus();
    };
  }, [sidebarOpen]);

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
    try {
      localStorage.setItem('astranull.theme', next);
    } catch {
      // Best-effort preference persistence only.
    }
    setTheme(next);
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
  const CollapseIcon = sidebarCollapsed ? ChevronRight : ChevronLeft;

  return (
    <div className={cn('app-shell', sidebarCollapsed && 'sidebar-collapsed')}>
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
            <ShellIconButton
              label={collapseLabel}
              className="sidebar-collapse"
              onClick={toggleSidebarCollapsed}
            >
              <CollapseIcon size={18} aria-hidden="true" focusable="false" />
            </ShellIconButton>
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
                <NavLink key={item.id} item={item} active={item.id === route} onClick={() => navigate(item.id)} />
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-foot">
          <span>
            <b>{tenantId}</b>
            {environment ? <> · {environment}</> : null}
          </span>
          <span>SOC-gated high-scale</span>
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
            <a href="/" aria-label="Public site">
              Public site
            </a>
            <Button type="button" variant="ghost" size="sm" onClick={logout}>
              Sign out
            </Button>
          </div>
        </div>
      </aside>
      <div className={cn('scrim', sidebarOpen && 'open')} onClick={() => setSidebarOpen(false)} aria-hidden="true" />
      <main className="main">
        <header className="topbar">
          <ShellIconButton label="Open navigation" className="menu-btn" buttonRef={menuButtonRef} expanded={sidebarOpen} controls="portal-navigation" onClick={() => setSidebarOpen(true)}>
            <Menu size={18} aria-hidden="true" focusable="false" />
          </ShellIconButton>
          <div className="crumbs" aria-label="Breadcrumb">
            <span>{NAV_GROUP_LABELS[current.group]}</span>
            <span className="sep" aria-hidden="true">
              ›
            </span>
            <b>{current.label}</b>
          </div>
          <div className="topbar-spacer" aria-hidden="true" />
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
        {children}
      </main>
    </div>
  );
}