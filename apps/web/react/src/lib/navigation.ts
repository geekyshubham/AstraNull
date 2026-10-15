import {
  Activity,
  Bell,
  CalendarClock,
  ClipboardList,
  Crosshair,
  FileText,
  Gauge,
  KeyRound,
  LifeBuoy,
  LayoutDashboard,
  ListChecks,
  LockKeyhole,
  PlugZap,
  ShieldCheck,
  Target,
  TriangleAlert,
  UserCog
} from 'lucide-react';
import type { NavItem, RouteId, SurfaceKind } from './types';

export const NAV_GROUP_LABELS: Record<SurfaceKind, string> = {
  overview: 'Overview',
  scope: 'Scope',
  validation: 'Validation',
  governance: 'Governance',
  account: 'Account',
  staff: 'Staff'
};

/** Customer sidebar items (Targets first; deferred execution history omitted) + two staff items. */
export const NAV_ITEMS: NavItem[] = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    group: 'overview',
    description: 'Readiness score, coverage, vectors, findings, and validation activity.',
    icon: LayoutDashboard
  },
  {
    id: 'targets',
    label: 'Targets',
    group: 'scope',
    description: 'Declared hostnames, IPs, and endpoints with ownership proof, tags, and the next validation step.',
    icon: Crosshair
  },
  {
    id: 'checks',
    label: 'Check library',
    group: 'validation',
    description: 'Browse 721 vectors, evidence boundaries, expected controls, and exact-target bounded checks.',
    icon: ListChecks
  },
  {
    id: 'test-policies',
    label: 'Validation schedules',
    group: 'validation',
    description: 'Scheduled validation cadences, schedule windows, and target bindings. Each schedule declares when checks run and the verdict they expect.',
    icon: CalendarClock
  },
  {
    id: 'findings',
    label: 'Findings',
    group: 'validation',
    description: 'Evidence-backed gaps, owners, SLAs, and remediation status.',
    icon: TriangleAlert
  },
  {
    id: 'reports',
    label: 'Reports',
    group: 'governance',
    description: 'Executive, technical, audit, and compliance report builders.',
    icon: FileText
  },
  {
    id: 'integrations',
    label: 'Integrations',
    group: 'governance',
    description: 'Optional read-only DNS/WAF provider connectors, manual metadata records, and alert channels.',
    icon: PlugZap
  },
  {
    id: 'notifications',
    label: 'Notifications',
    group: 'governance',
    description: 'Safe in-app rules, provider status, retries, and DLQ recovery.',
    icon: Bell
  },
  {
    id: 'audit',
    label: 'Audit log',
    group: 'governance',
    description: 'Tenant actions, security-relevant changes, and custody chain records.',
    icon: ClipboardList
  },
  {
    id: 'settings',
    label: 'Settings',
    group: 'account',
    description: 'Tenant profile, roles, tokens, retention, SSO, and safe defaults.',
    icon: KeyRound
  },
  {
    id: 'support',
    label: 'Support',
    group: 'account',
    description: 'Support readiness, escalation paths, runbook references, and non-production on-call posture.',
    icon: LifeBuoy
  },
  {
    id: 'admin',
    label: 'Admin console',
    group: 'staff',
    description: 'Internal overview for sign-ups, tenant lifecycle, approvals, support, and internal audit.',
    icon: UserCog
  },
  {
    id: 'internal-soc',
    label: 'SOC console',
    group: 'staff',
    description: 'Governed high-scale request review, authorization packs, and tenant kill switch.',
    icon: Gauge
  }
];

/** Detail routes reachable via deep-link but hidden from the sidebar. */
export const DETAIL_ROUTE_ITEMS: NavItem[] = [
  {
    id: 'runs',
    label: 'Test runs',
    group: 'validation',
    description: 'Legacy execution list. Results and evidence now live on each target and check; this address still resolves for existing links.',
    icon: Activity
  },
  {
    id: 'check-detail',
    label: 'Check detail',
    group: 'validation',
    description: 'Vector family, safety mode, bounds, expected behavior, and recent verdicts for one check.',
    icon: ListChecks
  },
  {
    id: 'policy-detail',
    label: 'Schedule detail',
    group: 'validation',
    description: 'Cadence, target bindings, expected verdicts, safe windows, and high-scale gating for one schedule.',
    icon: ClipboardList
  },
  {
    id: 'target-detail',
    label: 'Target detail',
    group: 'scope',
    description: 'Per-target checks, runs, findings, WAF posture, and verification ladder.',
    icon: Target
  },
  {
    id: 'run-detail',
    label: 'Run detail',
    group: 'validation',
    description: 'Timeline, probe result, correlation truth table, and evidence chain for one run.',
    icon: Activity
  },
  {
    id: 'scan-detail',
    label: 'Validation scan',
    group: 'scope',
    description: 'Live step progress, bounded request and response metadata, requests sent, verdicts, and the metadata-only activity log for one validation scan.',
    icon: Activity
  },
  {
    id: 'finding-detail',
    label: 'Finding detail',
    group: 'validation',
    description: 'Verdict explanation, triage state, remediation, evidence bundle, and custody export for one finding.',
    icon: TriangleAlert
  },
  {
    id: 'finding-group-detail',
    label: 'Finding group',
    group: 'validation',
    description: 'Affected assets, shared verdict, and remediation context for one grouped finding.',
    icon: TriangleAlert
  },
  {
    id: 'evidence-detail',
    label: 'Evidence detail',
    group: 'validation',
    description: 'Artifact record, custody chain position, SHA-256 digest, and sealed payload for one evidence artifact.',
    icon: ShieldCheck
  },
  {
    id: 'report-detail',
    label: 'Report detail',
    group: 'governance',
    description: 'Report kind, custody preview, export formats, and digest verification for one generated report.',
    icon: FileText
  },
  {
    id: 'tenant-detail',
    label: 'Tenant detail',
    group: 'staff',
    description: 'Tenant lifecycle, users, entitlements, notes, support actions, subscriptions, and audit activity.',
    icon: UserCog
  },
  {
    id: 'queue-detail',
    label: 'Queue detail',
    group: 'staff',
    description: 'SOC execution workspace with queue context, artifacts, adapter telemetry, and notes for one request.',
    icon: ShieldCheck
  }
];

export type RouteCrumb = { group: SurfaceKind; label: string };

/** Customers never see a Staff group: their SOC console reads as Governance and a queue item as a high-scale request. */
export function routeCrumb(item: { id: string; group: SurfaceKind; label: string }, principal?: string): RouteCrumb {
  if (String(principal ?? '').trim().toLowerCase() === 'staff') return { group: item.group, label: item.label };
  if (item.id === 'queue-detail') return { group: 'validation', label: 'High-scale request' };
  if (item.id === 'internal-soc') return { group: 'governance', label: item.label };
  return { group: item.group, label: item.label };
}

export const ROUTE_BY_ID = new Map<RouteId, NavItem>(
  [...NAV_ITEMS, ...DETAIL_ROUTE_ITEMS].map((item) => [item.id, item])
);

/** Retired hash routes and the live route each one now opens. */
const RETIRED_HASH_ROUTES: Readonly<Record<string, RouteId>> = {
  'target-group': 'targets',
  'target-groups': 'targets',
  'target-group-detail': 'targets',
  subscription: 'dashboard'
};

function hashRoutePart(hash: string) {
  const raw = hash.replace(/^#/, '');
  return raw.includes('?') ? raw.slice(0, raw.indexOf('?')) : raw;
}

function routeIdFromHash(hash: string): RouteId | null {
  const routePart = hashRoutePart(hash);
  if (!routePart) return null;
  const retired = RETIRED_HASH_ROUTES[routePart];
  if (retired) return retired;
  return ROUTE_BY_ID.has(routePart as RouteId) ? routePart as RouteId : null;
}

/** Resolve only real React routes. Unknown hashes never inherit the pathname's dashboard. */
export function resolvePortalRoute(pathname: string, hash = ''): RouteId {
  if (hash.replace(/^#/, '')) return routeIdFromHash(hash) ?? 'not-found';

  const pathRoute = pathname.replace(/^\/+/, '').replace(/\/+$/, '');
  if (pathname === '/internal/admin') return 'admin';
  if (pathname === '/internal/soc') return 'internal-soc';
  if (pathRoute === 'internal-soc.html') return 'internal-soc';
  if (pathRoute === 'index.html' || pathRoute === 'app' || pathRoute === '') return 'dashboard';

  const normalizedPathRoute = pathRoute.endsWith('.html') ? pathRoute.slice(0, -5) : pathRoute;
  if (ROUTE_BY_ID.has(normalizedPathRoute as RouteId)) return normalizedPathRoute as RouteId;
  return 'not-found';
}

export function getRouteFromHash(): RouteId {
  return resolvePortalRoute(window.location.pathname, window.location.hash);
}

export function getRouteFromLocation(): RouteId {
  const route = resolvePortalRoute(window.location.pathname, window.location.hash);
  const retired = RETIRED_HASH_ROUTES[hashRoutePart(window.location.hash)];
  if (retired) {
    window.history.replaceState(window.history.state, '', `${window.location.pathname}${window.location.search}#${retired}`);
  }
  return route;
}

export const PLATFORM_PROMISE =
  'AstraNull proves DDoS readiness for customer-declared targets without requiring cloud credentials or automatic IP inventory discovery.';

export const DEFENSIVE_RULES = [
  {
    title: 'No-access-first',
    body: 'Core workflows start from customer-declared targets and do not require cloud credentials.'
  },
  {
    title: 'Outside-in only',
    body: 'Validation runs from external probes against declared targets; nothing is installed in your network.'
  },
  {
    title: 'Governed safety limits',
    body: 'Validation runs under bounded safety limits, strict timeouts, and tenant kill-switch controls.'
  },
  {
    title: 'Evidence over assumptions',
    body: 'Every verdict links back to observed external probe evidence, health signals, approvals, or declarations.'
  }
];

export const STAFF_LINKS = [
  {
    label: 'Internal Admin',
    href: '/internal/admin',
    icon: LockKeyhole,
    description: 'Staff-only tenant, sign-up, support, and approval management.'
  },
  {
    label: 'SOC console',
    href: '/internal/soc',
    icon: Gauge,
    description: 'Staff execution plane for governed high-scale operations.'
  }
];