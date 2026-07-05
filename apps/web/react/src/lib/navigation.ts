import {
  Activity,
  Bell,
  BookOpenCheck,
  Bot,
  Boxes,
  CircleDollarSign,
  ClipboardList,
  FileCheck2,
  FileText,
  Gauge,
  KeyRound,
  LifeBuoy,
  LayoutDashboard,
  ListChecks,
  LockKeyhole,
  Network,
  PanelTop,
  PlugZap,
  Radar,
  ScanSearch,
  ServerCog,
  ShieldCheck,
  ShieldHalf,
  Siren,
  SquareKanban,
  Target,
  TriangleAlert,
  UserCog,
  Wrench
} from 'lucide-react';
import type { NavItem, RouteId, SurfaceKind } from './types';

export const NAV_GROUP_LABELS: Record<SurfaceKind, string> = {
  overview: 'Overview',
  scope: 'Declared scope',
  validation: 'Validation',
  posture: 'Posture',
  governance: 'Governance',
  staff: 'Staff'
};

export const NAV_ITEMS: NavItem[] = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    group: 'overview',
    description: 'Readiness score, coverage, vectors, findings, and SOC status.',
    icon: LayoutDashboard
  },
  {
    id: 'onboarding',
    label: 'Onboarding',
    group: 'overview',
    description: 'Guided environment, target group, agent, safe run, and evidence setup.',
    icon: BookOpenCheck
  },
  {
    id: 'environments',
    label: 'Environments',
    group: 'scope',
    description: 'Declared environment IDs with validation evidence, findings, and active scope counts.',
    icon: ServerCog
  },
  {
    id: 'target-groups',
    label: 'Target Groups',
    group: 'scope',
    description: 'Customer-declared business services, expected behavior, and owners.',
    icon: Target
  },
  {
    id: 'target-group-detail',
    label: 'Target Group Detail',
    group: 'scope',
    description: 'Per-service tabs for targets, expected behavior, agents, checks, runs, findings, and settings.',
    icon: PanelTop
  },
  {
    id: 'agents',
    label: 'Agents',
    group: 'scope',
    description: 'Outbound-only observation agents, placement, versions, and health.',
    icon: Bot
  },
  {
    id: 'agent-detail',
    label: 'Agent Detail',
    group: 'scope',
    description: 'Identity, heartbeat, capabilities, placement evidence, logs, and update history for one outbound agent.',
    icon: Bot
  },
  {
    id: 'checks',
    label: 'Checks',
    group: 'validation',
    description: 'Safe-by-default readiness checks and SOC-gated high-scale scenarios.',
    icon: ListChecks
  },
  {
    id: 'test-policies',
    label: 'Test Policies',
    group: 'validation',
    description: 'Cadence, expected verdicts, target bindings, safe windows, and high-scale policy gating.',
    icon: ClipboardList
  },
  {
    id: 'runs',
    label: 'Test Runs',
    group: 'validation',
    description: 'Execution timeline, probe results, agent observations, and verdicts.',
    icon: Activity
  },
  {
    id: 'run-detail',
    label: 'Run Detail',
    group: 'validation',
    description: 'Timeline, probe result, agent observation, correlation truth table, and evidence chain for one run.',
    icon: Activity
  },
  {
    id: 'findings',
    label: 'Findings',
    group: 'validation',
    description: 'Evidence-backed gaps, owners, SLAs, and remediation status.',
    icon: TriangleAlert
  },
  {
    id: 'evidence',
    label: 'Evidence Vault',
    group: 'validation',
    description: 'Custody-ready evidence, exports, and verdict source material.',
    icon: FileCheck2
  },
  {
    id: 'waf-posture',
    label: 'WAF Posture',
    group: 'posture',
    description: 'Declared WAF assets, coverage rollups, drift visibility, and create actions backed by live APIs.',
    icon: ShieldHalf
  },
  {
    id: 'waf-asset-detail',
    label: 'WAF Asset Detail',
    group: 'posture',
    description: 'Ruleset effectiveness, bypass classes, drift, exceptions, validation runs, and remediation for one asset.',
    icon: ShieldHalf
  },
  {
    id: 'cve-pipeline',
    label: 'CVE Pipeline',
    group: 'posture',
    description: 'Live-exposure triage and mitigation workflow for declared assets.',
    icon: Radar
  },
  {
    id: 'cve-detail',
    label: 'CVE Detail',
    group: 'posture',
    description: 'Triage factors, asset matches, and safe validation actions for one CVE item.',
    icon: Radar
  },
  {
    id: 'supply-chain',
    label: 'Supply Chain',
    group: 'posture',
    description: 'CNAME, dependency, vendor, and exposure risk tracking.',
    icon: Boxes
  },
  {
    id: 'supply-chain-detail',
    label: 'Supply Chain Detail',
    group: 'posture',
    description: 'Evidence summary, remediation steps, and state actions for one supply-chain risk.',
    icon: Boxes
  },
  {
    id: 'remediation',
    label: 'Remediation',
    group: 'posture',
    description: 'Action items, safe retests, SIEM/SOAR previews, and closure paths.',
    icon: Wrench
  },
  {
    id: 'discovery',
    label: 'Discovery',
    group: 'posture',
    description: 'Approval-gated candidate inbox that never promotes inventory automatically.',
    icon: ScanSearch
  },
  {
    id: 'discovery-entity',
    label: 'Discovery Entity',
    group: 'posture',
    description: 'Candidate source evidence, confidence, decision trail, promote and dismiss workflow.',
    icon: Network
  },
  {
    id: 'high-scale',
    label: 'High-Scale Requests',
    group: 'governance',
    description: 'Customer request form, authorization pack, windows, and custody.',
    icon: Siren
  },
  {
    id: 'soc',
    label: 'SOC Console',
    group: 'governance',
    description: 'SOC-gated queue, kill switch state, checklists, and execution notes.',
    icon: ShieldCheck
  },
  {
    id: 'reports',
    label: 'Reports',
    group: 'governance',
    description: 'Executive, technical, SOC, audit, release, and WAF report builders.',
    icon: FileText
  },
  {
    id: 'report-detail',
    label: 'Report Detail',
    group: 'governance',
    description: 'Report kind, custody preview, export formats, and digest verification for one generated report.',
    icon: FileText
  },
  {
    id: 'integrations',
    label: 'Integrations',
    group: 'governance',
    description: 'Notification, ticketing, SIEM, SOAR, and optional read-only provider connectors.',
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
    label: 'Audit Log',
    group: 'governance',
    description: 'Tenant actions, security-relevant changes, and custody chain records.',
    icon: ClipboardList
  },
  {
    id: 'release-evidence',
    label: 'Release Evidence',
    group: 'governance',
    description: 'Production-readiness evidence inventory and launch gate visibility.',
    icon: SquareKanban
  },
  {
    id: 'settings',
    label: 'Settings',
    group: 'governance',
    description: 'Tenant profile, roles, tokens, retention, SSO, and safe defaults.',
    icon: KeyRound
  },
  {
    id: 'support',
    label: 'Support',
    group: 'governance',
    description: 'Support readiness, escalation paths, runbook references, and non-production on-call posture.',
    icon: LifeBuoy
  },
  {
    id: 'subscription',
    label: 'Subscription',
    group: 'governance',
    description: 'Plan, entitlements, limits, billing state, contract references, and effective dates.',
    icon: CircleDollarSign
  },
  {
    id: 'admin',
    label: 'Admin Console',
    group: 'staff',
    description: 'Internal overview for sign-ups, tenant lifecycle, approvals, support, and internal audit.',
    icon: UserCog
  },
  {
    id: 'tenant-detail',
    label: 'Tenant Detail',
    group: 'staff',
    description: 'Tenant lifecycle, users, entitlements, notes, support actions, subscriptions, and audit activity.',
    icon: UserCog
  },
  {
    id: 'internal-soc',
    label: 'Internal SOC',
    group: 'staff',
    description: 'Dedicated staff SOC execution plane with kill switch, Go/No-Go checklist, provider contacts, and timeline.',
    icon: Gauge
  }
];

export const ROUTE_BY_ID = new Map<RouteId, NavItem>(NAV_ITEMS.map((item) => [item.id, item]));

function routeIdFromHash(hash: string): RouteId | null {
  const raw = hash.replace(/^#/, '');
  const routePart = raw.includes('?') ? raw.slice(0, raw.indexOf('?')) : raw;
  return ROUTE_BY_ID.has(routePart as RouteId) ? routePart as RouteId : null;
}

export function getRouteFromHash(): RouteId {
  return routeIdFromHash(window.location.hash) ?? 'dashboard';
}

export function getRouteFromLocation(): RouteId {
  const hashRoute = routeIdFromHash(window.location.hash);
  if (hashRoute) return hashRoute;
  const pathRoute = window.location.pathname.replace(/^\/+/, '').replace(/\/+$/, '');
  if (window.location.pathname === '/internal/admin') return 'admin';
  if (window.location.pathname === '/internal/soc') return 'internal-soc';
  if (pathRoute === 'internal-soc.html') return 'internal-soc';
  if (pathRoute === 'index.html') return 'dashboard';
  const normalizedPathRoute = pathRoute.endsWith('.html') ? pathRoute.slice(0, -5) : pathRoute;
  if (ROUTE_BY_ID.has(normalizedPathRoute as RouteId)) return normalizedPathRoute as RouteId;
  if (ROUTE_BY_ID.has(pathRoute as RouteId)) return pathRoute as RouteId;
  if (pathRoute === 'app' || pathRoute === '') return 'dashboard';
  return 'dashboard';
}

export const PLATFORM_PROMISE =
  'AstraNull proves DDoS readiness for customer-declared targets without requiring cloud credentials or automatic IP inventory discovery.';

export const DEFENSIVE_RULES = [
  {
    title: 'No-access-first',
    body: 'Core workflows start from customer-declared targets and do not require cloud credentials.'
  },
  {
    title: 'Outbound-only agents',
    body: 'Agents call AstraNull over outbound HTTPS; no inbound management ports are required.'
  },
  {
    title: 'SOC-gated high-scale',
    body: 'Customers request high-scale validation; SOC approves, schedules, coordinates, stops, and closes.'
  },
  {
    title: 'Evidence over assumptions',
    body: 'Every verdict links back to observed probe data, agent observations, health signals, approvals, or declarations.'
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
    label: 'Internal SOC',
    href: '/internal/soc',
    icon: Gauge,
    description: 'Staff execution plane for governed high-scale operations.'
  }
];
